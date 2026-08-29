import NIOCore
import NIOPosix
import Testing

#if canImport(Darwin)
    import Darwin
#else
    import Glibc
#endif

@testable import Netstack

// The mirror image of the outbound path: something on the host dials, and this
// process opens a connection INTO the guest for it. Without this, a service in
// the guest is reachable only from the guest, and "publish a port" has no
// meaning -- the guest's address is on a subnet that exists only in this
// process.

private let pfGuest = IPv4Address("192.168.127.2")!
private let pfGateway = IPv4Address("192.168.127.1")!
private let pfGuestMAC = MACAddress("0a:0b:0c:0d:0e:0f")!
private let pfGatewayMAC = MACAddress("5a:94:ef:e4:0c:ee")!

private final class PFHolder: @unchecked Sendable {
    var stack: Stack?
    var forwarder: PortForwarder?
    var link: WireLinkEndpoint?
}

private func portForwardingGateway(
    group: EventLoopGroup, guestSide: inout Int32, guestPort: UInt16, maximumConnections: Int = 256
) async throws -> PFHolder {
    var pair: [Int32] = [0, 0]
    #expect(socketpair(AF_UNIX, SOCK_DGRAM, 0, &pair) == 0)
    guestSide = pair[1]
    let link = try await WireBootstrap.adoptingDatagramSocket(
        pair[0], group: group, linkAddress: pfGatewayMAC, mtu: 1500
    ).get()
    let holder = PFHolder()
    holder.link = link
    try await link.eventLoop.submit {
        let stack = Stack(
            link: link,
            configuration: Stack.Configuration(
                gatewayAddress: pfGateway, subnet: IPv4Subnet(cidr: "192.168.127.0/24")!))
        stack.start()
        stack.arpCache.record(pfGuest, pfGuestMAC)
        holder.stack = stack
        holder.forwarder = PortForwarder(
            stack: stack, guestAddress: pfGuest, guestPort: guestPort,
            maximumConnections: maximumConnections)
    }.get()
    try await holder.forwarder!.listen(port: 0).get()
    return holder
}

/// Segments the gateway put on the wire.
private func pfDrain(_ fd: Int32) -> [(header: TCPHeader, payload: ByteBuffer)] {
    var out: [(header: TCPHeader, payload: ByteBuffer)] = []
    for _ in 0..<64 {
        var back = [UInt8](repeating: 0, count: 4096)
        let read = back.withUnsafeMutableBytes { recv(fd, $0.baseAddress, $0.count, MSG_DONTWAIT) }
        guard read > 0 else { break }
        var packet = PacketBuffer(received: ByteBuffer(bytes: back[0..<read]))
        guard let ethernet = EthernetHeader.parse(&packet), ethernet.etherType == .ipv4 else { continue }
        guard let ip = IPv4Header.parse(&packet), ip.protocolNumber == .tcp else { continue }
        guard let tcp = TCPHeader.parse(&packet, header: ip) else { continue }
        out.append((tcp, packet.payload))
    }
    return out
}

private func pfAwait(
    _ fd: Int32, where predicate: ([(header: TCPHeader, payload: ByteBuffer)]) -> Bool
) async -> [(header: TCPHeader, payload: ByteBuffer)] {
    var collected: [(header: TCPHeader, payload: ByteBuffer)] = []
    for _ in 0..<400 {
        collected += pfDrain(fd)
        if predicate(collected) { return collected }
        try? await Task.sleep(nanoseconds: 5_000_000)
    }
    return collected
}

/// A segment from the guest, answering the gateway.
private func pfGuestSegment(
    sourcePort: UInt16, destinationPort: UInt16, sequence: UInt32, acknowledgement: UInt32,
    flags: TCPFlags, payload: [UInt8] = []
) -> [UInt8] {
    let allocator = ByteBufferAllocator()
    let header = TCPHeader(
        sourcePort: sourcePort, destinationPort: destinationPort,
        sequence: SequenceNumber(sequence), acknowledgement: SequenceNumber(acknowledgement),
        dataOffset: 5, flags: flags, window: 65535, checksum: 0, urgentPointer: 0, options: [])
    let segment = header.serialize(
        payload: ByteBuffer(bytes: payload), source: pfGuest, destination: pfGateway, allocator: allocator)
    var packet = PacketBuffer(allocator: allocator, payload: segment)
    IPv4Header(source: pfGuest, destination: pfGateway, protocolNumber: .tcp, payloadLength: segment.readableBytes)
        .prepend(to: &packet)
    EthernetHeader(destination: pfGatewayMAC, source: pfGuestMAC, etherType: .ipv4).prepend(to: &packet)
    return Array(packet.frame.readableBytesView)
}

@Test func aHostConnectionOpensOneIntoTheGuestAndCarriesBytes() async throws {
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    var guestSide: Int32 = -1
    let holder = try await portForwardingGateway(group: group, guestSide: &guestSide, guestPort: 8080)
    let hostPort = holder.forwarder!.listeningAddress!.port!

    // Something on the host dials the published port.
    let dialler = try await ClientBootstrap(group: group)
        .connect(host: "127.0.0.1", port: hostPort).get()

    // The gateway should now be dialling the guest.
    let syn = await pfAwait(guestSide) { $0.contains { $0.header.flags.contains(.syn) } }
    let opening = try #require(syn.first { $0.header.flags.contains(.syn) })
    #expect(!opening.header.flags.contains(.ack), "the gateway sent a SYN-ACK where a SYN belonged")
    #expect(opening.header.destinationPort == 8080, "the connection went to the wrong guest port")
    let gatewayISS = opening.header.sequence.value
    let guestPortUsed = opening.header.sourcePort

    // The guest accepts.
    let guestISS: UInt32 = 5000
    var bytes = pfGuestSegment(
        sourcePort: 8080, destinationPort: guestPortUsed, sequence: guestISS,
        acknowledgement: gatewayISS &+ 1, flags: [.syn, .ack])
    _ = bytes.withUnsafeBytes { send(guestSide, $0.baseAddress, $0.count, 0) }

    // The host writes; the bytes should reach the guest.
    var out = dialler.allocator.buffer(capacity: 5)
    out.writeString("hello")
    try await dialler.writeAndFlush(out)

    let data = await pfAwait(guestSide) { $0.contains { $0.payload.readableBytes > 0 } }
    let carried = data.first { $0.payload.readableBytes > 0 }
    #expect(
        carried.map { String(decoding: $0.payload.readableBytesView, as: UTF8.self) } == "hello",
        "the host's bytes did not reach the guest")

    try? await dialler.close()
    holder.forwarder?.close()
    _ = try? await holder.stack?.shutdown().get()
    _ = try? await holder.link?.close().get()
    close(guestSide)
    try? await group.shutdownGracefully()
    _ = holder.stack
}

@Test func aHostConnectionPastTheLimitIsClosedRatherThanQueued() async throws {
    // A host connection this gateway will not serve should fail now: the dialler
    // learns immediately, and nothing is held here waiting for room that may
    // never come.
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    var guestSide: Int32 = -1
    let holder = try await portForwardingGateway(
        group: group, guestSide: &guestSide, guestPort: 8080, maximumConnections: 1)
    let hostPort = holder.forwarder!.listeningAddress!.port!

    let first = try await ClientBootstrap(group: group).connect(host: "127.0.0.1", port: hostPort).get()
    _ = await pfAwait(guestSide) { $0.contains { $0.header.flags.contains(.syn) } }

    let second = try await ClientBootstrap(group: group).connect(host: "127.0.0.1", port: hostPort).get()
    // The second is accepted by the kernel and closed by us, which the dialler
    // sees as the connection ending.
    for _ in 0..<400 where second.isActive {
        try? await Task.sleep(nanoseconds: 5_000_000)
    }
    #expect(!second.isActive, "a connection past the limit was kept")
    let refused = try await holder.link!.eventLoop.submit { holder.forwarder?.refusedForLimit ?? 0 }.get()
    #expect(refused == 1)

    try? await first.close()
    holder.forwarder?.close()
    _ = try? await holder.stack?.shutdown().get()
    _ = try? await holder.link?.close().get()
    close(guestSide)
    try? await group.shutdownGracefully()
    _ = holder.stack
}

@Test func aGuestThatRefusesTheConnectionEndsTheHostsToo() async throws {
    // The only means a TCP server has of saying no to a dialler that has already
    // connected: the connection goes away. Leaving it open would present as a
    // service that accepts and never answers.
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    var guestSide: Int32 = -1
    let holder = try await portForwardingGateway(group: group, guestSide: &guestSide, guestPort: 8080)
    let hostPort = holder.forwarder!.listeningAddress!.port!

    let dialler = try await ClientBootstrap(group: group).connect(host: "127.0.0.1", port: hostPort).get()
    let syn = await pfAwait(guestSide) { $0.contains { $0.header.flags.contains(.syn) } }
    let opening = try #require(syn.first { $0.header.flags.contains(.syn) })

    // The guest resets it.
    var bytes = pfGuestSegment(
        sourcePort: 8080, destinationPort: opening.header.sourcePort, sequence: 0,
        acknowledgement: opening.header.sequence.value &+ 1, flags: [.rst, .ack])
    _ = bytes.withUnsafeBytes { send(guestSide, $0.baseAddress, $0.count, 0) }

    for _ in 0..<400 where dialler.isActive {
        try? await Task.sleep(nanoseconds: 5_000_000)
    }
    #expect(!dialler.isActive, "the host's connection outlived the guest's refusal")

    holder.forwarder?.close()
    _ = try? await holder.stack?.shutdown().get()
    _ = try? await holder.link?.close().get()
    close(guestSide)
    try? await group.shutdownGracefully()
    _ = holder.stack
}
