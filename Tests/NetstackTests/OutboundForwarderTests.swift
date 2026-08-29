import NIOCore
import NIOPosix
import Testing

#if canImport(Darwin)
    import Darwin
#else
    import Glibc
#endif

@testable import Netstack

// The point of the whole package: a guest opens a TCP connection and it comes
// out of a real socket on the host.
//
// These tests use a real loopback listener rather than a stub, because the
// thing being tested is precisely the join between this stack and the operating
// system's -- and a stub on either side would be testing the join to the stub.

private let outboundGuestMAC = MACAddress("0a:0b:0c:0d:0e:0f")!
private let outboundGatewayMAC = MACAddress("5a:94:ef:e4:0c:ee")!

private final class Holder: @unchecked Sendable {
    var stack: Stack?
    var forwarder: OutboundTCPForwarder?
    var link: WireLinkEndpoint?
}

/// Everything a guest needs to reach the host: a socketpair for the wire, a
/// stack on it, and an outbound forwarder.
private func gateway(
    group: EventLoopGroup, guestSide: inout Int32, maximumConnections: Int = 1024
) async throws -> Holder {
    var pair: [Int32] = [0, 0]
    #expect(socketpair(AF_UNIX, SOCK_DGRAM, 0, &pair) == 0)
    guestSide = pair[1]
    let link = try await WireBootstrap.adoptingDatagramSocket(
        pair[0], group: group, linkAddress: outboundGatewayMAC, mtu: 1500
    ).get()
    let holder = Holder()
    holder.link = link
    try await link.eventLoop.submit {
        let stack = Stack(
            link: link,
            configuration: Stack.Configuration(
                gatewayAddress: IPv4Address("192.168.127.1")!,
                subnet: IPv4Subnet(cidr: "192.168.127.0/24")!))
        stack.start()
        // The guest's link address, which the gateway would otherwise have to
        // ARP for before it could answer anything.
        stack.arpCache.record(IPv4Address("192.168.127.2")!, outboundGuestMAC)
        holder.stack = stack
        holder.forwarder = OutboundTCPForwarder(stack: stack, maximumConnections: maximumConnections)
    }.get()
    return holder
}

/// One ethernet frame carrying one TCP segment from the guest.
private func guestFrame(
    to destination: IPv4Address, destinationPort: UInt16, sequence: UInt32, acknowledgement: UInt32 = 0,
    flags: TCPFlags, payload: [UInt8] = [], sourcePort: UInt16 = 50000
) -> [UInt8] {
    let allocator = ByteBufferAllocator()
    let header = TCPHeader(
        sourcePort: sourcePort, destinationPort: destinationPort,
        sequence: SequenceNumber(sequence), acknowledgement: SequenceNumber(acknowledgement),
        dataOffset: 5, flags: flags, window: 65535, checksum: 0, urgentPointer: 0, options: [])
    let source = IPv4Address("192.168.127.2")!
    let segment = header.serialize(
        payload: ByteBuffer(bytes: payload), source: source, destination: destination, allocator: allocator)
    var packet = PacketBuffer(allocator: allocator, payload: segment)
    IPv4Header(source: source, destination: destination, protocolNumber: .tcp, payloadLength: segment.readableBytes)
        .prepend(to: &packet)
    EthernetHeader(destination: outboundGatewayMAC, source: outboundGuestMAC, etherType: .ipv4)
        .prepend(to: &packet)
    return Array(packet.frame.readableBytesView)
}

/// Every TCP segment the gateway has emitted, drained without blocking.
private func drainSegments(_ fd: Int32) -> [(header: TCPHeader, payload: ByteBuffer)] {
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

private func send(_ fd: Int32, _ bytes: [UInt8]) {
    #expect(bytes.withUnsafeBytes { Darwin.send(fd, $0.baseAddress, $0.count, 0) } == bytes.count)
}

/// Poll for segments rather than sleeping a fixed time: the work is on another
/// thread and its duration is not this test's to guess.
private func awaitSegments(
    _ fd: Int32, where predicate: ([(header: TCPHeader, payload: ByteBuffer)]) -> Bool
) async -> [(header: TCPHeader, payload: ByteBuffer)] {
    var collected: [(header: TCPHeader, payload: ByteBuffer)] = []
    for _ in 0..<400 {
        collected += drainSegments(fd)
        if predicate(collected) { return collected }
        try? await Task.sleep(nanoseconds: 5_000_000)
    }
    return collected
}

@Test func aGuestConnectionReachesARealListenerAndCarriesBytesBothWays() async throws {
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    var guestSide: Int32 = -1
    let holder = try await gateway(group: group, guestSide: &guestSide)

    // A real listener on loopback, echoing what it receives in upper case so
    // the bytes coming back cannot be the bytes that went out by accident.
    let listener = try await ServerBootstrap(group: group)
        .childChannelInitializer { channel in
            channel.pipeline.addHandler(UppercasingEcho())
        }
        .bind(host: "127.0.0.1", port: 0).get()
    let port = UInt16(listener.localAddress!.port!)

    // The guest dials it.
    send(guestSide, guestFrame(
        to: IPv4Address("127.0.0.1")!, destinationPort: port, sequence: 7000, flags: [.syn]))
    let synAck = await awaitSegments(guestSide) { $0.contains { $0.header.flags.contains(.syn) } }
    let answer = try #require(synAck.first { $0.header.flags.contains(.syn) })
    #expect(answer.header.flags.contains(.ack), "the SYN was not answered")
    let gatewayISS = answer.header.sequence.value

    // Third leg, then data.
    send(guestSide, guestFrame(
        to: IPv4Address("127.0.0.1")!, destinationPort: port, sequence: 7001,
        acknowledgement: gatewayISS &+ 1, flags: [.ack]))
    send(guestSide, guestFrame(
        to: IPv4Address("127.0.0.1")!, destinationPort: port, sequence: 7001,
        acknowledgement: gatewayISS &+ 1, flags: [.ack, .psh], payload: Array("hello".utf8)))

    let echoed = await awaitSegments(guestSide) { segments in
        segments.contains { $0.payload.readableBytes > 0 }
    }
    let data = echoed.first { $0.payload.readableBytes > 0 }
    let text = data.map { String(decoding: $0.payload.readableBytesView, as: UTF8.self) }
    #expect(text == "HELLO", "the listener's answer did not come back to the guest: \(String(describing: text))")

    try? await listener.close()
    _ = try? await holder.link?.close().get()
    close(guestSide)
    try? await group.shutdownGracefully()
    _ = holder.stack
}

@Test func aGuestDiallingAPortNothingIsListeningOnIsResetImmediately() async throws {
    // The reason the dial happens BEFORE the SYN is answered. Answering first
    // is simpler and turns every failed connection into a successful one that
    // dies: `connect()` returns success and the first read fails, which is a
    // different error, arriving later, on a path applications handle worse.
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    var guestSide: Int32 = -1
    let holder = try await gateway(group: group, guestSide: &guestSide)

    // Bound and closed, so the port is one nothing can be listening on.
    let scout = try await ServerBootstrap(group: group).bind(host: "127.0.0.1", port: 0).get()
    let deadPort = UInt16(scout.localAddress!.port!)
    try await scout.close()

    send(guestSide, guestFrame(
        to: IPv4Address("127.0.0.1")!, destinationPort: deadPort, sequence: 7000, flags: [.syn]))

    let answer = await awaitSegments(guestSide) { !$0.isEmpty }
    let reset = try #require(answer.first)
    #expect(reset.header.flags.contains(.rst), "the guest was told the connection existed")
    #expect(reset.header.flags.contains(.ack), "a bare reset is one a dialler ignores")
    #expect(reset.header.acknowledgement == SequenceNumber(7001))
    #expect(holder.forwarder?.refusedForDial == 1)

    _ = try? await holder.link?.close().get()
    close(guestSide)
    try? await group.shutdownGracefully()
    _ = holder.stack
}

@Test func aGuestCannotOpenMoreConnectionsThanTheLimitAllows() async throws {
    // The bound the forwarder's own SYN limit does not provide. That one stops
    // counting the moment a request is settled, so without this a guest opens
    // connections that all SUCCEED and holds a host file descriptor per
    // connection until the process runs out -- and a process out of descriptors
    // takes everything else in it down, not just the gateway.
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    var guestSide: Int32 = -1
    let holder = try await gateway(group: group, guestSide: &guestSide, maximumConnections: 1)

    let listener = try await ServerBootstrap(group: group)
        .childChannelInitializer { channel in channel.eventLoop.makeSucceededVoidFuture() }
        .bind(host: "127.0.0.1", port: 0).get()
    let port = UInt16(listener.localAddress!.port!)

    // The first connection takes the only slot.
    send(guestSide, guestFrame(
        to: IPv4Address("127.0.0.1")!, destinationPort: port, sequence: 7000, flags: [.syn],
        sourcePort: 50001))
    let first = await awaitSegments(guestSide) { $0.contains { $0.header.flags.contains(.syn) } }
    #expect(first.contains { $0.header.flags.contains(.syn) }, "the first connection was refused")

    // The second is refused, and refused with a reset rather than in silence:
    // the forwarder consumed the segment, so silence would be a hang.
    send(guestSide, guestFrame(
        to: IPv4Address("127.0.0.1")!, destinationPort: port, sequence: 9000, flags: [.syn],
        sourcePort: 50002))
    let second = await awaitSegments(guestSide) { $0.contains { $0.header.flags.contains(.rst) } }
    let reset = try #require(second.first { $0.header.flags.contains(.rst) })
    #expect(reset.header.acknowledgement == SequenceNumber(9001))
    #expect(holder.forwarder?.refusedForLimit == 1)
    #expect(holder.forwarder?.establishedCount == 1, "the slot was not held by the live connection")

    try? await listener.close()
    _ = try? await holder.link?.close().get()
    close(guestSide)
    try? await group.shutdownGracefully()
    _ = holder.stack
}

/// Echoes what it reads, upper-cased.
private final class UppercasingEcho: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let incoming = unwrapInboundIn(data)
        var out = context.channel.allocator.buffer(capacity: incoming.readableBytes)
        out.writeBytes(incoming.readableBytesView.map { $0 >= 97 && $0 <= 122 ? $0 - 32 : $0 })
        context.writeAndFlush(wrapOutboundOut(out), promise: nil)
    }
}
