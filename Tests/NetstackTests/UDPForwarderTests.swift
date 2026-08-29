import NIOCore
import NIOPosix
import Testing

#if canImport(Darwin)
    import Darwin
#else
    import Glibc
#endif

@testable import Netstack

// UDP has no connection to accept and no close to observe, so what a forwarder
// keeps is a NAT table -- and a table a guest can grow is the thing worth
// testing.

private let udpGuest = IPv4Address("192.168.127.2")!
private let udpGateway = IPv4Address("192.168.127.1")!
private let udpGuestMAC = MACAddress("0a:0b:0c:0d:0e:0f")!
private let udpGatewayMAC = MACAddress("5a:94:ef:e4:0c:ee")!

private final class UDPHolder: @unchecked Sendable {
    var stack: Stack?
    var forwarder: UDPForwarder?
    var link: WireLinkEndpoint?
    /// Held, not discarded. A `DNSServer` keeps its endpoint's callback weakly,
    /// so one that nothing retains stops answering the moment it is built --
    /// which looks exactly like a forwarder that swallowed the query.
    var dns: DNSServer?
}

private func udpGatewayFixture(
    group: EventLoopGroup, guestSide: inout Int32, maximumFlows: Int = 512
) async throws -> UDPHolder {
    var pair: [Int32] = [0, 0]
    #expect(socketpair(AF_UNIX, SOCK_DGRAM, 0, &pair) == 0)
    guestSide = pair[1]
    let link = try await WireBootstrap.adoptingDatagramSocket(
        pair[0], group: group, linkAddress: udpGatewayMAC, mtu: 1500
    ).get()
    let holder = UDPHolder()
    holder.link = link
    try await link.eventLoop.submit {
        let stack = Stack(
            link: link,
            configuration: Stack.Configuration(
                gatewayAddress: udpGateway, subnet: IPv4Subnet(cidr: "192.168.127.0/24")!))
        stack.start()
        stack.arpCache.record(udpGuest, udpGuestMAC)
        holder.stack = stack
        holder.forwarder = UDPForwarder(stack: stack, maximumFlows: maximumFlows)
    }.get()
    return holder
}

private func guestDatagram(
    to destination: IPv4Address, port: UInt16, sourcePort: UInt16 = 40000, payload: [UInt8]
) -> [UInt8] {
    let allocator = ByteBufferAllocator()
    let datagram = UDPHeader.serialize(
        payload: ByteBuffer(bytes: payload), source: udpGuest, destination: destination,
        sourcePort: sourcePort, destinationPort: port, allocator: allocator)!
    var packet = PacketBuffer(allocator: allocator, payload: datagram)
    IPv4Header(
        source: udpGuest, destination: destination, protocolNumber: .udp,
        payloadLength: datagram.readableBytes
    ).prepend(to: &packet)
    EthernetHeader(destination: udpGatewayMAC, source: udpGuestMAC, etherType: .ipv4).prepend(to: &packet)
    return Array(packet.frame.readableBytesView)
}

/// Datagrams the gateway put on the wire, as (source address, source port,
/// payload).
private func drainDatagrams(_ fd: Int32) -> [(IPv4Address, UInt16, [UInt8])] {
    var out: [(IPv4Address, UInt16, [UInt8])] = []
    for _ in 0..<64 {
        var back = [UInt8](repeating: 0, count: 4096)
        let read = back.withUnsafeMutableBytes { recv(fd, $0.baseAddress, $0.count, MSG_DONTWAIT) }
        guard read > 0 else { break }
        var packet = PacketBuffer(received: ByteBuffer(bytes: back[0..<read]))
        guard let ethernet = EthernetHeader.parse(&packet), ethernet.etherType == .ipv4 else { continue }
        guard let ip = IPv4Header.parse(&packet), ip.protocolNumber == .udp else { continue }
        guard let udp = UDPHeader.parse(&packet, header: ip) else { continue }
        out.append((ip.source, udp.sourcePort, Array(packet.payload.readableBytesView)))
    }
    return out
}

private func awaitDatagrams(
    _ fd: Int32, count: Int = 1
) async -> [(IPv4Address, UInt16, [UInt8])] {
    var collected: [(IPv4Address, UInt16, [UInt8])] = []
    for _ in 0..<400 {
        collected += drainDatagrams(fd)
        if collected.count >= count { return collected }
        try? await Task.sleep(nanoseconds: 5_000_000)
    }
    return collected
}

/// Echoes every datagram back, upper-cased, so the reply cannot be the request
/// arriving twice.
private final class UppercasingUDPEcho: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = AddressedEnvelope<ByteBuffer>
    typealias OutboundOut = AddressedEnvelope<ByteBuffer>

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let envelope = unwrapInboundIn(data)
        var out = context.channel.allocator.buffer(capacity: envelope.data.readableBytes)
        out.writeBytes(envelope.data.readableBytesView.map { $0 >= 97 && $0 <= 122 ? $0 - 32 : $0 })
        context.writeAndFlush(
            wrapOutboundOut(AddressedEnvelope(remoteAddress: envelope.remoteAddress, data: out)), promise: nil)
    }
}

@Test func aGuestDatagramReachesARealSocketAndTheReplyComesBack() async throws {
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    let echo = try await DatagramBootstrap(group: group)
        .channelInitializer { channel in channel.pipeline.addHandler(UppercasingUDPEcho()) }
        .bind(host: "127.0.0.1", port: 0).get()
    let port = UInt16(echo.localAddress!.port!)
    var guestSide: Int32 = -1
    let holder = try await udpGatewayFixture(group: group, guestSide: &guestSide)

    let bytes = guestDatagram(
        to: IPv4Address("127.0.0.1")!, port: port, payload: Array("hello".utf8))
    _ = bytes.withUnsafeBytes { send(guestSide, $0.baseAddress, $0.count, 0) }

    let replies = await awaitDatagrams(guestSide)
    let reply = try #require(replies.first)
    #expect(String(decoding: reply.2, as: UTF8.self) == "HELLO")
    // From the address the guest addressed, not from the gateway's. The guest's
    // socket is connected to that address; a reply from anywhere else is one the
    // guest's kernel discards, and the application sees no answer at all.
    #expect(reply.0 == IPv4Address("127.0.0.1")!, "the reply came from the wrong address")
    #expect(reply.1 == port, "the reply came from the wrong port")

    try? await echo.close()
    _ = try? await holder.stack?.shutdown().get()
    _ = try? await holder.link?.close().get()
    close(guestSide)
    try? await group.shutdownGracefully()
    _ = holder.stack
}

@Test func datagramsForTheGatewayItselfAreLeftForItsOwnServices() async throws {
    // The rule is the gateway's ADDRESS, not a list of ports: a port list would
    // have to be kept in step with every service ever added, and would be wrong
    // the first time it was not.
    //
    // DHCP is the case that proves it. A guest's DISCOVER is a UDP datagram, and
    // a forwarder that swallowed everything would try to send it to the
    // internet -- so the guest would never get an address, and the failure would
    // look like a DHCP bug.
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    var guestSide: Int32 = -1
    let holder = try await udpGatewayFixture(group: group, guestSide: &guestSide)
    try await holder.link!.eventLoop.submit {
        holder.dns = try DNSServer(
            stack: holder.stack!, records: [.init(name: "gateway.containers.internal", address: udpGateway)])
    }.get()

    var query = ByteBuffer()
    query.writeInteger(UInt16(0x4321), endianness: .big)
    query.writeInteger(UInt16(0x0100), endianness: .big)
    query.writeInteger(UInt16(1), endianness: .big)
    query.writeBytes([UInt8](repeating: 0, count: 6))
    for label in ["gateway", "containers", "internal"] {
        query.writeInteger(UInt8(label.utf8.count))
        query.writeBytes(Array(label.utf8))
    }
    query.writeInteger(UInt8(0))
    query.writeInteger(UInt16(1), endianness: .big)
    query.writeInteger(UInt16(1), endianness: .big)

    let bytes = guestDatagram(
        to: udpGateway, port: 53, payload: Array(query.readableBytesView))
    _ = bytes.withUnsafeBytes { send(guestSide, $0.baseAddress, $0.count, 0) }

    let replies = await awaitDatagrams(guestSide)
    #expect(!replies.isEmpty, "the gateway's own DNS server never saw the query")
    #expect(replies.first?.0 == udpGateway)
    #expect(holder.forwarder?.flowCount == 0, "a flow was opened for a datagram the gateway owns")

    _ = try? await holder.stack?.shutdown().get()
    _ = try? await holder.link?.close().get()
    close(guestSide)
    try? await group.shutdownGracefully()
    _ = holder.stack
}

@Test func aGuestCannotOpenMoreFlowsThanTheLimitAllows() async throws {
    // A guest varies its source port freely, so without a bound a loop over
    // 65,536 ports opens 65,536 file descriptors -- and a process out of
    // descriptors takes everything in it down, not just the gateway.
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    let echo = try await DatagramBootstrap(group: group)
        .channelInitializer { channel in channel.pipeline.addHandler(UppercasingUDPEcho()) }
        .bind(host: "127.0.0.1", port: 0).get()
    let port = UInt16(echo.localAddress!.port!)
    var guestSide: Int32 = -1
    let holder = try await udpGatewayFixture(group: group, guestSide: &guestSide, maximumFlows: 2)

    for sourcePort in UInt16(40000)...UInt16(40009) {
        let bytes = guestDatagram(
            to: IPv4Address("127.0.0.1")!, port: port, sourcePort: sourcePort,
            payload: Array("hello".utf8))
        _ = bytes.withUnsafeBytes { send(guestSide, $0.baseAddress, $0.count, 0) }
    }
    _ = await awaitDatagrams(guestSide, count: 2)

    let count = try await holder.link!.eventLoop.submit { holder.forwarder?.flowCount ?? 0 }.get()
    let refused = try await holder.link!.eventLoop.submit { holder.forwarder?.refusedForLimit ?? 0 }.get()
    #expect(count <= 2, "the table grew past its bound: \(count)")
    #expect(refused > 0, "nothing was refused: the limit was never reached")

    try? await echo.close()
    _ = try? await holder.stack?.shutdown().get()
    _ = try? await holder.link?.close().get()
    close(guestSide)
    try? await group.shutdownGracefully()
    _ = holder.stack
}

@Test func aSecondDatagramOnAFlowReusesItsSocket() async throws {
    // What makes it a flow rather than a datagram relay. The guest's socket is
    // waiting for a reply from a particular address and port, so every datagram
    // of one conversation has to leave from the same host socket -- and a
    // forwarder that opened one per datagram would also open one per datagram
    // of a burst, which is the limit above reached in a millisecond.
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    let echo = try await DatagramBootstrap(group: group)
        .channelInitializer { channel in channel.pipeline.addHandler(UppercasingUDPEcho()) }
        .bind(host: "127.0.0.1", port: 0).get()
    let port = UInt16(echo.localAddress!.port!)
    var guestSide: Int32 = -1
    let holder = try await udpGatewayFixture(group: group, guestSide: &guestSide)

    for _ in 0..<4 {
        let bytes = guestDatagram(
            to: IPv4Address("127.0.0.1")!, port: port, payload: Array("hello".utf8))
        _ = bytes.withUnsafeBytes { send(guestSide, $0.baseAddress, $0.count, 0) }
        _ = await awaitDatagrams(guestSide)
    }

    // `openedSockets`, not `flowCount`. The table is keyed on the four-tuple,
    // so its size cannot exceed one for this conversation however many sockets
    // were opened -- this test was written against `flowCount` first and passed
    // against a forwarder that opened one socket per datagram and overwrote the
    // entry every time.
    let opened = try await holder.link!.eventLoop.submit { holder.forwarder?.openedSockets ?? 0 }.get()
    #expect(opened == 1, "four datagrams of one conversation opened \(opened) sockets")

    try? await echo.close()
    _ = try? await holder.stack?.shutdown().get()
    _ = try? await holder.link?.close().get()
    close(guestSide)
    try? await group.shutdownGracefully()
    _ = holder.stack
}
