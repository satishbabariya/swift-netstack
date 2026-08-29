import NIOCore
import NIOEmbedded
import NIOPosix
import Testing

#if canImport(Darwin)
    import Darwin
#else
    import Glibc
#endif

@testable import Netstack

// The gateway is the resolver because the DHCP offer says so, which means every
// name a guest looks up passes through here. That makes it the one place a
// malformed or hostile query reaches first.

private let dnsGuest = IPv4Address("192.168.127.2")!
private let dnsGateway = IPv4Address("192.168.127.1")!
private let dnsGuestMAC = MACAddress("0a:0b:0c:0d:0e:0f")!
private let dnsGatewayMAC = MACAddress("5a:94:ef:e4:0c:ee")!

private final class DNSFixture {
    let loop = EmbeddedEventLoop()
    let clock = ManualClock()
    let link: RecordingEndpoint
    let stack: Stack
    let server: DNSServer

    init(records: [DNSServer.StaticRecord], upstream: [SocketAddress] = []) throws {
        link = RecordingEndpoint(eventLoop: loop, linkAddress: dnsGatewayMAC)
        stack = Stack(
            link: link,
            configuration: Stack.Configuration(
                gatewayAddress: dnsGateway, subnet: IPv4Subnet(cidr: "192.168.127.0/24")!),
            clock: clock)
        stack.start()
        stack.arpCache.record(dnsGuest, dnsGuestMAC)
        server = try DNSServer(stack: stack, records: records, upstream: upstream)
    }

    func ask(_ query: ByteBuffer, port: UInt16 = 40000) {
        let allocator = ByteBufferAllocator()
        let datagram = UDPHeader.serialize(
            payload: query, source: dnsGuest, destination: dnsGateway,
            sourcePort: port, destinationPort: DNSServer.port, allocator: allocator)!
        var packet = PacketBuffer(allocator: allocator, payload: datagram)
        IPv4Header(
            source: dnsGuest, destination: dnsGateway, protocolNumber: .udp,
            payloadLength: datagram.readableBytes
        ).prepend(to: &packet)
        EthernetHeader(destination: dnsGatewayMAC, source: dnsGuestMAC, etherType: .ipv4).prepend(to: &packet)
        link.inject(packet.frame)
    }

    func replies() -> [ByteBuffer] {
        var out: [ByteBuffer] = []
        for frame in link.drainTransmitted() {
            var packet = PacketBuffer(received: frame)
            guard let ethernet = EthernetHeader.parse(&packet), ethernet.etherType == .ipv4 else { continue }
            guard let ip = IPv4Header.parse(&packet), ip.protocolNumber == .udp else { continue }
            guard let udp = UDPHeader.parse(&packet, header: ip), udp.sourcePort == DNSServer.port else { continue }
            out.append(packet.payload)
        }
        return out
    }

    func drain() {
        server.close()
        loop.advanceTime(by: .hours(1))
        _ = link.drainTransmitted()
    }
}

/// A query, built by hand rather than with this package's own encoder.
private func dnsQuery(
    _ name: String, id: UInt16 = 0x1234, type: UInt16 = 1, klass: UInt16 = 1, recursionDesired: Bool = true
) -> ByteBuffer {
    var buffer = ByteBuffer()
    buffer.writeInteger(id, endianness: .big)
    buffer.writeInteger(UInt16(recursionDesired ? 0x0100 : 0), endianness: .big)
    buffer.writeInteger(UInt16(1), endianness: .big)  // QDCOUNT
    buffer.writeInteger(UInt16(0), endianness: .big)
    buffer.writeInteger(UInt16(0), endianness: .big)
    buffer.writeInteger(UInt16(0), endianness: .big)
    for label in name.split(separator: ".") {
        buffer.writeInteger(UInt8(label.utf8.count))
        buffer.writeBytes(Array(label.utf8))
    }
    buffer.writeInteger(UInt8(0))
    buffer.writeInteger(type, endianness: .big)
    buffer.writeInteger(klass, endianness: .big)
    return buffer
}

/// The A record address in a reply, if there is exactly one.
private func answeredAddress(_ reply: ByteBuffer) -> IPv4Address? {
    var buffer = reply
    guard buffer.readableBytes > 12 else { return nil }
    _ = buffer.readSlice(length: 4)
    guard let questions = buffer.readInteger(endianness: .big, as: UInt16.self),
        let answers = buffer.readInteger(endianness: .big, as: UInt16.self),
        questions == 1, answers == 1
    else { return nil }
    _ = buffer.readSlice(length: 4)
    // Skip the echoed question.
    while let length = buffer.readInteger(as: UInt8.self), length != 0 {
        guard buffer.readSlice(length: Int(length)) != nil else { return nil }
    }
    guard buffer.readSlice(length: 4) != nil else { return nil }
    // The answer: a two-byte name pointer, type, class, TTL, length, address.
    guard buffer.readSlice(length: 2) != nil,
        let type = buffer.readInteger(endianness: .big, as: UInt16.self), type == 1,
        buffer.readSlice(length: 2) != nil, buffer.readSlice(length: 4) != nil,
        let length = buffer.readInteger(endianness: .big, as: UInt16.self), length == 4,
        let bytes = buffer.readBytes(length: 4)
    else { return nil }
    return IPv4Address(bytes[0], bytes[1], bytes[2], bytes[3])
}

private func responseCode(_ reply: ByteBuffer) -> UInt16? {
    reply.getInteger(at: reply.readerIndex + 2, endianness: .big, as: UInt16.self).map { $0 & 0x000F }
}

@Test func aNameTheGatewayOwnsIsAnsweredWithItsAddress() throws {
    let fixture = try DNSFixture(records: [
        .init(name: "gateway.containers.internal", address: dnsGateway)
    ])
    defer { fixture.drain() }

    fixture.ask(dnsQuery("gateway.containers.internal"))

    let reply = try #require(fixture.replies().first)
    #expect(answeredAddress(reply) == dnsGateway)
    #expect(reply.getInteger(at: reply.readerIndex, endianness: .big, as: UInt16.self) == 0x1234, "the id was not echoed")
    #expect(fixture.server.answeredLocally == 1)
}

@Test func aNameIsMatchedWithoutRegardToCase() throws {
    // RFC 4343. A guest that varies the case of a name is exactly the input
    // that finds a comparison someone forgot to fold, and it is free to vary.
    let fixture = try DNSFixture(records: [
        .init(name: "Gateway.Containers.Internal", address: dnsGateway)
    ])
    defer { fixture.drain() }

    fixture.ask(dnsQuery("GATEWAY.containers.INTERNAL"))

    #expect(answeredAddress(try #require(fixture.replies().first)) == dnsGateway)
}

@Test func theEchoedQuestionKeepsTheCaseItWasAskedIn() throws {
    // RFC 1035 §4.1.2 requires the question to be echoed as it was asked, and
    // some resolvers compare it byte-for-byte as a spoofing check. The name is
    // lowercased for LOOKUP, so an answer that re-encoded it would fail those
    // resolvers while passing every test that only reads the address back.
    let fixture = try DNSFixture(records: [
        .init(name: "gateway.containers.internal", address: dnsGateway)
    ])
    defer { fixture.drain() }

    let asked = dnsQuery("GaTeWaY.containers.internal")
    fixture.ask(asked)

    let reply = try #require(fixture.replies().first)
    let question = Array(asked.readableBytesView.dropFirst(12))
    let echoed = Array(reply.readableBytesView.dropFirst(12).prefix(question.count))
    #expect(echoed == question, "the echoed question was re-encoded rather than copied")
}

@Test func anUnknownNameInAZoneTheGatewayOwnsIsNxdomainRatherThanForwarded() throws {
    // Forwarding it would leak the guest's internal names to a public resolver
    // and wait out a timeout to return the same answer.
    let fixture = try DNSFixture(records: [
        .init(name: "gateway.containers.internal", address: dnsGateway)
    ])
    defer { fixture.drain() }

    fixture.ask(dnsQuery("nothing.containers.internal"))

    let reply = try #require(fixture.replies().first)
    #expect(responseCode(reply) == DNSCodec.responseCodeNameError)
}

@Test func aQueryWithNoUpstreamIsRefusedRatherThanDropped() throws {
    // Refused, not silent. A guest waiting out a resolver timeout on every
    // lookup is a machine that looks broken in a way nothing explains; a
    // REFUSED is an answer its resolver can act on immediately.
    let fixture = try DNSFixture(records: [])
    defer { fixture.drain() }

    fixture.ask(dnsQuery("example.com"))

    let reply = try #require(fixture.replies().first)
    #expect(responseCode(reply) == DNSCodec.responseCodeRefused)
}

// MARK: - The parser, which is where a hostile guest reaches first

@Test func aCompressionPointerInAQuestionIsRefused() {
    // The well-known DNS bug, and the reason this parser refuses pointers
    // outright rather than following them with a budget.
    //
    // RFC 1035 §4.1.4 compression points BACKWARDS, to a name that has already
    // appeared; in the first question of a query there is nothing before it but
    // the header, so a pointer here cannot refer to a name at all. A parser that
    // follows one can be sent a pointer to itself and walk forever on a datagram
    // the guest sends once. With pointers refused there is no loop to bound and
    // no budget to get wrong.
    var buffer = ByteBuffer()
    buffer.writeInteger(UInt16(1), endianness: .big)
    buffer.writeInteger(UInt16(0), endianness: .big)
    buffer.writeInteger(UInt16(1), endianness: .big)
    buffer.writeInteger(UInt16(0), endianness: .big)
    buffer.writeInteger(UInt16(0), endianness: .big)
    buffer.writeInteger(UInt16(0), endianness: .big)
    buffer.writeInteger(UInt16(0xC00C), endianness: .big)  // a pointer to itself
    buffer.writeInteger(UInt16(1), endianness: .big)
    buffer.writeInteger(UInt16(1), endianness: .big)

    #expect(DNSCodec.parseQuery(buffer) == nil)
}

@Test func aLabelLongerThanTheProtocolAllowsIsRefusedByThePointerCheck() {
    // The same check as the test above, and finding that out is the point.
    //
    // A separate guard for the 63-byte label limit was written here first. It
    // survived its own falsification: removing it failed nothing, because a
    // length byte above 63 has one of its top two bits set, and those are
    // exactly the bits that mark a compression pointer. The guard was removed
    // rather than left standing as protection that protects nothing, and this
    // test kept -- what it pins is that the bound holds, not which line holds
    // it.
    var buffer = ByteBuffer()
    buffer.writeInteger(UInt16(1), endianness: .big)
    buffer.writeInteger(UInt16(0), endianness: .big)
    buffer.writeInteger(UInt16(1), endianness: .big)
    buffer.writeBytes([UInt8](repeating: 0, count: 6))
    buffer.writeInteger(UInt8(64))  // one past the maximum
    buffer.writeBytes([UInt8](repeating: 0x61, count: 64))
    buffer.writeInteger(UInt8(0))
    buffer.writeInteger(UInt16(1), endianness: .big)
    buffer.writeInteger(UInt16(1), endianness: .big)

    #expect(DNSCodec.parseQuery(buffer) == nil)
}

@Test func aNameLongerThanTheProtocolAllowsIsRefused() {
    // 255 bytes total, however it is divided. A parser that bounded only the
    // label length would accept a name of any length made of legal labels.
    var buffer = ByteBuffer()
    buffer.writeInteger(UInt16(1), endianness: .big)
    buffer.writeInteger(UInt16(0), endianness: .big)
    buffer.writeInteger(UInt16(1), endianness: .big)
    buffer.writeBytes([UInt8](repeating: 0, count: 6))
    for _ in 0..<10 {
        buffer.writeInteger(UInt8(63))
        buffer.writeBytes([UInt8](repeating: 0x61, count: 63))
    }
    buffer.writeInteger(UInt8(0))
    buffer.writeInteger(UInt16(1), endianness: .big)
    buffer.writeInteger(UInt16(1), endianness: .big)

    #expect(DNSCodec.parseQuery(buffer) == nil)
}

@Test func aReplyArrivingOnTheServerPortIsNotAQuery() {
    // QR set. Without the check a guest can send this gateway a "reply" it never
    // asked for, and every path below treats it as a question to answer.
    var buffer = dnsQuery("example.com")
    buffer.setInteger(UInt16(0x8180), at: 2, endianness: .big)
    #expect(DNSCodec.parseQuery(buffer) == nil)
}

@Test func aQueryWithTwoQuestionsIsRefused() {
    // Every resolver sends one. Two is a message this gateway cannot answer
    // correctly -- a static answer would answer the first and silently drop the
    // second -- so it is not answered at all.
    var buffer = dnsQuery("example.com")
    buffer.setInteger(UInt16(2), at: 4, endianness: .big)
    #expect(DNSCodec.parseQuery(buffer) == nil)
}

@Test func atruncatedQueryIsRefused() {
    var buffer = dnsQuery("example.com")
    let head = buffer.readSlice(length: 14)!
    #expect(DNSCodec.parseQuery(head) == nil)
}

// MARK: - Forwarding, which needs a real socket on both sides

private final class DNSHolder: @unchecked Sendable {
    var stack: Stack?
    var server: DNSServer?
    var link: WireLinkEndpoint?
}

/// Answers every query with a fixed A record, or -- when `corrupt` is set --
/// with an answer to a question nobody asked.
private final class FakeResolver: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = AddressedEnvelope<ByteBuffer>
    typealias OutboundOut = AddressedEnvelope<ByteBuffer>

    let address: IPv4Address
    let corrupt: Bool
    var seenIDs: [UInt16] = []

    init(address: IPv4Address, corrupt: Bool = false) {
        self.address = address
        self.corrupt = corrupt
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let envelope = unwrapInboundIn(data)
        guard let query = DNSCodec.parseQuery(envelope.data) else { return }
        seenIDs.append(query.id)
        let question = corrupt ? dnsQuery("elsewhere.example", id: query.id) : envelope.data
        guard let parsed = DNSCodec.parseQuery(question),
            var reply = DNSCodec.answer(
                to: parsed, in: question, address: address, ttl: 60,
                allocator: context.channel.allocator)
        else { return }
        reply.setInteger(query.id, at: reply.readerIndex, endianness: .big)
        context.writeAndFlush(
            wrapOutboundOut(AddressedEnvelope(remoteAddress: envelope.remoteAddress, data: reply)),
            promise: nil)
    }
}

/// A gateway on a real socketpair, with a real upstream resolver on loopback.
private func forwardingGateway(
    group: EventLoopGroup, guestSide: inout Int32, upstream: SocketAddress, maximumPending: Int = 256
) async throws -> DNSHolder {
    var pair: [Int32] = [0, 0]
    #expect(socketpair(AF_UNIX, SOCK_DGRAM, 0, &pair) == 0)
    guestSide = pair[1]
    let link = try await WireBootstrap.adoptingDatagramSocket(
        pair[0], group: group, linkAddress: dnsGatewayMAC, mtu: 1500
    ).get()
    let holder = DNSHolder()
    holder.link = link
    try await link.eventLoop.submit {
        let stack = Stack(
            link: link,
            configuration: Stack.Configuration(
                gatewayAddress: dnsGateway, subnet: IPv4Subnet(cidr: "192.168.127.0/24")!))
        stack.start()
        stack.arpCache.record(dnsGuest, dnsGuestMAC)
        holder.stack = stack
        holder.server = try DNSServer(
            stack: stack, records: [.init(name: "gateway.containers.internal", address: dnsGateway)],
            upstream: [upstream], maximumPending: maximumPending)
    }.get()
    try await holder.server!.startForwarding(group: group).get()
    return holder
}

private func askOverWire(_ fd: Int32, _ query: ByteBuffer, port: UInt16 = 40000) {
    let allocator = ByteBufferAllocator()
    let datagram = UDPHeader.serialize(
        payload: query, source: dnsGuest, destination: dnsGateway,
        sourcePort: port, destinationPort: DNSServer.port, allocator: allocator)!
    var packet = PacketBuffer(allocator: allocator, payload: datagram)
    IPv4Header(
        source: dnsGuest, destination: dnsGateway, protocolNumber: .udp, payloadLength: datagram.readableBytes
    ).prepend(to: &packet)
    EthernetHeader(destination: dnsGatewayMAC, source: dnsGuestMAC, etherType: .ipv4).prepend(to: &packet)
    let bytes = Array(packet.frame.readableBytesView)
    _ = bytes.withUnsafeBytes { send(fd, $0.baseAddress, $0.count, 0) }
}

private func awaitReply(_ fd: Int32) async -> ByteBuffer? {
    for _ in 0..<400 {
        var back = [UInt8](repeating: 0, count: 4096)
        let read = back.withUnsafeMutableBytes { recv(fd, $0.baseAddress, $0.count, MSG_DONTWAIT) }
        if read > 0 {
            var packet = PacketBuffer(received: ByteBuffer(bytes: back[0..<read]))
            guard let ethernet = EthernetHeader.parse(&packet), ethernet.etherType == .ipv4 else { continue }
            guard let ip = IPv4Header.parse(&packet), ip.protocolNumber == .udp else { continue }
            guard let udp = UDPHeader.parse(&packet, header: ip), udp.sourcePort == DNSServer.port else { continue }
            return packet.payload
        }
        try? await Task.sleep(nanoseconds: 5_000_000)
    }
    return nil
}

@Test func aNameTheGatewayDoesNotOwnIsForwardedAndTheAnswerComesBack() async throws {
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    let resolver = FakeResolver(address: IPv4Address("93.184.216.34")!)
    let upstream = try await DatagramBootstrap(group: group)
        .channelInitializer { channel in channel.pipeline.addHandler(resolver) }
        .bind(host: "127.0.0.1", port: 0).get()
    var guestSide: Int32 = -1
    let holder = try await forwardingGateway(
        group: group, guestSide: &guestSide, upstream: upstream.localAddress!)

    askOverWire(guestSide, dnsQuery("example.com", id: 0xBEEF))

    let reply = try #require(await awaitReply(guestSide))
    #expect(answeredAddress(reply) == IPv4Address("93.184.216.34")!)
    #expect(
        reply.getInteger(at: reply.readerIndex, endianness: .big, as: UInt16.self) == 0xBEEF,
        "the guest's own transaction id did not come back")

    try? await upstream.close()
    _ = try? await holder.stack?.shutdown().get()
    _ = try? await holder.link?.close().get()
    close(guestSide)
    try? await group.shutdownGracefully()
    _ = holder.stack
}

@Test func theIdSentUpstreamIsNotTheOneTheGuestChose() async throws {
    // Reusing the guest's id would let a guest pick the id an upstream reply
    // must carry -- half of what an off-path attacker needs, and all of what an
    // on-path one does to answer its neighbours' queries.
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    let resolver = FakeResolver(address: IPv4Address("93.184.216.34")!)
    let upstream = try await DatagramBootstrap(group: group)
        .channelInitializer { channel in channel.pipeline.addHandler(resolver) }
        .bind(host: "127.0.0.1", port: 0).get()
    var guestSide: Int32 = -1
    let holder = try await forwardingGateway(
        group: group, guestSide: &guestSide, upstream: upstream.localAddress!)

    askOverWire(guestSide, dnsQuery("example.com", id: 0xBEEF))
    _ = await awaitReply(guestSide)

    let seen = try await upstream.eventLoop.submit { resolver.seenIDs }.get()
    #expect(seen.count == 1)
    #expect(seen.first != 0xBEEF, "the guest's id was forwarded verbatim")

    try? await upstream.close()
    _ = try? await holder.stack?.shutdown().get()
    _ = try? await holder.link?.close().get()
    close(guestSide)
    try? await group.shutdownGracefully()
    _ = holder.stack
}

@Test func aReplyAnsweringADifferentQuestionIsDiscarded() async throws {
    // Matching on the transaction id alone is the classic cache-poisoning
    // opening: sixteen bits is a number an attacker can simply try. The question
    // has to match too, and this upstream returns the right id with the wrong
    // question to prove that it does.
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    let resolver = FakeResolver(address: IPv4Address("6.6.6.6")!, corrupt: true)
    let upstream = try await DatagramBootstrap(group: group)
        .channelInitializer { channel in channel.pipeline.addHandler(resolver) }
        .bind(host: "127.0.0.1", port: 0).get()
    var guestSide: Int32 = -1
    let holder = try await forwardingGateway(
        group: group, guestSide: &guestSide, upstream: upstream.localAddress!)

    askOverWire(guestSide, dnsQuery("example.com", id: 0xBEEF))

    // Nothing should come back, and the server should say why.
    let reply = await awaitReply(guestSide)
    #expect(reply == nil, "an answer to a question nobody asked was passed to the guest")
    let unmatched = try await holder.link!.eventLoop.submit { holder.server?.unmatchedReplies ?? 0 }.get()
    #expect(unmatched == 1)

    try? await upstream.close()
    _ = try? await holder.stack?.shutdown().get()
    _ = try? await holder.link?.close().get()
    close(guestSide)
    try? await group.shutdownGracefully()
    _ = holder.stack
}
