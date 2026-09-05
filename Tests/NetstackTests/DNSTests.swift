import Foundation
import NIOCore
import NIOEmbedded
import NIOPosix
import Testing

@testable import Netstack

#if canImport(Darwin)
    import Darwin
#else
    import Glibc
#endif

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

private func answeredTimeToLive(_ reply: ByteBuffer) -> UInt32? {
    var buffer = reply
    guard buffer.readableBytes > 12 else { return nil }
    _ = buffer.readSlice(length: 4)
    guard let questions = buffer.readInteger(endianness: .big, as: UInt16.self),
        let answers = buffer.readInteger(endianness: .big, as: UInt16.self),
        questions == 1, answers == 1
    else { return nil }
    _ = buffer.readSlice(length: 4)
    while let length = buffer.readInteger(as: UInt8.self), length != 0 {
        guard buffer.readSlice(length: Int(length)) != nil else { return nil }
    }
    guard buffer.readSlice(length: 4) != nil else { return nil }
    // Name pointer, type, class, then the TTL.
    guard buffer.readSlice(length: 2) != nil, buffer.readSlice(length: 2) != nil,
        buffer.readSlice(length: 2) != nil
    else { return nil }
    return buffer.readInteger(endianness: .big, as: UInt32.self)
}

private func responseCode(_ reply: ByteBuffer) -> UInt16? {
    reply.getInteger(at: reply.readerIndex + 2, endianness: .big, as: UInt16.self).map { $0 & 0x000F }
}

@Test func aNameThisGatewayHoldsHasNoAaaaRatherThanNotExisting() throws {
    // NXDOMAIN says the name does not exist, for every type at once, and a
    // resolver caches that. A name this gateway holds an address for exists --
    // it has no record of the type asked for, which is NODATA: NOERROR with no
    // answers.
    //
    // Found by asking a real Linux guest rather than a synthetic one. Every
    // check here asked for A, and a real resolver asks for AAAA as well:
    //
    //     nslookup host.containers.internal
    //     ** server can't find host.containers.internal: NXDOMAIN
    //
    // while the A query beside it answered 192.168.127.254 correctly.
    let fixture = try DNSFixture(records: [
        .init(name: "host.containers.internal", address: dnsGateway)
    ])
    defer { fixture.drain() }

    fixture.ask(dnsQuery("host.containers.internal", type: 28))
    // `replies()` empties the link, so it is read once and kept. Reading it
    // twice is how the first version of this test lost its own answer.
    let reply = try #require(fixture.replies().first)
    #expect(responseCode(reply) == 0, "a name this gateway holds was answered as though absent")
    #expect(
        reply.getInteger(at: reply.readerIndex + 6, endianness: .big, as: UInt16.self) == 0,
        "an AAAA answer was invented for a stack that does not do IPv6")

    // And a name that really is not there keeps saying so, or this would have
    // turned every mistyped name into a lookup that waits on records which are
    // never coming.
    fixture.ask(dnsQuery("nosuchname.containers.internal"))
    let absent = try #require(fixture.replies().first)
    #expect(responseCode(absent) == 3, "an unknown name in an owned zone was not NXDOMAIN")
}

@Test func theHostsSearchListIsReadFromResolvConf() {
    // A guest gets this in DHCP option 119, and without it a short name the host
    // can resolve is a name the guest cannot. gvproxy reads the host's
    // /etc/resolv.conf for every gateway it starts without a config file; this
    // sent an empty list unless somebody wrote one out.
    let text = """
        # Generated by something
        nameserver 8.8.8.8
        search corp.example lab.example
        options ndots:2
        """
    #expect(
        DNSServer.searchDomains(inResolvConf: text, applyingDarwinLimits: true)
            == ["corp.example", "lab.example"])

    // No search line, and no file at all, are both "no search domains" rather
    // than an error: a host without one is ordinary.
    #expect(DNSServer.searchDomains(inResolvConf: "nameserver 8.8.8.8", applyingDarwinLimits: true).isEmpty)
    #expect(DNSServer.searchDomains(inResolvConf: "", applyingDarwinLimits: true).isEmpty)

    // Runs of spaces do not become empty labels. Upstream's split leaves them,
    // and option 119 encodes each label by its length, so a zero-length one is
    // a malformed option rather than an empty name.
    #expect(
        DNSServer.searchDomains(inResolvConf: "search  a.example   b.example ", applyingDarwinLimits: true)
            == ["a.example", "b.example"])
}

@Test func theSearchListIsCutToWhatMacosWillAccept() {
    // macOS takes at most six domains and 256 characters, and upstream applies
    // both limits there and neither anywhere else. A list cut through the middle
    // of a name would be worse than a list cut short, so the character limit
    // falls back to the last space.
    let seven = (1...7).map { "domain\($0).example" }.joined(separator: " ")
    #expect(
        DNSServer.searchDomains(inResolvConf: "search \(seven)", applyingDarwinLimits: true).count == 6)
    #expect(
        DNSServer.searchDomains(inResolvConf: "search \(seven)", applyingDarwinLimits: false).count == 7,
        "the limits are macOS's and were applied where they do not exist")

    let long = (1...20).map { "averyverylongdomainname\($0).example" }.joined(separator: " ")
    let cut = DNSServer.searchDomains(inResolvConf: "search \(long)", applyingDarwinLimits: true)
    #expect(cut.count <= 6)
    for domain in cut {
        #expect(domain.hasSuffix(".example"), "a name was cut through the middle: \(domain)")
    }
}

@Test func anAnswerThisGatewayMakesItselfIsNotCached() async throws {
    // These records change while the gateway runs -- `/services/dns/add` is how
    // podman points a name at a container that has just started -- so an answer
    // a guest cached is an answer that can be wrong, with no second lookup to
    // correct it until the cache expires.
    //
    // This defaulted to 60 seconds: a minute of a guest resolving a name to
    // wherever it used to point. Every answer gvproxy builds carries Ttl: 0, in
    // all four places it builds one.
    let fixture = try DNSFixture(records: [
        .init(name: "gateway.containers.internal", address: dnsGateway)
    ])
    defer { fixture.drain() }

    fixture.ask(dnsQuery("gateway.containers.internal"))

    let reply = try #require(fixture.replies().first)
    #expect(answeredAddress(reply) == dnsGateway, "the name was not answered locally")
    #expect(answeredTimeToLive(reply) == 0, "a record that can change was given a lifetime")
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
    /// Bytes of filler appended to the reply, so a test can make an answer that
    /// will not fit a datagram without inventing a record set to fill it.
    let padding: Int
    var seenIDs: [UInt16] = []

    init(address: IPv4Address, corrupt: Bool = false, padding: Int = 0) {
        self.address = address
        self.corrupt = corrupt
        self.padding = padding
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
        if padding > 0 { reply.writeBytes([UInt8](repeating: 0, count: padding)) }
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
    #expect(makeSocketPair(AF_UNIX, .datagram, &pair) == 0)
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
        let read = back.withUnsafeMutableBytes { recv(fd, $0.baseAddress, $0.count, dontWait) }
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

@Test func aZoneWithADefaultAddressAnswersEveryNameUnderIt() async throws {
    // Upstream's `DefaultIP`, which is the wildcard. Without a zone, a name this
    // gateway does not have goes to a real resolver; with a zone and no default,
    // it is NXDOMAIN; with a default, it is the default. All three are different
    // answers and this checks the third against the second.
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    var guestSide: Int32 = -1
    let holder = try await zoneGateway(group: group, guestSide: &guestSide)
    let server = try #require(holder.server)

    let wildcard = IPv4Address("10.9.8.7")!
    let added = try await holder.stack!.eventLoop.submit {
        server.addZone(DNSServer.Zone(name: "apps.test", defaultAddress: wildcard))
    }.get()
    #expect(added)

    let answer = try #require(await zoneAsk(guestSide, "anything.apps.test", id: 0x51))
    #expect(answer.code == 0, "a name in a wildcard zone was not answered")
    #expect(answer.address == wildcard)

    // The apex too, not only names below it.
    let apex = try #require(await zoneAsk(guestSide, "apps.test", id: 0x52))
    #expect(apex.address == wildcard)

    _ = try? await holder.stack?.shutdown().get()
    _ = try? await holder.link?.close().get()
    close(guestSide)
    try? await group.shutdownGracefully()
}

@Test func aRecordInAZoneIsNamedRelativeToIt() async throws {
    // The part of upstream's model that is not the obvious one: a zone's record
    // names are relative, so `gateway` in `containers.internal` answers
    // `gateway.containers.internal`. Reading them as absolute makes every record
    // added through the API silently unreachable.
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    var guestSide: Int32 = -1
    let holder = try await zoneGateway(group: group, guestSide: &guestSide)
    let server = try #require(holder.server)

    let host = IPv4Address("10.1.1.1")!
    let fallback = IPv4Address("10.2.2.2")!
    _ = try await holder.stack!.eventLoop.submit {
        server.addZone(
            DNSServer.Zone(
                name: "svc.test", records: [.init(name: "api", address: host)],
                defaultAddress: fallback))
    }.get()

    let exact = try #require(await zoneAsk(guestSide, "api.svc.test", id: 0x61))
    #expect(exact.address == host, "the relative record did not answer")
    // And the default is still what everything else gets, so the record above is
    // being matched rather than merely reached.
    let other = try #require(await zoneAsk(guestSide, "other.svc.test", id: 0x62))
    #expect(other.address == fallback)

    _ = try? await holder.stack?.shutdown().get()
    _ = try? await holder.link?.close().get()
    close(guestSide)
    try? await group.shutdownGracefully()
}

@Test func theZonesFromTheGatewaysOwnConfigurationCannotBeTakenOverAtRuntime() async throws {
    // The one refusal `addZone` has. The guests were told this gateway is their
    // resolver and `gateway.containers.internal` is how they reach the host; an
    // API that could point that name somewhere else is an API that can cut every
    // guest off from the thing it was pointed at.
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    var guestSide: Int32 = -1
    let holder = try await zoneGateway(group: group, guestSide: &guestSide)
    let server = try #require(holder.server)

    let hijack = try await holder.stack!.eventLoop.submit {
        server.addZone(
            DNSServer.Zone(name: "containers.internal", defaultAddress: IPv4Address("6.6.6.6")!))
    }.get()
    #expect(!hijack, "a protected zone was replaced")

    // The floor: an unprotected zone still goes in, so the refusal above is the
    // protection working rather than `addZone` refusing everything.
    let ordinary = try await holder.stack!.eventLoop.submit {
        server.addZone(DNSServer.Zone(name: "other.test", defaultAddress: IPv4Address("6.6.6.6")!))
    }.get()
    #expect(ordinary)

    let answer = try #require(await zoneAsk(guestSide, "gateway.containers.internal", id: 0x71))
    #expect(answer.address == dnsGateway, "the protected name stopped resolving to the gateway")

    _ = try? await holder.stack?.shutdown().get()
    _ = try? await holder.link?.close().get()
    close(guestSide)
    try? await group.shutdownGracefully()
}

@Test func addingAZoneThatExistsMergesRatherThanReplacing() async throws {
    // Upstream merges, and the reason is the caller: a tool adding one name
    // should not have to know, or resend, every name already there.
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    var guestSide: Int32 = -1
    let holder = try await zoneGateway(group: group, guestSide: &guestSide)
    let server = try #require(holder.server)

    _ = try await holder.stack!.eventLoop.submit {
        server.addZone(
            DNSServer.Zone(name: "merge.test", records: [.init(name: "one", address: IPv4Address("10.0.0.1")!)]))
        server.addZone(
            DNSServer.Zone(name: "merge.test", records: [.init(name: "two", address: IPv4Address("10.0.0.2")!)]))
    }.get()

    let first = try #require(await zoneAsk(guestSide, "one.merge.test", id: 0x81))
    #expect(first.address == IPv4Address("10.0.0.1")!, "the first record was lost by the second call")
    let second = try #require(await zoneAsk(guestSide, "two.merge.test", id: 0x82))
    #expect(second.address == IPv4Address("10.0.0.2")!)

    // And the same name again updates rather than duplicating.
    _ = try await holder.stack!.eventLoop.submit {
        server.addZone(
            DNSServer.Zone(name: "merge.test", records: [.init(name: "one", address: IPv4Address("10.0.0.9")!)]))
    }.get()
    let updated = try #require(await zoneAsk(guestSide, "one.merge.test", id: 0x83))
    #expect(updated.address == IPv4Address("10.0.0.9")!, "re-adding a record did not update it")

    _ = try? await holder.stack?.shutdown().get()
    _ = try? await holder.link?.close().get()
    close(guestSide)
    try? await group.shutdownGracefully()
}

@Test func theMoreSpecificZoneAnswersRegardlessOfTheOrderTheyWereAdded() async throws {
    // Where this departs from upstream. Upstream walks its zone list in order and
    // takes the first suffix match, so which zone answers depends on which was
    // added first -- a DNS question decided by a configuration accident. The more
    // specific zone is the authoritative one; that is what delegation means.
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    var guestSide: Int32 = -1
    let holder = try await zoneGateway(group: group, guestSide: &guestSide)
    let server = try #require(holder.server)

    let broad = IPv4Address("10.5.0.1")!
    let narrow = IPv4Address("10.5.0.2")!
    _ = try await holder.stack!.eventLoop.submit {
        // Broad first, so first-match order would give the wrong answer.
        server.addZone(DNSServer.Zone(name: "deep.test", defaultAddress: broad))
        server.addZone(DNSServer.Zone(name: "inner.deep.test", defaultAddress: narrow))
    }.get()

    let answer = try #require(await zoneAsk(guestSide, "host.inner.deep.test", id: 0x91))
    #expect(answer.address == narrow, "the broader zone answered for a name the narrower one owns")
    let outside = try #require(await zoneAsk(guestSide, "host.deep.test", id: 0x92))
    #expect(outside.address == broad)

    _ = try? await holder.stack?.shutdown().get()
    _ = try? await holder.link?.close().get()
    close(guestSide)
    try? await group.shutdownGracefully()
}

/// A zone fixture with no upstream at all: these tests are about what the
/// gateway answers itself, and a resolver behind it would make a wrong answer
/// look like a forwarded one.
private func zoneGateway(group: EventLoopGroup, guestSide: inout Int32) async throws -> DNSHolder {
    var pair: [Int32] = [0, 0]
    #expect(makeSocketPair(AF_UNIX, .datagram, &pair) == 0)
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
            stack: stack, records: [.init(name: "gateway.containers.internal", address: dnsGateway)])
    }.get()
    return holder
}

/// Ask over the wire and read the A record back.
private func zoneAsk(_ fd: Int32, _ name: String, id: UInt16) async -> (address: IPv4Address?, code: UInt16?)? {
    askOverWire(fd, dnsQuery(name, id: id))
    guard let reply = await awaitReply(fd) else { return nil }
    return (answeredAddress(reply), responseCode(reply))
}

// MARK: - The resolver over TCP

/// One length-prefixed message, as RFC 1035 §4.2.2 frames them.
private func framed(_ message: ByteBuffer) -> ByteBuffer {
    var out = ByteBufferAllocator().buffer(capacity: message.readableBytes + 2)
    out.writeInteger(UInt16(message.readableBytes), endianness: .big)
    var body = message
    out.writeBuffer(&body)
    return out
}

/// Every complete framed reply an embedded channel has written.
private func replies(from channel: EmbeddedChannel) throws -> [ByteBuffer] {
    var out: [ByteBuffer] = []
    while var written = try channel.readOutbound(as: ByteBuffer.self) {
        while let length = written.getInteger(at: written.readerIndex, as: UInt16.self),
            written.readableBytes >= Int(length) + 2
        {
            written.moveReaderIndex(forwardBy: 2)
            guard let message = written.readSlice(length: Int(length)) else { break }
            out.append(message)
        }
    }
    return out
}

@Test func theResolverAnswersOverTCPAsWellAsUDP() throws {
    // Upstream serves DNS on both, and a resolver needs both: an answer that
    // will not fit a datagram comes back truncated, and the asker's next move
    // is the same question over TCP. Measured against a real guest before this
    // existed, `nc -z 192.168.127.1 53` could not even connect.
    let fixture = try DNSFixture(records: [
        .init(name: "gateway.containers.internal", address: dnsGateway)
    ])
    let channel = EmbeddedChannel(loop: fixture.loop)
    try channel.connect(to: SocketAddress(ipAddress: "192.168.127.2", port: 40000)).wait()
    // Driven, not waited on: `serve` submits its pipeline setup to the loop,
    // and an `EmbeddedEventLoop` runs what is submitted only when it is run --
    // so waiting here without running it waits for ever.
    let ready = fixture.server.serve(channel)
    fixture.loop.run()
    try ready.wait()

    try channel.writeInbound(framed(dnsQuery("gateway.containers.internal")))
    let answers = try replies(from: channel)
    #expect(answers.count == 1, "\(answers.count) replies to one question")
    let reply = try #require(answers.first)
    #expect(answeredAddress(reply) == dnsGateway)
    _ = try? channel.finish()
}

@Test func aQueryArrivingInPiecesIsAnsweredWhenItIsWhole() throws {
    // TCP is a stream: the length prefix and the message it describes can
    // arrive in any number of reads, and a resolver that assumed one read per
    // message would answer some questions and silently drop others.
    let fixture = try DNSFixture(records: [
        .init(name: "gateway.containers.internal", address: dnsGateway)
    ])
    let channel = EmbeddedChannel(loop: fixture.loop)
    try channel.connect(to: SocketAddress(ipAddress: "192.168.127.2", port: 40000)).wait()
    // Driven, not waited on: `serve` submits its pipeline setup to the loop,
    // and an `EmbeddedEventLoop` runs what is submitted only when it is run --
    // so waiting here without running it waits for ever.
    let ready = fixture.server.serve(channel)
    fixture.loop.run()
    try ready.wait()

    var whole = framed(dnsQuery("gateway.containers.internal"))
    guard let head = whole.readSlice(length: 3) else {
        Issue.record("the framed query was shorter than its own prefix")
        return
    }
    try channel.writeInbound(head)
    #expect(try replies(from: channel).isEmpty, "positive control: answered half a question")
    try channel.writeInbound(whole)
    #expect(try replies(from: channel).count == 1, "the rest of the question was never answered")
    _ = try? channel.finish()
}

@Test func twoQueriesInOneReadAreBothAnswered() throws {
    // RFC 7766 §6.2.1.1 lets a client pipeline, and a resolver that answered
    // only the first would leave the second to time out.
    let fixture = try DNSFixture(records: [
        .init(name: "gateway.containers.internal", address: dnsGateway)
    ])
    let channel = EmbeddedChannel(loop: fixture.loop)
    try channel.connect(to: SocketAddress(ipAddress: "192.168.127.2", port: 40000)).wait()
    // Driven, not waited on: `serve` submits its pipeline setup to the loop,
    // and an `EmbeddedEventLoop` runs what is submitted only when it is run --
    // so waiting here without running it waits for ever.
    let ready = fixture.server.serve(channel)
    fixture.loop.run()
    try ready.wait()

    var both = framed(dnsQuery("gateway.containers.internal"))
    var second = framed(dnsQuery("gateway.containers.internal"))
    both.writeBuffer(&second)
    try channel.writeInbound(both)
    #expect(try replies(from: channel).count == 2, "only one of two pipelined questions was answered")
    _ = try? channel.finish()
}

@Test func aTCPConnectionIsGivenSomethingToCloseItWhenItAsksNothing() throws {
    // A connection costs a descriptor and a slot in the forwarder's limit. A
    // guest that opens one and says nothing is spending both, and RFC 7766
    // §6.2.3 puts the responsibility for that on the server.
    //
    // This asserts that the bound is INSTALLED, not that it fires, and the
    // difference belongs in the name rather than hidden behind one. NIO's
    // `IdleStateHandler` measures elapsed time with `NIODeadline.now()` -- the
    // real clock -- so no amount of advancing this fixture's clock will make it
    // fire, and the version of this test that tried spent an hour of virtual
    // time proving only that. Watching it genuinely time out would mean waiting
    // ten real seconds, which is not a trade this suite makes.
    //
    // What this does catch is the bound being deleted, which is the failure
    // that would actually happen.
    let fixture = try DNSFixture(records: [])
    let channel = EmbeddedChannel(loop: fixture.loop)
    try channel.connect(to: SocketAddress(ipAddress: "192.168.127.2", port: 40000)).wait()
    // Driven, not waited on: `serve` submits its pipeline setup to the loop,
    // and an `EmbeddedEventLoop` runs what is submitted only when it is run --
    // so waiting here without running it waits for ever.
    let ready = fixture.server.serve(channel)
    fixture.loop.run()
    try ready.wait()

    #expect(throws: Never.self) {
        try channel.pipeline.syncOperations.handler(type: IdleStateHandler.self)
    }
    _ = try? channel.finish()
}

// MARK: - Truncation, and the datagram size the asker offered

@Test func aReplyTooLargeForADatagramComesBackTruncated() async throws {
    // Upstream truncates and this relayed whole, so an oversized answer went
    // out as a fragmented datagram -- dropped somewhere, with nobody told why.
    // RFC 1035 §4.2.1 makes TC the way to say "ask again over TCP", which is
    // only worth saying now that there is a TCP listener to ask.
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    let resolver = FakeResolver(address: IPv4Address("93.184.216.34")!, padding: 900)
    let upstream = try await DatagramBootstrap(group: group)
        .channelInitializer { channel in channel.pipeline.addHandler(resolver) }
        .bind(host: "127.0.0.1", port: 0).get()
    var guestSide: Int32 = -1
    let holder = try await forwardingGateway(
        group: group, guestSide: &guestSide, upstream: upstream.localAddress!)

    askOverWire(guestSide, dnsQuery("example.com", id: 0xBEEF))
    let reply = try #require(await awaitReply(guestSide))

    let flags = try #require(
        reply.getInteger(at: reply.readerIndex + 2, endianness: .big, as: UInt16.self))
    #expect(flags & DNSCodec.truncatedFlag != 0, "an oversized reply came back without TC set")
    #expect(reply.readableBytes <= 512, "the truncated reply is \(reply.readableBytes) bytes")
    #expect(
        reply.getInteger(at: reply.readerIndex, endianness: .big, as: UInt16.self) == 0xBEEF,
        "the guest's transaction id did not come back on the truncation")

    try? await upstream.close()
    _ = try? await holder.stack?.shutdown().get()
    _ = try? await holder.link?.close().get()
    close(guestSide)
    try? await group.shutdownGracefully()
    _ = holder.stack
}

@Test func aReplyThatFitsIsNotTruncated() async throws {
    // The positive control for the check above: without it, a resolver that
    // truncated everything would pass it and every answer would cost a second
    // round trip over TCP.
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

    let flags = try #require(
        reply.getInteger(at: reply.readerIndex + 2, endianness: .big, as: UInt16.self))
    #expect(flags & DNSCodec.truncatedFlag == 0, "a reply that fits was truncated anyway")
    #expect(answeredAddress(reply) == IPv4Address("93.184.216.34")!)

    try? await upstream.close()
    _ = try? await holder.stack?.shutdown().get()
    _ = try? await holder.link?.close().get()
    close(guestSide)
    try? await group.shutdownGracefully()
    _ = holder.stack
}

@Test func theAskersOwnDatagramSizeIsHonoured() throws {
    // RFC 6891's OPT record, whose CLASS field carries a size rather than a
    // class. Without reading it every reply over 512 bytes would be truncated,
    // including the ones the asker had said it would take whole.
    let plain = dnsQuery("example.com", id: 1)
    let parsedPlain = try #require(DNSCodec.parseQuery(plain))
    #expect(
        DNSCodec.advertisedUDPSize(in: plain, after: parsedPlain) == 512,
        "a query with no OPT record asks for RFC 1035's 512")

    let large = queryAdvertising(4096, id: 2)
    let parsedLarge = try #require(DNSCodec.parseQuery(large))
    #expect(DNSCodec.advertisedUDPSize(in: large, after: parsedLarge) == 4096)

    // Below the floor is a request nothing has to honour, and honouring it
    // would truncate every answer this gateway gives.
    let tiny = queryAdvertising(20, id: 3)
    let parsedTiny = try #require(DNSCodec.parseQuery(tiny))
    #expect(DNSCodec.advertisedUDPSize(in: tiny, after: parsedTiny) == 512)
}

/// `example.com` A IN with an EDNS0 OPT record advertising `size`.
private func queryAdvertising(_ size: UInt16, id: UInt16) -> ByteBuffer {
    var out = ByteBufferAllocator().buffer(capacity: 64)
    out.writeInteger(id, endianness: .big)
    out.writeInteger(UInt16(0x0100), endianness: .big)
    out.writeInteger(UInt16(1), endianness: .big)  // one question
    out.writeInteger(UInt16(0), endianness: .big)
    out.writeInteger(UInt16(0), endianness: .big)
    out.writeInteger(UInt16(1), endianness: .big)  // one additional: the OPT
    out.writeInteger(UInt8(7))
    out.writeString("example")
    out.writeInteger(UInt8(3))
    out.writeString("com")
    out.writeInteger(UInt8(0))
    out.writeInteger(UInt16(1), endianness: .big)  // A
    out.writeInteger(UInt16(1), endianness: .big)  // IN
    // The OPT pseudo-record: root name, type 41, class = the size.
    out.writeInteger(UInt8(0))
    out.writeInteger(DNSCodec.optRecordType, endianness: .big)
    out.writeInteger(size, endianness: .big)
    out.writeInteger(UInt32(0), endianness: .big)  // extended rcode and flags
    out.writeInteger(UInt16(0), endianness: .big)  // no rdata
    return out
}

@Test func aQuestionOfAnyTypeIsForwardedAndItsAnswerComesBack() async throws {
    // Every other forwarding test here asks for an A record, so a guard on the
    // type anywhere in that path would go unnoticed -- and upstream's own suite
    // resolves CNAME, MX, NS, SRV and TXT through exactly this route.
    //
    // What makes it work is that the reply is relayed rather than rebuilt: this
    // gateway has no opinion about record types it does not serve itself. What
    // could break it is the pending table, which matches an upstream reply
    // against the whole question -- name, TYPE and class -- so that a stolen
    // transaction id is not enough to answer with something else. A type this
    // side mishandled would fail to match and the guest would hear nothing.
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    let resolver = FakeResolver(address: IPv4Address("93.184.216.34")!)
    let upstream = try await DatagramBootstrap(group: group)
        .channelInitializer { channel in channel.pipeline.addHandler(resolver) }
        .bind(host: "127.0.0.1", port: 0).get()
    var guestSide: Int32 = -1
    let holder = try await forwardingGateway(
        group: group, guestSide: &guestSide, upstream: upstream.localAddress!)

    // 16 is TXT, which this gateway neither serves nor understands.
    askOverWire(guestSide, dnsQuery("example.com", id: 0xCAFE, type: 16))
    let reply = try #require(await awaitReply(guestSide))

    #expect(
        reply.getInteger(at: reply.readerIndex, endianness: .big, as: UInt16.self) == 0xCAFE,
        "the guest's transaction id did not come back on a non-A question")
    // Read out of the bytes rather than through `parseQuery`, which takes a
    // QUERY and refuses a response -- as it should, and as the first version of
    // this test found out.
    //
    // `example.com` encodes as 13 bytes, so after the 12-byte header the
    // question's type sits at 25 and the answer count at 6.
    #expect(
        reply.getInteger(at: reply.readerIndex + 25, endianness: .big, as: UInt16.self) == 16,
        "the answer came back for a different question type than was asked")
    #expect(
        (reply.getInteger(at: reply.readerIndex + 6, endianness: .big, as: UInt16.self) ?? 0) > 0,
        "the reply carried no answer at all")

    try? await upstream.close()
    _ = try? await holder.stack?.shutdown().get()
    _ = try? await holder.link?.close().get()
    close(guestSide)
    try? await group.shutdownGracefully()
    _ = holder.stack
}

// MARK: - The TCP framing, as a hostile guest would send it

/// SplitMix64. Local for the same reason `ControlPlaneTests` keeps its own: a
/// generator is cheaper than a dependency between test files.
private struct DNSRandom {
    private var state: UInt64
    init(seed: UInt64) { state = seed }
    mutating func next() -> UInt64 {
        state &+= 0x9E37_79B9_7F4A_7C15
        var z = state
        z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
        z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
        return z ^ (z >> 31)
    }
}

/// One mutation of a framed query. Each is a shape that breaks a
/// length-prefixed reader rather than random noise: a prefix that disagrees
/// with the body, a message split where a reader might assume it is not, two
/// messages run together with the seam moved.
private func mutateFramedQuery(_ input: [UInt8], _ rng: inout DNSRandom) -> [UInt8] {
    guard input.count > 2 else { return input }
    var out = input
    switch rng.next() % 7 {
    case 0:
        out[Int(rng.next() % UInt64(out.count))] ^= UInt8(1 << (rng.next() % 8))
    case 1:
        // A prefix claiming far more than follows: the reader must wait rather
        // than read past the end of what it has.
        out[0] = 0xFF
        out[1] = 0xFF
    case 2:
        // A prefix of nothing at all.
        out[0] = 0
        out[1] = 0
    case 3:
        out = Array(out.prefix(2 + Int(rng.next() % UInt64(out.count - 2))))
    case 4:
        // The same message twice.
        out += out
    case 5:
        // A runt message between the two.
        out.insert(contentsOf: [0x00, 0x01, 0x41], at: 2)
    default:
        // A prefix one shorter than the body, so the tail of one message is
        // read as the head of the next.
        let claimed = UInt16(out.count - 2)
        out[0] = UInt8(truncatingIfNeeded: (claimed &- 1) >> 8)
        out[1] = UInt8(truncatingIfNeeded: claimed &- 1)
    }
    return out
}

@Test func theResolverOverTCPSurvivesWhateverAGuestFrames() throws {
    // A guest opens this connection and chooses every byte on it, so the
    // length-prefixed reader in front of the resolver is as exposed as the
    // datagram parsers `FuzzTests` covers -- and it is newer than they are.
    //
    // The invariant is server-wide rather than per-connection. Garbage on one
    // connection may legitimately leave that one mid-message: a prefix claiming
    // more than was sent is a promise the reader has to keep waiting on, and a
    // valid query appended after it is the body of the message the guest said
    // was coming. What must not happen is that connection taking the resolver
    // down with it, so what is checked is a FRESH connection afterwards.
    let iterations = Int(ProcessInfo.processInfo.environment["NETSTACK_DNSTCP_FUZZ_ITERATIONS"] ?? "") ?? 300
    let seed = UInt64(ProcessInfo.processInfo.environment["NETSTACK_DNSTCP_FUZZ_SEED"] ?? "") ?? 0xD15EA5E
    let fixture = try DNSFixture(records: [
        .init(name: "gateway.containers.internal", address: dnsGateway)
    ])

    func ask(_ bytes: [UInt8]) throws -> Int {
        let channel = EmbeddedChannel(loop: fixture.loop)
        try channel.connect(to: SocketAddress(ipAddress: "192.168.127.2", port: 40000)).wait()
        let ready = fixture.server.serve(channel)
        fixture.loop.run()
        try ready.wait()
        _ = try? channel.writeInbound(ByteBuffer(bytes: bytes))
        var replies = 0
        while let written = ((try? channel.readOutbound(as: ByteBuffer.self)) ?? nil) {
            _ = written
            replies += 1
        }
        _ = try? channel.finish()
        return replies
    }

    let valid = Array(framed(dnsQuery("gateway.containers.internal")).readableBytesView)
    #expect(try ask(valid) == 1, "the fixture could not answer before any of this began")

    var rng = DNSRandom(seed: seed)
    var answered = 0
    for _ in 0..<iterations {
        var bytes = valid
        for _ in 0...(rng.next() % 3) {
            bytes = mutateFramedQuery(bytes, &rng)
        }
        answered += (try? ask(bytes)) ?? 0
    }

    // The companion, inline rather than beside: a corpus the reader rejects at
    // the prefix would leave this test green while exercising nothing, which is
    // the hole `FuzzTests` names in its own and the one the control-plane
    // fuzzer had to have closed for it separately.
    #expect(
        answered > iterations / 10,
        "\(answered) of \(iterations) mutated frames were answered, too few to be reaching the reader")

    // And the resolver is still there for somebody else.
    #expect(try ask(valid) == 1, "a fresh connection stopped being answered")
    fixture.drain()
}

@Test func aMalformedAdditionalSectionAnswersTheFloor() throws {
    // The comment on `advertisedUDPSize` says "anything malformed answers 512",
    // and nothing checked it. It reads the GUEST's query, so every byte it
    // walks is chosen by the guest: an ARCOUNT that lies, a name that never
    // ends, a compression pointer, an rdlength that runs past the buffer. What
    // it must not do is read past what it has, loop, or return a size the asker
    // never offered.
    //
    // Written because the last commit found a claim of mine that was wrong. The
    // difference between a comment and a check is whether anyone has tried.
    func query(_ trailer: [UInt8], additional: UInt16) -> ByteBuffer {
        var out = ByteBufferAllocator().buffer(capacity: 64)
        out.writeInteger(UInt16(0x4242), endianness: .big)
        out.writeInteger(UInt16(0x0100), endianness: .big)
        out.writeInteger(UInt16(1), endianness: .big)
        out.writeInteger(UInt16(0), endianness: .big)
        out.writeInteger(UInt16(0), endianness: .big)
        out.writeInteger(additional, endianness: .big)
        out.writeInteger(UInt8(7))
        out.writeString("example")
        out.writeInteger(UInt8(3))
        out.writeString("com")
        out.writeInteger(UInt8(0))
        out.writeInteger(UInt16(1), endianness: .big)
        out.writeInteger(UInt16(1), endianness: .big)
        out.writeBytes(trailer)
        return out
    }

    let cases: [(String, ByteBuffer)] = [
        ("an ARCOUNT with nothing behind it", query([], additional: 1)),
        ("an ARCOUNT of sixty-five thousand", query([], additional: 0xFFFF)),
        ("a name that never ends", query([UInt8](repeating: 0x3F, count: 40), additional: 1)),
        ("a compression pointer where a record should be", query([0xC0, 0x0C], additional: 1)),
        ("a record cut off mid-type", query([0x00, 0x00], additional: 1)),
    ]

    for (description, malformed) in cases {
        let parsed = try #require(DNSCodec.parseQuery(malformed), "could not parse \(description)")
        let size = DNSCodec.advertisedUDPSize(in: malformed, after: parsed)
        #expect(size == 512, "\(description) advertised \(size) rather than the floor")
    }

    // The positive control beside them: a well-formed OPT record is still read,
    // so the cases above are answering the floor because they are malformed
    // rather than because nothing is ever read.
    let good = queryAdvertising(4096, id: 9)
    let parsedGood = try #require(DNSCodec.parseQuery(good))
    #expect(DNSCodec.advertisedUDPSize(in: good, after: parsedGood) == 4096)

    // And one that looks malformed and is not, which is why it sits here rather
    // than in the list above -- where it was, until it failed.
    //
    // The record's rdlength claims sixty-five thousand bytes that are not
    // there, but the size an asker offers is the CLASS field, and that is
    // present and readable. Nothing reads the rdata, and the walk returns
    // before rdlength is used for anything, so the lie changes nothing this
    // code does. Answering the floor here would truncate replies the asker had
    // said it would take, on the strength of a field nobody looks at.
    let lyingLength = query(
        [0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF], additional: 1)
    let parsedLying = try #require(DNSCodec.parseQuery(lyingLength))
    #expect(
        DNSCodec.advertisedUDPSize(in: lyingLength, after: parsedLying) == 4096,
        "a readable OPT header was ignored because a field nothing reads was wrong")
}
