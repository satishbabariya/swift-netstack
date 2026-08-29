import NIOCore
import NIOEmbedded
import Testing

@testable import Netstack

private struct Fixture {
    let nic: NIC
    let link: RecordingEndpoint
    let ip: IPv4Protocol
    let clock: ManualClock
}

private func makeFixture(promiscuous: Bool = true, spoofing: Bool = true) -> Fixture {
    let clock = ManualClock()
    let link = RecordingEndpoint(eventLoop: EmbeddedEventLoop(), linkAddress: MACAddress("5a:94:ef:e4:0c:ee")!)
    let nic = NIC(id: 1, link: link)
    nic.addAddress(IPv4Address("192.168.127.1")!, prefixLength: 24)
    nic.acceptsAnyDestination = promiscuous
    nic.allowsAnySource = spoofing

    let routes = RouteTable()
    routes.register(nic)
    routes.add(Route(destination: IPv4Subnet(cidr: "192.168.127.0/24")!, gateway: nil, nicID: 1))

    let cache = ARPCache(clock: clock)
    cache.record(IPv4Address("192.168.127.2")!, MACAddress("0a:0b:0c:0d:0e:0f")!)
    let responder = ARPResponder(nic: nic, cache: cache, allocator: ByteBufferAllocator())
    let ip = IPv4Protocol(
        nic: nic, routes: routes, arpCache: cache, arpResponder: responder,
        reassembler: Reassembler(clock: clock), allocator: ByteBufferAllocator())
    nic.setHandler(for: .ipv4) { packet, ethernet in ip.handleInbound(packet, ethernet) }
    return Fixture(nic: nic, link: link, ip: ip, clock: clock)
}

private func ipFrame(to destination: String, protocolNumber: UInt8, payload: [UInt8], ttl: UInt8 = 64) -> ByteBuffer {
    var ipPacket = PacketBuffer(allocator: ByteBufferAllocator(), payload: ByteBuffer(bytes: payload))
    var header = IPv4Header(
        source: IPv4Address("192.168.127.2")!,
        destination: IPv4Address(destination)!,
        protocolNumber: IPProtocol(rawValue: protocolNumber),
        payloadLength: payload.count
    )
    header.ttl = ttl
    header.prepend(to: &ipPacket)

    var frame = ByteBuffer()
    frame.writeBytes(MACAddress("5a:94:ef:e4:0c:ee")!.bytes)
    frame.writeBytes(MACAddress("0a:0b:0c:0d:0e:0f")!.bytes)
    frame.writeInteger(UInt16(0x0800), endianness: .big)
    var body = ipPacket.frame
    frame.writeBuffer(&body)
    return frame
}

@Test func deliversToARegisteredProtocolHandler() {
    let f = makeFixture()
    var seen: [UInt8] = []
    var seenSource: IPv4Address?
    f.ip.setHandler(for: .udp) { header, payload in
        seenSource = header.source
        seen = Array(payload.readableBytesView)
    }
    f.link.inject(ipFrame(to: "192.168.127.1", protocolNumber: 17, payload: [0xaa, 0xbb]))

    #expect(seen == [0xaa, 0xbb])
    #expect(seenSource == IPv4Address("192.168.127.2"))
}

@Test func deliversPacketsForOtherHostsWhenPromiscuous() {
    let f = makeFixture(promiscuous: true)
    var count = 0
    f.ip.setHandler(for: .tcp) { _, _ in count += 1 }
    // The gateway terminating a guest connection to the public internet.
    f.link.inject(ipFrame(to: "93.184.216.34", protocolNumber: 6, payload: [0x01]))
    #expect(count == 1)
}

@Test func dropsPacketsForOtherHostsWhenNotPromiscuous() {
    let f = makeFixture(promiscuous: false)
    var count = 0
    f.ip.setHandler(for: .tcp) { _, _ in count += 1 }
    f.link.inject(ipFrame(to: "93.184.216.34", protocolNumber: 6, payload: [0x01]))
    #expect(count == 0)
}

@Test func answersAnEchoRequest() {
    let f = makeFixture()
    var echo = ByteBuffer()
    echo.writeInteger(UInt8(8))
    echo.writeInteger(UInt8(0))
    echo.writeInteger(UInt16(0), endianness: .big)
    echo.writeInteger(UInt16(0xabcd), endianness: .big)
    echo.writeInteger(UInt16(1), endianness: .big)
    echo.writeBytes([0xde, 0xad])
    let checksum = echo.withUnsafeReadableBytes { Checksum.compute($0) }
    echo.setInteger(checksum, at: 2, endianness: .big)

    f.link.inject(ipFrame(to: "192.168.127.1", protocolNumber: 1, payload: Array(echo.readableBytesView)))

    let frames = f.link.drainTransmitted()
    #expect(frames.count == 1)
    var reply = PacketBuffer(received: frames[0])
    _ = EthernetHeader.parse(&reply)
    let header = IPv4Header.parse(&reply)
    #expect(header?.protocolNumber == .icmp)
    #expect(header?.source == IPv4Address("192.168.127.1"))
    #expect(header?.destination == IPv4Address("192.168.127.2"))
    let icmp = ICMPv4Header.parse(&reply)
    #expect(icmp?.type == .echoReply)
    #expect(icmp?.identifier == 0xabcd)
    #expect(Array(reply.payload.readableBytesView) == [0xde, 0xad])
}

@Test func dropsAPacketWhoseTTLHasExpired() {
    let f = makeFixture()
    var count = 0
    f.ip.setHandler(for: .udp) { _, _ in count += 1 }
    f.link.inject(ipFrame(to: "93.184.216.34", protocolNumber: 17, payload: [0x01], ttl: 0))
    #expect(count == 0)
}

@Test func sendPrependsAHeaderAndResolvesTheLinkAddress() throws {
    let f = makeFixture()
    try f.ip.send(
        payload: ByteBuffer(bytes: [0x01, 0x02]),
        to: IPv4Address("192.168.127.2")!,
        from: nil,
        protocolNumber: .udp)

    let frames = f.link.drainTransmitted()
    #expect(frames.count == 1)
    var packet = PacketBuffer(received: frames[0])
    let ethernet = EthernetHeader.parse(&packet)
    #expect(ethernet?.destination == MACAddress("0a:0b:0c:0d:0e:0f"))
    let header = IPv4Header.parse(&packet)
    #expect(header?.source == IPv4Address("192.168.127.1"))
    #expect(header?.destination == IPv4Address("192.168.127.2"))
    #expect(Array(packet.payload.readableBytesView) == [0x01, 0x02])
}

@Test func sendHonoursASpoofedSource() throws {
    let f = makeFixture(spoofing: true)
    try f.ip.send(
        payload: ByteBuffer(bytes: [0x01]),
        to: IPv4Address("192.168.127.2")!,
        from: IPv4Address("93.184.216.34"),
        protocolNumber: .tcp)

    var packet = PacketBuffer(received: f.link.drainTransmitted()[0])
    _ = EthernetHeader.parse(&packet)
    let ipHeader = IPv4Header.parse(&packet)
    #expect(ipHeader?.source == IPv4Address("93.184.216.34"))
}

@Test func sendThrowsRatherThanSubstitutingARefusedSource() throws {
    // Without spoofing, a `from:` address the NIC does not own cannot be
    // honoured. `RouteTable.lookup` still resolves the route — the
    // destination itself is perfectly reachable — but `send` must refuse to
    // transmit from the wrong address rather than silently answering as the
    // NIC's own primary address instead.
    let f = makeFixture(spoofing: false)
    #expect(throws: StackError.noRoute) {
        try f.ip.send(
            payload: ByteBuffer(bytes: [0x01]),
            to: IPv4Address("192.168.127.2")!,
            from: IPv4Address("93.184.216.34"),
            protocolNumber: .tcp)
    }
    #expect(f.link.drainTransmitted().isEmpty)
}

@Test func promiscuousWithoutSpoofingDoesNotAnswerAnEchoToAForeignAddressFromTheWrongSource() {
    // The real scenario the fix targets: promiscuous ON (the gateway
    // accepts frames addressed to hosts it does not own, so it can
    // terminate a guest's connection to an arbitrary destination) but
    // spoofing OFF (it may not transmit FROM an address it does not own).
    // An echo request arrives addressed to a foreign IP that is not the
    // NIC's own. Before this fix, `handleICMP`'s `try? send(... from:
    // header.destination ...)` silently substituted the NIC's own primary
    // address as the reply's source instead of the address that was
    // actually pinged — answering from the WRONG source. It must now not
    // answer at all.
    let f = makeFixture(promiscuous: true, spoofing: false)
    var echo = ByteBuffer()
    echo.writeInteger(UInt8(8))
    echo.writeInteger(UInt8(0))
    echo.writeInteger(UInt16(0), endianness: .big)
    echo.writeInteger(UInt16(0xabcd), endianness: .big)
    echo.writeInteger(UInt16(1), endianness: .big)
    echo.writeBytes([0xde, 0xad])
    let checksum = echo.withUnsafeReadableBytes { Checksum.compute($0) }
    echo.setInteger(checksum, at: 2, endianness: .big)

    // 203.0.113.9 is not an address this NIC owns.
    f.link.inject(ipFrame(to: "203.0.113.9", protocolNumber: 1, payload: Array(echo.readableBytesView)))

    #expect(f.link.drainTransmitted().isEmpty)
}

@Test func sendFragmentsAnOversizedPayload() throws {
    let f = makeFixture()
    try f.ip.send(
        payload: ByteBuffer(bytes: Array(repeating: UInt8(0xaa), count: 3000)),
        to: IPv4Address("192.168.127.2")!,
        from: nil,
        protocolNumber: .udp)

    let frames = f.link.drainTransmitted()
    #expect(frames.count == 3)
    // Every fragment shares one identification, distinct from the next datagram's.
    var ids: Set<UInt16> = []
    for frame in frames {
        var packet = PacketBuffer(received: frame)
        _ = EthernetHeader.parse(&packet)
        ids.insert(IPv4Header.parse(&packet)!.identification)
    }
    #expect(ids.count == 1)
}

@Test func sendWithNoRouteThrows() {
    let f = makeFixture()
    #expect(throws: StackError.noRoute) {
        try f.ip.send(payload: ByteBuffer(bytes: [0x01]), to: IPv4Address("8.8.8.8")!, from: nil, protocolNumber: .udp)
    }
}

@Test func sendWithAnUnresolvedNextHopRequestsARPAndThrows() {
    let f = makeFixture()
    #expect(throws: StackError.noRoute) {
        try f.ip.send(payload: ByteBuffer(bytes: [0x01]), to: IPv4Address("192.168.127.55")!, from: nil, protocolNumber: .udp)
    }
    // An ARP request went out for the unresolved address.
    let frames = f.link.drainTransmitted()
    #expect(frames.count == 1)
    var packet = PacketBuffer(received: frames[0])
    let ethernetHeader = EthernetHeader.parse(&packet)
    #expect(ethernetHeader?.etherType == .arp)
    let arp = ARPPacket.parse(&packet)
    #expect(arp?.targetIP == IPv4Address("192.168.127.55"))
}

// `IPv4Header.init(source:destination:protocolNumber:payloadLength:)` computes
// `UInt16(minimumLength + payloadLength)` with a non-failable conversion that
// TRAPS the process if the total exceeds 65535. `send()` takes an arbitrary
// caller-supplied payload, so it must reject an oversized one before ever
// building a header, rather than letting that conversion crash the process.
@Test func sendRejectsAPayloadTooLargeToFitAnIPv4Datagram() {
    let f = makeFixture()
    var oversized = ByteBufferAllocator().buffer(capacity: 70000)
    oversized.writeRepeatingByte(0xaa, count: 70000)
    #expect(throws: StackError.messageTooLong) {
        try f.ip.send(
            payload: oversized,
            to: IPv4Address("192.168.127.2")!,
            from: nil,
            protocolNumber: .udp)
    }

    // Pin the exact edge: 65515 = 65535 - IPv4Header.minimumLength is the
    // largest payload that still fits an IPv4 datagram, and 65516 is the
    // smallest that does not. The 70000-byte case above is far past either
    // and would not catch an off-by-one at the boundary itself.
    var atTheLimit = ByteBufferAllocator().buffer(capacity: 65515)
    atTheLimit.writeRepeatingByte(0xaa, count: 65515)
    do {
        try f.ip.send(
            payload: atTheLimit,
            to: IPv4Address("192.168.127.2")!,
            from: nil,
            protocolNumber: .udp)
    } catch let error as StackError {
        #expect(error != .messageTooLong)
    } catch {
        // Anything other than StackError is unexpected here, but only
        // `.messageTooLong` is what this test is pinning against.
    }

    var oneOverTheLimit = ByteBufferAllocator().buffer(capacity: 65516)
    oneOverTheLimit.writeRepeatingByte(0xaa, count: 65516)
    #expect(throws: StackError.messageTooLong) {
        try f.ip.send(
            payload: oneOverTheLimit,
            to: IPv4Address("192.168.127.2")!,
            from: nil,
            protocolNumber: .udp)
    }
}

@Test func aBroadcastGoesToTheBroadcastLinkAddressWithoutAsking() throws {
    // ARP cannot resolve 255.255.255.255: there is no host there to answer. A
    // broadcast that went through the cache would emit an ARP request per
    // attempt and never send anything.
    //
    // Not hypothetical. It is what a DHCP offer is -- broadcast precisely
    // BECAUSE the client does not have an address yet and therefore cannot
    // answer an ARP for one -- so without this the gateway can never tell a
    // guest what its address is.
    let fixture = makeFixture()
    _ = fixture.link.drainTransmitted()
    try fixture.ip.send(
        payload: ByteBuffer(bytes: [1, 2, 3, 4]), to: .broadcast, from: nil, protocolNumber: .udp)

    let frames = fixture.link.drainTransmitted()
    #expect(frames.count == 1, "the broadcast produced \(frames.count) frames rather than one")
    var packet = PacketBuffer(received: try #require(frames.first))
    let ethernet = try #require(EthernetHeader.parse(&packet))
    #expect(ethernet.etherType == .ipv4, "an ARP request went out instead of the datagram")
    #expect(ethernet.destination == .broadcast)
    let ip = try #require(IPv4Header.parse(&packet))
    #expect(ip.destination == .broadcast)
}
