import NIOCore
import NIOEmbedded
import Testing

@testable import Netstack

// How a guest learns its address, its route, and where to ask about names.
// Every field in a request is guest-supplied, so the tests that matter are the
// ones about what the server does with a request it did not expect.

private let dhcpGuestMAC = MACAddress("0a:0b:0c:0d:0e:0f")!
private let dhcpGatewayMAC = MACAddress("5a:94:ef:e4:0c:ee")!
private let dhcpGateway = IPv4Address("192.168.127.1")!

private final class DHCPFixture {
    let loop = EmbeddedEventLoop()
    let link: RecordingEndpoint
    let stack: Stack
    let server: DHCPServer

    init(
        cidr: String = "192.168.127.0/24", staticLeases: [MACAddress: IPv4Address] = [:],
        searchDomains: [String] = []
    ) throws {
        link = RecordingEndpoint(eventLoop: loop, linkAddress: dhcpGatewayMAC)
        stack = Stack(
            link: link,
            configuration: Stack.Configuration(
                gatewayAddress: dhcpGateway, subnet: IPv4Subnet(cidr: cidr)!),
            clock: ManualClock())
        stack.start()
        server = try DHCPServer(
            stack: stack, staticLeases: staticLeases, searchDomains: searchDomains)
    }

    /// Deliver a client message as though it arrived on the wire, broadcast
    /// from 0.0.0.0 as a client without an address must.
    func send(_ message: ByteBuffer, from source: IPv4Address = IPv4Address(0)) {
        let allocator = ByteBufferAllocator()
        let datagram = UDPHeader.serialize(
            payload: message, source: source, destination: IPv4Address(0xFFFF_FFFF),
            sourcePort: DHCPServer.clientPort, destinationPort: DHCPServer.serverPort, allocator: allocator)!
        var packet = PacketBuffer(allocator: allocator, payload: datagram)
        IPv4Header(
            source: source, destination: IPv4Address(0xFFFF_FFFF), protocolNumber: .udp,
            payloadLength: datagram.readableBytes
        ).prepend(to: &packet)
        EthernetHeader(destination: dhcpGatewayMAC, source: dhcpGuestMAC, etherType: .ipv4)
            .prepend(to: &packet)
        link.inject(packet.frame)
    }

    /// Every DHCP reply emitted since the last drain.
    func replies() -> [DHCPMessage] {
        var out: [DHCPMessage] = []
        for frame in link.drainTransmitted() {
            var packet = PacketBuffer(received: frame)
            guard let ethernet = EthernetHeader.parse(&packet), ethernet.etherType == .ipv4 else { continue }
            guard let ip = IPv4Header.parse(&packet), ip.protocolNumber == .udp else { continue }
            guard let udp = UDPHeader.parse(&packet, header: ip), udp.destinationPort == DHCPServer.clientPort
            else { continue }
            if let message = DHCPCodec.parse(packet.payload) { out.append(message) }
        }
        return out
    }

    /// DISCOVER from one hardware address, and the address it is offered.
    func discover(from hardware: MACAddress, transaction: UInt32 = 0x1234_5678) -> IPv4Address? {
        send(clientMessage(type: .discover, transaction: transaction, hardware: hardware))
        return replies().first { $0.messageType == .offer }?.yourAddress
    }

    /// The options carried by the offer, by code.
    func discoverOptions(from hardware: MACAddress) -> [UInt8: [UInt8]]? {
        send(clientMessage(type: .discover, hardware: hardware))
        guard let raw = rawReplies().first else { return nil }
        return optionValues(in: raw)
    }

    func drain() {
        server.close()
        loop.advanceTime(by: .hours(1))
        _ = link.drainTransmitted()
    }
}

/// A client message, built by hand so the tests are not checking this package's
/// serializer against itself.
private func clientMessage(
    type: DHCPMessage.MessageType, transaction: UInt32 = 0x1234_5678,
    hardware: MACAddress = dhcpGuestMAC, requested: IPv4Address? = nil, serverIdentifier: IPv4Address? = nil
) -> ByteBuffer {
    var buffer = ByteBuffer()
    buffer.writeInteger(UInt8(1))  // BOOTREQUEST
    buffer.writeInteger(UInt8(1))  // ethernet
    buffer.writeInteger(UInt8(6))
    buffer.writeInteger(UInt8(0))
    buffer.writeInteger(transaction, endianness: .big)
    buffer.writeInteger(UInt16(0), endianness: .big)
    buffer.writeInteger(UInt16(0x8000), endianness: .big)  // broadcast flag
    buffer.writeBytes([UInt8](repeating: 0, count: 16))  // ciaddr, yiaddr, siaddr, giaddr
    buffer.writeBytes(hardware.bytes)
    buffer.writeBytes([UInt8](repeating: 0, count: 10))
    buffer.writeBytes([UInt8](repeating: 0, count: 64 + 128))
    buffer.writeBytes([99, 130, 83, 99])
    buffer.writeBytes([53, 1, type.rawValue])
    if let requested { buffer.writeBytes([50, 4] + requested.bytes) }
    if let serverIdentifier { buffer.writeBytes([54, 4] + serverIdentifier.bytes) }
    buffer.writeInteger(UInt8(255))
    return buffer
}

@Test func aDiscoverIsAnsweredWithAnOfferFromTheSubnet() throws {
    let fixture = try DHCPFixture()
    defer { fixture.drain() }

    fixture.send(clientMessage(type: .discover))

    let replies = fixture.replies()
    #expect(replies.count == 1)
    let offer = try #require(replies.first)
    #expect(offer.messageType == .offer)
    #expect(offer.operation == .reply)
    #expect(offer.transaction == 0x1234_5678, "the client matches replies by transaction")
    #expect(IPv4Subnet(cidr: "192.168.127.0/24")!.contains(offer.yourAddress))
    #expect(offer.yourAddress != dhcpGateway, "the gateway offered its own address")
    #expect(offer.serverAddress == dhcpGateway)
}

@Test func aRequestIsAcknowledgedWithTheSameAddressTheOfferNamed() throws {
    let fixture = try DHCPFixture()
    defer { fixture.drain() }

    fixture.send(clientMessage(type: .discover))
    let offered = try #require(fixture.replies().first).yourAddress

    fixture.send(clientMessage(type: .request, requested: offered))

    let ack = try #require(fixture.replies().first)
    #expect(ack.messageType == .ack)
    #expect(ack.yourAddress == offered, "the acknowledged address is not the offered one")
}

@Test func theSameHardwareAddressKeepsItsLeaseAcrossAReboot() throws {
    // Why the lease is keyed on hardware rather than on the transaction: a
    // guest that reboots and starts a fresh DISCOVER must not be renumbered,
    // because a forwarded port pointing at its old address would stop working
    // and nothing would say why.
    let fixture = try DHCPFixture()
    defer { fixture.drain() }

    fixture.send(clientMessage(type: .discover, transaction: 1))
    let first = try #require(fixture.replies().first).yourAddress
    fixture.send(clientMessage(type: .discover, transaction: 2))
    let second = try #require(fixture.replies().first).yourAddress

    #expect(first == second)
}

@Test func twoGuestsGetTwoAddresses() throws {
    // The negative control for the test above. Without it, a server that
    // returned one fixed address to everybody would pass it.
    let fixture = try DHCPFixture()
    defer { fixture.drain() }

    fixture.send(clientMessage(type: .discover, hardware: MACAddress("02:00:00:00:00:01")!))
    let first = try #require(fixture.replies().first).yourAddress
    fixture.send(clientMessage(type: .discover, hardware: MACAddress("02:00:00:00:00:02")!))
    let second = try #require(fixture.replies().first).yourAddress

    #expect(first != second)
}

@Test func anExhaustedPoolAnswersNothingRatherThanEvictingALease() throws {
    // Refusing is worse for the guest that asked and better for the one that
    // already has an address. Evicting the oldest lease to serve a new request
    // lets a guest with two hardware addresses take an address away from
    // itself, which presents as a machine that intermittently loses its
    // network.
    //
    // A /30 has exactly two usable addresses and the gateway holds one, so the
    // pool is one deep.
    let fixture = try DHCPFixture(cidr: "192.168.127.0/30")
    defer { fixture.drain() }

    fixture.send(clientMessage(type: .discover, hardware: MACAddress("02:00:00:00:00:01")!))
    let leased = try #require(fixture.replies().first).yourAddress

    fixture.send(clientMessage(type: .discover, hardware: MACAddress("02:00:00:00:00:02")!))
    #expect(fixture.replies().isEmpty, "the second guest was served from an empty pool")
    #expect(fixture.server.exhausted == 1)

    // And the first guest still has what it was given.
    fixture.send(clientMessage(type: .discover, hardware: MACAddress("02:00:00:00:00:01")!))
    #expect(try #require(fixture.replies().first).yourAddress == leased, "the lease was evicted after all")
}

@Test func aRequestForAnAddressTheGuestWasNotOfferedIsRefused() throws {
    // RFC 2131 §4.3.2's NAK. Quietly acknowledging a different address than the
    // one asked for leaves the client configured with an address this gateway
    // will not route, and nothing tells it so.
    let fixture = try DHCPFixture()
    defer { fixture.drain() }

    fixture.send(clientMessage(type: .discover))
    _ = fixture.replies()

    fixture.send(clientMessage(type: .request, requested: IPv4Address("192.168.127.222")!))

    let reply = try #require(fixture.replies().first)
    #expect(reply.messageType == .nak)
}

@Test func aRequestAddressedToAnotherServerIsIgnored() throws {
    // RFC 2131 §4.3.2. On a wire with one server this never happens; the check
    // costs a comparison and removes the case where two gateways hand one
    // client two addresses.
    let fixture = try DHCPFixture()
    defer { fixture.drain() }

    fixture.send(clientMessage(type: .discover))
    _ = fixture.replies()

    fixture.send(clientMessage(type: .request, serverIdentifier: IPv4Address("192.168.127.99")!))

    #expect(fixture.replies().isEmpty, "the gateway answered for a server that is not it")
}

@Test func aReleaseReturnsTheAddressToThePool() throws {
    let fixture = try DHCPFixture(cidr: "192.168.127.0/30")
    defer { fixture.drain() }

    fixture.send(clientMessage(type: .discover, hardware: MACAddress("02:00:00:00:00:01")!))
    _ = fixture.replies()
    fixture.send(clientMessage(type: .release, hardware: MACAddress("02:00:00:00:00:01")!))
    _ = fixture.replies()

    fixture.send(clientMessage(type: .discover, hardware: MACAddress("02:00:00:00:00:02")!))
    #expect(!fixture.replies().isEmpty, "the released address was not reusable")
}

@Test func theOfferCarriesTheRouteTheResolverAndTheMtu() throws {
    // A guest that gets an address and no route has a network it cannot use, and
    // the failure looks like a routing problem rather than a DHCP one.
    let fixture = try DHCPFixture()
    defer { fixture.drain() }

    fixture.send(clientMessage(type: .discover))
    let raw = try #require(fixture.rawReplies().first)

    let options = optionCodes(in: raw)
    #expect(options.contains(1), "no subnet mask")
    #expect(options.contains(3), "no router")
    #expect(options.contains(6), "no resolver")
    #expect(options.contains(51), "no lease time")
    #expect(options.contains(26), "no interface MTU")
}

// MARK: - Parser bounds, which is where a hostile guest reaches first

@Test func aTruncatedMessageIsDroppedRatherThanPartlyParsed() {
    var buffer = ByteBuffer()
    buffer.writeBytes([UInt8](repeating: 0, count: 100))
    #expect(DHCPCodec.parse(buffer) == nil)
}

@Test func aMessageWithoutTheMagicCookieIsNotDhcp() {
    var buffer = clientMessage(type: .discover)
    // Overwrite the cookie in place, leaving everything else valid.
    buffer.setBytes([0, 0, 0, 0], at: DHCPMessage.fixedLength)
    #expect(DHCPCodec.parse(buffer) == nil)
}

@Test func theOptionWalkStopsAtItsOwnBoundRatherThanTheDatagramsSize() {
    // The bound that is not in the RFC, which is why it is here.
    //
    // The walk terminates either way -- the datagram is finite -- so the honest
    // statement of what this buys is narrower than "it stops": it stops after a
    // bounded amount of work rather than after however much the guest chose to
    // send, and a 64 KB datagram of three-byte options is 20,000 iterations
    // this declines to run.
    //
    // Asserted by putting a real option PAST the cap: what is beyond it is not
    // read, which is the observable form of the walk having stopped.
    var buffer = clientMessage(type: .discover)
    buffer.moveWriterIndex(to: buffer.writerIndex - 1)  // drop the 255
    while buffer.readableBytes < DHCPMessage.fixedLength + 4 + DHCPMessage.maximumOptionBytes {
        buffer.writeBytes([250, 1, 0])
    }
    buffer.writeBytes([50, 4] + IPv4Address("192.168.127.99")!.bytes)
    buffer.writeInteger(UInt8(255))

    let parsed = DHCPCodec.parse(buffer)
    #expect(parsed?.messageType == .discover, "the message before the padding was lost")
    #expect(parsed?.requestedAddress == nil, "an option past the cap was read: the walk did not stop")
}

@Test func anOptionClaimingMoreBytesThanRemainStopsTheWalk() {
    var buffer = clientMessage(type: .discover)
    buffer.moveWriterIndex(to: buffer.writerIndex - 1)
    buffer.writeBytes([50, 200, 1, 2, 3])  // claims 200, supplies 3

    let parsed = DHCPCodec.parse(buffer)
    #expect(parsed?.messageType == .discover)
    #expect(parsed?.requestedAddress == nil, "a truncated option was read anyway")
}

@Test func aClientClaimingANonEthernetHardwareTypeIsDropped() {
    // Guessing would put a wrong address in the lease table under a key nothing
    // will ever match again -- an address leaked from the pool per datagram.
    var buffer = clientMessage(type: .discover)
    buffer.setInteger(UInt8(6), at: 1)  // IEEE 802 rather than ethernet
    #expect(DHCPCodec.parse(buffer) == nil)
}

private func optionCodes(in buffer: ByteBuffer) -> Set<UInt8> {
    var buffer = buffer
    guard buffer.readSlice(length: DHCPMessage.fixedLength + 4) != nil else { return [] }
    var codes: Set<UInt8> = []
    while let code = buffer.readInteger(as: UInt8.self), code != 255 {
        if code == 0 { continue }
        guard let length = buffer.readInteger(as: UInt8.self),
            buffer.readSlice(length: Int(length)) != nil
        else { break }
        codes.insert(code)
    }
    return codes
}

extension DHCPFixture {
    /// Replies as raw payloads, for tests that look at the options rather than
    /// at the fields the parser keeps.
    func rawReplies() -> [ByteBuffer] {
        var out: [ByteBuffer] = []
        for frame in link.drainTransmitted() {
            var packet = PacketBuffer(received: frame)
            guard let ethernet = EthernetHeader.parse(&packet), ethernet.etherType == .ipv4 else { continue }
            guard let ip = IPv4Header.parse(&packet), ip.protocolNumber == .udp else { continue }
            guard let udp = UDPHeader.parse(&packet, header: ip), udp.destinationPort == DHCPServer.clientPort
            else { continue }
            out.append(packet.payload)
        }
        return out
    }
}

@Test func aStaticLeaseIsHonouredAndKeptOutOfThePool() throws {
    // How a caller gives a guest a known address before the guest has ever
    // booted, which is what makes "forward host port 8080 to the guest" possible
    // without first asking where the guest ended up.
    //
    // The order here is the test. The pinned guest asks **last**, after every
    // other address is gone -- because that is the case the pool exclusion is
    // for and the only one it is needed in. Ask the pinned guest first and its
    // address is in `leases`, which the allocator already skips; the exclusion
    // then changes nothing and a test written that way passes with it deleted.
    //
    // A /28 rather than a /24 so the pool can actually be exhausted: with 253
    // addresses, handing out a few dozen never reaches the pinned one.
    let pinned = IPv4Address("192.168.127.5")!
    let known = MACAddress("0a:00:00:00:77:77")!
    let harness = try DHCPFixture(cidr: "192.168.127.0/28", staticLeases: [known: pinned])
    defer { harness.drain() }

    var handedOut: Set<IPv4Address> = []
    for index in 0..<32 {
        let mac = MACAddress(bytes: [0x0a, 0, 0, 0, 0x99, UInt8(index)])!
        if let address = harness.discover(from: mac) { handedOut.insert(address) }
    }
    #expect(!handedOut.isEmpty, "no addresses were handed out at all")
    #expect(
        harness.discover(from: MACAddress("0a:00:00:00:fe:fe")!) == nil,
        "the pool was not exhausted, so the check below proves nothing")
    #expect(
        !handedOut.contains(pinned),
        "the pinned address was handed to a guest that booted first")

    // And it is still there for the guest it was pinned to, which arrives to
    // find every other address taken.
    #expect(harness.discover(from: known) == pinned, "the static lease was ignored")
}

@Test func searchDomainsAreOfferedAsOption119() throws {
    // RFC 3397, so a guest can resolve `web` as `web.svc.test`. Encoded as DNS
    // labels rather than text: `3svc4test0`.
    let harness = try DHCPFixture(searchDomains: ["svc.test", "example.com"])
    defer { harness.drain() }
    let options = try #require(harness.discoverOptions(from: MACAddress("0a:00:00:00:aa:bb")!))
    let list = try #require(options[119], "no search list was offered")

    #expect(
        list == [3, 115, 118, 99, 4, 116, 101, 115, 116, 0]
            + [7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109, 0])
}

@Test func noSearchDomainsMeansNoOptionRatherThanAnEmptyOne() throws {
    // An empty option is not the same as an absent one: some clients read a
    // zero-length 119 as "the search list is empty", which overrides whatever
    // they were configured with. Saying nothing leaves them alone.
    let harness = try DHCPFixture()
    defer { harness.drain() }
    let options = try #require(harness.discoverOptions(from: MACAddress("0a:00:00:00:cc:dd")!))
    #expect(options[119] == nil)
    // The floor: the reply carried its ordinary options, so this is the search
    // list being absent rather than the reply being empty.
    #expect(options[53] != nil, "the offer had no message type")
    #expect(options[3] != nil, "the offer had no router")
}

@Test func aLabelTooLongToEncodeIsSkippedRatherThanTruncated() throws {
    // A DNS label's length byte has two reserved top bits, so 63 is the most it
    // can express. Truncating to fit would put a different name in the guest's
    // search list -- one an operator never wrote and cannot see -- and a name
    // that resolves is worse than a name that is missing.
    let long = String(repeating: "a", count: 64)
    let encoded = DHCPServer.encodeSearchList(["\(long).test", "ok.test"])

    #expect(!encoded.contains(64), "an unencodable label was written anyway")
    // The rest of the list still arrives.
    #expect(encoded.suffix(9) == [2, 111, 107, 4, 116, 101, 115, 116, 0])
}

/// Every option in a reply, by code, with its bytes. `optionCodes` above answers
/// "was it there"; several tests need to know what it said.
private func optionValues(in buffer: ByteBuffer) -> [UInt8: [UInt8]] {
    var buffer = buffer
    guard buffer.readSlice(length: DHCPMessage.fixedLength + 4) != nil else { return [:] }
    var out: [UInt8: [UInt8]] = [:]
    while let code = buffer.readInteger(as: UInt8.self), code != 255 {
        if code == 0 { continue }
        guard let length = buffer.readInteger(as: UInt8.self),
            let value = buffer.readBytes(length: Int(length))
        else { break }
        out[code] = value
    }
    return out
}

// The pool must not contain an address the gateway answers for.
//
// It contained the HOST address -- the one `host.containers.internal` resolves
// to, and the one NAT translates to the host's loopback. A guest handed it
// believes it is the host: the name resolves to itself, and its ARP for that
// address collides with the gateway's.
//
// On the default /24 that takes two hundred and fifty guests, so nothing ever
// saw it. On a /29 it is the fifth, and the fifth is where this looks:
//
//     guest 4: leased 192.168.127.5
//     guest 5: leased 192.168.127.6   <- the host's address
@Test func theLeasePoolNeverContainsAnAddressTheGatewayAnswersFor() {
    let subnet = IPv4Subnet(cidr: "192.168.127.0/29")!
    let gateway = subnet.firstUsable
    let host = subnet.lastUsable
    let virtual = IPv4Address("192.168.127.4")!

    let pool = DHCPServer.addresses(in: subnet, excluding: [gateway, host, virtual])

    #expect(!pool.contains(gateway), "the pool contains the gateway's own address")
    #expect(!pool.contains(host), "the pool contains the host address")
    #expect(!pool.contains(virtual), "the pool contains one of the gateway's virtual addresses")
    #expect(!pool.contains(subnet.address), "the pool contains the network address")
    #expect(!pool.contains(subnet.broadcast), "the pool contains the broadcast address")

    // What is left is what a guest may have: .2, .3 and .5 on a /29 whose .4 is
    // spoken for. Asserted exactly, because "fewer than before" would hold for a
    // pool that had lost the wrong ones.
    let expected = ["192.168.127.2", "192.168.127.3", "192.168.127.5"].map { IPv4Address($0)! }
    #expect(pool == expected, "the pool is \(pool.map(\.description))")
}
