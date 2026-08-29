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

    init(cidr: String = "192.168.127.0/24") throws {
        link = RecordingEndpoint(eventLoop: loop, linkAddress: dhcpGatewayMAC)
        stack = Stack(
            link: link,
            configuration: Stack.Configuration(
                gatewayAddress: dhcpGateway, subnet: IPv4Subnet(cidr: cidr)!),
            clock: ManualClock())
        stack.start()
        server = try DHCPServer(stack: stack)
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
