import NIOCore
import NIOEmbedded
import Testing

@testable import Netstack

private func udpDatagram(from source: String, to destination: String, sourcePort: UInt16, destinationPort: UInt16, payload: [UInt8]) -> ByteBuffer {
    UDPHeader.serialize(
        payload: ByteBuffer(bytes: payload),
        source: IPv4Address(source)!, destination: IPv4Address(destination)!,
        sourcePort: sourcePort, destinationPort: destinationPort,
        allocator: ByteBufferAllocator())
}

@Test func serializedDatagramHasAValidChecksum() {
    let datagram = udpDatagram(from: "192.168.127.2", to: "192.168.127.1", sourcePort: 4000, destinationPort: 53, payload: [0xaa, 0xbb, 0xcc])
    #expect(datagram.readableBytes == 11)

    var pseudo: UInt32 = 0
    var pseudoBytes = ByteBuffer()
    pseudoBytes.writeBytes(IPv4Address("192.168.127.2")!.bytes)
    pseudoBytes.writeBytes(IPv4Address("192.168.127.1")!.bytes)
    pseudoBytes.writeInteger(UInt8(0))
    pseudoBytes.writeInteger(UInt8(17))
    pseudoBytes.writeInteger(UInt16(11), endianness: .big)
    pseudo = pseudoBytes.withUnsafeReadableBytes { Checksum.partial($0) }
    let total = datagram.withUnsafeReadableBytes { Checksum.partial($0, initial: pseudo) }
    #expect(Checksum.complete(total) == 0)
}

@Test func parsesAValidDatagram() {
    let datagram = udpDatagram(from: "192.168.127.2", to: "192.168.127.1", sourcePort: 4000, destinationPort: 53, payload: [0x01, 0x02])
    var packet = PacketBuffer(received: datagram)
    let ipHeader = IPv4Header(
        source: IPv4Address("192.168.127.2")!, destination: IPv4Address("192.168.127.1")!,
        protocolNumber: .udp, payloadLength: datagram.readableBytes)

    let header = UDPHeader.parse(&packet, header: ipHeader)
    #expect(header?.sourcePort == 4000)
    #expect(header?.destinationPort == 53)
    #expect(header?.length == 10)
    #expect(Array(packet.payload.readableBytesView) == [0x01, 0x02])
}

// Renamed from the brief's `rejectsABadChecksum` — that name already exists
// in IPv4HeaderTests.swift, and Swift Testing's `@Test` functions share one
// namespace across every file regardless of access level.
@Test func udpRejectsABadChecksum() {
    var datagram = udpDatagram(from: "192.168.127.2", to: "192.168.127.1", sourcePort: 4000, destinationPort: 53, payload: [0x01])
    datagram.setInteger(UInt16(0x1234), at: 6, endianness: .big)
    var packet = PacketBuffer(received: datagram)
    let ipHeader = IPv4Header(
        source: IPv4Address("192.168.127.2")!, destination: IPv4Address("192.168.127.1")!,
        protocolNumber: .udp, payloadLength: datagram.readableBytes)
    #expect(UDPHeader.parse(&packet, header: ipHeader) == nil)
}

@Test func acceptsAZeroChecksum() {
    // Zero means the sender declined to compute one. RFC 768 permits it.
    var datagram = udpDatagram(from: "192.168.127.2", to: "192.168.127.1", sourcePort: 4000, destinationPort: 53, payload: [0x01])
    datagram.setInteger(UInt16(0), at: 6, endianness: .big)
    var packet = PacketBuffer(received: datagram)
    let ipHeader = IPv4Header(
        source: IPv4Address("192.168.127.2")!, destination: IPv4Address("192.168.127.1")!,
        protocolNumber: .udp, payloadLength: datagram.readableBytes)
    #expect(UDPHeader.parse(&packet, header: ipHeader)?.sourcePort == 4000)
}

@Test func rejectsARuntAndABadLengthField() {
    var runt = PacketBuffer(received: ByteBuffer(bytes: [0x00, 0x35, 0x00]))
    let ipHeader = IPv4Header(
        source: IPv4Address("1.2.3.4")!, destination: IPv4Address("5.6.7.8")!, protocolNumber: .udp, payloadLength: 3)
    #expect(UDPHeader.parse(&runt, header: ipHeader) == nil)

    // Length field claiming more than is present.
    var datagram = udpDatagram(from: "1.2.3.4", to: "5.6.7.8", sourcePort: 1, destinationPort: 2, payload: [0x01])
    datagram.setInteger(UInt16(500), at: 4, endianness: .big)
    datagram.setInteger(UInt16(0), at: 6, endianness: .big)  // disable checksum so length is the only fault
    var packet = PacketBuffer(received: datagram)
    #expect(UDPHeader.parse(&packet, header: ipHeader) == nil)
}

@Test func aBoundEndpointReceivesDatagrams() throws {
    let loop = EmbeddedEventLoop()
    let link = RecordingEndpoint(eventLoop: loop, linkAddress: MACAddress("5a:94:ef:e4:0c:ee")!)
    let stack = Stack(
        link: link,
        configuration: Stack.Configuration(gatewayAddress: IPv4Address("192.168.127.1")!, subnet: IPv4Subnet(cidr: "192.168.127.0/24")!),
        clock: ManualClock())
    stack.start()

    let endpoint = UDPEndpoint(stack: stack)
    try endpoint.bind(address: IPv4Address("192.168.127.1")!, port: 53)

    var received: [UInt8] = []
    var fromAddress: IPv4Address?
    var fromPort: UInt16?
    endpoint.onDatagram = { payload, address, port in
        received = Array(payload.readableBytesView)
        fromAddress = address
        fromPort = port
    }

    stack.arpCache.record(IPv4Address("192.168.127.2")!, MACAddress("0a:0b:0c:0d:0e:0f")!)
    injectUDP(into: link, from: "192.168.127.2", to: "192.168.127.1", sourcePort: 4000, destinationPort: 53, payload: [0xde, 0xad])

    #expect(received == [0xde, 0xad])
    #expect(fromAddress == IPv4Address("192.168.127.2"))
    #expect(fromPort == 4000)
}

@Test func aBoundEndpointCanReply() throws {
    let loop = EmbeddedEventLoop()
    let link = RecordingEndpoint(eventLoop: loop, linkAddress: MACAddress("5a:94:ef:e4:0c:ee")!)
    let stack = Stack(
        link: link,
        configuration: Stack.Configuration(gatewayAddress: IPv4Address("192.168.127.1")!, subnet: IPv4Subnet(cidr: "192.168.127.0/24")!),
        clock: ManualClock())
    stack.start()
    stack.arpCache.record(IPv4Address("192.168.127.2")!, MACAddress("0a:0b:0c:0d:0e:0f")!)

    let endpoint = UDPEndpoint(stack: stack)
    try endpoint.bind(address: IPv4Address("192.168.127.1")!, port: 53)
    _ = link.drainTransmitted()

    try endpoint.send(ByteBuffer(bytes: [0xbe, 0xef]), to: IPv4Address("192.168.127.2")!, port: 4000)

    let frames = link.drainTransmitted()
    #expect(frames.count == 1)
    var packet = PacketBuffer(received: frames[0])
    _ = EthernetHeader.parse(&packet)
    let ipHeader = IPv4Header.parse(&packet)
    #expect(ipHeader?.protocolNumber == .udp)
    let udpHeader = UDPHeader.parse(&packet, header: ipHeader!)
    #expect(udpHeader?.sourcePort == 53)
    #expect(udpHeader?.destinationPort == 4000)
    #expect(Array(packet.payload.readableBytesView) == [0xbe, 0xef])
}

@Test func aClosedEndpointStopsReceiving() throws {
    let loop = EmbeddedEventLoop()
    let link = RecordingEndpoint(eventLoop: loop, linkAddress: MACAddress("5a:94:ef:e4:0c:ee")!)
    let stack = Stack(
        link: link,
        configuration: Stack.Configuration(gatewayAddress: IPv4Address("192.168.127.1")!, subnet: IPv4Subnet(cidr: "192.168.127.0/24")!),
        clock: ManualClock())
    stack.start()

    let endpoint = UDPEndpoint(stack: stack)
    try endpoint.bind(address: IPv4Address("192.168.127.1")!, port: 53)
    var count = 0
    endpoint.onDatagram = { _, _, _ in count += 1 }
    endpoint.close()

    injectUDP(into: link, from: "192.168.127.2", to: "192.168.127.1", sourcePort: 4000, destinationPort: 53, payload: [0x01])
    #expect(count == 0)

    // The port is free again.
    let replacement = UDPEndpoint(stack: stack)
    try replacement.bind(address: IPv4Address("192.168.127.1")!, port: 53)
}

@Test func bindingAPortTwiceThrows() throws {
    let loop = EmbeddedEventLoop()
    let link = RecordingEndpoint(eventLoop: loop, linkAddress: MACAddress("5a:94:ef:e4:0c:ee")!)
    let stack = Stack(
        link: link,
        configuration: Stack.Configuration(gatewayAddress: IPv4Address("192.168.127.1")!, subnet: IPv4Subnet(cidr: "192.168.127.0/24")!),
        clock: ManualClock())
    stack.start()

    let first = UDPEndpoint(stack: stack)
    try first.bind(address: IPv4Address("192.168.127.1")!, port: 53)
    let second = UDPEndpoint(stack: stack)
    #expect(throws: StackError.portInUse) {
        try second.bind(address: IPv4Address("192.168.127.1")!, port: 53)
    }
}

@Test func anUnboundPortElicitsAnICMPPortUnreachableQuotingTheOriginalDatagram() throws {
    let loop = EmbeddedEventLoop()
    let link = RecordingEndpoint(eventLoop: loop, linkAddress: MACAddress("5a:94:ef:e4:0c:ee")!)
    let stack = Stack(
        link: link,
        configuration: Stack.Configuration(gatewayAddress: IPv4Address("192.168.127.1")!, subnet: IPv4Subnet(cidr: "192.168.127.0/24")!),
        clock: ManualClock())
    stack.start()
    // The reply needs to resolve the original sender's link address.
    stack.arpCache.record(IPv4Address("192.168.127.2")!, MACAddress("0a:0b:0c:0d:0e:0f")!)

    let source = IPv4Address("192.168.127.2")!
    let destination = IPv4Address("192.168.127.1")!
    let sourcePort: UInt16 = 4321
    let destinationPort: UInt16 = 9999  // nothing is bound here
    let payload: [UInt8] = [0xde, 0xad, 0xbe, 0xef]

    let datagram = UDPHeader.serialize(
        payload: ByteBuffer(bytes: payload),
        source: source, destination: destination,
        sourcePort: sourcePort, destinationPort: destinationPort,
        allocator: ByteBufferAllocator())

    // Read the datagram's own wire header straight off the bytes about to
    // be injected: a plain `getInteger` peek, not a Netstack helper, so
    // these expectations cannot be a self-consistency check against the
    // code under test — that has hidden defects here before.
    let expectedSourcePort = datagram.getInteger(at: datagram.readerIndex, endianness: .big, as: UInt16.self)!
    let expectedDestinationPort = datagram.getInteger(at: datagram.readerIndex + 2, endianness: .big, as: UInt16.self)!
    let expectedLength = datagram.getInteger(at: datagram.readerIndex + 4, endianness: .big, as: UInt16.self)!
    let expectedChecksum = datagram.getInteger(at: datagram.readerIndex + 6, endianness: .big, as: UInt16.self)!
    #expect(expectedSourcePort == sourcePort)
    #expect(expectedDestinationPort == destinationPort)
    #expect(expectedLength == UInt16(UDPHeader.length + payload.count))

    injectRawUDPDatagram(datagram, into: link, from: "192.168.127.2", to: "192.168.127.1")

    let frames = link.drainTransmitted()
    #expect(frames.count == 1)

    var packet = PacketBuffer(received: frames[0])
    _ = EthernetHeader.parse(&packet)
    let ipHeader = IPv4Header.parse(&packet)
    #expect(ipHeader?.protocolNumber == .icmp)
    // The reply comes from the address the original datagram was addressed
    // to, back to whoever sent it.
    #expect(ipHeader?.source == destination)
    #expect(ipHeader?.destination == source)

    let icmp = ICMPv4Header.parse(&packet)
    #expect(icmp?.type == .destinationUnreachable)
    #expect(icmp?.code == ICMPv4.UnreachableCode.port.rawValue)

    // The quoted IP header. Read raw rather than through IPv4Header.parse:
    // it legitimately declares the ORIGINAL datagram's length while only
    // eight bytes of payload actually follow it here, which parse's length
    // guard exists to reject on live ingress.
    var quotedPayload = packet.payload
    let quotedIPBytes = quotedPayload.readBytes(length: IPv4Header.minimumLength)!
    #expect(quotedIPBytes[9] == IPProtocol.udp.rawValue)
    #expect(Array(quotedIPBytes[12..<16]) == source.bytes)
    #expect(Array(quotedIPBytes[16..<20]) == destination.bytes)

    // The quoted eight bytes: the original datagram's own UDP wire header —
    // source port, destination port, length (header + payload), checksum —
    // reconstructed from the quoted bytes themselves, then cross-checked
    // against the bytes that were actually injected above.
    let quotedUDPBytes = quotedPayload.readBytes(length: UDPHeader.length)!
    let quotedSourcePort = UInt16(quotedUDPBytes[0]) << 8 | UInt16(quotedUDPBytes[1])
    let quotedDestinationPort = UInt16(quotedUDPBytes[2]) << 8 | UInt16(quotedUDPBytes[3])
    let quotedLength = UInt16(quotedUDPBytes[4]) << 8 | UInt16(quotedUDPBytes[5])
    let quotedChecksum = UInt16(quotedUDPBytes[6]) << 8 | UInt16(quotedUDPBytes[7])

    #expect(quotedSourcePort == sourcePort)
    #expect(quotedDestinationPort == destinationPort)
    #expect(quotedLength == UInt16(UDPHeader.length + payload.count))
    #expect(quotedSourcePort == expectedSourcePort)
    #expect(quotedDestinationPort == expectedDestinationPort)
    #expect(quotedLength == expectedLength)
    #expect(quotedChecksum == expectedChecksum)
}

/// Build a full ethernet/IP/UDP frame and hand it to the link.
private func injectUDP(into link: RecordingEndpoint, from source: String, to destination: String, sourcePort: UInt16, destinationPort: UInt16, payload: [UInt8]) {
    let datagram = UDPHeader.serialize(
        payload: ByteBuffer(bytes: payload),
        source: IPv4Address(source)!, destination: IPv4Address(destination)!,
        sourcePort: sourcePort, destinationPort: destinationPort,
        allocator: ByteBufferAllocator())
    injectRawUDPDatagram(datagram, into: link, from: source, to: destination)
}

/// Wrap an already-built UDP datagram in ethernet/IP and hand it to the
/// link. Factored out of `injectUDP` above so a caller can inject the exact
/// buffer it also inspects for expected values, rather than building a
/// second one from the same inputs.
private func injectRawUDPDatagram(_ datagram: ByteBuffer, into link: RecordingEndpoint, from source: String, to destination: String) {
    var ipPacket = PacketBuffer(allocator: ByteBufferAllocator(), payload: datagram)
    let header = IPv4Header(
        source: IPv4Address(source)!, destination: IPv4Address(destination)!,
        protocolNumber: .udp, payloadLength: datagram.readableBytes)
    header.prepend(to: &ipPacket)

    var frame = ByteBuffer()
    frame.writeBytes(MACAddress("5a:94:ef:e4:0c:ee")!.bytes)
    frame.writeBytes(MACAddress("0a:0b:0c:0d:0e:0f")!.bytes)
    frame.writeInteger(UInt16(0x0800), endianness: .big)
    var body = ipPacket.frame
    frame.writeBuffer(&body)
    link.inject(frame)
}
