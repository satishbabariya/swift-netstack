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

/// Build a full ethernet/IP/UDP frame and hand it to the link.
private func injectUDP(into link: RecordingEndpoint, from source: String, to destination: String, sourcePort: UInt16, destinationPort: UInt16, payload: [UInt8]) {
    let datagram = UDPHeader.serialize(
        payload: ByteBuffer(bytes: payload),
        source: IPv4Address(source)!, destination: IPv4Address(destination)!,
        sourcePort: sourcePort, destinationPort: destinationPort,
        allocator: ByteBufferAllocator())

    var ipPacket = PacketBuffer(allocator: ByteBufferAllocator(), payload: datagram)
    var header = IPv4Header(
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
