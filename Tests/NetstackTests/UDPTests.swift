import NIOCore
import NIOEmbedded
import Testing

@testable import Netstack

private func udpDatagram(from source: String, to destination: String, sourcePort: UInt16, destinationPort: UInt16, payload: [UInt8]) -> ByteBuffer {
    UDPHeader.serialize(
        payload: ByteBuffer(bytes: payload),
        source: IPv4Address(source)!, destination: IPv4Address(destination)!,
        sourcePort: sourcePort, destinationPort: destinationPort,
        allocator: ByteBufferAllocator())!
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

// `UDPHeader.serialize`'s `let total = UInt16(length + payload.readableBytes)`
// used to be a non-failable conversion: any payload over 65527 bytes made it
// TRAP the whole process (`Fatal error: Not enough bits to represent the
// passed value`), reachable from `UDPEndpoint.send` and, through it, from a
// NIO handler calling `writeAndFlush` on `NetstackDatagramChannel` with an
// oversized `ByteBuffer`. `IPv4Protocol.send` has its own guard against an
// oversized payload, but it runs one layer up, after this serializer has
// already trapped — so it never got a chance to fire. These three pin the
// real bound (65535 − 20-byte IPv4 header − 8-byte UDP header = 65507, not
// the 65527 the naive conversion alone would have allowed) at the boundary.
@Test func serializeRejectsAnOversizedPayloadInsteadOfTrapping() {
    var oversized = ByteBufferAllocator().buffer(capacity: 70000)
    oversized.writeRepeatingByte(0, count: 70000)
    let result = UDPHeader.serialize(
        payload: oversized, source: IPv4Address("192.168.127.2")!, destination: IPv4Address("192.168.127.1")!,
        sourcePort: 4000, destinationPort: 53, allocator: ByteBufferAllocator())
    #expect(result == nil)
}

@Test func serializeAcceptsTheLargestUDPPayload() {
    var largest = ByteBufferAllocator().buffer(capacity: UDPHeader.maximumPayloadLength)
    largest.writeRepeatingByte(0, count: UDPHeader.maximumPayloadLength)
    let result = UDPHeader.serialize(
        payload: largest, source: IPv4Address("192.168.127.2")!, destination: IPv4Address("192.168.127.1")!,
        sourcePort: 4000, destinationPort: 53, allocator: ByteBufferAllocator())
    #expect(result?.readableBytes == UDPHeader.length + UDPHeader.maximumPayloadLength)
}

@Test func serializeRejectsOneByteOverTheLargestUDPPayload() {
    var overByOne = ByteBufferAllocator().buffer(capacity: UDPHeader.maximumPayloadLength + 1)
    overByOne.writeRepeatingByte(0, count: UDPHeader.maximumPayloadLength + 1)
    let result = UDPHeader.serialize(
        payload: overByOne, source: IPv4Address("192.168.127.2")!, destination: IPv4Address("192.168.127.1")!,
        sourcePort: 4000, destinationPort: 53, allocator: ByteBufferAllocator())
    #expect(result == nil)
}

@Test func sendingAnOversizedPayloadThrowsMessageTooLongInsteadOfTrapping() throws {
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

    var oversized = ByteBufferAllocator().buffer(capacity: 70000)
    oversized.writeRepeatingByte(0, count: 70000)

    #expect(throws: StackError.messageTooLong) {
        try endpoint.send(oversized, to: IPv4Address("192.168.127.2")!, port: 4000)
    }
}

@Test func sendAcceptsTheLargestUDPPayloadAndRejectsOneByteMore() throws {
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

    var largest = ByteBufferAllocator().buffer(capacity: UDPHeader.maximumPayloadLength)
    largest.writeRepeatingByte(0, count: UDPHeader.maximumPayloadLength)
    // Must not throw at all — in particular not `.messageTooLong`.
    try endpoint.send(largest, to: IPv4Address("192.168.127.2")!, port: 4000)

    var overByOne = ByteBufferAllocator().buffer(capacity: UDPHeader.maximumPayloadLength + 1)
    overByOne.writeRepeatingByte(0, count: UDPHeader.maximumPayloadLength + 1)
    #expect(throws: StackError.messageTooLong) {
        try endpoint.send(overByOne, to: IPv4Address("192.168.127.2")!, port: 4000)
    }
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

@Test func aWildcardBoundEndpointSendsFromTheNICsAddressWhenSpoofingIsAllowed() throws {
    // A wildcard bind (`.any`, 0.0.0.0) has no address of its own to prefer.
    // `UDPEndpoint.send` used to pass it straight through to `ipv4.send`
    // regardless: with spoofing allowed, `RouteTable.lookup` honours ANY
    // preferred source, `.any` included, putting 0.0.0.0 in the emitted
    // packet's IP source field — never a valid source address in practice.
    let loop = EmbeddedEventLoop()
    let link = RecordingEndpoint(eventLoop: loop, linkAddress: MACAddress("5a:94:ef:e4:0c:ee")!)
    let stack = Stack(
        link: link,
        configuration: Stack.Configuration(
            gatewayAddress: IPv4Address("192.168.127.1")!, subnet: IPv4Subnet(cidr: "192.168.127.0/24")!,
            allowsAnySource: true),
        clock: ManualClock())
    stack.start()
    stack.arpCache.record(IPv4Address("192.168.127.2")!, MACAddress("0a:0b:0c:0d:0e:0f")!)

    let endpoint = UDPEndpoint(stack: stack)
    try endpoint.bind(address: .any, port: 53)
    _ = link.drainTransmitted()

    try endpoint.send(ByteBuffer(bytes: [0xbe, 0xef]), to: IPv4Address("192.168.127.2")!, port: 4000)

    let frames = link.drainTransmitted()
    #expect(frames.count == 1)
    var packet = PacketBuffer(received: frames[0])
    _ = EthernetHeader.parse(&packet)
    let ipHeader = IPv4Header.parse(&packet)
    // The NIC's own address, never 0.0.0.0.
    #expect(ipHeader?.source == IPv4Address("192.168.127.1")!)
    #expect(ipHeader?.source != .any)
    // The checksum must have been computed against the address that was
    // ACTUALLY put on the wire, not against `.any` — `UDPHeader.parse`
    // verifies it against `ipHeader.source` and returns nil on a mismatch.
    let udpHeader = UDPHeader.parse(&packet, header: ipHeader!)
    #expect(udpHeader != nil)
    #expect(udpHeader?.sourcePort == 53)
}

@Test func aWildcardBoundEndpointSendsSuccessfullyWhenSpoofingIsDisallowed() throws {
    // The regression this closes: with `allowsAnySource == false`,
    // `RouteTable.lookup` cannot honour `.any` as a preferred source (the
    // NIC does not own it and is not allowed to spoof it), so it fell back
    // to `primaryAddress` while reporting `sourceWasHonoured == false` —
    // which `IPv4Protocol.send` treats as `.noRoute`, turning an ordinary
    // wildcard-bound send into a total failure. A wildcard bind has no
    // preference to fail to honour in the first place.
    let loop = EmbeddedEventLoop()
    let link = RecordingEndpoint(eventLoop: loop, linkAddress: MACAddress("5a:94:ef:e4:0c:ee")!)
    let stack = Stack(
        link: link,
        configuration: Stack.Configuration(
            gatewayAddress: IPv4Address("192.168.127.1")!, subnet: IPv4Subnet(cidr: "192.168.127.0/24")!,
            allowsAnySource: false),
        clock: ManualClock())
    stack.start()
    stack.arpCache.record(IPv4Address("192.168.127.2")!, MACAddress("0a:0b:0c:0d:0e:0f")!)

    let endpoint = UDPEndpoint(stack: stack)
    try endpoint.bind(address: .any, port: 53)
    _ = link.drainTransmitted()

    // Must not throw.
    try endpoint.send(ByteBuffer(bytes: [0xbe, 0xef]), to: IPv4Address("192.168.127.2")!, port: 4000)

    let frames = link.drainTransmitted()
    #expect(frames.count == 1)
    var packet = PacketBuffer(received: frames[0])
    _ = EthernetHeader.parse(&packet)
    let ipHeader = IPv4Header.parse(&packet)
    #expect(ipHeader?.source == IPv4Address("192.168.127.1")!)
    let udpHeader = UDPHeader.parse(&packet, header: ipHeader!)
    #expect(udpHeader != nil)
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
        allocator: ByteBufferAllocator())!

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
        allocator: ByteBufferAllocator())!
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
