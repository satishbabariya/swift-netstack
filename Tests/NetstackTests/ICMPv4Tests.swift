import NIOCore
import Testing

@testable import Netstack

private func echoRequest(identifier: UInt16, sequence: UInt16, payload: [UInt8]) -> ByteBuffer {
    var buffer = ByteBuffer()
    buffer.writeInteger(UInt8(8))   // echo request
    buffer.writeInteger(UInt8(0))
    buffer.writeInteger(UInt16(0), endianness: .big)  // checksum placeholder
    buffer.writeInteger(identifier, endianness: .big)
    buffer.writeInteger(sequence, endianness: .big)
    buffer.writeBytes(payload)
    let checksum = buffer.withUnsafeReadableBytes { Checksum.compute($0) }
    buffer.setInteger(checksum, at: 2, endianness: .big)
    return buffer
}

@Test func parsesAnEchoRequest() {
    var packet = PacketBuffer(received: echoRequest(identifier: 0x1234, sequence: 7, payload: [0xaa, 0xbb]))
    let header = ICMPv4Header.parse(&packet)
    #expect(header?.type == .echoRequest)
    #expect(header?.code == 0)
    #expect(header?.identifier == 0x1234)
    #expect(header?.sequence == 7)
    #expect(Array(packet.payload.readableBytesView) == [0xaa, 0xbb])
}

// Renamed from the brief's `rejectsABadChecksum` — that name already exists
// at top level in IPv4HeaderTests.swift. `@Test` functions are ordinary
// top-level functions, and same-named top-level declarations in different
// files of one module are an "invalid redeclaration" regardless of access
// level (`private` does not create a separate namespace per file here).
@Test func icmpRejectsABadChecksum() {
    var buffer = echoRequest(identifier: 1, sequence: 1, payload: [0xaa])
    buffer.setInteger(UInt16(0xffff), at: 2, endianness: .big)
    var packet = PacketBuffer(received: buffer)
    #expect(ICMPv4Header.parse(&packet) == nil)
}

// Same collision as above, this time against EthernetTests.swift's `rejectsARunt`.
@Test func icmpRejectsARunt() {
    var packet = PacketBuffer(received: ByteBuffer(bytes: [0x08, 0x00]))
    #expect(ICMPv4Header.parse(&packet) == nil)
}

@Test func echoReplyMirrorsIdentifierSequenceAndPayload() {
    var request = PacketBuffer(received: echoRequest(identifier: 0x4321, sequence: 9, payload: [0x01, 0x02, 0x03]))
    let header = ICMPv4Header.parse(&request)!
    let reply = ICMPv4.echoReply(to: header, payload: request.payload, allocator: ByteBufferAllocator())

    #expect(reply.withUnsafeReadableBytes { Checksum.compute($0) } == 0)
    var parsed = PacketBuffer(received: reply)
    let replyHeader = ICMPv4Header.parse(&parsed)
    #expect(replyHeader?.type == .echoReply)
    #expect(replyHeader?.identifier == 0x4321)
    #expect(replyHeader?.sequence == 9)
    #expect(Array(parsed.payload.readableBytesView) == [0x01, 0x02, 0x03])
}

@Test func unreachableQuotesTheOffendingHeaderAndEightPayloadBytes() {
    var offending = IPv4Header(
        source: IPv4Address("192.168.127.2")!,
        destination: IPv4Address("8.8.8.8")!,
        protocolNumber: .udp,
        payloadLength: 40
    )
    offending.identification = 0x55aa
    let quotedPayload = ByteBuffer(bytes: Array(0..<40).map(UInt8.init))

    let message = ICMPv4.destinationUnreachable(
        code: .port, quoting: offending, quotedPayload: quotedPayload, allocator: ByteBufferAllocator())

    #expect(message.withUnsafeReadableBytes { Checksum.compute($0) } == 0)
    // 8 bytes of ICMP header, 20 of quoted IP header, 8 of quoted payload.
    #expect(message.readableBytes == 36)

    var parsed = PacketBuffer(received: message)
    let header = ICMPv4Header.parse(&parsed)
    #expect(header?.type == .destinationUnreachable)
    #expect(header?.code == 3)

    // The quoted header must be a valid IPv4 header in its own right.
    var quoted = PacketBuffer(received: parsed.payload)
    let quotedHeader = IPv4Header.parse(&quoted)
    #expect(quotedHeader?.identification == 0x55aa)
    #expect(quotedHeader?.destination == IPv4Address("8.8.8.8"))
    #expect(Array(quoted.payload.readableBytesView) == [0, 1, 2, 3, 4, 5, 6, 7])
}

@Test func fragmentationNeededCarriesTheNextHopMTU() {
    let offending = IPv4Header(
        source: IPv4Address("192.168.127.2")!,
        destination: IPv4Address("8.8.8.8")!,
        protocolNumber: .tcp,
        payloadLength: 1400
    )
    let message = ICMPv4.fragmentationNeeded(
        nextHopMTU: 1400, quoting: offending, quotedPayload: ByteBuffer(bytes: Array(repeating: UInt8(0), count: 8)),
        allocator: ByteBufferAllocator())

    #expect(message.withUnsafeReadableBytes { Checksum.compute($0) } == 0)
    // The MTU lives in the low half of the unused word, bytes 6-7.
    #expect(message.getInteger(at: 6, endianness: .big, as: UInt16.self) == 1400)
    #expect(message.getInteger(at: 0, as: UInt8.self) == 3)
    #expect(message.getInteger(at: 1, as: UInt8.self) == 4)
}

@Test func timeExceededQuotesTheHeader() {
    let offending = IPv4Header(
        source: IPv4Address("192.168.127.2")!,
        destination: IPv4Address("1.1.1.1")!,
        protocolNumber: .udp,
        payloadLength: 8
    )
    let message = ICMPv4.timeExceeded(
        quoting: offending, quotedPayload: ByteBuffer(bytes: [1, 2, 3, 4, 5, 6, 7, 8]), allocator: ByteBufferAllocator())
    #expect(message.getInteger(at: 0, as: UInt8.self) == 11)
    #expect(message.withUnsafeReadableBytes { Checksum.compute($0) } == 0)
}
