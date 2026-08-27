import NIOCore
import Testing

@testable import Netstack

private let testSource = IPv4Address("192.168.127.2")!
private let testDestination = IPv4Address("192.168.127.1")!

private func sampleIPv4Header(payloadLength: Int) -> IPv4Header {
    IPv4Header(source: testSource, destination: testDestination, protocolNumber: .tcp, payloadLength: payloadLength)
}

/// Computed independently of `TCPHeader.pseudoHeaderSum` — this is the same
/// standard arithmetic (RFC 793 §3.1's pseudo-header, over the same fixed
/// protocol number 6), inlined here rather than called, so a test that uses
/// it to embed a checksum in literal bytes is not exercising the
/// implementation under test to build its own fixtures.
private func tcpChecksum(_ bytes: [UInt8], source: IPv4Address, destination: IPv4Address) -> UInt16 {
    var sum: UInt32 = 0
    sum += UInt32(source.raw >> 16) + UInt32(source.raw & 0xffff)
    sum += UInt32(destination.raw >> 16) + UInt32(destination.raw & 0xffff)
    sum += UInt32(6)  // TCP
    sum += UInt32(bytes.count)
    return bytes.withUnsafeBytes { Checksum.complete(Checksum.partial($0, initial: sum)) }
}

/// Fills in bytes[16..17] (the checksum field) of a literal TCP segment so
/// it validates for `testSource` -> `testDestination`.
private func embedChecksum(in bytes: inout [UInt8]) {
    bytes[16] = 0
    bytes[17] = 0
    let checksum = tcpChecksum(bytes, source: testSource, destination: testDestination)
    bytes[16] = UInt8(checksum >> 8)
    bytes[17] = UInt8(checksum & 0xff)
}

/// A SYN with MSS(1460), window-scale(7), and SACK-permitted options,
/// padded with one NOP to a 4-byte boundary — data offset 8 words (32
/// bytes), no payload. Checksum is filled in and correct for the bytes as
/// they stand when this returns.
private func validSynHeaderBytes() -> [UInt8] {
    var bytes: [UInt8] = [
        0x30, 0x39,  // source port 12345
        0x00, 0x50,  // destination port 80
        0x00, 0x00, 0x00, 0x01,  // sequence 1
        0x00, 0x00, 0x00, 0x00,  // acknowledgement 0
        0x80, 0x02,  // data offset 8, reserved 0, flags: SYN
        0xff, 0xff,  // window 65535
        0x00, 0x00,  // checksum, filled in below
        0x00, 0x00,  // urgent pointer
        0x02, 0x04, 0x05, 0xb4,  // MSS = 1460
        0x03, 0x03, 0x07,  // window scale = 7
        0x04, 0x02,  // SACK permitted
        0x01, 0x01, 0x01,  // NOP NOP NOP, padding options to a 4-byte boundary
    ]
    embedChecksum(in: &bytes)
    return bytes
}

@Test func parsesASynWithOptionsAgainstLiteralWireBytes() {
    let bytes = validSynHeaderBytes()
    var packet = PacketBuffer(received: ByteBuffer(bytes: bytes))
    let header = TCPHeader.parse(&packet, header: sampleIPv4Header(payloadLength: bytes.count))

    #expect(header?.sourcePort == 12345)
    #expect(header?.destinationPort == 80)
    #expect(header?.sequence == SequenceNumber(1))
    #expect(header?.acknowledgement == SequenceNumber(0))
    #expect(header?.dataOffset == 8)
    #expect(header?.flags == .syn)
    #expect(header?.window == 65535)
    #expect(header?.urgentPointer == 0)
    #expect(header?.options == [.maximumSegmentSize(1460), .windowScale(7), .sackPermitted])
    #expect(packet.readableBytes == 0)  // the whole 32-byte segment was the header; no payload left
}

@Test func rejectsABadTCPChecksum() {
    var bytes = validSynHeaderBytes()
    bytes[16] ^= 0xff
    var packet = PacketBuffer(received: ByteBuffer(bytes: bytes))
    let parsed = TCPHeader.parse(&packet, header: sampleIPv4Header(payloadLength: bytes.count))
    #expect(parsed == nil)
}

@Test func rejectsADataOffsetBelowFive() {
    var bytes: [UInt8] = [
        0x30, 0x39, 0x00, 0x50,
        0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00,
        0x40, 0x02,  // data offset 4 — below the 5-word (20-byte) minimum
        0xff, 0xff,
        0x00, 0x00,
        0x00, 0x00,
    ]
    embedChecksum(in: &bytes)
    var packet = PacketBuffer(received: ByteBuffer(bytes: bytes))
    let parsed = TCPHeader.parse(&packet, header: sampleIPv4Header(payloadLength: bytes.count))
    #expect(parsed == nil)
}

@Test func rejectsADataOffsetThatOverrunsTheSegment() {
    var bytes: [UInt8] = [
        0x30, 0x39, 0x00, 0x50,
        0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00,
        0xf0, 0x02,  // data offset 15 (60 bytes) — the segment is only 20
        0xff, 0xff,
        0x00, 0x00,
        0x00, 0x00,
    ]
    embedChecksum(in: &bytes)
    var packet = PacketBuffer(received: ByteBuffer(bytes: bytes))
    let parsed = TCPHeader.parse(&packet, header: sampleIPv4Header(payloadLength: bytes.count))
    #expect(parsed == nil)
}

@Test func skipsAnUnknownTCPOptionKindByItsLength() {
    var bytes: [UInt8] = [
        0x30, 0x39, 0x00, 0x50,
        0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00,
        0x80, 0x02,  // data offset 8, flags: SYN
        0xff, 0xff,
        0x00, 0x00,
        0x00, 0x00,
        30, 4, 0xaa, 0xbb,  // unknown option: kind 30, length 4 (2 value bytes)
        0x02, 0x04, 0x05, 0xb4,  // MSS = 1460, follows the unknown option
        0x01, 0x01, 0x01, 0x01,  // pad to a 4-byte boundary (32 bytes total)
    ]
    embedChecksum(in: &bytes)
    var packet = PacketBuffer(received: ByteBuffer(bytes: bytes))
    let header = TCPHeader.parse(&packet, header: sampleIPv4Header(payloadLength: bytes.count))
    #expect(header?.options == [.unknown(kind: 30), .maximumSegmentSize(1460)])
}

@Test func rejectsAnOptionWhoseLengthWouldLoopForever() {
    // Kind 2 (MSS) with a declared length of 0. A parser that advances by the
    // declared length spins forever on this — a remote hang from one segment.
    var bytes = validSynHeaderBytes()
    bytes[20] = 2  // kind: MSS
    bytes[21] = 0  // length: 0
    var packet = PacketBuffer(received: ByteBuffer(bytes: bytes))
    let parsed = TCPHeader.parse(&packet, header: sampleIPv4Header(payloadLength: bytes.count))
    #expect(parsed == nil)
}

/// Step 6 of the Task 7 brief: encode a SYN with all three options using
/// the Task 2 vector codec (`VectorFrames`, in `Support/VectorFrames.swift`)
/// — an independent TCP implementation, deliberately not sharing any code
/// with `TCPHeader` — and parse it with `TCPHeader.parse`. Two
/// independently-implemented encoders/decoders agreeing is worth more than
/// either agreeing with itself.
@Test func crossChecksAgainstTheVectorCodec() throws {
    let codec = VectorFrames(
        gateway: IPv4Address("192.168.127.1")!, gatewayMAC: MACAddress("5a:94:ef:e4:0c:ee")!,
        guest: IPv4Address("192.168.127.2")!, guestMAC: MACAddress("0a:0b:0c:0d:0e:0f")!)

    let line = TCPLine(
        flags: "S", seqStart: 1000, seqEnd: 1000, payloadLength: 0, ack: nil, window: 65535,
        options: ["mss 1460", "wscale 7", "sackOK"])
    let frame = try codec.encode(.tcp(line), direction: .inbound)

    var packet = PacketBuffer(received: frame)
    let ethernet = EthernetHeader.parse(&packet)
    #expect(ethernet?.etherType == .ipv4)

    let ip = IPv4Header.parse(&packet)
    #expect(ip?.protocolNumber == .tcp)

    let header = ip.flatMap { TCPHeader.parse(&packet, header: $0) }
    #expect(header?.sourcePort == 50000)
    #expect(header?.destinationPort == 8080)
    #expect(header?.sequence == SequenceNumber(1000))
    #expect(header?.acknowledgement == SequenceNumber(0))
    #expect(header?.flags == .syn)
    #expect(header?.window == 65535)
    #expect(header?.dataOffset == 8)
    #expect(header?.options == [.maximumSegmentSize(1460), .windowScale(7), .sackPermitted])
}
