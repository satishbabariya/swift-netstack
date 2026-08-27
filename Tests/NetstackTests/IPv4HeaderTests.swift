import NIOCore
import Testing

@testable import Netstack

private let sampleHeader: [UInt8] = [
    0x45, 0x00, 0x00, 0x1c,  // v4, IHL 5, DSCP 0, total length 28
    0xab, 0xcd, 0x40, 0x00,  // id 0xabcd, DF set, offset 0
    0x40, 0x11, 0x00, 0x00,  // TTL 64, UDP, checksum zeroed
    0xc0, 0xa8, 0x7f, 0x01,  // 192.168.127.1
    0xc0, 0xa8, 0x7f, 0x02,  // 192.168.127.2
]

@Test func parsesAnIPv4Header() {
    var bytes = sampleHeader
    let checksum = bytes.withUnsafeBytes { Checksum.compute($0) }
    bytes[10] = UInt8(checksum >> 8)
    bytes[11] = UInt8(checksum & 0xff)

    var packet = PacketBuffer(received: ByteBuffer(bytes: bytes + [0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04]))
    let header = IPv4Header.parse(&packet)

    #expect(header?.version == 4)
    #expect(header?.headerLength == 20)
    #expect(header?.totalLength == 28)
    #expect(header?.identification == 0xabcd)
    #expect(header?.flags.contains(.dontFragment) == true)
    #expect(header?.flags.contains(.moreFragments) == false)
    #expect(header?.fragmentOffset == 0)
    #expect(header?.ttl == 64)
    #expect(header?.protocolNumber == .udp)
    #expect(header?.source == IPv4Address("192.168.127.1"))
    #expect(header?.destination == IPv4Address("192.168.127.2"))
    #expect(header?.payloadLength == 8)
}

@Test func rejectsABadChecksum() {
    var bytes = sampleHeader
    bytes[10] = 0xff
    bytes[11] = 0xff
    var packet = PacketBuffer(received: ByteBuffer(bytes: bytes))
    let parsed = IPv4Header.parse(&packet)
    #expect(parsed == nil)
}

@Test func rejectsWrongVersionAndShortIHL() {
    var wrongVersion = sampleHeader
    wrongVersion[0] = 0x65  // version 6
    var a = PacketBuffer(received: ByteBuffer(bytes: wrongVersion))
    let parsedWrongVersion = IPv4Header.parse(&a)
    #expect(parsedWrongVersion == nil)

    var shortIHL = sampleHeader
    shortIHL[0] = 0x44  // IHL 4, below the 5-word minimum
    var b = PacketBuffer(received: ByteBuffer(bytes: shortIHL))
    let parsedShortIHL = IPv4Header.parse(&b)
    #expect(parsedShortIHL == nil)
}

@Test func rejectsATruncatedPacket() {
    var packet = PacketBuffer(received: ByteBuffer(bytes: Array(sampleHeader.prefix(12))))
    let parsed = IPv4Header.parse(&packet)
    #expect(parsed == nil)
}

@Test func rejectsTotalLengthLongerThanTheFrame() {
    var bytes = sampleHeader
    bytes[2] = 0xff  // total length 65280, frame is 20 bytes
    bytes[3] = 0x00
    let checksum = bytes.withUnsafeBytes { Checksum.compute($0) }
    bytes[10] = UInt8(checksum >> 8)
    bytes[11] = UInt8(checksum & 0xff)
    var packet = PacketBuffer(received: ByteBuffer(bytes: bytes))
    let parsed = IPv4Header.parse(&packet)
    #expect(parsed == nil)
}

@Test func rejectsTotalLengthShorterThanTheHeader() {
    var bytes = sampleHeader
    bytes[2] = 0x00  // total length 16, shorter than the 20-byte header itself
    bytes[3] = 0x10
    bytes[10] = 0
    bytes[11] = 0
    let checksum = bytes.withUnsafeBytes { Checksum.compute($0) }
    bytes[10] = UInt8(checksum >> 8)
    bytes[11] = UInt8(checksum & 0xff)
    var packet = PacketBuffer(received: ByteBuffer(bytes: bytes))
    let parsed = IPv4Header.parse(&packet)
    #expect(parsed == nil)
}

@Test func rejectsAnIHLThatOverrunsTheFrame() {
    var bytes = sampleHeader
    bytes[0] = 0x46  // IHL 6 — claims a 24-byte header
    bytes[10] = 0
    bytes[11] = 0
    let checksum = bytes.withUnsafeBytes { Checksum.compute($0) }
    bytes[10] = UInt8(checksum >> 8)
    bytes[11] = UInt8(checksum & 0xff)
    // Frame is only 20 bytes — shorter than the claimed 24-byte header.
    var packet = PacketBuffer(received: ByteBuffer(bytes: bytes))
    let parsed = IPv4Header.parse(&packet)
    #expect(parsed == nil)
}

@Test func skipsOptionsAndReportsTheirLength() {
    var bytes: [UInt8] = [
        0x46, 0x00, 0x00, 0x1c,  // IHL 6 — one 4-byte option word
        0x00, 0x00, 0x00, 0x00,
        0x40, 0x11, 0x00, 0x00,
        0xc0, 0xa8, 0x7f, 0x01,
        0xc0, 0xa8, 0x7f, 0x02,
        0x01, 0x01, 0x01, 0x00,  // NOP NOP NOP EOL
    ]
    let checksum = bytes.withUnsafeBytes { Checksum.compute($0) }
    bytes[10] = UInt8(checksum >> 8)
    bytes[11] = UInt8(checksum & 0xff)

    var packet = PacketBuffer(received: ByteBuffer(bytes: bytes + [0xaa, 0xbb, 0xcc, 0xdd]))
    let header = IPv4Header.parse(&packet)
    #expect(header?.headerLength == 24)
    #expect(header?.payloadLength == 4)
    #expect(Array(packet.payload.readableBytesView) == [0xaa, 0xbb, 0xcc, 0xdd])
}

@Test func reEmittingAParsedOptionsHeaderProducesAValidTwentyByteHeader() {
    // The ICMP error path re-prepends a header it got from `parse`. If that
    // header carried options, `prepend` must still emit a well-formed
    // 20-byte header with a correct checksum, not reserve 24 bytes and
    // leave four of them uninitialised and unchecksummed.
    var bytes: [UInt8] = [
        0x46, 0x00, 0x00, 0x1c,  // IHL 6 — one 4-byte option word
        0x00, 0x00, 0x00, 0x00,
        0x40, 0x11, 0x00, 0x00,
        0xc0, 0xa8, 0x7f, 0x01,
        0xc0, 0xa8, 0x7f, 0x02,
        0x01, 0x01, 0x01, 0x00,  // NOP NOP NOP EOL
    ]
    let checksum = bytes.withUnsafeBytes { Checksum.compute($0) }
    bytes[10] = UInt8(checksum >> 8)
    bytes[11] = UInt8(checksum & 0xff)

    var incoming = PacketBuffer(received: ByteBuffer(bytes: bytes + [0xaa, 0xbb, 0xcc, 0xdd]))
    let parsed = IPv4Header.parse(&incoming)
    #expect(parsed?.headerLength == 24)

    var outgoing = PacketBuffer(allocator: ByteBufferAllocator(), payload: ByteBuffer(bytes: [0xaa, 0xbb, 0xcc, 0xdd]))
    parsed?.prepend(to: &outgoing)

    let emitted = Array(outgoing.frame.readableBytesView)
    #expect(emitted.count == 24)                 // 20-byte header + 4-byte payload
    #expect(emitted[0] == 0x45)                  // IHL back down to 5
    #expect(emitted.prefix(20).withUnsafeBytes { Checksum.compute($0) } == 0)
}

@Test func prependComputesTheChecksum() {
    var packet = PacketBuffer(allocator: ByteBufferAllocator(), payload: ByteBuffer(bytes: [0x01, 0x02, 0x03, 0x04]))
    var header = IPv4Header(
        source: IPv4Address("192.168.127.1")!,
        destination: IPv4Address("192.168.127.2")!,
        protocolNumber: .udp,
        payloadLength: 4
    )
    header.identification = 0xabcd
    header.flags = [.dontFragment]
    header.prepend(to: &packet)

    // A header carrying its own correct checksum sums to zero.
    let emitted = Array(packet.frame.readableBytesView.prefix(20))
    #expect(emitted.withUnsafeBytes { Checksum.compute($0) } == 0)

    var reparsed = PacketBuffer(received: packet.frame)
    let parsed = IPv4Header.parse(&reparsed)
    #expect(parsed?.source == header.source)
    #expect(parsed?.destination == header.destination)
    #expect(parsed?.totalLength == 24)
    #expect(parsed?.ttl == 64)
}
