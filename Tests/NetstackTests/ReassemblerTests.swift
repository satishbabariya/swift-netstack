import NIOCore
import Testing

@testable import Netstack

private func fragment(id: UInt16, offset: Int, more: Bool, bytes: [UInt8]) -> (IPv4Header, ByteBuffer) {
    var header = IPv4Header(
        source: IPv4Address("192.168.127.2")!,
        destination: IPv4Address("192.168.127.1")!,
        protocolNumber: .udp,
        payloadLength: bytes.count
    )
    header.identification = id
    header.fragmentOffset = offset
    header.flags = more ? [.moreFragments] : []
    return (header, ByteBuffer(bytes: bytes))
}

/// A fragment whose header carries IPv4 options (IHL 6, a 24-byte header),
/// built from raw wire bytes and parsed through `IPv4Header.parse` — the
/// only way to get a `headerLength` other than the minimum 20, since its
/// setter is private. Options are NOP NOP NOP EOL (0x01 0x01 0x01 0x00).
private func fragmentWithOptions(id: UInt16, offset: Int, more: Bool, payloadLength: Int) -> (IPv4Header, ByteBuffer) {
    let headerLength = 24
    var bytes = [UInt8](repeating: 0, count: headerLength)
    bytes[0] = 0x46  // version 4, IHL 6 (24-byte header)
    bytes[1] = 0x00  // DSCP

    let totalLength = UInt16(headerLength + payloadLength)
    bytes[2] = UInt8(totalLength >> 8)
    bytes[3] = UInt8(totalLength & 0xff)

    bytes[4] = UInt8(id >> 8)
    bytes[5] = UInt8(id & 0xff)

    let offsetWords = UInt16(offset / 8)
    let flagsAndOffset = (more ? UInt16(0x2000) : 0) | offsetWords
    bytes[6] = UInt8(flagsAndOffset >> 8)
    bytes[7] = UInt8(flagsAndOffset & 0xff)

    bytes[8] = 64  // TTL
    bytes[9] = IPProtocol.udp.rawValue
    // bytes[10...11] checksum, filled in below.

    let source = IPv4Address("192.168.127.2")!
    let destination = IPv4Address("192.168.127.1")!
    bytes.replaceSubrange(12..<16, with: source.bytes)
    bytes.replaceSubrange(16..<20, with: destination.bytes)
    bytes[20] = 0x01  // NOP
    bytes[21] = 0x01  // NOP
    bytes[22] = 0x01  // NOP
    bytes[23] = 0x00  // EOL

    let checksum = bytes.withUnsafeBytes { Checksum.compute($0) }
    bytes[10] = UInt8(checksum >> 8)
    bytes[11] = UInt8(checksum & 0xff)

    let payload = Array(repeating: UInt8(0xaa), count: payloadLength)
    var packet = PacketBuffer(received: ByteBuffer(bytes: bytes + payload))
    let header = IPv4Header.parse(&packet)!
    return (header, packet.payload)
}

@Test func anUnfragmentedPacketPassesStraightThrough() {
    let reassembler = Reassembler(clock: ManualClock())
    let (header, payload) = fragment(id: 1, offset: 0, more: false, bytes: [0x01, 0x02])
    let result = reassembler.process(header: header, payload: payload)
    #expect(result != nil)
    #expect(Array(result!.1.readableBytesView) == [0x01, 0x02])
    #expect(reassembler.pendingCount == 0)
}

@Test func reassemblesFragmentsInOrder() {
    let reassembler = Reassembler(clock: ManualClock())
    let first = fragment(id: 7, offset: 0, more: true, bytes: Array(repeating: UInt8(0xaa), count: 8))
    let second = fragment(id: 7, offset: 8, more: false, bytes: [0xbb, 0xbb])

    #expect(reassembler.process(header: first.0, payload: first.1) == nil)
    #expect(reassembler.pendingCount == 1)

    let result = reassembler.process(header: second.0, payload: second.1)
    #expect(result != nil)
    #expect(result!.1.readableBytes == 10)
    #expect(Array(result!.1.readableBytesView.suffix(2)) == [0xbb, 0xbb])
    #expect(reassembler.pendingCount == 0)
}

@Test func reassemblesFragmentsOutOfOrder() {
    let reassembler = Reassembler(clock: ManualClock())
    let last = fragment(id: 9, offset: 16, more: false, bytes: [0xcc])
    let middle = fragment(id: 9, offset: 8, more: true, bytes: Array(repeating: UInt8(0xbb), count: 8))
    let first = fragment(id: 9, offset: 0, more: true, bytes: Array(repeating: UInt8(0xaa), count: 8))

    #expect(reassembler.process(header: last.0, payload: last.1) == nil)
    #expect(reassembler.process(header: middle.0, payload: middle.1) == nil)
    let result = reassembler.process(header: first.0, payload: first.1)

    #expect(result != nil)
    let bytes = Array(result!.1.readableBytesView)
    #expect(bytes.count == 17)
    #expect(bytes[0] == 0xaa)
    #expect(bytes[8] == 0xbb)
    #expect(bytes[16] == 0xcc)
}

@Test func keepsDatagramsWithDifferentIdentificationsApart() {
    let reassembler = Reassembler(clock: ManualClock())
    let a = fragment(id: 1, offset: 0, more: true, bytes: Array(repeating: UInt8(0x11), count: 8))
    let b = fragment(id: 2, offset: 0, more: true, bytes: Array(repeating: UInt8(0x22), count: 8))
    _ = reassembler.process(header: a.0, payload: a.1)
    _ = reassembler.process(header: b.0, payload: b.1)
    #expect(reassembler.pendingCount == 2)

    let aTail = fragment(id: 1, offset: 8, more: false, bytes: [0x11])
    let result = reassembler.process(header: aTail.0, payload: aTail.1)
    #expect(result?.1.readableBytes == 9)
    #expect(reassembler.pendingCount == 1)
}

@Test func expiresIncompleteDatagrams() {
    let clock = ManualClock()
    let reassembler = Reassembler(clock: clock, timeout: .seconds(30))
    let first = fragment(id: 5, offset: 0, more: true, bytes: Array(repeating: UInt8(0xaa), count: 8))
    _ = reassembler.process(header: first.0, payload: first.1)
    #expect(reassembler.pendingCount == 1)

    clock.advance(by: .seconds(31))
    reassembler.reapExpired()
    #expect(reassembler.pendingCount == 0)

    // The late tail must not resurrect the discarded datagram.
    let second = fragment(id: 5, offset: 8, more: false, bytes: [0xbb])
    #expect(reassembler.process(header: second.0, payload: second.1) == nil)
}

@Test func evictsTheOldestWhenOverTheMemoryLimit() {
    let clock = ManualClock()
    let reassembler = Reassembler(clock: clock, timeout: .seconds(30), memoryLimit: 24)
    for id in UInt16(1)...UInt16(5) {
        let f = fragment(id: id, offset: 0, more: true, bytes: Array(repeating: UInt8(id), count: 8))
        _ = reassembler.process(header: f.0, payload: f.1)
        clock.advance(by: .milliseconds(1))
    }
    // 5 x 8 bytes exceeds the 24-byte cap; the oldest are evicted.
    #expect(reassembler.pendingCount == 3)
}

@Test func rejectsAFragmentThatWouldOverrunTheMaximumDatagram() {
    // The 65535 limit covers header + payload. A payload that fits the
    // limit on its own but overruns it once the 20-byte header is added
    // must be rejected at admission — at assembly the conversion to
    // UInt16 is non-failable and would trap the process.
    let reassembler = Reassembler(clock: ManualClock())
    let head = fragment(id: 40, offset: 0, more: true, bytes: Array(repeating: UInt8(0xaa), count: 65512))
    // `process` returns nil for any incomplete, still-pending fragment
    // whether it was accepted or rejected, so that alone proves nothing.
    // pendingCount confirms this one really was accepted.
    #expect(reassembler.process(header: head.0, payload: head.1) == nil)
    #expect(reassembler.pendingCount == 1)

    // end = 65520; 65520 + 20 > 65535, so this must be refused.
    let tail = fragment(id: 40, offset: 65512, more: false, bytes: Array(repeating: UInt8(0xbb), count: 8))
    #expect(reassembler.process(header: tail.0, payload: tail.1) == nil)
    #expect(reassembler.pendingCount == 1)   // still incomplete, not assembled
}

@Test func rejectsASingleFragmentWhosePayloadAloneExceedsTheMaximum() {
    // A single fragment whose payload alone already exceeds 65535 must be
    // caught even before the header is added in. Pinned separately from the
    // header+payload case above so that if the admission bound is ever split
    // into two conditions, this input still has a test that catches it.
    let reassembler = Reassembler(clock: ManualClock())
    let bad = fragment(id: 3, offset: 65528, more: false, bytes: Array(repeating: UInt8(0), count: 16))
    #expect(reassembler.process(header: bad.0, payload: bad.1) == nil)
    #expect(reassembler.pendingCount == 0)
}

@Test func aFirstFragmentWithOptionsCannotOverrunTheDatagramLimit() {
    // The stored entry header is fixed by the fragment that creates the
    // entry and may carry options; totalLength comes from the terminator.
    // Bounding each fragment against its OWN header lets three
    // individually-admissible fragments overflow at assembly, which traps.
    //
    // The datagram totals 65515 payload bytes: 20 + 65515 == 65535 fits, but
    // 24 + 65515 == 65539 does not. A fragmenting sender never actually
    // splits a datagram this way (only the first fragment ever carries the
    // original header, options included, and IP fragmentation itself is
    // rare at all) — this is a hostile construction, not a valid multi-hop
    // fragmentation pattern.
    let reassembler = Reassembler(clock: ManualClock())

    // Creates the entry. Its 24-byte header (options) becomes entry.header.
    let head = fragmentWithOptions(id: 60, offset: 0, more: true, payloadLength: 15)
    #expect(reassembler.process(header: head.0, payload: head.1) == nil)
    #expect(reassembler.pendingCount == 1)

    // Ordinary 20-byte header. Its OWN header + end (20 + 65515) would fit,
    // but the entry's stored 24-byte header + end (24 + 65515 = 65539)
    // does not — this must be rejected, and no assembly may occur.
    let terminator = fragment(id: 60, offset: 15, more: false, bytes: Array(repeating: UInt8(0xbb), count: 65500))
    let result = reassembler.process(header: terminator.0, payload: terminator.1)
    #expect(result == nil)
    #expect(reassembler.pendingCount == 1)   // only the head fragment's entry remains
}

@Test func rejectsAnOverlappingFragment() {
    // Legitimate fragmentation never overlaps. An overlapping fragment is
    // an attempt to rewrite bytes already accepted (the teardrop family),
    // so it is dropped rather than merged — and the datagram still
    // completes from the fragments that were accepted.
    let reassembler = Reassembler(clock: ManualClock())
    let first = fragment(id: 20, offset: 0, more: true, bytes: Array(repeating: UInt8(0xaa), count: 8))
    #expect(reassembler.process(header: first.0, payload: first.1) == nil)

    // Overlaps bytes 4..<8, which are already accepted. Must be dropped.
    let overlapping = fragment(id: 20, offset: 4, more: true, bytes: Array(repeating: UInt8(0xff), count: 8))
    #expect(reassembler.process(header: overlapping.0, payload: overlapping.1) == nil)

    let last = fragment(id: 20, offset: 8, more: false, bytes: [0xbb, 0xbb])
    let result = reassembler.process(header: last.0, payload: last.1)

    #expect(result != nil)
    let bytes = Array(result!.1.readableBytesView)
    #expect(bytes.count == 10)
    #expect(bytes.prefix(8).allSatisfy { $0 == 0xaa })   // 0xff never landed
    #expect(Array(bytes.suffix(2)) == [0xbb, 0xbb])
}

@Test func duplicateFragmentsCannotEvictOtherDatagrams() {
    // The eviction policy is oldest-first when over the memory cap. If a
    // peer's duplicate fragments were counted repeatedly, it could inflate
    // its own accounted size and push an older, legitimate datagram out.
    let clock = ManualClock()
    let reassembler = Reassembler(clock: clock, timeout: .seconds(30), memoryLimit: 24)

    let victim = fragment(id: 1, offset: 0, more: true, bytes: Array(repeating: UInt8(0x11), count: 8))
    _ = reassembler.process(header: victim.0, payload: victim.1)
    clock.advance(by: .milliseconds(1))

    // The same fragment of a second datagram, sent four times.
    for _ in 0..<4 {
        let flood = fragment(id: 2, offset: 0, more: true, bytes: Array(repeating: UInt8(0x22), count: 8))
        _ = reassembler.process(header: flood.0, payload: flood.1)
    }

    // Held bytes must be 16, not 40 — so nothing was evicted and the
    // older datagram survives.
    #expect(reassembler.pendingCount == 2)

    let victimTail = fragment(id: 1, offset: 8, more: false, bytes: [0x11])
    #expect(reassembler.process(header: victimTail.0, payload: victimTail.1)?.1.readableBytes == 9)
}

@Test func rejectsASecondFinalFragmentThatDisagrees() {
    // The fragment with moreFragments clear defines where the datagram
    // ends. A second one claiming a different end must not overwrite it,
    // or a peer could truncate or extend someone else's datagram.
    let reassembler = Reassembler(clock: ManualClock())
    let terminator = fragment(id: 30, offset: 8, more: false, bytes: [0xbb, 0xbb])
    #expect(reassembler.process(header: terminator.0, payload: terminator.1) == nil)

    // Different end (18, not 10), and deliberately non-overlapping so the
    // overlap check cannot be what rejects it.
    let conflicting = fragment(id: 30, offset: 16, more: false, bytes: [0xcc, 0xcc])
    #expect(reassembler.process(header: conflicting.0, payload: conflicting.1) == nil)

    let head = fragment(id: 30, offset: 0, more: true, bytes: Array(repeating: UInt8(0xaa), count: 8))
    let result = reassembler.process(header: head.0, payload: head.1)

    // Completes at the length the FIRST terminator declared: 10 bytes.
    #expect(result?.1.readableBytes == 10)
}

@Test func rejectsEmptyFragments() {
    // Zero-length fragments evade the overlap test and the memory cap, so
    // a peer could repeat one indefinitely to grow the pending table.
    let reassembler = Reassembler(clock: ManualClock())
    for _ in 0..<100 {
        let empty = fragment(id: 50, offset: 0, more: true, bytes: [])
        #expect(reassembler.process(header: empty.0, payload: empty.1) == nil)
    }
    #expect(reassembler.pendingCount == 0)

    // A non-fragmented packet with an empty payload is still delivered.
    let bare = fragment(id: 51, offset: 0, more: false, bytes: [])
    #expect(reassembler.process(header: bare.0, payload: bare.1) != nil)
}
