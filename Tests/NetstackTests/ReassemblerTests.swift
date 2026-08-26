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
    let reassembler = Reassembler(clock: ManualClock())
    // Offset 65528 plus 16 bytes exceeds the 65535-byte IPv4 maximum.
    let bad = fragment(id: 3, offset: 65528, more: false, bytes: Array(repeating: UInt8(0), count: 16))
    #expect(reassembler.process(header: bad.0, payload: bad.1) == nil)
    #expect(reassembler.pendingCount == 0)
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
