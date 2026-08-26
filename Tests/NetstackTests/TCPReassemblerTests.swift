import Foundation
import NIOCore
import Testing

@testable import Netstack

/// Peak resident set size in bytes, as `getrusage` reports it on Darwin.
/// Same technique as `ReassemblerTests.swift`'s `peakResidentBytes` — kept
/// separate rather than shared so neither file's measurement can be changed
/// out from under the other.
private func tcpPeakResidentBytes() -> Int {
    var info = rusage()
    getrusage(RUSAGE_SELF, &info)
    return info.ru_maxrss
}

private func tcpDeliveredBytes(_ buffers: [ByteBuffer]) -> [UInt8] {
    buffers.flatMap { Array($0.readableBytesView) }
}

private func tcpSegment(_ sequence: UInt32, _ bytes: [UInt8], flags: TCPFlags = []) -> Segment {
    Segment(sequence: SequenceNumber(sequence), flags: flags, payload: ByteBuffer(bytes: bytes))
}

// MARK: - Segment

@Test func aSegmentsLengthCountsSynAndFinAsOneSequenceNumberEach() {
    #expect(tcpSegment(1000, [1, 2, 3]).length == 3)
    #expect(tcpSegment(1000, [1, 2, 3], flags: .fin).length == 4)
    #expect(tcpSegment(1000, [], flags: .fin).length == 1)
    #expect(tcpSegment(1000, [1, 2, 3], flags: [.syn, .fin]).length == 5)
    #expect(tcpSegment(1000, [], flags: .ack).length == 0)
}

// MARK: - Ordinary delivery

@Test func tcpReassemblyDeliversAnInOrderSegmentImmediately() {
    let reassembler = TCPReassembler(maximumBytes: 4096, maximumSegments: 64)
    let rcvNxt = SequenceNumber(1000)

    let delivered = reassembler.insert(tcpSegment(1000, [1, 2, 3]), rcvNxt: rcvNxt)

    #expect(tcpDeliveredBytes(delivered) == [1, 2, 3])
    #expect(reassembler.pendingSegments == 0)
    #expect(reassembler.pendingBytes == 0)
}

@Test func tcpReassemblyHoldsAnOutOfOrderSegmentUntilTheGapFills() {
    let reassembler = TCPReassembler(maximumBytes: 4096, maximumSegments: 64)
    let rcvNxt = SequenceNumber(1000)

    let held = reassembler.insert(tcpSegment(1010, Array(repeating: 0xbb, count: 10)), rcvNxt: rcvNxt)
    #expect(held.isEmpty)
    #expect(reassembler.pendingSegments == 1)
    #expect(reassembler.pendingBytes > 0)

    let delivered = reassembler.insert(tcpSegment(1000, Array(repeating: 0xaa, count: 10)), rcvNxt: rcvNxt)
    #expect(tcpDeliveredBytes(delivered) == Array(repeating: 0xaa, count: 10) + Array(repeating: 0xbb, count: 10))
    #expect(reassembler.pendingSegments == 0)
    #expect(reassembler.pendingBytes == 0)
}

@Test func tcpReassemblyDeliversAcrossTheSequenceSpaceWrap() {
    // rcvNxt sits ten bytes below 2^32, so the second half of this stream is
    // at sequence numbers that are numerically SMALLER than the first half.
    // Anything comparing raw `UInt32` order, or ordering by `SequenceNumber`
    // itself rather than by the offset from rcvNxt, delivers these backwards.
    let reassembler = TCPReassembler(maximumBytes: 4096, maximumSegments: 64)
    let rcvNxt = SequenceNumber(0xffff_fff6)

    #expect(reassembler.insert(tcpSegment(0xffff_fffe, [0xcc, 0xcc]), rcvNxt: rcvNxt).isEmpty)
    #expect(reassembler.insert(tcpSegment(0x0000_0000, [0xdd, 0xdd]), rcvNxt: rcvNxt).isEmpty)
    #expect(reassembler.pendingSegments == 2)

    let delivered = reassembler.insert(tcpSegment(0xffff_fff6, Array(repeating: 0xaa, count: 8)), rcvNxt: rcvNxt)
    #expect(tcpDeliveredBytes(delivered) == Array(repeating: 0xaa, count: 8) + [0xcc, 0xcc, 0xdd, 0xdd])
    #expect(reassembler.pendingSegments == 0)
}

// MARK: - Overlap

@Test func tcpReassemblyKeepsTheBytesThatArrivedFirstWhenSegmentsOverlap() {
    let reassembler = TCPReassembler(maximumBytes: 4096, maximumSegments: 64)
    let rcvNxt = SequenceNumber(1000)

    // [1100, 1110) arrives first and is queued behind a gap.
    #expect(reassembler.insert(tcpSegment(1100, Array(repeating: 0xbb, count: 10)), rcvNxt: rcvNxt).isEmpty)

    // A later segment claims [1000, 1150) — overlapping the ten bytes already
    // accepted. Those ten must NOT be rewritten by the newcomer.
    let delivered = reassembler.insert(tcpSegment(1000, Array(repeating: 0xaa, count: 150)), rcvNxt: rcvNxt)

    var expected = Array(repeating: UInt8(0xaa), count: 150)
    expected.replaceSubrange(100..<110, with: Array(repeating: UInt8(0xbb), count: 10))
    #expect(tcpDeliveredBytes(delivered) == expected)
    #expect(reassembler.pendingSegments == 0)
    #expect(reassembler.pendingBytes == 0)
}

@Test func tcpReassemblyKeepsOnlyTheNovelBytesOfAPartiallyOverlappingRetransmission() {
    let reassembler = TCPReassembler(maximumBytes: 4096, maximumSegments: 64)
    let rcvNxt = SequenceNumber(1000)

    // A repacketised retransmission: the second segment repeats bytes already
    // queued and extends past them. Dropping the whole segment because it
    // overlaps (which is what the IPv4 reassembler does) would lose the
    // extension; first-received-wins has to be per BYTE here, not per segment.
    #expect(reassembler.insert(tcpSegment(1010, Array(repeating: 0xbb, count: 10)), rcvNxt: rcvNxt).isEmpty)
    #expect(reassembler.insert(tcpSegment(1010, Array(repeating: 0xcc, count: 20)), rcvNxt: rcvNxt).isEmpty)

    let delivered = reassembler.insert(tcpSegment(1000, Array(repeating: 0xaa, count: 10)), rcvNxt: rcvNxt)
    #expect(
        tcpDeliveredBytes(delivered)
            == Array(repeating: 0xaa, count: 10) + Array(repeating: 0xbb, count: 10) + Array(repeating: 0xcc, count: 10))
}

@Test func tcpReassemblyDiscardsASegmentEntirelyBelowRcvNxt() {
    let reassembler = TCPReassembler(maximumBytes: 4096, maximumSegments: 64)
    let rcvNxt = SequenceNumber(1000)

    let delivered = reassembler.insert(tcpSegment(900, Array(repeating: 0xcc, count: 50)), rcvNxt: rcvNxt)

    #expect(delivered.isEmpty)
    #expect(reassembler.pendingSegments == 0)
    #expect(reassembler.pendingBytes == 0)

    // Control: a reassembler that discards EVERYTHING would satisfy the three
    // expectations above, so prove it is still working — and that no byte of
    // the stale segment survived to be spliced in front of the live one.
    let live = reassembler.insert(tcpSegment(1000, [0x11, 0x22]), rcvNxt: rcvNxt)
    #expect(tcpDeliveredBytes(live) == [0x11, 0x22])
}

@Test func tcpReassemblyTrimsTheAlreadyDeliveredPrefixOfARetransmission() {
    let reassembler = TCPReassembler(maximumBytes: 4096, maximumSegments: 64)
    let rcvNxt = SequenceNumber(1000)

    // [990, 1010): the first ten bytes were already delivered, the last ten
    // are new and in order.
    let delivered = reassembler.insert(
        tcpSegment(990, Array(repeating: 0xaa, count: 10) + Array(repeating: 0xbb, count: 10)), rcvNxt: rcvNxt)

    #expect(tcpDeliveredBytes(delivered) == Array(repeating: 0xbb, count: 10))
    #expect(reassembler.pendingSegments == 0)
}

// MARK: - Bounds

@Test func tcpReassemblyByteCapRejectsFurtherOutOfOrderSegments() {
    // `maximumSegments` is deliberately far out of reach here so the byte cap
    // is the only thing that can bind.
    let reassembler = TCPReassembler(maximumBytes: 2000, maximumSegments: 1_000_000)
    let rcvNxt = SequenceNumber(1000)

    for index in 0..<500 {
        _ = reassembler.insert(tcpSegment(2000 + UInt32(index * 2), [0xbb]), rcvNxt: rcvNxt)
    }

    // A flat bound, deliberately not phrased in terms of
    // `perSegmentOverhead`: `2000 / (1 + perSegmentOverhead)` would be 2000
    // with the overhead charge set to zero, and every one of the 500
    // segments offered would satisfy it. ~7 fit at the real constant.
    #expect(reassembler.pendingBytes <= 2000)
    #expect(reassembler.pendingSegments <= 50)
    #expect(reassembler.pendingSegments > 0)
}

@Test func tcpReassemblySegmentCountCapRejectsFurtherOutOfOrderSegments() {
    // The mirror image of the byte-cap test: `maximumBytes` is far out of
    // reach, so only the count cap can bind. The brief's
    // `aPinnedGapCannotGrowTheQueueWithoutBound` does NOT isolate this — with
    // `perSegmentOverhead` charged, its byte cap binds first and its count
    // assertion passes even with the count cap deleted. This test is the one
    // that actually falsifies the count cap.
    let reassembler = TCPReassembler(maximumBytes: 1 << 20, maximumSegments: 8)
    let rcvNxt = SequenceNumber(1000)

    for index in 0..<500 {
        _ = reassembler.insert(tcpSegment(2000 + UInt32(index * 2), [UInt8(index % 256)]), rcvNxt: rcvNxt)
    }

    #expect(reassembler.pendingSegments == 8)
    #expect(reassembler.pendingBytes < 1 << 20)
}

@Test func tcpReassemblyRejectsTheNewestSegmentRatherThanEvictingQueuedOnes() {
    // Unlike an IP fragment, a rejected TCP segment is harmless — the peer
    // retransmits it. Evicting a queued segment to make room would instead
    // throw away data that has already been paid for, so when a cap binds the
    // NEWCOMER loses. Verified by filling the queue and then checking that the
    // bytes which survive are the ones admitted first.
    let reassembler = TCPReassembler(maximumBytes: 1 << 20, maximumSegments: 4)
    let rcvNxt = SequenceNumber(1000)

    for index in 0..<4 {
        _ = reassembler.insert(tcpSegment(1001 + UInt32(index), [UInt8(0xa0 + index)]), rcvNxt: rcvNxt)
    }
    #expect(reassembler.pendingSegments == 4)

    // Newcomers, all rejected: the queue is unchanged.
    for index in 0..<50 {
        _ = reassembler.insert(tcpSegment(2000 + UInt32(index * 2), [0xff]), rcvNxt: rcvNxt)
    }
    #expect(reassembler.pendingSegments == 4)

    let delivered = reassembler.insert(tcpSegment(1000, [0x99]), rcvNxt: rcvNxt)
    #expect(tcpDeliveredBytes(delivered) == [0x99, 0xa0, 0xa1, 0xa2, 0xa3])
}

@Test func tcpReassemblyNeverRejectsInOrderDataEvenWhenEveryCapIsAtItsLimit() {
    // The stall this closes: if in-order data could be rejected for want of
    // queue room, the segment that fills the gap would be refused by a queue
    // full of the very out-of-order segments waiting on that gap, and the
    // connection would never make progress again. In-order data is delivered
    // straight out, never queued, so no cap ever applies to it.
    let reassembler = TCPReassembler(maximumBytes: 400, maximumSegments: 4)
    let rcvNxt = SequenceNumber(1000)

    for index in 0..<50 {
        _ = reassembler.insert(tcpSegment(5000 + UInt32(index * 2), [0xbb]), rcvNxt: rcvNxt)
    }
    #expect(reassembler.pendingSegments > 0)

    let delivered = reassembler.insert(tcpSegment(1000, Array(repeating: 0xaa, count: 100)), rcvNxt: rcvNxt)
    #expect(tcpDeliveredBytes(delivered) == Array(repeating: 0xaa, count: 100))
}

@Test func tcpReassemblyDeliversEveryPieceUnlockedByOneInOrderSegment() {
    // An in-order segment that STRADDLES a queued run: [1000, 1030) arriving
    // with [1010, 1020) already queued splits into two novel pieces, and the
    // second one ([1020, 1030)) only becomes contiguous once the queued run
    // between them is delivered. Exempting merely "the piece at offset zero"
    // from the caps would drop that tail whenever the queue is full.
    let reassembler = TCPReassembler(maximumBytes: 400, maximumSegments: 1)
    let rcvNxt = SequenceNumber(1000)

    #expect(reassembler.insert(tcpSegment(1010, Array(repeating: 0xbb, count: 10)), rcvNxt: rcvNxt).isEmpty)
    #expect(reassembler.pendingSegments == 1)

    let delivered = reassembler.insert(tcpSegment(1000, Array(repeating: 0xaa, count: 30)), rcvNxt: rcvNxt)
    #expect(
        tcpDeliveredBytes(delivered)
            == Array(repeating: 0xaa, count: 10) + Array(repeating: 0xbb, count: 10) + Array(repeating: 0xaa, count: 10))
    #expect(reassembler.pendingSegments == 0)
}

@Test func aPinnedGapCannotGrowTheQueueWithoutBound() {
    let reassembler = TCPReassembler(maximumBytes: 4096, maximumSegments: 64)
    let rcvNxt = SequenceNumber(1000)

    // A gap at 1000 that is never filled; this segment pins the queue head.
    _ = reassembler.insert(tcpSegment(2000, [0xaa]), rcvNxt: rcvNxt)

    for offset in 0..<10_000 {
        _ = reassembler.insert(tcpSegment(3000 + UInt32(offset * 2), [0xbb]), rcvNxt: rcvNxt)
    }

    #expect(reassembler.pendingSegments <= 64)
    #expect(reassembler.pendingBytes <= 4096)

    // The two upper bounds above are, on their own, satisfied by a
    // reassembler that queues nothing whatsoever — they were observed passing
    // against an empty stub. These make the bounds mean "held, and bounded"
    // rather than merely "bounded".
    #expect(reassembler.pendingSegments > 0)
    #expect(reassembler.pendingBytes > 0)
}

// MARK: - The `Comparable` hazard

@Test func tcpReassemblyRejectsASegmentAbsurdlyFarPastRcvNxt() {
    // `SequenceNumber`'s `<` is RFC 1982 serial arithmetic, which is not a
    // strict weak ordering over the whole 32-bit space: at exactly 2^31 apart
    // it answers false in both directions, and beyond that it is not
    // transitive. Keeping the queue's domain far inside half the space is what
    // makes ordering these well defined at all, so a segment outside it is
    // refused at the door rather than sorted.
    let reassembler = TCPReassembler(maximumBytes: 1 << 20, maximumSegments: 1024)
    let rcvNxt = SequenceNumber(1000)

    for distance in [(1 << 30) + 1, 1 << 31, (1 << 31) + 1000, 3 << 30] {
        let delivered = reassembler.insert(
            Segment(sequence: rcvNxt + distance, flags: .fin, payload: ByteBuffer(bytes: [0xaa])), rcvNxt: rcvNxt)
        #expect(delivered.isEmpty)
    }

    #expect(reassembler.pendingSegments == 0)
    #expect(reassembler.pendingBytes == 0)
    #expect(reassembler.finSequence == nil)

    // Control: every expectation above is satisfied by a reassembler that
    // refuses everything, so prove the refusals were about the DISTANCE. The
    // same segment shape just inside the domain is admitted, and its FIN
    // recorded.
    _ = reassembler.insert(tcpSegment(2000, [0xaa], flags: .fin), rcvNxt: rcvNxt)
    #expect(reassembler.pendingSegments == 1)
    #expect(reassembler.finSequence == SequenceNumber(2001))
}

@Test func tcpReassemblyAcceptsASegmentAtTheEdgeOfTheAdmissibleDomain() {
    let reassembler = TCPReassembler(maximumBytes: 1 << 20, maximumSegments: 1024)
    let rcvNxt = SequenceNumber(1000)

    let inside = TCPReassembler.maximumSequenceOffset - 1
    #expect(reassembler.insert(Segment(sequence: rcvNxt + inside, flags: [], payload: ByteBuffer(bytes: [0xaa])), rcvNxt: rcvNxt).isEmpty)
    #expect(reassembler.pendingSegments == 1)
}

@Test func theAdmissibleSequenceDomainStaysFarInsideHalfTheSequenceSpace() {
    // Every queued offset lives in [0, maximumSequenceOffset], so the largest
    // distance between any two queued sequence numbers is that bound. Held
    // well under 2^31, that keeps every comparison this class makes inside the
    // range where RFC 1982 ordering is total.
    #expect(TCPReassembler.maximumSequenceOffset <= 1 << 30)
    #expect(TCPReassembler.maximumSequenceOffset >= 1 << 20)
}

// MARK: - The FIN seam

@Test func tcpReassemblyKeepsAnOutOfOrderFinAcrossTheGapFilling() {
    let reassembler = TCPReassembler(maximumBytes: 4096, maximumSegments: 64)
    let rcvNxt = SequenceNumber(1000)

    // FIN-bearing segment arrives out of order: data [1010, 1020), FIN at 1020.
    #expect(reassembler.insert(tcpSegment(1010, Array(repeating: 0xbb, count: 10), flags: .fin), rcvNxt: rcvNxt).isEmpty)
    #expect(reassembler.finSequence == SequenceNumber(1020))

    let delivered = reassembler.insert(tcpSegment(1000, Array(repeating: 0xaa, count: 10)), rcvNxt: rcvNxt)
    #expect(tcpDeliveredBytes(delivered).count == 20)

    // The FIN survived the gap filling, and the caller's advanced rcvNxt now
    // sits exactly on it — which is the signal that the FIN is in order.
    #expect(reassembler.finSequence == SequenceNumber(1020))
    #expect(rcvNxt + tcpDeliveredBytes(delivered).count == reassembler.finSequence)
}

@Test func tcpReassemblyRecordsAnInOrderBareFin() {
    let reassembler = TCPReassembler(maximumBytes: 4096, maximumSegments: 64)
    let rcvNxt = SequenceNumber(1000)

    let delivered = reassembler.insert(tcpSegment(1000, [], flags: .fin), rcvNxt: rcvNxt)

    #expect(delivered.isEmpty)
    #expect(reassembler.finSequence == SequenceNumber(1000))
    #expect(reassembler.pendingSegments == 0)
}

@Test func tcpReassemblyKeepsTheFirstFinPositionItWasTold() {
    let reassembler = TCPReassembler(maximumBytes: 4096, maximumSegments: 64)
    let rcvNxt = SequenceNumber(1000)

    #expect(reassembler.insert(tcpSegment(1010, Array(repeating: 0xbb, count: 10), flags: .fin), rcvNxt: rcvNxt).isEmpty)
    #expect(reassembler.finSequence == SequenceNumber(1020))

    // A second, contradictory FIN never moves it: same first-received-wins
    // rule the byte ranges follow.
    _ = reassembler.insert(tcpSegment(1030, Array(repeating: 0xcc, count: 10), flags: .fin), rcvNxt: rcvNxt)
    #expect(reassembler.finSequence == SequenceNumber(1020))
}

@Test func tcpReassemblyIgnoresAFinAlreadyBehindRcvNxt() {
    let reassembler = TCPReassembler(maximumBytes: 4096, maximumSegments: 64)
    let rcvNxt = SequenceNumber(1000)

    _ = reassembler.insert(tcpSegment(900, Array(repeating: 0xcc, count: 50), flags: .fin), rcvNxt: rcvNxt)

    #expect(reassembler.finSequence == nil)

    // Control: a reassembler that never records a FIN at all would pass the
    // line above. One at or ahead of rcvNxt still has to be recorded.
    _ = reassembler.insert(tcpSegment(990, Array(repeating: 0xcc, count: 50), flags: .fin), rcvNxt: rcvNxt)
    #expect(reassembler.finSequence == SequenceNumber(1040))
}

// MARK: - Real retained memory

@Test func tcpReassemblyAdmittedSegmentsDoNotPinTheirOriginalFrameStorage() {
    // A NIO slice is copy-on-write: it keeps a live reference to the ENTIRE
    // original allocation. Queued as received, one byte sliced off a 1500-byte
    // MTU frame pins all 1500 bytes while `pendingBytes` sees one.
    let reassembler = TCPReassembler(maximumBytes: 1 << 20, maximumSegments: 1024)
    var frame = ByteBufferAllocator().buffer(capacity: 1500)
    frame.writeRepeatingByte(0xaa, count: 1500)
    let oneByte = frame.getSlice(at: frame.readerIndex, length: 1)!
    #expect(oneByte.storageCapacity >= 1500)  // confirms the slice really is COW-backed by the whole frame

    _ = reassembler.insert(Segment(sequence: SequenceNumber(2000), flags: [], payload: oneByte), rcvNxt: SequenceNumber(1000))

    #expect(reassembler.pendingSegments == 1)
    #expect(reassembler.pendingStorageCapacityForTesting < 1500)
}

@Test func tcpReassemblyMemoryLimitBoundsRealRSSUnderAFloodOfMinimalSegments() {
    // The attack shape: 1-byte out-of-order segments behind a gap that is
    // never filled. Nothing is ever delivered, so the caps are the only thing
    // keeping this bounded. The count cap is set far out of reach so this
    // measures the BYTE cap specifically — i.e. whether `perSegmentOverhead`
    // and copy-on-admission together make `maximumBytes` track real
    // retention.
    //
    // Each segment is sliced off its OWN freshly allocated 1500-byte MTU
    // frame, because that is how segments really arrive — one NIC read, one
    // frame. Slicing them all off a single shared frame (which is what
    // `ReassemblerTests`' equivalent does, and what this test did first)
    // makes the test blind to exactly the defect it is here for: the shared
    // frame is one allocation no matter how many slices reference it, so
    // copy-on-admission can be deleted entirely and this measures 86 bytes
    // per segment and passes. With distinct frames it measures 2207.
    //
    // Two assertions do the work, and neither may be phrased in terms of
    // `perSegmentOverhead`: a bound that scales with the constant is vacuous
    // the moment the constant is set to zero, which is precisely the
    // regression to catch. `pendingSegments` is bounded by a flat number
    // instead — ~778 entries fit at the current constant, 200,000 fit at
    // zero, so the two are three orders of magnitude apart.
    //
    // Read `ReassemblerTests.reassemblyMemoryLimitBoundsRealRSSUnderAFloodOfMinimalFragments`
    // for why the `getrusage` half is indicative only and NOT protection:
    // `ru_maxrss` is a process-wide high-water mark, so an unrelated
    // concurrent test that has already pushed the peak up makes `grown` read
    // ~0 and pass regardless. `pendingSegments` is the real guard — it reads
    // this class's own deterministic count, which nothing else in the process
    // can move.
    let maximumBytes = 200_000
    let reassembler = TCPReassembler(maximumBytes: maximumBytes, maximumSegments: 1_000_000)
    let rcvNxt = SequenceNumber(1000)

    let before = tcpPeakResidentBytes()
    for index in 0..<200_000 {
        var frame = ByteBufferAllocator().buffer(capacity: 1500)
        frame.writeRepeatingByte(0xaa, count: 1500)
        let slice = frame.getSlice(at: index % 1400, length: 1)!
        _ = reassembler.insert(
            Segment(sequence: SequenceNumber(2000 + UInt32(index * 2)), flags: [], payload: slice), rcvNxt: rcvNxt)
    }
    let grown = tcpPeakResidentBytes() - before

    #expect(reassembler.pendingBytes <= maximumBytes)
    #expect(reassembler.pendingSegments <= 2000)
    // Upper bounds alone pass against a reassembler that queues nothing.
    #expect(reassembler.pendingSegments > 100)
    #expect(grown < 30_000_000)
}
