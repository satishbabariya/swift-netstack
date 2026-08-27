import NIOCore
import Testing

@testable import Netstack

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

    let beforeWrap = reassembler.insert(tcpSegment(0xffff_fffe, [0xcc, 0xcc]), rcvNxt: rcvNxt)
    #expect(beforeWrap.isEmpty)
    let afterWrap = reassembler.insert(tcpSegment(0x0000_0000, [0xdd, 0xdd]), rcvNxt: rcvNxt)
    #expect(afterWrap.isEmpty)
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
    let queued = reassembler.insert(tcpSegment(1100, Array(repeating: 0xbb, count: 10)), rcvNxt: rcvNxt)
    #expect(queued.isEmpty)

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
    let firstQueued = reassembler.insert(tcpSegment(1010, Array(repeating: 0xbb, count: 10)), rcvNxt: rcvNxt)
    #expect(firstQueued.isEmpty)
    let repacketised = reassembler.insert(tcpSegment(1010, Array(repeating: 0xcc, count: 20)), rcvNxt: rcvNxt)
    #expect(repacketised.isEmpty)

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

    let held = reassembler.insert(tcpSegment(1010, Array(repeating: 0xbb, count: 10)), rcvNxt: rcvNxt)
    #expect(held.isEmpty)
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
    let atTheEdge = reassembler.insert(Segment(sequence: rcvNxt + inside, flags: [], payload: ByteBuffer(bytes: [0xaa])), rcvNxt: rcvNxt)
    #expect(atTheEdge.isEmpty)
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
    let outOfOrderFin = reassembler.insert(tcpSegment(1010, Array(repeating: 0xbb, count: 10), flags: .fin), rcvNxt: rcvNxt)
    #expect(outOfOrderFin.isEmpty)
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

    let firstFin = reassembler.insert(tcpSegment(1010, Array(repeating: 0xbb, count: 10), flags: .fin), rcvNxt: rcvNxt)
    #expect(firstFin.isEmpty)
    #expect(reassembler.finSequence == SequenceNumber(1020))

    // A second, contradictory FIN never moves it: same first-received-wins
    // rule the byte ranges follow.
    _ = reassembler.insert(tcpSegment(1030, Array(repeating: 0xcc, count: 10), flags: .fin), rcvNxt: rcvNxt)
    #expect(reassembler.finSequence == SequenceNumber(1020))
    #expect(reassembler.pendingSegments == 1, "nor is its data kept: it sits past a FIN already recorded")
}

@Test func tcpReassemblyRefusesDataAtOrBeyondARecordedFin() {
    // A peer that has sent a FIN has promised no more data, so a byte at or
    // past the FIN's position is a protocol violation. RFC 9293 has no notion
    // of data after a FIN, so no conforming peer can notice this rule.
    //
    // Tested here rather than through `TCPStateMachine` because it cannot be
    // reached through it: once a FIN is recorded it is also reached in the same
    // call (round 1's gate admits a FIN only from a segment starting at
    // RCV.NXT), the connection moves to CLOSE-WAIT, and step 5 stops driving
    // the receiver entirely -- so no later segment gets this far. This class's
    // own API is public and this is where the position lives, which is why the
    // rule is enforced and asserted at this level.
    let reassembler = TCPReassembler(maximumBytes: 4096, maximumSegments: 64)
    let rcvNxt = SequenceNumber(1000)

    _ = reassembler.insert(tcpSegment(1010, [], flags: .fin), rcvNxt: rcvNxt)
    #expect(reassembler.finSequence == SequenceNumber(1010))

    _ = reassembler.insert(tcpSegment(1010, Array(repeating: 0xcc, count: 10)), rcvNxt: rcvNxt)
    #expect(reassembler.pendingSegments == 0, "data at the FIN's own sequence number is refused")

    _ = reassembler.insert(tcpSegment(1020, Array(repeating: 0xcc, count: 10)), rcvNxt: rcvNxt)
    #expect(reassembler.pendingSegments == 0, "and data beyond it")

    // Positive control. Refusing everything satisfies both lines above, and
    // would strand a connection whose FIN is still behind a gap: the bytes that
    // fill that gap arrive after the FIN was recorded and must still be taken.
    _ = reassembler.insert(tcpSegment(1005, Array(repeating: 0xdd, count: 5)), rcvNxt: rcvNxt)
    #expect(reassembler.pendingSegments == 1, "data before the FIN is still admitted")

    let delivered = reassembler.insert(tcpSegment(1000, Array(repeating: 0xaa, count: 5)), rcvNxt: rcvNxt)
    #expect(tcpDeliveredBytes(delivered) == Array(repeating: 0xaa, count: 5) + Array(repeating: 0xdd, count: 5))
    #expect(rcvNxt + tcpDeliveredBytes(delivered).count == reassembler.finSequence, "RCV.NXT lands exactly on the FIN")
}

@Test func tcpReassemblyTrimsAnArrivingSegmentThatStraddlesARecordedFin() {
    let reassembler = TCPReassembler(maximumBytes: 4096, maximumSegments: 64)
    let rcvNxt = SequenceNumber(1000)

    _ = reassembler.insert(tcpSegment(1010, [], flags: .fin), rcvNxt: rcvNxt)
    _ = reassembler.insert(tcpSegment(1008, Array(repeating: 0xcc, count: 10)), rcvNxt: rcvNxt)

    // Two of its ten bytes are before the FIN; eight are not.
    #expect(reassembler.pendingBytes == 2 + TCPReassembler.perSegmentOverhead)
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
    //
    // `storageCapacity` is the quantity COW pinning moves, and it separates
    // the two cases with nothing in between: measured on this input, a queued
    // exactly-sized 1-byte copy reports 1, and the same segment with
    // copy-on-admission deleted reports 2048 — the slice's whole backing
    // frame, since NIO rounds capacity up to a power of two. A 64x margin
    // below the bound asserted here, and no process-wide reading is involved,
    // so no concurrent test can move it either way.
    let reassembler = TCPReassembler(maximumBytes: 1 << 20, maximumSegments: 1024)
    var frame = ByteBufferAllocator().buffer(capacity: 1500)
    frame.writeRepeatingByte(0xaa, count: 1500)
    let oneByte = frame.getSlice(at: frame.readerIndex, length: 1)!
    #expect(oneByte.storageCapacity >= 1500)  // confirms the slice really is COW-backed by the whole frame

    _ = reassembler.insert(Segment(sequence: SequenceNumber(2000), flags: [], payload: oneByte), rcvNxt: SequenceNumber(1000))

    // An upper bound on retained storage is satisfied perfectly by a queue
    // holding nothing, so assert the segment is actually held before bounding
    // what it holds.
    #expect(reassembler.pendingSegments == 1)
    #expect(reassembler.pendingStorageCapacityForTesting <= 32)
}

@Test func tcpReassemblyMemoryLimitBoundsRealRetentionUnderAFloodOfMinimalSegments() {
    // The attack shape: 1-byte out-of-order segments behind a gap that is
    // never filled. Nothing is ever delivered, so the caps are the only thing
    // keeping this bounded. The count cap is set far out of reach so this
    // exercises the BYTE cap specifically — i.e. whether `perSegmentOverhead`
    // and copy-on-admission together make `maximumBytes` bound what is really
    // retained rather than what the segments declared on the wire.
    //
    // Each segment is sliced off its OWN freshly allocated 1500-byte MTU
    // frame. That is how segments really arrive — one NIC read, one frame —
    // and it is also the only shape in which copy-on-write pinning is
    // observable at all. Slicing a whole flood off ONE shared frame (which is
    // what `ReassemblerTests`' equivalent does, and what this test did first)
    // pins a single allocation however many slices point into it, so uncopied
    // slices and fresh copies retain nearly the same amount and the shape is
    // blind to precisely the defect it exists for.
    //
    // NOTHING HERE IS MEASURED. An earlier version of this test read process
    // RSS growth from `getrusage`'s `ru_maxrss` and asserted on the delta,
    // which was wrong in both directions. `ru_maxrss` is a PROCESS-WIDE,
    // monotonically non-decreasing high-water mark, and Swift Testing runs
    // this suite concurrently in one process:
    //
    //  * It fired on unrelated breakage. A change that broke a bound in the
    //    IPv4 reassembler — a different type, a different file — failed this
    //    TCP test, because the peak this reads is the whole process's.
    //  * Far worse, it failed silently the other way. Once any earlier or
    //    concurrent test has pushed the process peak above whatever this
    //    workload would reach, `after - before` reads ~0 and the assertion
    //    passes regardless of what this code actually retained. That is not
    //    an occasional flake: on a process whose peak is already high it
    //    fails to fail on every run, indefinitely. No threshold repairs it —
    //    the defect is in what `ru_maxrss` means, not in where the line was
    //    drawn.
    //
    // The claim is unchanged; only the instrument is. Every assertion below
    // is a deterministic function of this reassembler's own state, and
    // nothing else in the process can move any of them.
    //
    // They are not redundant with one another — each sees a failure the
    // others cannot — and none may be phrased in terms of
    // `perSegmentOverhead`, since a bound that scales with the constant is
    // vacuous the moment the constant is set to zero, which is one of the two
    // regressions to catch:
    //
    //  * `pendingSegments <= 2000` catches the overhead charge going away.
    //    Measured on this exact input: 778 entries survive at the real
    //    constant, 200,000 with it set to zero — the entire flood, more than
    //    two orders of magnitude apart. `storageCapacity` cannot see this
    //    one: with the overhead zeroed each of those 200,000 entries still
    //    holds an exactly-sized 1-byte copy, so per-entry storage is
    //    unchanged at 1. The real per-entry cost (array element, backing
    //    storage object, malloc's minimum bucket) is invisible to
    //    `storageCapacity` by construction; the count is what bounds it.
    //  * `pendingStorageCapacityForTesting` catches copy-on-admission going
    //    away, which the count cannot see, because the number of entries is
    //    identical either way. Measured on this flood: 778 bytes of backing
    //    allocation held with the copy in place, 1,593,344 with it deleted —
    //    every entry pinning its whole 2048-byte frame instead of the 1 byte
    //    it declares — against the 778 * 32 = 24,896 asserted here. A 64x
    //    margin, with no noise in it.
    //  * `pendingSegments > 100` is the positive control. Both bounds above
    //    are upper bounds, and an upper bound is satisfied perfectly by a
    //    reassembler that queued nothing whatsoever.
    //
    // One thing genuinely does not survive the change of instrument, and is
    // recorded here rather than dropped quietly: no test re-measures the
    // ABSOLUTE per-segment cost in resident bytes (167.5 with the copy and no
    // overhead charge, 2207 with neither fix) that calibrates
    // `perSegmentOverhead` at 256. That figure needs a real allocator
    // reading, and a process-wide high-water mark cannot supply one
    // trustworthily under concurrency. It stays a one-off measurement
    // documented on the constant itself. What is guarded here is that both
    // fixes are still in force — which is what a regression would remove —
    // not that 256 is still the numerically right charge.
    let maximumBytes = 200_000
    let reassembler = TCPReassembler(maximumBytes: maximumBytes, maximumSegments: 1_000_000)
    let rcvNxt = SequenceNumber(1000)

    for index in 0..<200_000 {
        var frame = ByteBufferAllocator().buffer(capacity: 1500)
        frame.writeRepeatingByte(0xaa, count: 1500)
        let slice = frame.getSlice(at: index % 1400, length: 1)!
        _ = reassembler.insert(
            Segment(sequence: SequenceNumber(2000 + UInt32(index * 2)), flags: [], payload: slice), rcvNxt: rcvNxt)
    }

    #expect(reassembler.pendingBytes <= maximumBytes)
    #expect(reassembler.pendingSegments <= 2000)
    // Upper bounds alone pass against a reassembler that queues nothing.
    #expect(reassembler.pendingSegments > 100)
    #expect(reassembler.pendingStorageCapacityForTesting <= reassembler.pendingSegments * 32)
}
