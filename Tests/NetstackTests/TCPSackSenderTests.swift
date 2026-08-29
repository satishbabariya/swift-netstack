import NIOCore
import Testing

@testable import Netstack

// RFC 6675, sender half: use what the peer reports to decide what is still in
// the network and what has been lost, instead of inferring both from a count of
// repeated acknowledgements.
//
// The differential against gVisor covers these paths end to end with SACK
// negotiated on both sides. These are here because a divergence there tells you
// two stacks disagree, not which rule was broken.

private let sackSenderStart = NIODeadline.uptimeNanoseconds(0)

private func sackPayload(_ count: Int) -> ByteBuffer {
    var buffer = ByteBufferAllocator().buffer(capacity: count)
    buffer.writeBytes([UInt8](repeating: 0x41, count: count))
    return buffer
}

/// SND.UNA = SND.NXT = 100 with SACK negotiated, so the sender's scoreboard is
/// live and its blocks are believed.
private func sackTCB(sndWnd: Int = 65535) -> TCB {
    var tcb = TCB(
        state: .established,
        sndUna: SequenceNumber(100),
        sndNxt: SequenceNumber(100),
        sndWnd: sndWnd,
        sndWl1: SequenceNumber(1000),
        sndWl2: SequenceNumber(100),
        iss: SequenceNumber(100),
        rcvNxt: SequenceNumber(1000),
        rcvWnd: 4096,
        irs: SequenceNumber(1000),
        offersSelectiveAcknowledgement: true)
    tcb.negotiateSelectiveAcknowledgement(fromSynOptions: [.sackPermitted])
    #expect(tcb.sackPermitted, "the fixture did not negotiate SACK: every test below would prove nothing")
    return tcb
}

private func sackSender(segmentSize: Int = 1000) -> Sender {
    Sender(
        congestionControl: Reno(maximumSegmentSize: segmentSize),
        clock: ManualClock(start: sackSenderStart), maximumBufferedBytes: 1 << 20)
}

/// Ten 1000-byte segments in flight from sequence 100.
private func tenSegmentsInFlight(_ sender: inout Sender, _ tcb: inout TCB) {
    let accepted = sender.write(sackPayload(10000))
    #expect(accepted)
    let segments = sender.segmentsToTransmit(tcb: &tcb, mss: 1000)
    #expect(segments.count == 10, "the fixture did not fill the window")
}

/// A block covering the whole of the segment starting at `index`, counting from
/// sequence 100 in 1000-byte segments.
private func block(_ index: Int, count: Int = 1) -> SACKBlock {
    SACKBlock(
        left: SequenceNumber(UInt32(100 + index * 1000)),
        right: SequenceNumber(UInt32(100 + (index + count) * 1000)))
}

private func ack(
    _ sender: inout Sender, _ tcb: inout TCB, upTo: UInt32 = 100, blocks: [SACKBlock] = []
) {
    _ = sender.acknowledged(
        upTo: SequenceNumber(upTo), tcb: &tcb, advertisedWindow: tcb.sndWnd,
        selectiveAcknowledgements: blocks)
}

@Test func selectivelyAcknowledgedBytesLeaveThePipe() {
    // The whole point of the scoreboard. Bytes the peer says it holds are not in
    // the network, so the window they were occupying is free -- which is what
    // lets a sender keep sending during recovery instead of waiting out a
    // round trip for a cumulative acknowledgement that cannot come until the
    // hole is filled.
    var tcb = sackTCB()
    var sender = sackSender()
    tenSegmentsInFlight(&sender, &tcb)
    #expect(sender.pipeSize == 10000, "positive control: everything is in the pipe to begin with")

    ack(&sender, &tcb, blocks: [block(5), block(7)])

    #expect(sender.selectivelyAcknowledgedBytes == 2000)
    #expect(sender.flightSize == 10000, "SACK is advisory: it retires nothing")
    #expect(sender.pipeSize < 10000, "the reported bytes are still counted as in the network")
}

@Test func aBlockCoveringOnlyPartOfASegmentLeavesItInThePipe() {
    // Whole records only, and the direction of the mistake is what matters. An
    // unmarked record is counted in the pipe and may be retransmitted, which
    // costs bandwidth; a record marked on a partial arrival is a hole nothing
    // will ever fill.
    var tcb = sackTCB()
    var sender = sackSender()
    tenSegmentsInFlight(&sender, &tcb)

    ack(
        &sender, &tcb,
        blocks: [SACKBlock(left: SequenceNumber(5100), right: SequenceNumber(5600))])

    #expect(sender.selectivelyAcknowledgedBytes == 0)
    #expect(sender.pipeSize == 10000)
}

@Test func threeSeparateRunsAboveAHoleDeclareItLost() {
    // RFC 6675 §4's `IsLost`, by its run count. Three separate arrivals above a
    // gap are the same evidence three duplicate acknowledgements are, and the
    // scoreboard is what turns it from a count into a statement about which
    // segment is missing.
    var tcb = sackTCB()
    var sender = sackSender()
    tenSegmentsInFlight(&sender, &tcb)

    // Runs at 2, 4, 6 and 8, each separated by a hole, so four discontiguous
    // runs sit above segment 0 -- one more than DupThresh.
    ack(&sender, &tcb, blocks: [block(2), block(4), block(6), block(8)])

    #expect(sender.presumedLostBytes > 0, "the hole below four separate runs was not declared lost")
    #expect(sender.inScoreboardRecovery)
}

@Test func enoughSackedBytesAboveAHoleDeclareItLostEvenInOneRun() {
    // §4's other arm, and it is not the same test. One contiguous arrival of
    // three segments is a single run -- the run count stays at one -- but it is
    // more than `(DupThresh - 1) * SMSS` bytes, which the RFC treats as equally
    // strong evidence. A sender with only the run test waits for reordering it
    // will not see.
    var tcb = sackTCB()
    var sender = sackSender()
    tenSegmentsInFlight(&sender, &tcb)

    ack(&sender, &tcb, blocks: [block(1, count: 3)])

    #expect(sender.presumedLostBytes == 1000, "only the segment below the run should be lost")
    #expect(sender.inScoreboardRecovery)
}

@Test func twoSackedSegmentsAreNotYetEnough() {
    // The negative control the two tests above need. Without it they show that
    // *some* amount of SACK information declares a loss, not that the threshold
    // is where the RFC puts it -- and a sender that declared loss on the first
    // block would pass both.
    var tcb = sackTCB()
    var sender = sackSender()
    tenSegmentsInFlight(&sender, &tcb)

    ack(&sender, &tcb, blocks: [block(1, count: 2)])

    #expect(sender.presumedLostBytes == 0, "two segments' worth of evidence started a recovery episode")
    #expect(!sender.inScoreboardRecovery)
}

@Test func aBareDuplicateAcknowledgementIsNotADuplicateOnceSackIsNegotiated() {
    // RFC 6675 §2 redefines the word: on a SACK connection an acknowledgement
    // counts as a duplicate only "if the ACK contains previously unknown SACK
    // information". A peer repeating an acknowledgement while telling this
    // sender nothing new has reported nothing, and counting those would
    // fast-retransmit on a peer that is merely quiet.
    //
    // This is the rule that made the differential agree with gVisor on the
    // third duplicate acknowledgement, where before this stack retransmitted
    // and inflated its window and gVisor did neither.
    var tcb = sackTCB()
    var sender = sackSender()
    tenSegmentsInFlight(&sender, &tcb)
    let windowBefore = sender.congestionControl.congestionWindow

    for _ in 0..<5 { ack(&sender, &tcb) }

    #expect(sender.duplicateAcknowledgements == 0)
    #expect(sender.presumedLostBytes == 0)
    #expect(sender.congestionControl.congestionWindow == windowBefore, "the window moved on no evidence")
}

@Test func threeAcknowledgementsCarryingNewInformationDoEnterRecovery() {
    // The other side of §2, and the reason the test above is about *bare*
    // duplicates. An acknowledgement that brings a block this sender had not
    // seen is a duplicate in every sense that matters, and three of them enter
    // recovery by `shouldEnterRecovery`'s first arm even when `IsLost` is still
    // false.
    var tcb = sackTCB()
    var sender = sackSender()
    tenSegmentsInFlight(&sender, &tcb)

    ack(&sender, &tcb, blocks: [block(9)])
    #expect(!sender.inScoreboardRecovery, "one block is not three")
    ack(&sender, &tcb, blocks: [block(9), block(7)])
    ack(&sender, &tcb, blocks: [block(9), block(7), block(5)])

    #expect(sender.inScoreboardRecovery)
    #expect(sender.presumedLostBytes > 0, "recovery began with nothing marked for retransmission")
}

@Test func recoveryIsNotReenteredOnAnotherHoleInsideTheSameEpisode() {
    // RecoveryPoint, and what it is worth. A second hole coming to light while
    // an episode is still running is the ordinary case -- one loss event
    // usually drops more than one segment -- and a sender that reduced its
    // threshold again for each would charge one event to the window twice.
    //
    // **Two earlier versions of this test could not fail**, and both failures
    // were the same mistake in different clothes: arranging for the guard to be
    // *reached* is not the same as arranging for its removal to *show*.
    //
    //   - The first followed entry with an acknowledgement carrying the same
    //     blocks. Nothing was newly lost, so the re-entry path was never
    //     reached at all.
    //   - The second brought new evidence but left the flight size unchanged,
    //     so the second reduction would have computed `max(FlightSize/2,
    //     2*SMSS)` from the same FlightSize and produced the same number. The
    //     guard was reached, removed, and invisible.
    //
    // So the middle acknowledgement here retires four segments: the second
    // reduction would be taken from a flight of 6000 rather than 10000, and
    // 3000 is a different number from 5000.
    var tcb = sackTCB()
    var sender = sackSender()
    tenSegmentsInFlight(&sender, &tcb)

    // Enter on a run above segment 0 alone.
    ack(&sender, &tcb, blocks: [block(1, count: 3)])
    #expect(sender.inScoreboardRecovery)
    #expect(sender.presumedLostBytes == 1000, "positive control: exactly one segment is lost so far")
    let threshold = sender.congestionControl.slowStartThreshold
    #expect(threshold == 5000, "positive control: the first reduction was taken from a flight of 10000")

    // Four segments retired, still short of RecoveryPoint at 10100.
    ack(&sender, &tcb, upTo: 4100)
    #expect(sender.inScoreboardRecovery, "a partial acknowledgement ended the episode")
    #expect(sender.flightSize == 6000)

    // New evidence, higher up: a run now sits above segment 4, so it is newly
    // lost while the episode is still running.
    ack(&sender, &tcb, upTo: 4100, blocks: [block(5, count: 3)])

    #expect(sender.presumedLostBytes > 0, "the second hole was not detected: the rest proves nothing")
    #expect(sender.inScoreboardRecovery)
    #expect(
        sender.congestionControl.slowStartThreshold == threshold,
        "the threshold was reduced a second time inside one episode")
}

@Test func recoveryEndsOnceEverythingOutstandingAtEntryIsAcknowledged() {
    var tcb = sackTCB()
    var sender = sackSender()
    tenSegmentsInFlight(&sender, &tcb)
    ack(&sender, &tcb, blocks: [block(2), block(4), block(6), block(8)])
    #expect(sender.inScoreboardRecovery)

    ack(&sender, &tcb, upTo: 10100)

    #expect(!sender.inScoreboardRecovery)
    #expect(sender.selectivelyAcknowledgedBytes == 0, "the scoreboard outlived the records it described")
}

@Test func aTimeoutDiscardsTheScoreboardRatherThanTrustingItAcrossOne() {
    // Considered and rejected rather than overlooked: keeping the marks would
    // spare the peer retransmissions of data it reported, and would stall. A
    // peer may discard SACKed data it has not delivered, and then its cumulative
    // acknowledgement never passes the hole while every later expiry declines to
    // resend what the scoreboard still calls delivered.
    var tcb = sackTCB()
    var sender = sackSender()
    tenSegmentsInFlight(&sender, &tcb)
    ack(&sender, &tcb, blocks: [block(5), block(7)])
    #expect(sender.selectivelyAcknowledgedBytes == 2000)

    _ = sender.retransmitTimerFired(tcb: &tcb)

    #expect(sender.selectivelyAcknowledgedBytes == 0)
    #expect(!sender.inScoreboardRecovery)
    // Nine, not ten: the timeout marks all ten and then unconditionally
    // retransmits the first, which clears its own mark on the way out. That is
    // the RFC 5681 §3.1 retransmission, not an accounting slip.
    #expect(sender.presumedLostBytes == 9000, "the timeout left SACKed records unowed")
}

@Test func aRetransmissionIsChargedAWholeSegmentOfWindowEvenWhenItIsShort() {
    // A window is an estimate of what the path can carry, and what a path
    // carries is packets. Under a window collapsed to one segment by a timeout,
    // charging a short retransmission by its length lets two packets out --
    // which is what the differential caught, on a first segment that had been
    // window-limited to 1380 bytes and left 40 of slack.
    var tcb = sackTCB(sndWnd: 65535)
    var sender = sackSender()
    // Nagle would hold the second, short write while the first is outstanding,
    // and then there would be one record rather than the two this is about.
    sender.nagleDisabled = true
    // A short first segment, then a second: exactly the shape that leaves slack.
    let first = sender.write(sackPayload(600))
    #expect(first)
    _ = sender.segmentsToTransmit(tcb: &tcb, mss: 1000)
    let second = sender.write(sackPayload(300))
    #expect(second)
    _ = sender.segmentsToTransmit(tcb: &tcb, mss: 1000)
    #expect(sender.unacknowledgedCount == 2, "the fixture did not produce two records")

    // The timeout collapses cwnd to one segment and presumes both lost. Its own
    // unconditional retransmission takes the first.
    _ = sender.retransmitTimerFired(tcb: &tcb)
    #expect(sender.congestionControl.congestionWindow == 1000)

    let drained = sender.segmentsToTransmit(tcb: &tcb, mss: 1000)

    #expect(
        drained.isEmpty,
        "the drain sent a second packet into a window collapsed to one segment: \(drained.map(\.payload.readableBytes))")
}
