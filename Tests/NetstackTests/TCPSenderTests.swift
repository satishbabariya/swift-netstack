import NIOCore
import Testing

@testable import Netstack

// RFC 6298 (timers, Karn) and RFC 5681 (windows, fast retransmit).
//
// Every assertion here is an exact constant rather than a comparison against a
// value read from the sender before the operation. `#expect(x == before)` and
// `#expect(x == 0)` are both true of a `Sender` that does nothing at all, and
// three of this file's properties -- "a duplicate ACK retires nothing", "a zero
// window sends nothing", "Karn suppresses the sample" -- are exactly that
// shape. Each is therefore paired with a positive control asserting there was
// non-zero state to preserve, or that the same operation *does* move the
// number under different conditions.
//
// Every mutating call is also hoisted into a `let` before being asserted on.
// `#expect` captures its operand expression so it can print it on failure, and
// a `mutating` call inside that capture does not compile -- so the natural
// spelling `#expect(sender.acknowledged(upTo: x, tcb: &tcb))`, which is both
// the call under test and the assertion about it, is not available here. That
// is a good thing: the call and the claim are separate lines, and it is
// visible when a test forgets to make one.

// MARK: - Fixtures

private let senderStart = NIODeadline.uptimeNanoseconds(0)

/// SND.UNA = SND.NXT = 100: the handshake is over and nothing is outstanding.
/// `sndWnd` defaults to a window wide enough that the congestion window is the
/// binding constraint unless a test says otherwise.
private func senderTCB(sndUna: UInt32 = 100, sndWnd: Int = 65535) -> TCB {
    TCB(
        state: .established,
        sndUna: SequenceNumber(sndUna),
        sndNxt: SequenceNumber(sndUna),
        sndWnd: sndWnd,
        sndWl1: SequenceNumber(1000),
        sndWl2: SequenceNumber(sndUna),
        iss: SequenceNumber(sndUna),
        rcvNxt: SequenceNumber(1000),
        rcvWnd: 4096,
        irs: SequenceNumber(1000))
}

private func senderPayload(_ count: Int, from: UInt8 = 0) -> ByteBuffer {
    var buffer = ByteBufferAllocator().buffer(capacity: count)
    buffer.writeBytes((0..<count).map { UInt8(truncatingIfNeeded: $0 &+ Int(from)) })
    return buffer
}

private func senderBytes(_ segment: Segment) -> [UInt8] {
    Array(segment.payload.readableBytesView)
}

private func senderBytes(_ buffer: ByteBuffer) -> [UInt8] {
    Array(buffer.readableBytesView)
}

/// Drive a sender to the ordinary steady state: `bytes` written and all of it
/// transmitted in `mss`-sized segments at the clock's current instant.
private func establishedSender(
    clock: ManualClock,
    segmentSize: Int = 1000,
    write bytes: Int = 3000,
    mss: Int = 1000,
    maximumBufferedBytes: Int = 1 << 20,
    tcb: inout TCB
) -> Sender {
    var sender = Sender(
        congestionControl: Reno(maximumSegmentSize: segmentSize), clock: clock, maximumBufferedBytes: maximumBufferedBytes)
    let accepted = sender.write(senderPayload(bytes))
    #expect(accepted, "fixture: the write must fit the buffer bound")
    _ = sender.segmentsToTransmit(tcb: &tcb, mss: mss)
    return sender
}

// MARK: - The send decision: min(cwnd, sndWnd)

@Test func theSenderSendsNoMoreThanTheSendWindowWhenTheSendWindowIsSmaller() {
    // Reno's initial window is ten segments (RFC 6928), so cwnd is 10000 here
    // and SND.WND of 2500 is the binding constraint. 10000 bytes are queued, so
    // neither the queue nor the MSS can be what stops transmission at 2500.
    var tcb = senderTCB(sndWnd: 2500)
    var sender = Sender(congestionControl: Reno(maximumSegmentSize: 1000), clock: ManualClock(start: senderStart), maximumBufferedBytes: 1 << 20)
    #expect(sender.congestionControl.congestionWindow == 10000, "positive control: cwnd is four times the window under test")
    let accepted = sender.write(senderPayload(10000))
    #expect(accepted)

    let segments = sender.segmentsToTransmit(tcb: &tcb, mss: 1000)

    #expect(segments.map(\.payload.readableBytes) == [1000, 1000, 500])
    #expect(segments.map(\.sequence) == [SequenceNumber(100), SequenceNumber(1100), SequenceNumber(2100)])
    #expect(sender.flightSize == 2500)
    #expect(sender.unsentBytes == 7500, "the 7500 bytes the window refused are still queued, not dropped")
    #expect(tcb.sndNxt == SequenceNumber(2600))
}

@Test func theSenderSendsNoMoreThanTheCongestionWindowWhenTheCongestionWindowIsSmaller() {
    // The mirror image: SND.WND is 65535 and cwnd is 10000, so cwnd binds. Both
    // directions are needed -- a sender that consults only one of the two
    // passes whichever test happens to make that one the smaller.
    var tcb = senderTCB(sndWnd: 65535)
    var sender = Sender(congestionControl: Reno(maximumSegmentSize: 1000), clock: ManualClock(start: senderStart), maximumBufferedBytes: 1 << 20)
    let accepted = sender.write(senderPayload(20000))
    #expect(accepted)

    let segments = sender.segmentsToTransmit(tcb: &tcb, mss: 1000)

    #expect(segments.count == 10)
    #expect(segments.map(\.payload.readableBytes).reduce(0, +) == 10000)
    #expect(sender.flightSize == 10000)
    #expect(sender.unsentBytes == 10000)
    #expect(tcb.sndNxt == SequenceNumber(10100))
}

// MARK: - Acknowledgement

@Test func aCumulativeAcknowledgementRetiresEverySegmentBelowIt() {
    var tcb = senderTCB()
    var sender = establishedSender(clock: ManualClock(start: senderStart), tcb: &tcb)

    #expect(sender.flightSize == 3000, "positive control: three segments are outstanding before the ACK")
    #expect(sender.unacknowledgedCount == 3)

    let accepted = sender.acknowledged(upTo: SequenceNumber(2100), tcb: &tcb)
    #expect(accepted)

    #expect(tcb.sndUna == SequenceNumber(2100))
    #expect(sender.flightSize == 1000, "the two segments below 2100 are retired; the third is not")
    #expect(sender.unacknowledgedCount == 1)
}

@Test func aDuplicateAcknowledgementRetiresNothing() {
    var tcb = senderTCB()
    var sender = establishedSender(clock: ManualClock(start: senderStart), tcb: &tcb)

    // Positive control: there IS something to retire, so "retires nothing" is a
    // statement about behaviour and not about an empty queue.
    #expect(sender.flightSize == 3000)
    #expect(sender.unacknowledgedCount == 3)

    let accepted = sender.acknowledged(upTo: SequenceNumber(100), tcb: &tcb)
    #expect(accepted, "an ACK of SND.UNA is acceptable, it just advances nothing")

    #expect(tcb.sndUna == SequenceNumber(100))
    #expect(sender.flightSize == 3000)
    #expect(sender.unacknowledgedCount == 3)
    #expect(sender.duplicateAcknowledgements == 1)
}

@Test func anAcknowledgementForDataNeverSentIsRejected() {
    var tcb = senderTCB()
    var sender = establishedSender(clock: ManualClock(start: senderStart), tcb: &tcb)
    #expect(tcb.sndNxt == SequenceNumber(3100))

    let pastSendNext = sender.acknowledged(upTo: SequenceNumber(3101), tcb: &tcb)
    #expect(pastSendNext == false, "one byte past SND.NXT was never sent")
    #expect(tcb.sndUna == SequenceNumber(100), "a rejected ACK must not move SND.UNA")
    #expect(sender.flightSize == 3000)
    #expect(sender.unacknowledgedCount == 3)

    // Positive control: the very next sequence number down, which WAS sent, is
    // accepted and does retire everything.
    let atSendNext = sender.acknowledged(upTo: SequenceNumber(3100), tcb: &tcb)
    #expect(atSendNext)
    #expect(tcb.sndUna == SequenceNumber(3100))
    #expect(sender.flightSize == 0)
    #expect(sender.unacknowledgedCount == 0)

    // And an ACK that has fallen behind SND.UNA is refused rather than
    // rewinding it.
    let stale = sender.acknowledged(upTo: SequenceNumber(100), tcb: &tcb)
    #expect(stale == false)
    #expect(tcb.sndUna == SequenceNumber(3100))
}

// MARK: - Fast retransmit (RFC 5681 3.2)

@Test func theThirdDuplicateAcknowledgementRetransmitsTheOldestSegmentAndReducesTheWindow() {
    var tcb = senderTCB()
    let clock = ManualClock(start: senderStart)
    var sender = establishedSender(clock: clock, tcb: &tcb)
    let written = senderBytes(senderPayload(3000))

    #expect(sender.congestionControl.congestionWindow == 10000)
    #expect(sender.congestionControl.slowStartThreshold == .max)

    let first = sender.acknowledged(upTo: SequenceNumber(100), tcb: &tcb)
    #expect(first)
    #expect(sender.congestionControl.congestionWindow == 10000, "one duplicate is not a loss signal")
    let afterFirst = sender.segmentsToTransmit(tcb: &tcb, mss: 1000)
    #expect(afterFirst.isEmpty)

    let second = sender.acknowledged(upTo: SequenceNumber(100), tcb: &tcb)
    #expect(second)
    #expect(sender.congestionControl.congestionWindow == 10000, "two duplicates are not a loss signal either")
    let afterSecond = sender.segmentsToTransmit(tcb: &tcb, mss: 1000)
    #expect(afterSecond.isEmpty)

    let third = sender.acknowledged(upTo: SequenceNumber(100), tcb: &tcb)
    #expect(third)
    #expect(sender.duplicateAcknowledgements == 3)
    // RFC 5681 3.2 with FlightSize 3000 and SMSS 1000:
    //   ssthresh = max(3000 / 2, 2 * 1000) = 2000
    //   cwnd     = ssthresh + 3 * SMSS     = 5000
    #expect(sender.congestionControl.slowStartThreshold == 2000)
    #expect(sender.congestionControl.congestionWindow == 5000)

    let retransmission = sender.segmentsToTransmit(tcb: &tcb, mss: 1000)
    #expect(retransmission.count == 1)
    #expect(retransmission.first?.sequence == SequenceNumber(100), "fast retransmit resends the OLDEST unacknowledged segment")
    #expect(retransmission.first.map(senderBytes) == Array(written[0..<1000]))
    #expect(tcb.sndNxt == SequenceNumber(3100), "a retransmission does not consume new sequence space")
    #expect(sender.flightSize == 3000, "the retransmitted segment stays outstanding")
    #expect(sender.unacknowledgedCount == 3)
}

@Test func aWindowUpdateThatRepeatsTheAcknowledgementNumberIsNotADuplicateAcknowledgement() {
    var tcb = senderTCB()
    let clock = ManualClock(start: senderStart)
    var sender = establishedSender(clock: clock, tcb: &tcb)

    // Four ACKs, all naming SND.UNA and none carrying data, but the last three
    // each advertising a different window. RFC 5681 3.2 excludes those: on an
    // idle connection a peer's window updates repeat the last acknowledgement
    // number, and counting them retransmits segments nothing was ever lost of.
    let baseline = sender.acknowledged(upTo: SequenceNumber(100), tcb: &tcb)
    #expect(baseline)
    #expect(sender.duplicateAcknowledgements == 1, "positive control: with the window held still, this one DID count")

    for window in [40000, 30000, 20000] {
        tcb.sndWnd = window
        let update = sender.acknowledged(upTo: SequenceNumber(100), tcb: &tcb)
        #expect(update)
    }

    #expect(sender.duplicateAcknowledgements == 0)
    #expect(sender.congestionControl.congestionWindow == 10000)
    #expect(sender.congestionControl.slowStartThreshold == .max)
    let emitted = sender.segmentsToTransmit(tcb: &tcb, mss: 1000)
    #expect(emitted.isEmpty, "nothing was lost, so nothing may be retransmitted")

    // Positive control: the same four acknowledgement numbers, with the window
    // held constant, DO trigger fast retransmit. Without it the assertions
    // above are equally true of a sender that never fast-retransmits at all.
    var controlTCB = senderTCB()
    var control = establishedSender(clock: clock, tcb: &controlTCB)
    for _ in 0..<4 {
        let duplicate = control.acknowledged(upTo: SequenceNumber(100), tcb: &controlTCB)
        #expect(duplicate)
    }
    #expect(control.congestionControl.congestionWindow == 5000)
    let controlEmitted = control.segmentsToTransmit(tcb: &controlTCB, mss: 1000)
    #expect(controlEmitted.count == 1)
}

@Test func anAcknowledgementCarryingDataIsNotADuplicateAcknowledgement() {
    var tcb = senderTCB()
    let clock = ManualClock(start: senderStart)
    var sender = establishedSender(clock: clock, tcb: &tcb)

    // RFC 5681 3.2's other exclusion: SEG.LEN must be zero. A bidirectional
    // flow piggybacks its acknowledgements on data segments, and every one of
    // those repeats SND.UNA while our own data is outstanding.
    for _ in 0..<3 {
        let withData = sender.acknowledged(upTo: SequenceNumber(100), tcb: &tcb, segmentLength: 10)
        #expect(withData)
    }

    #expect(sender.duplicateAcknowledgements == 0)
    #expect(sender.congestionControl.congestionWindow == 10000)
    #expect(sender.congestionControl.slowStartThreshold == .max)
    let emitted = sender.segmentsToTransmit(tcb: &tcb, mss: 1000)
    #expect(emitted.isEmpty)

    // Positive control: identical calls with SEG.LEN zero do signal loss.
    var controlTCB = senderTCB()
    var control = establishedSender(clock: clock, tcb: &controlTCB)
    for _ in 0..<3 {
        let bare = control.acknowledged(upTo: SequenceNumber(100), tcb: &controlTCB, segmentLength: 0)
        #expect(bare)
    }
    #expect(control.congestionControl.congestionWindow == 5000)
}

// MARK: - The retransmission timer (RFC 6298 5)

@Test func theRetransmitTimerResendsTheOldestSegmentAndKeepsItQueued() {
    var tcb = senderTCB()
    let clock = ManualClock(start: senderStart)
    var sender = establishedSender(clock: clock, tcb: &tcb)
    let written = senderBytes(senderPayload(3000))

    clock.advance(by: .seconds(1))
    let first = sender.retransmitTimerFired(tcb: &tcb)

    #expect(first?.sequence == SequenceNumber(100))
    #expect(first.map(senderBytes) == Array(written[0..<1000]))
    #expect(sender.flightSize == 3000, "RFC 6298 5.5: the retransmitted segment is NOT discarded")
    #expect(sender.unacknowledgedCount == 3)
    #expect(tcb.sndNxt == SequenceNumber(3100))
    // RFC 5681 3.1 on timeout: cwnd collapses to one segment,
    // ssthresh = max(FlightSize / 2, 2 * SMSS) = max(1500, 2000) = 2000.
    #expect(sender.congestionControl.congestionWindow == 1000)
    #expect(sender.congestionControl.slowStartThreshold == 2000)
    #expect(sender.retransmissionTimeout == .seconds(2), "RFC 6298 5.5: the RTO doubles on expiry")

    // Firing again resends the same segment, which is only possible because the
    // first firing kept it.
    clock.advance(by: .seconds(2))
    let second = sender.retransmitTimerFired(tcb: &tcb)
    #expect(second?.sequence == SequenceNumber(100))
    #expect(second.map(senderBytes) == Array(written[0..<1000]))
    #expect(sender.flightSize == 3000)
    #expect(sender.retransmissionTimeout == .seconds(4))
}

@Test func theRetransmissionTimeoutDoublesOnEveryExpiryAndSaturatesAtSixtySeconds() {
    var tcb = senderTCB()
    let clock = ManualClock(start: senderStart)
    var sender = establishedSender(clock: clock, segmentSize: 1460, write: 100, mss: 1460, tcb: &tcb)

    #expect(sender.retransmissionTimeout == .seconds(1), "RFC 6298 2.1: one second until a measurement exists")

    var observed: [TimeAmount] = []
    for _ in 0..<8 {
        _ = sender.retransmitTimerFired(tcb: &tcb)
        observed.append(sender.retransmissionTimeout)
    }
    #expect(
        observed == [.seconds(2), .seconds(4), .seconds(8), .seconds(16), .seconds(32), .seconds(60), .seconds(60), .seconds(60)],
        "RFC 6298 5.5 permits a ceiling of at least 60 seconds; 64 saturates to 60 and stays there")
}

@Test func anAcknowledgementOfNewDataRestartsTheRetransmitTimer() {
    // RFC 6298 5.3. Getting this wrong in the "never restart" direction makes
    // every long transfer spuriously retransmit, and nothing else in the suite
    // would notice.
    var tcb = senderTCB()
    let clock = ManualClock(start: senderStart)
    var sender = establishedSender(clock: clock, write: 2000, tcb: &tcb)

    #expect(sender.retransmitDeadline == senderStart + .seconds(1), "5.1: armed when the data went out, at the initial one-second RTO")

    clock.advance(by: .milliseconds(500))
    let accepted = sender.acknowledged(upTo: SequenceNumber(1100), tcb: &tcb)
    #expect(accepted)

    // The 500ms sample is unambiguous, so RFC 6298 2.2 gives SRTT = 500ms,
    // RTTVAR = 250ms, RTO = 500ms + max(1ms, 1000ms) = 1500ms.
    #expect(sender.retransmissionTimeout == .milliseconds(1500))
    #expect(sender.retransmitDeadline == senderStart + .milliseconds(2000), "restarted at now (500ms) plus the new RTO (1500ms)")
    #expect(sender.flightSize == 1000, "one segment is still outstanding, so the timer must still be running")
}

@Test func aDuplicateAcknowledgementDoesNotRestartTheRetransmitTimer() {
    // RFC 6298 5.3 in the other direction. Restarting on every ACK means a lost
    // segment is never retransmitted for as long as the peer keeps
    // acknowledging the ones that did arrive.
    var tcb = senderTCB()
    let clock = ManualClock(start: senderStart)
    var sender = establishedSender(clock: clock, write: 2000, tcb: &tcb)
    #expect(sender.retransmitDeadline == senderStart + .seconds(1))

    clock.advance(by: .milliseconds(500))
    let duplicate = sender.acknowledged(upTo: SequenceNumber(100), tcb: &tcb)
    #expect(duplicate)

    #expect(sender.retransmitDeadline == senderStart + .seconds(1), "unchanged, still measured from the original transmission")

    // Positive control: an identically-placed sender whose ACK at that same
    // 500ms instant acknowledges new data DOES move the deadline. Without it
    // "unchanged" above is equally true of a sender whose timer never moves.
    var controlTCB = senderTCB()
    let controlClock = ManualClock(start: senderStart)
    var control = establishedSender(clock: controlClock, write: 2000, tcb: &controlTCB)
    #expect(control.retransmitDeadline == senderStart + .seconds(1))
    controlClock.advance(by: .milliseconds(500))
    let newData = control.acknowledged(upTo: SequenceNumber(1100), tcb: &controlTCB)
    #expect(newData)
    #expect(control.retransmitDeadline == senderStart + .milliseconds(2000))
}

@Test func theRetransmitTimerStopsWhenEverythingOutstandingIsAcknowledged() {
    // RFC 6298 5.2.
    var tcb = senderTCB()
    let clock = ManualClock(start: senderStart)
    var sender = establishedSender(clock: clock, write: 2000, tcb: &tcb)

    #expect(sender.retransmitDeadline == senderStart + .seconds(1), "positive control: a timer was running, so turning it off is an action")
    #expect(sender.flightSize == 2000)

    clock.advance(by: .milliseconds(500))
    let accepted = sender.acknowledged(upTo: SequenceNumber(2100), tcb: &tcb)
    #expect(accepted)

    #expect(sender.retransmitDeadline == nil)
    #expect(sender.flightSize == 0)
    #expect(sender.unacknowledgedCount == 0)
}

// MARK: - Karn's algorithm

@Test func aRetransmittedSegmentDoesNotProduceAnRTTSample() {
    var tcb = senderTCB()
    let clock = ManualClock(start: senderStart)
    var sender = establishedSender(clock: clock, segmentSize: 1460, write: 100, mss: 1460, tcb: &tcb)

    clock.advance(by: .seconds(2))
    _ = sender.retransmitTimerFired(tcb: &tcb)
    // Asserted as a constant rather than captured into `rtoBefore` and compared
    // with itself: the plan's spelling of this test is passed by a sender that
    // never updates the RTO at all.
    #expect(sender.retransmissionTimeout == .seconds(2), "positive control: the backed-off RTO is the value that must survive")

    clock.advance(by: .milliseconds(10))
    let accepted = sender.acknowledged(upTo: tcb.sndNxt, tcb: &tcb)
    #expect(accepted)

    // Sampling the ambiguous ACK would give R = 10ms, hence
    // RTO = clamp(10ms + max(1ms, 20ms)) = 1s -- a visibly different number.
    #expect(sender.retransmissionTimeout == .seconds(2), "an ambiguous ACK must not update the RTO")
}

@Test func anUnambiguousAcknowledgementDoesProduceAnRTTSample() {
    // The positive control Karn's test needs: the same shape of ACK, on a
    // segment that was never retransmitted, moves the RTO. The 500ms sample is
    // chosen above 333ms so that 3 * R clears RFC 6298 2.4's one-second floor
    // -- below it the clamp would hide the arithmetic.
    var tcb = senderTCB()
    let clock = ManualClock(start: senderStart)
    var sender = establishedSender(clock: clock, segmentSize: 1460, write: 100, mss: 1460, tcb: &tcb)

    #expect(sender.retransmissionTimeout == .seconds(1))

    clock.advance(by: .milliseconds(500))
    let accepted = sender.acknowledged(upTo: tcb.sndNxt, tcb: &tcb)
    #expect(accepted)

    #expect(sender.retransmissionTimeout == .milliseconds(1500))
}

// MARK: - The queue is bounded, and copies on admission

@Test func aZeroWindowStopsTransmissionWithoutDiscardingQueuedData() {
    var tcb = senderTCB(sndWnd: 0)
    var sender = Sender(congestionControl: Reno(maximumSegmentSize: 1000), clock: ManualClock(start: senderStart), maximumBufferedBytes: 1 << 20)
    let written = senderBytes(senderPayload(3000))
    let accepted = sender.write(senderPayload(3000))
    #expect(accepted)

    let none = sender.segmentsToTransmit(tcb: &tcb, mss: 1000)
    #expect(none.isEmpty)
    #expect(tcb.sndNxt == SequenceNumber(100))
    #expect(sender.flightSize == 0)
    #expect(sender.retransmitDeadline == nil, "5.1 arms the timer when data is SENT; none was")
    // The point of the test: the data was withheld, not dropped.
    #expect(sender.unsentBytes == 3000)

    tcb.sndWnd = 3000
    let segments = sender.segmentsToTransmit(tcb: &tcb, mss: 1000)
    #expect(segments.map(\.payload.readableBytes) == [1000, 1000, 1000])
    #expect(segments.flatMap(senderBytes) == written, "every byte, in order, survived the closed window")
    #expect(sender.unsentBytes == 0)
    #expect(sender.retransmitDeadline == senderStart + .seconds(1))
}

@Test func writeRefusesPastTheBufferBoundAndAcceptsAgainOnceAnAcknowledgementFreesRoom() {
    // The bound is expressed in terms of the measured per-chunk overhead rather
    // than a literal, so the test states the rule -- payload plus overhead, per
    // admitted chunk -- instead of a number that would silently stop meaning
    // anything if the overhead were re-measured. 1024 is a power of two so the
    // allocator's rounding of the copy is a no-op and the charge is exact.
    let capacity = 2 * (1024 + Sender.perChunkOverhead)
    var tcb = senderTCB()
    var sender = Sender(congestionControl: Reno(maximumSegmentSize: 1024), clock: ManualClock(start: senderStart), maximumBufferedBytes: capacity)

    let firstWrite = sender.write(senderPayload(1024))
    #expect(firstWrite)
    let secondWrite = sender.write(senderPayload(1024, from: 128))
    #expect(secondWrite)
    #expect(sender.bufferedBytes == capacity)
    let refused = sender.write(senderPayload(1))
    #expect(refused == false, "the bound is on retained memory, so even one more byte costs a whole chunk's overhead")
    #expect(sender.unsentBytes == 2048, "the refused write left the queue exactly as it was")

    _ = sender.segmentsToTransmit(tcb: &tcb, mss: 1024)
    #expect(sender.flightSize == 2048)
    let refusedAgain = sender.write(senderPayload(1))
    #expect(refusedAgain == false, "transmitting does not free the queue -- the peer has not acknowledged it yet")

    let accepted = sender.acknowledged(upTo: SequenceNumber(100 + 1024), tcb: &tcb)
    #expect(accepted)
    #expect(sender.bufferedBytes == 1024 + Sender.perChunkOverhead)
    let afterAck = sender.write(senderPayload(1024, from: 200))
    #expect(afterAck, "the acknowledgement freed exactly one chunk's worth of room")
    #expect(sender.bufferedBytes == capacity)
}

@Test func queuedPayloadsDoNotPinTheFrameTheyWereSlicedFrom() {
    // A NIO `ByteBuffer` slice is copy-on-write: it holds the ENTIRE original
    // allocation alive. `storageCapacity` reports that allocation, so it
    // separates "copied on admission" from "kept the slice" with no noise --
    // 1 against 2048 for a 1-byte slice of an MTU-sized frame.
    var frame = ByteBufferAllocator().buffer(capacity: 1500)
    frame.writeBytes([UInt8](repeating: 0xaa, count: 1499))
    frame.writeBytes([0x5a])
    let slice = frame.getSlice(at: frame.writerIndex - 1, length: 1)!
    #expect(slice.readableBytes == 1)
    #expect(slice.storageCapacity == 2048, "positive control: the slice really does pin the whole frame")

    var tcb = senderTCB()
    var sender = Sender(congestionControl: Reno(maximumSegmentSize: 1000), clock: ManualClock(start: senderStart), maximumBufferedBytes: 1 << 20)
    let accepted = sender.write(slice)
    #expect(accepted)

    #expect(sender.queuedStorageCapacityForTesting == 1, "the queue holds a fresh, exactly-sized copy, not the slice")
    #expect(sender.bufferedBytes == 1 + Sender.perChunkOverhead)

    // And it is a copy of the right byte: a copy taken from the wrong offset
    // would satisfy the capacity assertion above just as well.
    let segments = sender.segmentsToTransmit(tcb: &tcb, mss: 1000)
    #expect(segments.flatMap(senderBytes) == [0x5a])
}

@Test func theBufferBoundChargesTheAllocationACopyReallyOccupies() {
    // NIO rounds a buffer's storage up to a power of two, so charging the
    // declared length under-accounts by nearly half at exactly the worst-case
    // size. The test above cannot see that -- 1024 is a power of two, so its
    // length and its capacity are the same number -- and this one exists
    // precisely because that made the rule untestable there.
    var probe = ByteBufferAllocator().buffer(capacity: 1025)
    probe.writeBytes([UInt8](repeating: 0x11, count: 1025))
    #expect(probe.storageCapacity == 2048, "positive control: 1025 bytes really do occupy a 2048-byte allocation")

    let capacity = 2048 + Sender.perChunkOverhead
    var sender = Sender(congestionControl: Reno(maximumSegmentSize: 1024), clock: ManualClock(start: senderStart), maximumBufferedBytes: capacity)

    let accepted = sender.write(senderPayload(1025))
    #expect(accepted)
    #expect(sender.bufferedBytes == capacity, "charged for the 2048 bytes held, not the 1025 declared")

    // A sender charging `readableBytes` would believe it had 1023 bytes spare
    // and take this; the queue would then hold 4096 bytes against a 2304-byte
    // bound.
    let refused = sender.write(senderPayload(1))
    #expect(refused == false)
    #expect(sender.unsentBytes == 1025)

    // The other side of the same rule, and the one the case above cannot
    // reach: a bound with room for the declared length but not for the
    // allocation must refuse the write outright. `write` tests the bound
    // twice -- once optimistically on the length, to avoid allocating for a
    // write it is going to refuse, and once exactly on the copy's capacity --
    // and only this shape tells the two apart. Without it the exact test can
    // be deleted with the suite still green.
    var tight = Sender(
        congestionControl: Reno(maximumSegmentSize: 1024), clock: ManualClock(start: senderStart),
        maximumBufferedBytes: 1025 + Sender.perChunkOverhead + 100)
    let overCapacity = tight.write(senderPayload(1025))
    #expect(overCapacity == false, "1025 declared bytes fit the bound; the 2048 they occupy do not")
    #expect(tight.bufferedBytes == 0)
    #expect(tight.unsentBytes == 0)

    // Positive control: the same sender does admit a write whose allocation
    // fits, so the refusal above is about the size and not about the sender.
    let fits = tight.write(senderPayload(1024))
    #expect(fits)
    #expect(tight.bufferedBytes == 1024 + Sender.perChunkOverhead)
}

@Test func acknowledgingPartOfAChunkReleasesNoRoom() {
    // Consuming a prefix of a queued write moves a reader index, which frees
    // no memory at all -- the whole allocation is still held. Refunding for it
    // would let `write` admit data against room that does not exist, which is
    // how a bound gets defeated without anyone editing the bound.
    let capacity = 1024 + Sender.perChunkOverhead
    var tcb = senderTCB()
    var sender = Sender(congestionControl: Reno(maximumSegmentSize: 512), clock: ManualClock(start: senderStart), maximumBufferedBytes: capacity)

    let accepted = sender.write(senderPayload(1024))
    #expect(accepted)
    #expect(sender.bufferedBytes == capacity)

    let segments = sender.segmentsToTransmit(tcb: &tcb, mss: 512)
    #expect(segments.map(\.payload.readableBytes) == [512, 512])

    let half = sender.acknowledged(upTo: SequenceNumber(612), tcb: &tcb)
    #expect(half)
    #expect(sender.flightSize == 512, "positive control: half the chunk really was acknowledged")
    #expect(sender.bufferedBytes == capacity, "half the chunk is acknowledged; none of its allocation is released")
    let refused = sender.write(senderPayload(1))
    #expect(refused == false)

    // And the charge IS refunded once the whole chunk goes, so the accounting
    // is conservative rather than simply stuck.
    let rest = sender.acknowledged(upTo: SequenceNumber(1124), tcb: &tcb)
    #expect(rest)
    #expect(sender.bufferedBytes == 0)
    let afterFullAck = sender.write(senderPayload(1))
    #expect(afterFullAck)
}

@Test func theNumberOfInFlightSegmentsIsBoundedIndependentlyOfTheBytes() {
    // The byte bound alone does not bound the segment records, and the MSS is
    // peer-influenced: a peer advertising a tiny MSS turns a bounded number of
    // queued bytes into a far larger number of in-flight records, none of
    // which the byte accounting sees. 1024 bytes at an MSS of 1 is 1024
    // records if nothing stops it.
    let segmentCap = 10
    var tcb = senderTCB()
    var sender = Sender(
        congestionControl: Reno(maximumSegmentSize: 1024), clock: ManualClock(start: senderStart),
        maximumBufferedBytes: segmentCap * (1 + Sender.perChunkOverhead))

    let accepted = sender.write(senderPayload(1024))
    #expect(accepted)
    #expect(sender.congestionControl.congestionWindow == 10240, "positive control: neither cwnd nor SND.WND is what stops this")

    let segments = sender.segmentsToTransmit(tcb: &tcb, mss: 1)

    #expect(segments.count == segmentCap)
    #expect(sender.unacknowledgedCount == segmentCap)
    #expect(sender.flightSize == segmentCap)
    #expect(sender.unsentBytes == 1024 - segmentCap, "the rest is held, not dropped")
}

@Test func theSenderRefusesToActWhenSomethingElseHasTakenSequenceSpace() {
    // This type models a byte stream and nothing else. A FIN (or anything else
    // that consumes sequence space without going through `segmentsToTransmit`)
    // moves SND.NXT by an amount none of the offsets here account for, and
    // every subsequent segment would be cut from the wrong place in the
    // stream. Fail closed rather than send the wrong bytes.
    var tcb = senderTCB()
    let clock = ManualClock(start: senderStart)
    var sender = establishedSender(clock: clock, write: 1000, tcb: &tcb)
    #expect(sender.flightSize == 1000)

    let more = sender.write(senderPayload(1000, from: 64))
    #expect(more)
    #expect(sender.unsentBytes == 1000, "positive control: there IS data to send, and room to send it")

    tcb.sndNxt = tcb.sndNxt + 1
    let refused = sender.segmentsToTransmit(tcb: &tcb, mss: 1000)
    #expect(refused.isEmpty)
    #expect(sender.unsentBytes == 1000, "and it is still queued afterwards")

    tcb.sndNxt = tcb.sndNxt + -1
    let resumed = sender.segmentsToTransmit(tcb: &tcb, mss: 1000)
    #expect(resumed.count == 1, "with SND.NXT back where this type left it, transmission resumes")
    #expect(resumed.first?.sequence == SequenceNumber(1100))
}
