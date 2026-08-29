import NIOCore
import Testing

@testable import Netstack

// RFC 8985 RACK: loss detected by TIME rather than by counting what arrived
// above a hole.
//
// RFC 6675 declares a segment lost when enough SACKed data sits above it, which
// needs enough data above it to exist. The last few segments of a transfer have
// none — nothing is sent after them, nothing arrives above them — so 6675 waits
// for the retransmission timer. RACK asks whether a segment sent BEFORE one that
// has since been delivered is still missing after a reordering window, and that
// question has an answer for the tail as well as the middle.

private let rackMSS = 1000
private let rackStart = NIODeadline.uptimeNanoseconds(0)

private func at(_ milliseconds: Int64) -> NIODeadline {
    .uptimeNanoseconds(UInt64(milliseconds) * 1_000_000)
}

private func rackTCB(sndWnd: Int = 65535) -> TCB {
    var tcb = TCB(
        state: .established, sndUna: SequenceNumber(100), sndNxt: SequenceNumber(100), sndWnd: sndWnd,
        sndWl1: SequenceNumber(1000), sndWl2: SequenceNumber(100), iss: SequenceNumber(100),
        rcvNxt: SequenceNumber(1000), rcvWnd: 4096, irs: SequenceNumber(1000),
        offersSelectiveAcknowledgement: true)
    tcb.negotiateSelectiveAcknowledgement(fromSynOptions: [.sackPermitted])
    return tcb
}

private func rackPayload(_ count: Int) -> ByteBuffer {
    var buffer = ByteBufferAllocator().buffer(capacity: count)
    buffer.writeBytes([UInt8](repeating: 0x41, count: count))
    return buffer
}

/// A sender with `count` segments in flight, each sent one millisecond apart so
/// send ORDER is observable — which is the only thing RACK looks at.
private func staggeredFlight(
    _ sender: inout Sender, _ tcb: inout TCB, clock: ManualClock, count: Int,
    gap: TimeAmount = .milliseconds(1)
) {
    // Written one segment at a time rather than all at once: a single large
    // write is cut into as many segments as the window allows and they all leave
    // together, which gives every record the same send time and nothing for RACK
    // to compare.
    for _ in 0..<count {
        let accepted = sender.write(rackPayload(rackMSS))
        #expect(accepted)
        let segments = sender.segmentsToTransmit(tcb: &tcb, mss: rackMSS)
        #expect(segments.count == 1, "the fixture did not send one segment at a time")
        clock.advance(by: gap)
    }
}

private func block(_ index: Int, count: Int = 1) -> SACKBlock {
    SACKBlock(
        left: SequenceNumber(UInt32(100 + index * rackMSS)),
        right: SequenceNumber(UInt32(100 + (index + count) * rackMSS)))
}

@Test func rackDeclaresTheTailLostWhenSomethingSentLaterArrives() throws {
    // The case RFC 6675 cannot see. Segment 0 is missing and only ONE segment
    // above it has been SACKed, which is neither three discontiguous runs nor
    // two segments' worth of bytes — so the scoreboard says nothing, and without
    // RACK the retransmission timer is the only thing left.
    let clock = ManualClock(start: rackStart)
    var tcb = rackTCB()
    var sender = Sender(
        congestionControl: Reno(maximumSegmentSize: rackMSS), clock: clock,
        maximumBufferedBytes: 1 << 20)
    sender.rackEnabled = true
    // Twenty milliseconds apart, not one. The window scales with the round trip
    // -- a quarter of it -- so on a fifty-millisecond path a segment sent one
    // millisecond earlier is well inside the window and is reordering, not loss.
    // A test that used a one-millisecond gap here was asserting that RACK
    // declares loss where the RFC says to wait.
    staggeredFlight(&sender, &tcb, clock: clock, count: 4, gap: .milliseconds(20))

    // Only segment 3 arrives, and it was sent sixty milliseconds after segment 0.
    clock.advance(by: .milliseconds(50))
    _ = sender.acknowledged(
        upTo: SequenceNumber(100), tcb: &tcb, advertisedWindow: 65535,
        selectiveAcknowledgements: [block(3)])

    #expect(sender.presumedLostBytes > 0, "the tail was not declared lost")
    #expect(sender.inScoreboardRecovery)
}

@Test func withoutRackTheSameCaseWaitsForTheTimer() throws {
    // The control, and the reason the test above means anything: the scoreboard
    // alone genuinely cannot see this, so a stack that declared the loss without
    // RACK would be doing it for some other reason.
    let clock = ManualClock(start: rackStart)
    var tcb = rackTCB()
    var sender = Sender(
        congestionControl: Reno(maximumSegmentSize: rackMSS), clock: clock,
        maximumBufferedBytes: 1 << 20)
    staggeredFlight(&sender, &tcb, clock: clock, count: 4, gap: .milliseconds(20))

    clock.advance(by: .milliseconds(50))
    _ = sender.acknowledged(
        upTo: SequenceNumber(100), tcb: &tcb, advertisedWindow: 65535,
        selectiveAcknowledgements: [block(3)])

    #expect(sender.presumedLostBytes == 0, "the scoreboard declared a loss it cannot have detected")
}

@Test func rackDoesNotDeclareLossForSomethingSentAfterWhatArrived() throws {
    // Send order is the whole question. A segment sent AFTER the one that
    // arrived has had no chance to be delivered yet, and calling it lost would
    // retransmit data still legitimately in flight — which on a fast path is
    // most of the window.
    let clock = ManualClock(start: rackStart)
    var tcb = rackTCB()
    var sender = Sender(
        congestionControl: Reno(maximumSegmentSize: rackMSS), clock: clock,
        maximumBufferedBytes: 1 << 20)
    sender.rackEnabled = true
    staggeredFlight(&sender, &tcb, clock: clock, count: 4)

    // Segment 0 arrives — the FIRST one sent — so nothing was sent before it.
    clock.advance(by: .milliseconds(50))
    _ = sender.acknowledged(
        upTo: SequenceNumber(100 + UInt32(rackMSS)), tcb: &tcb, advertisedWindow: 65535)

    #expect(sender.presumedLostBytes == 0, "segments sent after the delivered one were declared lost")
}

@Test func theWindowClosesOnlyWhenLossIsAlreadyKnown() throws {
    // §7.2, and the reading that is easy to get backwards.
    //
    // The window's default is a quarter of the smallest round trip. The ZERO is
    // the special case, taken only when the sender is already in recovery or has
    // counted DupThresh duplicate acknowledgements -- states in which something
    // is known to have been lost and there is nothing to be gained by waiting
    // longer.
    //
    // This test replaces one that asserted the opposite -- that the window is
    // zero until reordering is observed -- and PASSED, because the code had the
    // same misreading in it. Under that rule the first selective acknowledgement
    // of a connection declares everything below it lost, so a burst arriving
    // slightly out of order costs a retransmission and a halved window on a path
    // with no loss at all.
    let clock = ManualClock(start: rackStart)
    var tcb = rackTCB()
    var sender = Sender(
        congestionControl: Reno(maximumSegmentSize: rackMSS), clock: clock,
        maximumBufferedBytes: 1 << 20)
    sender.rackEnabled = true
    staggeredFlight(&sender, &tcb, clock: clock, count: 4)

    // A round trip, so the window has a length to be a quarter of.
    clock.advance(by: .milliseconds(100))
    _ = sender.acknowledged(
        upTo: SequenceNumber(100 + UInt32(rackMSS)), tcb: &tcb, advertisedWindow: 65535)
    #expect(!sender.sawReorderingForTesting, "the fixture reordered something")
    #expect(
        sender.reorderWindowForTesting > .zero,
        "the window was closed on a connection with no evidence of loss")

    // Segment 1 was sent two milliseconds before segment 3, and the window is
    // twenty-five: not lost.
    _ = sender.acknowledged(
        upTo: SequenceNumber(100 + UInt32(rackMSS)), tcb: &tcb, advertisedWindow: 65535,
        selectiveAcknowledgements: [block(3)])
    #expect(sender.presumedLostBytes == 0, "a segment well inside the window was called lost")
}

@Test func rackGoesQuietAfterATimeoutRatherThanRemarkingTheNewFlight() throws {
    // Not a guard, a limitation, and it is written down because the difference
    // matters to whoever reads this next.
    //
    // Everything outstanding is retransmitted after a timeout, which gives every
    // record a send time later than anything RACK remembers -- so RACK marks
    // nothing until a new delivery updates it. And the delivery that would
    // update it has to be of an unambiguous transmission, which a retransmitted
    // record is not. So RACK is quiet from a timeout until fresh data is sent
    // and acknowledged. RFC 8985 keeps it working through timestamps and DSACK;
    // this implements neither.
    //
    // An explicit reset of RACK's state was written for this and removed:
    // falsification showed it made no difference, for exactly the reason above.
    let clock = ManualClock(start: rackStart)
    var tcb = rackTCB()
    var sender = Sender(
        congestionControl: Reno(maximumSegmentSize: rackMSS), clock: clock,
        maximumBufferedBytes: 1 << 20)
    sender.rackEnabled = true
    staggeredFlight(&sender, &tcb, clock: clock, count: 4, gap: .milliseconds(20))
    clock.advance(by: .milliseconds(50))
    _ = sender.acknowledged(
        upTo: SequenceNumber(100), tcb: &tcb, advertisedWindow: 65535,
        selectiveAcknowledgements: [block(3)])
    #expect(sender.presumedLostBytes > 0, "positive control: RACK marked something before the timeout")

    _ = sender.retransmitTimerFired(tcb: &tcb)
    clock.advance(by: .milliseconds(10))
    _ = sender.segmentsToTransmit(tcb: &tcb, mss: rackMSS)
    let afterRetransmission = sender.presumedLostBytes

    clock.advance(by: .milliseconds(10))
    _ = sender.acknowledged(
        upTo: SequenceNumber(100), tcb: &tcb, advertisedWindow: 65535,
        selectiveAcknowledgements: [block(3)])

    #expect(
        sender.presumedLostBytes == afterRetransmission,
        "RACK acted on a flight it has no unambiguous evidence about")
}

@Test func aRetransmissionsArrivalDoesNotDateRacksViewOfSendOrder() throws {
    // Karn's argument applied to send ORDER. A segment sent twice has an
    // acknowledgement that may be answering either send, so dating "the most
    // recently sent thing that arrived" from the second would measure from a
    // transmission the peer may never have seen -- and everything sent before
    // THAT looks lost.
    //
    // Asserted with an exact figure rather than an upper bound. The first
    // version bounded the loss above and could not fail: the timeout that set it
    // up marks everything lost anyway, so any ceiling was already satisfied.
    let clock = ManualClock(start: rackStart)
    var tcb = rackTCB()
    var sender = Sender(
        congestionControl: Reno(maximumSegmentSize: rackMSS), clock: clock,
        maximumBufferedBytes: 1 << 20)
    sender.rackEnabled = true
    staggeredFlight(&sender, &tcb, clock: clock, count: 4)

    // Segment 0 alone is retransmitted, by the scoreboard rather than a timeout,
    // so segments 1-3 keep their marks clear and the question is only what RACK
    // does with the retransmission's acknowledgement.
    clock.advance(by: .seconds(2))
    _ = sender.acknowledged(
        upTo: SequenceNumber(100), tcb: &tcb, advertisedWindow: 65535,
        selectiveAcknowledgements: [block(1), block(2), block(3)])
    #expect(sender.presumedLostBytes == rackMSS, "the fixture lost something other than segment 0")
    _ = sender.segmentsToTransmit(tcb: &tcb, mss: rackMSS)
    #expect(sender.presumedLostBytes == 0, "the retransmission did not go out")

    // Acknowledged, then fresh data sent one millisecond later. A sender that
    // dated send order from the retransmission would find that fresh segment
    // sent "before" it and call it lost.
    clock.advance(by: .milliseconds(10))
    _ = sender.acknowledged(
        upTo: SequenceNumber(100 + UInt32(4 * rackMSS)), tcb: &tcb, advertisedWindow: 65535)
    let accepted = sender.write(rackPayload(rackMSS))
    #expect(accepted)
    clock.advance(by: .milliseconds(1))
    _ = sender.segmentsToTransmit(tcb: &tcb, mss: rackMSS)
    clock.advance(by: .milliseconds(1))
    _ = sender.acknowledged(
        upTo: SequenceNumber(100 + UInt32(4 * rackMSS)), tcb: &tcb, advertisedWindow: 65535)

    #expect(
        sender.presumedLostBytes == 0,
        "fresh data was declared lost from a send time taken off an ambiguous retransmission")
}

@Test func aSegmentOlderThanTheWindowIsLostEvenWithoutReordering() throws {
    // The other side of the rule above: the window is a bound, not a
    // suppression. A segment sent long enough before the delivered one is lost
    // whether or not this path has ever reordered anything.
    //
    // Without this, the test above passes against a sender whose window is
    // infinite -- which would never detect a loss at all.
    let clock = ManualClock(start: rackStart)
    var tcb = rackTCB()
    var sender = Sender(
        congestionControl: Reno(maximumSegmentSize: rackMSS), clock: clock,
        maximumBufferedBytes: 1 << 20)
    sender.rackEnabled = true

    // One segment, then a long gap, then three more: the first is a hundred
    // milliseconds older than anything else, which is four windows.
    let accepted = sender.write(rackPayload(rackMSS))
    #expect(accepted)
    _ = sender.segmentsToTransmit(tcb: &tcb, mss: rackMSS)
    clock.advance(by: .milliseconds(100))
    staggeredFlight(&sender, &tcb, clock: clock, count: 3)

    clock.advance(by: .milliseconds(100))
    _ = sender.acknowledged(
        upTo: SequenceNumber(100), tcb: &tcb, advertisedWindow: 65535,
        selectiveAcknowledgements: [block(3)])

    #expect(sender.presumedLostBytes >= rackMSS, "the segment four windows old was not declared lost")
}

@Test func aSegmentIsGivenARoundTripBeforeItIsCalledLost() throws {
    // §6.2 measures a segment's age as `xmit_ts + rack.rtt + reo_wnd` against
    // NOW, and the round trip in that sum is not decoration: it is the time the
    // segment needs to have been given to arrive at all.
    //
    // Without it a segment is called lost as soon as something sent a window
    // later is acknowledged — which on a path whose round trip is longer than
    // the window is every segment in the flight, every time.
    let clock = ManualClock(start: rackStart)
    var tcb = rackTCB()
    var sender = Sender(
        congestionControl: Reno(maximumSegmentSize: rackMSS), clock: clock,
        maximumBufferedBytes: 1 << 20)
    sender.rackEnabled = true
    staggeredFlight(&sender, &tcb, clock: clock, count: 4)

    // Segment 3 is acknowledged 200 ms after it was sent, so `rack.rtt` is
    // about 200 ms and the window a quarter of that.
    clock.advance(by: .milliseconds(200))
    _ = sender.acknowledged(
        upTo: SequenceNumber(100), tcb: &tcb, advertisedWindow: 65535,
        selectiveAcknowledgements: [block(3)])
    let afterFirst = sender.presumedLostBytes

    // Segments 0-2 were sent three milliseconds before segment 3 and are 200 ms
    // old — one round trip, but not one round trip plus a window — so they are
    // not yet lost.
    #expect(afterFirst == 0, "segments were called lost before a round trip had passed")

    // Another 60 ms takes them past the window, and the next acknowledgement
    // finds them.
    clock.advance(by: .milliseconds(60))
    _ = sender.acknowledged(
        upTo: SequenceNumber(100), tcb: &tcb, advertisedWindow: 65535,
        selectiveAcknowledgements: [block(3), block(2)])
    #expect(sender.presumedLostBytes > 0, "the segments were never called lost at all")
}

@Test func aSegmentSentInTheSameInstantIsOrderedBySequence() throws {
    // §6.2's tie-break, and the only thing the ordering test decides that the
    // age test does not.
    //
    // A flight written in one call leaves in one instant, so every record shares
    // a send time and the age test cannot separate them — it gives the same
    // answer for the segment below the delivered one and the segment above it.
    // Sequence is what says which is which, and without it a burst that is
    // partly acknowledged declares the UNSENT half lost along with the missing
    // one.
    let clock = ManualClock(start: rackStart)
    var tcb = rackTCB()
    var sender = Sender(
        congestionControl: Reno(maximumSegmentSize: rackMSS), clock: clock,
        maximumBufferedBytes: 1 << 20)
    sender.rackEnabled = true

    // One write, one transmit: four segments, all with the same send time.
    let accepted = sender.write(rackPayload(4 * rackMSS))
    #expect(accepted)
    let segments = sender.segmentsToTransmit(tcb: &tcb, mss: rackMSS)
    #expect(segments.count == 4, "the fixture did not send the flight in one burst")

    // Long enough for the age test to admit everything: the flight is 500 ms
    // old and its round trip is 500 ms, so `xmit_ts + rtt + window` is 500 plus
    // a quarter — and the second acknowledgement below is what takes `now` past
    // it.
    clock.advance(by: .milliseconds(500))
    _ = sender.acknowledged(
        upTo: SequenceNumber(100), tcb: &tcb, advertisedWindow: 65535,
        selectiveAcknowledgements: [block(1)])
    // Not yet: the deadline is the send time plus a round trip plus a window,
    // and on a flight that left in one instant the round trip alone accounts for
    // all the time that has passed. A second acknowledgement a window later is
    // what takes `now` past it -- and the fact that it takes two is the age test
    // working, not a fixture quirk.
    #expect(sender.presumedLostBytes == 0, "the deadline was reached without the window")
    clock.advance(by: .milliseconds(200))
    _ = sender.acknowledged(
        upTo: SequenceNumber(100), tcb: &tcb, advertisedWindow: 65535,
        selectiveAcknowledgements: [block(1)])

    // Segment 0 is below the delivered one and lost. Segments 2 and 3 are above
    // it and are not: nothing has been sent after them for them to be late
    // against.
    #expect(
        sender.presumedLostBytes == rackMSS,
        "the burst above the delivered segment was declared lost: \(sender.presumedLostBytes)")
}

@Test func theWindowClosesOnceTheSenderIsAlreadyInRecovery() throws {
    // §7.2's zero, and the state that selects it. Once the sender is in recovery
    // something is known to have been lost, and there is nothing to be gained by
    // giving the rest of the flight another quarter round trip to arrive: what
    // is missing at that point is missing.
    //
    // The window's default is `min_RTT / 4`; this is the exception, and it needs
    // its own test because every other test here is on a connection that has
    // never lost anything.
    let clock = ManualClock(start: rackStart)
    var tcb = rackTCB()
    var sender = Sender(
        congestionControl: Reno(maximumSegmentSize: rackMSS), clock: clock,
        maximumBufferedBytes: 1 << 20)
    sender.rackEnabled = true
    staggeredFlight(&sender, &tcb, clock: clock, count: 6, gap: .milliseconds(20))

    // Enough SACKed runs above segment 0 for the scoreboard to declare it lost,
    // which is what puts the sender in recovery.
    clock.advance(by: .milliseconds(100))
    _ = sender.acknowledged(
        upTo: SequenceNumber(100), tcb: &tcb, advertisedWindow: 65535,
        selectiveAcknowledgements: [block(5), block(3), block(1)])
    #expect(sender.inScoreboardRecovery, "the fixture did not enter recovery")
    #expect(
        sender.reorderWindowForTesting == .zero,
        "the window stayed open on a sender that already knows it lost something")
}

@Test func anEndpointCanBeToldToUseRack() throws {
    // The selection reaching the sender, which nothing above can see: every test
    // here drives a `Sender` directly and would pass against an endpoint that
    // never turned RACK on.
    let fixture = TCPFixture()
    do {
        let endpoint = try listeningEndpoint(fixture)
        endpoint.rack = true
        try withExtendedLifetime(endpoint) {
            completeHandshake(fixture)
            _ = fixture.drainSegments()
            #expect(endpoint.usesRackForTesting, "the endpoint built a sender with RACK off")
        }
    }
    fixture.drain()
}
