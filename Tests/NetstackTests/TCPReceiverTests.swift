import NIOCore
import Testing

@testable import Netstack

// MARK: - Test fixtures

private func segment(sequence: UInt32, payload: Int = 0, fill: UInt8 = 0xaa, flags: TCPFlags = []) -> Segment {
    var buffer = ByteBuffer()
    if payload > 0 {
        buffer.writeBytes([UInt8](repeating: fill, count: payload))
    }
    return Segment(sequence: SequenceNumber(sequence), flags: flags, payload: buffer)
}

private func stateMachineSegment(
    sequence: UInt32, ack: UInt32 = 100, flags: TCPFlags = [.ack], payload: Int = 0, fill: UInt8 = 0xaa
) -> TCPSegment {
    let header = TCPHeader(
        sourcePort: 55000,
        destinationPort: 80,
        sequence: SequenceNumber(sequence),
        acknowledgement: SequenceNumber(ack),
        dataOffset: 5,
        flags: flags,
        window: 4096,
        checksum: 0,
        urgentPointer: 0,
        options: [])
    var buffer = ByteBuffer()
    if payload > 0 {
        buffer.writeBytes([UInt8](repeating: fill, count: payload))
    }
    return TCPSegment(header: header, payload: buffer)
}

private func establishedTCB(rcvNxt: UInt32 = 1000, rcvWnd: Int = 4096, sndUna: UInt32 = 100, sndNxt: UInt32 = 100) -> TCB {
    TCB(
        state: .established,
        sndUna: SequenceNumber(sndUna),
        sndNxt: SequenceNumber(sndNxt),
        sndWnd: 4096,
        sndWl1: SequenceNumber(rcvNxt),
        sndWl2: SequenceNumber(sndUna),
        iss: SequenceNumber(sndUna),
        rcvNxt: SequenceNumber(rcvNxt),
        rcvWnd: rcvWnd,
        irs: SequenceNumber(rcvNxt))
}

private func receivedBytes(_ buffers: [ByteBuffer]) -> [UInt8] {
    buffers.flatMap { Array($0.readableBytesView) }
}

private func deliveredBytes(_ actions: [TCPAction]) -> [UInt8] {
    actions.flatMap { action -> [UInt8] in
        if case .deliver(let buffer) = action { return Array(buffer.readableBytesView) }
        return []
    }
}

private func hasSendAck(_ actions: [TCPAction]) -> Bool {
    actions.contains {
        if case .sendAck = $0 { return true }
        return false
    }
}

private func hasDeliver(_ actions: [TCPAction]) -> Bool {
    actions.contains {
        if case .deliver = $0 { return true }
        return false
    }
}

/// An established TCB with a window scale genuinely negotiated, as RFC 7323
/// §2.3 negotiates it.
///
/// `TCB.rcvWindScale` is `private(set)` and must stay that way: the shift is
/// fixed once, by the handshake, and a test that reached past that would be
/// exercising a state no connection can be in. `windowScaleToOffer` is the
/// constructor parameter that exists for exactly this — it is `nil` on every
/// connection this stack builds today, so this is currently the only way a
/// non-zero shift is reachable at all.
///
/// The two shifts are deliberately *different* numbers. With `ourShift ==
/// peerShift` nothing distinguishes `>> rcvWindScale` from `>> sndWindScale`,
/// and the direction is the whole substance of RFC 7323 §2.3: `rcvWindScale`
/// is ours and scales what we advertise, `sndWindScale` is the peer's and
/// scales what it advertises.
private func scaledTCB(rcvNxt: UInt32 = 1000, rcvWnd: Int, ourShift: UInt8, peerShift: UInt8 = 3) -> TCB {
    var tcb = TCB(
        state: .established,
        sndUna: SequenceNumber(100),
        sndNxt: SequenceNumber(100),
        sndWnd: 4096,
        sndWl1: SequenceNumber(rcvNxt),
        sndWl2: SequenceNumber(100),
        iss: SequenceNumber(100),
        rcvNxt: SequenceNumber(rcvNxt),
        rcvWnd: rcvWnd,
        irs: SequenceNumber(rcvNxt),
        windowScaleToOffer: ourShift)
    tcb.negotiateWindowScale(fromSynOptions: [.windowScale(peerShift)])
    return tcb
}

/// The right edge of the receive window: the highest sequence number the peer
/// has been told it may send. Retracting this is what RFC 9293 §3.8.6.2.2
/// forbids.
///
/// In **real bytes**, which is the only unit the rule is stated in. `window`
/// is the 16-bit field as it goes on the wire, and the peer decodes it as
/// `window << Rcv.Wind.Shift`; with no scale negotiated the shift is zero and
/// this is the plain sum it has always been. Comparing wire values instead
/// would be comparing two different units the moment a scale is negotiated,
/// and would call a legitimate fall in the wire value a retraction.
private func rightEdge(_ tcb: TCB, window: UInt16) -> SequenceNumber {
    tcb.rcvNxt + (Int(window) << Int(tcb.rcvWindScale))
}

/// The wire field a real window would be advertised in at this connection's
/// negotiated scale — the starting edge for a retraction sequence, expressed
/// the way the handshake would have expressed it.
private func onTheWire(_ window: Int, at scale: UInt8) -> UInt16 {
    UInt16(min(window >> Int(scale), Int(UInt16.max)))
}

// MARK: - In-order delivery

@Test func theReceiverAdvancesRcvNxtAndDeliversAnInOrderSegment() {
    var tcb = establishedTCB(rcvNxt: 1000)
    var receiver = Receiver(reassembler: TCPReassembler(maximumBytes: 4096, maximumSegments: 64))

    let outcome = receiver.accept(segment(sequence: 1000, payload: 10, fill: 0xaa), tcb: &tcb)

    #expect(receivedBytes(outcome.delivered) == Array(repeating: 0xaa, count: 10))
    #expect(tcb.rcvNxt == SequenceNumber(1010), "RCV.NXT advances over exactly the bytes delivered")
    #expect(outcome.shouldAck)
}

@Test func theReceiverAdvancesRcvNxtAcrossTheSequenceSpaceWrap() {
    // RCV.NXT ten bytes below 2^32: the second half of this segment sits at
    // numerically smaller sequence numbers than the first. Anything that adds
    // in `Int` and clamps, rather than wrapping in `UInt32`, lands elsewhere.
    var tcb = establishedTCB(rcvNxt: 0xffff_fff6)
    var receiver = Receiver(reassembler: TCPReassembler(maximumBytes: 4096, maximumSegments: 64))

    let outcome = receiver.accept(segment(sequence: 0xffff_fff6, payload: 20, fill: 0xcc), tcb: &tcb)

    #expect(receivedBytes(outcome.delivered) == Array(repeating: 0xcc, count: 20))
    #expect(tcb.rcvNxt == SequenceNumber(0x0000_000a))
}

// MARK: - Out-of-order data

@Test func anOutOfOrderSegmentDoesNotAdvanceRcvNxt() {
    // "Does not advance" and "delivers nothing" are both satisfied by a
    // receiver that does nothing whatever -- this test passed against a stub
    // returning empty from every call. The second half is the floor under it:
    // the same receiver must go on to deliver those exact bytes, in that
    // order, once the gap in front of them closes. Held, not dropped.
    var tcb = establishedTCB(rcvNxt: 1000)
    var receiver = Receiver(reassembler: TCPReassembler(maximumBytes: 4096, maximumSegments: 64))

    let outcome = receiver.accept(segment(sequence: 1010, payload: 10, fill: 0xbb), tcb: &tcb)

    #expect(outcome.delivered.isEmpty)
    #expect(tcb.rcvNxt == SequenceNumber(1000))

    let filled = receiver.accept(segment(sequence: 1000, payload: 10, fill: 0xaa), tcb: &tcb)
    #expect(receivedBytes(filled.delivered) == Array(repeating: 0xaa, count: 10) + Array(repeating: 0xbb, count: 10))
    #expect(tcb.rcvNxt == SequenceNumber(1020), "the held bytes were kept, and RCV.NXT covers both segments")
}

@Test func anOutOfOrderSegmentIsStillAcknowledged() {
    // The duplicate ACK. RFC 5681 §3.2: a receiver MUST send an immediate ACK
    // for an out-of-order segment, and the sender's fast retransmit counts
    // those duplicates. Suppress this and fast retransmit (Task 11) never
    // fires -- the connection still works, waiting on the retransmission
    // timer instead, so only a throughput measurement would ever notice.
    var tcb = establishedTCB(rcvNxt: 1000)
    var receiver = Receiver(reassembler: TCPReassembler(maximumBytes: 4096, maximumSegments: 64))

    let outcome = receiver.accept(segment(sequence: 1010, payload: 10, fill: 0xbb), tcb: &tcb)

    #expect(outcome.shouldAck, "an out-of-order segment must be acknowledged immediately")
}

@Test func aSegmentThatOccupiesNoSequenceSpaceIsNotAcknowledged() {
    // A receiver that never asks for an ACK at all satisfies the first
    // expectation -- it passed against a do-nothing stub. The second is the
    // floor: the same receiver, one line later, must ask for one when the
    // segment does occupy sequence space. What is being pinned down is the
    // distinction, not the `false`.
    var tcb = establishedTCB(rcvNxt: 1000)
    var receiver = Receiver(reassembler: TCPReassembler(maximumBytes: 4096, maximumSegments: 64))

    let bareAck = receiver.accept(segment(sequence: 1000), tcb: &tcb)
    #expect(!bareAck.shouldAck, "acknowledging a bare ACK would put two peers in an ACK loop")

    let oneByte = receiver.accept(segment(sequence: 1000, payload: 1), tcb: &tcb)
    #expect(oneByte.shouldAck, "one byte is enough to owe an ACK")

    let bareFin = receiver.accept(segment(sequence: 1001, flags: .fin), tcb: &tcb)
    #expect(bareFin.shouldAck, "and so is a FIN carrying no data at all")
}

@Test func aSegmentFillingAGapDeliversItselfAndEverythingQueuedBehindIt() {
    var tcb = establishedTCB(rcvNxt: 1000)
    var receiver = Receiver(reassembler: TCPReassembler(maximumBytes: 4096, maximumSegments: 64))

    let third = receiver.accept(segment(sequence: 1020, payload: 10, fill: 0xcc), tcb: &tcb)
    #expect(third.delivered.isEmpty)

    let second = receiver.accept(segment(sequence: 1010, payload: 10, fill: 0xbb), tcb: &tcb)
    #expect(second.delivered.isEmpty)

    let outcome = receiver.accept(segment(sequence: 1000, payload: 10, fill: 0xaa), tcb: &tcb)

    #expect(
        receivedBytes(outcome.delivered)
            == Array(repeating: 0xaa, count: 10) + Array(repeating: 0xbb, count: 10) + Array(repeating: 0xcc, count: 10),
        "the whole run, in sequence order, not just the arriving segment")
    #expect(tcb.rcvNxt == SequenceNumber(1030))
}

// MARK: - The advertised window

@Test func theAdvertisedWindowShrinksAsTheQueueFillsAndRecoversWhenTheGapCloses() {
    // Both halves matter. A window that never shrinks promises a peer room
    // the reassembly queue does not have; a window that never recovers
    // strangles a connection that has already drained.
    let control = {
        var tcb = establishedTCB(rcvNxt: 1000, rcvWnd: 4096)
        var receiver = Receiver(reassembler: TCPReassembler(maximumBytes: 4096, maximumSegments: 64))
        return receiver.accept(segment(sequence: 1000, payload: 400), tcb: &tcb).advertisedWindow
    }()
    #expect(control == 4096, "with nothing queued, 400 in-order bytes cost the window nothing")

    var tcb = establishedTCB(rcvNxt: 1000, rcvWnd: 4096)
    var receiver = Receiver(reassembler: TCPReassembler(maximumBytes: 4096, maximumSegments: 64))

    _ = receiver.accept(segment(sequence: 2000, payload: 1000, fill: 0xbb), tcb: &tcb)
    let shrunk = receiver.accept(segment(sequence: 1000, payload: 400, fill: 0xaa), tcb: &tcb)
    // 1000 payload bytes plus one segment's overhead are held, so 2840 of the
    // 4096-byte queue is free; RCV.NXT has moved 400 and the right edge may
    // not move back, so 3696 is what can be offered.
    #expect(shrunk.advertisedWindow == 3696)
    #expect(shrunk.advertisedWindow < control, "the queued segment is what costs the window")

    let recovered = receiver.accept(segment(sequence: 1400, payload: 600, fill: 0xaa), tcb: &tcb)
    #expect(tcb.rcvNxt == SequenceNumber(3000), "the gap closing delivers the queued bytes too")
    #expect(recovered.advertisedWindow == 4096, "and the queue they leave is empty again")
}

@Test func theAdvertisedWindowNeverShrinksBelowWhatWasAlreadyOffered() {
    // Retracting the right window edge is forbidden (RFC 9293 3.8.6.2.2): the
    // peer may already have data in flight for space we advertised, and taking
    // it back makes that data unacceptable on arrival -- the connection stalls
    // with both sides believing the other owes them something.
    //
    // Driven over a sequence rather than a single in-order segment. With one
    // in-order segment and an empty queue the free-space figure is the whole
    // cap, so a receiver that advertised free space with no clamp at all would
    // pass -- the retraction only becomes visible once something is queued.
    // The first step below is that something.
    var tcb = establishedTCB(rcvNxt: 1000, rcvWnd: 4096)
    var receiver = Receiver(reassembler: TCPReassembler(maximumBytes: 4096, maximumSegments: 64))
    var edge = rightEdge(tcb, window: UInt16(tcb.rcvWnd))

    // Queued out-of-order bytes consume capacity without advancing RCV.NXT,
    // so free space falls while the edge may not.
    for step in [(sequence: UInt32(2000), payload: 1000), (sequence: 1000, payload: 400), (sequence: 1400, payload: 600)] {
        let outcome = receiver.accept(segment(sequence: step.sequence, payload: step.payload), tcb: &tcb)
        let newEdge = rightEdge(tcb, window: outcome.advertisedWindow)
        #expect(newEdge.isAtOrAfter(edge), "the right window edge moved backwards at sequence \(step.sequence)")
        edge = newEdge
    }
}

@Test func theAdvertisedWindowFitsTheWireFieldWithoutBeingTruncatedToIt() {
    // `<= 65535` is satisfied by advertising zero -- this test, in that form,
    // passed against a receiver that returned nothing from every call. The
    // point is not the ceiling but that the receiver clamps rather than
    // truncates: the default reassembler holds 256 KiB, which does not fit a
    // UInt16, and `UInt16(truncatingIfNeeded:)` of 262144 is 0 -- a receiver
    // that truncated would advertise a closed window on a completely empty
    // queue and stall the connection immediately. So the assertion is on the
    // exact value.
    //
    // 65535 is also the real ceiling today, not a placeholder: no window scale
    // is negotiated anywhere in the stack yet. See `Receiver`'s doc comment on
    // the seam Task 13 opens.
    //
    // The TCB is configured at 65535 rather than 4096 so that the wire clamp is
    // the only thing standing between the 256 KiB queue and the advertisement.
    // With 4096 configured, `TCB.rcvWndMax` caps first and the truncation this
    // test exists to catch would never be reached -- see
    // `theAdvertisedWindowNeverExceedsTheConfiguredReceiveWindow`.
    var tcb = establishedTCB(rcvNxt: 1000, rcvWnd: 65535)
    var receiver = Receiver(reassembler: TCPReassembler())

    let outcome = receiver.accept(segment(sequence: 1000, payload: 10), tcb: &tcb)

    #expect(outcome.advertisedWindow == 65535)
    #expect(tcb.rcvWnd == 65535, "and the TCB records what was advertised, since it is what the next acceptability test uses")
}

// MARK: - The negotiated receive window scale (RFC 7323 §2.3)

@Test func theAdvertisedWindowIsTheRealWindowShiftedRightByTheNegotiatedScale() {
    // The positive control first, and it is the half a degenerate receiver
    // fails: with no scale negotiated the shift is zero and the advertisement
    // is the real window untouched. A receiver that always emitted zero, or
    // always emitted 65535, would satisfy one of the two halves below and not
    // the other.
    var unscaled = establishedTCB(rcvNxt: 1000, rcvWnd: 65535)
    var unscaledReceiver = Receiver(reassembler: TCPReassembler())
    #expect(unscaledReceiver.accept(segment(sequence: 1000, payload: 1), tcb: &unscaled).advertisedWindow == 65535, "`>> 0` is the identity")

    // And with a scale, the shift is *lossy downwards*. 1,000,000 >> 7 is
    // 7812.5; 7812 is what goes on the wire, promising 999,936 bytes. 7813
    // would promise 1,000,064 against a queue that holds 1,000,000 — an
    // advertisement rounded up claims space the receiver does not have, which
    // is the one direction the error may not go.
    var tcb = scaledTCB(rcvWnd: 1_000_000, ourShift: 7)
    var receiver = Receiver(reassembler: TCPReassembler(maximumBytes: 1_000_000, maximumSegments: 64))

    let outcome = receiver.accept(segment(sequence: 1000, payload: 1), tcb: &tcb)

    #expect(outcome.advertisedWindow == 7812, "truncated, not rounded up to 7813")
    #expect(Int(outcome.advertisedWindow) << 7 == 999_936)
    #expect(
        tcb.rcvWnd == 999_936,
        "and the TCB records the window in *real bytes* — what the peer decodes — because that is the unit the acceptability test measures in")
}

@Test func theScaledAdvertisementStillFitsTheWireFieldHoweverSmallTheShift() {
    // A shift of 1 against a 10 MB queue: the real window divided by two is
    // still 5,000,000, which does not fit a 16-bit field. `UInt16(_:)` would
    // trap on it and `UInt16(truncatingIfNeeded:)` would advertise 4928. The
    // wire's own limit binds after the shift, not instead of it.
    var tcb = scaledTCB(rcvWnd: 10_000_000, ourShift: 1)
    var receiver = Receiver(reassembler: TCPReassembler(maximumBytes: 10_000_000, maximumSegments: 64))

    let outcome = receiver.accept(segment(sequence: 1000, payload: 1), tcb: &tcb)

    #expect(outcome.advertisedWindow == 65535)
    #expect(tcb.rcvWnd == 131_070, "65535 << 1: the largest window this connection can express, and it is twice the unscaled ceiling")
}

@Test func theRightWindowEdgeNeverMovesBackwardsAtAScaleThatCannotExpressEveryWindow() {
    // The point of the task. At a shift of 7 the smallest expressible step is
    // 128 bytes, so the free-space figure almost never lands on a value the
    // wire can carry, and the rounding has to go *up* on the never-retract
    // floor while it goes *down* on the space we actually have.
    //
    // Concretely: the floor is the smallest wire value W with
    // `RCV.NXT_new + (W << S) >= edge_old`, i.e. a **ceiling** division, and a
    // floor on the *wire* value rather than on the real one. Clamping in real
    // bytes and shifting afterwards — `(offered - consumed) >> S` — is a floor
    // division, and gives up to `2^S - 1` bytes of the edge away at step two
    // below.
    //
    // Asserted on the edge, in real bytes, across three steps. The wire value
    // is not the thing under test and legitimately falls from 32 to 29 while
    // the edge holds; a test that watched the wire value would call that a
    // retraction and a truncating one a success, exactly backwards.
    var tcb = scaledTCB(rcvWnd: 4096, ourShift: 7)
    var receiver = Receiver(reassembler: TCPReassembler(maximumBytes: 4096, maximumSegments: 64))
    var edge = rightEdge(tcb, window: onTheWire(tcb.rcvWnd, at: tcb.rcvWindScale))
    #expect(edge == SequenceNumber(5096), "1000 + (32 << 7): the handshake could offer 4096 exactly, since 4096 is a whole number of 128s")

    var wire: [UInt16] = []
    for step in [(sequence: UInt32(2000), payload: 1000), (sequence: 1000, payload: 400), (sequence: 1400, payload: 600)] {
        let outcome = receiver.accept(segment(sequence: step.sequence, payload: step.payload), tcb: &tcb)
        let newEdge = rightEdge(tcb, window: outcome.advertisedWindow)
        #expect(newEdge.isAtOrAfter(edge), "the right window edge moved backwards at sequence \(step.sequence)")
        edge = newEdge
        wire.append(outcome.advertisedWindow)
    }

    // The middle step is where a floor division retracts. 1000 out-of-order
    // bytes plus one segment's overhead leave 2840 free, which is 22 whole
    // 128s; RCV.NXT has moved 400, so the edge allows the window to fall to
    // 3696 real bytes — but 3696 is 28.875 steps, and 28 of them is 3584,
    // which is 112 bytes short of the edge already promised.
    #expect(wire == [32, 29, 32])
    #expect(wire[1] < wire[0], "the wire value does fall — the edge is what may not")
    #expect(edge == SequenceNumber(7096), "and once the gap closes the queue is empty again")
}

@Test func theConfiguredReceiveWindowStillCapsTheAdvertisementOnceItIsScaled() {
    // `TCB.rcvWndMax` is a cap on the *real* window, so it has to be applied
    // before the shift; applied to the wire value it would cap at 12,800 wire
    // units, which is 1.6 MB of real window from a connection configured for
    // 12,800 bytes. The default 256 KiB queue is what makes the difference
    // visible: uncapped, 262,144 >> 7 is 2048.
    var tcb = scaledTCB(rcvWnd: 12_800, ourShift: 7)
    var receiver = Receiver(reassembler: TCPReassembler())

    let outcome = receiver.accept(segment(sequence: 1000, payload: 1), tcb: &tcb)

    #expect(outcome.advertisedWindow == 100, "12,800 configured bytes are 100 units of 128, not the 2048 the queue could have offered")
    #expect(tcb.rcvWnd == 12_800)
}

@Test func theAcceptabilityWindowIsTheScaledWindowAndNotTheWireField() {
    // What makes the unit of `tcb.rcvWnd` load-bearing rather than a matter of
    // taste. `TCPStateMachine.isInReceiveWindow` and the §3.9 trim both measure
    // an arriving segment against `rcvNxt + rcvWnd`, so recording the wire
    // field there would narrow the connection's real window by a factor of
    // 2^S — 128 here — and silently discard data the peer was told it could
    // send. That is not a lost optimisation: it is a stall, since the peer
    // retransmits into a window we keep refusing.
    let queue = TCPReassembler()
    var tcb = scaledTCB(rcvWnd: 12_800, ourShift: 7)
    var receiver = Receiver(reassembler: queue)

    _ = receiveDrivingASender(segment: stateMachineSegment(sequence: 1000, payload: 10), on: &tcb, receiver: &receiver)
    #expect(tcb.rcvNxt == SequenceNumber(1010))
    #expect(tcb.rcvWnd == 12_800, "the real window, which is what the next acceptability test measures against")

    // 5000 past RCV.NXT: well inside the 12,800 real bytes advertised, and 50x
    // outside the 100 that went on the wire.
    _ = receiveDrivingASender(segment: stateMachineSegment(sequence: 6010, payload: 10), on: &tcb, receiver: &receiver)
    #expect(queue.pendingSegments == 1, "a segment inside the window the peer was actually offered must be accepted")

    // The control, so this is not satisfied by a machine that accepts
    // everything: 13,000 past RCV.NXT is outside the real window too.
    _ = receiveDrivingASender(segment: stateMachineSegment(sequence: 14_010, payload: 10), on: &tcb, receiver: &receiver)
    #expect(queue.pendingSegments == 1, "and one outside it is still refused")
}

// MARK: - FIN

@Test func anOutOfOrderFinIsNotActedOnUntilTheGapFills() {
    var tcb = establishedTCB(rcvNxt: 1000)
    var receiver = Receiver(reassembler: TCPReassembler(maximumBytes: 4096, maximumSegments: 64))

    let held = receiver.accept(segment(sequence: 1010, payload: 10, fill: 0xbb, flags: .fin), tcb: &tcb)
    #expect(!held.finReached, "the FIN's sequence has not been reached: 1000..<1010 is still missing")
    #expect(tcb.rcvNxt == SequenceNumber(1000))

    let filled = receiver.accept(segment(sequence: 1000, payload: 10, fill: 0xaa), tcb: &tcb)
    #expect(filled.finReached, "the gap-filling segment carries no FIN of its own, but it is what reaches one")
    #expect(tcb.rcvNxt == SequenceNumber(1021), "RCV.NXT covers 20 payload bytes and the FIN's own sequence number")
}

@Test func theFinIsReportedExactlyOnce() {
    var tcb = establishedTCB(rcvNxt: 1000)
    var receiver = Receiver(reassembler: TCPReassembler(maximumBytes: 4096, maximumSegments: 64))

    let first = receiver.accept(segment(sequence: 1000, flags: .fin), tcb: &tcb)
    #expect(first.finReached)
    #expect(tcb.rcvNxt == SequenceNumber(1001), "a bare FIN consumes one sequence number")

    let retransmitted = receiver.accept(segment(sequence: 1000, flags: .fin), tcb: &tcb)
    #expect(!retransmitted.finReached, "a retransmitted FIN must not re-fire the transition")
    #expect(tcb.rcvNxt == SequenceNumber(1001))
}

// MARK: - The seam with the state machine

@Test func theStateMachineLeavesRcvNxtEntirelyToTheReceiver() {
    // The double-ownership test. Both this machine and the receiver once
    // advanced RCV.NXT over in-order payload and over a FIN; if both still do,
    // every arriving byte moves it twice and the connection acknowledges data
    // it has never seen. Exact equality is what catches that -- an assertion
    // that RCV.NXT merely "advanced" is satisfied by advancing it twice.
    var tcb = establishedTCB(rcvNxt: 1000)
    var receiver = Receiver(reassembler: TCPReassembler())

    _ = receiveDrivingASender(segment: stateMachineSegment(sequence: 1000, payload: 10), on: &tcb, receiver: &receiver)
    #expect(tcb.rcvNxt == SequenceNumber(1010), "ten bytes, advanced once")

    _ = receiveDrivingASender(segment: stateMachineSegment(sequence: 1010, flags: [.fin, .ack]), on: &tcb, receiver: &receiver)
    #expect(tcb.rcvNxt == SequenceNumber(1011), "and the FIN's one sequence number, also once")
    #expect(tcb.state == .closeWait)
}

@Test func theStateMachineDeliversDataThatArrivedOutOfOrderOnceTheGapFills() {
    var tcb = establishedTCB(rcvNxt: 1000)
    var receiver = Receiver(reassembler: TCPReassembler())

    let outOfOrder = receiveDrivingASender(
        segment: stateMachineSegment(sequence: 1010, payload: 10, fill: 0xbb), on: &tcb, receiver: &receiver)
    #expect(!hasDeliver(outOfOrder), "nothing is deliverable while 1000..<1010 is missing")
    #expect(tcb.rcvNxt == SequenceNumber(1000))
    #expect(hasSendAck(outOfOrder), "but it is acknowledged -- this is the duplicate ACK fast retransmit counts")

    let inOrder = receiveDrivingASender(
        segment: stateMachineSegment(sequence: 1000, payload: 10, fill: 0xaa), on: &tcb, receiver: &receiver)
    #expect(deliveredBytes(inOrder) == Array(repeating: 0xaa, count: 10) + Array(repeating: 0xbb, count: 10))
    #expect(tcb.rcvNxt == SequenceNumber(1020))
}

@Test func aFinAheadOfAGapIsRefusedUntilThePeerRetransmitsItInOrder() {
    // The legitimate half of the in-order-FIN gate, and the reason its cost to
    // real traffic is one retransmission rather than a hang.
    //
    // A FIN ahead of a gap is stripped: its position cannot be trusted, because
    // nothing distinguishes it from a forged one (see
    // `aForgedFinCannotTruncateAStream`). Its *data* is still queued, the peer
    // is still ACKed, and the peer -- which retransmits a FIN until it is
    // acknowledged -- sends it again once our ACK has moved its SND.UNA. That
    // retransmission arrives at RCV.NXT and closes the connection. Nothing
    // re-drives the state machine for a gap that has since filled, and nothing
    // needs to.
    var tcb = establishedTCB(rcvNxt: 1000)
    var receiver = Receiver(reassembler: TCPReassembler())

    let ahead = receiveDrivingASender(
        segment: stateMachineSegment(sequence: 1010, flags: [.fin, .ack], payload: 10, fill: 0xbb), on: &tcb, receiver: &receiver)
    #expect(tcb.state == .established, "the FIN is ahead of a gap; its position is not trusted")
    #expect(hasSendAck(ahead), "and the peer is told where we actually are, so it retransmits from there")

    let filled = receiveDrivingASender(
        segment: stateMachineSegment(sequence: 1000, payload: 10, fill: 0xaa), on: &tcb, receiver: &receiver)
    #expect(
        deliveredBytes(filled) == Array(repeating: 0xaa, count: 10) + Array(repeating: 0xbb, count: 10),
        "the data that travelled with the refused FIN is not lost -- only the flag was stripped")
    #expect(tcb.state == .established, "filling the gap does not resurrect a FIN we declined to record")
    #expect(tcb.rcvNxt == SequenceNumber(1020), "twenty payload bytes and no FIN")

    let retransmitted = receiveDrivingASender(
        segment: stateMachineSegment(sequence: 1020, flags: [.fin, .ack]), on: &tcb, receiver: &receiver)
    #expect(tcb.state == .closeWait, "the retransmission arrives at RCV.NXT and is honoured")
    #expect(tcb.rcvNxt == SequenceNumber(1021))
    #expect(hasSendAck(retransmitted))
}

// MARK: - The forged FIN (RFC 5961 §3.2, applied to the FIN by analogy)

@Test func aForgedFinCannotTruncateAStream() {
    // The worst of the three, because the application is told the stream ended
    // normally. One bare FIN carrying no data, at any sequence number in the
    // offered window -- no guessing worth the name against a 4096-byte window
    // -- used to fix the FIN's position permanently (first-received-wins), and
    // the connection then reported EOF the moment RCV.NXT reached that forged
    // position. Everything the peer sent afterwards was silently dropped: the
    // state was already CLOSE-WAIT, where step 5 delivers nothing.
    var tcb = establishedTCB(rcvNxt: 1000, rcvWnd: 4096)
    var receiver = Receiver(reassembler: TCPReassembler())

    let forged = receiveDrivingASender(
        segment: stateMachineSegment(sequence: 1500, flags: [.fin, .ack]), on: &tcb, receiver: &receiver)
    #expect(tcb.state == .established, "a FIN 500 bytes ahead of RCV.NXT must not be recorded")
    #expect(hasSendAck(forged), "it is answered, exactly as an off-position RST is challenged")
    #expect(tcb.rcvNxt == SequenceNumber(1000))

    // The peer now streams 1000 bytes in two segments. The first is what used
    // to reach the forged position.
    let first = receiveDrivingASender(
        segment: stateMachineSegment(sequence: 1000, payload: 500, fill: 0xaa), on: &tcb, receiver: &receiver)
    #expect(tcb.state == .established, "reaching the forged position must not close the connection")
    #expect(deliveredBytes(first).count == 500)

    let second = receiveDrivingASender(
        segment: stateMachineSegment(sequence: 1500, payload: 500, fill: 0xbb), on: &tcb, receiver: &receiver)
    #expect(deliveredBytes(second) == Array(repeating: 0xbb, count: 500), "the second half must not be silently dropped")
    #expect(tcb.rcvNxt == SequenceNumber(2000), "all 1000 bytes, not 500")

    // Positive control. "Never closes" is satisfied perfectly by a connection
    // that can no longer close at all, which is the failure mode this fix could
    // plausibly introduce -- so the peer's real FIN, in order, must still work.
    let genuine = receiveDrivingASender(
        segment: stateMachineSegment(sequence: 2000, flags: [.fin, .ack]), on: &tcb, receiver: &receiver)
    #expect(tcb.state == .closeWait, "the peer's own FIN, at RCV.NXT, still closes the connection")
    #expect(tcb.rcvNxt == SequenceNumber(2001))
    #expect(hasSendAck(genuine))
}

@Test func aForgedFinCannotWedgeTeardownForever() {
    // The second injection: name a position the stream will never reach. The
    // forged FIN at 3000 used to be recorded permanently, so the peer's real
    // FIN at 1010 was discarded as "a second FIN claiming a different position"
    // and RCV.NXT never reached 3000. The connection stayed ESTABLISHED through
    // three retransmissions and would have stayed so forever.
    var tcb = establishedTCB(rcvNxt: 1000, rcvWnd: 4096)
    var receiver = Receiver(reassembler: TCPReassembler())

    _ = receiveDrivingASender(
        segment: stateMachineSegment(sequence: 3000, flags: [.fin, .ack]), on: &tcb, receiver: &receiver)
    _ = receiveDrivingASender(
        segment: stateMachineSegment(sequence: 1000, payload: 10, fill: 0xaa), on: &tcb, receiver: &receiver)
    #expect(tcb.rcvNxt == SequenceNumber(1010))

    // The peer's real FIN, and its retransmissions. The first one is enough;
    // the other two are here because the review drove three and found all three
    // ignored, and because a fix that worked only on a retransmission would be
    // a different bug wearing this test's green tick.
    for attempt in 1...3 {
        let actions = receiveDrivingASender(
            segment: stateMachineSegment(sequence: 1010, flags: [.fin, .ack]), on: &tcb, receiver: &receiver)
        #expect(tcb.state == .closeWait, "the peer's real FIN was ignored on attempt \(attempt)")
        #expect(hasSendAck(actions), "and a FIN must be acknowledged, on attempt \(attempt)")
    }
    #expect(tcb.rcvNxt == SequenceNumber(1011), "and RCV.NXT crossed the FIN exactly once across all three")
}

@Test func theSameGuessSentAsAResetIsAlreadyHarmlessAndStillIs() {
    // The control the review ran alongside the two injections above, kept here
    // so the symmetry is visible: the identical guess, in the identical window,
    // sent as a RST does nothing but draw a challenge ACK, because RFC 5961
    // step 1 insists on RCV.NXT exactly. That was the whole argument -- the FIN
    // reaches the application as nearly the same outcome and had no such check
    // -- so if this control ever stops holding, the FIN gate above is being
    // measured against a bar that has itself slipped.
    var tcb = establishedTCB(rcvNxt: 1000, rcvWnd: 4096)
    var receiver = Receiver(reassembler: TCPReassembler())

    let challenged = receiveDrivingASender(
        segment: stateMachineSegment(sequence: 1500, flags: [.rst]), on: &tcb, receiver: &receiver)
    #expect(tcb.state == .established, "an in-window RST that is not at RCV.NXT must not tear the connection down")
    #expect(challenged == [.sendAck], "it draws a challenge ACK and nothing else")

    // And the RST at RCV.NXT still works: "does not tear down" is satisfied by
    // a machine that can no longer be reset at all.
    _ = receiveDrivingASender(segment: stateMachineSegment(sequence: 1000, flags: [.rst]), on: &tcb, receiver: &receiver)
    #expect(tcb.state == .closed, "a RST at RCV.NXT exactly is still honoured")
}

// MARK: - Trimming to the offered window (RFC 9293 §3.9)

@Test func aSegmentIsTrimmedToTheRightEdgeOfTheOfferedWindow() {
    // The acceptability test accepts a segment whose first OR last byte is in
    // the window; it bounds neither the extent nor the end. So a segment that
    // merely starts at RCV.NXT passed it and then went to the reassembler
    // whole, where the only remaining limit was a quarter of the sequence
    // space. 5000 bytes against a 4-byte window were delivered in full.
    var tcb = establishedTCB(rcvNxt: 1000, rcvWnd: 4)
    let queue = TCPReassembler()
    var receiver = Receiver(reassembler: queue)

    let actions = receiveDrivingASender(
        segment: stateMachineSegment(sequence: 1000, payload: 5000, fill: 0xaa), on: &tcb, receiver: &receiver)
    #expect(deliveredBytes(actions).count == 4, "only the four bytes the peer was offered")
    #expect(tcb.rcvNxt == SequenceNumber(1004), "RCV.NXT must not run 5000 bytes past a 4-byte window")
    #expect(queue.pendingSegments == 0, "and the remainder is dropped, not queued for later")

    // The same segment, offset so that its start is in the window and its bulk
    // is past the right edge: the reviewer's second row. Everything past the
    // edge used to be queued.
    var offsetTcb = establishedTCB(rcvNxt: 1000, rcvWnd: 4)
    let offsetQueue = TCPReassembler()
    var offsetReceiver = Receiver(reassembler: offsetQueue)
    _ = receiveDrivingASender(
        segment: stateMachineSegment(sequence: 1003, payload: 5000, fill: 0xbb), on: &offsetTcb, receiver: &offsetReceiver)
    #expect(offsetTcb.rcvNxt == SequenceNumber(1000), "it is out of order, so nothing is delivered")
    #expect(offsetQueue.pendingBytes == 1 + TCPReassembler.perSegmentOverhead, "exactly the one byte inside the window is held")
}

@Test func aSegmentThatFitsTheOfferedWindowIsNotTrimmedAtAll() {
    // The positive control for the trim. "Nothing past the right edge reaches
    // the reassembler" is satisfied completely by a receiver that is never
    // driven at all, and a trim with an off-by-one or an inverted bound would
    // look identical from the test above. So: a segment that fits exactly must
    // arrive whole, in order and out of order alike.
    var inOrder = establishedTCB(rcvNxt: 1000, rcvWnd: 4)
    var inOrderReceiver = Receiver(reassembler: TCPReassembler())
    let actions = receiveDrivingASender(
        segment: stateMachineSegment(sequence: 1000, payload: 4, fill: 0xaa), on: &inOrder, receiver: &inOrderReceiver)
    #expect(deliveredBytes(actions) == Array(repeating: 0xaa, count: 4), "a segment filling the window exactly is delivered whole")
    #expect(inOrder.rcvNxt == SequenceNumber(1004))

    var outOfOrder = establishedTCB(rcvNxt: 1000, rcvWnd: 100)
    let queue = TCPReassembler()
    var outOfOrderReceiver = Receiver(reassembler: queue)
    _ = receiveDrivingASender(
        segment: stateMachineSegment(sequence: 1050, payload: 10, fill: 0xbb), on: &outOfOrder, receiver: &outOfOrderReceiver)
    #expect(queue.pendingBytes == 10 + TCPReassembler.perSegmentOverhead, "and an out-of-order one well inside the window is held whole")
}

@Test func aTrimHandsTheReceiverNothingOutsideTheWindowInEitherDirection() {
    // White-box, on `receiverInput`'s own return value, and the reason is worth
    // stating: the LOW side of the trim -- dropping bytes below RCV.NXT -- has
    // no connection-level consequence today, because `TCPReassembler` clips at
    // RCV.NXT itself a moment later. Setting `below` to zero was falsified
    // against the whole 339-test suite and nothing failed. An assertion driven
    // through `TCPStateMachine.receive` therefore cannot guard that line at
    // all, and writing one that appears to would be worse than writing none.
    //
    // What is being pinned is the seam's own contract -- the receiver is handed
    // only bytes inside the window -- so that it holds on this function's terms
    // rather than on a neighbour's silent behaviour. The same neighbour's
    // clipping was already noted by the midpoint review as an undocumented
    // dependency of exactly this kind.
    var tcb = establishedTCB(rcvNxt: 1010, rcvWnd: 20)

    // Overlapping the left edge: a retransmission the peer resent because our
    // ACK was lost. Ten bytes are already received; ten are new.
    let overlapping = TCPStateMachine.receiverInput(
        for: stateMachineSegment(sequence: 1000, payload: 20, fill: 0xaa), tcb: tcb)
    #expect(overlapping.segment.sequence == SequenceNumber(1010), "the already-received prefix is dropped, not re-offered")
    #expect(overlapping.segment.payload.readableBytes == 10)

    // Overlapping the right edge, and both edges at once.
    let past = TCPStateMachine.receiverInput(for: stateMachineSegment(sequence: 1010, payload: 50, fill: 0xbb), tcb: tcb)
    #expect(past.segment.sequence == SequenceNumber(1010))
    #expect(past.segment.payload.readableBytes == 20, "nothing past RCV.NXT + RCV.WND")

    let straddling = TCPStateMachine.receiverInput(for: stateMachineSegment(sequence: 1000, payload: 100, fill: 0xcc), tcb: tcb)
    #expect(straddling.segment.sequence == SequenceNumber(1010))
    #expect(straddling.segment.payload.readableBytes == 20, "exactly the offered window, from both directions at once")

    // Positive control: a segment already inside the window is handed over
    // untouched. Every assertion above is satisfied by returning an empty
    // segment always, which would drop the connection's entire data path.
    tcb.rcvNxt = SequenceNumber(1010)
    let fits = TCPStateMachine.receiverInput(for: stateMachineSegment(sequence: 1012, payload: 5, fill: 0xdd), tcb: tcb)
    #expect(fits.segment.sequence == SequenceNumber(1012), "an in-window segment keeps its own sequence number")
    #expect(Array(fits.segment.payload.readableBytesView) == Array(repeating: 0xdd, count: 5), "and all of its bytes")
    #expect(!fits.finRefused)
}

@Test func aFinPastTheRightEdgeOfTheWindowIsNotRecorded() {
    // The FIN gate and the trim have to agree at one point: a segment that
    // starts at RCV.NXT but runs past the right edge has its tail trimmed, and
    // the FIN sits in the part that was trimmed away. Recording it would place
    // the FIN behind bytes this connection has just refused, which is the
    // wedge of `aForgedFinCannotWedgeTeardownForever` reached by a legal
    // segment start.
    var tcb = establishedTCB(rcvNxt: 1000, rcvWnd: 4)
    var receiver = Receiver(reassembler: TCPReassembler())

    _ = receiveDrivingASender(
        segment: stateMachineSegment(sequence: 1000, flags: [.fin, .ack], payload: 10, fill: 0xaa), on: &tcb, receiver: &receiver)
    #expect(tcb.state == .established, "the FIN is past the right edge; it is not ours to record")
    #expect(tcb.rcvNxt == SequenceNumber(1004), "four bytes were accepted and the rest, FIN included, refused")
}

// MARK: - The advertised window is bounded by the configured one

@Test func theAdvertisedWindowNeverExceedsTheConfiguredReceiveWindow() {
    // The configured RCV.WND used to enter `advertisedWindow` only as a floor,
    // so free reassembly space -- 256 KiB by default -- decided what was
    // advertised. A TCB configured with `rcvWnd: 100` advertised 65535 after
    // one byte.
    var tcb = establishedTCB(rcvNxt: 1000, rcvWnd: 100)
    var receiver = Receiver(reassembler: TCPReassembler())

    let outcome = receiver.accept(segment(sequence: 1000, payload: 1), tcb: &tcb)
    #expect(outcome.advertisedWindow == 100, "the queue's free space is what we could offer, not what we said we would")
    #expect(tcb.rcvWnd == 100)

    // Positive control: a cap is satisfied by advertising a closed window
    // forever, and by any figure below the cap. A connection configured wide
    // must still get the wide window from the same queue.
    var wide = establishedTCB(rcvNxt: 1000, rcvWnd: 65535)
    var wideReceiver = Receiver(reassembler: TCPReassembler())
    let wideOutcome = wideReceiver.accept(segment(sequence: 1000, payload: 1), tcb: &wide)
    #expect(wideOutcome.advertisedWindow == 65535)
}

@Test func theResetWindowIsNotWidenedByTheReceiversDefaultQueueSize() {
    // Why the cap above is a security fix and not a tidy-up. RFC 5961's RST
    // test (`isInReceiveWindow`) measures against the same `rcvWnd` the
    // receiver writes back, so a window widened by a defaulted queue size
    // widens the band of blind RSTs that draw a challenge ACK -- from the 100
    // bytes this connection actually offered to 65535, a factor of 655, as a
    // side effect of a convenience default that had nothing to do with resets.
    var tcb = establishedTCB(rcvNxt: 1000, rcvWnd: 100)
    var receiver = Receiver(reassembler: TCPReassembler())
    _ = receiveDrivingASender(segment: stateMachineSegment(sequence: 1000, payload: 1), on: &tcb, receiver: &receiver)
    #expect(tcb.rcvWnd == 100)

    let far = receiveDrivingASender(segment: stateMachineSegment(sequence: 21_001, flags: [.rst]), on: &tcb, receiver: &receiver)
    #expect(far == [.none], "a RST 20000 past RCV.NXT is outside the offered window and is discarded in silence")
    #expect(tcb.state == .established)

    // Positive controls: silence is also what a machine that ignores every RST
    // produces. Both live behaviours must survive the narrowing.
    let near = receiveDrivingASender(segment: stateMachineSegment(sequence: 1050, flags: [.rst]), on: &tcb, receiver: &receiver)
    #expect(near == [.sendAck], "a RST inside the 100-byte window still draws a challenge ACK")
    _ = receiveDrivingASender(segment: stateMachineSegment(sequence: 1001, flags: [.rst]), on: &tcb, receiver: &receiver)
    #expect(tcb.state == .closed, "and a RST at RCV.NXT exactly still tears the connection down")
}

// MARK: - Data queued past the peer's own FIN

@Test func dataQueuedPastAPeersOwnFinCannotWedgeTeardown() {
    // The residual from round 1, traced rather than assumed. The mechanism is
    // an OVERSHOOT, not "data arriving after a FIN": the offending bytes arrive
    // while nothing is known about any FIN at all.
    //
    // The peer queues 10 bytes at 1005. It then sends 5 bytes and a FIN in
    // order at 1000, putting its FIN at 1005 -- contradicting data it has
    // already sent. Admitting that segment used to deliver its 5 bytes AND the
    // 10 queued behind them, landing RCV.NXT on 1015: past the FIN, never on
    // it. `Receiver` tests `rcvNxt == fin`, an exact equality that could then
    // never hold again, so the connection stayed ESTABLISHED for good and went
    // on accepting data (1020, 1025, ...) with no way to ever close.
    var tcb = establishedTCB(rcvNxt: 1000, rcvWnd: 4096)
    var receiver = Receiver(reassembler: TCPReassembler())

    _ = receiveDrivingASender(
        segment: stateMachineSegment(sequence: 1005, payload: 10, fill: 0xbb), on: &tcb, receiver: &receiver)
    #expect(tcb.rcvNxt == SequenceNumber(1000), "out of order: queued, nothing delivered yet")

    let actions = receiveDrivingASender(
        segment: stateMachineSegment(sequence: 1000, flags: [.fin, .ack], payload: 5, fill: 0xaa), on: &tcb, receiver: &receiver)
    #expect(tcb.state == .closeWait, "RCV.NXT must land on the FIN, not jump over it")
    #expect(tcb.rcvNxt == SequenceNumber(1006), "five bytes plus the FIN's own sequence number")
    #expect(
        deliveredBytes(actions) == Array(repeating: 0xaa, count: 5),
        "and the bytes the peer queued past its own FIN are dropped, not handed to the application")
    #expect(hasSendAck(actions))
}

@Test func aQueuedRunStraddlingTheFinKeepsOnlyThePartBeforeIt() {
    // The other branch of the discard: a queued run that begins before the
    // FIN's position and continues past it is trimmed rather than dropped
    // whole. Getting this wrong in the dropping direction loses bytes the peer
    // legitimately sent before its FIN; getting it wrong in the keeping
    // direction is the overshoot again, one byte at a time.
    var tcb = establishedTCB(rcvNxt: 1000, rcvWnd: 4096)
    var receiver = Receiver(reassembler: TCPReassembler())

    _ = receiveDrivingASender(
        segment: stateMachineSegment(sequence: 1002, payload: 10, fill: 0xbb), on: &tcb, receiver: &receiver)
    let actions = receiveDrivingASender(
        segment: stateMachineSegment(sequence: 1000, flags: [.fin, .ack], payload: 5, fill: 0xaa), on: &tcb, receiver: &receiver)

    #expect(tcb.state == .closeWait)
    #expect(tcb.rcvNxt == SequenceNumber(1006))
    #expect(
        deliveredBytes(actions) == Array(repeating: 0xaa, count: 2) + Array(repeating: 0xbb, count: 3),
        "the queued run's first three bytes are before the FIN and are delivered; the rest is not")
}

@Test func queuedDataIsOnlyDiscardedWhenAFinSaysItMustBe() {
    // The positive control, and it is the load-bearing half of this pair: "the
    // connection is not wedged" is satisfied perfectly by a reassembler that
    // empties its queue on every insert, and "teardown completes" by one that
    // tears down on anything. Neither may be true.
    //
    // The same shape as the wedge, minus the FIN. Nothing may be discarded, and
    // the connection must stay open.
    var tcb = establishedTCB(rcvNxt: 1000, rcvWnd: 4096)
    var receiver = Receiver(reassembler: TCPReassembler())

    _ = receiveDrivingASender(
        segment: stateMachineSegment(sequence: 1005, payload: 10, fill: 0xbb), on: &tcb, receiver: &receiver)
    let filled = receiveDrivingASender(
        segment: stateMachineSegment(sequence: 1000, payload: 5, fill: 0xaa), on: &tcb, receiver: &receiver)

    #expect(
        deliveredBytes(filled) == Array(repeating: 0xaa, count: 5) + Array(repeating: 0xbb, count: 10),
        "with no FIN in play, every queued byte is still delivered when the gap closes")
    #expect(tcb.state == .established, "and nothing has closed the connection")
    #expect(tcb.rcvNxt == SequenceNumber(1015))

    // And the conforming close that follows still completes, on the same
    // connection: the peer's real FIN sits after all of its data.
    let closing = receiveDrivingASender(
        segment: stateMachineSegment(sequence: 1015, flags: [.fin, .ack]), on: &tcb, receiver: &receiver)
    #expect(tcb.state == .closeWait)
    #expect(tcb.rcvNxt == SequenceNumber(1016))
    #expect(hasSendAck(closing))
}

@Test func anUnacceptableSegmentNeverReachesTheReassembler() {
    // Ordering property: the receiver is driven only after RFC 9293's
    // acceptability test. Run the other way round, a peer could queue -- and
    // ultimately have delivered -- data far outside the window it was offered.
    //
    // "Nothing was queued" on its own is satisfied by a receiver that queues
    // nothing ever, which is how this passed against a do-nothing stub. The
    // control below is the floor: an out-of-order segment that IS acceptable,
    // offered to the same machine, must reach the queue. Without it this test
    // would still pass if step 5 stopped calling the receiver altogether --
    // which would suppress every out-of-order segment, not just the hostile
    // one, and look identical from here.
    let rejected = TCPReassembler()
    var farOutOfWindow = establishedTCB(rcvNxt: 1000, rcvWnd: 100)
    var rejecting = Receiver(reassembler: rejected)
    _ = receiveDrivingASender(segment: stateMachineSegment(sequence: 50_000, payload: 10), on: &farOutOfWindow, receiver: &rejecting)
    #expect(rejected.pendingSegments == 0)
    #expect(farOutOfWindow.rcvNxt == SequenceNumber(1000))

    let accepted = TCPReassembler()
    var inWindow = establishedTCB(rcvNxt: 1000, rcvWnd: 100)
    var accepting = Receiver(reassembler: accepted)
    _ = receiveDrivingASender(segment: stateMachineSegment(sequence: 1050, payload: 10), on: &inWindow, receiver: &accepting)
    #expect(accepted.pendingSegments == 1, "an acceptable out-of-order segment is held, not discarded")
}

/// `TCPStateMachine.receive` drives a `Sender` as well as a `Receiver` — it is
/// the single advancer of SND.UNA over data, and is called from inside the
/// machine so no caller can acknowledge separately (see `TCPStateMachine`'s doc
/// comment on the split). Nothing in this file asserts anything about the send
/// side, so a fresh sender per call is exactly right: it makes SND.UNA advance
/// the way the machine expects while carrying no queue, no in-flight record and
/// no duplicate-ACK run from one call into the next. A shared one would quietly
/// turn every test here into an integration test of two components, which is
/// the same reasoning the fresh-receiver helper above rests on.
///
/// A fresh `ChallengeACKBudget` per call, for the third time and the same
/// reason: RFC 5961 §7's throttle is stack-wide state that survives across
/// segments, and letting it accumulate here would make a test in this file fail
/// because of how many segments an unrelated test above it had sent. The
/// throttle's own behaviour is asserted where it is observable —
/// `TCPEndpointTests`' challenge-ACK section, against real emitted frames.
private func receiveDrivingASender(segment: TCPSegment, on tcb: inout TCB, receiver: inout Receiver) -> [TCPAction] {
    var sender = Sender(
        congestionControl: Reno(maximumSegmentSize: 1460), clock: ManualClock(), maximumBufferedBytes: 64 * 1024)
    var challengeACKs = ChallengeACKBudget(clock: ManualClock())
    return TCPStateMachine.receive(
        segment: segment, on: &tcb, receiver: &receiver, sender: &sender, challengeACKs: &challengeACKs)
}
