import NIOCore
import Testing

@testable import Netstack

// MARK: - Test fixtures

/// Builds a `TCPSegment` for a given sequence/ack/flags. `payload` is a
/// byte count only (its content is never inspected by the state machine
/// except for its length and, when delivered, its identity), so it is
/// filled with zero bytes.
private func segment(
    sequence: UInt32, ack: UInt32 = 0, flags: TCPFlags = [], payload: Int = 0, window: UInt16 = 4096,
    options: [TCPOption] = []
) -> TCPSegment {
    let header = TCPHeader(
        sourcePort: 55000,
        destinationPort: 80,
        sequence: SequenceNumber(sequence),
        acknowledgement: SequenceNumber(ack),
        // Derived rather than fixed at 5, so a fixture carrying options is not
        // internally inconsistent. The state machine never reads it; a header
        // that says "no options" while carrying three would still be a
        // misleading thing to leave in a fixture.
        dataOffset: 5 + TCPOptionCodec.encode(options).count / 4,
        flags: flags,
        window: window,
        checksum: 0,
        urgentPointer: 0,
        options: options)
    var buffer = ByteBuffer()
    if payload > 0 {
        buffer.writeBytes([UInt8](repeating: 0, count: payload))
    }
    return TCPSegment(header: header, payload: buffer)
}

/// `TCPStateMachine.receive` takes a `Receiver`, which owns RCV.NXT, delivery
/// and the advertised window. Every call site in this file goes through here so
/// the plumbing is written once.
///
/// **A fresh receiver per call, deliberately.** No test in this file may depend
/// on reassembly state surviving between two `receive` calls -- an out-of-order
/// segment offered here is forgotten before the next one arrives. That is not
/// an oversight to be fixed by hoisting the receiver: the tests that exercise
/// the receiver's memory, and the seam between it and this machine, live in
/// `TCPReceiverTests.swift` and hold a receiver across calls on purpose. Making
/// this one persistent would quietly turn every test below into an integration
/// test of two components at once, which is how the seam stopped being covered
/// by anything the first time.
private func stateMachineReceive(segment: TCPSegment, on tcb: inout TCB) -> [TCPAction] {
    var receiver = Receiver(reassembler: TCPReassembler())
    return receiveDrivingASender(segment: segment, on: &tcb, receiver: &receiver)
}

/// `windowScaleToOffer` defaults to nil, which is what every connection this
/// stack actually creates carries (`TCPEndpoint.windowScaleToOffer`). The
/// negotiation tests below pass a non-nil one on purpose: the rule has to be
/// exercised with a real offer *before* the stack starts making one, or the
/// step that starts advertising the option would be the first thing to run it.
private func listenTCB(iss: UInt32 = 1000, windowScaleToOffer: UInt8? = nil) -> TCB {
    TCB(
        state: .listen,
        sndUna: SequenceNumber(iss),
        sndNxt: SequenceNumber(iss),
        sndWnd: 0,
        sndWl1: SequenceNumber(0),
        sndWl2: SequenceNumber(0),
        iss: SequenceNumber(iss),
        rcvNxt: SequenceNumber(0),
        rcvWnd: 4096,
        irs: SequenceNumber(0),
        windowScaleToOffer: windowScaleToOffer)
}

private func synSentTCB(iss: UInt32 = 2000, windowScaleToOffer: UInt8? = nil) -> TCB {
    TCB(
        state: .synSent,
        sndUna: SequenceNumber(iss),
        sndNxt: SequenceNumber(iss) + 1,
        sndWnd: 0,
        sndWl1: SequenceNumber(0),
        sndWl2: SequenceNumber(0),
        iss: SequenceNumber(iss),
        rcvNxt: SequenceNumber(0),
        rcvWnd: 4096,
        irs: SequenceNumber(0),
        windowScaleToOffer: windowScaleToOffer)
}

/// A Window Scale option as it arrives from the wire: the three option bytes
/// (kind 3, length 3, shift) plus a NOP pad, run through `TCPOptionCodec.parse`.
///
/// Deliberately not a `.windowScale(shift)` case written by hand, and not
/// `TCPOptionCodec.encode` either. RFC 7323 §2.3's clamp to a maximum shift of
/// 14 lives in `parse`, and `TCB.negotiateWindowScale(fromSynOptions:)` relies
/// on it rather than re-checking. A fixture that skipped the parser would be
/// feeding the TCB a shift no peer could actually deliver, and
/// `aPeerWindowScaleOfFourteenIsRecordedAndFifteenArrivesAlreadyClampedToIt`
/// would then assert nothing about this stack at all.
///
/// The mutating `parse(&bytes)` is hoisted here so no `#expect` contains it.
private func windowScaleOptionFromTheWire(shift: UInt8) -> [TCPOption] {
    var bytes = ByteBuffer()
    bytes.writeBytes([3, 3, shift, 1])
    return TCPOptionCodec.parse(&bytes) ?? []
}

private func synReceivedTCB(iss: UInt32 = 3000, irs: UInt32 = 8000) -> TCB {
    TCB(
        state: .synReceived,
        sndUna: SequenceNumber(iss),
        sndNxt: SequenceNumber(iss) + 1,
        sndWnd: 4096,
        sndWl1: SequenceNumber(irs),
        sndWl2: SequenceNumber(iss),
        iss: SequenceNumber(iss),
        rcvNxt: SequenceNumber(irs) + 1,
        rcvWnd: 4096,
        irs: SequenceNumber(irs))
}

private func establishedTCB(
    sndUna: UInt32 = 100, sndNxt: UInt32 = 100, rcvNxt: UInt32 = 1000, rcvWnd: Int = 100
) -> TCB {
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

private func finWait1TCB(sndUna: UInt32 = 100, rcvNxt: UInt32 = 1000, rcvWnd: Int = 100) -> TCB {
    TCB(
        state: .finWait1,
        sndUna: SequenceNumber(sndUna),
        sndNxt: SequenceNumber(sndUna) + 1,
        sndWnd: 4096,
        sndWl1: SequenceNumber(rcvNxt),
        sndWl2: SequenceNumber(sndUna),
        iss: SequenceNumber(sndUna),
        rcvNxt: SequenceNumber(rcvNxt),
        rcvWnd: rcvWnd,
        irs: SequenceNumber(rcvNxt))
}

private func finWait2TCB(sndUna: UInt32 = 100, rcvNxt: UInt32 = 1000, rcvWnd: Int = 100) -> TCB {
    TCB(
        state: .finWait2,
        sndUna: SequenceNumber(sndUna),
        sndNxt: SequenceNumber(sndUna),
        sndWnd: 4096,
        sndWl1: SequenceNumber(rcvNxt),
        sndWl2: SequenceNumber(sndUna),
        iss: SequenceNumber(sndUna),
        rcvNxt: SequenceNumber(rcvNxt),
        rcvWnd: rcvWnd,
        irs: SequenceNumber(rcvNxt))
}

private func lastAckTCB(sndUna: UInt32 = 100, rcvNxt: UInt32 = 1000, rcvWnd: Int = 100) -> TCB {
    TCB(
        state: .lastAck,
        sndUna: SequenceNumber(sndUna),
        sndNxt: SequenceNumber(sndUna) + 1,
        sndWnd: 4096,
        sndWl1: SequenceNumber(rcvNxt),
        sndWl2: SequenceNumber(sndUna),
        iss: SequenceNumber(sndUna),
        rcvNxt: SequenceNumber(rcvNxt),
        rcvWnd: rcvWnd,
        irs: SequenceNumber(rcvNxt))
}

/// TIME-WAIT: our FIN has been sent and acknowledged (`sndUna == sndNxt`), and
/// the peer's FIN has been received and processed, so RCV.NXT sits one past it
/// -- the peer's FIN occupied `rcvNxt - 1`.
private func timeWaitTCB(sndUna: UInt32 = 100, rcvNxt: UInt32 = 1000, rcvWnd: Int = 100) -> TCB {
    TCB(
        state: .timeWait,
        sndUna: SequenceNumber(sndUna),
        sndNxt: SequenceNumber(sndUna),
        sndWnd: 4096,
        sndWl1: SequenceNumber(rcvNxt),
        sndWl2: SequenceNumber(sndUna),
        iss: SequenceNumber(sndUna),
        rcvNxt: SequenceNumber(rcvNxt),
        rcvWnd: rcvWnd,
        irs: SequenceNumber(rcvNxt))
}

private func containsSendSynAck(_ actions: [TCPAction]) -> Bool {
    actions.contains { if case .sendSynAck = $0 { return true }; return false }
}

private func containsSendAck(_ actions: [TCPAction]) -> Bool {
    actions.contains { if case .sendAck = $0 { return true }; return false }
}

private func containsDeliver(_ actions: [TCPAction]) -> Bool {
    actions.contains { if case .deliver = $0 { return true }; return false }
}

private func containsDeleteTCB(_ actions: [TCPAction]) -> Bool {
    actions.contains { if case .deleteTCB = $0 { return true }; return false }
}

private func containsStartTimeWait(_ actions: [TCPAction]) -> Bool {
    actions.contains { if case .startTimeWait = $0 { return true }; return false }
}

private func containsSendFin(_ actions: [TCPAction]) -> Bool {
    actions.contains { if case .sendFin = $0 { return true }; return false }
}

private func closeWaitTCB(sndUna: UInt32 = 100, rcvNxt: UInt32 = 1000, rcvWnd: Int = 100) -> TCB {
    TCB(
        state: .closeWait,
        sndUna: SequenceNumber(sndUna),
        sndNxt: SequenceNumber(sndUna),
        sndWnd: 4096,
        sndWl1: SequenceNumber(rcvNxt),
        sndWl2: SequenceNumber(sndUna),
        iss: SequenceNumber(sndUna),
        rcvNxt: SequenceNumber(rcvNxt),
        rcvWnd: rcvWnd,
        irs: SequenceNumber(rcvNxt))
}

// MARK: - Happy path

@Test func passiveOpenMovesListenToSynReceived() {
    var tcb = listenTCB(iss: 1000)
    let actions = stateMachineReceive(segment: segment(sequence: 5000, flags: [.syn]), on: &tcb)
    #expect(tcb.state == .synReceived)
    #expect(containsSendSynAck(actions))
    #expect(tcb.irs == SequenceNumber(5000))
    #expect(tcb.rcvNxt == SequenceNumber(5001))
}

@Test func handshakeCompletionMovesSynReceivedToEstablished() {
    var tcb = synReceivedTCB(iss: 3000, irs: 8000)
    let actions = stateMachineReceive(segment: segment(sequence: 8001, ack: 3001, flags: [.ack]), on: &tcb)
    #expect(tcb.state == .established)
    #expect(tcb.sndUna == SequenceNumber(3001))
    // The handshake-completing ACK carries no data and no FIN, so there is
    // nothing left to answer: the connection is simply open. Asserting this
    // pins down that the transition sends nothing -- a stray .sendAck here
    // would be an unprovoked segment on every accepted connection, and a
    // .sendRst would refuse a connection that just completed correctly.
    #expect(actions == [.none])
}

@Test func localCloseFromSynReceivedSendsAFin() {
    // A close() that only bumps sndNxt leaves the sender to infer "there is
    // an unsent FIN" from state and sndNxt. Nothing else in this machine
    // works that way, and a sender that inferred it wrongly would produce a
    // connection that opens fine and then never closes.
    var tcb = synReceivedTCB(iss: 3000, irs: 8000)
    let actions = TCPStateMachine.close(on: &tcb)
    #expect(tcb.state == .finWait1)
    #expect(tcb.sndNxt == SequenceNumber(3002), "our FIN consumes a sequence number")
    #expect(containsSendFin(actions))
}

@Test func localCloseFromCloseWaitSendsAFin() {
    var tcb = closeWaitTCB(sndUna: 100)
    let actions = TCPStateMachine.close(on: &tcb)
    #expect(tcb.state == .lastAck)
    #expect(tcb.sndNxt == SequenceNumber(101))
    #expect(containsSendFin(actions))
}

@Test func aCloseInAStateThatHasAlreadyClosedSendsNoFin() {
    // SYN-RECEIVED, ESTABLISHED and CLOSE-WAIT are the only three states
    // whose CLOSE queues a FIN (see the three tests around this one). A
    // second CLOSE must not emit another one, or a half-closed connection
    // would retransmit FINs the peer has already acknowledged. Without this,
    // "returns .sendFin" could be satisfied by returning it unconditionally.
    var finWait1 = finWait1TCB(sndUna: 100)
    let finWait1Actions = TCPStateMachine.close(on: &finWait1)
    #expect(!containsSendFin(finWait1Actions))
    var timeWait = establishedTCB(sndUna: 100)
    timeWait.state = .timeWait
    let timeWaitActions = TCPStateMachine.close(on: &timeWait)
    #expect(!containsSendFin(timeWaitActions))
    var listening = listenTCB()
    let listenActions = TCPStateMachine.close(on: &listening)
    #expect(!containsSendFin(listenActions))
    #expect(containsDeleteTCB(listenActions), "closing a LISTEN just discards the block")
}

@Test func activeOpenMovesSynSentToEstablished() {
    var tcb = synSentTCB(iss: 2000)
    let actions = stateMachineReceive(segment: segment(sequence: 9000, ack: 2001, flags: [.syn, .ack]), on: &tcb)
    #expect(tcb.state == .established)
    #expect(containsSendAck(actions))
    #expect(tcb.irs == SequenceNumber(9000))
}

@Test func simultaneousOpenMovesSynSentToSynReceived() {
    var tcb = synSentTCB(iss: 2000)
    let actions = stateMachineReceive(segment: segment(sequence: 9000, flags: [.syn]), on: &tcb)
    #expect(tcb.state == .synReceived)
    #expect(containsSendSynAck(actions))
}

@Test func localCloseMovesEstablishedToFinWait1() {
    var tcb = establishedTCB(sndNxt: 500)
    let actions = TCPStateMachine.close(on: &tcb)
    #expect(tcb.state == .finWait1)
    #expect(tcb.sndNxt == SequenceNumber(501), "our FIN consumes a sequence number")
    #expect(containsSendFin(actions))
}

@Test func peerCloseMovesEstablishedToCloseWait() {
    var tcb = establishedTCB(sndUna: 100, sndNxt: 100, rcvNxt: 1000, rcvWnd: 100)
    let actions = stateMachineReceive(segment: segment(sequence: 1000, ack: 100, flags: [.fin, .ack]), on: &tcb)
    #expect(tcb.state == .closeWait)
    #expect(containsSendAck(actions))
    #expect(tcb.rcvNxt == SequenceNumber(1001))
}

@Test func simultaneousCloseMovesFinWait1ToClosing() {
    var tcb = finWait1TCB(sndUna: 100, rcvNxt: 1000, rcvWnd: 100)
    // The peer's FIN acks only what we'd already sent (sndUna), not the
    // FIN we just sent ourselves -- both sides closing at once.
    let actions = stateMachineReceive(segment: segment(sequence: 1000, ack: 100, flags: [.fin, .ack]), on: &tcb)
    #expect(tcb.state == .closing)
    #expect(containsSendAck(actions))
}

@Test func finWait1PlusAckMovesToFinWait2() {
    var tcb = finWait1TCB(sndUna: 100, rcvNxt: 1000, rcvWnd: 100)
    // sndNxt is sndUna+1 (our unacked FIN); acking it exactly retires it.
    _ = stateMachineReceive(segment: segment(sequence: 1000, ack: 101, flags: [.ack]), on: &tcb)
    #expect(tcb.state == .finWait2)
    #expect(tcb.sndUna == SequenceNumber(101))
}

@Test func finWait2PlusFinMovesToTimeWait() {
    var tcb = finWait2TCB(sndUna: 100, rcvNxt: 1000, rcvWnd: 100)
    let actions = stateMachineReceive(segment: segment(sequence: 1000, ack: 100, flags: [.fin, .ack]), on: &tcb)
    #expect(tcb.state == .timeWait)
    #expect(containsStartTimeWait(actions))
    #expect(tcb.rcvNxt == SequenceNumber(1001))
}

@Test func lastAckPlusAckMovesToClosed() {
    var tcb = lastAckTCB(sndUna: 100, rcvNxt: 1000, rcvWnd: 100)
    // sndNxt is sndUna+1 (our unacked FIN); acking it exactly retires it.
    let actions = stateMachineReceive(segment: segment(sequence: 1000, ack: 101, flags: [.ack]), on: &tcb)
    #expect(tcb.state == .closed)
    #expect(containsDeleteTCB(actions))
}

@Test func inOrderDataInEstablishedIsDeliveredAndAcked() {
    var tcb = establishedTCB(sndUna: 100, sndNxt: 100, rcvNxt: 1000, rcvWnd: 100)
    let actions = stateMachineReceive(segment: segment(sequence: 1000, ack: 100, flags: [.ack], payload: 10), on: &tcb)
    #expect(tcb.rcvNxt == SequenceNumber(1010))
    #expect(containsDeliver(actions))
    #expect(containsSendAck(actions))
}

// MARK: - Security properties (RFC 9293 §3.10.7.4, RFC 5961)

@Test func aSegmentOutsideTheReceiveWindowIsAckedNotAccepted() {
    // RFC 9293 §3.10.7.4: an unacceptable segment gets an ACK carrying the
    // expected next sequence, and is otherwise dropped. Accepting it would let
    // a peer inject data anywhere in the stream.
    var tcb = establishedTCB(rcvNxt: 1000, rcvWnd: 100)
    let actions = stateMachineReceive(segment: segment(sequence: 5000, payload: 4), on: &tcb)
    #expect(actions.contains { if case .sendAck = $0 { return true }; return false })
    #expect(!actions.contains { if case .deliver = $0 { return true }; return false })
    #expect(tcb.rcvNxt == SequenceNumber(1000), "rcvNxt must not move for a rejected segment")
}

@Test func aResetIsIgnoredUnlessItIsInWindow() {
    // RFC 5961: a blind off-window RST must not tear down the connection, or
    // any peer that can guess the four-tuple can kill it.
    var tcb = establishedTCB(rcvNxt: 1000, rcvWnd: 100)
    let offWindowActions = stateMachineReceive(segment: segment(sequence: 50_000, flags: [.rst]), on: &tcb)
    #expect(tcb.state == .established, "an off-window RST must not close the connection")
    // The state-only assertion above cannot by itself distinguish "silently
    // discarded" from "in window but not an exact RCV.NXT match, so
    // challenged with an ACK instead of reset" (RFC 5961 §3.2's own
    // distinction) -- both leave state unchanged for a sequence number this
    // far outside the window, which is nowhere near RCV.NXT either way.
    // Asserting the returned action is what actually pins the in-window
    // guard down: without it, deleting that guard still leaves this test
    // green (it would just start returning a challenge ACK instead of
    // nothing), which is exactly the kind of falsification that passes for
    // the wrong reason.
    #expect(offWindowActions == [.none], "an off-window RST must be silently discarded, not challenged")

    _ = stateMachineReceive(segment: segment(sequence: 1000, flags: [.rst]), on: &tcb)
    #expect(tcb.state == .closed)
}

@Test func aSynInAnEstablishedConnectionDoesNotResetIt() {
    // A challenge ACK is sent instead -- RFC 5961 §4.
    var tcb = establishedTCB(rcvNxt: 1000, rcvWnd: 100)
    let actions = stateMachineReceive(segment: segment(sequence: 1000, flags: [.syn]), on: &tcb)
    #expect(tcb.state == .established)
    #expect(actions.contains { if case .sendAck = $0 { return true }; return false })
}

@Test func anAckForDataNeverSentIsRejected() {
    // RFC 9293 §3.10.7.4: ACK beyond SND.NXT is unacceptable. Honouring it
    // would advance sndUna past data that was never transmitted.
    var tcb = establishedTCB(sndUna: 100, sndNxt: 200)
    _ = stateMachineReceive(segment: segment(sequence: 1000, ack: 5000, flags: [.ack]), on: &tcb)
    #expect(tcb.sndUna == SequenceNumber(100))
}

@Test func aHalfSpaceAckIsRejectedWhenNothingIsInFlight() {
    // The negated-ordering hole, at the one site where it was live. With
    // nothing in flight (SND.UNA == SND.NXT, the ordinary state of an idle
    // connection) the acceptable-ACK window is empty, so every ACK but
    // SND.UNA itself must be refused. The old shape tested the two bounds as
    // a pair of negated `lessThan`s, and `lessThan` answers `false` at
    // exactly 2^31 apart -- so both negations answered `true` and the guest's
    // chosen value was the one value waved through, dragging SND.UNA half the
    // sequence space forward, past data that was never sent. That is the
    // property `anAckForDataNeverSentIsRejected` above exists to hold, and it
    // held everywhere except at the value a hostile peer can compute directly.
    var tcb = establishedTCB(sndUna: 100, sndNxt: 100, rcvNxt: 1000, rcvWnd: 100)
    let hostile = SequenceNumber(100 &+ 0x8000_0000)
    let actions = stateMachineReceive(segment: segment(sequence: 1000, ack: hostile.value, flags: [.ack]), on: &tcb)
    #expect(tcb.sndUna == SequenceNumber(100), "SND.UNA must not advance to a guest-chosen half-space ACK")
    #expect(tcb.sndWl2 == SequenceNumber(100), "nor may the rejected ACK be recorded as a window update")
    #expect(actions == [.sendAck], "an ACK beyond SND.NXT is answered with an ACK and dropped")
}

@Test func anInvertedSendWindowRejectsEveryAckRatherThanAdmittingABand() {
    // The degenerate case: a TCB whose SND.NXT precedes SND.UNA describes a
    // range that cannot contain anything -- more acknowledged than was ever
    // sent. No correct path builds one, but an earlier bug advancing one
    // variable without the other would, and the shape being replaced did not
    // fail closed there: it admitted a whole 100-value band (verified by
    // sweeping all 2^32 acknowledgements against both shapes), because its
    // upper bound was a negated `lessThan` whose undefined point sits inside
    // the inverted range. Accepting turns one upstream bug into an
    // accept-anything hole exactly when the state is already known bad, so
    // the predicate rejects instead.
    //
    // At this site -- unlike the ESTABLISHED one above -- the half-space
    // value alone is NOT admitted, because the positive lower bound
    // (SND.UNA < SEG.ACK) already excludes it. The inverted span is what
    // separates the two shapes here.
    var tcb = TCB(
        state: .synReceived,
        sndUna: SequenceNumber(3000),
        sndNxt: SequenceNumber(2900),  // precedes sndUna: an impossible TCB
        sndWnd: 4096,
        sndWl1: SequenceNumber(8000),
        sndWl2: SequenceNumber(3000),
        iss: SequenceNumber(3000),
        rcvNxt: SequenceNumber(8001),
        rcvWnd: 4096,
        irs: SequenceNumber(8000))
    let hostile = SequenceNumber(2900 &+ 0x8000_0000)  // inside the band the old shape admitted
    let actions = stateMachineReceive(segment: segment(sequence: 8001, ack: hostile.value, flags: [.ack]), on: &tcb)
    #expect(tcb.state == .synReceived, "an impossible TCB must not be talked into ESTABLISHED")
    #expect(tcb.sndUna == SequenceNumber(3000))
    #expect(actions == [.sendRst(sequence: hostile, ack: nil)])
}

@Test func aSynSentTcbWhoseSynConsumedNoSequenceNumberAcceptsNoAck() {
    // A fourth site with the same defect, which a grep for `!` does not
    // find: SYN-SENT spelled its negation structurally, computing
    // `ackTooOld`/`ackTooNew` from positive `lessThan`s and accepting when
    // neither held. That is the same negated accept guard in disguise, and
    // it has the same hole -- verified by sweeping all 2^32 acknowledgements
    // against both shapes.
    //
    // Here the acceptable window is ISS < SEG.ACK =< SND.NXT, so a TCB whose
    // SND.NXT was never advanced past ISS (the SYN's own sequence number
    // never reserved) describes an empty window and must accept nothing. The
    // old shape accepted ISS + 2^31 and adopted it as SND.UNA.
    var tcb = TCB(
        state: .synSent,
        sndUna: SequenceNumber(2000),
        sndNxt: SequenceNumber(2000),  // never advanced past iss
        sndWnd: 0,
        sndWl1: SequenceNumber(0),
        sndWl2: SequenceNumber(0),
        iss: SequenceNumber(2000),
        rcvNxt: SequenceNumber(0),
        rcvWnd: 4096,
        irs: SequenceNumber(0))
    let hostile = SequenceNumber(2000 &+ 0x8000_0000)
    let actions = stateMachineReceive(segment: segment(sequence: 9000, ack: hostile.value, flags: [.syn, .ack]), on: &tcb)
    #expect(tcb.state == .synSent, "an empty acceptable-ACK window must accept nothing")
    #expect(tcb.sndUna == SequenceNumber(2000), "and must not adopt the guest's number as SND.UNA")
    #expect(actions == [.sendRst(sequence: hostile, ack: nil)])
}

@Test func aHalfSpaceAckIsNotAcceptedAsAWindowUpdate() {
    // RFC 9293 §3.10.7.4's window-update test is "SND.WL1 < SEG.SEQ, or
    // SND.WL1 == SEG.SEQ and SND.WL2 =< SEG.ACK". Written as
    // `!ack.lessThan(sndWl2)` its second half admitted SND.WL2 + 2^31, so an
    // acknowledgement that is not in fact at or after SND.WL2 could install
    // a window. Least severe of the three -- a stale window update rather
    // than corrupted send state -- and, once the ESTABLISHED hole above is
    // closed, only reachable by a TCB whose SND.WL2 sits 2^31 from an
    // otherwise-valid ACK, which a live connection would take 2 GiB to
    // reach. It is fixed anyway: it is the same defect, and leaving one
    // behind teaches the next reader the wrong pattern.
    var tcb = establishedTCB(sndUna: 100, sndNxt: 200, rcvNxt: 1000, rcvWnd: 100)
    tcb.sndWnd = 1
    tcb.sndWl1 = SequenceNumber(1000)
    tcb.sndWl2 = SequenceNumber(150 &+ 0x8000_0000)
    _ = stateMachineReceive(segment: segment(sequence: 1000, ack: 150, flags: [.ack], window: 65535), on: &tcb)
    #expect(tcb.sndUna == SequenceNumber(150), "the ACK itself is perfectly acceptable and does advance SND.UNA")
    #expect(tcb.sndWnd == 1, "but it is not at or after SND.WL2, so it must not install a window")
    #expect(tcb.sndWl2 == SequenceNumber(150 &+ 0x8000_0000), "and must not be recorded as the last window update")
}

@Test func anOrdinaryWindowUpdateIsStillAccepted() {
    // The other half of every range test: too strict breaks the connection
    // just as thoroughly as too loose, and nothing else in this suite
    // exercises the window-update path at all. Without this, the three
    // rejection tests above would all be satisfied by a predicate that
    // simply never accepts anything.
    var tcb = establishedTCB(sndUna: 100, sndNxt: 200, rcvNxt: 1000, rcvWnd: 100)
    tcb.sndWnd = 1
    tcb.sndWl1 = SequenceNumber(1000)
    tcb.sndWl2 = SequenceNumber(100)
    _ = stateMachineReceive(segment: segment(sequence: 1000, ack: 150, flags: [.ack], window: 65535), on: &tcb)
    #expect(tcb.sndUna == SequenceNumber(150))
    #expect(tcb.sndWnd == 65535)
    #expect(tcb.sndWl1 == SequenceNumber(1000))
    #expect(tcb.sndWl2 == SequenceNumber(150))
}

@Test func aDuplicateAckOfExactlySndUnaStillCarriesAWindowUpdate() {
    // SEG.ACK == SND.UNA is inside RFC 9293's acceptable-ACK window even
    // though it advances nothing: it is how a sender learns the peer has
    // reopened a window it had closed. The ESTABLISHED range test is
    // therefore inclusive at the low end, and this is what says so -- an
    // exclusive bound would leave a sender stuck against a zero window
    // forever, which no other test in this suite would notice.
    var tcb = establishedTCB(sndUna: 100, sndNxt: 200, rcvNxt: 1000, rcvWnd: 100)
    tcb.sndWnd = 0
    tcb.sndWl1 = SequenceNumber(1000)
    tcb.sndWl2 = SequenceNumber(100)
    _ = stateMachineReceive(segment: segment(sequence: 1000, ack: 100, flags: [.ack], window: 65535), on: &tcb)
    #expect(tcb.sndUna == SequenceNumber(100))
    #expect(tcb.sndWnd == 65535, "a zero window must be reopenable by a duplicate ACK")
}

@Test func aSynToAClosedPortIsRefusedWithARstCarryingAnAck() {
    // RFC 9293 §3.10.7.1: a segment arriving in CLOSED with the ACK bit off
    // must be answered with <SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>. The
    // ACK bit and its value are load-bearing, not decoration: the peer has
    // no other way to validate a reset carrying sequence zero, so a RST with
    // the ACK bit clear -- or with an off-by-one acknowledgement -- is one
    // the peer is required to discard, and a guest blocked in connect() then
    // sees a hang where it should see "connection refused". Task 15's vector
    // suite codifies this exact exchange as `0.100 > R. 0:0(0) ack 1`.
    var tcb = establishedTCB()
    tcb.state = .closed
    let actions = stateMachineReceive(segment: segment(sequence: 5000, flags: [.syn]), on: &tcb)
    // SEG.LEN counts the SYN, so a bare SYN at 5000 is acknowledged with 5001.
    #expect(actions == [.sendRst(sequence: SequenceNumber(0), ack: SequenceNumber(5001))])

    // A bare SYN is the case that matters, but SEG.LEN is payload + SYN +
    // FIN, and getting the payload term wrong is the same class of bug.
    var withData = tcb
    let dataActions = stateMachineReceive(segment: segment(sequence: 5000, flags: [.syn], payload: 7), on: &withData)
    #expect(dataActions == [.sendRst(sequence: SequenceNumber(0), ack: SequenceNumber(5008))])

    // The ACK-on case is the other RFC form -- <SEQ=SEG.ACK><CTL=RST>, ACK
    // bit clear -- and must NOT gain an acknowledgement. Without this, "the
    // action can carry an ack" could be satisfied by always setting one.
    var acked = tcb
    let ackedActions = stateMachineReceive(segment: segment(sequence: 5000, ack: 77, flags: [.ack]), on: &acked)
    #expect(ackedActions == [.sendRst(sequence: SequenceNumber(77), ack: nil)])
}

@Test func aHalfSpaceAcknowledgementFromTheGuestIsHandledNotTrapped() {
    // Every lessThan in TCPStateMachine compares an attacker-controlled wire
    // field against a TCB value, and we hand the peer our ISS in the
    // SYN-ACK. So a guest can compute iss + 2^31 and send it back as its
    // ACK, landing both operands exactly half the sequence space apart --
    // the one point RFC 1982 leaves undefined -- on any connection it
    // chooses, first try. That path must be *handled*: an assert there is an
    // assert on peer behaviour, and in a debug build (which is what `swift
    // test` and most CI runs are) it hands a sandboxed guest a one-segment
    // abort of the stack that sandboxes it.
    //
    // Random fuzzing would never find this: one exact value out of 2^32 is
    // not reachable by chance.
    var tcb = synReceivedTCB(iss: 3000, irs: 8000)
    let hostile = SequenceNumber(3000 &+ 0x8000_0000)  // iss + 2^31, wrapping
    let actions = stateMachineReceive(segment: segment(sequence: 8001, ack: hostile.value, flags: [.ack]), on: &tcb)
    // Reaching this line at all is most of the point -- a trap would have
    // taken the process down before it.
    #expect(tcb.sndUna == SequenceNumber(3000), "a half-space ACK must not retire our SYN")
    #expect(tcb.state == .synReceived, "nor complete the handshake")
    #expect(actions == [.sendRst(sequence: hostile, ack: nil)], "it is an unacceptable ACK, so it is reset")
}

// MARK: - TIME-WAIT (RFC 9293 §3.10.7.4)

@Test func aBareAckInTimeWaitDoesNotRestartTheTwoMslTimer() {
    // The threat `ReceiveOutcome.finReached` was made edge-triggered to close,
    // open by another route. Any acceptable segment with a plausible ACK -- an
    // empty one will do, costing the sender nothing -- used to return
    // `.startTimeWait`, under a comment claiming that "only a retransmission of
    // the remote's already-processed FIN reaches here". It does not: a FIN
    // retransmission sits one behind the window and is unacceptable, so it
    // never reached that branch at all, while bare ACKs reached it every time.
    // A peer could hold the block open indefinitely.
    var tcb = timeWaitTCB(sndUna: 100, rcvNxt: 1000, rcvWnd: 100)
    for attempt in 1...3 {
        let actions = stateMachineReceive(segment: segment(sequence: 1000, ack: 100, flags: [.ack]), on: &tcb)
        #expect(!containsStartTimeWait(actions), "bare ACK \(attempt) restarted the 2*MSL timer")
        #expect(containsSendAck(actions), "it is still acknowledged -- refusing the timer is not refusing the segment")
        #expect(tcb.state == .timeWait)
    }

    // A FIN elsewhere in the sequence space is no better than a bare ACK: it is
    // not the FIN this connection processed, so it earns no timer either.
    let forged = stateMachineReceive(segment: segment(sequence: 1500, ack: 100, flags: [.fin, .ack]), on: &tcb)
    #expect(!containsStartTimeWait(forged), "a FIN that is not the one already processed must not refresh TIME-WAIT")
}

@Test func aRetransmittedFinInTimeWaitDoesRestartTheTwoMslTimer() {
    // The positive control, and the half RFC 9293 §3.10.7.4 actually asks for:
    // "the only thing that can arrive in this state is a retransmission of the
    // remote FIN. Acknowledge it, and restart the 2 MSL timeout." Without this,
    // the test above is satisfied by never restarting the timer at all -- which
    // would drop a peer whose final ACK was lost back into a fresh connection
    // attempt against a block that had already gone away.
    //
    // The peer's FIN occupied `rcvNxt - 1`, which is one behind the receive
    // window, so this segment is deliberately an *unacceptable* one: that is
    // the only shape a FIN retransmission can have here, and recognising it is
    // the whole of the fix.
    var tcb = timeWaitTCB(sndUna: 100, rcvNxt: 1000, rcvWnd: 100)
    let actions = stateMachineReceive(segment: segment(sequence: 999, ack: 100, flags: [.fin, .ack]), on: &tcb)
    #expect(containsStartTimeWait(actions), "a retransmission of the peer's FIN must restart the 2*MSL timer")
    #expect(containsSendAck(actions), "and be re-acknowledged, since our last ACK evidently did not arrive")
    #expect(tcb.state == .timeWait, "TIME-WAIT is not left by a FIN retransmission")
    #expect(tcb.rcvNxt == SequenceNumber(1000), "and RCV.NXT does not move a second time over a FIN already crossed")
}

@Test func ecnBitsOnASynAreTreatedAsAPlainSyn() {
    // TCPFlags deliberately does not name CWR/ECE (see its doc comment),
    // but TCPHeader.parse carries all eight raw wire bits through into
    // TCPFlags.rawValue regardless. A dispatch that compared
    // `flags == [.syn]` would silently miss any ECN-capable SYN -- and
    // Linux sends ECN-setup SYNs (ECE + CWR set) by default in several
    // configurations. The state machine must use `.contains(.syn)`, which
    // ignores the unnamed bits, so an ECN-setup SYN is still just a SYN.
    var tcb = listenTCB(iss: 1000)
    let ece: UInt8 = 1 << 6
    let cwr: UInt8 = 1 << 7
    let ecnSetupSyn = TCPFlags(rawValue: TCPFlags.syn.rawValue | ece | cwr)
    let actions = stateMachineReceive(segment: segment(sequence: 5000, flags: ecnSetupSyn), on: &tcb)
    #expect(tcb.state == .synReceived)
    #expect(containsSendSynAck(actions))
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
/// A fresh `ChallengeACKBudget` per call, and for the same reason again. Every
/// test in this file that asserts a challenge ACK — the blind reset, the SYN on
/// a synchronized connection, the unacceptable segment — would otherwise start
/// failing once the file accumulated more than a hundred of them between clock
/// advances, which is a coupling between unrelated tests and not a property of
/// the machine. The throttle is asserted where it is observable, in
/// `TCPEndpointTests`' challenge-ACK section, against real emitted frames.
private func receiveDrivingASender(segment: TCPSegment, on tcb: inout TCB, receiver: inout Receiver) -> [TCPAction] {
    var sender = Sender(
        congestionControl: Reno(maximumSegmentSize: 1460), clock: ManualClock(), maximumBufferedBytes: 64 * 1024)
    var challengeACKs = ChallengeACKBudget(clock: ManualClock())
    return TCPStateMachine.receive(
        segment: segment, on: &tcb, receiver: &receiver, sender: &sender, challengeACKs: &challengeACKs)
}

// MARK: - RFC 7323 Window Scale negotiation

// Every connection this stack opens today records **zero** in both directions,
// because `TCPEndpoint.windowScaleToOffer` is nil and RFC 7323 §2.2 scales
// nothing unless both sides sent the option. So these tests drive the rule with
// an offer supplied by the fixture rather than by the endpoint, and they assert
// the rule rather than the live values.
//
// That matters because the obvious version of this section is vacuous: state it
// as "the peer offered and we did not, both zero" four times over and a `TCB`
// that records nothing at all passes every one. Three of the eight tests below
// are positive controls that such a TCB fails — the two that negotiate a real
// pair in each direction of open, and the ignore-outside-the-handshake test,
// which negotiates 9/5 first and then requires them to *survive* rather than
// requiring zero to stay zero. `peerOfferedWindowScale` carries two more: it is
// true in the "peer offered, we did not" case, where every shift is zero.

@Test func aPassiveOpenRecordsBothWindowScalesWhenBothSidesSendTheOption() {
    var tcb = listenTCB(iss: 1000, windowScaleToOffer: 5)
    let actions = stateMachineReceive(
        segment: segment(sequence: 5000, flags: [.syn], options: windowScaleOptionFromTheWire(shift: 9)), on: &tcb)
    #expect(tcb.state == .synReceived)
    #expect(containsSendSynAck(actions))

    // Both shifts, asserted distinctly, and deliberately different numbers. 9
    // is the PEER's and applies to SND.WND; 5 is OURS and applies to the window
    // we advertise. RFC 7323 negotiates the two directions independently, and a
    // test that offered the same shift on both sides could not see an
    // implementation that swapped them.
    #expect(tcb.sndWindScale == 9)
    #expect(tcb.rcvWindScale == 5)
    #expect(tcb.peerOfferedWindowScale)
}

@Test func anActiveOpenRecordsBothWindowScalesFromTheSynAck() {
    var tcb = synSentTCB(iss: 2000, windowScaleToOffer: 5)
    let actions = stateMachineReceive(
        segment: segment(
            sequence: 9000, ack: 2001, flags: [.syn, .ack], options: windowScaleOptionFromTheWire(shift: 9)),
        on: &tcb)
    #expect(tcb.state == .established)
    #expect(containsSendAck(actions))
    #expect(tcb.sndWindScale == 9)
    #expect(tcb.rcvWindScale == 5)
    #expect(tcb.peerOfferedWindowScale)
}

@Test func aSimultaneousOpenRecordsBothWindowScalesFromThePeersOwnSyn() {
    // The other way out of SYN-SENT: the peer's bare SYN arrives before it has
    // acknowledged ours. Both sides have already sent their option by then, so
    // the negotiation runs ahead of the branch that tells the two apart.
    var tcb = synSentTCB(iss: 2000, windowScaleToOffer: 5)
    let actions = stateMachineReceive(
        segment: segment(sequence: 9000, flags: [.syn], options: windowScaleOptionFromTheWire(shift: 9)), on: &tcb)
    #expect(tcb.state == .synReceived)
    #expect(containsSendSynAck(actions))
    #expect(tcb.sndWindScale == 9)
    #expect(tcb.rcvWindScale == 5)
}

@Test func aPeerWindowScaleWeDoNotAnswerIsAppliedInNeitherDirection() {
    // The half an implementation gets wrong. The peer's shift is right there in
    // the SYN and it is tempting to record it *because we received it*, but RFC
    // 7323 §2.2 makes the option an offer both sides must take up: "both sides
    // MUST send Window Scale options in their <SYN> segments to enable window
    // scaling in either direction." A peer that offers one and gets no reply
    // does not scale, so a stack that recorded 9 here would left-shift a window
    // the peer never right-shifted and believe SND.WND to be 512 times what the
    // peer actually offered.
    var tcb = listenTCB(iss: 1000, windowScaleToOffer: nil)
    _ = stateMachineReceive(
        segment: segment(sequence: 5000, flags: [.syn], options: windowScaleOptionFromTheWire(shift: 9)), on: &tcb)
    #expect(tcb.state == .synReceived)
    #expect(tcb.sndWindScale == 0)
    #expect(tcb.rcvWindScale == 0)

    // The offer itself is still recorded, and this assertion is why this test
    // is not one more restatement that zero is zero: a TCB that recorded
    // nothing at all fails it. RFC 7323 §2.2 makes the option's presence in our
    // SYN-ACK conditional on its presence in this SYN -- "If a Window Scale
    // option was received in the initial <SYN> segment, then this option MAY be
    // sent in the <SYN,ACK> segment" -- and this arriving SYN is the only moment
    // that fact is observable.
    #expect(tcb.peerOfferedWindowScale)
}

@Test func aWindowScaleWeOfferAloneIsAppliedInNeitherDirection() {
    // The mirror of the case above, and the one that governs an active open
    // whose SYN-ACK comes back without the option.
    var tcb = listenTCB(iss: 1000, windowScaleToOffer: 5)
    _ = stateMachineReceive(segment: segment(sequence: 5000, flags: [.syn]), on: &tcb)
    #expect(tcb.state == .synReceived)
    #expect(tcb.sndWindScale == 0)
    #expect(tcb.rcvWindScale == 0)
    #expect(!tcb.peerOfferedWindowScale)
}

@Test func aHandshakeWithNoWindowScaleOnEitherSideScalesNeitherDirection() {
    // The shape of every connection this stack currently opens.
    var tcb = listenTCB(iss: 1000)
    _ = stateMachineReceive(segment: segment(sequence: 5000, flags: [.syn]), on: &tcb)
    #expect(tcb.state == .synReceived)
    #expect(tcb.sndWindScale == 0)
    #expect(tcb.rcvWindScale == 0)
    #expect(!tcb.peerOfferedWindowScale)
}

@Test func aWindowScaleOutsideTheHandshakeIsIgnored() {
    // RFC 7323 §2.2: "A Window Scale option in a segment without a SYN bit MUST
    // be ignored."
    //
    // Negotiated first, so this asserts that the recorded shifts SURVIVE rather
    // than that zero stays zero. "Capture it from the first segment that
    // carried one" is a plausible implementation, and it would overwrite 9 with
    // 2 here — a renegotiation channel open to anyone who can guess the
    // four-tuple, which is exactly what the SYN-bit restriction closes. A TCB
    // that recorded nothing would never have had 9 to lose, so this fails
    // against that too.
    var tcb = listenTCB(iss: 1000, windowScaleToOffer: 5)
    _ = stateMachineReceive(
        segment: segment(sequence: 5000, flags: [.syn], options: windowScaleOptionFromTheWire(shift: 9)), on: &tcb)
    _ = stateMachineReceive(segment: segment(sequence: 5001, ack: 1001, flags: [.ack]), on: &tcb)
    #expect(tcb.state == .established)

    _ = stateMachineReceive(
        segment: segment(
            sequence: 5001, ack: 1001, flags: [.ack], payload: 4, options: windowScaleOptionFromTheWire(shift: 2)),
        on: &tcb)
    #expect(tcb.sndWindScale == 9)
    #expect(tcb.rcvWindScale == 5)
}

@Test func aSynOnASynchronizedConnectionDoesNotRenegotiateTheWindowScale() {
    // The SYN-bearing case the rule above does not cover: RFC 5961 §4's SYN on
    // an already-synchronized connection, which draws a challenge ACK and is
    // dropped. It carries a SYN bit, so "ignore the option unless the segment
    // has a SYN" is not on its own enough — the negotiation has to be tied to
    // the handshake, not to the flag.
    var tcb = listenTCB(iss: 1000, windowScaleToOffer: 5)
    _ = stateMachineReceive(
        segment: segment(sequence: 5000, flags: [.syn], options: windowScaleOptionFromTheWire(shift: 9)), on: &tcb)
    _ = stateMachineReceive(segment: segment(sequence: 5001, ack: 1001, flags: [.ack]), on: &tcb)
    #expect(tcb.state == .established)

    let actions = stateMachineReceive(
        segment: segment(sequence: 5001, flags: [.syn], options: windowScaleOptionFromTheWire(shift: 2)), on: &tcb)
    #expect(containsSendAck(actions), "RFC 5961 §4 challenges it rather than accepting it")
    #expect(tcb.state == .established)
    #expect(tcb.sndWindScale == 9)
    #expect(tcb.rcvWindScale == 5)
}

@Test func aPeerWindowScaleOfFourteenIsRecordedAndFifteenArrivesAlreadyClampedToIt() {
    // The seam with `TCPOptionCodec`'s clamp. `TCB` re-checks nothing — it
    // records whatever shift reaches it — so this pair is what says the bound
    // is still where RFC 7323 §2.3 puts it. If either fails, the clamp moved,
    // and the defect is there rather than here.
    //
    // Both offer shift 0 on our side, which is a real offer and not the absence
    // of one: RFC 7323 §2.2 calls shift.cnt = 0 "offering to scale, while
    // applying a scale factor of 1". That is why `peerOfferedWindowScale` is
    // stored separately from the shifts — a recorded 0 cannot tell "offered
    // zero" from "offered nothing", and the option we may put in a SYN-ACK
    // depends on the difference.
    var atTheBound = listenTCB(iss: 1000, windowScaleToOffer: 0)
    _ = stateMachineReceive(
        segment: segment(sequence: 5000, flags: [.syn], options: windowScaleOptionFromTheWire(shift: 14)),
        on: &atTheBound)
    #expect(atTheBound.sndWindScale == 14)
    #expect(atTheBound.rcvWindScale == 0)
    #expect(atTheBound.peerOfferedWindowScale)

    var beyondIt = listenTCB(iss: 1000, windowScaleToOffer: 0)
    _ = stateMachineReceive(
        segment: segment(sequence: 5000, flags: [.syn], options: windowScaleOptionFromTheWire(shift: 15)),
        on: &beyondIt)
    #expect(beyondIt.sndWindScale == 14, "15 must have arrived clamped; the clamp is TCPOptionCodec's")
}

// MARK: - RFC 7323 Window Scale: applying Snd.Wind.Shift to SND.WND

// RFC 7323 §2.3: "The window field (SEG.WND) in the header of every incoming
// segment, with the exception of <SYN> segments, MUST be left-shifted by
// Snd.Wind.Shift bits before updating SND.WND: SND.WND = SEG.WND <<
// Snd.Wind.Shift."
//
// `TCPStateMachine` decodes the peer's window at FOUR sites and the exception
// splits them two and two. The two reached only by a non-SYN segment (the ACK
// that completes a passive handshake, and every later window update) shift; the
// two that read the window out of a SYN or a SYN-ACK never do, because §2.2
// forbids the peer from having scaled it: "The window field in a segment where
// the SYN bit is set (i.e., a <SYN> or <SYN,ACK>) MUST NOT be scaled."
//
// Every connection this stack opens today negotiates a shift of zero, because
// `TCPEndpoint.windowScaleToOffer` is nil and §2.2 scales nothing unless both
// sides sent the option, so `<< 0` is the identity and none of this moves the
// wire yet. These tests therefore negotiate a real shift through the fixture's
// `windowScaleToOffer`, as the negotiation tests above do, rather than asserting
// against the zero every live connection carries -- which would be satisfied by
// a stack that shifts nothing and equally by one that shifts everything.

/// Drives a passive open to ESTABLISHED with a genuinely negotiated shift, and
/// returns the TCB with SND.WND set from the window in the ACK that completed
/// the handshake -- the SYN-RECEIVED decode site.
///
/// `peerShift` is the peer's, and it is the one that reaches SND.WND;
/// `windowScaleToOffer: 5` is ours and must not, which is what makes a stack
/// that shifted by `rcvWindScale` visible here. Both are supplied through the
/// constructor rather than written to `TCB` directly: the shifts are
/// `private(set)` and negotiating them is the only way a connection ever
/// acquires one.
private func passiveOpenCompleted(peerShift: UInt8, ourShift: UInt8 = 5, windowInTheFinalAck: UInt16) -> TCB {
    var tcb = listenTCB(iss: 1000, windowScaleToOffer: ourShift)
    _ = stateMachineReceive(
        segment: segment(
            sequence: 5000, flags: [.syn], window: 4096, options: windowScaleOptionFromTheWire(shift: peerShift)),
        on: &tcb)
    _ = stateMachineReceive(
        segment: segment(sequence: 5001, ack: 1001, flags: [.ack], window: windowInTheFinalAck), on: &tcb)
    return tcb
}

@Test func theWindowThatCompletesAPassiveHandshakeIsLeftShiftedByTheNegotiatedScale() {
    // RFC 9293 §3.10.7.4's SYN-RECEIVED arm sets SND.WND <- SEG.WND, and RFC
    // 7323 §2.3 is what SEG.WND means once a shift has been negotiated. Nothing
    // carrying a SYN can reach this line -- step 3 above it challenges and
    // returns for any segment with the SYN bit -- so §2.3's <SYN> exception does
    // not cover it.
    let tcb = passiveOpenCompleted(peerShift: 7, windowInTheFinalAck: 65535)
    #expect(tcb.state == .established)
    #expect(tcb.sndWindScale == 7)
    #expect(tcb.sndWnd == 8_388_480, "65535 << 7")

    // And the shift applied is the PEER's, not ours. Asserted here rather than
    // left to the two numbers being different: 65535 << 5 is 2,097,120, so a
    // stack that reached for `rcvWindScale` would be caught by the line above
    // too, but only by accident of the fixture.
    #expect(tcb.rcvWindScale == 5)
}

@Test func aWindowUpdateOnAnEstablishedConnectionIsLeftShiftedByTheNegotiatedScale() {
    // The decode that carries every window update for the life of the
    // connection. `Sender.segmentsToTransmit` commits to `min(cwnd, sndWnd)` in
    // bytes, so an unshifted update under-uses the path by up to 2^14.
    var tcb = passiveOpenCompleted(peerShift: 7, windowInTheFinalAck: 65535)
    #expect(tcb.sndWnd == 8_388_480)

    // A second, later window from the same peer: RFC 9293's SND.WL1/SND.WL2
    // test admits it (same SEG.SEQ, SEG.ACK at SND.WL2), and it must arrive
    // shifted too -- a stack that shifted only the handshake's window would
    // pass the test above and freeze at 8,388,480 here.
    _ = stateMachineReceive(segment: segment(sequence: 5001, ack: 1001, flags: [.ack], window: 32768), on: &tcb)
    #expect(tcb.sndWnd == 4_194_304, "32768 << 7")
}

@Test func aNegotiatedScaleOfFourteenLeftShiftsThePeersWindowToJustUnderTwoToTheThirty() {
    // The top of the range `TCPOptionCodec.maximumWindowScale` allows, and the
    // reason this arithmetic is safe. **This test depends on that clamp** and
    // does no bound of its own: 14 is what keeps the largest SND.WND this line
    // can produce at 65535 << 14 = 1,073,725,440, just under 2^30. RFC 7323
    // §2.3 derives that bound from serial-number comparison -- "two times the
    // maximum window size must be less than 2^31, or max window < 2^30" -- and
    // `SequenceNumber` and every `isInRange` built on it are what would stop
    // meaning anything if the clamp moved. Nothing here can overflow an `Int`;
    // that is a consequence of the clamp, not an independent fact.
    let tcb = passiveOpenCompleted(peerShift: 14, windowInTheFinalAck: 65535)
    #expect(tcb.sndWindScale == 14)
    #expect(tcb.sndWnd == 1_073_725_440, "65535 << 14, the largest SND.WND the clamp permits")
    #expect(tcb.sndWnd < 1 << 30)
}

@Test func aNegotiatedScaleOfZeroLeavesThePeersWindowExactlyAsItArrived() {
    // The positive control, and the test that gives the three above their
    // meaning: a stack that shifts nothing satisfies nothing above it, but a
    // stack that shifts *everything* -- by a constant, by `rcvWindScale`, by
    // anything not the negotiated `sndWindScale` -- satisfies them all and
    // fails here.
    //
    // Shift 0 on both sides is a real offer, not the absence of one: RFC 7323
    // §2.2 calls shift.cnt = 0 "offering to scale, while applying a scale factor
    // of 1 to the receive window". So the option is on the wire and the
    // negotiation ran; what it negotiated is the identity.
    var tcb = passiveOpenCompleted(peerShift: 0, ourShift: 0, windowInTheFinalAck: 65535)
    #expect(tcb.sndWindScale == 0)
    #expect(tcb.sndWnd == 65535)

    _ = stateMachineReceive(segment: segment(sequence: 5001, ack: 1001, flags: [.ack], window: 4096), on: &tcb)
    #expect(tcb.sndWnd == 4096)
}

@Test func theWindowInASynAckIsNotScaledEvenThoughThatSynAckNegotiatedAScale() {
    // RFC 7323 §2.2: "The window field in a segment where the SYN bit is set
    // (i.e., a <SYN> or <SYN,ACK>) MUST NOT be scaled." The peer chose this
    // window before it knew whether scaling had been agreed at all, so shifting
    // it would multiply the peer's OPENING window by up to 2^14 -- SND.WND of a
    // gigabyte where the peer offered 64 KiB -- and this stack would transmit
    // into a buffer that size on the first write after every active open.
    //
    // The scale is negotiated by this very segment, so the shift is available at
    // the line that must not use it. That is what makes this a defect a reader
    // can walk into and why it needs a test rather than a comment.
    var tcb = synSentTCB(iss: 2000, windowScaleToOffer: 5)
    let actions = stateMachineReceive(
        segment: segment(
            sequence: 9000, ack: 2001, flags: [.syn, .ack], window: 65535,
            options: windowScaleOptionFromTheWire(shift: 7)),
        on: &tcb)
    #expect(tcb.state == .established)
    #expect(containsSendAck(actions))
    #expect(tcb.sndWindScale == 7, "the scale IS negotiated here -- it is simply not applied to this window")
    #expect(tcb.sndWnd == 65535, "not 8,388,480")
}

@Test func theWindowInASimultaneousOpensSynIsNotScaledEitherRfc7323() {
    // The second SYN-bearing decode: out of SYN-SENT by the other route, where
    // the peer's bare SYN arrives before it has acknowledged ours. Same rule,
    // and §2.2 names this case first -- "a <SYN> or <SYN,ACK>".
    var tcb = synSentTCB(iss: 2000, windowScaleToOffer: 5)
    let actions = stateMachineReceive(
        segment: segment(sequence: 9000, flags: [.syn], window: 65535, options: windowScaleOptionFromTheWire(shift: 7)),
        on: &tcb)
    #expect(tcb.state == .synReceived)
    #expect(containsSendSynAck(actions))
    #expect(tcb.sndWindScale == 7)
    #expect(tcb.sndWnd == 65535, "not 8,388,480")
}

@Test func theFirstWindowUpdateAfterAnActiveOpenIsShiftedThoughTheSynAckWasNot() {
    // The two halves against each other, in the order a real active open runs
    // them: the SYN-ACK's 65535 is 65535, and the very next segment's 65535 is
    // 8,388,480. A stack that shifted uniformly and one that shifted nowhere
    // each fail exactly one of these two assertions.
    var tcb = synSentTCB(iss: 2000, windowScaleToOffer: 5)
    _ = stateMachineReceive(
        segment: segment(
            sequence: 9000, ack: 2001, flags: [.syn, .ack], window: 65535,
            options: windowScaleOptionFromTheWire(shift: 7)),
        on: &tcb)
    #expect(tcb.sndWnd == 65535)

    _ = stateMachineReceive(segment: segment(sequence: 9001, ack: 2001, flags: [.ack], window: 65535), on: &tcb)
    #expect(tcb.state == .established)
    #expect(tcb.sndWnd == 8_388_480, "65535 << 7, the same 65535 that was left alone in the SYN-ACK")
}

// MARK: - RFC 7323 §3 Timestamps negotiation

@Test func timestampsAreInUseOnlyWhenBothSidesSentTheOption() {
    // The same rule as the window scale, and it is stated separately because
    // the two are negotiated from the same segment and it would be easy to make
    // one depend on the other. They are independent: a peer may offer both,
    // either, or neither, and each is settled on its own.
    var both = TCB(
        state: .listen, sndUna: SequenceNumber(0), sndNxt: SequenceNumber(0), sndWnd: 0,
        sndWl1: SequenceNumber(0), sndWl2: SequenceNumber(0), iss: SequenceNumber(1000),
        rcvNxt: SequenceNumber(0), rcvWnd: 65535, irs: SequenceNumber(0), offersTimestamps: true)
    both.negotiateTimestamps(fromSynOptions: [.timestamps(value: 4242, echo: 0)])
    #expect(both.timestampsEnabled)
    #expect(both.tsRecent == 4242, "TS.Recent is seeded from the SYN that negotiated it")
    #expect(both.hasTSRecent)

    // The peer offered and we did not.
    var weDeclined = TCB(
        state: .listen, sndUna: SequenceNumber(0), sndNxt: SequenceNumber(0), sndWnd: 0,
        sndWl1: SequenceNumber(0), sndWl2: SequenceNumber(0), iss: SequenceNumber(1000),
        rcvNxt: SequenceNumber(0), rcvWnd: 65535, irs: SequenceNumber(0), offersTimestamps: false)
    weDeclined.negotiateTimestamps(fromSynOptions: [.timestamps(value: 4242, echo: 0)])
    #expect(!weDeclined.timestampsEnabled)
    #expect(!weDeclined.hasTSRecent, "nothing may be echoed, so nothing is recorded")

    // We offered and the peer did not.
    var peerDeclined = TCB(
        state: .listen, sndUna: SequenceNumber(0), sndNxt: SequenceNumber(0), sndWnd: 0,
        sndWl1: SequenceNumber(0), sndWl2: SequenceNumber(0), iss: SequenceNumber(1000),
        rcvNxt: SequenceNumber(0), rcvWnd: 65535, irs: SequenceNumber(0), offersTimestamps: true)
    peerDeclined.negotiateTimestamps(fromSynOptions: [.maximumSegmentSize(1460)])
    #expect(!peerDeclined.timestampsEnabled)
}

@Test func aTimestampOfZeroIsAnOfferAndNotAnAbsence() {
    // Zero is a legal TSval — a peer whose clock starts there sends it — so
    // `tsRecent == 0` cannot mean "no timestamp yet". `hasTSRecent` is what
    // distinguishes them, and without it a first echo would be indistinguishable
    // from never having heard from the peer. The same trap
    // `peerOfferedWindowScale` exists for, one option over.
    var tcb = TCB(
        state: .listen, sndUna: SequenceNumber(0), sndNxt: SequenceNumber(0), sndWnd: 0,
        sndWl1: SequenceNumber(0), sndWl2: SequenceNumber(0), iss: SequenceNumber(1000),
        rcvNxt: SequenceNumber(0), rcvWnd: 65535, irs: SequenceNumber(0), offersTimestamps: true)
    tcb.negotiateTimestamps(fromSynOptions: [.timestamps(value: 0, echo: 0)])
    #expect(tcb.timestampsEnabled)
    #expect(tcb.tsRecent == 0)
    #expect(tcb.hasTSRecent, "a zero timestamp was still a timestamp")
}

// MARK: - RFC 7323 §4.3 TS.Recent

private func timestampTCB(rcvNxt: UInt32 = 1000, tsRecent: UInt32, lastAckSent: UInt32) -> TCB {
    var tcb = TCB(
        state: .listen, sndUna: SequenceNumber(0), sndNxt: SequenceNumber(0), sndWnd: 0,
        sndWl1: SequenceNumber(0), sndWl2: SequenceNumber(0), iss: SequenceNumber(1000),
        rcvNxt: SequenceNumber(rcvNxt), rcvWnd: 65535, irs: SequenceNumber(0), offersTimestamps: true)
    tcb.negotiateTimestamps(fromSynOptions: [.timestamps(value: tsRecent, echo: 0)])
    tcb.recordAckSent(SequenceNumber(lastAckSent))
    return tcb
}

private func timestampedSegment(sequence: UInt32, tsval: UInt32) -> TCPHeader {
    segment(sequence: sequence, flags: [.ack], options: [.timestamps(value: tsval, echo: 0)]).header
}

@Test func tsRecentAdvancesOnlyForASegmentAtOrBelowTheLastAcknowledgementSent() {
    var tcb = timestampTCB(tsRecent: 100, lastAckSent: 1000)

    // At Last.ACK.sent: adopted.
    tcb.updateTSRecent(from: timestampedSegment(sequence: 1000, tsval: 200))
    #expect(tcb.tsRecent == 200)

    // Beyond it: refused, even though the timestamp is newer. A peer must not
    // drive TS.Recent forward with data we have not acknowledged in sequence.
    tcb.updateTSRecent(from: timestampedSegment(sequence: 5000, tsval: 300))
    #expect(tcb.tsRecent == 200, "a segment past Last.ACK.sent must not touch TS.Recent")
}

@Test func tsRecentNeverMovesBackwards() {
    // The half PAWS is built on. An older timestamp adopted here would let a
    // replayed segment make itself look current to every later check.
    var tcb = timestampTCB(tsRecent: 500, lastAckSent: 1000)
    tcb.updateTSRecent(from: timestampedSegment(sequence: 900, tsval: 400))
    #expect(tcb.tsRecent == 500, "an older timestamp must not replace TS.Recent")

    // Positive control: a newer one on the same segment shape is adopted, so
    // the refusal above is about the value and not about the segment.
    tcb.updateTSRecent(from: timestampedSegment(sequence: 900, tsval: 600))
    #expect(tcb.tsRecent == 600)
}

@Test func aTimestampClockThatWrapsDoesNotFreezeTsRecent() {
    // Serial arithmetic, not integer order. A timestamp clock wraps at 2^32,
    // and `>=` on UInt32 would read every value after the wrap as a step
    // backwards — freezing TS.Recent permanently and, once PAWS reads it,
    // discarding every subsequent segment on the connection.
    var tcb = timestampTCB(tsRecent: UInt32.max - 10, lastAckSent: 1000)
    tcb.updateTSRecent(from: timestampedSegment(sequence: 900, tsval: 5))
    #expect(tcb.tsRecent == 5, "a wrapped timestamp is newer, not older")
}

@Test func tsRecentIsUntouchedWhenTimestampsWereNotNegotiated() {
    var tcb = TCB(
        state: .listen, sndUna: SequenceNumber(0), sndNxt: SequenceNumber(0), sndWnd: 0,
        sndWl1: SequenceNumber(0), sndWl2: SequenceNumber(0), iss: SequenceNumber(1000),
        rcvNxt: SequenceNumber(1000), rcvWnd: 65535, irs: SequenceNumber(0), offersTimestamps: false)
    tcb.negotiateTimestamps(fromSynOptions: [.timestamps(value: 100, echo: 0)])
    tcb.recordAckSent(SequenceNumber(1000))
    tcb.updateTSRecent(from: timestampedSegment(sequence: 900, tsval: 999))
    #expect(!tcb.timestampsEnabled)
    #expect(tcb.tsRecent == 0, "a connection not using timestamps records none")
}
