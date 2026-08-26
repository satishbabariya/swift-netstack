import NIOCore
import Testing

@testable import Netstack

// MARK: - Test fixtures

/// Builds a `TCPSegment` for a given sequence/ack/flags. `payload` is a
/// byte count only (its content is never inspected by the state machine
/// except for its length and, when delivered, its identity), so it is
/// filled with zero bytes.
private func segment(sequence: UInt32, ack: UInt32 = 0, flags: TCPFlags = [], payload: Int = 0) -> TCPSegment {
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
        buffer.writeBytes([UInt8](repeating: 0, count: payload))
    }
    return TCPSegment(header: header, payload: buffer)
}

private func listenTCB(iss: UInt32 = 1000) -> TCB {
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
        irs: SequenceNumber(0))
}

private func synSentTCB(iss: UInt32 = 2000) -> TCB {
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
        irs: SequenceNumber(0))
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
    let actions = TCPStateMachine.receive(segment: segment(sequence: 5000, flags: [.syn]), on: &tcb)
    #expect(tcb.state == .synReceived)
    #expect(containsSendSynAck(actions))
    #expect(tcb.irs == SequenceNumber(5000))
    #expect(tcb.rcvNxt == SequenceNumber(5001))
}

@Test func handshakeCompletionMovesSynReceivedToEstablished() {
    var tcb = synReceivedTCB(iss: 3000, irs: 8000)
    let actions = TCPStateMachine.receive(segment: segment(sequence: 8001, ack: 3001, flags: [.ack]), on: &tcb)
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
    #expect(!containsSendFin(TCPStateMachine.close(on: &finWait1)))
    var timeWait = establishedTCB(sndUna: 100)
    timeWait.state = .timeWait
    #expect(!containsSendFin(TCPStateMachine.close(on: &timeWait)))
    var listening = listenTCB()
    let listenActions = TCPStateMachine.close(on: &listening)
    #expect(!containsSendFin(listenActions))
    #expect(containsDeleteTCB(listenActions), "closing a LISTEN just discards the block")
}

@Test func activeOpenMovesSynSentToEstablished() {
    var tcb = synSentTCB(iss: 2000)
    let actions = TCPStateMachine.receive(segment: segment(sequence: 9000, ack: 2001, flags: [.syn, .ack]), on: &tcb)
    #expect(tcb.state == .established)
    #expect(containsSendAck(actions))
    #expect(tcb.irs == SequenceNumber(9000))
}

@Test func simultaneousOpenMovesSynSentToSynReceived() {
    var tcb = synSentTCB(iss: 2000)
    let actions = TCPStateMachine.receive(segment: segment(sequence: 9000, flags: [.syn]), on: &tcb)
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
    let actions = TCPStateMachine.receive(segment: segment(sequence: 1000, ack: 100, flags: [.fin, .ack]), on: &tcb)
    #expect(tcb.state == .closeWait)
    #expect(containsSendAck(actions))
    #expect(tcb.rcvNxt == SequenceNumber(1001))
}

@Test func simultaneousCloseMovesFinWait1ToClosing() {
    var tcb = finWait1TCB(sndUna: 100, rcvNxt: 1000, rcvWnd: 100)
    // The peer's FIN acks only what we'd already sent (sndUna), not the
    // FIN we just sent ourselves -- both sides closing at once.
    let actions = TCPStateMachine.receive(segment: segment(sequence: 1000, ack: 100, flags: [.fin, .ack]), on: &tcb)
    #expect(tcb.state == .closing)
    #expect(containsSendAck(actions))
}

@Test func finWait1PlusAckMovesToFinWait2() {
    var tcb = finWait1TCB(sndUna: 100, rcvNxt: 1000, rcvWnd: 100)
    // sndNxt is sndUna+1 (our unacked FIN); acking it exactly retires it.
    _ = TCPStateMachine.receive(segment: segment(sequence: 1000, ack: 101, flags: [.ack]), on: &tcb)
    #expect(tcb.state == .finWait2)
    #expect(tcb.sndUna == SequenceNumber(101))
}

@Test func finWait2PlusFinMovesToTimeWait() {
    var tcb = finWait2TCB(sndUna: 100, rcvNxt: 1000, rcvWnd: 100)
    let actions = TCPStateMachine.receive(segment: segment(sequence: 1000, ack: 100, flags: [.fin, .ack]), on: &tcb)
    #expect(tcb.state == .timeWait)
    #expect(containsStartTimeWait(actions))
    #expect(tcb.rcvNxt == SequenceNumber(1001))
}

@Test func lastAckPlusAckMovesToClosed() {
    var tcb = lastAckTCB(sndUna: 100, rcvNxt: 1000, rcvWnd: 100)
    // sndNxt is sndUna+1 (our unacked FIN); acking it exactly retires it.
    let actions = TCPStateMachine.receive(segment: segment(sequence: 1000, ack: 101, flags: [.ack]), on: &tcb)
    #expect(tcb.state == .closed)
    #expect(containsDeleteTCB(actions))
}

@Test func inOrderDataInEstablishedIsDeliveredAndAcked() {
    var tcb = establishedTCB(sndUna: 100, sndNxt: 100, rcvNxt: 1000, rcvWnd: 100)
    let actions = TCPStateMachine.receive(segment: segment(sequence: 1000, ack: 100, flags: [.ack], payload: 10), on: &tcb)
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
    let actions = TCPStateMachine.receive(segment: segment(sequence: 5000, payload: 4), on: &tcb)
    #expect(actions.contains { if case .sendAck = $0 { return true }; return false })
    #expect(!actions.contains { if case .deliver = $0 { return true }; return false })
    #expect(tcb.rcvNxt == SequenceNumber(1000), "rcvNxt must not move for a rejected segment")
}

@Test func aResetIsIgnoredUnlessItIsInWindow() {
    // RFC 5961: a blind off-window RST must not tear down the connection, or
    // any peer that can guess the four-tuple can kill it.
    var tcb = establishedTCB(rcvNxt: 1000, rcvWnd: 100)
    let offWindowActions = TCPStateMachine.receive(segment: segment(sequence: 50_000, flags: [.rst]), on: &tcb)
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

    _ = TCPStateMachine.receive(segment: segment(sequence: 1000, flags: [.rst]), on: &tcb)
    #expect(tcb.state == .closed)
}

@Test func aSynInAnEstablishedConnectionDoesNotResetIt() {
    // A challenge ACK is sent instead -- RFC 5961 §4.
    var tcb = establishedTCB(rcvNxt: 1000, rcvWnd: 100)
    let actions = TCPStateMachine.receive(segment: segment(sequence: 1000, flags: [.syn]), on: &tcb)
    #expect(tcb.state == .established)
    #expect(actions.contains { if case .sendAck = $0 { return true }; return false })
}

@Test func anAckForDataNeverSentIsRejected() {
    // RFC 9293 §3.10.7.4: ACK beyond SND.NXT is unacceptable. Honouring it
    // would advance sndUna past data that was never transmitted.
    var tcb = establishedTCB(sndUna: 100, sndNxt: 200)
    _ = TCPStateMachine.receive(segment: segment(sequence: 1000, ack: 5000, flags: [.ack]), on: &tcb)
    #expect(tcb.sndUna == SequenceNumber(100))
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
    let actions = TCPStateMachine.receive(segment: segment(sequence: 5000, flags: [.syn]), on: &tcb)
    // SEG.LEN counts the SYN, so a bare SYN at 5000 is acknowledged with 5001.
    #expect(actions == [.sendRst(sequence: SequenceNumber(0), ack: SequenceNumber(5001))])

    // A bare SYN is the case that matters, but SEG.LEN is payload + SYN +
    // FIN, and getting the payload term wrong is the same class of bug.
    var withData = tcb
    let dataActions = TCPStateMachine.receive(segment: segment(sequence: 5000, flags: [.syn], payload: 7), on: &withData)
    #expect(dataActions == [.sendRst(sequence: SequenceNumber(0), ack: SequenceNumber(5008))])

    // The ACK-on case is the other RFC form -- <SEQ=SEG.ACK><CTL=RST>, ACK
    // bit clear -- and must NOT gain an acknowledgement. Without this, "the
    // action can carry an ack" could be satisfied by always setting one.
    var acked = tcb
    let ackedActions = TCPStateMachine.receive(segment: segment(sequence: 5000, ack: 77, flags: [.ack]), on: &acked)
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
    let actions = TCPStateMachine.receive(segment: segment(sequence: 8001, ack: hostile.value, flags: [.ack]), on: &tcb)
    // Reaching this line at all is most of the point -- a trap would have
    // taken the process down before it.
    #expect(tcb.sndUna == SequenceNumber(3000), "a half-space ACK must not retire our SYN")
    #expect(tcb.state == .synReceived, "nor complete the handshake")
    #expect(actions == [.sendRst(sequence: hostile, ack: nil)], "it is an unacceptable ACK, so it is reset")
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
    let actions = TCPStateMachine.receive(segment: segment(sequence: 5000, flags: ecnSetupSyn), on: &tcb)
    #expect(tcb.state == .synReceived)
    #expect(containsSendSynAck(actions))
}
