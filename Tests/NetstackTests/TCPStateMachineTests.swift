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
    _ = actions
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
    _ = TCPStateMachine.close(on: &tcb)
    #expect(tcb.state == .finWait1)
    #expect(tcb.sndNxt == SequenceNumber(501), "our FIN consumes a sequence number")
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
