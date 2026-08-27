import NIOCore

/// The eleven TCP connection states from RFC 9293 §3.3.2, Figure 5.
///
/// `.closed` is a real, representable state here (not "no TCB exists") so
/// that transitions into it (e.g. LAST-ACK + ACK -> CLOSED) are ordinary
/// switch cases in `TCPStateMachine` rather than a special-cased teardown
/// path.
enum TCPState: Equatable, Sendable {
    case closed
    case listen
    case synSent
    case synReceived
    case established
    case finWait1
    case finWait2
    case closeWait
    case closing
    case lastAck
    case timeWait
}

/// What `TCPStateMachine` wants the caller to do, having already mutated
/// the `TCB` it was given. The state machine performs no I/O itself --
/// every RFC 9293 transition that would "send a segment" instead returns
/// one of these, which is what keeps the machine a pure, directly testable
/// function of `(segment, TCB) -> (TCB, [TCPAction])`.
enum TCPAction: Equatable, Sendable {
    /// Send a SYN|ACK built from the TCB's current `iss`/`rcvNxt`.
    case sendSynAck
    /// Send a bare ACK built from the TCB's current `sndNxt`/`rcvNxt`.
    /// Covers both an ordinary "data received" ACK and an RFC 5961
    /// challenge ACK -- both are, on the wire, the same segment shape.
    case sendAck
    /// Send a RST at the given sequence number, optionally with the ACK bit
    /// set and acknowledging `ack`.
    ///
    /// RFC 9293 §3.10.7.1 specifies two distinct refusal segments, and the
    /// difference is on the wire, not cosmetic. When the offending segment
    /// carried an ACK, the reset is `<SEQ=SEG.ACK><CTL=RST>` -- the ACK bit
    /// is *clear*, because SEG.ACK already tells us the sequence number the
    /// peer is expecting. When it did not, there is no such number to reuse,
    /// so the reset is `<SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>`: sequence
    /// zero, and the ACK bit set so the peer can validate it against what it
    /// actually sent. `ack` is `nil` for the first form and carries
    /// `SEG.SEQ + SEG.LEN` for the second; a peer that receives the second
    /// form with the ACK bit clear, or with the wrong acknowledgement, is
    /// required to discard it -- which a guest waiting on `connect()`
    /// experiences as a hang rather than "connection refused".
    case sendRst(sequence: SequenceNumber, ack: SequenceNumber?)
    /// Send a FIN (with the ACK bit set, as every segment past the handshake
    /// carries) built from the TCB's current `sndNxt`/`rcvNxt`.
    ///
    /// `close(on:)` already bumps `sndNxt` to reserve the sequence number the
    /// FIN consumes, so the FIN occupies `sndNxt - 1`. Returning this action
    /// rather than leaving the sender to infer "there is an unsent FIN" from
    /// `state` and `sndNxt` keeps the send decision where every other one in
    /// this machine lives: in the returned action list.
    case sendFin
    /// Deliver received, in-order data to the application.
    case deliver(ByteBuffer)
    /// Arm (or re-arm) the 2*MSL TIME-WAIT timer.
    case startTimeWait
    /// The connection is finished; the caller should discard the TCB.
    case deleteTCB
    /// Nothing to do.
    case none
}

/// The TCP Control Block (RFC 9293 §3.3.1): the send and receive sequence
/// variables plus the current state. This struct holds no I/O handles and
/// no data buffers of its own -- it is exactly the state RFC 9293's state
/// machine reads and mutates, and nothing else.
struct TCB: Equatable, Sendable {
    var state: TCPState

    // Send Sequence Variables (RFC 9293 §3.3.1).
    /// SND.UNA: oldest unacknowledged sequence number.
    var sndUna: SequenceNumber
    /// SND.NXT: next sequence number to be sent.
    var sndNxt: SequenceNumber
    /// SND.WND: send window, as last advertised by the peer.
    var sndWnd: Int
    /// SND.WL1: segment sequence number used for the last window update.
    var sndWl1: SequenceNumber
    /// SND.WL2: segment acknowledgment number used for the last window update.
    var sndWl2: SequenceNumber
    /// ISS: initial send sequence number.
    var iss: SequenceNumber

    // Receive Sequence Variables (RFC 9293 §3.3.1).
    /// RCV.NXT: next sequence number expected on an incoming segment.
    var rcvNxt: SequenceNumber
    /// RCV.WND: receive window we have advertised to the peer.
    var rcvWnd: Int
    /// The largest receive window this connection may ever advertise: whatever
    /// `rcvWnd` was configured with when the block was created.
    ///
    /// Not an RFC 9293 §3.3.1 variable. It exists because `rcvWnd` is
    /// *overwritten* on every arriving segment with the window just advertised
    /// (see `Receiver.accept`), so the configured figure survives nowhere else
    /// — and without it a connection configured with a small window advertises
    /// whatever the reassembly queue happens to have free, which on the default
    /// queue is 65535 after a single byte. That is not merely a wider window
    /// than was asked for: `TCPStateMachine.isInReceiveWindow`, RFC 5961's
    /// RST test, measures against `rcvWnd` too, so a convenience default would
    /// otherwise widen a security test by 655x as a side effect.
    ///
    /// Derived from `rcvWnd` in the initialiser rather than taken as a separate
    /// parameter: two independently supplied figures could disagree, and the
    /// only sensible initial advertisement is the configured one.
    let rcvWndMax: Int
    /// IRS: initial receive sequence number.
    var irs: SequenceNumber

    init(
        state: TCPState,
        sndUna: SequenceNumber,
        sndNxt: SequenceNumber,
        sndWnd: Int,
        sndWl1: SequenceNumber,
        sndWl2: SequenceNumber,
        iss: SequenceNumber,
        rcvNxt: SequenceNumber,
        rcvWnd: Int,
        irs: SequenceNumber
    ) {
        self.state = state
        self.sndUna = sndUna
        self.sndNxt = sndNxt
        self.sndWnd = sndWnd
        self.sndWl1 = sndWl1
        self.sndWl2 = sndWl2
        self.iss = iss
        self.rcvNxt = rcvNxt
        self.rcvWnd = rcvWnd
        self.rcvWndMax = rcvWnd
        self.irs = irs
    }
}
