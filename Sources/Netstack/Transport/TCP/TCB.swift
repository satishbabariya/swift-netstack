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
    ///
    /// Which is why RFC 5961 §7's rate limit cannot live on this side of the
    /// interface: a caller holding an action list can no longer tell the two
    /// apart, and throttling here would throttle a guest's flow control along
    /// with the challenges. `TCPStateMachine` spends the budget before it
    /// forms this case; by the time one exists, it has already been paid for.
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

    // MARK: - Window scale (RFC 7323)

    /// The shift the **peer** advertised, to be applied to the window the peer
    /// sends us: `SND.WND = SEG.WND << sndWindScale` (RFC 7323 §2.3).
    ///
    /// RFC 7323 §2.3's model implementation calls this `Snd.Wind.Shift`; RFC
    /// 1323, which it obsoletes, called it `Snd.Wind.Scale`, and that is the
    /// spelling the rest of this module's comments already use. Same variable.
    ///
    /// **Zero on every connection today, and that is not the same as "unused".**
    /// See `negotiateWindowScale(fromSynOptions:)` for the ordering.
    private(set) var sndWindScale: UInt8 = 0

    /// The shift **we** advertised, to be applied to the window we send:
    /// `SEG.WND = RCV.WND >> rcvWindScale` (RFC 7323 §2.3, `Rcv.Wind.Shift`).
    ///
    /// Not the same number as `sndWindScale` and not derivable from it: RFC
    /// 7323 negotiates the two directions independently, and a peer's shift
    /// says nothing about ours.
    private(set) var rcvWindScale: UInt8 = 0

    /// Whether the peer's SYN (passive open) or SYN-ACK (active open) carried a
    /// Window Scale option at all.
    ///
    /// Not redundant with `sndWindScale != 0`, and the difference is what makes
    /// it worth storing. RFC 7323 §2.2 makes `shift.cnt = 0` a legal offer
    /// ("offering to scale, while applying a scale factor of 1"), so a recorded
    /// shift of zero is genuinely ambiguous between "the peer offered zero" and
    /// "the peer offered nothing". Applying a shift cannot tell the two apart
    /// and does not care — `<< 0` is the identity — but *emitting* the option
    /// must. RFC 7323 §2.2 authorises it in a SYN-ACK conditionally, and this is
    /// the condition: "If a Window Scale option was received in the initial
    /// `<SYN>` segment, then this option MAY be sent in the `<SYN,ACK>`
    /// segment." (Read exactly: that is a permission granted *if*, not an
    /// explicit "only if" — §2.2 spells "only if" out for Timestamps in §3.2 and
    /// does not here. It is still the condition worth checking, because it is
    /// the only clause in the document that authorises the option in a SYN-ACK
    /// at all, and §2.2's "both sides MUST send Window Scale options in their
    /// SYN segments to enable window scaling" makes one sent unprompted
    /// pointless: the peer that sent no option is not scaling either way.)
    ///
    /// Recorded at the one moment it is observable — the arriving SYN — because
    /// nothing later in the connection can reconstruct it.
    private(set) var peerOfferedWindowScale = false

    /// The shift this stack puts in its **own** SYN and SYN-ACK, or `nil` for
    /// "we send no Window Scale option at all".
    ///
    /// `nil` on every connection this stack currently creates — see
    /// `TCPEndpoint.windowScaleToOffer`, which is the single place that decides
    /// it and the single input a later task flips. It is a constructor
    /// parameter rather than a constant here so that the negotiation below can
    /// be exercised with a non-`nil` offer by a test before any connection
    /// carries one, which is the whole point of doing this first.
    ///
    /// Linux keeps the same value in the same place (`tcp_sock.request_r_scale`,
    /// the receive scale it asked for, alongside `rcv_wscale`/`snd_wscale`).
    /// RFC 7323 §2.3 names it only as "R" in the model implementation's rules
    /// and gives it no connection variable of its own.
    let windowScaleToOffer: UInt8?

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
        irs: SequenceNumber,
        windowScaleToOffer: UInt8? = nil
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
        self.windowScaleToOffer = windowScaleToOffer
    }

    /// RFC 7323's Window Scale negotiation, run **once** per connection, from
    /// the segment that carries the peer's half of the handshake: the SYN on a
    /// passive open, the SYN-ACK on an active one, the peer's SYN on a
    /// simultaneous open. `TCPStateMachine`'s LISTEN and SYN-SENT handlers are
    /// the only two callers, and that is what makes the third bullet below
    /// true.
    ///
    /// ## The rule
    ///
    /// RFC 7323 §2.3's model implementation: "Upon receiving a `<SYN>` segment
    /// with a Window Scale option containing `shift.cnt = S`, a TCP MUST set
    /// `Snd.Wind.Shift` to `S` and MUST set `Rcv.Wind.Shift` to `R`; otherwise,
    /// it MUST set both `Snd.Wind.Shift` and `Rcv.Wind.Shift` to zero", where
    /// `R` is the shift this TCP wants for its own receive window.
    ///
    /// Read on its own that rule has no case for "the peer offered and we
    /// decline to answer" — it presumes the preceding bullet, "if a TCP
    /// receives a `<SYN>` segment containing a Window Scale option, it SHOULD
    /// send its own Window Scale option in the `<SYN,ACK>` segment", has been
    /// followed, so that `R` exists. §2.2 is what settles the case where it has
    /// not: "This option is an offer, not a promise; both sides MUST send
    /// Window Scale options in their <SYN> segments to enable window scaling in
    /// either direction." A side that sends none disables scaling in **both**
    /// directions, its own and the peer's. Hence `windowScaleToOffer == nil`
    /// zeroing `sndWindScale` as well, which is the half an implementation gets
    /// wrong: the peer's shift is right there in the segment, and recording it
    /// because we received it would have us left-shift a window the peer never
    /// scaled.
    ///
    /// Three consequences worth naming, because each is a plausible
    /// implementation that is wrong:
    ///
    /// - The two shifts are **not** the same number. `sndWindScale` is the
    ///   peer's, `rcvWindScale` is ours, and RFC 7323 negotiates them
    ///   independently.
    /// - Both are zero unless **both** sides sent the option. Neither half
    ///   stands alone.
    /// - The option is meaningful only on a SYN or SYN-ACK. RFC 7323 §2.2: "A
    ///   Window Scale option in a segment without a SYN bit MUST be ignored."
    ///   Nothing calls this outside the handshake, so a Window Scale option on
    ///   a data segment, on an ACK, or on the RFC 5961 §4 SYN that arrives on
    ///   an already-synchronized connection changes nothing. "Capture it from
    ///   the first segment that carried one" would be a live renegotiation
    ///   channel for anyone who can guess the four-tuple.
    ///
    /// ## The shift arrives already bounded
    ///
    /// `TCPOptionCodec.parse` clamps a peer's `shift.cnt` to RFC 7323 §2.3's
    /// maximum of 14 before it ever reaches here (see
    /// `TCPOptionCodec.maximumWindowScale`), so this does no bound of its own
    /// and `sndWindScale` is guaranteed `<= 14`. **That guarantee is depended
    /// on here.** Anything that moves or relaxes the clamp is changing what
    /// this can record, and what tasks after this one will left-shift by.
    ///
    /// ## Why this records a shift nothing yet applies
    ///
    /// Window scaling lands in four steps and the order is not negotiable:
    /// record the negotiated shifts (this), apply `sndWindScale` to SND.WND,
    /// apply `rcvWindScale` to the window we advertise, and only then send the
    /// option ourselves. Advertising last is the whole point. A `wscale 7`
    /// alongside a 65535 window promises the peer up to 8 MB — and at 14, up to
    /// 1 GB — against a reassembler that caps at 256 KiB; the peer fills the
    /// pipe it was promised, most of it is dropped, and it presents as packet
    /// loss with no error raised anywhere.
    ///
    /// So this is inert until the last of those four steps: `windowScaleToOffer`
    /// is `nil` on every connection, so both shifts stay zero on every
    /// connection, exactly as §2.2 requires of a side that sends no option. The
    /// inertness is temporary, ordered and stated — it is not a branch waiting
    /// for a caller. The rule itself is live and directly tested with a
    /// non-`nil` offer, so that the step which starts sending the option flips
    /// one input into a rule already known to be right.
    mutating func negotiateWindowScale(fromSynOptions options: [TCPOption]) {
        var peerShift: UInt8?
        for option in options {
            // First one wins, matching `TCPEndpoint.peerSegmentSize(in:)`. A
            // segment carrying two Window Scale options is malformed either
            // way; neither this nor the MSS reader rejects the segment for it,
            // and the two agreeing about which copy to believe is worth more
            // than either choice.
            if case .windowScale(let shift) = option {
                peerShift = shift
                break
            }
        }

        peerOfferedWindowScale = peerShift != nil

        guard let peerShift, let ourShift = windowScaleToOffer else {
            sndWindScale = 0
            rcvWindScale = 0
            return
        }
        sndWindScale = peerShift
        rcvWindScale = ourShift
    }
}
