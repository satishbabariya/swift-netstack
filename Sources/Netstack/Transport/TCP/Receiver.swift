import NIOCore

/// What one segment's arrival did to the receive side of a connection.
///
/// Everything the state machine needs from the receiver is here, as a return
/// value. It is deliberately not a set of properties for the caller to go and
/// read afterwards: the state machine must not be in a position to re-derive
/// any of this, because a second derivation is a second opinion, and the two
/// disagree the moment either is edited. See `Receiver`.
struct ReceiveOutcome: Sendable {
    /// Bytes that became contiguous with RCV.NXT, oldest first. Possibly bytes
    /// from earlier segments this one unblocked; possibly none at all. RCV.NXT
    /// has already been advanced over them.
    let delivered: [ByteBuffer]

    /// Whether the peer is owed an acknowledgement for this segment.
    let shouldAck: Bool

    /// RCV.WND to advertise, already written into the TCB. See
    /// `Receiver.advertisedWindow` for why this is a `UInt16` and what Task 13
    /// has to change here.
    let advertisedWindow: UInt16

    /// True on the one call where RCV.NXT first reaches the peer's FIN, and
    /// never again. **Edge-triggered, deliberately.** A level-triggered "the
    /// FIN is in order" would be true for every subsequent segment on the
    /// connection, and the state machine reads this as *an event*: it is what
    /// drives the once-only transition out of ESTABLISHED (or FIN-WAIT-*) and
    /// what makes RFC 9293's "acknowledge the FIN" fire once rather than on
    /// every segment thereafter.
    ///
    /// This once *also* carried the 2*MSL timer: level-triggering it would have
    /// let a peer hold a TIME-WAIT block open indefinitely by sending anything
    /// at all. It no longer does, and the claim is not repeated here as though
    /// it did. The receiver is not driven in TIME-WAIT at all, so this is never
    /// true there; the 2*MSL restart is decided by `TCPStateMachine`'s own
    /// retransmitted-FIN test, which is the only thing that may restart it.
    ///
    /// **So the edge is no longer a defence, and it is worth being exact about
    /// what it still is.** Made level-triggered, the whole suite fails in
    /// exactly one place: `theFinIsReportedExactlyOnce`, which drives this type
    /// directly. No test that goes through `TCPStateMachine` can tell the two
    /// apart, and none can: every state the FIN transition leads to —
    /// CLOSE-WAIT, CLOSING, TIME-WAIT — is one where step 5 stops driving the
    /// receiver, so there is no second call in which a level would be read.
    /// It is kept because it is this type's stated contract, because it costs
    /// no stored state, and because it is what would keep the transition
    /// once-only if step 5's list of data-accepting states were ever widened —
    /// which step 6 already anticipates by keeping a `.synReceived` case it
    /// cannot currently reach. It is not kept because anything hostile depends
    /// on it, and it should not be cited as though something did.
    ///
    /// The edge costs no stored state. Reaching the FIN advances RCV.NXT one
    /// past it (the FIN consumes a sequence number), so the equality that
    /// produced this is false on every later call by construction.
    let finReached: Bool
}

/// The receive side of a TCP connection: the single owner of RCV.NXT, of what
/// is delivered to the application, and of the window advertised back.
///
/// ## Why "single owner" is the whole point
///
/// `TCPStateMachine` used to advance RCV.NXT and emit `.deliver` itself, for
/// in-order data only, while `TCPReassembler` did the same job with
/// out-of-order handling on top. Each was individually correct. Together they
/// are the defect: two components both believing they own RCV.NXT means the
/// connection's idea of what it has received depends on which path a segment
/// happened to take, and no test of either component alone can see it. Every
/// serious defect this stack has produced has had that shape.
///
/// So the split is by *kind of question*, with nothing straddling it:
///
/// - **State** — acceptability, RST handling, challenge ACKs, SND.UNA, every
///   transition including the FIN's — belongs to `TCPStateMachine`.
/// - **Bytes** — which are in order, how far RCV.NXT moves, what reaches the
///   application, what window is left — belongs here.
///
/// The FIN is the one place the two touch, and the seam there is exact: this
/// type answers *when* the FIN's sequence has been reached (`finReached`), the
/// state machine decides *what that means* for the connection's state. Neither
/// side recomputes the other's answer. If the same sequence comparison ever
/// appears in both files again, the defect is back.
///
/// ## What this type does not do
///
/// It does not test acceptability, it does not trim to the window, and it does
/// not decide whether a FIN may be honoured. It must be driven only after RFC
/// 9293 §3.10.7.4's checks have passed *and* after the segment has been trimmed
/// to the offered window, which is why `TCPStateMachine` owns the call rather
/// than the other way round.
///
/// Both halves are needed and neither is sufficient alone. The acceptability
/// test admits a segment whose *first or last* byte is in the window; it bounds
/// neither the segment's extent nor its end, so on its own it lets a peer that
/// merely starts inside a 4-byte window hand this type 5000 bytes. Trimming is
/// the half that actually confines the data (RFC 9293 §3.9), and it happens in
/// `TCPStateMachine.receiverInput(for:tcb:)` immediately after the test. Only
/// with both in place is it true that `TCPReassembler`'s own domain bound —
/// which admits anything within a quarter of the sequence space, vastly wider
/// than any window we advertise — never becomes the operative limit.
///
/// A receiver driven ahead of either would queue, and eventually deliver, bytes
/// the connection said it would not accept.
///
/// ## A struct wrapping a class
///
/// `reassembler` is a reference. Copying a `Receiver` therefore does **not**
/// copy the queued segments — two copies share one queue and will fight over
/// it. Hold exactly one per connection and pass it `inout`. The type is a
/// struct rather than a class only because it has no identity of its own worth
/// having; that is not a promise of value semantics.
struct Receiver {
    /// The largest window expressible in the header's 16-bit field.
    ///
    /// ## The window-scale seam
    ///
    /// `advertisedWindow` is the on-the-wire field, so it is what the peer will
    /// actually decode — not a "real" window this receiver would like to have.
    /// `TCB.rcvWindScale` now records the shift *we* negotiated, but it is zero
    /// on every connection — this stack sends no Window Scale option yet, and
    /// RFC 7323 §2.2 scales nothing unless both sides did — so there is still no
    /// scale factor to apply here and none is invented.
    ///
    /// When the shift is applied, the change to *this* side of the connection —
    /// the window we advertise — belongs in `advertisedWindow(...)` below and
    /// nowhere else. **That is not the whole of window scaling.** RFC 7323 §2.3
    /// negotiates a scale in each direction independently, and the peer's
    /// direction is decoded in `TCPStateMachine`, at the four sites marked
    /// "Snd.Wind.Scale" there (`tcb.sndWnd = Int(header.window)`). Exactly **two**
    /// of those four take `<< tcb.sndWindScale`: the SYN-RECEIVED and ESTABLISHED
    /// window updates in `generalSegmentArrives`. The other two read the window
    /// out of a SYN or SYN-ACK, and RFC 7323 §2.3 exempts `<SYN>` segments from
    /// the shift — the peer chose that window before it knew scaling had been
    /// agreed, so shifting it would inflate the peer's opening window by up to
    /// 2^14. (An earlier revision of this paragraph said all of them needed the
    /// shift. They do not.) The two that do matter as much as this one:
    /// `CongestionControl` already commits the send decision to
    /// `min(cwnd, sndWnd)` in bytes, so leaving them unscaled would under-use
    /// the path by up to 2^14 while this side looked perfectly correct.
    ///
    /// On this side, the value advertised becomes the real window
    /// shifted right by the negotiated scale, and the shift is **lossy** — the
    /// peer decodes `advertised << scale`, so rounding must go downwards or the
    /// connection promises space it does not have. The clamp here becomes
    /// `65535 << scale` rather than 65535. Note that this makes the granularity
    /// of a retraction check coarser too: at scale 14 the smallest expressible
    /// step is 16 KiB, so the "never move the right edge backwards" arithmetic
    /// must be done in real bytes and only then shifted, not the other way
    /// round. RFC 7323 caps the scale at 14 and nothing here may assume it can
    /// exceed that.
    private static let maximumUnscaledWindow = Int(UInt16.max)

    private let reassembler: TCPReassembler

    init(reassembler: TCPReassembler = TCPReassembler()) {
        self.reassembler = reassembler
    }

    /// Offer one segment that has already passed RFC 9293 §3.10.7.4's
    /// acceptability test and been trimmed to the offered window.
    ///
    /// Mutates `tcb.rcvNxt` and `tcb.rcvWnd`. The split with `TCPStateMachine`
    /// is by *phase*, not by field: that file **initialises** RCV.NXT from the
    /// peer's ISS during the handshake (`TCPStateMachine.swift`'s `.listen` and
    /// `.synSent` handlers), and this file **advances** it over received bytes.
    /// The two can never run for the same segment — `generalSegmentArrives`,
    /// which is the only path that reaches here, is never entered in LISTEN or
    /// SYN-SENT, and the initialising writes live nowhere else. Advancement has
    /// exactly one writer, and it is this method; that is the property worth
    /// keeping, and it is weaker than "no other code writes the field".
    ///
    /// Writing `rcvWnd` back is not bookkeeping: `TCPStateMachine`'s
    /// acceptability test measures the next segment against it, so leaving it
    /// at whatever the connection was configured with would mean accepting
    /// segments against a window that was never advertised — the same two-owner
    /// problem this type exists to close, one field over. That the two stay
    /// consistent depends on the never-retract rule below: a segment the peer
    /// put in flight for space it was offered is still inside `rcvNxt + rcvWnd`
    /// when it lands, because the right edge only ever moves forward.
    mutating func accept(_ segment: Segment, tcb: inout TCB) -> ReceiveOutcome {
        let offered = tcb.rcvWnd
        let delivered = reassembler.insert(segment, rcvNxt: tcb.rcvNxt)

        var consumed = 0
        for buffer in delivered {
            consumed += buffer.readableBytes
        }
        tcb.rcvNxt = tcb.rcvNxt + consumed

        // The FIN is in order exactly when RCV.NXT has reached the sequence
        // number it occupies. `TCPReassembler` fixes that number on admission
        // and never moves it, so this is a plain equality rather than anything
        // that needs re-deriving from the arriving segment -- and the segment
        // that reaches it is very often not the one that carried it.
        //
        // Stepping RCV.NXT one past the FIN is what makes this fire once: the
        // FIN consumes a sequence number, so the equality cannot hold again.
        var finReached = false
        if let fin = reassembler.finSequence, tcb.rcvNxt == fin {
            tcb.rcvNxt = fin + 1
            consumed += 1
            finReached = true
        }

        let window = advertisedWindow(offered: offered, consumed: consumed, maximum: tcb.rcvWndMax)
        tcb.rcvWnd = Int(window)

        // Every segment that occupies sequence space is acknowledged: in order,
        // to advance the peer's SND.UNA; out of order, as the duplicate ACK
        // RFC 5681 §3.2 requires and the sender's fast retransmit counts.
        // Segments that occupy none -- a bare ACK, a window update -- are not,
        // because two peers that acknowledge each other's acknowledgements
        // never stop.
        return ReceiveOutcome(
            delivered: delivered, shouldAck: segment.length > 0, advertisedWindow: window, finReached: finReached)
    }

    /// The window to advertise: as much of the reassembly queue as is free,
    /// but never so little that the right edge of the window moves backwards.
    ///
    /// The right edge is `RCV.NXT + RCV.WND`, and RFC 9293 §3.8.6.2.2 forbids
    /// retracting it. The peer may already have put data in flight for space it
    /// was offered; taking that space back makes the data unacceptable when it
    /// lands, and the connection stalls with each side waiting on the other.
    /// So the floor is the previously offered window less whatever RCV.NXT has
    /// just moved: shrinking by exactly what was consumed leaves the edge
    /// where it was, and anything less than that is a retraction.
    ///
    /// The consequence is that the window can only shrink while RCV.NXT is
    /// advancing. A peer that stalls the stream and then floods out-of-order
    /// segments keeps the advertised window open even as the queue fills — the
    /// advertisement is a promise already made, and it is `TCPReassembler`'s
    /// caps, not this figure, that bound what is actually retained. Those caps
    /// refuse the excess and the peer retransmits, which is the outcome RFC
    /// 9293 asks a receiver to prefer over breaking its word.
    ///
    /// `maximum` is `TCB.rcvWndMax`, the window the connection was configured
    /// with, and it is a **cap as well as a floor**. Free queue space is what
    /// the receiver *could* offer, not what it was asked to offer: with the
    /// default 256 KiB queue, a TCB configured with `rcvWnd: 100` would
    /// otherwise advertise 65535 after one 1-byte segment. That is not only a
    /// broken configuration knob — `TCPStateMachine.isInReceiveWindow`, RFC
    /// 5961's RST test, measures against the same `rcvWnd`, so the convenience
    /// default would silently widen a security test from 100 bytes to 65535,
    /// admitting a blind RST 20000 past RCV.NXT that the configured window
    /// would have discarded in silence. A security test must not be widened as
    /// a side effect of a defaulted queue size.
    ///
    /// Order matters where the two conflict. The never-retract floor wins over
    /// the cap — a promise already made to the peer cannot be withdrawn by
    /// lowering the configured window afterwards — and the `UInt16` clamp is
    /// the wire's limit and wins over both, since a `rcvWnd` above 65535 was
    /// never expressible with no window scale negotiated (see
    /// `maximumUnscaledWindow`) and `UInt16(_:)` would trap on it.
    private func advertisedWindow(offered: Int, consumed: Int, maximum: Int) -> UInt16 {
        let free = reassembler.availableBytes
        let floor = max(0, offered - consumed)
        let ceiling = max(0, min(maximum, Self.maximumUnscaledWindow))
        return UInt16(min(max(floor, min(free, ceiling)), Self.maximumUnscaledWindow))
    }
}
