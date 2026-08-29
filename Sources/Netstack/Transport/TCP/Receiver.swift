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

    /// Whether the acknowledgement may be delayed, or must go out at once.
    ///
    /// RFC 9293 §3.8.6.3 permits delaying an acknowledgement "for a period of
    /// time" — at most 500 ms, and never for more than one full-sized segment in
    /// a row. Two cases must never be delayed and this flag is what distinguishes
    /// them:
    ///
    /// - **Out-of-order data.** The acknowledgement it draws is a *duplicate*
    ///   acknowledgement, and RFC 5681 §3.2's fast retransmit counts those. Delay
    ///   one and the peer's loss detection is delayed with it — the segment sits
    ///   unretransmitted until an RTO that fast retransmit exists to avoid.
    /// - **A segment that fills a gap.** The peer has been receiving duplicate
    ///   acknowledgements and is waiting to learn the hole is closed. Making it
    ///   wait 500 ms more is the worst possible moment to economise on a frame.
    let ackMayBeDelayed: Bool

    /// The window field to put on the wire, already written into the TCB.
    ///
    /// **A wire field, not RCV.WND.** With a window scale negotiated the two
    /// differ: the peer decodes this as `advertisedWindow << Rcv.Wind.Shift`,
    /// and it is that product — the real window — that `tcb.rcvWnd` records and
    /// that every sequence-number comparison measures against. `UInt16` is the
    /// header's own type and is deliberate; see `Receiver.advertisedWindow` for
    /// which way each bound rounds on the way into it.
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
    /// ## The window-scale seam, now closed
    ///
    /// `advertisedWindow` is the on-the-wire field, so it is what the peer will
    /// actually decode — not a "real" window this receiver would like to have.
    /// `TCB.rcvWindScale` records the shift *we* negotiated, and
    /// `advertisedWindow(...)` below now applies it. It is still zero on every
    /// connection this stack builds — `TCPEndpoint.windowScaleToOffer` is `nil`,
    /// and RFC 7323 §2.2 scales nothing unless both sides sent the option — so
    /// the shift is the identity in production and the arithmetic here is
    /// exercised only where a `TCB` is constructed with an offer of its own.
    /// That ordering is the point: **apply before advertising**, because
    /// advertising a scale we do not apply claims a window we cannot honour.
    ///
    /// **This is not the whole of window scaling.** RFC 7323 §2.3 negotiates a
    /// scale in each direction independently, and the peer's direction is
    /// decoded in `TCPStateMachine`, at the four sites marked "Snd.Wind.Scale"
    /// there (`tcb.sndWnd = Int(header.window)`). Exactly **two** of those four
    /// take `<< tcb.sndWindScale`: the SYN-RECEIVED and ESTABLISHED window
    /// updates in `generalSegmentArrives`. The other two read the window out of
    /// a SYN or SYN-ACK, and RFC 7323 §2.3 exempts `<SYN>` segments from the
    /// shift — the peer chose that window before it knew scaling had been
    /// agreed, so shifting it would inflate the peer's opening window by up to
    /// 2^14. (An earlier revision of this paragraph said all of them needed the
    /// shift. They do not.) One site on *this* side of the seam is still
    /// outstanding: `TCPEndpoint.advertisedWindow(of:)` builds the window field
    /// for every segment this method does not — the SYN-ACK above all — and
    /// still clamps `tcb.rcvWnd` to 65535 without shifting it. Correct while the
    /// shift is zero, and the step that starts offering a scale must fix it in
    /// the same change, or the handshake will advertise 2^S times the window the
    /// connection has.
    ///
    /// ## The clamp is on the wire value, and so is the never-retract floor
    ///
    /// The shift is **lossy**, and which way each bound rounds is not a matter
    /// of taste:
    ///
    /// - *Space we have* rounds **down**. The peer decodes `advertised <<
    ///   scale`, so a wire value rounded up promises bytes the queue cannot
    ///   hold.
    /// - *Space we already promised* rounds **up**, and this is the half that
    ///   is easy to get backwards. Plan 3 asked for the never-retract clamp to
    ///   be applied in real bytes and shifted afterwards; that is a floor
    ///   division applied to a floor already at the limit, and it hands back up
    ///   to `2^S - 1` bytes of the right edge — 16 KiB at scale 14 — every time
    ///   the floor binds. See `advertisedWindow(offered:consumed:maximum:scale:)`
    ///   for the derivation.
    ///
    /// The `UInt16` clamp needs no scaling: it is a limit on the wire field
    /// itself, and everything is already in wire units by the time it applies.
    /// A real window above `65535 << scale` is simply not expressible, which is
    /// what this constant says. RFC 7323 caps the scale at 14 — `TCPOptionCodec`
    /// enforces that on the peer's shift before `TCB` records it — but note that
    /// *our* shift reaches `TCB` as a constructor parameter that nothing bounds,
    /// so the arithmetic below is written to stay total rather than to lean on
    /// the cap: Swift's shifts on `Int` saturate to zero rather than trapping,
    /// so an out-of-contract shift yields a closed window rather than a crash.
    private static let maximumUnscaledWindow = Int(UInt16.max)

    private let reassembler: TCPReassembler

    /// What is held out of order, as RFC 2018 blocks. Asked for at the moment a
    /// segment is emitted rather than kept alongside the queue, so the report
    /// cannot describe a queue that has since changed.
    func sackBlocks(rcvNxt: SequenceNumber, limit: Int) -> [SACKBlock] {
        reassembler.sackBlocks(rcvNxt: rcvNxt, limit: limit)
    }

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
    ///
    /// It is written back **shifted left again**, in real bytes, because that
    /// is the unit every reader of the field works in: `isInReceiveWindow`,
    /// RFC 5961's RST test and the §3.9 trim all measure sequence numbers
    /// against `rcvNxt + rcvWnd`, and sequence numbers count bytes. Recording
    /// the wire field instead would narrow the connection's real window by a
    /// factor of `2^rcvWindScale` — 16384 at the maximum scale — and discard
    /// data the peer had been told it could send, which is a stall rather than
    /// a lost optimisation: the peer retransmits into a window we keep
    /// refusing. `window << rcvWindScale` is exactly what the peer decodes, so
    /// the two ends agree on the edge by construction; it is also, and not
    /// coincidentally, what makes `offered` on the *next* call a window the
    /// wire could express, which the never-retract floor below relies on.
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

        // RFC 9293 §3.8.6.3's two exceptions, decided here because this is the
        // only place that knows which of them applies.
        //
        // `consumed == 0` on a segment that occupied sequence space means it did
        // not advance RCV.NXT: it was out of order, and the acknowledgement it
        // draws is a duplicate acknowledgement that RFC 5681 §3.2's fast
        // retransmit counts. Delaying it delays the peer's loss detection.
        //
        // `delivered.count > 1` means this segment closed a gap and released
        // what was queued behind it. The peer has been collecting duplicate
        // acknowledgements and is waiting to hear the hole is filled; 500 ms is
        // the worst possible moment to save a frame.
        let outOfOrder = segment.length > 0 && consumed == 0
        let filledAGap = delivered.count > 1
        let ackMayBeDelayed = !outOfOrder && !filledAGap && !finReached

        let window = advertisedWindow(
            offered: offered, consumed: consumed, maximum: tcb.rcvWndMax, scale: tcb.rcvWindScale,
            held: tcb.heldBytes)
        tcb.rcvWnd = Int(window) << Int(tcb.rcvWindScale)

        // Every segment that occupies sequence space is acknowledged: in order,
        // to advance the peer's SND.UNA; out of order, as the duplicate ACK
        // RFC 5681 §3.2 requires and the sender's fast retransmit counts.
        // Segments that occupy none -- a bare ACK, a window update -- are not,
        // because two peers that acknowledge each other's acknowledgements
        // never stop.
        return ReceiveOutcome(
            delivered: delivered, shouldAck: segment.length > 0, ackMayBeDelayed: ackMayBeDelayed,
            advertisedWindow: window, finReached: finReached)
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
    /// where it was, and anything less than that is a retraction. (That
    /// subtraction is in real bytes; the section on the shift below is about
    /// expressing its result in a wire field that may not be able to name it
    /// exactly, and that is where the rounding has to be argued.)
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
    /// the wire's limit and wins over both, since a window above `65535 <<
    /// scale` is not expressible in the header at all (see
    /// `maximumUnscaledWindow`) and `UInt16(_:)` would trap on it.
    ///
    /// ## Where the shift goes, and which way each bound rounds
    ///
    /// `scale` is `TCB.rcvWindScale`, the shift **we** negotiated; the peer
    /// decodes `result << scale` (RFC 7323 §2.3). `sndWindScale` is the peer's
    /// shift for the peer's own window and has no business here — the two are
    /// negotiated independently and are not the same number.
    ///
    /// The two bounds are in different units before the shift and must not be
    /// rounded the same way:
    ///
    /// - **The cap** — free queue space, and the configured `rcvWndMax` — is
    ///   space we have, so it rounds **down**. `min(free, maximum) >> scale`
    ///   discards up to `2^scale - 1` bytes we could have offered. Rounding up
    ///   would advertise space that does not exist.
    ///
    /// - **The floor** — the right edge already promised — rounds **up**, and
    ///   getting this backwards is a live bug rather than an inefficiency.
    ///   Writing S for the scale, the rule is that
    ///   `RCV.NXT_new + (result << S)` may not fall below the old edge
    ///   `RCV.NXT_old + offered`, and `RCV.NXT_new` is `RCV.NXT_old +
    ///   consumed`, so the constraint is `result << S >= offered - consumed`:
    ///   a **ceiling** division, `result >= ceil((offered - consumed) / 2^S)`,
    ///   and therefore a floor on the *wire* value, not on the real one.
    ///
    ///   Plan 3 asked for the opposite — clamp in real bytes, shift afterwards
    ///   — and that is `(offered - consumed) >> S`, a floor division of a
    ///   quantity that is already the minimum permitted. It retracts the edge
    ///   by up to `2^S - 1` bytes, 16 KiB at scale 14, on every segment where
    ///   the floor binds. The receiver tests' scaled retraction sequence — the
    ///   one asserting on the edge in real bytes across three steps — is what
    ///   separates the two; nothing that watches the wire value can, because
    ///   the wire value falls legitimately while the edge holds.
    ///
    /// The ceiling division is written as `(offered >> scale) - (consumed >>
    /// scale)`, which is the same value and cannot overflow. `offered` is a
    /// window this connection previously advertised, so it is `wire << scale`
    /// for some wire value and `offered >> scale` recovers that wire value
    /// exactly; `ceil((q * 2^S - c) / 2^S)` is `q - floor(c / 2^S)`. The one
    /// call where `offered` is *not* a previous advertisement is the first,
    /// where it is the configured `rcvWnd` and may not be a whole number of
    /// `2^scale`; `>> scale` there rounds it down to the largest window the
    /// handshake could actually have put on the wire, which is the edge the
    /// peer was really given. Rounding it up instead would let the first
    /// advertisement exceed `rcvWndMax` and defeat that cap.
    private func advertisedWindow(offered: Int, consumed: Int, maximum: Int, scale: UInt8, held: Int) -> UInt16 {
        let shift = Int(scale)
        // What the reassembler can take, less what the application has not yet
        // read. Before the endpoint held anything this was the whole story and
        // the window never moved; now a connection whose reader has stopped
        // advertises less, and eventually zero, which is the entire point of
        // having a buffer at all.
        let free = max(0, reassembler.availableBytes - held)
        let floor = max(0, (offered >> shift) - (consumed >> shift))
        let ceiling = max(0, min(free, maximum)) >> shift
        return UInt16(min(max(floor, ceiling), Self.maximumUnscaledWindow))
    }
}
