import NIOCore

/// What one segment's arrival did to the receive side of a connection.
///
/// Everything the state machine needs from the receiver is here, as a return
/// value. It is deliberately not a set of properties for the caller to go and
/// read afterwards: the state machine must not be in a position to re-derive
/// any of this, because a second derivation is a second opinion, and the two
/// disagree the moment either is edited. See `Receiver`.
public struct ReceiveOutcome: Sendable {
    /// Bytes that became contiguous with RCV.NXT, oldest first. Possibly bytes
    /// from earlier segments this one unblocked; possibly none at all. RCV.NXT
    /// has already been advanced over them.
    public let delivered: [ByteBuffer]

    /// Whether the peer is owed an acknowledgement for this segment.
    public let shouldAck: Bool

    /// RCV.WND to advertise, already written into the TCB. See
    /// `Receiver.advertisedWindow` for why this is a `UInt16` and what Task 13
    /// has to change here.
    public let advertisedWindow: UInt16

    /// True on the one call where RCV.NXT first reaches the peer's FIN, and
    /// never again. **Edge-triggered, deliberately.** A level-triggered "the
    /// FIN is in order" would be true for every subsequent segment on the
    /// connection, and the state machine's FIN handling is not idempotent: in
    /// TIME-WAIT it restarts the 2*MSL timer, so a peer could hold a TIME-WAIT
    /// block open indefinitely by sending anything at all.
    ///
    /// The edge costs no stored state. Reaching the FIN advances RCV.NXT one
    /// past it (the FIN consumes a sequence number), so the equality that
    /// produced this is false on every later call by construction.
    public let finReached: Bool

    public init(delivered: [ByteBuffer], shouldAck: Bool, advertisedWindow: UInt16, finReached: Bool) {
        self.delivered = delivered
        self.shouldAck = shouldAck
        self.advertisedWindow = advertisedWindow
        self.finReached = finReached
    }
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
/// It does not test acceptability. It must be driven only after RFC 9293
/// §3.10.7.4's checks have passed, which is why `TCPStateMachine` owns the call
/// rather than the other way round: the acceptability test is what confines a
/// peer's data to the window it was offered, and a receiver driven ahead of it
/// would queue, and eventually deliver, bytes the connection said it would not
/// accept. `TCPReassembler`'s own domain bound limits the damage but does not
/// replace that test — it admits anything within a quarter of the sequence
/// space, which is vastly wider than any window we advertise.
///
/// ## A struct wrapping a class
///
/// `reassembler` is a reference. Copying a `Receiver` therefore does **not**
/// copy the queued segments — two copies share one queue and will fight over
/// it. Hold exactly one per connection and pass it `inout`. The type is a
/// struct rather than a class only because it has no identity of its own worth
/// having; that is not a promise of value semantics.
public struct Receiver {
    /// The largest window expressible in the header's 16-bit field.
    ///
    /// ## The window-scale seam (Task 13)
    ///
    /// `advertisedWindow` is the on-the-wire field, so it is what the peer will
    /// actually decode — not a "real" window this receiver would like to have.
    /// Nothing in the stack negotiates a window scale yet: `TCPOptions` parses
    /// `.windowScale`, but no `TCB` field records a negotiated shift, so there
    /// is no scale factor available to this task and none is invented here.
    ///
    /// When Task 13 adds one, the change belongs in `advertisedWindow(...)`
    /// below and nowhere else: the value advertised becomes the real window
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

    public init(reassembler: TCPReassembler = TCPReassembler()) {
        self.reassembler = reassembler
    }

    /// Offer one segment that has already passed RFC 9293 §3.10.7.4's
    /// acceptability test.
    ///
    /// Mutates `tcb.rcvNxt` and `tcb.rcvWnd`, which no other code in this
    /// module writes.
    ///
    /// Writing `rcvWnd` back is not bookkeeping: `TCPStateMachine`'s
    /// acceptability test measures the next segment against it, so leaving it
    /// at whatever the connection was configured with would mean accepting
    /// segments against a window that was never advertised — the same two-owner
    /// problem this type exists to close, one field over. That the two stay
    /// consistent depends on the never-retract rule below: a segment the peer
    /// put in flight for space it was offered is still inside `rcvNxt + rcvWnd`
    /// when it lands, because the right edge only ever moves forward.
    public mutating func accept(_ segment: Segment, tcb: inout TCB) -> ReceiveOutcome {
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

        let window = advertisedWindow(offered: offered, consumed: consumed)
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
    /// The `UInt16` clamp is the wire's limit and takes precedence over the
    /// floor. A TCB configured with an `rcvWnd` above 65535 was never
    /// expressible in the first place, since no window scale is negotiated;
    /// see `maximumUnscaledWindow`.
    private func advertisedWindow(offered: Int, consumed: Int) -> UInt16 {
        let free = reassembler.availableBytes
        let floor = max(0, offered - consumed)
        return UInt16(min(max(free, floor), Self.maximumUnscaledWindow))
    }
}
