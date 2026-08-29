import NIOCore

/// Joins two TCP endpoints so that bytes arriving on one leave by the other,
/// and so that neither can be made to buffer without bound.
///
/// This is what a gateway does: the guest dials somewhere, the forwarder accepts,
/// and something has to carry the stream between the accepted connection and
/// whatever the gateway opened on the other side.
///
/// ## Backpressure is the whole design, not a feature of it
///
/// A splice is where an unbounded queue appears if nobody stops it. The guest can
/// send faster than the far side drains, and a naive implementation reads
/// everything offered and buffers whatever will not fit — which is a
/// guest-controlled allocation with a helpful name.
///
/// So this never buffers. It reads from a side only when the *other* side has
/// room, and when a write is refused it stops reading until the refusal clears.
/// Not reading is what shrinks the advertised window, which is what stops the
/// peer — the chain that `TCPEndpoint`'s receive buffer made expressible.
///
/// The alternative was measured before this existed: `onData` used to deliver
/// synchronously with no way to decline, so a splice could only drop what it
/// could not forward, having already acknowledged it.
public final class TCPSplice {
    private let a: TCPEndpoint
    private let b: TCPEndpoint
    private var closed = false

    /// Bytes taken from one side and refused by the other, waiting to be retried.
    ///
    /// At most one write's worth per direction, and it is not a queue: the point
    /// is that a refusal stops the reading, so nothing accumulates behind this.
    /// It exists because `send` is all-or-nothing — it refuses rather than
    /// truncating — so a refused write has to be held somewhere until the far
    /// side has room, and holding it here is what lets the near side stay unread.
    private var pendingAToB: ByteBuffer?
    private var pendingBToA: ByteBuffer?

    public init(_ a: TCPEndpoint, _ b: TCPEndpoint) {
        self.a = a
        self.b = b
        wire()
    }

    private func wire() {
        a.onData = { [weak self] in self?.pump(from: .a) }
        b.onData = { [weak self] in self?.pump(from: .b) }
        // Note the crossing: `a` becoming writable is what unblocks the side
        // reading from `b`. The signal is about the sink, the pump is named for
        // the source, and wiring these straight through -- which reads more
        // naturally -- makes each side retry the buffer it is not holding.
        a.onWritable = { [weak self] in self?.pump(from: .b) }
        b.onWritable = { [weak self] in self?.pump(from: .a) }
        a.onClosed = { [weak self] in self?.closeBoth() }
        b.onClosed = { [weak self] in self?.closeBoth() }
    }

    private enum Side { case a, b }

    private func pump(from side: Side) {
        guard !closed else { return }
        let source = side == .a ? a : b
        let sink = side == .a ? b : a

        // Retry whatever the sink refused last time, BEFORE reading anything new.
        // Reading first would reorder the stream, which is the one thing a splice
        // may never do.
        if let held = side == .a ? pendingAToB : pendingBToA {
            // Cleared before the retry, not after it. `write` refuses to
            // overwrite a held buffer — that check is what stops a silent drop —
            // and a retry that left the slot occupied would trip it against
            // itself. The precondition found this within one run of adding it,
            // which is the argument for having added it.
            if side == .a { pendingAToB = nil } else { pendingBToA = nil }
            guard write(held, to: sink, side: side) else { return }
        }

        // Only now take more, and only what the sink will accept. A read the sink
        // cannot take is a byte this splice would have to hold, and holding is
        // what it exists not to do.
        while true {
            let chunk = source.read(maximum: Self.chunk)
            guard chunk.readableBytes > 0 else { return }
            guard write(chunk, to: sink, side: side) else { return }
        }
    }

    /// Returns true when the whole buffer went; false when it was refused and is
    /// now held, which means the caller must stop reading.
    private func write(_ buffer: ByteBuffer, to sink: TCPEndpoint, side: Side) -> Bool {
        do {
            try sink.send(buffer)
            if side == .a { pendingAToB = nil } else { pendingBToA = nil }
            return true
        } catch {
            // `send` refuses rather than truncating, so nothing was partially
            // written and the buffer is intact. Hold it and stop: the far side's
            // acknowledgements will drain its send buffer, and the retry happens
            // on this side's next signal.
            //
            // **Overwriting a held buffer would be silent data loss**, and the
            // only thing preventing it is that every caller stops on a `false`
            // return. That is a convention, and a convention is what this project
            // has repeatedly found does not hold — so it is asserted here rather
            // than trusted.
            //
            // **It fired on the first run after being added**, which is worth
            // recording because the reasoning that preceded it was wrong. I had
            // argued this was unreachable — that the read loop's guard made a
            // second refusal in one pass impossible — and written that into the
            // comment. It was reachable immediately, by the retry above:
            // retrying a held buffer called this method with the slot still
            // occupied, so the check tripped against its own held value.
            //
            // The retry now clears the slot first. The general point stands
            // though, and is why the precondition remains: no test in this file
            // reaches a genuine double-refusal — falsifying the read loop's
            // guard leaves every splice test green, including the one written to
            // catch dropped bytes, because a drop needs two refusals inside one
            // pass and the tests never produce one. A precondition turns a silent
            // loss into a loud failure for whoever eventually does.
            let alreadyHeld = side == .a ? pendingAToB : pendingBToA
            precondition(
                alreadyHeld == nil,
                "a second write was attempted while one was still held: the caller ignored a refusal")
            if side == .a { pendingAToB = buffer } else { pendingBToA = buffer }
            return false
        }
    }

    private func closeBoth() {
        guard !closed else { return }
        closed = true
        a.close()
        b.close()
    }

    /// How much is read from a side in one go.
    ///
    /// Bounded rather than "everything available" so that one direction cannot
    /// monopolise a pass, and so the amount held on a refusal is bounded by this
    /// rather than by whatever the peer managed to send.
    private static let chunk = 32 * 1024

    /// Bytes held after a refused write, for tests. Nonzero only while the far
    /// side is full, and the assertion that it stays small is what says this is a
    /// splice and not a buffer.
    var heldForTesting: Int {
        (pendingAToB?.readableBytes ?? 0) + (pendingBToA?.readableBytes ?? 0)
    }
}
