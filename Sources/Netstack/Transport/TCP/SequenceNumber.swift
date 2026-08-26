/// A TCP sequence number: 32 bits that wrap.
///
/// Comparison is RFC 1982 serial arithmetic, not integer order — `a` precedes
/// `b` when the forward distance from `a` to `b` is less than half the space.
/// Using plain `UInt32` comparison instead is correct for every test that does
/// not cross the wrap, which is why it survives so easily. At exactly half
/// the space (2^31 apart), RFC 1982 leaves the ordering undefined; see
/// `lessThan` for the deliberate, non-contradictory choice made here.
public struct SequenceNumber: Hashable, Sendable, CustomStringConvertible {
    public let value: UInt32

    public init(_ value: UInt32) { self.value = value }

    public static func + (lhs: SequenceNumber, rhs: Int) -> SequenceNumber {
        SequenceNumber(lhs.value &+ UInt32(truncatingIfNeeded: rhs))
    }

    /// Forward distance from `rhs` to `lhs`, signed.
    ///
    /// At exactly half the space (2^31) apart, this returns `Int32.min` in
    /// both directions rather than negatives of each other — `Int32` cannot
    /// represent +2^31, so the true distance saturates to the one
    /// representable extreme regardless of which operand is which.
    /// `lessThan` does not build its half-space decision on this operator; it
    /// special-cases that distance directly instead.
    public static func - (lhs: SequenceNumber, rhs: SequenceNumber) -> Int {
        Int(Int32(bitPattern: lhs.value &- rhs.value))
    }

    /// RFC 1982 serial "less than": `self` precedes `other` when the forward
    /// distance from `self` to `other` is less than half the space.
    ///
    /// At exactly half the space (2^31 apart), RFC 1982 leaves the ordering
    /// undefined. The literal translation of the bit-pattern trick below
    /// would report `true` in both directions, which breaks asymmetry and
    /// can cycle a `sort()`. This deliberately uses `halfSpaceOrdering()`
    /// instead — `false` in both directions, neither precedes the other —
    /// which is defined, asymmetric and safe for a sort.
    ///
    /// The half-space case is **not** a symptom of an internal bug, and must
    /// never trap. Every operand this stack compares against a TCB value is a
    /// sequence or acknowledgement number lifted straight off the wire, and
    /// we echo our own ISS to the peer in the SYN-ACK — so a hostile peer can
    /// compute `iss + 2^31` and send it back on any connection it likes, at
    /// will, on the first try. An `assertionFailure` here would therefore be
    /// asserting on *peer behaviour*, which is a category error: it hands any
    /// guest a one-segment abort of the stack that is supposed to sandbox it.
    /// RFC 1982 leaves this point undefined precisely because the number is
    /// chosen remotely; the only correct response is to define an answer and
    /// return it.
    public func lessThan(_ other: SequenceNumber) -> Bool {
        let diff = value &- other.value
        if diff == 0x8000_0000 {
            return SequenceNumber.halfSpaceOrdering()
        }
        return Int32(bitPattern: diff) < 0
    }

    /// The ordering to use at exactly half the space (2^31) apart, where RFC
    /// 1982 leaves "precedes" undefined: neither value precedes the other.
    /// That is defined and non-contradictory, whereas returning `true` in
    /// both directions (the literal translation of the bit-pattern trick in
    /// `lessThan`) would break asymmetry and let a `sort()` cycle.
    ///
    /// Kept as a named function rather than a bare `return false` so the
    /// *decision* has somewhere to be documented and somewhere to be tested
    /// on its own — flipping it to `true` would silently restore the
    /// asymmetry bug, and `theHalfSpaceOrderingHelperReturnsFalse` exists to
    /// catch exactly that edit.
    static func halfSpaceOrdering() -> Bool { false }

    // MARK: - Acceptance tests
    //
    // The three predicates below exist because **negating `lessThan` is
    // unsafe against a wire-supplied value**. `lessThan` answers `false` at
    // exactly 2^31 apart (the point RFC 1982 leaves undefined), so
    // `!a.lessThan(b)` answers `true` there — and a guard written as a
    // negated ordering therefore *admits* the one value whose ordering is
    // undefined. Since we echo our own sequence numbers to the peer, that
    // value is one a hostile peer can compute directly and send at will, so
    // "the one value that gets waved through" and "the one value an attacker
    // picks" are the same value.
    //
    // These are built on `-` instead, which is total: it is
    // `Int(Int32(bitPattern: lhs.value &- rhs.value))`, a signed forward
    // distance over `[-2^31, 2^31-1]` with no undefined case, and at exactly
    // half the space it yields `Int32.min` — *negative*, so a positive
    // forward-distance test rejects it with no special case anywhere.
    //
    // If you find yourself about to write `!x.lessThan(y)` as an accept
    // guard, use one of these instead. A *positive* `lessThan` is fine: it
    // answers `false` at the undefined point, which rejects rather than
    // admits.

    /// `low < self <= high`, measured as a forward distance from `low`.
    ///
    /// This is RFC 9293's "SND.UNA < SEG.ACK =< SND.NXT" acceptable-ACK
    /// window. Both bounds are TCB values a segment must fall between, and
    /// `self` is the wire-supplied number under test.
    public func isInRange(after low: SequenceNumber, throughAndIncluding high: SequenceNumber) -> Bool {
        SequenceNumber.isInRange(offset: self - low, span: high - low, includingLow: false)
    }

    /// `low <= self <= high`, measured as a forward distance from `low`.
    ///
    /// RFC 9293's other ACK window: a segment acknowledging exactly SND.UNA
    /// is a duplicate that advances nothing, but it still carries a window
    /// update, so the inclusive bound is load-bearing rather than cosmetic.
    public func isInRange(from low: SequenceNumber, throughAndIncluding high: SequenceNumber) -> Bool {
        SequenceNumber.isInRange(offset: self - low, span: high - low, includingLow: true)
    }

    /// `other <= self`: `self` does not precede `other`.
    ///
    /// The open-ended relation, for the one place with a lower bound and no
    /// upper one (RFC 9293's "SND.WL2 =< SEG.ACK" window-update test).
    public func isAtOrAfter(_ other: SequenceNumber) -> Bool {
        (self - other) >= 0
    }

    /// Shared core: `span` is `high - low`, `offset` is `self - low`.
    ///
    /// A **negative** `span` means `high` precedes `low` — an inverted,
    /// self-contradictory range that no correct caller can construct (in a
    /// TCB it would mean SND.NXT preceding SND.UNA, i.e. more acknowledged
    /// than was ever sent). It is reachable if some earlier bug advances one
    /// variable without the other, so it is handled rather than asserted:
    /// **reject everything**, failing closed. Admitting instead would turn
    /// one upstream bug into an accept-anything hole precisely when the
    /// state is already known to be corrupt — not hypothetical, since the
    /// negated-`lessThan` shape these predicates replace admitted a whole
    /// band of values in exactly that case. A span of exactly 2^31 also
    /// lands here: `-` saturates it to `Int32.min`, so an unrepresentably
    /// wide range fails closed too.
    ///
    /// Be aware that the `guard` below is **redundant, and deliberately kept
    /// anyway**: accepting requires `offset >= 0` and `offset <= span`,
    /// which is already unsatisfiable when `span < 0`, so deleting the guard
    /// changes no answer for any input (verified by sweeping all 2^32 values
    /// against both forms). It is here to state the intent where a reader
    /// looks for it, and to keep failing closed if the offset bounds are
    /// ever edited. Do not read it as the thing doing the work — the range
    /// arithmetic is.
    private static func isInRange(offset: Int, span: Int, includingLow: Bool) -> Bool {
        guard span >= 0 else { return false }
        return offset >= (includingLow ? 0 : 1) && offset <= span
    }

    /// Half-open: `[start, start + size)`. A zero size contains nothing.
    ///
    /// - Precondition: `size` must be less than 2^31. RFC 7323 caps the
    ///   window scale factor at 14, so a legitimate peer's advertised window
    ///   tops out around 2^30 — a `size` anywhere near 2^31 means our own
    ///   caller computed it wrongly, not that the peer sent something
    ///   exotic. This asserts the caller's mistake in debug builds rather
    ///   than clamping it, which would only hide the bug: for `size >= 2^31`
    ///   this method's arithmetic silently *rejects* sequence numbers that
    ///   are mathematically inside the window, because a forward distance of
    ///   exactly 2^31 cannot be represented as a positive signed offset (see
    ///   `-` above).
    public func inWindow(start: SequenceNumber, size: Int) -> Bool {
        assert(size < 0x8000_0000, "window size \(size) is outside the valid TCP domain (must be < 2^31)")
        guard size > 0 else { return false }
        let offset = self - start
        return offset >= 0 && offset < size
    }

    public var description: String { String(value) }
}

extension SequenceNumber: Comparable {
    /// Provided for sorting within a single window only. At exactly half the
    /// space (2^31 apart), neither value precedes the other — a deliberate,
    /// non-contradictory choice (see `lessThan`), not a consequence of RFC
    /// 1982, which leaves that point undefined. Beyond a single window,
    /// comparing values that are not close to each other is not meaningful:
    /// callers must not rely on transitivity over distances beyond 2^31.
    public static func < (lhs: SequenceNumber, rhs: SequenceNumber) -> Bool { lhs.lessThan(rhs) }
}
