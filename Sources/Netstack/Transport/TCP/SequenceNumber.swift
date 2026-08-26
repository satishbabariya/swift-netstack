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
    /// can cycle a `sort()`. This deliberately returns `false` in both
    /// directions instead — neither precedes the other — which is defined
    /// and non-contradictory. Two live sequence numbers landing exactly 2^31
    /// apart means something has already gone wrong upstream; the
    /// `assertionFailure` surfaces that during development without trapping
    /// a release build that is meant to stay up.
    public func lessThan(_ other: SequenceNumber) -> Bool {
        let diff = value &- other.value
        if diff == 0x8000_0000 {
            assertionFailure("SequenceNumber \(value) and \(other.value) are exactly 2^31 apart; ordering between them is undefined")
            return false
        }
        return Int32(bitPattern: diff) < 0
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
