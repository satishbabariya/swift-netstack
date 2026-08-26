/// A TCP sequence number: 32 bits that wrap.
///
/// Comparison is RFC 1982 serial arithmetic, not integer order — `a` precedes
/// `b` when the forward distance from `a` to `b` is less than half the space.
/// Using plain `UInt32` comparison instead is correct for every test that does
/// not cross the wrap, which is why it survives so easily.
public struct SequenceNumber: Hashable, Sendable, CustomStringConvertible {
    public let value: UInt32

    public init(_ value: UInt32) { self.value = value }

    public static func + (lhs: SequenceNumber, rhs: Int) -> SequenceNumber {
        SequenceNumber(lhs.value &+ UInt32(truncatingIfNeeded: rhs))
    }

    /// Forward distance from `rhs` to `lhs`, signed.
    public static func - (lhs: SequenceNumber, rhs: SequenceNumber) -> Int {
        Int(Int32(bitPattern: lhs.value &- rhs.value))
    }

    public func lessThan(_ other: SequenceNumber) -> Bool {
        Int32(bitPattern: value &- other.value) < 0
    }

    /// Half-open: `[start, start + size)`. A zero size contains nothing.
    public func inWindow(start: SequenceNumber, size: Int) -> Bool {
        guard size > 0 else { return false }
        let offset = self - start
        return offset >= 0 && offset < size
    }

    public var description: String { String(value) }
}

extension SequenceNumber: Comparable {
    /// Provided for sorting within a single window only. Across a full wrap
    /// there is no total order, so this delegates to `lessThan` and callers
    /// must not rely on transitivity over distances beyond 2^31.
    public static func < (lhs: SequenceNumber, rhs: SequenceNumber) -> Bool { lhs.lessThan(rhs) }
}
