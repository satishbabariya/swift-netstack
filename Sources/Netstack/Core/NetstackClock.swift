import NIOConcurrencyHelpers
import NIOCore

/// The stack's only source of time.
///
/// Nothing in `Sources/Netstack` calls `NIODeadline.now()` directly. Every
/// timer reads its clock, so a test can freeze time and a retransmission
/// suite becomes deterministic instead of a race against the CI machine.
public protocol NetstackClock: Sendable {
    func now() -> NIODeadline
}

public struct RealClock: NetstackClock {
    public init() {}
    public func now() -> NIODeadline { .now() }
}

/// A clock that moves only when told to.
///
/// Advance this in lockstep with an `EmbeddedEventLoop` so scheduled work and
/// timer deadlines agree on what time it is.
public final class ManualClock: NetstackClock, @unchecked Sendable {
    private let state: NIOLockedValueBox<NIODeadline>

    public init(start: NIODeadline = .uptimeNanoseconds(0)) {
        self.state = NIOLockedValueBox(start)
    }

    public func now() -> NIODeadline {
        state.withLockedValue { $0 }
    }

    public func advance(by amount: TimeAmount) {
        state.withLockedValue { $0 = $0 + amount }
    }
}
