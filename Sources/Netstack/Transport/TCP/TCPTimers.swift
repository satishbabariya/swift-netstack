import NIOCore

/// The two timers one TCP connection owns: retransmission and TIME_WAIT.
///
/// Both are one-shot `Scheduled<Void>` tasks rather than NIO `RepeatedTask`s.
/// That is deliberate. Plan 1's `Stack` maintenance timer was a `RepeatedTask`
/// and it leaked, in two distinct ways, and both failure modes apply here per
/// *connection* rather than once per stack:
///
/// 1. A scheduled task lives on the event loop's own queue, which retains the
///    closure independently of every external reference. Dropping the owner
///    does not stop it; only `cancel()` does. So `deinit` cancels — see the
///    note on `deinit` for why that is load-bearing here and not merely tidy.
/// 2. `Stack.start()` could be called twice, and the second call overwrote the
///    handle to a still-live task, orphaning it beyond any possibility of
///    cancellation. So every scheduling entry point here cancels what is
///    already there **before** it overwrites the handle.
///
/// Loop-confined like everything else in this package: no locks, and time
/// comes from the injected `NetstackClock`, never `NIODeadline.now()`.
public final class TCPTimers {
    private let eventLoop: EventLoop
    private let clock: NetstackClock

    /// 2·MSL. Conventionally 60 seconds, which is also gVisor's default.
    ///
    /// Injected rather than hardcoded for two reasons: the differential
    /// harness needs it stated rather than buried, and a test that had to
    /// wait 60 real seconds is a test nobody runs.
    public let timeWaitDuration: TimeAmount

    private var retransmitTask: Scheduled<Void>?
    private var timeWaitTask: Scheduled<Void>?

    public init(eventLoop: EventLoop, clock: NetstackClock, timeWaitDuration: TimeAmount = .seconds(60)) {
        self.eventLoop = eventLoop
        self.clock = clock
        self.timeWaitDuration = timeWaitDuration
    }

    /// Whether a retransmission is pending: true from `scheduleRetransmit`
    /// until the body fires, or until a cancellation, whichever comes first.
    public var hasRetransmitScheduled: Bool { retransmitTask != nil }

    /// Arm the retransmission timer `delay` from *the clock's* now.
    ///
    /// Re-arming is the normal case — every RTO backoff does it — so this
    /// cancels any pending retransmission first. Assigning over the handle
    /// without cancelling would leave the previous task on the loop's queue,
    /// unreachable and therefore uncancellable, and both bodies would run.
    public func scheduleRetransmit(after delay: TimeAmount, _ body: @escaping () -> Void) {
        retransmitTask?.cancel()
        retransmitTask = nil
        retransmitTask = schedule(at: clock.now() + delay) { [weak self] in
            // Clear the handle *before* running the body: the body's whole
            // job is usually to re-arm this same timer, and clearing
            // afterwards would silently drop the new handle it installed.
            self?.retransmitTask = nil
            body()
        }
    }

    public func cancelRetransmit() {
        retransmitTask?.cancel()
        retransmitTask = nil
    }

    /// Arm TIME_WAIT for `timeWaitDuration` from *the clock's* now.
    public func startTimeWait(_ body: @escaping () -> Void) {
        timeWaitTask?.cancel()
        timeWaitTask = nil
        timeWaitTask = schedule(at: clock.now() + timeWaitDuration) { [weak self] in
            self?.timeWaitTask = nil
            body()
        }
    }

    public func cancelAll() {
        cancelRetransmit()
        timeWaitTask?.cancel()
        timeWaitTask = nil
    }

    /// `[weak self]` in the two closures above keeps the loop's queue from
    /// retaining this object, so dropping a connection deallocates its timers
    /// and this `deinit` runs at all. What the `deinit` then buys is separate
    /// and is the reason the weak capture is not enough on its own: the
    /// queued closure also retains `body`, and `body` is the caller's — for a
    /// TCP connection it captures the TCB, the retransmission queue and the
    /// egress path. Without this cancel all of that stays alive on the loop's
    /// queue until the deadline, and then *runs*, driving a connection that no
    /// longer exists.
    ///
    /// Note deliberately that the closures do **not** `guard let self else
    /// { return }` around `body()`. Doing so would make a broken `deinit`
    /// unobservable — the body would silently not run either way, while the
    /// captured state still leaked until the deadline. Leaving `body()`
    /// unconditional makes this cancellation the only thing standing between
    /// a dropped connection and a timer firing into it, which is what
    /// `TCPTimerTests` asserts.
    ///
    /// A bare `cancel()` is safe from `deinit`: it takes no promise, captures
    /// no `self`, and does not require being on the event loop, so it cannot
    /// deadlock the way awaiting a cancellation promise would.
    deinit {
        cancelAll()
    }

    private func schedule(at deadline: NIODeadline, _ work: @escaping () -> Void) -> Scheduled<Void> {
        // `EventLoop.scheduleTask` wants a `@Sendable` closure; `work` closes
        // over a caller-supplied body and a weak `self`, neither of which is
        // `Sendable`. `TimerBody` earns that one crossing the same way
        // `Stack`'s `ShutdownBox` does — see its comment.
        let body = TimerBody(run: work)
        return eventLoop.scheduleTask(deadline: deadline) { body.run() }
    }
}

/// A `Sendable` carrier for one timer body, used only to get a loop-confined
/// closure past `EventLoop.scheduleTask`'s `@Sendable` requirement.
///
/// `@unchecked`, and safe for the same reason every other loop-confined
/// access in this package is safe without a lock: the wrapped closure is
/// only ever invoked from the body of the task the event loop itself runs,
/// on that loop's own thread. `private`, so nothing outside `TCPTimers` can
/// use it to launder a closure anywhere else.
private struct TimerBody: @unchecked Sendable {
    let run: () -> Void
}
