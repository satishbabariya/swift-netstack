import NIOCore
import NIOEmbedded
import Testing

@testable import Netstack

// Every assertion here about something *not* happening is paired with one
// about the same thing happening, on an identically-configured timer that
// was not cancelled or dropped. That pairing is not decoration: "the body did
// not run", "the weak reference went nil" and "nothing is scheduled after
// cancel" are all satisfied perfectly by a `TCPTimers` whose every method has
// an empty body. The paired assertion is what a do-nothing implementation
// cannot satisfy, and it is the only reason these tests mean anything.

/// One `EmbeddedEventLoop` and one `ManualClock`, advanced together.
///
/// They must move in lockstep. `EmbeddedEventLoop` starts at
/// `uptimeNanoseconds(0)` and so does `ManualClock`, and `TCPTimers` computes
/// its deadlines from the clock while the loop decides what has come due from
/// its own time. Let them drift and a deadline means nothing.
private struct TimerFixture {
    let loop = EmbeddedEventLoop()
    let clock = ManualClock(start: .uptimeNanoseconds(0))

    func makeTimers(timeWaitDuration: TimeAmount = .seconds(60)) -> TCPTimers {
        TCPTimers(eventLoop: loop, clock: clock, timeWaitDuration: timeWaitDuration)
    }

    /// Move both clocks forward. `EmbeddedEventLoop.advanceTime` is what
    /// actually runs due tasks -- `run()` alone never fires anything whose
    /// deadline is still in the future.
    func advance(by amount: TimeAmount) {
        clock.advance(by: amount)
        loop.advanceTime(by: amount)
    }

    /// `EmbeddedEventLoop.deinit` traps if any scheduled task is left
    /// outstanding, which would kill the test runner before it printed a
    /// summary. Draining at the end of a test keeps a genuine assertion
    /// failure legible as an assertion failure.
    func drain() {
        advance(by: .hours(1))
    }
}

/// A counter a timer body can bump. A reference type so the escaping body and
/// the assertion afterwards are looking at the same storage.
private final class FiringCounter {
    private(set) var count = 0
    func record() { count += 1 }
}

@Test func aScheduledRetransmitFiresAtItsDeadlineAndNotOneNanosecondBefore() {
    let fixture = TimerFixture()
    let timers = fixture.makeTimers()
    let fired = FiringCounter()

    timers.scheduleRetransmit(after: .milliseconds(200)) { fired.record() }
    #expect(timers.hasRetransmitScheduled, "scheduling must actually arm something")
    #expect(fired.count == 0, "scheduling must not run the body eagerly")

    fixture.advance(by: .nanoseconds(199_999_999))
    #expect(fired.count == 0, "one nanosecond short of the deadline is still short")
    #expect(timers.hasRetransmitScheduled)

    fixture.advance(by: .nanoseconds(1))
    #expect(fired.count == 1)
    #expect(!timers.hasRetransmitScheduled, "a fired one-shot timer is no longer scheduled")

    withExtendedLifetime(timers) {}
}

@Test func cancellingARetransmitStopsTheBodyAndClearsTheScheduledFlag() {
    let fixture = TimerFixture()
    let cancelled = fixture.makeTimers()
    let kept = fixture.makeTimers()
    let cancelledFired = FiringCounter()
    let keptFired = FiringCounter()

    cancelled.scheduleRetransmit(after: .milliseconds(100)) { cancelledFired.record() }
    kept.scheduleRetransmit(after: .milliseconds(100)) { keptFired.record() }
    #expect(cancelled.hasRetransmitScheduled)
    #expect(kept.hasRetransmitScheduled)

    cancelled.cancelRetransmit()
    #expect(!cancelled.hasRetransmitScheduled)
    #expect(kept.hasRetransmitScheduled, "one connection's cancellation must not disarm another's timer")

    fixture.advance(by: .seconds(1))
    #expect(cancelledFired.count == 0)
    // Without this, "it did not fire" would also be true of a deadline the
    // test never reached, and of a body that was never wired up at all.
    #expect(keptFired.count == 1, "the deadline really did pass during that advance")

    withExtendedLifetime((cancelled, kept)) {}
}

@Test func schedulingARetransmitTwiceCancelsTheFirstSoOnlyOneBodyEverRuns() {
    // The `Stack` maintenance timer's second failure mode, per connection: a
    // re-arm that assigns over the handle instead of cancelling through it
    // leaves the first task on the loop's queue, reachable by nothing and
    // cancellable by nobody. Both bodies then run. Every RTO backoff re-arms,
    // so this is the common path, not an edge case.
    let fixture = TimerFixture()
    let timers = fixture.makeTimers()
    let first = FiringCounter()
    let second = FiringCounter()

    timers.scheduleRetransmit(after: .milliseconds(500)) { first.record() }
    timers.scheduleRetransmit(after: .milliseconds(100)) { second.record() }
    #expect(timers.hasRetransmitScheduled)

    // Past both deadlines, so an orphaned first task would have fired too.
    fixture.advance(by: .seconds(1))
    #expect(first.count == 0, "the first body must have been cancelled, not merely forgotten")
    #expect(second.count == 1)
    #expect(first.count + second.count == 1, "exactly one body ran, not merely at least one")
    #expect(!timers.hasRetransmitScheduled)

    withExtendedLifetime(timers) {}
}

@Test func timeWaitDefaultsToTwoMaximumSegmentLifetimes() {
    let fixture = TimerFixture()
    let timers = fixture.makeTimers()
    let fired = FiringCounter()

    #expect(timers.timeWaitDuration == .seconds(60), "2 * MSL, matching gVisor's default")
    timers.startTimeWait { fired.record() }

    fixture.advance(by: .milliseconds(59_999))
    #expect(fired.count == 0)

    fixture.advance(by: .milliseconds(1))
    #expect(fired.count == 1)

    withExtendedLifetime(timers) {}
}

@Test func timeWaitFiresAfterTheInjectedDurationRatherThanAHardcodedOne() {
    // The point of injecting the duration: a hardcoded 60 seconds would make
    // this pass only after a minute of real time, and the differential
    // harness needs to be able to state the value rather than infer it.
    let fixture = TimerFixture()
    let timers = fixture.makeTimers(timeWaitDuration: .milliseconds(250))
    let fired = FiringCounter()

    timers.startTimeWait { fired.record() }

    fixture.advance(by: .milliseconds(249))
    #expect(fired.count == 0, "a hardcoded duration would put the deadline somewhere else entirely")

    fixture.advance(by: .milliseconds(1))
    #expect(fired.count == 1)

    withExtendedLifetime(timers) {}
}

@Test func cancelAllStopsTheRetransmitAndTheTimeWaitTimerTogether() {
    let fixture = TimerFixture()
    let cancelled = fixture.makeTimers(timeWaitDuration: .milliseconds(300))
    let kept = fixture.makeTimers(timeWaitDuration: .milliseconds(300))
    let cancelledRetransmit = FiringCounter()
    let cancelledTimeWait = FiringCounter()
    let keptRetransmit = FiringCounter()
    let keptTimeWait = FiringCounter()

    cancelled.scheduleRetransmit(after: .milliseconds(100)) { cancelledRetransmit.record() }
    cancelled.startTimeWait { cancelledTimeWait.record() }
    kept.scheduleRetransmit(after: .milliseconds(100)) { keptRetransmit.record() }
    kept.startTimeWait { keptTimeWait.record() }
    #expect(cancelled.hasRetransmitScheduled)

    cancelled.cancelAll()
    #expect(!cancelled.hasRetransmitScheduled)

    fixture.advance(by: .seconds(1))
    #expect(cancelledRetransmit.count == 0)
    #expect(cancelledTimeWait.count == 0, "cancelAll must reach the TIME_WAIT timer too, not just the retransmit one")
    #expect(keptRetransmit.count == 1, "both deadlines really did pass during that advance")
    #expect(keptTimeWait.count == 1)

    withExtendedLifetime((cancelled, kept)) {}
}

@Test func aRetransmitCancelledAfterItsDeadlinePassesButBeforeTheLoopRunsDoesNotFire() {
    // Cancellation has to win the race against a task that is already due.
    // Moving both clocks forward first, then scheduling with a zero delay,
    // puts the deadline exactly at the loop's current time: due, queued, and
    // not yet run, because `EmbeddedEventLoop` runs nothing until it is told
    // to.
    let fixture = TimerFixture()
    fixture.advance(by: .seconds(1))

    let cancelled = fixture.makeTimers()
    let kept = fixture.makeTimers()
    let cancelledFired = FiringCounter()
    let keptFired = FiringCounter()

    cancelled.scheduleRetransmit(after: .nanoseconds(0)) { cancelledFired.record() }
    kept.scheduleRetransmit(after: .nanoseconds(0)) { keptFired.record() }
    #expect(cancelled.hasRetransmitScheduled)
    #expect(cancelledFired.count == 0, "an already-due task still must not run until the loop runs it")
    #expect(keptFired.count == 0)

    cancelled.cancelRetransmit()
    fixture.loop.run()

    #expect(cancelledFired.count == 0)
    #expect(keptFired.count == 1, "the deadline had indeed already passed -- run() fired the twin")

    withExtendedLifetime((cancelled, kept)) {}
}

@Test func droppingATCPTimersDeallocatesItEvenWithATimerStillPending() {
    // Guards the *capture*, and nothing else. If the scheduled closures held
    // `self` strongly, the loop's queue would keep this object alive until
    // its deadline no matter what `deinit` contained -- and `deinit` would
    // never run at all.
    let fixture = TimerFixture()
    var timers: TCPTimers? = fixture.makeTimers()
    weak var weakTimers = timers
    let fired = FiringCounter()

    timers!.scheduleRetransmit(after: .seconds(1)) { fired.record() }
    #expect(weakTimers != nil, "alive before we drop it -- otherwise the nil below proves nothing")
    #expect(timers!.hasRetransmitScheduled, "a task really is queued on the loop, so there is something that could have retained it")

    timers = nil
    #expect(weakTimers == nil, "the loop's queue must not retain the timers: capture self weakly")

    fixture.drain()
}

@Test func noTimerBodyRunsAfterItsTCPTimersOwnerIsDropped() {
    // Guards the *cancellation*, which the weak-reference test above does
    // not: the queued closure retains the caller's body regardless of how it
    // captured `self`, so without `cancelAll()` in `deinit` that body stays
    // on the loop's queue and then fires into a connection that no longer
    // exists.
    let fixture = TimerFixture()
    var dropped: TCPTimers? = fixture.makeTimers(timeWaitDuration: .milliseconds(500))
    let kept = fixture.makeTimers(timeWaitDuration: .milliseconds(500))
    let droppedRetransmit = FiringCounter()
    let droppedTimeWait = FiringCounter()
    let keptRetransmit = FiringCounter()
    let keptTimeWait = FiringCounter()

    dropped!.scheduleRetransmit(after: .milliseconds(500)) { droppedRetransmit.record() }
    dropped!.startTimeWait { droppedTimeWait.record() }
    kept.scheduleRetransmit(after: .milliseconds(500)) { keptRetransmit.record() }
    kept.startTimeWait { keptTimeWait.record() }
    #expect(dropped!.hasRetransmitScheduled, "something is genuinely armed at the moment we drop the owner")

    dropped = nil
    fixture.advance(by: .seconds(5))

    #expect(droppedRetransmit.count == 0, "deinit must cancel the retransmit timer")
    #expect(droppedTimeWait.count == 0, "deinit must cancel the TIME_WAIT timer")
    // The whole test is vacuous without these two: a deadline that was never
    // reached, or bodies that were never scheduled, would also "not run".
    #expect(keptRetransmit.count == 1, "an owner that is still alive does get its retransmit")
    #expect(keptTimeWait.count == 1, "an owner that is still alive does leave TIME_WAIT")

    withExtendedLifetime(kept) {}
}
