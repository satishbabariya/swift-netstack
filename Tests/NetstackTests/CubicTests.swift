import Foundation
import NIOCore
import Testing

@testable import Netstack

// RFC 9438. Reno's window grows by one segment per round trip, which on a path
// with a large bandwidth-delay product is far too slow to use what is there.
// CUBIC's window is a function of the TIME since the last congestion event
// rather than of the number of acknowledgements, so recovery takes a time that
// does not depend on the round trip.
//
// These tests check the formulas against the RFC's own arithmetic. That is
// weaker evidence than the differential harness -- which compares Reno against
// gVisor frame for frame and does not cover CUBIC, for the reason `Cubic`'s own
// comment gives -- and saying so is part of the record.

private let cubicMSS = 1000
private let start = NIODeadline.uptimeNanoseconds(0)

private func after(_ milliseconds: Int64) -> NIODeadline {
    .uptimeNanoseconds(UInt64(milliseconds) * 1_000_000)
}

/// Run `rounds` round trips of acknowledgements, a full window each.
///
/// CUBIC's window TRACKS the curve through acknowledgements rather than being
/// set to it: each one moves the window by `(target - cwnd) / cwnd`, which is a
/// fraction of a segment. So a test that advances the clock and delivers one
/// acknowledgement sees almost nothing move, however far the curve has gone --
/// which is how three assertions here first came to compare a number with
/// itself. The window only reaches the curve if a window's worth of
/// acknowledgements arrives per round trip, which is what a real connection
/// does and what this does.
@discardableResult
private func run(_ cubic: inout Cubic, rounds: Int, roundTrip: Int64 = 100, from: Int64 = 0) -> Int64 {
    var clock = from
    for _ in 0..<rounds {
        clock += roundTrip
        let perRound = max(1, cubic.congestionWindow / cubicMSS)
        for _ in 0..<perRound {
            cubic.acked(
                bytes: cubicMSS, flightSize: cubic.congestionWindow, now: after(clock),
                smoothedRoundTrip: .milliseconds(roundTrip))
        }
    }
    return clock
}

/// Drive `cubic` to congestion avoidance with a known `W_max`, then return it
/// positioned at the congestion event.
private func afterLoss(window segments: Int) -> Cubic {
    var cubic = Cubic(maximumSegmentSize: cubicMSS)
    // Grow through slow start to the wanted window, then take a loss there.
    while cubic.congestionWindow < segments * cubicMSS {
        cubic.acked(
            bytes: cubicMSS, flightSize: cubic.congestionWindow, now: start,
            smoothedRoundTrip: .milliseconds(100))
    }
    cubic.lossDetectedWithScoreboard(flightSize: cubic.congestionWindow)
    return cubic
}

@Test func theInitialWindowIsTenSegments() {
    // The same as Reno's here, so switching algorithms does not silently change
    // the first flight of every connection — which is the one thing a change of
    // congestion control should not do.
    let cubic = Cubic(maximumSegmentSize: cubicMSS)
    #expect(cubic.congestionWindow == 10 * cubicMSS)
}

@Test func slowStartIsUnchangedFromReno() {
    // RFC 9438 §4.1 leaves slow start to RFC 5681. An algorithm that changed it
    // would be changing the part of TCP that is not the problem.
    var cubic = Cubic(maximumSegmentSize: cubicMSS)
    var reno = Reno(maximumSegmentSize: cubicMSS)
    for _ in 0..<5 {
        cubic.acked(
            bytes: cubicMSS, flightSize: cubic.congestionWindow, now: start,
            smoothedRoundTrip: .milliseconds(100))
        reno.acked(
            bytes: cubicMSS, flightSize: reno.congestionWindow, now: start,
            smoothedRoundTrip: .milliseconds(100))
    }
    #expect(cubic.congestionWindow == reno.congestionWindow)
}

@Test func aLossReducesTheWindowByTheCubicFactorRatherThanByHalf() {
    // β = 0.7, not Reno's 0.5. The gentler decrease is half of why CUBIC
    // recovers faster; a test that only checked "the window went down" would
    // pass against Reno.
    var cubic = afterLoss(window: 100)
    #expect(cubic.slowStartThreshold == 70 * cubicMSS)
    #expect(cubic.congestionWindow == 70 * cubicMSS, "a scoreboard loss must not inflate the window")

    var inflating = afterLoss(window: 100)
    inflating.lossDetected(flightSize: 100 * cubicMSS)
    #expect(
        inflating.congestionWindow > inflating.slowStartThreshold,
        "RFC 5681 §3.2's three-segment inflation is missing from the duplicate-ACK path")
}

@Test func theWindowClimbsBackTowardsWhereItWasAndThenPastIt() {
    // The shape of the curve, which is the whole feature: concave up to `W_max`,
    // then convex beyond it. Checked at three points rather than one, because a
    // window that merely increases passes a single-point test against any
    // algorithm at all.
    var cubic = afterLoss(window: 100)
    let reduced = cubic.congestionWindow / cubicMSS

    // K = cbrt(100 * 0.3 / 0.4) = cbrt(75) ≈ 4.217 seconds, so the curve reaches
    // W_max around then and is below it before.
    #expect(abs(cubic.timeToOriginForTesting - 4.217) < 0.01, "K is not what the RFC's formula gives")

    var early = cubic
    run(&early, rounds: 10)  // one second
    var atOrigin = cubic
    run(&atOrigin, rounds: 42)  // ~4.2 seconds, about K
    var late = cubic
    run(&late, rounds: 80)  // eight seconds

    let earlyWindow = early.congestionWindow / cubicMSS
    let originWindow = atOrigin.congestionWindow / cubicMSS
    let lateWindow = late.congestionWindow / cubicMSS

    #expect(earlyWindow > reduced, "the window did not grow at all")
    #expect(earlyWindow < 100, "the window passed W_max long before K")
    #expect(originWindow > earlyWindow)
    #expect(lateWindow > originWindow, "the convex region is missing: growth stopped at W_max")
    #expect(lateWindow > 100, "the window never exceeded W_max, so it can never probe for more")
}

@Test func theWindowFollowsTheRenoFriendlyEstimateOnAShortRoundTrip() {
    // §4.2. On a short round trip the cubic curve is below what an
    // additive-increase sender would have reached, and CUBIC takes the larger
    // of the two so that it does not do worse than Reno where Reno was fine.
    //
    // The first version of this asserted `cubic >= reno` directly and failed,
    // and the assertion was the thing that was wrong: §4.2's estimate grows by
    // `3(1-β)/(1+β)` ≈ 0.53 segments per round trip, not by Reno's 1, because
    // the factor is chosen to be Reno-equivalent in AGGREGATE against a
    // multiplicative decrease of 0.7 rather than 0.5. Instantaneously CUBIC can
    // and does sit below Reno; claiming otherwise was claiming something the RFC
    // does not.
    //
    // So the assertion is against the RFC's expression, transcribed here from
    // §4.2 rather than read from the code. That is not free of the risk of
    // transcribing the same mistake twice — it is a second reading of the same
    // document — but it does catch the whole class of errors where the code
    // computes something else entirely.
    var cubic = afterLoss(window: 20)
    let roundTripSeconds = 0.010
    let rounds = 20
    run(&cubic, rounds: rounds, roundTrip: 10)

    let beta = 0.7
    let elapsed = Double(rounds) * roundTripSeconds
    let estimate = 20.0 * beta + (3.0 * (1.0 - beta) / (1.0 + beta)) * (elapsed / roundTripSeconds)
    let measured = Double(cubic.congestionWindow) / Double(cubicMSS)
    #expect(
        abs(measured - estimate) < 1.0,
        "the window is not tracking §4.2's estimate: \(measured) vs \(estimate)")

    // And the region really is the Reno-friendly one — the cubic curve is
    // BELOW the estimate here, which is the condition that selects it. Without
    // this the test above passes against a stack that ignores the region
    // entirely and happens to land on a similar number.
    let cubicHere = 0.4 * pow(elapsed - cubic.timeToOriginForTesting, 3) + 20.0
    #expect(cubicHere < estimate, "the fixture is not in the Reno-friendly region: the test proves nothing")
}

@Test func fastConvergenceLowersTheTargetOnlyWhenTheSecondLossComesEarlier() {
    // §4.6. A connection whose available bandwidth has DROPPED is pushed down
    // before it reaches where it was last time, and must give up its share
    // rather than climbing back to a window the path can no longer carry.
    //
    // Asserted on `W_max` directly, because fast convergence is DEFINED as
    // lowering it. An earlier version compared the window at some later instant
    // instead, which also depends on `K` and the elapsed time — and its control
    // case turned out to converge too, so it was comparing two converged states
    // and calling the difference evidence.
    //
    // The two cases differ in one thing: whether the window had climbed PAST
    // the previous maximum before the second loss. That is the condition, and
    // reaching it needs time to pass, which is why the second loss here is
    // taken after eight seconds rather than immediately.
    var converging = afterLoss(window: 100)
    run(&converging, rounds: 10)  // one second: still well below W_max = 100
    let beforeReaching = Double(converging.congestionWindow) / Double(cubicMSS)
    #expect(beforeReaching < 100, "the fixture already passed W_max: it cannot show convergence")
    converging.lossDetectedWithScoreboard(flightSize: converging.congestionWindow)

    var notConverging = afterLoss(window: 100)
    run(&notConverging, rounds: 80)  // eight seconds: past K ≈ 4.217
    let afterPassing = Double(notConverging.congestionWindow) / Double(cubicMSS)
    #expect(afterPassing > 100, "the fixture never passed W_max: both cases would converge")
    notConverging.lossDetectedWithScoreboard(flightSize: notConverging.congestionWindow)

    #expect(
        abs(converging.windowMaxForTesting - beforeReaching * (1.0 + 0.7) / 2.0) < 0.01,
        "the early loss did not converge: W_max is \(converging.windowMaxForTesting)")
    #expect(
        abs(notConverging.windowMaxForTesting - afterPassing) < 0.01,
        "the late loss converged when it should not have: W_max is \(notConverging.windowMaxForTesting)")
}

@Test func aTimeoutCollapsesTheWindowToOneSegmentAndSlowStartsFromThere() {
    // §4.6. `W_max` is remembered so the curve still aims at the rate the path
    // was carrying, but the window itself collapses: after a timeout nothing is
    // known about the pipe.
    //
    // What follows is ordinary slow start, and that is the whole answer to a
    // question this file spent three attempts on. The epoch does not have to be
    // cleared here: the window is one segment and the threshold is at least two,
    // so slow start ALWAYS follows a timeout, and the crossing back into
    // congestion avoidance starts a fresh epoch of its own. `Cubic.timeout` used
    // to clear it anyway; falsification showed the clearing had no effect, and
    // it was removed rather than left as protection that protects nothing. The
    // loss path is different -- it lands in congestion avoidance directly -- and
    // `aLossRestartsTheCurveRatherThanContinuingTheOldOne` is that one.
    var cubic = afterLoss(window: 100)
    cubic.timeout(flightSize: 70 * cubicMSS)
    #expect(cubic.congestionWindow == cubicMSS)

    // Ten seconds pass -- long enough for the curve to be far past W_max -- and
    // then slow start resumes.
    var resumed = cubic
    for _ in 0..<5 {
        resumed.acked(
            bytes: cubicMSS, flightSize: resumed.congestionWindow, now: after(10_000),
            smoothedRoundTrip: .milliseconds(100))
    }
    #expect(
        resumed.congestionWindow == 6 * cubicMSS,
        "the window jumped rather than slow-starting: the epoch was set at the timeout")
}

@Test func aWindowsWorthOfAcknowledgementsMovesFarMoreThanOne() {
    // §4.3's increment is `(W_cubic(t + RTT) - cwnd) / cwnd` PER acknowledgement,
    // and the division is the whole point: a window's worth of them covers the
    // distance over one round trip, so growth per round trip does not depend on
    // how chatty the receiver is.
    //
    // Two earlier versions of this could not fail. The first compared fifty
    // single acknowledgements against one batch of fifty -- a sender that jumped
    // the whole distance per acknowledgement reaches the target either way. The
    // second compared one acknowledgement's movement against the size of the
    // gap, and there is no gap to speak of: the window TRACKS the curve, so it
    // is never far behind it.
    //
    // What remains is a ratio, and it is the property itself rather than a proxy
    // for it: one acknowledgement must move about a seventieth of what seventy
    // do. A sender that skipped the division moves the same distance for one as
    // for seventy, and the ratio collapses to one.
    var one = afterLoss(window: 100)
    run(&one, rounds: 20)
    var many = one
    let before = Double(one.congestionWindow) / Double(cubicMSS)
    let windowSegments = one.congestionWindow / cubicMSS

    one.acked(
        bytes: cubicMSS, flightSize: one.congestionWindow, now: after(2100),
        smoothedRoundTrip: .milliseconds(100))
    for _ in 0..<windowSegments {
        many.acked(
            bytes: cubicMSS, flightSize: many.congestionWindow, now: after(2100),
            smoothedRoundTrip: .milliseconds(100))
    }

    let single = Double(one.congestionWindow) / Double(cubicMSS) - before
    let full = Double(many.congestionWindow) / Double(cubicMSS) - before
    #expect(single > 0, "one acknowledgement moved nothing")
    #expect(
        full > single * 10,
        "a window's worth moved \(full) where one moved \(single): the per-acknowledgement division is missing")
}

@Test func theWindowTracksTheCurveRatherThanLaggingARoundTripBehindIt() {
    // §4.3 aims at `W_cubic(t + RTT)` — where the curve WILL be a round trip
    // from now — precisely so that by the time that round trip has passed the
    // window is where the curve is. Aiming at `W_cubic(t)` instead leaves the
    // window a full round trip behind for ever, which on a long path is most of
    // the benefit.
    //
    // A one-second round trip is chosen so the lag is large enough to measure:
    // at eight seconds the curve is at about 121 segments and one round trip
    // behind it is about 109, where at 100 ms the two would be a segment and a
    // half apart and the test would be measuring its own tolerance.
    var cubic = afterLoss(window: 100)
    run(&cubic, rounds: 8, roundTrip: 1000)

    let elapsed = 8.0
    let expected = 0.4 * pow(elapsed - cubic.timeToOriginForTesting, 3) + 100.0
    let lagging = 0.4 * pow(elapsed - 1.0 - cubic.timeToOriginForTesting, 3) + 100.0
    let measured = Double(cubic.congestionWindow) / Double(cubicMSS)

    #expect(
        abs(measured - expected) < abs(measured - lagging),
        "the window is closer to the curve one round trip back (\(lagging)) than to the curve now (\(expected)): \(measured)")
}

@Test func aLossRestartsTheCurveRatherThanContinuingTheOldOne() {
    // The epoch is what `t` is measured from, so a loss that did not reset it
    // would have the new curve start wherever the old one had got to -- and the
    // first acknowledgements after the loss would jump the window most of the
    // way back to where it was, which is precisely what the reduction was for.
    //
    // The fixture has to be IN congestion avoidance when the loss arrives.
    // Two earlier attempts at this were unfalsifiable because the epoch was
    // already nil at the moment of the loss -- during slow start it is never
    // set -- so clearing it again changed nothing.
    var cubic = afterLoss(window: 100)
    run(&cubic, rounds: 80)  // eight seconds, well past K, so the epoch is live
    let beforeLoss = Double(cubic.congestionWindow) / Double(cubicMSS)
    #expect(beforeLoss > 100, "the fixture never entered the convex region")

    cubic.lossDetectedWithScoreboard(flightSize: cubic.congestionWindow)
    let reduced = Double(cubic.congestionWindow) / Double(cubicMSS)

    // One round trip of acknowledgements immediately after the loss.
    var clock: Int64 = 8100
    for _ in 0..<Int(reduced) {
        cubic.acked(
            bytes: cubicMSS, flightSize: cubic.congestionWindow, now: after(clock),
            smoothedRoundTrip: .milliseconds(100))
    }
    clock += 100
    let after = Double(cubic.congestionWindow) / Double(cubicMSS)

    #expect(
        after < reduced * 1.1,
        "the window jumped from \(reduced) to \(after) in one round trip: the old epoch survived the loss")
}

@Test func anEndpointCanBeToldWhichAlgorithmToUse() throws {
    // The selection reaching the sender, which is the only part of this that
    // the unit tests above cannot see: they exercise `Cubic` directly and would
    // all pass against an endpoint that never built one.
    let fixture = TCPFixture()
    do {
        let endpoint = try listeningEndpoint(fixture)
        endpoint.congestionControl = .cubic
        try withExtendedLifetime(endpoint) {
            completeHandshake(fixture)
            _ = fixture.drainSegments()
            #expect(endpoint.usesCubicForTesting, "the endpoint built a Reno sender after being told CUBIC")
        }
    }
    fixture.drain()
}
