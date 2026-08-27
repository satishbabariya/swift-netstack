import NIOCore
import Testing

@testable import Netstack

// RFC 6298. Every number in this file was worked by hand from the shift-based
// Jacobson update and is asserted exactly, not as a range: this is arithmetic
// with one right answer, and the same answers will be compared against gVisor
// in the differential. A range assertion would accept a wrong implementation
// that happened to land nearby.
//
//     first sample:  SRTT = R              RTTVAR = R / 2
//     later samples: RTTVAR = RTTVAR - (RTTVAR >> 2) + (|SRTT - R| >> 2)
//                    SRTT   = SRTT   - (SRTT   >> 3) + (R        >> 3)
//                    (RTTVAR first, using the OLD SRTT)
//     always:        RTO    = clamp(SRTT + max(G, 4 * RTTVAR), 1s ... 60s)

private let oneMillisecond = TimeAmount.milliseconds(1)

@Test func theFirstRTTSampleSeedsTheEstimatorDirectly() {
    // RFC 6298 §2.2. The first sample is not blended with anything -- there is
    // nothing to blend it with -- so SRTT is the sample and RTTVAR is half of
    // it. 400_000_003ns is deliberately not divisible by 2, 4 or 8: every
    // truncation in this file has to land somewhere specific.
    var estimator = RTTEstimator(clockGranularity: oneMillisecond)
    estimator.measure(.nanoseconds(400_000_003))

    #expect(estimator.smoothed == .nanoseconds(400_000_003))
    #expect(estimator.variance == .nanoseconds(200_000_001), "R / 2 truncates toward zero")
    // 400_000_003 + max(1_000_000, 4 * 200_000_001) = 400_000_003 + 800_000_004
    #expect(estimator.retransmissionTimeout == .nanoseconds(1_200_000_007))
}

@Test func subsequentRTTSamplesFollowTheJacobsonFixedPointUpdate() {
    // Three samples, every intermediate asserted. The samples sit above 333ms
    // so that RTO stays clear of the one-second floor -- otherwise the clamp
    // would hide the arithmetic under test.
    //
    // The third sample is SMALLER than SRTT. That is the point of it: it drives
    // |SRTT - R| through the branch a monotonically increasing sequence never
    // touches, and it is the branch where a signed `>>` on a negative
    // difference (which rounds toward negative infinity, not toward zero) would
    // silently produce a different RTTVAR.
    var estimator = RTTEstimator(clockGranularity: oneMillisecond)

    estimator.measure(.nanoseconds(400_000_003))
    #expect(estimator.smoothed == .nanoseconds(400_000_003))
    #expect(estimator.variance == .nanoseconds(200_000_001))
    #expect(estimator.retransmissionTimeout == .nanoseconds(1_200_000_007))

    // R = 500_000_005, |SRTT - R| = 100_000_002.
    //   RTTVAR = 200_000_001 - 50_000_000 + 25_000_000 = 175_000_001
    //   SRTT   = 400_000_003 - 50_000_000 + 62_500_000 = 412_500_003
    //   RTO    = 412_500_003 + 700_000_004             = 1_112_500_007
    // The 3/4 + 1/4 integer-division form gives 175_000_000 / 412_500_002 here:
    // one nanosecond apart, which is exactly why these are equalities.
    estimator.measure(.nanoseconds(500_000_005))
    #expect(estimator.smoothed == .nanoseconds(412_500_003))
    #expect(estimator.variance == .nanoseconds(175_000_001))
    #expect(estimator.retransmissionTimeout == .nanoseconds(1_112_500_007))

    // R = 300_000_001, below SRTT. |SRTT - R| = 112_500_002.
    //   RTTVAR = 175_000_001 - 43_750_000 + 28_125_000 = 159_375_001
    //   SRTT   = 412_500_003 - 51_562_500 + 37_500_000 = 398_437_503
    //   RTO    = 398_437_503 + 637_500_004             = 1_035_937_507
    estimator.measure(.nanoseconds(300_000_001))
    #expect(estimator.smoothed == .nanoseconds(398_437_503))
    #expect(estimator.variance == .nanoseconds(159_375_001))
    #expect(estimator.retransmissionTimeout == .nanoseconds(1_035_937_507))
}

@Test func theOneSecondFloorBindsForAHostLocalSample() {
    // RFC 6298 §2.4. A 1ms RTT computes an RTO of 3ms; the floor lifts it to a
    // full second. For a host-local gateway this is the COMMON path, not an
    // edge case -- every real sample here will be microseconds.
    //
    // The floor applies to the RTO only. SRTT and RTTVAR keep the measured
    // values, which is what the next update has to blend against; clamping the
    // state instead would poison every subsequent sample.
    var estimator = RTTEstimator(clockGranularity: oneMillisecond)
    estimator.measure(.milliseconds(1))

    #expect(estimator.smoothed == .milliseconds(1))
    #expect(estimator.variance == .microseconds(500))
    #expect(estimator.retransmissionTimeout == .seconds(1), "1ms + 4 * 0.5ms = 3ms, floored to 1s")
}

@Test func theSixtySecondCeilingBindsForAVeryLargeSample() {
    // RFC 6298 §2.5. A 30s sample computes 30s + 4 * 15s = 90s; the ceiling
    // caps it at 60s. As with the floor, the estimator state is not capped.
    var estimator = RTTEstimator(clockGranularity: oneMillisecond)
    estimator.measure(.seconds(30))

    #expect(estimator.smoothed == .seconds(30))
    #expect(estimator.variance == .seconds(15))
    #expect(estimator.retransmissionTimeout == .seconds(60), "90s capped to 60s")
}

@Test func theClockGranularityFloorsTheVarianceTerm() {
    // RFC 6298 §2.3: RTO = SRTT + max(G, 4 * RTTVAR). G is why the estimator
    // takes a granularity at all, so it needs a case where G is the term that
    // wins and the result is still clear of the 1s floor and 60s ceiling.
    //
    // G = 4s (a deliberately coarse clock). Two identical 2s samples: SRTT
    // stays exactly 2s (S - (S >> 3) + (S >> 3) == S), and RTTVAR decays
    // 1_000_000_000 -> 750_000_000 because |SRTT - R| is zero. 4 * RTTVAR is
    // then 3s, below G, so G supplies the term: RTO = 2s + 4s = 6s.
    // Ignoring G entirely would give 5s here.
    var estimator = RTTEstimator(clockGranularity: .seconds(4))
    estimator.measure(.seconds(2))
    estimator.measure(.seconds(2))

    #expect(estimator.smoothed == .seconds(2))
    #expect(estimator.variance == .milliseconds(750))
    #expect(estimator.retransmissionTimeout == .seconds(6))
}

@Test func backingOffDoublesTheTimeoutAndSaturatesAtSixtySeconds() {
    // RFC 6298 §5.5. Each expiry doubles the RTO; the same 60s ceiling that
    // caps the computed value caps the backoff, so it saturates rather than
    // running away to hours.
    var estimator = RTTEstimator(clockGranularity: oneMillisecond)
    estimator.measure(.milliseconds(1))
    #expect(estimator.retransmissionTimeout == .seconds(1))

    let expected: [TimeAmount] = [.seconds(2), .seconds(4), .seconds(8), .seconds(16), .seconds(32), .seconds(60), .seconds(60)]
    for step in expected {
        estimator.backOff()
        #expect(estimator.retransmissionTimeout == step)
    }
    // 32 doubles to 64, not 60, so the last two entries prove the cap rather
    // than the doubling.
}

@Test func aFreshMeasurementClearsTheBackoff() {
    // RFC 6298 §5.7: once a new, unambiguous RTT measurement arrives the RTO is
    // recomputed from SRTT and RTTVAR, which discards the accumulated backoff.
    // Keeping a doubled RTO after the pipe has demonstrably drained would leave
    // the connection retransmitting on minute-long timers forever.
    var estimator = RTTEstimator(clockGranularity: oneMillisecond)
    estimator.measure(.nanoseconds(400_000_003))
    estimator.backOff()
    estimator.backOff()
    #expect(estimator.retransmissionTimeout == .nanoseconds(4_800_000_028), "1_200_000_007 doubled twice")

    estimator.measure(.nanoseconds(500_000_005))
    #expect(estimator.retransmissionTimeout == .nanoseconds(1_112_500_007), "recomputed, not doubled again")
}

@Test func resettingTheEstimatorRestoresTheFirstSamplePath() {
    // reset() returns the estimator to its no-measurement state, so the next
    // sample takes the SRTT = R / RTTVAR = R/2 path again instead of being
    // blended into stale state (the sender needs this when a connection's path
    // changes underneath it).
    var estimator = RTTEstimator(clockGranularity: oneMillisecond)
    estimator.measure(.nanoseconds(400_000_003))
    estimator.measure(.nanoseconds(500_000_005))
    #expect(estimator.smoothed == .nanoseconds(412_500_003), "positive control: there is state to clear")

    estimator.reset()
    #expect(estimator.smoothed == .zero)
    #expect(estimator.variance == .zero)
    #expect(estimator.retransmissionTimeout == .seconds(1), "back to the RFC 6298 §2.1 initial RTO")

    // Blending would give SRTT = 412_500_003 - 51_562_500 + 37_500_000; the
    // first-sample path gives the sample itself.
    estimator.measure(.nanoseconds(300_000_001))
    #expect(estimator.smoothed == .nanoseconds(300_000_001))
    #expect(estimator.variance == .nanoseconds(150_000_000))
}

@Test func theInitialTimeoutIsOneSecondBeforeAnyMeasurement() {
    // RFC 6298 §2.1. The first segment of a connection is sent before any RTT
    // is known, and it still needs a timer.
    let estimator = RTTEstimator(clockGranularity: oneMillisecond)
    #expect(estimator.smoothed == .zero)
    #expect(estimator.variance == .zero)
    #expect(estimator.retransmissionTimeout == .seconds(1))
}

@Test func aNonPositiveRTTSampleIsIgnored() {
    // A zero or negative sample means the clock went backwards or the sample
    // was taken wrongly, not that the path is instantaneous. Folding it in
    // would drag SRTT toward zero and shorten every subsequent timer.
    var estimator = RTTEstimator(clockGranularity: oneMillisecond)
    estimator.measure(.nanoseconds(400_000_003))
    #expect(estimator.smoothed == .nanoseconds(400_000_003), "positive control: the estimator does hold state")

    estimator.measure(.zero)
    estimator.measure(.nanoseconds(-5))
    #expect(estimator.smoothed == .nanoseconds(400_000_003), "unchanged")
    #expect(estimator.variance == .nanoseconds(200_000_001), "unchanged")
    #expect(estimator.retransmissionTimeout == .nanoseconds(1_200_000_007), "unchanged")
}
