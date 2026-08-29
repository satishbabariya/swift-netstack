import NIOCore

/// RFC 6298's round-trip time estimator and retransmission timer.
///
/// The estimator holds three numbers: a smoothed round-trip time, a variance,
/// and the retransmission timeout derived from them. It is a pure value --
/// it reads no clock and starts no timers. The sender takes the samples (and
/// decides, under Karn's algorithm, which transmissions are eligible to be
/// sampled at all) and owns the timer; this type only does the arithmetic.
///
/// ## The arithmetic is shift-based on purpose
///
/// RFC 6298 §2.3 states the update as `RTTVAR = (1 - beta) * RTTVAR + beta *
/// |SRTT - R|` with `beta = 1/4` and `alpha = 1/8`, but every stack this one
/// is compared against implements it in Jacobson's fixed-point form:
///
///     RTTVAR = RTTVAR - (RTTVAR >> 2) + (|SRTT - R| >> 2)
///     SRTT   = SRTT   - (SRTT   >> 3) + (R        >> 3)
///
/// That is *not* bit-identical to computing `3/4 * RTTVAR + 1/4 * |SRTT - R|`
/// with integer division: `V - (V >> 2)` keeps the low two bits of `V` whereas
/// `3 * V / 4` throws away three quarters of them, so the two forms differ by
/// a nanosecond or two whenever `V` is not a multiple of four. Those
/// nanoseconds compound, and they would show up in the differential against
/// gVisor as a diverging RTO with no protocol meaning behind it. Hence the
/// shift form, and hence the exact equalities in `RTTEstimatorTests`.
///
/// `>>` on a negative `Int64` rounds toward negative infinity rather than
/// toward zero, which would make the RTTVAR update depend on the *sign* of
/// `SRTT - R`; `measure` takes the absolute difference before shifting so the
/// sample-below-SRTT case follows the same path as every other.
struct RTTEstimator: Sendable, Equatable {
    /// RFC 6298 §2.4. The floor is deliberately the standard one second even
    /// though this stack's real RTTs are host-local microseconds: the
    /// differential compares loss recovery against gVisor, which uses the
    /// standard floor, and a shorter one here would make every retransmission
    /// comparison diverge for reasons that have nothing to do with
    /// correctness. Lowering it is a decision for after the differential is
    /// clean, not before.
    static let minimumTimeout = TimeAmount.seconds(1)

    /// RFC 6298 §2.5 permits any ceiling of at least 60 seconds.
    static let maximumTimeout = TimeAmount.seconds(60)

    /// `G` in `RTO = SRTT + max(G, 4 * RTTVAR)`. Injected rather than assumed,
    /// so the differential can be reproduced with a stated granularity instead
    /// of a hidden constant.
    private let granularity: Int64

    private var srtt: Int64
    private var rttvar: Int64
    private var hasSample: Bool
    private var rto: Int64

    init(clockGranularity: TimeAmount) {
        self.granularity = max(0, clockGranularity.nanoseconds)
        self.srtt = 0
        self.rttvar = 0
        self.hasSample = false
        // RFC 6298 §2.1: until a measurement exists the RTO is one second. The
        // SYN goes out before anything is known about the path and still needs
        // a timer behind it.
        self.rto = Self.minimumTimeout.nanoseconds
    }

    /// SRTT. Zero before the first measurement.
    var smoothed: TimeAmount { .nanoseconds(srtt) }

    /// RTTVAR. Zero before the first measurement.
    var variance: TimeAmount { .nanoseconds(rttvar) }

    /// The current RTO, clamped to `minimumTimeout ... maximumTimeout` and
    /// including any accumulated `backOff()`.
    var retransmissionTimeout: TimeAmount { .nanoseconds(rto) }

    /// Fold one unambiguous RTT sample into the estimate.
    ///
    /// Recomputing the RTO here is what discards an accumulated backoff, per
    /// RFC 6298 §5.7: a fresh measurement is evidence the path is delivering
    /// again, so the doubled timers from the previous loss episode no longer
    /// describe it.
    /// `expectedSamples` is RFC 7323 Appendix G's correction, and it is not
    /// optional once timestamps are in use.
    ///
    /// ## Why a per-ACK sample must be damped
    ///
    /// RFC 6298's α = 1/8 and β = 1/4 are chosen for ONE sample per round trip,
    /// which is what Karn's algorithm and a single timed segment give. With
    /// timestamps every acknowledgement carries a usable measurement, so a
    /// window of ten segments produces ten samples per round trip -- and the
    /// estimator tracks ten times faster than it was designed to. Appendix G's
    /// fix is to divide both gains by the number of samples expected in a round
    /// trip, which it approximates as half the flight.
    ///
    /// This was found by measurement, not by reading. The differential harness
    /// had a residual disagreement about when a FIN is retransmitted, and both
    /// estimators were instrumented rather than reasoned about: at the same
    /// instant, on the same acknowledgement, gVisor's smoothed round trip stayed
    /// at 10 ms and this one jumped to 259 ms. gVisor applies Appendix G; this
    /// did not, so one ambiguous-but-timestamped sample of a full second moved
    /// the estimate twenty-five times further here than there.
    ///
    /// Pass 1 -- the default -- when the sample is Karn-timed, which is one per
    /// round trip by construction.
    mutating func measure(_ sample: TimeAmount, expectedSamples: Int = 1) {
        let r = sample.nanoseconds
        // A zero or negative sample means the clock moved backwards or the
        // sample was taken wrongly -- not that the path is instantaneous.
        // Folding it in would drag SRTT toward zero and shorten every
        // subsequent timer, so it is discarded rather than trusted.
        guard r > 0 else { return }

        if hasSample {
            // RTTVAR is updated first, against the OLD SRTT: RFC 6298 §2.3
            // defines the variance in terms of the estimate the sample is
            // being compared against, not the one that includes it.
            let difference = srtt >= r ? srtt - r : r - srtt
            let samples = Int64(max(1, expectedSamples))
            if samples == 1 {
                // The integer shifts are exact for α = 1/8 and β = 1/4 and are
                // kept for that case: it is every connection without
                // timestamps, and it is the arithmetic the vectors were derived
                // against.
                rttvar = rttvar - (rttvar >> 2) + (difference >> 2)
                srtt = srtt - (srtt >> 3) + (r >> 3)
            } else {
                // Appendix G, in integer arithmetic. α' = 1/(8n) and β' = 1/(4n)
                // become divisions by 8n and 4n, which is the same expression
                // with the shift replaced by a divide -- and the divide is what
                // makes n expressible at all.
                rttvar = rttvar - (rttvar / (4 * samples)) + (difference / (4 * samples))
                srtt = srtt - (srtt / (8 * samples)) + (r / (8 * samples))
            }
        } else {
            // RFC 6298 §2.2. Nothing to blend against yet.
            srtt = r
            rttvar = r / 2
            hasSample = true
        }

        rto = Self.clamped(srtt.addingSaturating(max(granularity, rttvar.multipliedSaturating(by: 4))))
    }

    /// RFC 6298 §5.5. Double the timer on expiry, up to the ceiling.
    ///
    /// The ceiling makes this saturate rather than run away: without it a
    /// connection to a black hole reaches hour-long timers and stops looking
    /// like a connection at all.
    mutating func backOff() {
        rto = Self.clamped(rto.multipliedSaturating(by: 2))
    }

    /// Return to the no-measurement state, so the next `measure` takes the
    /// first-sample path again.
    ///
    /// The estimate describes a path. When the path changes underneath the
    /// connection, blending new samples into the old estimate converges slowly
    /// through values that describe neither.
    mutating func reset() {
        srtt = 0
        rttvar = 0
        hasSample = false
        rto = Self.minimumTimeout.nanoseconds
    }

    private static func clamped(_ nanoseconds: Int64) -> Int64 {
        min(max(nanoseconds, minimumTimeout.nanoseconds), maximumTimeout.nanoseconds)
    }
}

extension Int64 {
    /// Saturating helpers. The inputs here are ultimately peer-influenced
    /// (a sample is measured against segments the peer chooses when to
    /// acknowledge), and this stack must degrade rather than trap on any
    /// value that reaches it.
    fileprivate func addingSaturating(_ other: Int64) -> Int64 {
        let result = addingReportingOverflow(other)
        return result.overflow ? (other > 0 ? .max : .min) : result.partialValue
    }

    fileprivate func multipliedSaturating(by other: Int64) -> Int64 {
        let result = multipliedReportingOverflow(by: other)
        return result.overflow ? .max : result.partialValue
    }
}
