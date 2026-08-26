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
public struct RTTEstimator: Sendable, Equatable {
    /// RFC 6298 §2.4. The floor is deliberately the standard one second even
    /// though this stack's real RTTs are host-local microseconds: the
    /// differential compares loss recovery against gVisor, which uses the
    /// standard floor, and a shorter one here would make every retransmission
    /// comparison diverge for reasons that have nothing to do with
    /// correctness. Lowering it is a decision for after the differential is
    /// clean, not before.
    public static let minimumTimeout = TimeAmount.seconds(1)

    /// RFC 6298 §2.5 permits any ceiling of at least 60 seconds.
    public static let maximumTimeout = TimeAmount.seconds(60)

    /// `G` in `RTO = SRTT + max(G, 4 * RTTVAR)`. Injected rather than assumed,
    /// so the differential can be reproduced with a stated granularity instead
    /// of a hidden constant.
    private let granularity: Int64

    private var srtt: Int64
    private var rttvar: Int64
    private var hasSample: Bool
    private var rto: Int64

    public init(clockGranularity: TimeAmount) {
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
    public var smoothed: TimeAmount { .nanoseconds(srtt) }

    /// RTTVAR. Zero before the first measurement.
    public var variance: TimeAmount { .nanoseconds(rttvar) }

    /// The current RTO, clamped to `minimumTimeout ... maximumTimeout` and
    /// including any accumulated `backOff()`.
    public var retransmissionTimeout: TimeAmount { .nanoseconds(rto) }

    /// Fold one unambiguous RTT sample into the estimate.
    ///
    /// Recomputing the RTO here is what discards an accumulated backoff, per
    /// RFC 6298 §5.7: a fresh measurement is evidence the path is delivering
    /// again, so the doubled timers from the previous loss episode no longer
    /// describe it.
    public mutating func measure(_ sample: TimeAmount) {
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
            rttvar = rttvar - (rttvar >> 2) + (difference >> 2)
            srtt = srtt - (srtt >> 3) + (r >> 3)
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
    public mutating func backOff() {
        rto = Self.clamped(rto.multipliedSaturating(by: 2))
    }

    /// Return to the no-measurement state, so the next `measure` takes the
    /// first-sample path again.
    ///
    /// The estimate describes a path. When the path changes underneath the
    /// connection, blending new samples into the old estimate converges slowly
    /// through values that describe neither.
    public mutating func reset() {
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
