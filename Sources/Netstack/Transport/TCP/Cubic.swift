import NIOCore

#if canImport(Darwin)
    import Darwin
#else
    import Glibc
#endif

/// RFC 9438 CUBIC.
///
/// ## What it is for, and why Reno is not enough
///
/// Reno's window grows by one segment per round trip in congestion avoidance.
/// On a path with a large bandwidth-delay product that is far too slow to use
/// what is there: after a loss, a connection on a 1 Gbit/s path with a 50 ms
/// round trip needs thousands of round trips -- minutes -- to get back to full
/// rate. CUBIC's window is a function of the TIME since the last congestion
/// event rather than of the number of acknowledgements, so it recovers in a
/// time that does not depend on the round trip, and it is what Linux uses.
///
/// ## The window is in segments here, and in bytes at the boundary
///
/// Every formula in the RFC is in segments -- `W_max`, `W_est`, the cubic
/// function itself -- and this type keeps them that way, converting only where
/// `CongestionControl` requires bytes. The alternative, working in bytes
/// throughout, means multiplying and dividing by the segment size inside each
/// formula, and it is exactly the kind of arithmetic that is wrong in one place
/// and right in four others.
///
/// ## What is NOT validated against another implementation
///
/// Reno is compared frame-for-frame against gVisor by the differential harness.
/// **CUBIC is not**, and the reason is worth stating rather than leaving to be
/// discovered: gVisor's CUBIC keeps its window in whole segments and this one
/// keeps it in a real number of segments, so the two round differently on every
/// acknowledgement, and the generator's connections never stay in congestion
/// avoidance long enough for the shape of the curve to matter more than the
/// rounding. Enabling it there would produce a divergence on arithmetic units
/// rather than on behaviour -- the same difference `differential/README.md`
/// records for the congestion window generally.
///
/// So what stands behind this type is `CubicTests`, which checks the formulas
/// against the RFC's own arithmetic and the region boundaries against worked
/// examples. That is weaker evidence than the differential and is said so here.
struct Cubic: CongestionControl, Sendable {
    /// RFC 9438 §4.2: the multiplicative decrease factor.
    static let beta = 0.7
    /// §4.3: the scaling constant, in segments per second cubed.
    static let cubicScale = 0.4

    let segmentSize: Int

    /// The window, in segments. Real rather than integral: the RFC's growth
    /// rule adds `(W_cubic(t + RTT) - cwnd) / cwnd` per acknowledgement, which
    /// is a fraction of a segment on any window worth having, and rounding it
    /// away at each step stops the window growing at all once it is large.
    private var window: Double
    private var threshold: Double

    /// `W_max`: the window at the last congestion event, in segments.
    private var windowMax = 0.0
    /// The previous `W_max`, which fast convergence compares against.
    private var lastWindowMax = 0.0
    /// `K`: how long, in seconds, the cubic function takes to climb back to
    /// `W_max` from the reduced window.
    private var timeToOrigin = 0.0
    /// The instant of the last congestion event, from which `t` is measured.
    private var epoch: NIODeadline?

    init(maximumSegmentSize: Int) {
        segmentSize = max(1, maximumSegmentSize)
        // Ten segments (RFC 6928), the same initial window Reno uses here, so
        // switching algorithms does not silently change the first flight.
        window = 10
        threshold = .infinity
    }

    var congestionWindow: Int { Int((window * Double(segmentSize)).rounded(.down)) }

    /// `W_max` in segments, and `K` in seconds.
    ///
    /// Exposed because fast convergence is DEFINED as lowering `W_max`, so a
    /// test that asserts on it is asserting the thing itself rather than a
    /// proxy. Inferring it from the window at some later instant would be
    /// asserting on the curve's output, which depends on `K` and the elapsed
    /// time as well, and would pass or fail for reasons that are not the one
    /// under test.
    var windowMaxForTesting: Double { windowMax }
    var timeToOriginForTesting: Double { timeToOrigin }

    var slowStartThreshold: Int {
        threshold.isFinite ? Int((threshold * Double(segmentSize)).rounded(.down)) : .max
    }

    mutating func acked(bytes: Int, flightSize: Int, now: NIODeadline, smoothedRoundTrip: TimeAmount) {
        guard bytes > 0 else { return }
        let segments = Double(bytes) / Double(segmentSize)

        if window < threshold {
            // Slow start is unchanged: RFC 9438 §4.1 leaves it to RFC 5681, and
            // an algorithm that changed it would be changing the part of TCP
            // that is not the problem.
            window += segments
            if window >= threshold {
                // Crossing into congestion avoidance without a loss -- which
                // happens after a timeout collapses the window and it climbs
                // back -- still needs an epoch to measure `t` from. §4.8.
                startEpoch(at: now, from: window)
            }
            return
        }

        let epoch = epoch ?? { startEpoch(at: now, from: window); return now }()
        let elapsed = seconds(from: epoch, to: now)
        let roundTrip = max(seconds(smoothedRoundTrip), 0.001)

        // §4.2's Reno-friendly region. On a path where Reno would have done
        // better -- short round trips, small windows -- CUBIC must not do worse,
        // so it tracks what Reno's window would have been and takes whichever is
        // larger.
        let renoEstimate =
            windowMax * Self.beta + (3.0 * (1.0 - Self.beta) / (1.0 + Self.beta)) * (elapsed / roundTrip)
        let cubicNow = cubicWindow(at: elapsed)
        if cubicNow < renoEstimate {
            window = max(window, renoEstimate)
            return
        }

        // §4.3: aim at where the curve will be one round trip from now, and
        // move a proportional share of the distance for each segment
        // acknowledged. Computing the target once and stepping per segment is
        // what makes the growth per round trip independent of how the
        // acknowledgements were batched.
        let target = cubicWindow(at: elapsed + roundTrip)
        var acknowledged = segments
        while acknowledged > 0 {
            let step = min(acknowledged, 1.0)
            window += ((target - window) / window) * step
            acknowledged -= step
        }
    }

    mutating func lossDetected(flightSize: Int) {
        reduce(flightSize: flightSize)
    }

    mutating func lossDetectedWithScoreboard(flightSize: Int) {
        reduce(flightSize: flightSize, inflate: false)
    }

    mutating func timeout(flightSize: Int) {
        // §4.6. `W_max` is remembered so the curve after the timeout still aims
        // at the rate the path was carrying, but the window itself collapses to
        // one segment: after a timeout nothing is known about the pipe.
        recordCongestionEvent()
        threshold = max(window * Self.beta, 2)
        window = 1
        // The epoch is deliberately NOT cleared here, and that is not an
        // oversight -- it was, until falsification showed the clearing had no
        // effect and it was removed rather than left as protection that
        // protects nothing.
        //
        // A timeout always leaves the window at one segment and the threshold at
        // two or more, so slow start always follows, and the crossing back into
        // congestion avoidance starts a fresh epoch of its own. There is no path
        // from here to the curve that does not go through that crossing. The
        // loss path is different -- it lands in congestion avoidance directly --
        // and clears the epoch for real.
    }

    // MARK: - Internals

    /// §4.2's multiplicative decrease, shared by both loss signals.
    ///
    /// `inflate` is the difference between them, and it is not CUBIC's: RFC
    /// 5681 §3.2 adds three segments to stand in for the ones duplicate
    /// acknowledgements said had left the network, and a SACK sender that
    /// computes `pipe` from the scoreboard must not count those departures
    /// twice. Same reasoning as `Reno`'s two entry points.
    private mutating func reduce(flightSize: Int, inflate: Bool = true) {
        recordCongestionEvent()
        threshold = max(window * Self.beta, 2)
        window = inflate ? threshold + 3 : threshold
        epoch = nil
    }

    /// §4.6's fast convergence, and the recomputation of `K` that follows from
    /// it.
    ///
    /// Fast convergence exists so that a connection whose available bandwidth
    /// has DROPPED gives up its share quickly instead of climbing back to a
    /// window the path can no longer carry. It is detected by `W_max` coming in
    /// below the previous one -- the connection was pushed down before it
    /// reached where it was last time -- and answered by aiming lower still.
    private mutating func recordCongestionEvent() {
        lastWindowMax = windowMax
        if window < lastWindowMax {
            windowMax = window * (1.0 + Self.beta) / 2.0
        } else {
            windowMax = window
        }
        // `K` is recomputed HERE, at the event, and not lazily at the first
        // acknowledgement after it. Both give the same curve -- nothing reads it
        // in between -- but computing it late leaves the state describing a
        // curve that has not been worked out yet, which is a thing a reader (or
        // a test) can look at and be told zero.
        timeToOrigin = cbrt(windowMax * (1.0 - Self.beta) / Self.cubicScale)
    }

    private mutating func startEpoch(at now: NIODeadline, from current: Double) {
        epoch = now
        guard windowMax <= current else { return }
        // Never congested, or already past the old maximum: the curve starts at
        // the current window with no climb to make, which is §4.8's case for
        // entering congestion avoidance without a loss.
        windowMax = current
        timeToOrigin = 0
    }

    /// `W_cubic(t) = C * (t - K)^3 + W_max`, §4.3.
    private func cubicWindow(at elapsed: Double) -> Double {
        let offset = elapsed - timeToOrigin
        return Self.cubicScale * offset * offset * offset + windowMax
    }

    private func seconds(from start: NIODeadline, to end: NIODeadline) -> Double {
        guard end > start else { return 0 }
        return Double((end - start).nanoseconds) / 1_000_000_000
    }

    private func seconds(_ amount: TimeAmount) -> Double {
        Double(amount.nanoseconds) / 1_000_000_000
    }
}
