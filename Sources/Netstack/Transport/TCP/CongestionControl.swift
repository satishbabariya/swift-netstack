import NIOCore

/// What the sender needs from a congestion-control algorithm.
///
/// Windows are in **bytes**, not segments. TCP's send decision is a byte
/// comparison (`min(cwnd, sndWnd)` against what is outstanding), so keeping the
/// window in segments would mean converting at every use and rounding at every
/// conversion.
///
/// Every loss signal carries the **flight size** -- the bytes actually
/// outstanding when the loss was detected -- because RFC 5681 §3.1 and §3.2
/// define the new threshold as `max(FlightSize/2, 2*SMSS)`, and FlightSize is
/// not the congestion window. On an application-limited connection the window
/// can sit far above what is in flight, and halving the window there sets the
/// threshold from a rate the path has never been asked to carry. Only the
/// sender knows the flight size, so it has to be passed in.
protocol CongestionControl {
    /// The current congestion window, in bytes.
    var congestionWindow: Int { get }
    /// The slow-start threshold, in bytes. At or above it, the algorithm is in
    /// congestion avoidance.
    var slowStartThreshold: Int { get }
    /// SMSS, in bytes.
    ///
    /// Exposed rather than kept a second time by the sender, which needs it for
    /// RFC 6675's loss test. Two copies of a number the peer influences is two
    /// chances to disagree, and the algorithm is where it already lives.
    var segmentSize: Int { get }
    /// A non-duplicate acknowledgement advanced the window by `bytes`.
    ///
    /// `now` and `smoothedRoundTrip` are carried because an algorithm whose
    /// window is a function of TIME needs both, and neither can be reached from
    /// here: the clock belongs to the stack and the round trip to the sender's
    /// estimator. Reno ignores them -- its window is a function of
    /// acknowledgements alone -- which is exactly why they are parameters rather
    /// than state every algorithm has to carry whether it uses them or not.
    mutating func acked(bytes: Int, flightSize: Int, now: NIODeadline, smoothedRoundTrip: TimeAmount)
    /// Loss inferred from duplicate acknowledgements (fast retransmit).
    mutating func lossDetected(flightSize: Int)
    /// Loss inferred from SACK information, RFC 6675.
    ///
    /// Separate from `lossDetected` because the window must **not** be
    /// inflated. RFC 5681 §3.2 adds `3*SMSS` to stand in for the segments the
    /// duplicate acknowledgements said had left the network -- an estimate,
    /// made because a Reno sender cannot see what arrived. A SACK sender can:
    /// it computes `pipe` from the scoreboard and bounds itself by that, so
    /// inflating as well would count the same departures twice.
    mutating func lossDetectedWithScoreboard(flightSize: Int)
    /// The retransmission timer expired.
    mutating func timeout(flightSize: Int)
}

/// Which algorithm an endpoint uses.
///
/// Reno is the default, and the reason is evidence rather than preference: it is
/// the one the differential harness compares frame-for-frame against gVisor, and
/// CUBIC is not -- see `Cubic`'s own comment for why that comparison cannot be
/// made as things stand. A caller on a path where Reno's one-segment-per-round-
/// trip growth is the bottleneck should choose CUBIC knowing that what stands
/// behind it is unit tests against the RFC's arithmetic.
public enum CongestionControlAlgorithm: Sendable {
    case reno
    case cubic

    func make(maximumSegmentSize: Int) -> any CongestionControl {
        switch self {
        case .reno: return Reno(maximumSegmentSize: maximumSegmentSize)
        case .cubic: return Cubic(maximumSegmentSize: maximumSegmentSize)
        }
    }
}

/// RFC 5681 Reno: slow start, congestion avoidance, fast retransmit.
///
/// Fast *recovery* is only half here. This type performs §3.2's window
/// inflation on `lossDetected`, but the duplicate-ACK counting that decides
/// when a loss has been detected, and the deflation when recovery ends, belong
/// to the sender, which is the thing that sees the acknowledgements.
struct Reno: CongestionControl, Sendable, Equatable {
    /// SMSS. Clamped to at least one byte at initialisation: a zero segment
    /// size can arrive from a peer-influenced MSS option, and it would
    /// otherwise divide by zero in congestion avoidance and produce an empty
    /// window on timeout -- a `congestionWindow` of zero wedges the connection
    /// permanently, since no amount of acknowledgement can grow it.
    let segmentSize: Int
    private var cwnd: Int
    private var ssthresh: Int

    init(maximumSegmentSize: Int) {
        let smss = max(1, maximumSegmentSize)
        self.segmentSize = smss
        // Initial window of ten segments (RFC 6928), which is also what gVisor
        // uses by default and therefore what the differential expects. RFC
        // 5681 §3.1's older `min(4*SMSS, max(2*SMSS, 4380))` would give three
        // segments for a 1460-byte MSS; the two differ on the first flight of
        // every connection, so this is a deliberate choice and not an
        // oversight. See the task-11 report.
        self.cwnd = smss.multipliedSaturating(by: 10)
        // RFC 5681 §3.1: ssthresh "may be arbitrarily high" initially, so the
        // connection begins in slow start and stays there until something is
        // learned about the path.
        self.ssthresh = .max
    }

    var congestionWindow: Int { cwnd }
    var slowStartThreshold: Int { ssthresh }

    mutating func acked(bytes: Int, flightSize: Int, now: NIODeadline, smoothedRoundTrip: TimeAmount) {
        // Nothing acknowledged means nothing learned about the path.
        guard bytes > 0 else { return }

        if cwnd < ssthresh {
            // Slow start, RFC 5681 §3.1. The `min` is the ABC-safe form: a
            // single cumulative ACK covering ten segments must open the window
            // by one segment, not ten, or a delayed or recovered ACK produces
            // a burst the path never agreed to.
            cwnd = cwnd.addingSaturating(min(bytes, segmentSize))
        } else {
            // Congestion avoidance, RFC 5681 §3.1. Of the forms the RFC
            // allows, this is the per-ACK approximation `cwnd += SMSS*SMSS /
            // cwnd`, which adds roughly one segment per round-trip time. It is
            // chosen over a counter-based form (accumulate acknowledged bytes,
            // add one segment when they reach cwnd) because it is stateless
            // and because it is the form the RFC states outright -- the
            // counter form's behaviour depends on when the counter is reset,
            // which is exactly the kind of unstated detail the differential
            // would trip over.
            //
            // The floor of one byte is a deliberate deviation. `SMSS*SMSS /
            // cwnd` truncates to zero once cwnd exceeds SMSS squared (2.1MB at
            // a 1460-byte MSS), and a literal reading would freeze the window
            // there forever. One byte per ACK is negligible against such a
            // window but keeps it monotonic.
            let squared = segmentSize.multipliedReportingOverflow(by: segmentSize)
            let increment = squared.overflow ? segmentSize : max(1, squared.partialValue / cwnd)
            cwnd = cwnd.addingSaturating(increment)
        }
        // `flightSize` is deliberately unused. RFC 5681 §3.1 also says cwnd
        // must not grow while the sender is application-limited, but that test
        // needs to know why the sender is idle -- no data queued, or a closed
        // receive window -- which is knowledge the sender has and this type
        // does not. Task 12 owns that decision; growing the window here on the
        // sender's behalf would hide it.
    }

    mutating func lossDetected(flightSize: Int) {
        // RFC 5681 §3.2, fast retransmit and fast recovery.
        ssthresh = reducedThreshold(flightSize: flightSize)
        // The three duplicate ACKs that signalled the loss are three segments
        // that have left the network, so the window is inflated by them.
        cwnd = ssthresh.addingSaturating(segmentSize.multipliedSaturating(by: 3))
    }

    mutating func lossDetectedWithScoreboard(flightSize: Int) {
        // RFC 6675 §5: the threshold is reduced exactly as in §3.2, and cwnd is
        // set to it. The difference from `lossDetected` is the missing
        // inflation, and the reason is in the protocol's own comment.
        ssthresh = reducedThreshold(flightSize: flightSize)
        cwnd = ssthresh
    }

    mutating func timeout(flightSize: Int) {
        // RFC 5681 §3.1. The window collapses to ONE segment, not to half.
        // A timeout means nothing is known about the state of the pipe --
        // neither how much is in it nor whether anything is draining -- so
        // Reno restarts slow start from a single segment. Halving instead
        // would keep an estimate that has just been shown to be wrong.
        ssthresh = reducedThreshold(flightSize: flightSize)
        cwnd = segmentSize
    }

    /// `max(FlightSize/2, 2*SMSS)`, RFC 5681 §3.1 and §3.2.
    ///
    /// The `2*SMSS` floor is what stops a loss with a single segment
    /// outstanding from setting a threshold of half a segment, which no sender
    /// can ever be at. A zero or negative flight size can reach here from a
    /// loss signalled with nothing outstanding, or from sender accounting that
    /// has gone wrong; it lands on the floor rather than on a negative window.
    private func reducedThreshold(flightSize: Int) -> Int {
        let outstanding = max(0, flightSize)
        return max(outstanding / 2, segmentSize.multipliedSaturating(by: 2))
    }
}

extension Int {
    /// Saturating helpers. Both the segment size and the flight size are
    /// influenced by the peer, and this stack degrades rather than traps on
    /// whatever arrives.
    fileprivate func addingSaturating(_ other: Int) -> Int {
        let result = addingReportingOverflow(other)
        return result.overflow ? (other > 0 ? .max : .min) : result.partialValue
    }

    fileprivate func multipliedSaturating(by other: Int) -> Int {
        let result = multipliedReportingOverflow(by: other)
        return result.overflow ? .max : result.partialValue
    }
}
