import NIOCore

/// The send side of a TCP connection: the queue of bytes the application has
/// written, the segments cut from it, and the machinery that decides when to
/// send them again.
///
/// This is the counterpart to `Receiver`, and the split between them is the
/// same one: `Receiver` owns RCV.NXT and the bytes coming in, this type owns
/// SND.UNA and the bytes going out, and `TCPStateMachine` owns the state. Only
/// one component advances any given sequence variable. `acknowledged` is
/// therefore the single place SND.UNA moves **over data**, and
/// `segmentsToTransmit` the single place SND.NXT does -- both take the TCB
/// `inout` for exactly that reason.
///
/// Stated exactly, because the stronger version of it is false and a false
/// invariant in a comment is what stops the next reader checking:
/// `TCPStateMachine` still writes SND.UNA at three sites, all of them outside
/// the data stream. One initialises it to ISS on a passive open; the other two
/// retire our own **SYN** in SYN-SENT and SYN-RECEIVED, where the only
/// acceptable acknowledgement is ISS+1. This type holds no record of a SYN --
/// see "What this type does not do" below -- so being handed one would have it
/// grow the congestion window by a byte the path never carried. Past the
/// handshake, the ESTABLISHED arm of RFC 9293 §3.10.7.4's step 4 calls
/// `acknowledged` instead of assigning SND.UNA, and the two can never run for
/// one segment: they are different arms of one switch on the connection state.
///
/// ## The retransmit queue is a peer-controlled allocation
///
/// Everything written stays queued until the peer acknowledges it, and **the
/// peer decides when that happens**. A peer that opens a large window, accepts
/// the data and then simply stops acknowledging pins every byte ever written
/// for as long as it likes -- and it costs the peer nothing to do it. That is
/// the same defect class that produced two Criticals in the IPv4 reassembler,
/// so the queue is bounded the same three ways:
///
/// 1. **`maximumBufferedBytes` bounds retained memory**, and `write` returns
///    `false` rather than truncating, so the caller can apply backpressure to
///    the application instead of silently losing a prefix of the stream. The
///    plan's `write` was unbounded and returned nothing; both halves of that
///    are the amendment.
/// 2. **Every write is copied into fresh, exactly-sized storage on
///    admission.** A NIO `ByteBuffer` slice is copy-on-write and keeps the
///    ENTIRE original allocation alive, so a 1-byte write sliced off a
///    1500-byte frame would pin 1500 bytes while the accounting saw 1. See
///    `queuedStorageCapacityForTesting`, which makes that falsifiable.
/// 3. **`perChunkOverhead` is charged on top of every chunk's length**,
///    because a freshly allocated 1-byte copy costs far more than one byte.
///    See that constant for the measurement.
///
/// A fourth cap, `maximumSegments`, bounds the number of in-flight segment
/// records independently of the bytes. It is not redundant: a record covers at
/// least one byte, so a peer advertising a tiny MSS turns a bounded number of
/// queued *bytes* into a far larger number of *records*, none of which the
/// byte accounting sees. It is derived from `maximumBufferedBytes` rather than
/// being a second knob to keep in step.
///
/// When a cap binds, the newcomer loses and nothing already queued is
/// disturbed -- `write` refuses, or `segmentsToTransmit` simply sends less.
/// Evicting queued data to make room would discard bytes the application was
/// already told were accepted.
///
/// ## What this type does not do
///
/// No SYN, no FIN, no Nagle, no SACK, and no sender-side silly-window-syndrome
/// avoidance. It moves a byte stream and nothing else: the control flags occupy
/// sequence space that this type's offsets do not model, which is why
/// `segmentsToTransmit` refuses to act when SND.NXT has moved by an amount it
/// did not itself send (see there), and why `persistApplies` refuses for the
/// same reason.
///
/// It *does* probe a zero window — see `persistTimerFired`, which is where the
/// one rule in this file that has no give-up condition lives.
struct Sender {
    /// The real per-chunk cost of holding one queued write: the array element,
    /// the `ByteBuffer`'s backing storage object, and malloc's rounding of a
    /// small allocation -- none of which `readableBytes` sees.
    ///
    /// Measured for this type, not inherited from `TCPReassembler`'s 256 --
    /// `Chunk` is a different shape from that class's `Entry` (a `ByteBuffer`
    /// and an `Int`, with no sequence number), and carrying a constant across
    /// unmeasured is how the IPv4 reassembler's bound was defeated repeatedly.
    ///
    /// Method: queue 264,000 one-byte writes with this constant set to zero
    /// and copy-on-admission in place, and read real RSS growth from
    /// `getrusage` in a process running that test alone (debug build, arm64
    /// macOS). Result, identical across three runs: 41,779,200 bytes of
    /// resident growth for 264,000 chunks, **158.25 bytes per queued 1-byte
    /// write**, against 264,000 bytes accounted -- a factor of 158. The count
    /// is just past a power of two so the chunk array's doubling has overshot
    /// to nearly 2x, which is the worst case for the array-element share of
    /// that figure.
    ///
    /// 256 is charged: 1.6x above the measurement, with headroom that a future
    /// `Chunk` field or a different allocator will not immediately eat.
    /// Over-charging only fills the queue sooner for very small writes, which
    /// is the right direction to be wrong in -- the cap must bound what is
    /// really retained, not what was declared.
    ///
    /// `getrusage` is the right instrument *here* and the wrong one in a test:
    /// `ru_maxrss` is a process-wide, monotonically non-decreasing high-water
    /// mark, and Swift Testing runs tests concurrently in one process, so a
    /// test built on it can read no growth on regressed code and pass. That is
    /// why the guarding test uses `storageCapacity` instead, and why this
    /// measurement was taken with `--filter` selecting it alone.
    static let perChunkOverhead = 256

    /// `G` in RFC 6298's `RTO = SRTT + max(G, 4 * RTTVAR)`.
    ///
    /// One millisecond. `RTTEstimator` takes this injected so a differential
    /// can be reproduced against a stated granularity, but the sender's
    /// interface has nowhere to put it, so it is stated here instead of being
    /// hidden inside the estimator's default.
    static let clockGranularity = TimeAmount.milliseconds(1)

    /// One admitted write. `bytes` is always freshly allocated, exactly-sized
    /// storage -- never the buffer handed to `write`, which may be a slice.
    ///
    /// `charge` is what was added to `accountedBytes` on admission and is
    /// refunded verbatim when the chunk is dropped. It is deliberately NOT
    /// recomputed as the chunk is consumed: acknowledging a prefix moves a
    /// reader index, which releases nothing, so refunding for it would let the
    /// accounting drift below what is really retained.
    private struct Chunk {
        var bytes: ByteBuffer
        let charge: Int
    }

    /// One transmitted, not-yet-acknowledged segment. Bytes are not stored
    /// here -- they are still in `chunks`, and this only records where the
    /// segment's boundaries fell so a retransmission can reproduce it exactly.
    ///
    /// `transmissions` is Karn's algorithm: at 2 or more the ACK is ambiguous,
    /// because it may be answering either transmission, and no RTT sample may
    /// be taken from it.
    private struct InFlight {
        var sequence: SequenceNumber
        var length: Int
        var transmissions: Int
        var sentAt: NIODeadline
        /// Whether this segment went out with PSH. Recorded rather than
        /// re-derived, because a retransmission must reproduce the segment it
        /// lost EXACTLY, and by the time it is rebuilt the write it came from
        /// may have more bytes queued behind it -- which would re-derive a
        /// different answer for a segment that is already on the peer's wire.
        var pushes: Bool
        /// Presumed lost by the retransmission timer, and not yet retransmitted
        /// since it fired. Set on every outstanding record when the timer
        /// expires and cleared, one record at a time, as each goes out again.
        ///
        /// This is what makes "at most once per episode" a property of the
        /// record rather than of a counter: a second acknowledgement cannot
        /// resend a segment the first one already resent, because the first one
        /// cleared this. Only another timeout sets it again.
        ///
        /// Deliberately NOT `transmissions > 1`. That is Karn's flag, it is
        /// never cleared, and keying eligibility on it would make a segment
        /// retransmitted in an earlier episode ineligible in this one.
        var presumedLost: Bool
        /// Reported by the peer as having arrived, via an RFC 2018 SACK block.
        ///
        /// Advisory, and that word carries weight: the peer is permitted to
        /// discard SACKed data it has not yet delivered, so this is not an
        /// acknowledgement and cannot retire the record. It is only ever used
        /// to decide what NOT to send -- what is not in the pipe, and what is
        /// not worth retransmitting -- which is the direction in which a wrong
        /// answer costs bandwidth rather than correctness.
        var sacked: Bool
    }

    /// The congestion-control algorithm, readable so a caller (and the tests)
    /// can see the window this sender is actually obeying rather than
    /// re-deriving it.
    private(set) var congestionControl: any CongestionControl

    private let clock: any NetstackClock
    private let maximumBufferedBytes: Int
    private let maximumSegments: Int

    /// Written bytes not yet acknowledged, oldest first. The first readable
    /// byte of `chunks[0]` is the byte at SND.UNA.
    private var chunks: [Chunk] = []
    private var accountedBytes = 0
    private var queuedBytes = 0

    /// Transmitted segments awaiting acknowledgement, ascending and
    /// contiguous, covering exactly `[SND.UNA, SND.NXT)`.
    private var inFlight: [InFlight] = []
    private var outstanding = 0

    /// Bytes of `inFlight` that the retransmission timer has presumed lost and
    /// that have not been retransmitted since it fired.
    ///
    /// This is the ENTIRE state of a timeout episode: an episode is running
    /// exactly while this is non-zero. There is no separate flag and no
    /// recovery point, on purpose -- either would have to be kept in step with
    /// the queue by hand, and this cannot drift because it is maintained at the
    /// same two places the queue is, and only there: a segment goes out again
    /// (`retransmit`), or it is acknowledged (`retire`).
    ///
    /// Subtracting it from `flightSize` gives `pipeSize`, and that subtraction
    /// is the whole answer to "one retransmission per timeout". A timeout means
    /// nothing is known about the pipe, so the sender stops counting the
    /// un-retransmitted remainder as being IN the pipe. Without it, `flightSize`
    /// straight after a timeout is the full outstanding window while `cwnd` is
    /// one segment, so the send decision has room for nothing at all and the
    /// only thing that can ever move again is the next timer expiry -- which is
    /// exactly the shape the differential recorded against gVisor.
    ///
    /// This is Linux's `tcp_packets_in_flight` (`packets_out - lost_out +
    /// retrans_out`) and RFC 6675 §4's `pipe`, in bytes rather than packets.
    ///
    /// It is NOT a NewReno `recover` (RFC 6582): there is no highest-sequence
    /// watermark here, so a segment that is presumed lost, retransmitted, and
    /// then lost AGAIN waits for the next timeout rather than being re-marked by
    /// a partial acknowledgement. That is the conservative direction, and it is
    /// what RFC 6298 §5.4 on its own guarantees.
    private var lostBytes = 0

    /// Bytes in flight the peer has selectively acknowledged. Excluded from
    /// `pipe`, because they are no longer in the network.
    private var sackedBytes = 0

    /// RFC 8985 RACK: loss detected by TIME rather than by counting what
    /// arrived above a hole.
    ///
    /// ## Why a second loss detector, when RFC 6675 already works
    ///
    /// 6675 declares a segment lost when enough SACKed data sits above it. That
    /// needs enough data above it to exist -- three discontiguous runs, or two
    /// segments' worth of bytes -- so the last few segments of a transfer are
    /// invisible to it: nothing is sent after them, nothing arrives above them,
    /// and the retransmission timer is the only thing left. RACK asks a
    /// different question. A segment sent BEFORE one that has since been
    /// delivered, and not itself delivered after a reordering window has passed,
    /// is lost -- and that question has an answer for the tail as well as the
    /// middle.
    ///
    /// **What is here is RACK's detection and not its reordering timer.** §6.3's
    /// timer re-examines the scoreboard once the window expires with no further
    /// acknowledgements; without it, a segment whose window has not yet passed
    /// when the last acknowledgement arrives waits for the RTO instead. That is
    /// the case the tail loss probe covers, which is why the two are usually
    /// spoken of together, and it is why this is `rackTimeBasedLossDetection`
    /// rather than `rack`.
    private struct RACK {
        /// `rack.xmit_ts` and `rack.end_seq`: when the most recently SENT of the
        /// delivered segments went out, and where it ended. "Most recently sent",
        /// not "most recently delivered" -- the whole comparison below is about
        /// send order.
        var mostRecentSend: NIODeadline?
        var mostRecentEnd: SequenceNumber?
        /// `rack.rtt`: the round trip of that most recently sent delivered
        /// segment. §6.2 measures a segment's age against `now` as
        /// `xmit_ts + rack.rtt + reo_wnd`, so this is part of how long a segment
        /// is given before it is called lost -- not a statistic.
        var roundTrip: TimeAmount = .zero
        /// `rack.reo_wnd`: how long to wait before calling a gap loss rather
        /// than reordering.
        var reorderWindow: TimeAmount = .zero
        /// Whether reordering has ever been observed. Until it has, the window
        /// is zero -- §7.2 -- because waiting for reordering that this path has
        /// never shown is a round trip spent on nothing.
        var sawReordering = false
        /// The smallest round trip seen, which the window is a fraction of.
        var minimumRoundTrip: TimeAmount?
        /// §6.3's reordering timer: when the earliest segment still inside its
        /// window stops being inside it.
        var reorderDeadline: NIODeadline?
        /// §7.2's tail loss probe: whether one has already gone out for the
        /// current tail. One, not a ladder -- the probe exists to draw an
        /// acknowledgement, and a peer that did not answer the first is not
        /// going to answer the second any sooner than the RTO will find out.
        var probeSent = false
    }

    private var rack = RACK()

    /// RACK's reordering window, and whether reordering has been observed.
    ///
    /// Exposed because the window is zero until reordering is seen, so a test
    /// about the window has to be able to say which of the two states it is in
    /// -- and inferring that from whether a segment was marked confuses "the
    /// window is open" with "this segment happened to be inside it".
    var rackEnabledForTesting: Bool { rackEnabled }
    var rackStateForTesting: (send: NIODeadline?, rtt: TimeAmount, window: TimeAmount, minRTT: TimeAmount?) {
        (rack.mostRecentSend, rack.roundTrip, rack.reorderWindow, rack.minimumRoundTrip)
    }
    var reorderWindowForTesting: TimeAmount { rack.reorderWindow }
    var sawReorderingForTesting: Bool { rack.sawReordering }

    /// Whether RACK is consulted. Off by default for the same reason CUBIC is:
    /// the differential harness compares this stack against gVisor with gVisor's
    /// own RACK disabled, so turning it on here would compare one stack's
    /// time-based detection against another stack's absence of it.
    var rackEnabled = false

    /// SND.NXT at the moment SACK-based recovery began, RFC 6675's
    /// RecoveryPoint. Non-nil exactly while an episode is running.
    ///
    /// The point of remembering it: an episode ends when everything that was
    /// outstanding when it started has been acknowledged, NOT on the first
    /// acknowledgement that advances. Without it a single partial ACK ends
    /// recovery, the window is restored, and the next hole starts a second
    /// episode that halves the threshold again -- one loss event charged twice.
    private var recoveryPoint: SequenceNumber?

    private var estimator: RTTEstimator
    private var timerDeadline: NIODeadline?
    private var duplicates = 0
    private var fastRetransmitPending = false

    /// When the next zero-window probe is due, or `nil` when the sender is not
    /// in the persist condition. **Absolute**, and deliberately never pushed
    /// out while it is already set: `updatePersistTimer` only ever assigns it
    /// from `nil`. A deadline recomputed on every arriving segment would let a
    /// peer that holds the window shut and keeps chattering defer the probe
    /// forever, which is the failure `TCPEndpoint.finDeadline` records for the
    /// FIN timer.
    private var persistTimerDeadline: NIODeadline?

    /// The interval between the last probe and the next. `nil` outside the
    /// persist condition, so that leaving it and re-entering starts the ladder
    /// again from the RTO rather than from wherever the previous episode
    /// stopped.
    ///
    /// Deliberately NOT reset by `RTTEstimator.measure` the way RFC 6298 §5.7
    /// discards the RTO's backoff. A fresh round-trip sample is evidence about
    /// the *path*; the persist interval measures how long the *receiver* has
    /// been unable to take data, and nothing about a round trip says anything
    /// about that.
    private var persistTimerInterval: TimeAmount?

    /// Whether the single byte a zero-window probe put on the wire is still
    /// unacknowledged.
    ///
    /// A `Bool` and not the probe's sequence number, because there is only ever
    /// one and its position is not free: `persistApplies` runs only when the
    /// probe is the *sole* outstanding record, so it always sits at SND.UNA and
    /// any acknowledgement that advances SND.UNA at all has retired it. That is
    /// what makes the two places this is cleared -- an advancing
    /// acknowledgement, and the empty-queue branch of `retransmitTimerFired` --
    /// the complete set.
    private var probeOutstanding = false

    /// TCP_NODELAY: whether RFC 9293 §3.7.4's small-segment rule is switched off.
    ///
    /// Off by default, so the rule applies — which is the conformant default and
    /// the one that protects a shared path from a chatty application. An
    /// application that knows its own traffic is request/response can turn it on
    /// and stop paying a round trip per write.
    var nagleDisabled = false

    /// SEG.WND from the last acknowledgement that reached `acknowledged` --
    /// the number that was ON THE WIRE, not what the TCB made of it.
    ///
    /// RFC 5681 §3.2's condition (e) is a comparison between two advertised
    /// windows, and reading it off `TCB.sndWnd` instead is a defect the Task 17
    /// differential caught: RFC 9293 §3.10.7.4's update rule REFUSES a window
    /// carried by a segment whose SND.WL1 is not newer, so a peer that pushes
    /// SND.WL1 forward with one out-of-order segment freezes `sndWnd` and every
    /// later window update then reads as "unchanged". Three of them in a row
    /// were enough to halve the congestion window and retransmit a segment
    /// nothing had been lost of. See
    /// `tcp-data.vec`'s `window-updates-are-not-duplicate-acknowledgements`.
    ///
    /// `nil` until the first acknowledgement, so the first one is never
    /// classified as a change against a window that was never advertised.
    private var lastAdvertisedWindow: Int?

    init(congestionControl: any CongestionControl, clock: any NetstackClock, maximumBufferedBytes: Int) {
        self.congestionControl = congestionControl
        self.clock = clock
        self.maximumBufferedBytes = max(0, maximumBufferedBytes)
        // The smallest charge any chunk can carry is one payload byte plus
        // the overhead, so this is the most chunks the byte cap can ever
        // admit; segments are cut from chunks, so it bounds them too. The
        // `1 +` is not cosmetic: dividing by `perChunkOverhead` alone traps
        // the initialiser outright if that constant is ever set to zero, which
        // is exactly the edit someone re-measuring it makes first.
        self.maximumSegments = max(1, self.maximumBufferedBytes / (1 + Self.perChunkOverhead))
        self.estimator = RTTEstimator(clockGranularity: Self.clockGranularity)
    }

    // MARK: - Observables

    /// Bytes transmitted and not yet acknowledged: RFC 5681's FlightSize, and
    /// what every loss signal has to be measured against.
    var flightSize: Int { outstanding }

    /// What the sender believes is actually **in the network**: `flightSize`
    /// less the bytes a timeout has presumed lost. Equal to `flightSize`
    /// whenever no timeout episode is running, which is almost always.
    ///
    /// This, not `flightSize`, is what `min(cwnd, SND.WND)` bounds. The two
    /// differ only between a timer expiry and the moment the last segment it
    /// presumed lost has gone out again, and in that interval counting the
    /// presumed-lost bytes as in flight would leave a window of one segment
    /// with no room in it for the very retransmissions it exists to carry.
    var pipeSize: Int { max(0, outstanding - lostBytes - sackedBytes) }

    /// Bytes in flight the peer has reported as arrived. For tests, and for
    /// anything asking why `pipe` is smaller than the flight size.
    var selectivelyAcknowledgedBytes: Int { sackedBytes }

    /// Whether RFC 6675 recovery is running.
    var inScoreboardRecovery: Bool { recoveryPoint != nil }

    /// Bytes presumed lost by the retransmission timer and still awaiting their
    /// retransmission. Non-zero exactly while a timeout episode is running.
    var presumedLostBytes: Int { lostBytes }

    /// Transmitted, unacknowledged **segments**. Distinct from `flightSize`,
    /// which counts their bytes.
    var unacknowledgedCount: Int { inFlight.count }

    /// Written but not yet transmitted. Non-zero means there is data the
    /// window, not the application, is holding back.
    var unsentBytes: Int { max(0, queuedBytes - outstanding) }

    /// Total charge held: every queued chunk's allocation plus
    /// `perChunkOverhead` each. This is the figure `maximumBufferedBytes`
    /// bounds, and it is deliberately larger than the bytes written.
    var bufferedBytes: Int { accountedBytes }

    /// Whether the buffer is below its bound at all.
    ///
    /// Deliberately weaker than "the next write will be accepted", which cannot
    /// be answered without knowing that write's size. A caller woken on this and
    /// then refused again simply re-arms its wait, so the weak form costs a
    /// retry; the strong form would need the pending write's length carried down
    /// here, and would still be wrong for the second waiter.
    var hasBufferSpace: Bool { accountedBytes < maximumBufferedBytes }

    /// Consecutive duplicate acknowledgements, by RFC 5681 §3.2's definition
    /// and not by "the ACK number repeated" -- see `acknowledged`.
    var duplicateAcknowledgements: Int { duplicates }

    /// When the retransmission timer should next fire, or `nil` when it is
    /// off. The caller owns the actual timer; this type only says when.
    var retransmitDeadline: NIODeadline? { timerDeadline }

    /// The current RTO, including any accumulated backoff.
    var retransmissionTimeout: TimeAmount { estimator.retransmissionTimeout }

    /// The estimate itself, separately from the RTO computed out of it.
    ///
    /// The RTO is a poor observable for "was a sample taken": RFC 6298 §2.4
    /// floors it at one second, so on a host-local path it reads the same
    /// whether the estimator moved or not. Anything asserting that a sample was
    /// or was not taken — Karn's tests, and RFC 7323 §4.1's timestamp sampling —
    /// has to read this instead.
    var smoothedRoundTrip: TimeAmount { estimator.smoothed }

    /// RFC 8985 §7's tail loss probe: when to prod the peer, or `nil` when
    /// there is nothing to prod it about.
    ///
    /// ## What it is for, which is not what a retransmission timer is for
    ///
    /// RACK needs an acknowledgement to work from. When the last segments of a
    /// transfer are lost there is nothing left to draw one: the peer has nothing
    /// to acknowledge and the sender has nothing to send. The probe is a segment
    /// sent for the sole purpose of provoking a reply, after roughly two round
    /// trips rather than the RTO's second or more -- and the reply, whatever it
    /// says, is what lets RACK see the hole.
    ///
    /// **Not armed during recovery.** In recovery there is already a
    /// retransmission in flight doing the same job, and a probe would be a
    /// second segment sent to learn something the first will report.
    var tailProbeDeadline: NIODeadline? {
        guard let interval = tailProbeInterval else { return nil }
        return clock.now() + interval
    }

    /// How long from NOW the probe should wait.
    ///
    /// §7.5.1 arms the timer "upon transmission of new data or receipt of an
    /// ACK", and the PTO is a duration measured from that moment -- not from
    /// when the last segment happened to go out. The difference shows on any
    /// connection whose peer is still sending: an acknowledgement re-arms the
    /// probe, and a deadline anchored to an older send time fires sooner than
    /// the RFC asks, sometimes much sooner.
    ///
    /// Measured against gVisor, which arms from the same two events.
    var tailProbeInterval: TimeAmount? {
        guard rackEnabled, !rack.probeSent, recoveryPoint == nil, lostBytes == 0 else { return nil }
        guard inFlight.last != nil, outstanding > 0 else { return nil }
        let smoothed = estimator.smoothed
        guard smoothed > .zero else { return nil }
        // §7.2: twice the smoothed round trip, plus a delayed-acknowledgement
        // allowance when a single segment is outstanding -- because a lone
        // segment is exactly what a receiver holds back waiting for a second
        // one. Never past the retransmission timeout, which is the deadline this
        // is trying to beat.
        var interval = TimeAmount.nanoseconds(smoothed.nanoseconds * 2)
        if inFlight.count == 1 { interval = interval + Self.delayedAckAllowance }
        // Capped at the RETRANSMISSION TIMER'S OWN DEADLINE, not at the RTO
        // interval. The two differ whenever the timer was armed before this
        // segment went out -- which is the ordinary case for a flight -- and the
        // probe exists to beat that timer, so a probe scheduled past it is a
        // probe that never happens.
        let now = clock.now()
        if let timer = timerDeadline {
            let remaining = timer > now ? timer - now : .nanoseconds(0)
            if interval > remaining { interval = remaining }
        }
        return interval
    }

    /// RFC 8985 §7.2's `WCDelAckT`: the worst-case delayed acknowledgement a
    /// receiver may impose. RFC 9293 §3.8.6.3 caps it at 500 ms; 200 is what
    /// every stack in practice uses and what the RFC's own text suggests.
    private static let delayedAckAllowance = TimeAmount.milliseconds(200)

    /// RFC 8985 §6.3's reordering timer: when to look again, or `nil` when
    /// nothing is waiting out its window.
    ///
    /// ## Why detection on acknowledgements alone is not enough
    ///
    /// `RACK_detect_loss` runs when an acknowledgement arrives, and a segment
    /// whose window has not passed at that moment is left alone -- correctly, it
    /// may still be reordering. But if that acknowledgement was the last one,
    /// nothing runs detection again, and the segment waits for the
    /// retransmission timer: an RTO in place of a round trip. This deadline is
    /// what the endpoint arms so the question gets asked once more.
    ///
    /// The caller owns the actual timer; this type only says when, exactly as
    /// for persist.
    var rackReorderDeadline: NIODeadline? { rack.reorderDeadline }

    /// When the next zero-window probe should go out, or `nil` when this sender
    /// is not in RFC 9293 §3.8.6.1's persist condition. The caller owns the
    /// actual timer; this type only says when.
    var persistDeadline: NIODeadline? { persistTimerDeadline }

    /// The interval the next probe is waiting out, or `nil` outside persist.
    /// Doubles per probe and saturates at `RTTEstimator.maximumTimeout`.
    var persistInterval: TimeAmount? { persistTimerInterval }

    /// Whether a probe's byte is on the wire and unacknowledged. Distinct from
    /// `flightSize == 1`: it says that the outstanding byte is a *probe*, which
    /// is what keeps the retransmission timer off it (see `persistApplies`).
    var hasProbeOutstanding: Bool { probeOutstanding }

    /// Diagnostic: the total `ByteBuffer.storageCapacity` of every queued
    /// chunk -- the size of the allocations they keep alive, not the number of
    /// bytes they declare. Not `private`, because `@testable import` elevates
    /// `internal` and not `private`.
    ///
    /// This makes copy-on-admission falsifiable without measuring anything:
    /// a fresh, exactly-sized 1-byte copy reports 1, an uncopied 1-byte slice
    /// of a 1500-byte frame reports 2048. It bounds pinning, not footprint --
    /// the per-chunk cost `perChunkOverhead` covers is invisible here.
    ///
    /// O(queued chunks); for tests and diagnostics only.
    var queuedStorageCapacityForTesting: Int {
        chunks.reduce(0) { $0 + $1.bytes.storageCapacity }
    }

    // MARK: - Writing

    /// Queue bytes for transmission. Returns `false` if the buffer bound would
    /// be exceeded, in which case **nothing was queued** and the caller should
    /// stop feeding the connection until an acknowledgement frees room.
    ///
    /// The bytes are copied into fresh, exactly-sized storage before anything
    /// else happens to them; see the type's doc comment for why the copy is
    /// load-bearing rather than defensive.
    mutating func write(_ bytes: ByteBuffer) -> Bool {
        let length = bytes.readableBytes
        // An empty write is a no-op rather than a refusal: there is nothing to
        // account for and nothing to hold, so reporting failure would push a
        // caller into backpressure it does not need.
        guard length > 0 else { return true }

        // Cheap rejection first, on the optimistic charge. The exact charge
        // uses the copy's real capacity, which is never smaller than `length`,
        // so anything this refuses the exact test would refuse too -- and this
        // way a refused write does not allocate.
        guard accountedBytes + length + Self.perChunkOverhead <= maximumBufferedBytes else { return false }

        var copy = ByteBufferAllocator().buffer(capacity: length)
        copy.writeBytes(bytes.readableBytesView)
        // Charged on the allocation's real capacity, not on `length`. NIO
        // rounds a buffer's storage up to a power of two, so a 1025-byte write
        // occupies 2048 -- charging the declared length would under-account by
        // nearly half at exactly the worst-case size.
        let charge = copy.storageCapacity + Self.perChunkOverhead
        guard accountedBytes + charge <= maximumBufferedBytes else { return false }

        chunks.append(Chunk(bytes: copy, charge: charge))
        accountedBytes += charge
        queuedBytes += length
        return true
    }

    // MARK: - Transmitting

    /// The segments to put on the wire now, in the order they must go out: a
    /// pending fast retransmission, then whatever a running timeout episode
    /// still owes, then as much new data as `min(cwnd, SND.WND)` allows.
    ///
    /// The middle stage is what makes a timeout cost one recovery instead of
    /// one segment per expiry. It is emitted from here rather than from
    /// `acknowledged` for the same reason the fast retransmission is: the
    /// ordinary loop acknowledges and then transmits, so a caller that never
    /// changed gets it in the same pass.
    ///
    /// SND.NXT is advanced over the new data before returning, so the caller
    /// must send everything returned.
    mutating func segmentsToTransmit(tcb: inout TCB, mss: Int) -> [Segment] {
        // Every `return` below goes through this, so the persist decision is
        // taken from the state this method LEAVES behind rather than the state
        // it found -- including the early returns, which are precisely the
        // paths on which nothing went out and something therefore has to.
        defer { updatePersistTimer(tcb: tcb) }
        var out: [Segment] = []

        if fastRetransmitPending {
            fastRetransmitPending = false
            // Not gated on the window: RFC 5681 §3.2 retransmits the lost
            // segment and only then inflates cwnd, and the segment's bytes are
            // already counted in FlightSize, so sending it again consumes no
            // new window.
            if let segment = retransmitOldest(tcb: &tcb) { out.append(segment) }
        }

        // `min(cwnd, SND.WND)`, and it bounds everything below -- the episode's
        // retransmissions as well as the new data. Read once: nothing in this
        // method moves the congestion window, which is the point (see
        // `drainPresumedLost`).
        let window = max(0, min(congestionControl.congestionWindow, tcb.sndWnd))

        out.append(contentsOf: drainPresumedLost(tcb: &tcb, window: window, segmentSize: max(1, mss)))

        // SND.NXT must be exactly where this type left it. If it is not,
        // something else has taken sequence space -- a FIN, most likely -- and
        // every offset below would be wrong by that amount. Fail closed rather
        // than sending bytes from the wrong place in the stream. The drain
        // above is deliberately ahead of this guard: it works from each
        // record's own sequence number rather than from an offset off SND.NXT,
        // so a FIN in the sequence space stops new data without also stopping
        // the recovery of the data underneath it.
        let sent = tcb.sndNxt - tcb.sndUna
        guard sent == outstanding, sent <= queuedBytes else { return out }

        // New data waits for the hole. Sending it while a segment is still
        // presumed lost puts bytes into a path that has just dropped some, and
        // fills the window the collapse to one segment opened up for the
        // retransmissions -- so the hole would then wait for the next timer
        // expiry after all, which is the defect this file is fixing.
        //
        // Load-bearing, not belt-and-braces: `usable` below is measured against
        // `pipeSize`, which by construction EXCLUDES the presumed-lost bytes,
        // so without this guard the room the drain could not use for a whole
        // segment would be spent on a short new one instead.
        //
        // RFC 6675 recovery is the exception, and it is not a relaxation of the
        // rule so much as the rule with better information. The paragraph above
        // holds new data back because the sender cannot tell how much of the
        // window the path is still carrying; that is exactly what the peer's
        // report answers. `pipeSize` already excludes both the presumed-lost
        // bytes and the SACKed ones, so `window - pipeSize` IS §5's
        // `cwnd - pipe`, and sending into it is step (C) rather than a raid on
        // the room the retransmissions need -- the drain above has already had
        // its pick of that room.
        guard lostBytes == 0 || recoveryPoint != nil else { return out }

        let segmentSize = max(1, mss)
        var usable = window - pipeSize
        var unsent = queuedBytes - sent
        var offset = sent

        while unsent > 0, usable > 0, inFlight.count < maximumSegments {
            let length = min(segmentSize, min(unsent, usable))

            // RFC 9293 §3.7.4, Nagle: "If there is unacknowledged data, then the
            // sending TCP endpoint buffers all user data (regardless of the PSH
            // bit) until the outstanding data has been acknowledged or until the
            // TCP endpoint can send a full-sized segment."
            //
            // Both escapes matter and the second is the one that keeps bulk
            // transfer working: a full-sized segment always goes, so a stream of
            // them is never held. What is held is a SHORT segment while anything
            // is still outstanding, which is exactly the telnet-style flow the
            // rule exists for — one keystroke per segment, one segment per round
            // trip, and the path carrying more header than payload.
            //
            // `nagleDisabled` is TCP_NODELAY. It exists because the rule has a
            // real cost: an application doing request/response in small writes
            // waits a round trip it did not need to. Combined with a peer that
            // delays acknowledgements, that becomes the classic stall — the
            // sender waiting for an acknowledgement the receiver is holding —
            // and `tcp-data.vec` pins it rather than leaving it folklore.
            let isFullSized = length >= segmentSize
            // A zero-window probe does not count as outstanding data here.
            //
            // Nagle's "unacknowledged data" means user data this sender chose to
            // put on the path — the dribble it exists to coalesce. A probe is
            // neither: it is one byte we were obliged to send to ask whether the
            // peer's window had reopened, and it is unacknowledged precisely
            // because the peer has not answered yet.
            //
            // Counting it gives the wrong answer at the worst moment. The peer
            // answers the probe by reopening its window; we then hold everything
            // queued, because a byte sent only to ask the question is still
            // outstanding. The connection would resume a round trip late every
            // time it recovered from a closed window.
            let outstandingUserData = outstanding - (probeOutstanding ? 1 : 0)
            let somethingOutstanding = outstandingUserData > 0 || !out.isEmpty
            // The third escape, and without it the rule deadlocks.
            //
            // A peer crawling out of a zero window offers one byte at a time. A
            // one-byte segment is not full-sized and there is always something
            // outstanding, so Nagle alone would buffer it — and the peer, waiting
            // on data before it opens the window further, would never send the
            // acknowledgement that releases it. The connection stops, and neither
            // side is at fault.
            //
            // So: when the *window* is what limits the segment rather than the
            // data available, send it. Nagle exists to stop an application
            // dribbling small writes into a path that could carry more; it has
            // nothing to say about a segment that is small because the receiver
            // said so. RFC 1122 §4.2.3.4 makes the same point from the
            // silly-window-syndrome side.
            //
            // Found by `aProbeAnsweredWithAWindowOfOneStaysInPersistAndAWindowOfTwoDoesNot`,
            // which is a persist test rather than a Nagle one — the interaction
            // was invisible from either feature alone.
            let windowLimited = length >= usable
            if !nagleDisabled, !isFullSized, !windowLimited, somethingOutstanding { break }
            let sequence = tcb.sndNxt
            let pushes = bytesRemainingInWrite(from: offset) <= segmentSize
            out.append(
                Segment(
                    sequence: sequence, flags: pushes ? [.ack, .psh] : .ack,
                    payload: gather(offset: offset, length: length)))
            inFlight.append(
                InFlight(
                    sequence: sequence, length: length, transmissions: 1, sentAt: clock.now(), pushes: pushes,
                    presumedLost: false, sacked: false))
            tcb.sndNxt = sequence + length
            outstanding += length
            offset += length
            unsent -= length
            usable -= length
        }

        // RFC 6298 §5.1: start the timer when data is sent and it is not
        // already running. A fast retransmission alone cannot start it --
        // there was outstanding data, so it was already running.
        if !out.isEmpty, timerDeadline == nil {
            armTimer()
        }
        return out
    }

    // MARK: - Acknowledgement

    /// Process an incoming acknowledgement. Returns `false` if it was
    /// unacceptable -- ahead of SND.NXT, so acknowledging data never sent, or
    /// behind SND.UNA, so already superseded -- in which case nothing was
    /// changed and the caller should not act on it.
    ///
    /// `segmentLength` is SEG.LEN of the segment that carried the ACK. It is
    /// a third amendment to the plan's interface, defaulted so that a pure ACK
    /// needs no argument, and it exists because RFC 5681 §3.2's duplicate-ACK
    /// test cannot be expressed without it: an ACK counts as a duplicate only
    /// when it acknowledges no new data, **carries no data itself**, and
    /// repeats the advertised window. Payload is not derivable from `(ack,
    /// tcb)`, so with the plan's signature a bidirectional flow -- where every
    /// acknowledgement rides on a data segment and repeats SND.UNA while our
    /// own data is outstanding -- would fast-retransmit continuously.
    ///
    /// `advertisedWindow` is SEG.WND, straight off the wire, and it is a
    /// REQUIRED argument rather than a defaulted one on purpose. RFC 5681
    /// §3.2's condition (e) compares it against the window in the previous
    /// acknowledgement -- not against `tcb.sndWnd`, which is what RFC 9293
    /// §3.10.7.4's update rule made of it and which a peer can freeze at will
    /// by pushing SND.WL1 forward once. Reading it off the TCB was a real
    /// defect (see `lastAdvertisedWindow`), and a caller that could omit this
    /// argument is a caller that can reintroduce it.
    ///
    /// A window update that happens to repeat the last ACK number is not a
    /// duplicate ACK, and counting it as one retransmits segments nothing was
    /// ever lost of, on an idle connection, invisibly until throughput is
    /// measured. Neither is the acknowledgement a stalled receiver sends back
    /// for a zero-window probe, which satisfies every one of §3.2's five
    /// conditions and is evidence of the opposite of loss; see the fourth
    /// condition on the duplicate branch below.
    mutating func acknowledged(
        upTo ack: SequenceNumber, tcb: inout TCB, segmentLength: Int = 0, advertisedWindow: Int,
        echoedTimestamp: UInt32? = nil, timestampClockNow: UInt32? = nil,
        selectiveAcknowledgements: [SACKBlock] = []
    ) -> Bool {
        // As in `segmentsToTransmit`, and for the same reason. The one that
        // matters here is the `advanced == 0` return: an acknowledgement that
        // retires nothing and reopens the window is the whole point of RFC 9293
        // §3.10.7.4 admitting SEG.ACK == SND.UNA, and it is what ENDS persist.
        //
        // `tcb.sndWnd` has already been updated by the caller at this point --
        // `TCPStateMachine` runs RFC 9293's window-update rule before handing
        // the acknowledgement on, and states that ordering as an obligation --
        // so the window this reads is the one the sender will actually obey,
        // including when the SND.WL1 rule deliberately refused the update.
        defer { updatePersistTimer(tcb: tcb) }
        let windowChanged = lastAdvertisedWindow.map { $0 != advertisedWindow } ?? false
        lastAdvertisedWindow = advertisedWindow

        // RFC 9293 §3.10.7.4's acceptable-ACK window, inclusive at the bottom
        // so a duplicate naming SND.UNA reaches the counting below. Written as
        // a forward-distance range rather than a negated ordering: at exactly
        // half the sequence space `lessThan` is false in both directions, so
        // `!ack.lessThan(...)` would admit the one value a peer can compute
        // and send at will.
        guard ack.isInRange(from: tcb.sndUna, throughAndIncluding: tcb.sndNxt) else { return false }

        // Before anything decides what this acknowledgement means. The blocks
        // describe data that is in flight NOW, indexed by sequence number, and
        // `retire` below both removes records and renumbers a partial one --
        // so a scoreboard update run afterwards would be matching the peer's
        // report against a different set of records than the peer saw.
        let learnedFromScoreboard = recordSelectiveAcknowledgements(selectiveAcknowledgements, tcb: tcb)

        let advanced = ack - tcb.sndUna
        let flightBefore = outstanding

        // RFC 6675 §4's `IsLost`, ahead of §3.2's duplicate-ACK counting below.
        // The two are alternatives, not stages: when the peer reports what it
        // holds there is no need to infer it from a count, and running both
        // would halve the threshold twice for one loss. This returns false when
        // nothing is SACKed, so a connection without the option reaches the
        // counter unchanged.
        _ = detectLossFromScoreboard(tcb: &tcb, flightSize: flightBefore)

        if advanced == 0 {
            // `!answeringOnlyAProbe` is the fourth condition, and it is here
            // because zero-window probing INTRODUCED the need for it. Before
            // there was a probe, a sender in the persist condition had nothing
            // outstanding, so RFC 5681 §3.2's condition (a) -- "the receiver of
            // the ACK has outstanding data" -- was false and a zero-window ACK
            // could not start a run. A probe makes (a) true, and (b) through (e)
            // are all true of the ACK a stalled receiver must send back, so
            // three of them in a row would fast-retransmit the probe byte and
            // halve `ssthresh` on a path that has dropped nothing.
            //
            // §3.2's own statement of what it is for is what excludes them: it
            // uses duplicate ACKs "as an indication that a segment has been
            // lost". A zero-window acknowledgement is evidence of the opposite
            // -- the probe ARRIVED, and the receiver is telling us it discarded
            // the byte because RFC 9293 §3.10.7.4 makes any SEG.LEN > 0
            // unacceptable against RCV.WND == 0. A stalled reader is not a
            // congested path.
            //
            // Narrow on purpose: the probe must be the ONLY thing outstanding.
            // Once the window has reopened and real data is in flight behind an
            // unacknowledged probe byte, duplicates mean what they always mean
            // and this must not swallow them.
            // The last two conditions are RFC 6675's, not RFC 5681's.
            //
            // §2 redefines "duplicate acknowledgement" for a SACK connection:
            // an ACK counts only "if the ACK contains previously unknown SACK
            // information". A peer that repeats an acknowledgement without
            // telling this sender anything new about what it holds has reported
            // nothing, and counting those would fast-retransmit on a peer
            // simply keeping quiet. gVisor's `isDupAck` opens with exactly this
            // test, and it is what a stack sending bare duplicates observably
            // does NOT provoke from it.
            //
            // `recoveryPoint == nil` keeps the counter out of an episode that is
            // already running, where the response to a duplicate is the drain,
            // not another reduction.
            if segmentLength == 0, !windowChanged, flightBefore > 0, !(probeOutstanding && flightBefore == 1),
                !(tcb.sackPermitted && !learnedFromScoreboard), recoveryPoint == nil
            {
                duplicates += 1
                // RFC 5681 §3.2: the THIRD duplicate is the loss signal. The
                // first two are ordinary reordering.
                //
                // `lostBytes == 0` is the answer to "what happens when a
                // timeout episode and a duplicate-acknowledgement episode
                // overlap": the TIMEOUT WINS, and the duplicates are counted
                // but do not act. Two reasons, and the second is the one that
                // bites. First, they carry no news -- the timer has already
                // declared every outstanding byte lost and the retransmissions
                // are already scheduled, so there is nothing for a loss signal
                // to discover. Second, §3.2's response is `cwnd = ssthresh +
                // 3*SMSS`, an INFLATION, and applying it here would undo the
                // collapse to one segment that §3.1 just made for a much
                // stronger signal: the connection would leave a timeout with a
                // window four segments wide. `retransmitTimerFired` already
                // clears the run in the other direction; this is the same rule
                // seen from the other side.
                if duplicates == 3, lostBytes == 0 {
                    if tcb.sackPermitted {
                        // Same threshold, different response. RFC 6675 §5 enters
                        // recovery here too -- `shouldEnterRecovery` is
                        // `DupAckCount >= 3 || IsLost(SND.UNA)` -- but a SACK
                        // sender bounds itself with `pipe` afterwards, so the
                        // window must not also be inflated by the three segments
                        // the duplicates stood for.
                        enterScoreboardRecovery(tcb: &tcb, flightSize: flightBefore)
                    } else {
                        congestionControl.lossDetected(flightSize: flightBefore)
                        fastRetransmitPending = true
                    }
                }
            } else {
                // Not a duplicate by §3.2's definition, so it does not extend
                // a run of them either.
                duplicates = 0
            }
            // RACK last, and the placement is the point: its window is a
            // fraction of the smallest round trip seen, and the sample that
            // would establish one is taken during retirement -- which does not
            // happen on this path. Running it here uses what was learned
            // before, which is all there is.
            _ = detectLossByTime(tcb: &tcb, flightSize: flightBefore)
            // Acceptable, but it retired nothing and the timer keeps running
            // against the transmission it was armed for -- RFC 6298 §5.3
            // restarts on new data only.
            return true
        }

        duplicates = 0
        fastRetransmitPending = false
        // New data acknowledged: this is a different tail, so it gets its own
        // probe. Without the reset a connection gets one probe for its whole
        // life, which is one more than none and far fewer than it needs.
        rack.probeSent = false
        // RFC 6675 §5's exit: the episode ends when the cumulative
        // acknowledgement passes what was outstanding when it began, not on the
        // first one that advances. A partial acknowledgement inside an episode
        // is the ordinary case -- it is the hole being filled -- and treating it
        // as the end would restore the window and let the next hole open a
        // second episode, charging one loss event to the threshold twice.
        if let point = recoveryPoint, !ack.lessThan(point) {
            recoveryPoint = nil
        }
        // A probe's byte is always the one at SND.UNA (`persistApplies` only
        // lets a probe exist while it is the sole outstanding record), so any
        // acknowledgement that advances SND.UNA at all has retired it.
        probeOutstanding = false
        let previousUna = tcb.sndUna
        tcb.sndUna = ack
        // The timestamp round trip, in the same milliseconds `TCPEndpoint`
        // stamps with. Only when the echo is one we could have sent: a zero
        // echo is what a peer puts on a segment before it has heard from us,
        // and a value ahead of our own clock is not a round trip at all.
        var timestampSample: TimeAmount?
        if let echo = echoedTimestamp, let now = timestampClockNow, echo != 0 {
            let elapsed = Int64(bitPattern: UInt64(now &- echo))
            if elapsed >= 0, elapsed < 60_000 {
                timestampSample = .milliseconds(elapsed)
            }
        }
        retire(
            previousUna: previousUna, advanced: advanced, timestampSample: timestampSample,
            timestampsInUse: tcb.timestampsEnabled)
        // After retirement, because retirement is where this acknowledgement's
        // round-trip sample is taken and RACK's window is a fraction of the
        // smallest one seen. Run before it, the window on the first
        // acknowledgement of a connection is a fraction of nothing -- zero --
        // and everything below the delivered segment is declared lost on the
        // spot.
        _ = detectLossByTime(tcb: &tcb, flightSize: flightBefore)
        congestionControl.acked(
            bytes: advanced, flightSize: flightBefore, now: clock.now(),
            smoothedRoundTrip: estimator.smoothed)

        if inFlight.isEmpty {
            // RFC 6298 §5.2.
            timerDeadline = nil
        } else {
            // RFC 6298 §5.3.
            armTimer()
        }
        return true
    }

    // MARK: - Round-trip time

    /// Fold the handshake's round trip into the estimator, before any data has
    /// been sent.
    ///
    /// This type models no SYN and must not start to: Task 14 of Plan 2 measured
    /// the cost of feeding it one -- `cwnd` grows by a byte and a stray one-byte
    /// segment can reach the wire. So `TCPEndpoint` owns the handshake, times
    /// it, and applies Karn's algorithm to it (`HandshakeRTT`); this method is
    /// the one seam through which the finished sample reaches the estimator, and
    /// it is the whole of this type's involvement in the handshake.
    ///
    /// Deliberately a sample rather than an assignment. The caller hands over a
    /// measurement and `RTTEstimator` decides what it is worth, so the handshake
    /// takes RFC 6298 §2.2's first-measurement path exactly as any other first
    /// sample would. What that buys is not the handshake's own value --
    /// microseconds, under a one-second floor -- but the first DATA sample,
    /// which then takes §2.3's Jacobson update instead of §2.2's deliberately
    /// conservative `RTTVAR = R / 2`. See `HandshakeRTT` for the arithmetic and
    /// for what the differential measured it to be worth.
    ///
    /// Nothing is in flight when this is called -- the connection has only just
    /// reached ESTABLISHED -- so there is no armed timer for the recomputed RTO
    /// to contradict and no accumulated backoff for it to discard.
    mutating func measureHandshakeRoundTrip(_ sample: TimeAmount) {
        estimator.measure(sample)
    }

    // MARK: - Retransmission

    /// The retransmission timer expired. Returns the segment to send again, or
    /// `nil` if nothing is outstanding.
    ///
    /// RFC 6298 §5.4-5.6: retransmit the earliest unacknowledged segment,
    /// double the RTO, and start the timer again. The segment is **not**
    /// discarded -- it stays queued until the peer acknowledges it, which is
    /// what makes a second expiry able to send it a third time.
    ///
    /// §5.4 asks for *the earliest* segment and no more, and for a long time
    /// this stack sent exactly that and nothing else -- conformant, and
    /// unusable at the same time. §5.4 does not say to stop there, and gVisor
    /// and Linux do not: an *n*-segment loss burst recovered here in *n*
    /// expiries on the 1, 2, 4, 8, 16 s ladder, about 31 seconds for five
    /// segments against roughly one anywhere else. So this method also presumes
    /// every outstanding byte lost, and `segmentsToTransmit` goes on
    /// retransmitting the rest of them as acknowledgements open the window.
    ///
    /// The backed-off RTO is not left doubled forever: `RTTEstimator.measure`
    /// recomputes the RTO from scratch, so the first unambiguous sample after
    /// the loss episode discards the accumulated backoff (RFC 6298 §5.7).
    /// Karn's algorithm is what makes that the *first unambiguous* sample and
    /// not the next one to arrive.
    mutating func retransmitTimerFired(tcb: inout TCB) -> Segment? {
        // A timeout supersedes any duplicate-ACK run: the segment those
        // duplicates were pointing at is about to be resent anyway, and
        // counting the run across the timeout would fast-retransmit it again.
        duplicates = 0
        fastRetransmitPending = false

        guard !inFlight.isEmpty else {
            timerDeadline = nil
            // Nothing is outstanding, so nothing can be owed, and `retire`'s
            // accounting should already have said so. Cleared here anyway
            // because the cost of the two disagreeing is not a wrong number:
            // a non-zero `lostBytes` with an empty queue holds `guard
            // lostBytes == 0` shut and no new data ever leaves this connection
            // again. This is the one place that is reachable with the queue
            // known to be empty.
            lostBytes = 0
            // Same argument, one field over: an empty queue cannot be holding
            // a probe, and a stale `true` here would hold `persistApplies`'
            // `outstanding == probeBytes` test open against an outstanding
            // byte that is not a probe.
            probeOutstanding = false
            return nil
        }

        congestionControl.timeout(flightSize: outstanding)
        estimator.backOff()
        armTimer()

        // Everything outstanding is presumed lost, which is the same judgement
        // RFC 5681 §3.1 makes one line above when it collapses cwnd to a single
        // segment: after a timeout nothing is known about the pipe, so the
        // sender stops claiming any of it is still in there. That is what
        // leaves room under the collapsed window for the retransmissions.
        //
        // `where !presumedLost` rather than a blanket assignment, so a second
        // expiry inside an episode re-marks only what the first one's drain has
        // already sent and does not double-count what it has not.
        //
        // The scoreboard is discarded here, and the alternative was considered
        // and rejected rather than overlooked.
        //
        // Keeping it would spare the peer retransmissions of data it has
        // already reported -- which is what Linux does, and what RFC 6675 §5.1
        // permits. It also **stalls**. A peer is entitled to discard SACKed
        // data it has not yet delivered; if it does, its cumulative
        // acknowledgement never passes the hole, the next expiry finds the same
        // records still marked as arrived, declines to resend them again, and
        // the connection makes no progress for as long as the peer is willing
        // to wait. Escaping that needs a second rule about how many timeouts a
        // SACK mark survives, and a rule with a counter in it is one more thing
        // to get wrong.
        //
        // A timeout is the signal that nothing is known about the pipe. Acting
        // on it means exactly that, including about what the peer said was in
        // it. The cost is a possible retransmission of data the peer holds,
        // once, on a path that has just stopped delivering entirely.
        sackedBytes = 0
        for index in inFlight.indices {
            inFlight[index].sacked = false
            guard !inFlight[index].presumedLost else { continue }
            inFlight[index].presumedLost = true
            lostBytes += inFlight[index].length
        }
        // The episode is over as a SACK episode: the timer's judgement replaces
        // it, and a RecoveryPoint left standing would suppress entry into the
        // next one.
        recoveryPoint = nil
        // RACK's state is deliberately NOT cleared here, and that is a
        // correction: it was, until falsification showed the clearing made no
        // difference, and it was removed rather than left as protection that
        // protects nothing.
        //
        // Everything outstanding is about to be retransmitted, which gives every
        // record a send time later than anything RACK remembers -- so RACK marks
        // nothing until a new delivery updates it, cleared or not. And the
        // delivery that would update it has to be of an UNAMBIGUOUS
        // transmission, which a retransmitted record is not. The honest summary
        // is that RACK goes quiet after a timeout until fresh data is sent and
        // acknowledged; RFC 8985 keeps it working through timestamps and DSACK,
        // which this does not implement.

        // §5.4's retransmission is unconditional -- it is not gated on the
        // window, the way `fastRetransmitPending`'s is not. It is also the only
        // one that is: everything the drain sends afterwards is under
        // `min(cwnd, SND.WND)`, and this one is what guarantees forward
        // progress when that window has no room for even a single segment.
        return retransmitOldest(tcb: &tcb)
    }

    // MARK: - Zero-window probing (RFC 9293 §3.8.6.1, RFC 1122 §4.2.2.17)

    /// The persist timer expired. Returns the one-byte probe to send, or `nil`
    /// if the persist condition has passed since the timer was armed.
    ///
    /// ## This is the rule in this file with no give-up condition, and that is deliberate
    ///
    /// RFC 9293 §3.8.6.1: "Probing of zero (offered) windows MUST be supported
    /// (MUST-36). A TCP implementation MAY keep its offered receive window
    /// closed indefinitely (MAY-8). As long as the receiving TCP peer continues
    /// to send acknowledgments in response to the probe segments, the sending
    /// TCP peer MUST allow the connection to stay open (MUST-37)." RFC 1122
    /// §4.2.5's summary table states the same thing from the other side:
    /// "Sender timeout OK conn with zero wind" is a **MUST NOT**.
    ///
    /// So what is bounded here is the **interval** between probes, and not
    /// their number. That is the opposite of the retransmission ladder next
    /// door, and copying that ladder's shape is the mistake to avoid: a persist
    /// timer that gives up after *N* probes turns a receiver whose application
    /// has stopped reading -- RFC 6429 §2's printer that ran out of paper -- into
    /// a dead connection, and the peer has done nothing wrong. RFC 1122 §4.2.2.17
    /// authorises the interval bound and declines to pick it: "Exponential
    /// backoff is recommended, possibly with some maximum interval not specified
    /// here." `RTTEstimator.maximumTimeout`'s sixty seconds is the one used, so
    /// that the probe ladder and the RTO ladder saturate at the same place.
    ///
    /// ## Why "probe forever" is not an unbounded resource
    ///
    /// Because the two things a persisting connection holds were already bounded
    /// before this method existed, and this method adds a third that is bounded
    /// by the interval cap:
    ///
    /// 1. **The connection block and its timers.** `TCPEndpoint`'s table is
    ///    capped by the backlog. Note what this does *not* say: the block was
    ///    already held indefinitely by a zero window before there was any probe
    ///    at all -- a wedged connection is not a collected one -- so persist adds
    ///    a timer to a block whose retention it did not cause.
    /// 2. **The send queue.** `Sender.maximumBufferedBytes` --
    ///    `TCPEndpoint.sendBufferBytes`, 256 KiB per connection. This is the
    ///    resource that actually matters and it is far and away the largest:
    ///    RFC 6429 §3 describes the attack in exactly these terms ("the server is
    ///    left holding on to the response data in its sending queue... this may
    ///    result in DoS to legitimate connections by locking up the necessary
    ///    resources"). A statement of the bound as "one connection and one
    ///    timer" understates it by five orders of magnitude per connection, so it
    ///    is stated as what it is: `sendBufferBytes` x the backlog.
    /// 3. **Probe traffic**, which is the only genuinely new resource. One
    ///    one-byte segment per connection per interval, and the interval
    ///    saturates at sixty seconds -- so a persisting connection costs one
    ///    frame a minute in the steady state, for as long as it lasts.
    ///
    /// RFC 6429 §4 is what closes the remaining gap, and this stack satisfies it:
    /// "a TCP implementation MUST NOT close a connection merely because it seems
    /// to be stuck in the ZWP or persist condition. Though unstated in RFC 1122,
    /// but implicit for system robustness, a TCP implementation needs to allow
    /// connections in the ZWP or persist condition to be closed or aborted by
    /// their applications or other resource management routines." Persist here
    /// never closes a connection on its own, and `TCPEndpoint.close()` closes a
    /// persisting one exactly as it closes any other.
    ///
    /// ## Karn
    ///
    /// Nothing special, and the absence of a special case is the decision. A
    /// probe is an ordinary `InFlight` record carrying ordinary new data, so its
    /// first transmission is unambiguous and its acknowledgement is a legitimate
    /// RTT sample -- there is exactly one segment it can be answering. Every
    /// probe after the first goes out through `retransmit`, which increments
    /// `transmissions`, and `retire` then refuses a sample from the record for
    /// the rest of its life. That is Karn's algorithm applying to a probe on the
    /// same terms as to anything else, which is what makes it right: the
    /// ambiguity Karn guards against is "which transmission is this ACK for",
    /// and a re-probed byte has exactly that ambiguity.
    ///
    /// The commoner case takes no sample at all and needs no rule: a receiver
    /// with RCV.WND == 0 finds any SEG.LEN > 0 unacceptable (RFC 9293
    /// §3.10.7.4's acceptability table) and drops the probe's byte, so the ACK
    /// it must still send carries SEG.ACK == SND.UNA, `advanced` is zero, and
    /// `retire` -- the only place a sample is taken -- is never reached.
    mutating func persistTimerFired(tcb: inout TCB) -> Segment? {
        guard persistApplies(tcb: tcb) else {
            persistTimerDeadline = nil
            persistTimerInterval = nil
            return nil
        }

        let segment: Segment?
        if probeOutstanding {
            // RFC 9293 §3.8.6.1's "or retransmit": once a probe is unanswered
            // the NEXT probe is that same byte again, never the byte after it.
            // The peer discarded the first one (see the acceptability note
            // above), so a byte at SND.UNA + 1 would sit behind a hole the peer
            // cannot close, and every probe after that would widen it.
            //
            // Index 0 is the probe: `persistApplies` has just established that
            // it is the only record in flight.
            segment = retransmit(0, tcb: &tcb)
        } else {
            segment = cutProbe(tcb: &tcb)
        }

        guard let segment else {
            // Unreachable: `persistApplies` has checked everything both
            // branches need. Fail closed rather than leave a timer re-arming
            // against a sender that can no longer produce the segment it is
            // for -- a silent no-op ladder would look exactly like a working
            // one from outside.
            persistTimerDeadline = nil
            persistTimerInterval = nil
            return nil
        }

        // RFC 9293 SHLD-30 / RFC 1122 §4.2.2.17: "SHOULD increase exponentially
        // the interval between successive probes". Measured from the moment the
        // probe went out, not from the answer to it -- a peer that answers every
        // probe promptly must not thereby hold the ladder at its first rung.
        // Never overflows: the operand is `RTTEstimator.maximumTimeout` at
        // worst, because the previous line through here already clamped it.
        let next = min((persistTimerInterval ?? estimator.retransmissionTimeout) * 2, RTTEstimator.maximumTimeout)
        persistTimerInterval = next
        persistTimerDeadline = clock.now() + next
        return segment
    }

    /// Cut, record and hand back the first probe of an episode: **one byte**,
    /// at SND.NXT, which under `persistApplies` is also SND.UNA.
    ///
    /// One byte, and not "as much as fits", because nothing fits: the whole
    /// point of the persist condition is that the receiver's window admits
    /// nothing at all, and RFC 9293 §3.8.6.1 asks for "at least one octet of new
    /// data (if available)". Sending more would be a plain violation of the
    /// window the peer advertised, and this stack's own `Receiver` would drop it.
    ///
    /// The byte is REAL, accounted data -- an `InFlight` record, with SND.NXT
    /// advanced over it -- and that is load-bearing rather than tidy. The
    /// scenario persist exists for is a window update lost in flight (RFC 1122
    /// §4.2.2.17's DISCUSSION: "a connection may hang forever when an ACK
    /// segment that re-opens the window is lost"), which means the receiver's
    /// window may well be OPEN when the probe lands. It then accepts the byte
    /// and acknowledges SND.UNA + 1 -- and a sender that had sent the byte
    /// without advancing SND.NXT would find that acknowledgement outside RFC
    /// 9293 §3.10.7.4's acceptable-ACK window and answer its own recovery with a
    /// challenge ACK.
    ///
    /// PSH follows the same per-write rule as every other segment
    /// (`bytesRemainingInWrite`), so a one-byte write is pushed and the first
    /// byte of a hundred-byte one is not. Recorded on the `InFlight` record, so
    /// re-probing reproduces it exactly.
    private mutating func cutProbe(tcb: inout TCB) -> Segment? {
        let sent = tcb.sndNxt - tcb.sndUna
        guard sent == outstanding, sent < queuedBytes, inFlight.count < maximumSegments else { return nil }

        let sequence = tcb.sndNxt
        let pushes = bytesRemainingInWrite(from: sent) <= 1
        let payload = gather(offset: sent, length: 1)
        inFlight.append(
            InFlight(
                sequence: sequence, length: 1, transmissions: 1, sentAt: clock.now(), pushes: pushes,
                presumedLost: false, sacked: false))
        tcb.sndNxt = sequence + 1
        outstanding += 1
        probeOutstanding = true
        return Segment(sequence: sequence, flags: pushes ? [.ack, .psh] : .ack, payload: payload)
    }

    /// Bring the persist timer into line with the state this sender is in now.
    ///
    /// Arms it from `nil` and never re-arms an already-armed one; see
    /// `persistTimerDeadline` for why that asymmetry is the point.
    ///
    /// RFC 9293 SHLD-29 sets the first interval: "SHOULD send the first
    /// zero-window probe when a zero window has existed for the retransmission
    /// timeout period". So the ladder starts at the RTO *as it stands when
    /// persist begins* -- including any backoff a loss episode left on it, which
    /// is right: a path that has just been timing out is not one to probe
    /// aggressively.
    private mutating func updatePersistTimer(tcb: TCB) {
        guard persistApplies(tcb: tcb) else {
            persistTimerDeadline = nil
            persistTimerInterval = nil
            return
        }
        guard persistTimerDeadline == nil else { return }
        let interval = estimator.retransmissionTimeout
        persistTimerInterval = interval
        persistTimerDeadline = clock.now() + interval
    }

    /// Whether this sender is in RFC 9293 §3.8.6.1's persist condition.
    ///
    /// ## The window test is the RFC's usable window, not `SND.WND == 0`
    ///
    /// RFC 9293 §3.8.6.2.1 defines `U = SND.UNA + SND.WND - SND.NXT`, and this
    /// is `U <= 0`. Writing it as `SND.WND == 0` instead is a live wedge, not a
    /// nicety: a probe that draws `win 1` while its own byte is still
    /// outstanding leaves SND.WND at 1 and U at 0, so `SND.WND == 0` would end
    /// persist while `segmentsToTransmit` still has room for nothing -- and
    /// since no segment goes out, nothing arms the retransmission timer either,
    /// and the connection stops with no timer running at all.
    ///
    /// `U` is also allowed to go NEGATIVE, per RFC 9293 §3.8.6's MUST-34 on
    /// shrinking windows, which is why this is `<= 0` and not `== 0`.
    ///
    /// ## What happens on `win 1`, since that is the neighbouring question
    ///
    /// At `U >= 1` this condition is false, persist ends, and
    /// `segmentsToTransmit` sends the one byte the window admits. With no
    /// sender-side silly-window-syndrome avoidance -- RFC 9293 §3.8.6.2.1's
    /// MUST-38, which this stack does not yet implement -- a peer that reopens
    /// one byte at a time therefore gets a one-byte-per-round-trip crawl. That
    /// is poor and it is not a wedge, and it is deliberately preferred to
    /// staying in persist at `U >= 1`, which WOULD be a wedge: a receiver that
    /// is genuinely draining one byte at a time is making progress, and refusing
    /// to send into the window it opened would stall a connection that is
    /// working. SWS avoidance is the fix and it belongs with the Nagle
    /// interaction §3.8.6.2 describes, not here.
    ///
    /// ## Which timer runs when both would apply
    ///
    /// `outstanding == probeBytes` is the arbitration, and it makes persist and
    /// the retransmission timer **mutually exclusive by construction** rather
    /// than by policy:
    ///
    /// - **Ordinary data is outstanding and the window then shuts.** Persist is
    ///   off; the retransmission timer is running (RFC 6298 §5.1 armed it when
    ///   the data went out and §5.2 has not stopped it). That is the right one:
    ///   `retransmitTimerFired`'s retransmission is already unconditional in the
    ///   window, so the segment at SND.UNA goes out on the RTO ladder and IS a
    ///   window probe -- RFC 9293 §3.8.6.1 asks for "at least one octet of new
    ///   data (if available), **or retransmit**", and §3.8.6.1 requires the peer
    ///   to answer it: "When the receiving TCP peer has a zero window and a
    ///   segment arrives, it must still send an acknowledgment showing its next
    ///   expected sequence number and current window (zero)." Running persist as
    ///   well would double the probe traffic and buy nothing. RFC 1122
    ///   §4.2.2.17's DISCUSSION anticipates exactly this: "This procedure is
    ///   similar to that of the retransmission algorithm, and it may be possible
    ///   to combine the two procedures in the implementation."
    /// - **Nothing is outstanding and the window is shut.** RFC 6298 §5.2 has
    ///   stopped the retransmission timer, so persist is the only thing that can
    ///   move -- which is the whole gap this method closes.
    /// - **Only a probe of ours is outstanding.** Persist owns it and the
    ///   retransmission timer is deliberately never armed for it: nothing calls
    ///   `armTimer` on the probe path. If it were armed, `retransmitTimerFired`
    ///   would call `congestionControl.timeout` on every probe, collapsing cwnd
    ///   and ratcheting `ssthresh` down towards its `2 * SMSS` floor for the
    ///   whole life of a persist episode -- so a connection that had merely
    ///   waited out a slow reader would leave persist believing the *path* had
    ///   been congesting all along. A probe drawing no answer is not a
    ///   congestion signal; it is a receiver that is still full.
    ///
    /// ## And the same fail-closed rule `segmentsToTransmit` uses
    ///
    /// `sent == outstanding` refuses to act when SND.NXT has moved by an amount
    /// this type did not send -- a FIN, in practice. A probe cut at a SND.NXT
    /// that is one past a FIN would put a data byte after the end of the stream.
    /// The connection cannot wedge for want of a probe in that state either:
    /// `TCPEndpoint` is retransmitting the FIN on its own ladder, and the peer
    /// must acknowledge that with its current window just as it must a probe.
    private func persistApplies(tcb: TCB) -> Bool {
        let sent = tcb.sndNxt - tcb.sndUna
        // RFC 9293 §3.8.6.2.1's usable window, U.
        guard tcb.sndWnd - sent <= 0 else { return false }
        guard sent == outstanding else { return false }
        guard outstanding == (probeOutstanding ? 1 : 0) else { return false }
        // Something to probe WITH: an unsent byte, or a probe already on the
        // wire waiting to be sent again. RFC 9293 §3.8.6.1's "(if available)".
        // With neither, a closed window costs nothing -- the next write is what
        // starts an episode, and it comes through `segmentsToTransmit`.
        return unsentBytes > 0 || probeOutstanding
    }

    /// Retransmit as many presumed-lost segments as the window has room for,
    /// oldest first, **at most one transmission each per timeout episode**.
    ///
    /// ## What happens to `cwnd` on the second and later retransmissions
    ///
    /// Nothing. This method never touches the congestion window, and that is
    /// the design rather than an omission.
    ///
    /// `congestionControl.timeout(flightSize:)` is called EXACTLY ONCE per
    /// episode, by `retransmitTimerFired`. Every retransmission after it rides
    /// the window that one call left behind -- `cwnd = SMSS`, `ssthresh =
    /// max(FlightSize/2, 2*SMSS)` -- and the only thing that grows that window
    /// is `Reno.acked`, one segment per acknowledgement of new data. That is
    /// slow start doing exactly what slow start is for: the episode drains at
    /// 1, 2, 4, ... segments per round trip, and the connection leaves it
    /// holding a window every byte of which an acknowledgement paid for.
    ///
    /// The two edits that suggest themselves both disable slow start silently:
    ///
    /// - **`timeout(flightSize:)` per retransmission.** cwnd is then pinned at
    ///   one segment for the whole episode, so the drain never accelerates --
    ///   one segment per round trip rather than one per expiry, better but
    ///   still linear in the burst. Worse, each call recomputes `ssthresh` from
    ///   a FlightSize that is by then smaller, ratcheting it down: the
    ///   connection exits believing the path carries less than the ONE
    ///   congestion event it actually suffered says, and stays in congestion
    ///   avoidance at that floor for the rest of its life.
    /// - **Growing cwnd per retransmitted segment.** The window then opens on
    ///   transmissions instead of on acknowledgements, which is not slow start;
    ///   it is no congestion control at all. Nothing has left the network just
    ///   because this sender put something into it, so the connection would
    ///   leave the episode with a window the path never agreed to and a queue
    ///   of new data ready to spend it in one burst.
    ///
    /// `theWindowGrowsOnlyOnAcknowledgementsWhileTheBurstRecovers` pins the
    /// exact cwnd and ssthresh at every step of an episode, so both of those
    /// are test failures and not matters of taste.
    private mutating func drainPresumedLost(tcb: inout TCB, window: Int, segmentSize: Int) -> [Segment] {
        var out: [Segment] = []
        var index = 0

        while lostBytes > 0, index < inFlight.count {
            guard inFlight[index].presumedLost else {
                index += 1
                continue
            }
            // Whole segments only, hence `>= length` and not `> 0`. A
            // retransmission has to reproduce the segment that was lost byte
            // for byte -- its boundaries and its PSH are already on the peer's
            // wire -- so unlike new data there is no short one to cut, and
            // admitting it on `> 0` would put up to a segment more than
            // `min(cwnd, SND.WND)` into the network. Under a window too small
            // for one segment the drain stops and the timer's own unconditional
            // retransmission is what keeps the connection moving.
            //
            // A retransmission is charged a **whole segment's worth of window**
            // even when it is short, and that is the second half of the test.
            // A window is an estimate of what the path can carry, and what a
            // path carries is packets: a 26-byte retransmission occupies a slot
            // exactly as a 1420-byte one does. Charging it by its length lets a
            // window collapsed to a single segment -- which is what RFC 5681
            // §3.1 collapses it to, on the strongest possible evidence that the
            // path could not carry what it had -- send two packets, because the
            // first one happened to be short. gVisor and Linux both count this
            // window in segments for the same reason; the differential is where
            // the difference became visible, on a scenario whose first segment
            // was window-limited to 1380 bytes and left 40 bytes of slack.
            //
            // `min(segmentSize, window)` rather than `segmentSize`, so a peer
            // advertising less than one segment still gets its retransmissions:
            // the charge is "a segment, or the whole window if that is smaller",
            // not "a segment, or nothing".
            let charge = max(inFlight[index].length, min(segmentSize, window))
            guard window - pipeSize >= charge else { break }
            guard let segment = retransmit(index, tcb: &tcb) else { break }
            out.append(segment)
            index += 1
        }
        return out
    }

    /// Rebuild and re-send the oldest unacknowledged segment, leaving it
    /// queued and marking it ambiguous for Karn's algorithm.
    private mutating func retransmitOldest(tcb: inout TCB) -> Segment? {
        retransmit(0, tcb: &tcb)
    }

    /// Rebuild and re-send `inFlight[index]`, leaving it queued, clearing its
    /// presumed-lost mark, and marking it ambiguous for Karn's algorithm.
    ///
    /// Karn is untouched by everything above: the ambiguity flag is
    /// `transmissions`, it lives on the record, it is only ever incremented,
    /// and `retire` still refuses a sample from any record above one. So the
    /// SECOND and later retransmissions of an episode suppress their samples
    /// exactly as the first does -- and, because the marking above moves no
    /// record and renumbers nothing, there is no bookkeeping for Karn's flag to
    /// have been keyed on and lost.
    private mutating func retransmit(_ index: Int, tcb: inout TCB) -> Segment? {
        guard index >= 0, index < inFlight.count else { return nil }
        let entry = inFlight[index]
        let offset = entry.sequence - tcb.sndUna
        guard offset >= 0, offset + entry.length <= queuedBytes else { return nil }

        inFlight[index].transmissions += 1
        inFlight[index].sentAt = clock.now()
        if inFlight[index].presumedLost {
            inFlight[index].presumedLost = false
            lostBytes -= entry.length
        }
        return Segment(
            sequence: entry.sequence, flags: entry.pushes ? [.ack, .psh] : .ack,
            payload: gather(offset: offset, length: entry.length))
    }

    /// How many bytes of the WRITE containing the byte at `offset` (counted
    /// from SND.UNA) still remain, that byte included.
    ///
    /// This is what decides PSH. RFC 1122 §4.2.2.2, carried forward by
    /// RFC 9293 §3.9.1: a sender that does not expose a push flag on its send
    /// call — and `TCPEndpoint.send` does not — **MUST** set PSH on the last
    /// buffered segment, "when there is no more queued data to be sent". The
    /// unit that "queued data" is measured in is the write, not the whole
    /// queue, which is what makes a window-split write push on every piece
    /// while an MSS-split one pushes only on its last: at each cut, if the
    /// rest of the write already fits in one segment, nothing more of it will
    /// follow as a full segment and this is its last. Linux
    /// (`tcp_write_xmit`) and gVisor (`snd.go`'s `splitSeg`, which clears PSH
    /// only when the segment being split is larger than one MSS) both draw the
    /// line in exactly that place, and the differential against gVisor is what
    /// found this stack drawing it nowhere at all.
    ///
    /// A segment cut across a write boundary — possible only when two writes
    /// are queued together — takes its answer from the write it STARTS in,
    /// which is the write whose remainder it is completing.
    private func bytesRemainingInWrite(from offset: Int) -> Int {
        var skip = offset
        for chunk in chunks {
            let available = chunk.bytes.readableBytes
            if skip < available { return available - skip }
            skip -= available
        }
        // `offset` is past everything queued; there is nothing to cut, and
        // `segmentsToTransmit`'s loop condition has already stopped.
        return 0
    }

    // MARK: - RFC 6675, the scoreboard

    /// RFC 6675's DupThresh. Three, the same number RFC 5681 §3.2 counts to,
    /// and for the same reason: fewer than three reordered segments are common
    /// enough on a healthy path that treating them as loss would collapse the
    /// window on nothing.
    private static let duplicateThreshold = 3

    /// Mark the in-flight records the peer says it has.
    ///
    /// Whole records only. A block that covers part of a record leaves it
    /// unmarked, which is the conservative direction: an unmarked record is
    /// counted in `pipe` and may be retransmitted, so the cost of missing a
    /// partial arrival is bandwidth, while the cost of marking one that has not
    /// wholly arrived is a hole nothing ever fills. Records and blocks both come
    /// from segment boundaries, so a partial overlap means the peer is
    /// describing a segmentation this sender did not use -- and then guessing at
    /// its edges is exactly the wrong response.
    /// Returns whether anything was newly marked -- RFC 6675 §2's "previously
    /// unknown SACK information", which is what decides whether the
    /// acknowledgement carrying it counts as a duplicate at all.
    @discardableResult
    private mutating func recordSelectiveAcknowledgements(_ blocks: [SACKBlock], tcb: TCB) -> Bool {
        guard !blocks.isEmpty else { return false }
        var learned = false
        for index in inFlight.indices where !inFlight[index].sacked {
            let record = inFlight[index]
            let end = record.sequence + record.length
            // Above SND.UNA, and within what has been sent. A block outside
            // that is either stale or forged; either way there is no record it
            // can legitimately describe, and the loop simply does not find one.
            for block in blocks
            where !record.sequence.lessThan(block.left) && !block.right.lessThan(end) && record.length > 0 {
                inFlight[index].sacked = true
                sackedBytes += record.length
                learned = true
                noteDelivered(inFlight[index], at: clock.now())
                break
            }
        }
        return learned
    }

    /// The smallest round trip seen, which RACK's reordering window is a
    /// fraction of.
    ///
    /// The MINIMUM rather than the smoothed average, and §7.2 is specific about
    /// it: the window is meant to cover the reordering a path introduces, and a
    /// smoothed round trip that has been inflated by queuing would make the
    /// window grow exactly when loss detection most needs to be prompt.
    private mutating func noteRoundTrip(_ sample: TimeAmount) {
        guard sample > .zero else { return }
        guard let current = rack.minimumRoundTrip else {
            rack.minimumRoundTrip = sample
            return
        }
        if sample < current { rack.minimumRoundTrip = sample }
    }

    /// Record a delivered segment against RACK's view of send order.
    ///
    /// Only unambiguous transmissions count. A segment sent twice has an
    /// acknowledgement that may be answering either, so treating the second
    /// send's time as "the most recently sent thing that arrived" would date
    /// the comparison from a transmission the peer may never have seen --
    /// Karn's argument, applied to send order rather than to the round trip.
    /// **The ambiguity guard is not covered by a test, and saying so is the
    /// point.** Falsification did not fail against anything here: constructing a
    /// case where an ambiguous retransmission's arrival would mark other
    /// segments needs a connection that keeps sending BETWEEN an original and
    /// its retransmission, so that segments exist which are older than the
    /// retransmission, still unacknowledged, and not already marked by whatever
    /// caused the retransmission. Every ordinary path either acknowledges those
    /// segments or has already marked them.
    ///
    /// It stays because the reasoning is Karn's and the cost is one comparison:
    /// an acknowledgement of a segment sent twice may be answering either send,
    /// so dating "the most recently sent thing that arrived" from the second
    /// would measure from a transmission the peer may never have seen.
    private mutating func noteDelivered(_ record: InFlight, at now: NIODeadline) {
        guard record.transmissions == 1 else { return }
        let end = record.sequence + record.length
        if let previous = rack.mostRecentSend, record.sentAt <= previous {
            // Something sent EARLIER arrived after something sent later: that is
            // reordering, and it is the observation that opens the window. Until
            // a path shows reordering, waiting for it costs a round trip on
            // every loss and buys nothing.
            if let recorded = rack.mostRecentEnd, end.lessThan(recorded) {
                rack.sawReordering = true
            }
            return
        }
        rack.mostRecentSend = record.sentAt
        rack.mostRecentEnd = end
        rack.roundTrip = now > record.sentAt ? now - record.sentAt : .zero
        // §6.2 keeps its own minimum, from ITS samples. The estimator's minimum
        // would do for a connection whose acknowledgements advance SND.UNA, and
        // is empty for one whose only news is selective -- which is exactly the
        // connection RACK exists for.
        noteRoundTrip(rack.roundTrip)
    }

    /// RFC 8985 §6.2: mark lost everything sent before the most recently
    /// delivered segment that has not itself been delivered within the
    /// reordering window.
    ///
    /// Returns whether anything was newly marked.
    private mutating func detectLossByTime(tcb: inout TCB, flightSize: Int) -> Bool {
        guard rackEnabled, let mostRecentSend = rack.mostRecentSend, let mostRecentEnd = rack.mostRecentEnd
        else { return false }
        updateReorderWindow()
        let now = clock.now()
        // Recomputed from scratch on every pass. Keeping a stale deadline would
        // leave a timer armed for a segment that has since been acknowledged,
        // and the endpoint would wake to do nothing.
        rack.reorderDeadline = nil

        var newlyLost = false
        for index in inFlight.indices {
            let record = inFlight[index]
            guard !record.sacked, !record.presumedLost else { continue }
            // §6.2's two tests, and they are genuinely two.
            //
            // `RACK_sent_after` asks whether the delivered segment was sent
            // after this one -- by time, with sequence as the tie-break for a
            // flight that left in the same instant. The second asks whether
            // enough time has passed since this one was sent: its send time,
            // plus a round trip, plus the reordering window, against NOW.
            //
            // An earlier version compared the two SEND times against each other
            // and dropped the round trip. That collapses the two tests into one
            // -- a segment sent later than the delivered one has a negative
            // difference, which no window admits -- so the ordering test became
            // unfalsifiable, which is how the redundancy was noticed. It was
            // also wrong: without the round trip, a segment is called lost as
            // soon as something sent a window later arrives, rather than after
            // it has had a round trip to appear in.
            let end = record.sequence + record.length
            let sentAfter =
                mostRecentSend > record.sentAt
                || (mostRecentSend == record.sentAt && end.lessThan(mostRecentEnd))
            guard sentAfter else { continue }
            let deadline = record.sentAt + rack.roundTrip + rack.reorderWindow
            guard now >= deadline else {
                // Still inside its window. Remember the LATEST such deadline, so
                // one timer covers every segment waiting: an earlier one would
                // fire and find nothing to do for the segments behind it, and
                // the endpoint would have to re-arm on each.
                if let existing = rack.reorderDeadline {
                    if deadline > existing { rack.reorderDeadline = deadline }
                } else {
                    rack.reorderDeadline = deadline
                }
                continue
            }
            inFlight[index].presumedLost = true
            lostBytes += record.length
            newlyLost = true
        }
        guard newlyLost else { return false }
        enterScoreboardRecovery(tcb: &tcb, flightSize: flightSize)
        return true
    }

    /// The tail loss probe timer expired: send something to draw an
    /// acknowledgement.
    ///
    /// New data if there is any -- a probe that carries useful bytes costs
    /// nothing beyond the segment itself -- and otherwise the last segment
    /// again. Returns nil when the connection has moved on and there is nothing
    /// left to probe about, which is reachable because the endpoint re-arms this
    /// on every arriving segment.
    mutating func tailProbeTimerFired(tcb: inout TCB, mss: Int) -> Segment? {
        guard rackEnabled, !rack.probeSent, outstanding > 0 else { return nil }
        rack.probeSent = true
        // New data first. `segmentsToTransmit` applies the window and Nagle, so
        // a probe that would not have been allowed as data is not smuggled out
        // as a probe.
        let fresh = segmentsToTransmit(tcb: &tcb, mss: mss)
        if let first = fresh.first { return first }
        // Nothing new: the last segment again, which is what RFC 8985 §7.3 calls
        // for and is the only thing guaranteed to be answerable.
        guard !inFlight.isEmpty else { return nil }
        return retransmit(inFlight.count - 1, tcb: &tcb)
    }

    /// The reordering timer expired: look again.
    ///
    /// Returns whether anything was newly declared lost, so the caller knows
    /// whether there is a retransmission to send.
    @discardableResult
    mutating func rackReorderTimerFired(tcb: inout TCB) -> Bool {
        detectLossByTime(tcb: &tcb, flightSize: outstanding)
    }

    /// §7.2's window: a quarter of the smallest round trip seen, capped at the
    /// smoothed one -- and **zero only when there is already strong evidence of
    /// loss**.
    ///
    /// ## The condition is not "until reordering is seen", and the first version
    /// had it that way
    ///
    /// Reading §7.2 as "wait for reordering before opening the window" is the
    /// obvious reading and it is backwards. The window's default is
    /// `min_RTT / 4`; the ZERO is the special case, taken only when the sender
    /// is already in recovery or has counted DupThresh duplicate
    /// acknowledgements -- states in which something is known to have been lost
    /// and there is no reason to keep waiting.
    ///
    /// The difference is not academic. Under the wrong reading the very first
    /// selective acknowledgement of a connection declares everything below it
    /// lost, because nothing has had a chance to reorder yet -- a burst that
    /// arrives slightly out of order costs a retransmission and a halved window
    /// on a path with no loss at all. A test was written asserting exactly that
    /// behaviour and passed, which is what a test encoding a misreading looks
    /// like from the inside.
    private mutating func updateReorderWindow() {
        if !rack.sawReordering, recoveryPoint != nil || duplicates >= Self.duplicateThreshold {
            rack.reorderWindow = .zero
            return
        }
        let minimum = rack.minimumRoundTrip ?? estimator.smoothed
        let quarter = TimeAmount.nanoseconds(max(0, minimum.nanoseconds / 4))
        // Capped at the smoothed round trip -- §7.2 -- but only once there is
        // one. Before the estimator has a sample its smoothed value is zero, and
        // capping at zero would close the window on every connection whose
        // acknowledgements have not yet advanced SND.UNA. Those are the
        // connections RACK is for.
        rack.reorderWindow = estimator.smoothed > .zero ? min(quarter, estimator.smoothed) : quarter
    }

    /// RFC 6675 §4's `IsLost`, applied to every record, in one pass.
    ///
    /// Returns whether an episode is running because of the scoreboard. Nothing
    /// reads it any more -- RFC 6675 §2's redefinition of "duplicate" took over
    /// the job of standing the counter down, and it is a better test because it
    /// is about what the peer said rather than about what this method concluded
    /// -- but it is kept because it is the honest answer to the question the
    /// name asks, and a caller that needs it should not have to re-derive it.
    ///
    /// ## The pass runs backwards, and that is what makes it one pass
    ///
    /// `IsLost(S)` asks about what has been SACKed **above** S: more than
    /// DupThresh discontiguous runs, or more than `(DupThresh - 1) * SMSS`
    /// bytes. Asked forwards, each record would rescan everything above it --
    /// quadratic in the number of in-flight segments, which the peer's window
    /// and this sender's own cap put in the hundreds. Walking from the top
    /// down, both quantities are running totals of what has already been
    /// visited, so each record is O(1).
    private mutating func detectLossFromScoreboard(tcb: inout TCB, flightSize: Int) -> Bool {
        guard sackedBytes > 0, !inFlight.isEmpty else { return false }

        let segmentSize = max(1, congestionControl.segmentSize)
        // Not saturating arithmetic and not needing to be: the multiplier is
        // two and the segment size is already clamped to a sane range by the
        // MSS negotiation, so the product cannot approach the limit the way a
        // peer-supplied window can.
        let byteThreshold = (Self.duplicateThreshold - 1) * segmentSize
        var sackedAbove = 0
        var runsAbove = 0
        var aboveWasSacked = false
        var newlyLost = false

        for index in stride(from: inFlight.count - 1, through: 0, by: -1) {
            let record = inFlight[index]
            if record.sacked {
                sackedAbove += record.length
                // A run is a maximal stretch of SACKed records. Counting the
                // START of each is what makes "discontiguous" mean what the RFC
                // means by it: three separate arrivals above a hole are strong
                // evidence, three adjacent segments of one arrival are not.
                if !aboveWasSacked { runsAbove += 1 }
                aboveWasSacked = true
                continue
            }
            aboveWasSacked = false
            guard !record.presumedLost else { continue }
            guard runsAbove > Self.duplicateThreshold || sackedAbove > byteThreshold else { continue }
            inFlight[index].presumedLost = true
            lostBytes += record.length
            newlyLost = true
        }

        guard newlyLost else { return recoveryPoint != nil }
        enterScoreboardRecovery(tcb: &tcb, flightSize: flightSize)
        return true
    }

    /// Begin an RFC 6675 recovery episode, once.
    ///
    /// RecoveryPoint is SND.NXT at entry, so everything outstanding now has to
    /// be acknowledged before another reduction can be charged -- §5, and the
    /// same rule RFC 6582 states for NewReno. Re-entering would charge one loss
    /// event to the threshold twice.
    ///
    /// The record at SND.UNA is marked lost on the way in. Entry means this
    /// sender has decided the hole is real; without the mark the drain has
    /// nothing to send and the episode would run with the window reduced and no
    /// retransmission in it -- the worst of both.
    private mutating func enterScoreboardRecovery(tcb: inout TCB, flightSize: Int) {
        guard recoveryPoint == nil else { return }
        recoveryPoint = tcb.sndNxt
        congestionControl.lossDetectedWithScoreboard(flightSize: flightSize)
        if let first = inFlight.first, !first.presumedLost, !first.sacked {
            inFlight[0].presumedLost = true
            lostBytes += first.length
        }
    }

    // MARK: - Internals

    private mutating func armTimer() {
        timerDeadline = clock.now() + estimator.retransmissionTimeout
    }

    /// Drop the in-flight records the acknowledgement covers, take at most one
    /// RTT sample from them, and release the chunks whose bytes they were.
    private mutating func retire(
        previousUna: SequenceNumber, advanced: Int, timestampSample: TimeAmount? = nil,
        timestampsInUse: Bool = false
    ) {
        var sample: TimeAmount?
        var retired = 0

        for entry in inFlight {
            guard (entry.sequence - previousUna) + entry.length <= advanced else { break }
            noteDelivered(entry, at: clock.now())
            // Karn's algorithm. A segment sent more than once has an ambiguous
            // ACK -- it may be answering either transmission -- and a sample
            // taken from the wrong one corrupts the RTO for everything after
            // it. Later unambiguous segments in the same acknowledgement
            // overwrite this, so the sample used is the freshest one that is
            // safe to use, not merely the first.
            if entry.transmissions == 1 {
                sample = clock.now() - entry.sentAt
            }
            outstanding -= entry.length
            // A presumed-lost segment can be acknowledged without ever being
            // retransmitted -- the timeout was spurious and it was in the
            // network all along, or a later retransmission's cumulative
            // acknowledgement covered it. Either way it stops being owed, and
            // `lostBytes` has to lose it here or the episode never ends.
            if entry.presumedLost { lostBytes -= entry.length }
            // Same reasoning as `presumedLost` above, for the same reason: the
            // counter is a running total over the records, so a record leaving
            // has to take its contribution with it. A cumulative acknowledgement
            // routinely covers data the peer had already SACKed -- that is what
            // filling the hole looks like -- so this is the ordinary path, not
            // an edge case.
            if entry.sacked { sackedBytes -= entry.length }
            retired += 1
        }
        if retired > 0 { inFlight.removeFirst(retired) }

        // A peer may acknowledge part of a segment. What is left of it stays
        // outstanding, and stays ineligible for a sample until it is fully
        // acknowledged.
        if var partial = inFlight.first {
            let consumed = advanced - (partial.sequence - previousUna)
            if consumed > 0, consumed < partial.length {
                partial.sequence = partial.sequence + consumed
                partial.length -= consumed
                outstanding -= consumed
                if partial.presumedLost { lostBytes -= consumed }
                if partial.sacked { sackedBytes -= consumed }
                inFlight[0] = partial
            }
        }

        // RFC 7323 §4.1: a timestamp echo makes the measurement unambiguous, so
        // it is taken even from an acknowledgement Karn would refuse.
        //
        // **This is the point of the option, not a side effect.** Karn exists
        // because an acknowledgement of retransmitted data cannot be attributed
        // to a transmission — and the whole cost of that is that a connection
        // losing segments stops measuring the path exactly when the path has
        // changed. TSecr names the transmission being acknowledged, so the
        // ambiguity is gone and the sample is legitimate.
        //
        // `timestampSample` is preferred over `sample` when present rather than
        // averaged with it: they measure the same round trip, and the timestamp
        // one is valid in strictly more cases.
        //
        // ## RFC 7323 Appendix G, and it applies to BOTH samples
        //
        // Once timestamps are in use, a usable measurement arrives with every
        // acknowledgement rather than once per round trip -- and that is true of
        // the Karn-timed sample as well, because the connection is producing
        // acknowledgements at the same rate either way. RFC 6298's α = 1/8 and
        // β = 1/4 are chosen for one sample per round trip, so the appendix
        // divides both by the number expected in one, approximated as half the
        // flight.
        //
        // **And the sample is discarded outright when nothing is left
        // outstanding.** The appendix's `ExpectedSamples` is
        // `ceil(FlightSize / (2 * SMSS))`, and a flight of zero makes that zero
        // -- a division by zero, not a gain of one.
        //
        // That edge is what produced the residual disagreement this project
        // carried for the whole of the TCP work. The acknowledgement that
        // retires the last outstanding segment is exactly the one whose sample
        // is the full backed-off timeout; taking it moved this estimate from
        // 10 ms to 259 ms while gVisor's stayed at 10, and every retransmission
        // timed against it landed a step late. Both estimators were instrumented
        // rather than reasoned about, which is how it was found -- the previous
        // attempt reasoned, and reached a conclusion about Linux that turned out
        // not to describe gVisor at all.
        //
        // The flight is read AFTER retirement, which is what "still outstanding"
        // means and what gVisor's `s.Outstanding` holds at the same point.
        let chosen = timestampSample ?? sample
        if let chosen {
            if timestampsInUse {
                if !inFlight.isEmpty {
                    let expected = max(1, Int((Double(inFlight.count) / 2).rounded(.up)))
                    estimator.measure(chosen, expectedSamples: expected)
                }
            } else {
                estimator.measure(chosen)
            }
            noteRoundTrip(chosen)
        }
        trimChunks(by: advanced)
    }

    /// Release `count` acknowledged bytes from the front of the queue.
    ///
    /// A chunk's charge is refunded only when the whole chunk goes. Consuming
    /// a prefix moves a reader index, which releases no memory at all, so
    /// refunding for it would let `write` admit data against room that does
    /// not exist.
    private mutating func trimChunks(by count: Int) {
        var remaining = min(count, queuedBytes)
        var dropped = 0

        while remaining > 0, dropped < chunks.count {
            let available = chunks[dropped].bytes.readableBytes
            if available > remaining {
                chunks[dropped].bytes.moveReaderIndex(forwardBy: remaining)
                queuedBytes -= remaining
                remaining = 0
            } else {
                accountedBytes -= chunks[dropped].charge
                queuedBytes -= available
                remaining -= available
                dropped += 1
            }
        }
        if dropped > 0 { chunks.removeFirst(dropped) }
    }

    /// Copy `length` bytes starting `offset` bytes past SND.UNA out of the
    /// queue and into a fresh buffer -- a segment's payload, which may span
    /// several writes.
    private func gather(offset: Int, length: Int) -> ByteBuffer {
        var payload = ByteBufferAllocator().buffer(capacity: length)
        var skip = offset
        var remaining = length

        for chunk in chunks {
            if remaining == 0 { break }
            let available = chunk.bytes.readableBytes
            if skip >= available {
                skip -= available
                continue
            }
            let view = chunk.bytes.readableBytesView
            let start = view.startIndex + skip
            let take = min(available - skip, remaining)
            payload.writeBytes(view[start..<(start + take)])
            remaining -= take
            skip = 0
        }
        return payload
    }
}
