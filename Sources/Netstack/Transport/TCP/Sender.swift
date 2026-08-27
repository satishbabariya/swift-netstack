import NIOCore

/// The send side of a TCP connection: the queue of bytes the application has
/// written, the segments cut from it, and the machinery that decides when to
/// send them again.
///
/// This is the counterpart to `Receiver`, and the split between them is the
/// same one: `Receiver` owns RCV.NXT and the bytes coming in, this type owns
/// SND.UNA and the bytes going out, and `TCPStateMachine` owns the state. Only
/// one component advances any given sequence variable. `acknowledged` is
/// therefore the single place SND.UNA moves, and `segmentsToTransmit` the
/// single place SND.NXT does -- both take the TCB `inout` for exactly that
/// reason. The state machine still assigns SND.UNA in its own ACK path today
/// (RFC 9293 §3.10.7.4); that is the seam wiring this type in has to close, and
/// it belongs to the task that does the wiring, not here.
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
/// No SYN, no FIN, no zero-window probe, no Nagle, no SACK. It moves a byte
/// stream and nothing else: the control flags occupy sequence space that this
/// type's offsets do not model, which is why `segmentsToTransmit` refuses to
/// act when SND.NXT has moved by an amount it did not itself send (see there).
public struct Sender {
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
    public static let perChunkOverhead = 256

    /// `G` in RFC 6298's `RTO = SRTT + max(G, 4 * RTTVAR)`.
    ///
    /// One millisecond. `RTTEstimator` takes this injected so a differential
    /// can be reproduced against a stated granularity, but the sender's
    /// interface has nowhere to put it, so it is stated here instead of being
    /// hidden inside the estimator's default.
    public static let clockGranularity = TimeAmount.milliseconds(1)

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
    }

    /// The congestion-control algorithm, readable so a caller (and the tests)
    /// can see the window this sender is actually obeying rather than
    /// re-deriving it.
    public private(set) var congestionControl: any CongestionControl

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

    private var estimator: RTTEstimator
    private var timerDeadline: NIODeadline?
    private var duplicates = 0
    private var fastRetransmitPending = false

    /// The peer's last advertised window, as this type last saw it. Used only
    /// to tell a duplicate ACK from a window update -- see `acknowledged`.
    /// `nil` until the first acknowledgement, so the first one is never
    /// classified as a change against a window that was never advertised.
    private var lastAdvertisedWindow: Int?

    public init(congestionControl: any CongestionControl, clock: any NetstackClock, maximumBufferedBytes: Int) {
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
    public var flightSize: Int { outstanding }

    /// Transmitted, unacknowledged **segments**. Distinct from `flightSize`,
    /// which counts their bytes.
    public var unacknowledgedCount: Int { inFlight.count }

    /// Written but not yet transmitted. Non-zero means there is data the
    /// window, not the application, is holding back.
    public var unsentBytes: Int { max(0, queuedBytes - outstanding) }

    /// Total charge held: every queued chunk's allocation plus
    /// `perChunkOverhead` each. This is the figure `maximumBufferedBytes`
    /// bounds, and it is deliberately larger than the bytes written.
    public var bufferedBytes: Int { accountedBytes }

    /// Consecutive duplicate acknowledgements, by RFC 5681 §3.2's definition
    /// and not by "the ACK number repeated" -- see `acknowledged`.
    public var duplicateAcknowledgements: Int { duplicates }

    /// When the retransmission timer should next fire, or `nil` when it is
    /// off. The caller owns the actual timer; this type only says when.
    public var retransmitDeadline: NIODeadline? { timerDeadline }

    /// The current RTO, including any accumulated backoff.
    public var retransmissionTimeout: TimeAmount { estimator.retransmissionTimeout }

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
    public mutating func write(_ bytes: ByteBuffer) -> Bool {
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

    /// The segments to put on the wire now: a pending fast retransmission if
    /// there is one, then as much new data as `min(cwnd, SND.WND)` allows.
    ///
    /// SND.NXT is advanced over the new data before returning, so the caller
    /// must send everything returned. The fast retransmission is emitted here
    /// rather than from `acknowledged` because that method returns whether the
    /// ACK was acceptable, and a caller that acknowledges and then transmits
    /// -- the ordinary loop -- sends it in the same pass either way.
    public mutating func segmentsToTransmit(tcb: inout TCB, mss: Int) -> [Segment] {
        var out: [Segment] = []

        if fastRetransmitPending {
            fastRetransmitPending = false
            // Not gated on the window: RFC 5681 §3.2 retransmits the lost
            // segment and only then inflates cwnd, and the segment's bytes are
            // already counted in FlightSize, so sending it again consumes no
            // new window.
            if let segment = retransmitOldest(tcb: &tcb) { out.append(segment) }
        }

        // SND.NXT must be exactly where this type left it. If it is not,
        // something else has taken sequence space -- a FIN, most likely -- and
        // every offset below would be wrong by that amount. Fail closed rather
        // than sending bytes from the wrong place in the stream.
        let sent = tcb.sndNxt - tcb.sndUna
        guard sent == outstanding, sent <= queuedBytes else { return out }

        let segmentSize = max(1, mss)
        let window = max(0, min(congestionControl.congestionWindow, tcb.sndWnd))
        var usable = window - sent
        var unsent = queuedBytes - sent
        var offset = sent

        while unsent > 0, usable > 0, inFlight.count < maximumSegments {
            let length = min(segmentSize, min(unsent, usable))
            let sequence = tcb.sndNxt
            out.append(Segment(sequence: sequence, flags: .ack, payload: gather(offset: offset, length: length)))
            inFlight.append(InFlight(sequence: sequence, length: length, transmissions: 1, sentAt: clock.now()))
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
    /// The window half of that test is read from `tcb.sndWnd` against the
    /// value seen on the previous acknowledgement, which requires the caller
    /// to have applied RFC 9293 §3.10.7.4's window update before calling. A
    /// window update that happens to repeat the last ACK number is not a
    /// duplicate ACK, and counting it as one retransmits segments nothing was
    /// ever lost of, on an idle connection, invisibly until throughput is
    /// measured.
    public mutating func acknowledged(upTo ack: SequenceNumber, tcb: inout TCB, segmentLength: Int = 0) -> Bool {
        let windowChanged = lastAdvertisedWindow.map { $0 != tcb.sndWnd } ?? false
        lastAdvertisedWindow = tcb.sndWnd

        // RFC 9293 §3.10.7.4's acceptable-ACK window, inclusive at the bottom
        // so a duplicate naming SND.UNA reaches the counting below. Written as
        // a forward-distance range rather than a negated ordering: at exactly
        // half the sequence space `lessThan` is false in both directions, so
        // `!ack.lessThan(...)` would admit the one value a peer can compute
        // and send at will.
        guard ack.isInRange(from: tcb.sndUna, throughAndIncluding: tcb.sndNxt) else { return false }

        let advanced = ack - tcb.sndUna
        let flightBefore = outstanding

        if advanced == 0 {
            if segmentLength == 0, !windowChanged, flightBefore > 0 {
                duplicates += 1
                // RFC 5681 §3.2: the THIRD duplicate is the loss signal. The
                // first two are ordinary reordering.
                if duplicates == 3 {
                    congestionControl.lossDetected(flightSize: flightBefore)
                    fastRetransmitPending = true
                }
            } else {
                // Not a duplicate by §3.2's definition, so it does not extend
                // a run of them either.
                duplicates = 0
            }
            // Acceptable, but it retired nothing and the timer keeps running
            // against the transmission it was armed for -- RFC 6298 §5.3
            // restarts on new data only.
            return true
        }

        duplicates = 0
        fastRetransmitPending = false
        let previousUna = tcb.sndUna
        tcb.sndUna = ack
        retire(previousUna: previousUna, advanced: advanced)
        congestionControl.acked(bytes: advanced, flightSize: flightBefore)

        if inFlight.isEmpty {
            // RFC 6298 §5.2.
            timerDeadline = nil
        } else {
            // RFC 6298 §5.3.
            armTimer()
        }
        return true
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
    /// The backed-off RTO is not left doubled forever: `RTTEstimator.measure`
    /// recomputes the RTO from scratch, so the first unambiguous sample after
    /// the loss episode discards the accumulated backoff (RFC 6298 §5.7).
    /// Karn's algorithm is what makes that the *first unambiguous* sample and
    /// not the next one to arrive.
    public mutating func retransmitTimerFired(tcb: inout TCB) -> Segment? {
        // A timeout supersedes any duplicate-ACK run: the segment those
        // duplicates were pointing at is about to be resent anyway, and
        // counting the run across the timeout would fast-retransmit it again.
        duplicates = 0
        fastRetransmitPending = false

        guard !inFlight.isEmpty else {
            timerDeadline = nil
            return nil
        }

        congestionControl.timeout(flightSize: outstanding)
        estimator.backOff()
        armTimer()
        return retransmitOldest(tcb: &tcb)
    }

    /// Rebuild and re-send the oldest unacknowledged segment, leaving it
    /// queued and marking it ambiguous for Karn's algorithm.
    private mutating func retransmitOldest(tcb: inout TCB) -> Segment? {
        guard let first = inFlight.first else { return nil }
        let offset = first.sequence - tcb.sndUna
        guard offset >= 0, offset + first.length <= queuedBytes else { return nil }

        inFlight[0].transmissions += 1
        inFlight[0].sentAt = clock.now()
        return Segment(sequence: first.sequence, flags: .ack, payload: gather(offset: offset, length: first.length))
    }

    // MARK: - Internals

    private mutating func armTimer() {
        timerDeadline = clock.now() + estimator.retransmissionTimeout
    }

    /// Drop the in-flight records the acknowledgement covers, take at most one
    /// RTT sample from them, and release the chunks whose bytes they were.
    private mutating func retire(previousUna: SequenceNumber, advanced: Int) {
        var sample: TimeAmount?
        var retired = 0

        for entry in inFlight {
            guard (entry.sequence - previousUna) + entry.length <= advanced else { break }
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
                inFlight[0] = partial
            }
        }

        if let sample { estimator.measure(sample) }
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
