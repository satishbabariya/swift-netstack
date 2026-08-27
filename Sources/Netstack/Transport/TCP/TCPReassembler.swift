import NIOCore

/// Holds out-of-order TCP segments until the gaps between them fill, and
/// hands back the bytes that have become contiguous with RCV.NXT.
///
/// Named `TCPReassembler` rather than `Reassembler` because
/// `Network/Reassembler.swift` already declares that name in this module.
/// That file is worth reading before this one: its IPv4 reassembler had its
/// memory bound defeated three separate times, and every one of those failure
/// modes is reachable here too, because the shape of the problem is identical
/// — a peer chooses how much unfinishable work to leave pending.
///
/// ## What bounds this
///
/// Three caps, each closing something the others cannot.
///
/// `maximumBytes` bounds retained memory — but only because
/// `perSegmentOverhead` is charged on top of every queued piece's payload
/// length, and because every queued piece is copied into freshly allocated,
/// exactly-sized storage on admission. Both halves are needed and neither is
/// sufficient alone. A NIO `ByteBuffer` slice is copy-on-write: it holds a
/// live reference to the ENTIRE original allocation until something writes
/// into it, so a 1-byte segment sliced off a 1500-byte MTU frame and queued
/// as received pins 1500 bytes while the accounting sees 1. Copying fixes
/// that pinning and still leaves the accounting wrong, because a freshly
/// allocated, exactly-sized 1-byte copy costs far more than 1 byte: the array
/// element, the `ByteBuffer`'s backing storage class instance, and whatever
/// malloc's minimum bucket rounds that allocation up to — none of which
/// `payload.readableBytes` sees. Measured on this class: 2207 bytes of real
/// RSS per queued 1-byte segment with neither fix, 167.5 with the copy but
/// no overhead charge, against an accounted 1 byte either way. See
/// `perSegmentOverhead`.
///
/// `maximumSegments` bounds the queue's entry count independently of
/// `maximumBytes`, as cheap insurance against ever mis-measuring that
/// overhead again. If `perSegmentOverhead` were ever reverted to zero, a
/// flood of 1-byte segments would barely move the byte total; this cap holds
/// regardless of what the byte accounting believes.
///
/// `maximumSequenceOffset` bounds the sequence-space *domain*, which is a
/// correctness bound rather than a memory one — see below.
///
/// ## When a cap binds, the newcomer loses
///
/// The IPv4 reassembler evicts its oldest pending datagram to make room,
/// because an IP fragment that is dropped is gone for good and the datagram
/// it belonged to can never complete. TCP is not like that: a rejected
/// segment is harmless, because the peer's retransmission timer will send it
/// again. Evicting a queued segment to admit a new one would therefore throw
/// away data that has already been paid for and replace it with data of no
/// greater value — and it would hand a peer that floods junk out-of-order
/// segments a way to destroy a legitimate flow's queued data. So when a cap
/// binds, the arriving segment is refused and nothing queued is disturbed.
///
/// The one thing never refused is data that is already in order. In-order
/// bytes are handed straight back to the caller and never enter the queue, so
/// no cap applies to them. This is not an optimisation: if the segment that
/// fills a gap could be rejected for want of queue room, then a queue full of
/// the very segments waiting on that gap would refuse it, and the connection
/// would never make progress again.
///
/// ## Overlap policy
///
/// First-received-wins, at BYTE granularity — bytes already accepted are
/// never rewritten by a later segment. Byte granularity, not segment
/// granularity, is the difference from the IPv4 reassembler, which drops an
/// overlapping fragment whole. A correctly fragmenting IP sender never
/// produces overlapping fragments, so an overlap there is always either a
/// duplicate or an attack. A correct TCP sender produces them constantly: a
/// retransmission may repacketise, so a segment that repeats ten queued bytes
/// and extends twenty past them is ordinary. Dropping it whole would discard
/// the twenty novel bytes and wait for another retransmission to supply them.
/// So an arriving segment is trimmed against what is already queued and only
/// its novel sub-ranges are kept — which, being a subset of what was offered,
/// can only ever reduce what this class retains.
///
/// ## The `Comparable` hazard
///
/// `SequenceNumber` conforms to `Comparable` through RFC 1982 serial
/// arithmetic, and **that ordering is not a strict weak ordering over the
/// whole 32-bit space**: at exactly 2^31 apart neither value precedes the
/// other, and beyond that distance the relation is not transitive. Swift's
/// `sort`, `min` and `max` on a comparator that is not a strict weak ordering
/// produce silently garbled results. This is the first place in the stack
/// that holds a *collection* of sequence numbers, so it is the first place
/// that hazard is reachable, and it is closed structurally in two ways:
///
/// 1. **The domain is bounded on admission.** A segment whose distance past
///    RCV.NXT exceeds `maximumSequenceOffset` is refused outright, so every
///    queued offset lies in `[0, maximumSequenceOffset]` and the largest
///    distance between any two queued sequence numbers is that bound — a
///    quarter of the sequence space at most, far inside the region where RFC
///    1982 ordering is total. No legitimate peer can be affected: RFC 7323
///    caps the window scale at 14, so the largest window a peer can advertise
///    is under 2^30, and data beyond the advertised window is unacceptable to
///    the state machine anyway.
/// 2. **Nothing is ever ordered by `SequenceNumber`'s `<`.** Every comparison
///    below is between `Int` offsets from the caller's current RCV.NXT
///    (`sequence - rcvNxt`), which are window-bounded by construction and
///    totally ordered. `SequenceNumber`'s `<` is not called anywhere in this
///    file, and the queue is kept sorted by insertion position rather than by
///    ever calling `sort`.
///
/// The two are not equal partners, and it is worth being precise about which
/// is load-bearing. (1) is: it was falsified by removing it, and a segment
/// 0xC000_0000 ahead of RCV.NXT — three quarters of the space forward, which
/// `SequenceNumber`'s `-` cannot represent as a positive offset and therefore
/// reports as a large negative one — was handed to the application as though
/// it were the byte AT RCV.NXT. Remote injection into the receive stream, one
/// segment, no guessing.
///
/// (2) could NOT be falsified on its own: swapping every comparison here to
/// `SequenceNumber`'s `<` while leaving (1) in place changes no observable
/// behaviour, and cannot, because every queued offset is then a non-negative
/// `Int` below 2^31, so every pairwise distance is below 2^31 and the two
/// orderings provably agree. (2) is therefore insurance against a future edit
/// that widens or removes (1) — it keeps this file's correctness argument
/// local (offsets are ordinary `Int`s) instead of resting on a global claim
/// about how far apart the queue's sequence numbers can be, and it keeps
/// `sort`/`min`/`max` on a possibly-cyclic comparator off the table entirely.
/// That trap is real and silent: `[0xC000_0000, 0, 0x6000_0000]` as
/// `SequenceNumber`s answers `a < b`, `b < c` AND `c < a`, and `min()` and
/// `max()` over it both return 0x6000_0000, with no diagnostic.
///
/// Bound (1) is in fact enforced in four places — the admission guard, the
/// staleness guard beside it, `pruneOutsideDomain`, and `novelRanges`'
/// clamp at RCV.NXT — and all four had to be removed before the injection
/// above could be provoked. That redundancy is deliberate; none of the four
/// should be deleted as "already covered".
///
/// Offsets are stable under RCV.NXT advancing: two entries' offsets both
/// shift by the same amount, so their relative order never changes and the
/// queue never needs re-sorting.
///
/// ## The FIN seam
///
/// `insert` returns payload bytes, so a FIN arriving on an out-of-order
/// segment would otherwise be queued along with its data and silently lost —
/// the connection would never reach CLOSE-WAIT. `finSequence` closes that:
/// it records the sequence number a FIN occupies as soon as the FIN-bearing
/// segment is admitted, whether or not its data is deliverable yet, and the
/// caller acts on it when its own RCV.NXT has advanced to equal it. That
/// equality is the signal that the FIN is in order, and it cannot be reached
/// until every byte before the FIN has been delivered, so recording the FIN
/// early can never close a connection ahead of its data.
///
/// First-received-wins applies here too: a second FIN claiming a different
/// position never moves the first.
///
/// **That rule is not what makes the recorded position trustworthy, and it must
/// not be read as though it were.** It was, and the reasoning went: a FIN whose
/// position is behind RCV.NXT is ignored, so the caller has necessarily already
/// dealt with it. That covers a *later* FIN behind the true one and says nothing
/// whatever about a *first* FIN ahead of it — and a first FIN ahead of it is
/// free to claim any position it likes, permanently, from a segment carrying no
/// deliverable byte. A guest that guessed nothing at all could truncate a stream
/// (the application sees a clean EOF mid-stream while the bytes behind the
/// forged FIN are dropped) or wedge teardown forever (by claiming a position the
/// stream never reaches, so the peer's real FIN is never acted on).
///
/// What makes the position trustworthy is the caller: `TCPStateMachine` honours
/// a FIN only on a segment that starts at exactly RCV.NXT and whose FIN sits
/// inside the offered window, and strips the flag otherwise — the RFC 5961
/// treatment it already gives a RST, for a flag whose blast radius is much the
/// same. So a FIN reaching this class has been accepted in sequence and there is
/// nothing left to re-validate. First-received-wins is then about duplicates
/// only, which is all it was ever able to be about.
///
/// This class keeps its own domain guard on the recorded position — behind
/// RCV.NXT or past `maximumSequenceOffset` and it is not recorded — because that
/// is what keeps `finSequence`, like every queued offset, inside the bounded
/// domain this file's offset arithmetic requires. It is a domain bound, not a
/// security check, and it is not a second opinion about whether the FIN is
/// legitimate: this class deliberately does not have one.
public final class TCPReassembler {
    /// The real, per-segment cost of holding one queued piece: the array
    /// element, the `ByteBuffer`'s backing storage object, and malloc's
    /// rounding of that tiny allocation — none of which shows up in
    /// `payload.readableBytes`.
    ///
    /// Measured for this class, not inherited from the IPv4 reassembler's
    /// 176. Queueing 264,000 one-byte out-of-order segments behind a
    /// permanent gap, with copy-on-admission in place and this constant set
    /// to zero, and reading real RSS growth from `getrusage` (debug build,
    /// arm64 macOS, run in isolation so no sibling test moves the process
    /// high-water mark): **167.5 bytes of resident memory per queued 1-byte
    /// segment**, against an accounted 264,000 bytes — a factor of 167. The
    /// count is picked just past a power of two so the array's doubling has
    /// overshot to nearly 2x, which is the worst case for the array-element
    /// share of that figure.
    ///
    /// 256 is charged: above every measurement taken, with headroom that a
    /// future `Entry` field or a different allocator will not immediately
    /// eat. (176, this class's first guess and the IPv4 reassembler's
    /// constant, would have left 5%.) The cost of over-charging is only that
    /// a queue of very small segments fills sooner, which is the right
    /// direction to be wrong in: the cap must bound what is actually
    /// retained, not what was declared on the wire.
    public static let perSegmentOverhead = 256

    /// The furthest past RCV.NXT a segment may sit and still be queued.
    ///
    /// A quarter of the sequence space. Above every window a peer can
    /// legitimately advertise (RFC 7323 caps window scale at 14, so under
    /// 2^30), and far below the 2^31 distance at which RFC 1982 ordering
    /// stops being total. See the type's doc comment.
    public static let maximumSequenceOffset = 1 << 30

    /// Enough for a full 64 KiB receive window of ordinary 1460-byte segments
    /// (~45 of them, ~73 KB once overhead is charged) with generous headroom,
    /// so ordinary reordering is absorbed rather than forced into
    /// retransmission.
    public static let defaultMaximumBytes = 256 * 1024

    /// Bounds entry count independently of `defaultMaximumBytes`. Well above
    /// the ~45 segments a full receive window of ordinary segments occupies,
    /// and low enough that a flood of minimal segments hits it long before
    /// the byte cap.
    public static let defaultMaximumSegments = 512

    /// One contiguous run of queued bytes. `bytes` is always freshly
    /// allocated, exactly-sized storage — never the slice it arrived in; see
    /// the type's doc comment. `charge` is what was added to `accountedBytes`
    /// on admission and is refunded verbatim on removal, so trimming an
    /// entry's already-delivered prefix (which moves a reader index without
    /// shrinking the underlying allocation) can never make the accounting
    /// drift below what is really retained.
    private struct Entry {
        var sequence: SequenceNumber
        var bytes: ByteBuffer
        let charge: Int
    }

    private let maximumBytes: Int
    private let maximumSegments: Int
    private let maximumOffset: Int

    /// Queued out-of-order runs, sorted ascending by offset from RCV.NXT and
    /// pairwise disjoint. Both invariants are maintained by construction:
    /// insertions go to a binary-searched position, and an arriving segment
    /// is trimmed against this queue before any of it is admitted.
    private var queue: [Entry] = []
    private var accountedBytes = 0
    private var fin: SequenceNumber?

    /// - Parameters:
    ///   - maximumBytes: cap on `pendingBytes`, which counts
    ///     `perSegmentOverhead` per queued run on top of its payload length.
    ///   - maximumSegments: cap on `pendingSegments`, enforced independently
    ///     of `maximumBytes`.
    ///   - maximumSequenceOffset: how far past RCV.NXT a segment may sit and
    ///     still be queued. Clamped to `TCPReassembler.maximumSequenceOffset`
    ///     from above, so no caller can widen the domain into the range where
    ///     RFC 1982 ordering stops being total — that bound is a correctness
    ///     invariant of this class, not a tunable.
    public init(
        maximumBytes: Int = TCPReassembler.defaultMaximumBytes,
        maximumSegments: Int = TCPReassembler.defaultMaximumSegments,
        maximumSequenceOffset: Int = TCPReassembler.maximumSequenceOffset
    ) {
        self.maximumBytes = max(0, maximumBytes)
        self.maximumSegments = max(0, maximumSegments)
        self.maximumOffset = min(max(1, maximumSequenceOffset), TCPReassembler.maximumSequenceOffset)
    }

    /// Total charge held by the queue: every queued run's payload length plus
    /// `perSegmentOverhead` each. This is the figure `maximumBytes` bounds,
    /// and it is deliberately larger than the payload bytes alone — see
    /// `perSegmentOverhead`.
    public var pendingBytes: Int { accountedBytes }

    /// Number of queued contiguous runs. One arriving segment can become more
    /// than one run when it straddles a gap between runs already queued.
    public var pendingSegments: Int { queue.count }

    /// How much of `maximumBytes` is still free, in the same (overhead-charged)
    /// units `pendingBytes` reports.
    ///
    /// Exists so that `Receiver` can derive the window it advertises from the
    /// one place that knows the cap, rather than being handed `maximumBytes` a
    /// second time and subtracting for itself. A second copy of the cap is a
    /// second thing to keep in step with this one.
    ///
    /// Conservative on purpose: because `pendingBytes` charges
    /// `perSegmentOverhead` per queued run, this is smaller than the payload
    /// room actually left, so a window derived from it under-promises. That is
    /// the right direction — the alternative advertises space the queue would
    /// then refuse.
    public var availableBytes: Int { max(0, maximumBytes - accountedBytes) }

    /// The sequence number a FIN occupies, once one has been seen at or ahead
    /// of RCV.NXT. The caller's FIN is in order when its own RCV.NXT equals
    /// this. See the type's doc comment.
    public var finSequence: SequenceNumber? { fin }

    /// Diagnostic: the total `ByteBuffer.storageCapacity` of every queued
    /// run's payload — the size of the allocations those payloads keep alive,
    /// not the number of bytes they declare. Not `private`, because
    /// `@testable import` elevates `internal` and not `private`.
    ///
    /// This exists to make copy-on-admission (see the type's doc comment)
    /// falsifiable by a test without measuring anything. `storageCapacity`
    /// reports the whole backing allocation a `ByteBuffer` references, so it
    /// separates the two cases exactly and with no noise between them: a
    /// fresh, exactly-sized 1-byte copy reports 1, while an uncopied 1-byte
    /// slice of a 1500-byte MTU frame reports 2048 (NIO rounds capacity up to
    /// a power of two). COW pinning is precisely what `storageCapacity` sees.
    ///
    /// It is deliberately NOT a substitute for `perSegmentOverhead`, and the
    /// two failures must not be conflated. Real per-segment retention cost —
    /// the array element, the backing storage object's own class header,
    /// malloc's minimum bucket — is invisible here: with the overhead charge
    /// set to zero, every queued entry still holds an exactly-sized 1-byte
    /// copy and this number is still 1 per entry, while 200,000 of them are
    /// retained instead of 778. `pendingSegments` is what bounds that. This
    /// number bounds pinning, not footprint.
    ///
    /// O(queued runs); for tests and diagnostics only, never on a packet path.
    var pendingStorageCapacityForTesting: Int {
        queue.reduce(0) { $0 + $1.bytes.storageCapacity }
    }

    /// Offer one segment. Returns the payload bytes that are now contiguous
    /// with `rcvNxt`, oldest first — possibly bytes from earlier segments
    /// this one unblocked, possibly none at all.
    ///
    /// The caller advances its own RCV.NXT by the total `readableBytes` of
    /// the returned buffers, then checks `finSequence` against it.
    ///
    /// Returned buffers are slices of the segment handed in, not copies:
    /// nothing here retains them past the call, so copying them would be
    /// pointless work on the in-order path. Only bytes that must be *held*
    /// are copied.
    public func insert(_ segment: Segment, rcvNxt: SequenceNumber) -> [ByteBuffer] {
        // Defensive: the caller's RCV.NXT is an argument, so nothing here can
        // assume it only ever moves the way this class's own return values
        // moved it. Re-establish "every queued offset is in
        // [0, maximumOffset]" against the RCV.NXT actually supplied, before
        // any offset arithmetic depends on it.
        pruneOutsideDomain(rcvNxt: rcvNxt)

        let segmentStart = segment.sequence - rcvNxt
        let segmentEnd = segmentStart + segment.length

        // Refuse anything outside the admissible domain rather than trying to
        // order it. `segmentStart` is a signed 32-bit distance, so a segment
        // at or beyond 2^31 ahead reads as a large NEGATIVE offset and is
        // caught by the staleness guard below instead — either way it never
        // reaches the queue.
        guard segmentStart <= maximumOffset, segmentEnd <= maximumOffset else { return [] }

        // Entirely behind RCV.NXT: every byte of it has already been
        // delivered, so there is nothing to keep and no FIN worth recording.
        guard segmentEnd > 0 else { return [] }

        let dataStart = segment.dataSequence - rcvNxt
        let dataEnd = dataStart + segment.payload.readableBytes

        // Record the FIN before anything can reject this segment's data. The
        // FIN's position is knowable whether or not its bytes fit, and acting
        // on it requires RCV.NXT to reach it, which requires the data. See
        // the type's doc comment -- including what this guard is and is not:
        // a domain bound on the offset, not a judgement about whether the FIN
        // may be honoured. That judgement is the caller's, and it is made
        // before the flag ever gets here.
        //
        // `segment.finSequence` rather than `rcvNxt + dataEnd`: the two are the
        // same number, and one of them has to be the definition (see
        // `Segment.finSequence`). `dataEnd` remains the offset the bound is
        // expressed in.
        if let finPosition = segment.finSequence, fin == nil, dataEnd >= 0, dataEnd <= maximumOffset {
            fin = finPosition
        }

        let pieces = novelRanges(dataStart: dataStart, dataEnd: dataEnd, rcvNxt: rcvNxt)
        return admit(pieces: pieces, of: segment, dataStart: dataStart, rcvNxt: rcvNxt)
    }

    /// Forget everything queued. For a connection being torn down.
    public func reset() {
        queue.removeAll()
        accountedBytes = 0
        fin = nil
    }

    // MARK: - Trimming an arriving segment against what is already queued

    /// The sub-ranges of `[dataStart, dataEnd)` (in offset space) that are
    /// not already covered by a queued run, clipped at RCV.NXT. Ascending,
    /// disjoint. First-received-wins is exactly this subtraction.
    private func novelRanges(dataStart: Int, dataEnd: Int, rcvNxt: SequenceNumber) -> [(start: Int, end: Int)] {
        var cursor = max(dataStart, 0)
        guard dataEnd > cursor else { return [] }

        var ranges: [(start: Int, end: Int)] = []
        var index = firstIndex(endingAfter: cursor, rcvNxt: rcvNxt)
        while index < queue.count, cursor < dataEnd {
            let start = queue[index].sequence - rcvNxt
            guard start < dataEnd else { break }
            let end = start + queue[index].bytes.readableBytes
            if start > cursor {
                ranges.append((start: cursor, end: start))
            }
            cursor = max(cursor, end)
            index += 1
        }
        if cursor < dataEnd {
            ranges.append((start: cursor, end: dataEnd))
        }
        return ranges
    }

    // MARK: - Delivery and admission

    /// Walk the queue and the arriving segment's novel ranges together in
    /// offset order, handing back everything contiguous from offset zero and
    /// queueing whatever is left that fits.
    ///
    /// Delivery is computed over the merge of the two rather than over the
    /// queue alone, because an arriving segment can be contiguous with
    /// RCV.NXT, straddle a queued run, and continue past it — `[1000, 1030)`
    /// arriving with `[1010, 1020)` already queued becomes two novel ranges,
    /// and the second is deliverable only once the queued run between them
    /// has been. Anything the walk reaches is delivered without ever being
    /// queued, charged, or copied, which is also what makes in-order data
    /// exempt from the caps.
    private func admit(
        pieces: [(start: Int, end: Int)], of segment: Segment, dataStart: Int, rcvNxt: SequenceNumber
    ) -> [ByteBuffer] {
        var delivered: [ByteBuffer] = []
        var reach = 0
        var queueIndex = 0
        var pieceIndex = 0

        while queueIndex < queue.count || pieceIndex < pieces.count {
            let queueStart = queueIndex < queue.count ? (queue[queueIndex].sequence - rcvNxt) : Int.max
            let pieceStart = pieceIndex < pieces.count ? pieces[pieceIndex].start : Int.max
            if queueStart <= pieceStart {
                guard queueStart <= reach else { break }
                reach = max(reach, queueStart + queue[queueIndex].bytes.readableBytes)
                delivered.append(queue[queueIndex].bytes)
                queueIndex += 1
            } else {
                guard pieceStart <= reach else { break }
                reach = max(reach, pieces[pieceIndex].end)
                delivered.append(slice(of: segment, range: pieces[pieceIndex], dataStart: dataStart))
                pieceIndex += 1
            }
        }

        if queueIndex > 0 {
            for entry in queue[0..<queueIndex] {
                accountedBytes -= entry.charge
            }
            queue.removeFirst(queueIndex)
        }

        // Whatever is still behind a gap has to be held. This is the only
        // path that costs memory, so it is the only path the caps guard. A
        // piece that does not fit is dropped and the peer retransmits it;
        // nothing already queued is evicted to make room. Once one piece does
        // not fit, no later piece will either, so the loop stops.
        for piece in pieces[pieceIndex...] {
            guard queue.count < maximumSegments else { break }
            let length = piece.end - piece.start
            let charge = length + Self.perSegmentOverhead
            guard accountedBytes + charge <= maximumBytes else { break }

            var copy = ByteBufferAllocator().buffer(capacity: length)
            copy.writeBytes(slice(of: segment, range: piece, dataStart: dataStart).readableBytesView)
            let entry = Entry(sequence: rcvNxt + piece.start, bytes: copy, charge: charge)
            queue.insert(entry, at: insertionIndex(forOffset: piece.start, rcvNxt: rcvNxt))
            accountedBytes += charge
        }

        return delivered
    }

    /// The arriving segment's own bytes for one offset-space range. Safe by
    /// construction: `range` came from `novelRanges`, which clips to
    /// `[max(dataStart, 0), dataEnd)`, so the index is inside the payload.
    private func slice(of segment: Segment, range: (start: Int, end: Int), dataStart: Int) -> ByteBuffer {
        let index = segment.payload.readerIndex + (range.start - dataStart)
        return segment.payload.getSlice(at: index, length: range.end - range.start) ?? ByteBuffer()
    }

    // MARK: - Domain maintenance

    /// Re-establish "every queued offset is in `[0, maximumOffset]`" against
    /// the RCV.NXT supplied by this call.
    ///
    /// Under normal use this does nothing: RCV.NXT advances only over bytes
    /// this class delivered, and delivered runs left the queue as they were
    /// delivered. It exists because RCV.NXT is a caller-supplied argument,
    /// and the domain bound is what makes every offset comparison in this
    /// file well defined — an invariant worth re-establishing unconditionally
    /// rather than assuming. A run partly behind RCV.NXT keeps its original
    /// `charge` when trimmed, since moving a reader index does not release
    /// the allocation behind it.
    private func pruneOutsideDomain(rcvNxt: SequenceNumber) {
        var firstLive = 0
        while firstLive < queue.count {
            let start = queue[firstLive].sequence - rcvNxt
            let end = start + queue[firstLive].bytes.readableBytes
            if end <= 0 {
                accountedBytes -= queue[firstLive].charge
                firstLive += 1
                continue
            }
            if start < 0 {
                queue[firstLive].bytes.moveReaderIndex(forwardBy: -start)
                queue[firstLive].sequence = rcvNxt
            }
            break
        }
        if firstLive > 0 {
            queue.removeFirst(firstLive)
        }
        while let last = queue.last, last.sequence - rcvNxt > maximumOffset {
            accountedBytes -= last.charge
            queue.removeLast()
        }
    }

    // MARK: - Ordered by Int offset, never by SequenceNumber

    /// Index of the first queued run whose end offset is past `offset`. The
    /// queue is sorted and disjoint, so end offsets are strictly increasing
    /// and this is a plain binary search — over `Int` offsets, never over
    /// `SequenceNumber` (see the type's doc comment).
    private func firstIndex(endingAfter offset: Int, rcvNxt: SequenceNumber) -> Int {
        var low = 0
        var high = queue.count
        while low < high {
            let mid = low + (high - low) / 2
            let end = (queue[mid].sequence - rcvNxt) + queue[mid].bytes.readableBytes
            if end <= offset {
                low = mid + 1
            } else {
                high = mid
            }
        }
        return low
    }

    /// Where a run starting at `offset` belongs, keeping the queue sorted
    /// ascending by offset. Again an `Int` comparison, not a
    /// `SequenceNumber` one.
    private func insertionIndex(forOffset offset: Int, rcvNxt: SequenceNumber) -> Int {
        var low = 0
        var high = queue.count
        while low < high {
            let mid = low + (high - low) / 2
            if (queue[mid].sequence - rcvNxt) < offset {
                low = mid + 1
            } else {
                high = mid
            }
        }
        return low
    }
}
