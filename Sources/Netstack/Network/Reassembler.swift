import NIOCore

/// Reassembles IPv4 fragments into whole datagrams.
///
/// Bounded on three axes, because an incomplete datagram is otherwise an
/// unbounded allocation a peer controls: each pending datagram expires after
/// `timeout`; the memory actually retained across all of them is capped at
/// `memoryLimit`; and the number of concurrently pending datagrams is capped
/// at `maximumPendingDatagrams` — independently of `memoryLimit`, because a
/// flood of minimal fragments (as little as 1 byte each) spread across many
/// different datagram IDs barely moves the byte total while still costing one
/// full entry — a header, an array, and a dictionary slot — per datagram. Both
/// caps evict oldest-first, in the order entries were created.
///
/// Each admitted fragment's payload is copied into freshly allocated,
/// exactly-sized storage rather than kept as the `ByteBuffer` slice it
/// arrived in. NIO's `getSlice` (and everything built on it, including how a
/// fragment reaches here from `PacketBuffer`) is copy-on-write: a slice keeps
/// a live reference to the ENTIRE original allocation until something writes
/// into it, so an uncopied 1-byte fragment sliced from a 1500-byte MTU frame
/// pins all 1500 bytes, not 1. `holdingBytes`/`heldBytes`/`memoryLimit` count
/// payload length either way, but only the copy makes that count track real
/// retained memory — without it, `memoryLimit` bounds the accounting, not the
/// actual allocation behind it, and the two can diverge by orders of
/// magnitude.
///
/// A correctly fragmenting sender never produces two fragments that claim
/// the same byte, so any incoming fragment whose byte range overlaps a
/// range already accepted for that datagram — an exact duplicate, a partial
/// overlap, or a second "final fragment" that disagrees with the first
/// about where the datagram ends — is dropped outright rather than merged.
/// Data that arrived first always wins; nothing already accepted is ever
/// silently rewritten by a later fragment. This is what closes the classic
/// overlapping-fragment ("teardrop") rewrite, and it also keeps a flood of
/// duplicate fragments from inflating this reassembler's own memory
/// accounting to evict unrelated, legitimate datagrams.
public final class Reassembler {
    /// RFC 791: total length is a 16-bit field.
    private static let maximumDatagram = 65535

    /// A fragmenting sender's job is to keep the receiver's job small: real
    /// IP fragmentation is rare in the first place, and a legitimate flow
    /// through one gateway to one guest is never fragmenting more than a
    /// handful of datagrams at once. This is generous headroom over that —
    /// enough to absorb a burst of ordinary reordering across many flows —
    /// while still bounding worst-case per-entry overhead (a header, an
    /// array, and a dictionary slot each) to a small, constant amount
    /// regardless of how minimal an attacker makes each fragment.
    public static let defaultMaximumPendingDatagrams = 1024

    private struct Key: Hashable {
        let source: IPv4Address
        let destination: IPv4Address
        let identification: UInt16
        let protocolNumber: UInt8
    }

    private struct Pending {
        var header: IPv4Header
        var received: [(offset: Int, bytes: ByteBuffer)] = []
        var holdingBytes = 0
        /// Set when the fragment carrying the end of the datagram arrives.
        var totalLength: Int?
        let startedAt: NIODeadline
    }

    private let clock: NetstackClock
    private let timeout: TimeAmount
    private let memoryLimit: Int
    private let maximumPendingDatagrams: Int
    private var pending: [Key: Pending] = [:]
    private var heldBytes = 0
    /// Every live key, oldest first — the order entries were created in, not
    /// the order they were last touched in (a fragment for an existing
    /// datagram never moves its position). Backs both eviction caps with an
    /// amortized O(1) "next oldest" instead of the O(n) table scan
    /// `pending.min(by: startedAt)` used to require on every admission while
    /// at the memory cap. `admissionOrderHead` is the index of the oldest
    /// entry that might still be live; entries at or before it may already
    /// be gone (completed, expired, or evicted) and are skipped lazily
    /// rather than removed from the middle of the array.
    private var admissionOrder: [Key] = []
    private var admissionOrderHead = 0

    public init(
        clock: NetstackClock, timeout: TimeAmount = .seconds(30), memoryLimit: Int = 4 * 1024 * 1024,
        maximumPendingDatagrams: Int = Reassembler.defaultMaximumPendingDatagrams
    ) {
        self.clock = clock
        self.timeout = timeout
        self.memoryLimit = memoryLimit
        self.maximumPendingDatagrams = max(1, maximumPendingDatagrams)
    }

    public var pendingCount: Int { pending.count }

    /// Diagnostic only: the total storage capacity retained by every byte
    /// buffer currently held across every pending fragment — as opposed to
    /// `heldBytes` (private) and the `memoryLimit` it is checked against,
    /// which count RFC-declared payload bytes. Before fragments were copied
    /// into fresh, exactly-sized storage on admission, this number could be
    /// orders of magnitude larger than the payload-byte accounting, because
    /// an uncopied slice pins the entire frame it was carved out of.
    public var heldStorageBytes: Int {
        pending.values.reduce(0) { total, entry in
            total + entry.received.reduce(0) { $0 + $1.bytes.storageCapacity }
        }
    }

    /// Feed one fragment in. Returns the whole datagram once it is complete,
    /// nil while it is still missing pieces or the fragment was rejected.
    public func process(header: IPv4Header, payload: ByteBuffer) -> (IPv4Header, ByteBuffer)? {
        let isFragment = header.flags.contains(.moreFragments) || header.fragmentOffset > 0
        guard isFragment else { return (header, payload) }

        // A fragment carrying no payload conveys nothing and cannot be part of a
        // legitimate datagram, but it evades both the overlap test (a zero-width
        // interval never intersects) and the memory cap (it adds zero bytes), so
        // it is refused rather than tracked.
        guard payload.readableBytes > 0 else { return nil }

        let offset = header.fragmentOffset
        let length = payload.readableBytes
        let end = offset + length

        let key = Key(
            source: header.source,
            destination: header.destination,
            identification: header.identification,
            protocolNumber: header.protocolNumber.rawValue
        )

        let isNewEntry = pending[key] == nil
        var entry = pending[key] ?? Pending(header: header, startedAt: clock.now())

        // Bound the datagram as it will be ASSEMBLED, not as this fragment
        // arrives. `entry.header` is fixed by whichever fragment created the
        // entry and may carry options, while `totalLength` comes from whichever
        // fragment terminates it — checking the incoming fragment's own header
        // ties none of them together and lets three individually-admissible
        // fragments overflow the conversion at assembly.
        guard entry.header.headerLength + end <= Self.maximumDatagram else { return nil }

        // Reject any fragment that overlaps a byte range already accepted
        // for this datagram (including an exact duplicate), and reject a
        // second "final fragment" that disagrees with the first about where
        // the datagram ends. First-received data always wins.
        let overlapsExisting = entry.received.contains { existing in
            offset < existing.offset + existing.bytes.readableBytes && existing.offset < end
        }
        guard !overlapsExisting else { return nil }
        if !header.flags.contains(.moreFragments), let existingTotal = entry.totalLength, existingTotal != end {
            return nil
        }

        // Copy into fresh, exactly-sized storage rather than keep `payload`
        // as received. `payload` reached here through a chain of NIO
        // `getSlice`/`readSlice` calls (see `PacketBuffer`), which are
        // copy-on-write: the slice shares the ENTIRE original frame's
        // storage until something writes into it. Stored as-is, a 1-byte
        // fragment sliced from a 1500-byte MTU frame would pin all 1500
        // bytes for as long as this entry stays pending, not 1 — silently
        // defeating `memoryLimit`, which only ever sees the 1-byte count.
        var copy = ByteBufferAllocator().buffer(capacity: length)
        copy.writeBytes(payload.readableBytesView)
        entry.received.append((offset: offset, bytes: copy))
        entry.holdingBytes += length
        heldBytes += length
        if !header.flags.contains(.moreFragments) {
            entry.totalLength = end
        }

        if isNewEntry {
            // A flood of minimal fragments across many different datagram
            // IDs can hold `heldBytes` far under `memoryLimit` while still
            // creating one entry per datagram — this cap is independent of
            // that one for exactly that reason.
            if pending.count >= maximumPendingDatagrams {
                evictOldest()
            }
            admissionOrder.append(key)
        }
        pending[key] = entry

        if let complete = assemble(key: key) {
            return complete
        }
        enforceMemoryLimit()
        pruneStaleOrderHead()
        return nil
    }

    /// Drop every datagram that has been incomplete for longer than the
    /// timeout. Called from the stack's periodic maintenance timer.
    public func reapExpired() {
        let deadline = clock.now()
        for (key, entry) in pending where entry.startedAt + timeout <= deadline {
            heldBytes -= entry.holdingBytes
            pending.removeValue(forKey: key)
        }
        pruneStaleOrderHead()
    }

    private func assemble(key: Key) -> (IPv4Header, ByteBuffer)? {
        guard var entry = pending[key], let totalLength = entry.totalLength else { return nil }

        // Contiguous from zero to totalLength, or we are still missing a hole.
        entry.received.sort { $0.offset < $1.offset }
        var covered = 0
        for piece in entry.received {
            guard piece.offset <= covered else { return nil }
            covered = max(covered, piece.offset + piece.bytes.readableBytes)
        }
        guard covered >= totalLength else { return nil }

        // The admission guard should make this unreachable. It is checked anyway
        // because the consequence of being wrong is a non-failable conversion that
        // traps the process, and this invariant has been got wrong once already.
        // Placed here — before `assembled` is allocated and before the accounting
        // below runs — so the drop-path decrement/removal fires exactly once,
        // not on top of the success path's own bookkeeping further down.
        guard entry.header.headerLength + totalLength <= Self.maximumDatagram else {
            heldBytes -= entry.holdingBytes
            pending.removeValue(forKey: key)
            return nil
        }

        var assembled = ByteBufferAllocator().buffer(capacity: totalLength)
        assembled.writeRepeatingByte(0, count: totalLength)
        for piece in entry.received {
            var bytes = piece.bytes
            let length = min(bytes.readableBytes, totalLength - piece.offset)
            guard length > 0, let slice = bytes.readSlice(length: length) else { continue }
            assembled.setBuffer(slice, at: piece.offset)
        }

        heldBytes -= entry.holdingBytes
        pending.removeValue(forKey: key)

        var header = entry.header
        header.flags.remove(.moreFragments)
        header.fragmentOffset = 0
        // Safe by construction: `process` admits a fragment only when
        // `entry.header.headerLength + end <= maximumDatagram` (65535), and the
        // guard just above re-checks the same bound against the final
        // `totalLength` using the header that is actually used here, so this
        // sum never exceeds UInt16.max. Do not relax either guard without
        // reworking this conversion, which is non-failable and traps.
        header.totalLength = UInt16(header.headerLength + totalLength)
        return (header, assembled)
    }

    private func enforceMemoryLimit() {
        while heldBytes > memoryLimit, !pending.isEmpty {
            guard evictOldest() else { return }
        }
    }

    /// Remove every already-gone entry from the front of `admissionOrder` —
    /// one that finished (assembled, or dropped for overrunning the
    /// datagram bound) or expired since it was appended. Safe, and cheap, to
    /// call whenever `pending` may have shrunk: each stale key is skipped
    /// exactly once over the table's lifetime, so the amortized cost is
    /// O(1) per fragment processed, not O(pendingCount) — unlike the table
    /// scan (`pending.min(by: startedAt)`) this replaces.
    private func pruneStaleOrderHead() {
        while admissionOrderHead < admissionOrder.count, pending[admissionOrder[admissionOrderHead]] == nil {
            admissionOrderHead += 1
        }
        // Once at least half of `admissionOrder` is a consumed stale prefix,
        // drop it, so the array does not grow without bound purely from
        // entries that left `pending` some other way than through here.
        if admissionOrderHead > 64, admissionOrderHead * 2 > admissionOrder.count {
            admissionOrder.removeFirst(admissionOrderHead)
            admissionOrderHead = 0
        }
    }

    /// Evict the single oldest still-pending entry, if any. Backs both
    /// `maximumPendingDatagrams` and `memoryLimit`.
    @discardableResult
    private func evictOldest() -> Bool {
        pruneStaleOrderHead()
        guard admissionOrderHead < admissionOrder.count else { return false }
        let key = admissionOrder[admissionOrderHead]
        admissionOrderHead += 1
        guard let entry = pending.removeValue(forKey: key) else { return false }
        heldBytes -= entry.holdingBytes
        return true
    }
}
