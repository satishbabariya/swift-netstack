import NIOCore

/// Reassembles IPv4 fragments into whole datagrams.
///
/// Bounded on four axes, because an incomplete datagram is otherwise an
/// unbounded allocation a peer controls: each pending datagram expires after
/// `timeout`; the memory actually retained across all of them is capped at
/// `memoryLimit`; the number of concurrently pending datagrams is capped at
/// `maximumPendingDatagrams` — independently of `memoryLimit`, because a
/// flood of minimal fragments (as little as 1 byte each) spread across many
/// different datagram IDs barely moves the byte total while still costing one
/// full entry — a header, an array, and a dictionary slot — per datagram; and
/// the number of fragments accepted for any ONE datagram is capped at
/// `maximumFragmentsPerDatagram`, because the same trick works the other way
/// too — one datagram ID, thousands of 1-byte fragments — and neither of the
/// other two caps limits it (`memoryLimit` is exactly what per-fragment
/// overhead charging below closes, but a second, structural cap on fragment
/// count is cheap insurance against ever mis-measuring that overhead again).
/// All three eviction/rejection caps evict oldest-first, in the order entries
/// were created, or reject outright once a single datagram's own cap is hit.
///
/// Each admitted fragment's payload is copied into freshly allocated,
/// exactly-sized storage rather than kept as the `ByteBuffer` slice it
/// arrived in. NIO's `getSlice` (and everything built on it, including how a
/// fragment reaches here from `PacketBuffer`) is copy-on-write: a slice keeps
/// a live reference to the ENTIRE original allocation until something writes
/// into it, so an uncopied 1-byte fragment sliced from a 1500-byte MTU frame
/// pins all 1500 bytes, not 1. Copying fixes that pinning, but it does not by
/// itself make `heldBytes`/`memoryLimit` track real retained memory: even a
/// freshly, exactly-sized copy of 1 payload byte costs far more than 1 byte
/// in practice, because what is actually retained per fragment is the
/// `(offset: Int, bytes: ByteBuffer)` array element, the `ByteBuffer`'s own
/// backing `_Storage` class instance (an allocation with a class header), and
/// whatever malloc's minimum bucket rounds that tiny allocation up to — none
/// of which `payload.readableBytes` sees. Measured empirically (this
/// package's own `getrusage`-based measurement, reproducing the 1-byte,
/// 8-byte-offset, `MoreFragments`-always-set shape end to end through
/// `process`): roughly 119–131 bytes of real RSS growth per 1-byte fragment
/// depending on build configuration, and a prior measurement on a different
/// platform/allocator put it at 147.7. `perFragmentOverhead` charges 176 —
/// comfortably above every measurement taken, including the least favourable
/// one, so `memoryLimit` bounds what is actually retained rather than merely
/// what was declared on the wire.
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

    /// The real, per-fragment cost of holding one admitted fragment pending —
    /// the array element, the `ByteBuffer`'s backing storage object, and
    /// malloc's rounding of that tiny allocation — none of which shows up in
    /// `payload.readableBytes`. See the type-level doc comment for how this
    /// number was measured. Charged on top of the declared payload length so
    /// `heldBytes`/`memoryLimit` bound what is actually retained.
    public static let perFragmentOverhead = 176

    /// A correctly fragmenting sender splits a datagram into at most a few
    /// dozen pieces even at the smallest MTU IPv4 permits (68 bytes, RFC
    /// 791 §3.1): a 65535-byte datagram needs at most ~1366 fragments at
    /// that floor, and ordinary Ethernet-MTU fragmentation needs a few dozen.
    /// This is generous headroom over that worst legitimate case while still
    /// bounding, independent of `memoryLimit`, how many times one datagram ID
    /// can pay `perFragmentOverhead` — insurance against `memoryLimit` alone
    /// ever being mis-measured or mis-tuned again.
    public static let defaultMaximumFragmentsPerDatagram = 2048

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
        /// The `admissionOrder` sequence number assigned when this entry was
        /// created. See `admissionOrder`'s doc comment for why this is
        /// needed: it lets a stale `admissionOrder` appearance for a KEY
        /// that has since been re-admitted (completed or evicted, then a
        /// fresh datagram with the identical source/destination/id/protocol
        /// arrived later) be told apart from the appearance that actually
        /// represents THIS live entry, by an O(1) comparison instead of
        /// conflating every appearance of the same key as equally live.
        let admissionSequence: Int
    }

    private let clock: NetstackClock
    private let timeout: TimeAmount
    private let memoryLimit: Int
    private let maximumPendingDatagrams: Int
    private let maximumFragmentsPerDatagram: Int
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
    ///
    /// One entry per ADMISSION (i.e. per `isNewEntry` in `process`), not one
    /// per key — the same key can be admitted more than once over this
    /// object's lifetime if an earlier entry under it completes or is
    /// evicted and a later fragment starts a fresh one. Each appearance
    /// carries the `admissionSequence` its `Pending` was stamped with when
    /// created, so a stale appearance from an earlier admission of the same
    /// key can be told apart from the one that represents the CURRENT entry
    /// by an O(1) comparison against `Pending.admissionSequence`, rather
    /// than by key membership in `pending` alone (which cannot distinguish
    /// "this key has never been re-admitted" from "this key was re-admitted
    /// after this appearance went stale").
    ///
    /// `pruneStaleOrderHead`'s head-only scan alone is not enough to bound
    /// this: a single never-completing entry sitting at the front pins
    /// `admissionOrderHead`, and every OTHER datagram that completes leaves
    /// `pending` from the middle, going stale where the head-only scan can
    /// never reach it. See `pruneStaleOrderHead`'s doc comment for the fix.
    private var admissionOrder: [(key: Key, sequence: Int)] = []
    private var admissionOrderHead = 0
    private var nextAdmissionSequence = 0

    /// Test-only instrumentation, not `private`: `@testable import` needs to
    /// read it to assert directly that `admissionOrder` stays bounded under
    /// a pinned-head attack.
    var admissionOrderCountForTesting: Int { admissionOrder.count }

    public init(
        clock: NetstackClock, timeout: TimeAmount = .seconds(30), memoryLimit: Int = 4 * 1024 * 1024,
        maximumPendingDatagrams: Int = Reassembler.defaultMaximumPendingDatagrams,
        maximumFragmentsPerDatagram: Int = Reassembler.defaultMaximumFragmentsPerDatagram
    ) {
        self.clock = clock
        self.timeout = timeout
        self.memoryLimit = memoryLimit
        self.maximumPendingDatagrams = max(1, maximumPendingDatagrams)
        self.maximumFragmentsPerDatagram = max(1, maximumFragmentsPerDatagram)
    }

    public var pendingCount: Int { pending.count }

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
        var entry = pending[key] ?? Pending(header: header, startedAt: clock.now(), admissionSequence: allocateAdmissionSequence())

        // Bound the datagram as it will be ASSEMBLED, not as this fragment
        // arrives. `entry.header` is fixed by whichever fragment created the
        // entry and may carry options, while `totalLength` comes from whichever
        // fragment terminates it — checking the incoming fragment's own header
        // ties none of them together and lets three individually-admissible
        // fragments overflow the conversion at assembly.
        guard entry.header.headerLength + end <= Self.maximumDatagram else { return nil }

        // Reject outright once this ONE datagram has already accumulated
        // `maximumFragmentsPerDatagram` fragments — independent of, and
        // cheaper to check than, the overlap scan below. No legitimately
        // fragmenting sender approaches this count (see the doc comment on
        // `defaultMaximumFragmentsPerDatagram`); an attacker sending nothing
        // but 1-byte fragments for a single ID is the shape this closes.
        guard entry.received.count < maximumFragmentsPerDatagram else { return nil }

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
        // Charge the real per-fragment retention cost, not just the payload
        // length — see `perFragmentOverhead`'s doc comment. Without this,
        // `memoryLimit` bounds the accounting, not the allocation behind it.
        let charge = length + Self.perFragmentOverhead
        entry.holdingBytes += charge
        heldBytes += charge
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
            admissionOrder.append((key: key, sequence: entry.admissionSequence))
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

    /// An `admissionOrder` appearance is live only if `pending[key]` still
    /// exists AND is the same admission this appearance recorded — a key
    /// membership check alone cannot tell "this key was never re-admitted"
    /// from "this key went stale here but was re-admitted later", and would
    /// misidentify the latter as live forever.
    private func isLive(_ appearance: (key: Key, sequence: Int)) -> Bool {
        pending[appearance.key]?.admissionSequence == appearance.sequence
    }

    /// Remove every already-gone entry from the front of `admissionOrder` —
    /// one that finished (assembled, or dropped for overrunning the
    /// datagram bound), expired, or was superseded by a later re-admission
    /// of the same key, since it was appended. Safe, and cheap, to call
    /// whenever `pending` may have shrunk: each stale appearance is skipped
    /// exactly once over the table's lifetime, so the amortized cost is
    /// O(1) per fragment processed, not O(pendingCount) — unlike the table
    /// scan (`pending.min(by: startedAt)`) this replaces.
    ///
    /// The head-only scan above has a gap: it can be pinned indefinitely by
    /// a single never-completing entry sitting at the front — e.g. one
    /// 1-byte `MoreFragments` fragment with no terminator ever admitted.
    /// Every OTHER datagram that completes leaves `pending` from the
    /// middle, so its `admissionOrder` appearance goes stale where this
    /// scan can never reach it: `admissionOrderHead` stops advancing, the
    /// prefix-drop above never fires, and `admissionOrder` grows by one
    /// `Key` per admission, forever — entirely unaccounted by
    /// `heldBytes`/`memoryLimit`. (Measured: 2M admission cycles against one
    /// pinned datagram grew real RSS by ~58 MB with `pendingCount == 1` and
    /// `heldBytes` in the low hundreds of bytes, against a 4 MiB cap.)
    ///
    /// Close that with a periodic FULL pass, not just the consumed prefix:
    /// once `admissionOrder` has grown past a multiple of
    /// `maximumPendingDatagrams` it could never legitimately reach through
    /// live entries alone (at most `maximumPendingDatagrams` entries can be
    /// live at once), rebuild it keeping only the appearances that are each
    /// currently live. This bounds `admissionOrder.count` to
    /// `4 * maximumPendingDatagrams + 1` elements (checked after every
    /// single append) — a small, constant memory footprint for this
    /// structure alone, independent of `memoryLimit` and of how the head is
    /// pinned, establishing that total retention here is bounded to within
    /// a stated constant factor rather than merely that the accounted
    /// number (`heldBytes`) stays small. Amortized O(1): each appearance is
    /// visited by at most one full pass before it is either dropped or
    /// survives as the sole live one for its key, and the threshold
    /// guarantees a full pass runs at most once per `maximumPendingDatagrams`
    /// further admissions.
    private func pruneStaleOrderHead() {
        while admissionOrderHead < admissionOrder.count, !isLive(admissionOrder[admissionOrderHead]) {
            admissionOrderHead += 1
        }
        // Once at least half of `admissionOrder` is a consumed stale prefix,
        // drop it, so the array does not grow without bound purely from
        // entries that left `pending` some other way than through here.
        if admissionOrderHead > 64, admissionOrderHead * 2 > admissionOrder.count {
            admissionOrder.removeFirst(admissionOrderHead)
            admissionOrderHead = 0
            return
        }
        guard admissionOrder.count > 4 * maximumPendingDatagrams else { return }
        var compacted: [(key: Key, sequence: Int)] = []
        compacted.reserveCapacity(pending.count)
        for index in admissionOrderHead..<admissionOrder.count {
            let appearance = admissionOrder[index]
            if isLive(appearance) {
                compacted.append(appearance)
            }
        }
        admissionOrder = compacted
        admissionOrderHead = 0
    }

    /// Evict the single oldest still-pending entry, if any. Backs both
    /// `maximumPendingDatagrams` and `memoryLimit`.
    @discardableResult
    private func evictOldest() -> Bool {
        pruneStaleOrderHead()
        guard admissionOrderHead < admissionOrder.count else { return false }
        let key = admissionOrder[admissionOrderHead].key
        admissionOrderHead += 1
        guard let entry = pending.removeValue(forKey: key) else { return false }
        heldBytes -= entry.holdingBytes
        return true
    }

    /// Allocate the sequence number that marks a newly created `Pending` as
    /// the live admission for its key. See `Pending.admissionSequence` and
    /// `admissionOrder`'s doc comments.
    private func allocateAdmissionSequence() -> Int {
        nextAdmissionSequence += 1
        return nextAdmissionSequence
    }
}
