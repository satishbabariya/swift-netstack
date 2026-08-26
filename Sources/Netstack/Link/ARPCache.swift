import NIOCore

/// An ARP packet over ethernet and IPv4. Other hardware and protocol types are
/// rejected rather than represented — nothing this stack attaches to uses them.
public struct ARPPacket: Sendable, Equatable {
    public static let length = 28

    public enum Operation: UInt16, Sendable {
        case request = 1
        case reply = 2
    }

    public var operation: Operation
    public var senderMAC: MACAddress
    public var senderIP: IPv4Address
    public var targetMAC: MACAddress
    public var targetIP: IPv4Address

    public init(operation: Operation, senderMAC: MACAddress, senderIP: IPv4Address, targetMAC: MACAddress, targetIP: IPv4Address) {
        self.operation = operation
        self.senderMAC = senderMAC
        self.senderIP = senderIP
        self.targetMAC = targetMAC
        self.targetIP = targetIP
    }

    public static func parse(_ packet: inout PacketBuffer) -> ARPPacket? {
        guard var body = packet.consumeHeader(length) else { return nil }
        guard
            body.readInteger(endianness: .big, as: UInt16.self) == 1,       // ethernet
            body.readInteger(endianness: .big, as: UInt16.self) == 0x0800,  // IPv4
            body.readInteger(as: UInt8.self) == 6,
            body.readInteger(as: UInt8.self) == 4,
            let rawOperation = body.readInteger(endianness: .big, as: UInt16.self),
            let operation = Operation(rawValue: rawOperation),
            let senderMACBytes = body.readBytes(length: 6),
            let senderIPBytes = body.readBytes(length: 4),
            let targetMACBytes = body.readBytes(length: 6),
            let targetIPBytes = body.readBytes(length: 4),
            let senderMAC = MACAddress(bytes: senderMACBytes),
            let targetMAC = MACAddress(bytes: targetMACBytes)
        else { return nil }

        return ARPPacket(
            operation: operation,
            senderMAC: senderMAC,
            senderIP: IPv4Address(senderIPBytes[0], senderIPBytes[1], senderIPBytes[2], senderIPBytes[3]),
            targetMAC: targetMAC,
            targetIP: IPv4Address(targetIPBytes[0], targetIPBytes[1], targetIPBytes[2], targetIPBytes[3])
        )
    }

    public func serialize(into allocator: ByteBufferAllocator) -> PacketBuffer {
        var body = allocator.buffer(capacity: Self.length)
        body.writeInteger(UInt16(1), endianness: .big)
        body.writeInteger(UInt16(0x0800), endianness: .big)
        body.writeInteger(UInt8(6))
        body.writeInteger(UInt8(4))
        body.writeInteger(operation.rawValue, endianness: .big)
        body.writeBytes(senderMAC.bytes)
        body.writeBytes(senderIP.bytes)
        body.writeBytes(targetMAC.bytes)
        body.writeBytes(targetIP.bytes)
        return PacketBuffer(allocator: allocator, payload: body)
    }
}

/// IP-to-MAC bindings with a time-to-live.
///
/// Loop-confined, so no lock. Expiry is lazy on `lookup` — a key is checked
/// only when it is asked for — but that is not enough on its own: nothing
/// fed by an attacker's own choices, rather than the stack's, may be allowed
/// to grow without bound. `record` is called from `IPv4Protocol.handleInbound`
/// on EVERY accepted IPv4 packet and from `ARPResponder.handle` on every ARP
/// seen — a guest (or, under promiscuous mode, anything it forwards for) can
/// grow this table just by varying the claimed source address, no valid ARP
/// exchange or checksum required. Bounded capacity with eviction closes that;
/// `reapExpired`, called from `Stack`'s maintenance timer, then lets an idle
/// cache actually shrink back down between floods instead of merely stopping
/// its growth at the cap.
public final class ARPCache {
    private struct Entry {
        let mac: MACAddress
        var expiresAt: NIODeadline
        /// The `order` position that currently represents this entry's most
        /// recent touch. See `order`'s doc comment for why this is needed.
        var sequence: Int
    }

    /// A single guest behind one gateway resolves only a handful of on-link
    /// peers in practice — the gateway itself and perhaps a few local
    /// services — so this is two to three orders of magnitude more headroom
    /// than legitimate traffic ever needs. It still caps worst-case memory
    /// to a small, constant amount (each entry is a MAC, a deadline, and a
    /// dictionary/array slot — on the order of tens of bytes) regardless of
    /// how many distinct source addresses a guest sends, spoofed or not.
    public static let defaultCapacity = 512

    private let clock: NetstackClock
    private let ttl: TimeAmount
    private let capacity: Int
    private var entries: [IPv4Address: Entry] = [:]
    /// A log of touches, oldest first: the front is the next eviction
    /// candidate, the back is the most recent touch. Appended to by both a
    /// new-or-refreshed `record` and a successful `lookup`, so an address
    /// the stack is actively talking to survives an eviction sweep even
    /// while a flood of unrelated, single-use spoofed sources is cycling
    /// through the rest of the table.
    ///
    /// Unlike the reassembler's `admissionOrder` (one entry per KEY, never
    /// re-touched), this is one entry per TOUCH — a re-touched key appears
    /// here more than once, with only its most recent appearance still
    /// live. Each appearance carries the sequence number it was assigned
    /// when appended (a monotonic counter, distinct from — and not implied
    /// by — the appearance's position, since `compactOrderIfNeeded` shifts
    /// positions but must not need to renumber every surviving element to
    /// keep them meaningful). `Entry.sequence` records which appearance is
    /// the live one, so a stale, superseded appearance is distinguished by
    /// an O(1) comparison instead of an O(n) search for the key: this is
    /// what makes touching an entry — done on every `record` and every
    /// `lookup`, i.e. on every accepted IPv4 packet — O(1) instead of the
    /// O(capacity) `firstIndex(of:)` + `remove(at:)` it replaces. `orderHead`
    /// is the index of the oldest appearance that might still be live;
    /// appearances at or before it may already be stale and are skipped
    /// lazily rather than removed from the middle of the array.
    ///
    /// Bounded to `4 * capacity + 1` elements by `compactOrderIfNeeded`'s
    /// periodic full pass — see that function's doc comment. Without it, one
    /// address that is recorded once and never touched again pins
    /// `orderHead` at its own appearance forever, and every touch of every
    /// OTHER address grows this array with nothing to reclaim it: an
    /// attacker pins with one packet, then floods from a second address to
    /// drive unbounded growth using only ordinary, individually-legitimate
    /// traffic.
    private var order: [(ip: IPv4Address, sequence: Int)] = []
    private var orderHead = 0
    private var nextSequence = 0

    /// Test-only instrumentation, not `private`: `@testable import` needs to
    /// read it, but nothing outside this file writes it. Counts every
    /// iteration of `compactOrderIfNeeded`'s loop, whether it ends up
    /// advancing `orderHead` past a stale appearance or breaking on a live
    /// one. Over the table's lifetime, the "advance past a stale one" case
    /// can happen at most once per appearance ever appended to `order`
    /// (once skipped, `orderHead` never revisits it), and the "break on a
    /// live one" case happens at most once per CALL — so the running total
    /// staying within a small constant multiple of the number of touches
    /// performed, rather than growing with `capacity`, is a direct,
    /// timing-independent witness that touching an entry is amortized O(1).
    /// Counting every iteration (not just the skips) also catches a future
    /// regression that keeps this general shape but drops the early
    /// `break`, which would scan needlessly far without ever registering as
    /// a "skip".
    ///
    /// A wall-clock regression guard for this same property was tried
    /// first; at capacities small enough not to also inflate memory for
    /// every OTHER test running concurrently in the same process, the
    /// difference between the O(1) and O(capacity) implementations was too
    /// fast on this hardware (sub-millisecond either way) to separate
    /// reliably, and at capacities large enough to separate reliably, the
    /// live entries the test had to hold for the duration measurably
    /// perturbed unrelated tests' own memory measurements (see
    /// `ReassemblerTests`). This counter sidesteps both problems.
    var orderScanStepsForTesting = 0

    /// Test-only instrumentation, not `private`, for the same reason as
    /// `orderScanStepsForTesting`: `order.count` itself, to assert directly
    /// that it stays bounded under a pinned-head attack rather than
    /// inferring it indirectly from scan-step counts.
    var orderCountForTesting: Int { order.count }

    public init(clock: NetstackClock, ttl: TimeAmount = .seconds(60), capacity: Int = ARPCache.defaultCapacity) {
        self.clock = clock
        self.ttl = ttl
        self.capacity = max(1, capacity)
    }

    public func record(_ ip: IPv4Address, _ mac: MACAddress) {
        let expiresAt = clock.now() + ttl
        if entries[ip] != nil {
            entries[ip] = Entry(mac: mac, expiresAt: expiresAt, sequence: nextTouchSequence(for: ip))
            compactOrderIfNeeded()
            return
        }
        if entries.count >= capacity {
            evictLeastRecentlyUsed()
        }
        entries[ip] = Entry(mac: mac, expiresAt: expiresAt, sequence: nextTouchSequence(for: ip))
        compactOrderIfNeeded()
    }

    public func lookup(_ ip: IPv4Address) -> MACAddress? {
        guard let entry = entries[ip] else { return nil }
        guard entry.expiresAt > clock.now() else {
            entries.removeValue(forKey: ip)
            return nil
        }
        let sequence = nextTouchSequence(for: ip)
        entries[ip]?.sequence = sequence
        compactOrderIfNeeded()
        return entry.mac
    }

    /// Evict every entry whose TTL has elapsed. Called from `Stack`'s
    /// periodic maintenance timer, alongside the reassembler's own sweep.
    public func reapExpired() {
        let now = clock.now()
        guard !entries.isEmpty else { return }
        let expired = entries.filter { $0.value.expiresAt <= now }.map(\.key)
        guard !expired.isEmpty else { return }
        for ip in expired {
            entries.removeValue(forKey: ip)
        }
        // A removed entry's appearances in `order` are already stale by
        // `entries[ip] == nil` alone; this just lets that be noticed —
        // and `order`'s storage reclaimed — without waiting for enough
        // further touches to cross `compactOrderIfNeeded`'s own threshold.
        compactOrderIfNeeded()
    }

    public var count: Int { entries.count }

    /// Record one more touch for `ip` and return the sequence number that
    /// makes THIS appearance in `order` the live one. O(1): just an append
    /// and a counter increment.
    ///
    /// Deliberately does NOT also run `compactOrderIfNeeded` — every caller
    /// must call it separately, and only AFTER `entries[ip]` itself has been
    /// updated to carry the returned sequence number. Compaction checks a
    /// candidate appearance for staleness by comparing it against
    /// `entries[appearance.ip]?.sequence`; calling it before that dictionary
    /// write lands would find no matching (or no) entry for the appearance
    /// this very call just appended, misread it as already-stale, and skip
    /// `orderHead` straight past a genuinely live entry — silently
    /// disabling eviction entirely once `orderHead` runs past the whole
    /// live prefix, which is exactly what happened here before this was
    /// split into two steps.
    private func nextTouchSequence(for ip: IPv4Address) -> Int {
        nextSequence += 1
        order.append((ip: ip, sequence: nextSequence))
        return nextSequence
    }

    /// Advance `orderHead` past every already-stale appearance at the front
    /// of `order` (superseded by a later touch of the same address, or its
    /// entry is gone), then drop that consumed prefix once it is worth the
    /// copy, so `order` does not grow without bound purely from re-touches
    /// of the same few hot addresses. Safe to call at any time: an
    /// appearance before `orderHead` is never live, since `orderHead` is
    /// only ever advanced past ones this loop (or `evictLeastRecentlyUsed`)
    /// has already found stale. Each appearance carries its own sequence
    /// number rather than relying on array position to imply one, so
    /// `removeFirst` shifting every surviving element's position here does
    /// not invalidate the comparison on the next call.
    ///
    /// The head-only scan above has a gap: it can be pinned indefinitely by
    /// a single address that is never re-touched while every OTHER address
    /// is repeatedly re-touched behind it. Each re-touch appends a fresh
    /// appearance without ever making the pinning entry's own appearance
    /// stale, so `orderHead` simply stops advancing and the prefix-drop
    /// above never fires again — `order` then grows by one element per
    /// touch, forever, entirely independent of `capacity`. (Measured: 4M
    /// touches against one pinned address and one hammered address grew
    /// `order` to ~4M elements and real RSS by ~165 MB at `capacity == 512`
    /// before this fix.)
    ///
    /// Close that with a periodic FULL pass, not just the consumed prefix:
    /// once `order` has grown past a multiple of `capacity` it could never
    /// legitimately reach through live entries alone (at most `capacity`
    /// entries can be live at once, so live appearances account for at most
    /// `capacity` elements), rebuild `order` keeping only the appearances
    /// that are still each entry's live one. This bounds `order.count` to a
    /// small constant multiple of `capacity` (`4 * capacity + 1`, since this
    /// is checked after every single append) regardless of the touch
    /// pattern, not merely as long as the head happens to keep moving.
    /// Amortized O(1): each appearance is visited by at most one full pass
    /// before it is either dropped or survives as the sole live one for its
    /// key, and the threshold guarantees a full pass runs at most once per
    /// `capacity` further touches.
    private func compactOrderIfNeeded() {
        while orderHead < order.count {
            orderScanStepsForTesting += 1
            let appearance = order[orderHead]
            if let entry = entries[appearance.ip], entry.sequence == appearance.sequence { break }
            orderHead += 1
        }
        if orderHead > 64, orderHead * 2 > order.count {
            order.removeFirst(orderHead)
            orderHead = 0
            return
        }
        guard order.count > 4 * capacity else { return }
        var compacted: [(ip: IPv4Address, sequence: Int)] = []
        compacted.reserveCapacity(entries.count)
        for index in orderHead..<order.count {
            orderScanStepsForTesting += 1
            let appearance = order[index]
            if let entry = entries[appearance.ip], entry.sequence == appearance.sequence {
                compacted.append(appearance)
            }
        }
        order = compacted
        orderHead = 0
    }

    private func evictLeastRecentlyUsed() {
        compactOrderIfNeeded()
        guard orderHead < order.count else { return }
        let oldest = order[orderHead]
        orderHead += 1
        entries.removeValue(forKey: oldest.ip)
    }
}
