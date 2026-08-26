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
    /// Least-recently-used order for the entries currently in `entries`: the
    /// front is the next eviction candidate, the back is the most recently
    /// touched. Touched by both a new-or-refreshed `record` and a successful
    /// `lookup`, so an address the stack is actively talking to survives an
    /// eviction sweep even while a flood of unrelated, single-use spoofed
    /// sources is cycling through the rest of the table.
    private var order: [IPv4Address] = []

    public init(clock: NetstackClock, ttl: TimeAmount = .seconds(60), capacity: Int = ARPCache.defaultCapacity) {
        self.clock = clock
        self.ttl = ttl
        self.capacity = max(1, capacity)
    }

    public func record(_ ip: IPv4Address, _ mac: MACAddress) {
        let expiresAt = clock.now() + ttl
        if entries[ip] != nil {
            entries[ip] = Entry(mac: mac, expiresAt: expiresAt)
            touch(ip)
            return
        }
        if entries.count >= capacity {
            evictLeastRecentlyUsed()
        }
        entries[ip] = Entry(mac: mac, expiresAt: expiresAt)
        order.append(ip)
    }

    public func lookup(_ ip: IPv4Address) -> MACAddress? {
        guard let entry = entries[ip] else { return nil }
        guard entry.expiresAt > clock.now() else {
            entries.removeValue(forKey: ip)
            removeFromOrder(ip)
            return nil
        }
        touch(ip)
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
        let expiredSet = Set(expired)
        order.removeAll { expiredSet.contains($0) }
    }

    public var count: Int { entries.count }

    private func touch(_ ip: IPv4Address) {
        removeFromOrder(ip)
        order.append(ip)
    }

    private func removeFromOrder(_ ip: IPv4Address) {
        guard let index = order.firstIndex(of: ip) else { return }
        order.remove(at: index)
    }

    private func evictLeastRecentlyUsed() {
        guard !order.isEmpty else { return }
        let oldest = order.removeFirst()
        entries.removeValue(forKey: oldest)
    }
}
