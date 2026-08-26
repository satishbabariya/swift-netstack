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
/// Loop-confined, so no lock. Expiry is lazy: an entry is checked on lookup
/// rather than swept, which costs nothing on a table this small and avoids a
/// timer that would fire forever on an idle stack.
public final class ARPCache {
    private struct Entry {
        let mac: MACAddress
        let expiresAt: NIODeadline
    }

    private let clock: NetstackClock
    private let ttl: TimeAmount
    private var entries: [IPv4Address: Entry] = [:]

    public init(clock: NetstackClock, ttl: TimeAmount = .seconds(60)) {
        self.clock = clock
        self.ttl = ttl
    }

    public func record(_ ip: IPv4Address, _ mac: MACAddress) {
        entries[ip] = Entry(mac: mac, expiresAt: clock.now() + ttl)
    }

    public func lookup(_ ip: IPv4Address) -> MACAddress? {
        guard let entry = entries[ip] else { return nil }
        guard entry.expiresAt > clock.now() else {
            entries.removeValue(forKey: ip)
            return nil
        }
        return entry.mac
    }

    public var count: Int { entries.count }
}
