import Foundation

/// A 48-bit ethernet address, stored in the low bits of a `UInt64`.
///
/// A `UInt64` rather than a six-byte tuple so the type is `Hashable` and
/// comparable for free — it spends its life as a dictionary key in the ARP
/// cache and the IP pool.
public struct MACAddress: Hashable, Sendable, CustomStringConvertible {
    public let raw: UInt64

    public init?(bytes: [UInt8]) {
        guard bytes.count == 6 else { return nil }
        var value: UInt64 = 0
        for byte in bytes {
            value = value << 8 | UInt64(byte)
        }
        self.raw = value
    }

    public init?(_ text: String) {
        let parts = text.split(separator: ":", omittingEmptySubsequences: false)
        guard parts.count == 6 else { return nil }
        var bytes: [UInt8] = []
        bytes.reserveCapacity(6)
        for part in parts {
            guard part.count == 2, let value = UInt8(part, radix: 16) else { return nil }
            bytes.append(value)
        }
        self.init(bytes: bytes)
    }

    public var bytes: [UInt8] {
        (0..<6).reversed().map { UInt8((raw >> (UInt64($0) * 8)) & 0xff) }
    }

    public var description: String {
        bytes.map { String(format: "%02x", $0) }.joined(separator: ":")
    }

    public static let broadcast = MACAddress(bytes: [0xff, 0xff, 0xff, 0xff, 0xff, 0xff])!

    public var isBroadcast: Bool { raw == MACAddress.broadcast.raw }

    /// The low bit of the first octet. Broadcast is a special case of it.
    public var isMulticast: Bool { (raw >> 40) & 0x01 == 1 }
}
