/// An IPv4 CIDR block, normalised to its network address on construction.
public struct IPv4Subnet: Hashable, Sendable, CustomStringConvertible {
    public let address: IPv4Address
    public let prefixLength: UInt8

    public init(address: IPv4Address, prefixLength: UInt8) {
        precondition(prefixLength <= 32, "IPv4 prefix length must be 0...32")
        self.prefixLength = prefixLength
        let mask: UInt32 = prefixLength == 0 ? 0 : ~UInt32(0) << (32 - UInt32(prefixLength))
        self.address = IPv4Address(address.raw & mask)
    }

    public init?(cidr: String) {
        let parts = cidr.split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count == 2,
            let address = IPv4Address(String(parts[0])),
            let prefix = UInt8(parts[1]), prefix <= 32
        else { return nil }
        self.init(address: address, prefixLength: prefix)
    }

    public var mask: IPv4Address {
        IPv4Address(prefixLength == 0 ? 0 : ~UInt32(0) << (32 - UInt32(prefixLength)))
    }

    public var broadcast: IPv4Address {
        IPv4Address(address.raw | ~mask.raw)
    }

    public func contains(_ candidate: IPv4Address) -> Bool {
        candidate.raw & mask.raw == address.raw
    }

    public var description: String { "\(address)/\(prefixLength)" }
}
