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

    /// The first address a host on this subnet may hold, which is the one after
    /// the network address.
    ///
    /// Upstream defaults the gateway to this and the host to `lastUsable`, and
    /// hard-coding either instead is a quiet way to break every subnet but the
    /// default one: the names a guest is given resolve to addresses it cannot
    /// route to, while everything else looks configured.
    public var firstUsable: IPv4Address {
        IPv4Address((address.raw & mask.raw) &+ 1)
    }

    /// The last address a host may hold, which is the one before the broadcast
    /// address.
    public var lastUsable: IPv4Address {
        IPv4Address(broadcast.raw &- 1)
    }

    public func contains(_ candidate: IPv4Address) -> Bool {
        candidate.raw & mask.raw == address.raw
    }

    public var description: String { "\(address)/\(prefixLength)" }
}
