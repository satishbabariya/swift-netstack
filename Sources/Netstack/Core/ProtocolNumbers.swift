public struct EtherType: RawRepresentable, Hashable, Sendable {
    public let rawValue: UInt16
    public init(rawValue: UInt16) { self.rawValue = rawValue }

    public static let ipv4 = EtherType(rawValue: 0x0800)
    public static let arp = EtherType(rawValue: 0x0806)
    public static let ipv6 = EtherType(rawValue: 0x86dd)
}

public struct IPProtocol: RawRepresentable, Hashable, Sendable {
    public let rawValue: UInt8
    public init(rawValue: UInt8) { self.rawValue = rawValue }

    public static let icmp = IPProtocol(rawValue: 1)
    public static let tcp = IPProtocol(rawValue: 6)
    public static let udp = IPProtocol(rawValue: 17)
}

public struct ICMPv4Type: RawRepresentable, Hashable, Sendable {
    public let rawValue: UInt8
    public init(rawValue: UInt8) { self.rawValue = rawValue }

    public static let echoReply = ICMPv4Type(rawValue: 0)
    public static let destinationUnreachable = ICMPv4Type(rawValue: 3)
    public static let echoRequest = ICMPv4Type(rawValue: 8)
    public static let timeExceeded = ICMPv4Type(rawValue: 11)
}
