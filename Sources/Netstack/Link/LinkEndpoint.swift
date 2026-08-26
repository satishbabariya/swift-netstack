import NIOCore

public struct LinkCapabilities: OptionSet, Sendable {
    public let rawValue: UInt32
    public init(rawValue: UInt32) { self.rawValue = rawValue }

    /// The wire computes outbound transport checksums for us.
    public static let txChecksumOffload = LinkCapabilities(rawValue: 1 << 0)
    /// Inbound transport checksums are already known good.
    public static let rxChecksumOffload = LinkCapabilities(rawValue: 1 << 1)
}

/// What a link endpoint hands its frames to. Implemented by `NIC`.
public protocol LinkDispatcher: AnyObject {
    /// Called on the link's event loop with one complete inbound frame.
    func deliverInbound(_ frame: PacketBuffer)
}

/// One wire.
///
/// Deals only in whole frames: header parsing belongs to the layer above,
/// so the link layer never needs to know what it is carrying.
///
/// The wire is assumed to carry ethernet frames, which is why
/// `linkAddress` is non-optional. That holds for every transport this
/// package targets — a datagram on the wire IS one ethernet frame. A wire
/// carrying bare IP would need a different abstraction; change this
/// protocol then, rather than weakening it now for a case that does not
/// arise.
public protocol LinkEndpoint: AnyObject {
    var mtu: UInt32 { get }
    var linkAddress: MACAddress { get }
    var capabilities: LinkCapabilities { get }
    /// The loop every callback arrives on and every `write` must be made from.
    var eventLoop: EventLoop { get }

    func attach(_ dispatcher: LinkDispatcher)
    /// Transmit. Batched because most wires amortise a syscall across frames.
    func write(_ packets: [PacketBuffer])
}
