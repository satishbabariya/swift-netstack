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
/// Deals only in whole frames. Header parsing belongs to the layer above, so
/// a wire carrying something other than ethernet can conform without
/// inventing link addresses it does not have.
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
