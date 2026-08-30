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

/// What `Gateway` needs from whatever is under it.
///
/// Two things satisfy this: a `WireLinkEndpoint`, which is one guest on one
/// wire, and a `NetworkSwitch`, which is a whole network of them. The gateway
/// above cannot tell them apart and has no reason to -- it terminates flows,
/// and where a frame entered is the link layer's business.
///
/// It exists rather than `Gateway` simply holding a `LinkEndpoint` because a
/// gateway also has to close its link and report what the link dropped, and
/// neither is something every link endpoint has (a loopback wire in a test drops
/// nothing and closes nothing).
///
/// `Sendable` for the reason everything else in this package is: the object is
/// confined to one event loop and reached only from it. The conformance lets
/// `Gateway` carry a link into the `@Sendable` closures its assembly runs on
/// that loop, which is the only place it crosses a boundary the compiler can
/// see.
public protocol GatewayLink: LinkEndpoint, Sendable {
    /// Frames the link would not carry, in each direction.
    var inboundDropped: Int { get }
    var outboundDropped: Int { get }
    /// Bytes that crossed, in each direction. Upstream reports the same two on
    /// `GET /stats` and they are the first thing anyone asks of a network that
    /// is not working: whether anything is moving at all.
    var bytesReceived: Int { get }
    var bytesSent: Int { get }
    /// Where the link reports what it refused.
    var log: RateLimitedLogger? { get set }
    func close() -> EventLoopFuture<Void>
}
