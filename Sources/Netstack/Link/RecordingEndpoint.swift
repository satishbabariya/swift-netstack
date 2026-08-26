import NIOCore

/// A link that goes nowhere: writes are captured, inbound frames are injected
/// by hand. The substrate for every stack test in this package.
public final class RecordingEndpoint: LinkEndpoint, @unchecked Sendable {
    public let mtu: UInt32
    public let linkAddress: MACAddress
    public let capabilities: LinkCapabilities
    public let eventLoop: EventLoop

    private var dispatcher: LinkDispatcher?
    private var captured: [ByteBuffer] = []

    public init(
        eventLoop: EventLoop,
        linkAddress: MACAddress,
        mtu: UInt32 = 1500,
        capabilities: LinkCapabilities = []
    ) {
        self.eventLoop = eventLoop
        self.linkAddress = linkAddress
        self.mtu = mtu
        self.capabilities = capabilities
    }

    public func attach(_ dispatcher: LinkDispatcher) {
        self.dispatcher = dispatcher
    }

    public func write(_ packets: [PacketBuffer]) {
        captured.append(contentsOf: packets.map(\.frame))
    }

    /// Everything written since the last drain.
    public var transmitted: [ByteBuffer] { captured }

    public func drainTransmitted() -> [ByteBuffer] {
        defer { captured.removeAll(keepingCapacity: true) }
        return captured
    }

    /// Deliver a frame as though it arrived off the wire. A frame injected
    /// before anything is attached is dropped, exactly as a real wire would.
    public func inject(_ frame: ByteBuffer) {
        dispatcher?.deliverInbound(PacketBuffer(received: frame))
    }
}
