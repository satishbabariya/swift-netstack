import NIOCore

/// A link that goes nowhere: writes are captured, inbound frames are injected
/// by hand. The substrate for every stack test in this package.
public final class RecordingEndpoint: LinkEndpoint, @unchecked Sendable {
    public let mtu: UInt32
    public let linkAddress: MACAddress
    public let capabilities: LinkCapabilities
    public let eventLoop: EventLoop

    private weak var dispatcher: (any LinkDispatcher)?
    /// Whether `attach` was ever called. Distinguishes "nothing is listening"
    /// — a legitimate state a real wire is also in — from "the dispatcher was
    /// deallocated while still attached", which is a bug that would otherwise
    /// present as packets silently vanishing.
    private var hasAttached = false
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
        eventLoop.preconditionInEventLoop()
        self.dispatcher = dispatcher
        hasAttached = true
    }

    public func write(_ packets: [PacketBuffer]) {
        eventLoop.preconditionInEventLoop()
        assert(dispatcher != nil || !hasAttached, "dispatcher was deallocated while still attached to this link")
        captured.append(contentsOf: packets.map(\.frame))
    }

    /// Everything written since the last drain.
    public var transmitted: [ByteBuffer] { captured }

    public func drainTransmitted() -> [ByteBuffer] {
        eventLoop.preconditionInEventLoop()
        defer { captured.removeAll(keepingCapacity: true) }
        return captured
    }

    /// Deliver a frame as though it arrived off the wire. A frame injected
    /// before anything is attached is dropped, exactly as a real wire would.
    public func inject(_ frame: ByteBuffer) {
        eventLoop.preconditionInEventLoop()
        assert(dispatcher != nil || !hasAttached, "dispatcher was deallocated while still attached to this link")
        dispatcher?.deliverInbound(PacketBuffer(received: frame))
    }
}
