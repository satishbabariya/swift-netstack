import NIOCore

/// Everything written is immediately delivered back inbound.
public final class LoopbackEndpoint: LinkEndpoint, @unchecked Sendable {
    public let mtu: UInt32
    public let linkAddress: MACAddress
    public let capabilities: LinkCapabilities = [.txChecksumOffload, .rxChecksumOffload]
    public let eventLoop: EventLoop

    private weak var dispatcher: (any LinkDispatcher)?
    /// Whether `attach` was ever called. Distinguishes "nothing is listening"
    /// — a legitimate state a real wire is also in — from "the dispatcher was
    /// deallocated while still attached", which is a bug that would otherwise
    /// present as packets silently vanishing.
    private var hasAttached = false

    public init(eventLoop: EventLoop, mtu: UInt32 = 65536) {
        self.eventLoop = eventLoop
        self.mtu = mtu
        // Loopback never puts a frame on a wire, so its address is never read.
        // Zero is a placeholder, not a claim about hardware.
        self.linkAddress = MACAddress(bytes: [0, 0, 0, 0, 0, 0])!
    }

    public func attach(_ dispatcher: LinkDispatcher) {
        eventLoop.preconditionInEventLoop()
        self.dispatcher = dispatcher
        hasAttached = true
    }

    public func write(_ packets: [PacketBuffer]) {
        eventLoop.preconditionInEventLoop()
        assert(dispatcher != nil || !hasAttached, "dispatcher was deallocated while still attached to this link")
        guard let dispatcher else { return }
        for packet in packets {
            dispatcher.deliverInbound(PacketBuffer(received: packet.frame))
        }
    }
}
