import NIOCore

/// Everything written is immediately delivered back inbound.
public final class LoopbackEndpoint: LinkEndpoint, @unchecked Sendable {
    public let mtu: UInt32
    public let linkAddress: MACAddress
    public let capabilities: LinkCapabilities = [.txChecksumOffload, .rxChecksumOffload]
    public let eventLoop: EventLoop

    private weak var dispatcher: (any LinkDispatcher)?

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
    }

    public func write(_ packets: [PacketBuffer]) {
        eventLoop.preconditionInEventLoop()
        guard let dispatcher else { return }
        for packet in packets {
            dispatcher.deliverInbound(PacketBuffer(received: packet.frame))
        }
    }
}
