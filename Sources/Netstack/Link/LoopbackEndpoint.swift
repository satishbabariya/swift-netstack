import NIOCore

/// Everything written is immediately delivered back inbound.
public final class LoopbackEndpoint: LinkEndpoint, @unchecked Sendable {
    public let mtu: UInt32
    public let linkAddress: MACAddress
    public let capabilities: LinkCapabilities = [.txChecksumOffload, .rxChecksumOffload]
    public let eventLoop: EventLoop

    private var dispatcher: LinkDispatcher?

    public init(eventLoop: EventLoop, mtu: UInt32 = 65536) {
        self.eventLoop = eventLoop
        self.mtu = mtu
        // Loopback has no meaningful hardware address.
        self.linkAddress = MACAddress(bytes: [0, 0, 0, 0, 0, 0])!
    }

    public func attach(_ dispatcher: LinkDispatcher) {
        self.dispatcher = dispatcher
    }

    public func write(_ packets: [PacketBuffer]) {
        guard let dispatcher else { return }
        for packet in packets {
            dispatcher.deliverInbound(PacketBuffer(received: packet.frame))
        }
    }
}
