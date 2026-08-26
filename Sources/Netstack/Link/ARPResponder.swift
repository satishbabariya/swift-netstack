import NIOCore

/// Answers ARP requests for addresses this NIC owns, and learns bindings from
/// everything it sees.
public final class ARPResponder {
    private let nic: NIC
    private let cache: ARPCache
    private let allocator: ByteBufferAllocator

    public init(nic: NIC, cache: ARPCache, allocator: ByteBufferAllocator) {
        self.nic = nic
        self.cache = cache
        self.allocator = allocator
    }

    public func handle(_ packet: PacketBuffer, _ ethernet: EthernetHeader) {
        var packet = packet
        guard let arp = ARPPacket.parse(&packet) else { return }

        // Learn from every ARP we see, request or reply. A gratuitous ARP
        // after a guest reboot updates the binding without a round trip.
        // An ARP probe uses 0.0.0.0 as the sender IP, which is not a binding.
        if arp.senderIP != .any {
            cache.record(arp.senderIP, arp.senderMAC)
        }

        guard arp.operation == .request, nic.hasAddress(arp.targetIP) else { return }

        let reply = ARPPacket(
            operation: .reply,
            senderMAC: nic.link.linkAddress,
            senderIP: arp.targetIP,
            targetMAC: arp.senderMAC,
            targetIP: arp.senderIP
        )
        var outgoing = reply.serialize(into: allocator)
        nic.send(&outgoing, to: arp.senderMAC, etherType: .arp)
    }

    /// Broadcast a request for `target`. The reply arrives through `handle`.
    public func request(_ target: IPv4Address, from source: IPv4Address) {
        let request = ARPPacket(
            operation: .request,
            senderMAC: nic.link.linkAddress,
            senderIP: source,
            targetMAC: MACAddress(bytes: [0, 0, 0, 0, 0, 0])!,
            targetIP: target
        )
        var outgoing = request.serialize(into: allocator)
        nic.send(&outgoing, to: .broadcast, etherType: .arp)
    }
}
