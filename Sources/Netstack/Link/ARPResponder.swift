import NIOCore

/// Answers ARP requests for addresses this NIC owns, and learns bindings from
/// everything it sees.
public final class ARPResponder {
    // Strong, unlike `IPv4Protocol.nic`. That similarity is only skin deep:
    // `IPv4Protocol` is backstopped even though its own field is `unowned`
    // — `ipv4 -> routes -> nics -> nic` keeps the NIC alive regardless — so
    // its `unowned` never actually risks dangling. `ARPResponder` had no
    // such backstop: `stack.arpResponder` is public, so `let r =
    // stack.arpResponder` outliving `stack` was a reachable, un-backstopped
    // dangling `unowned` — trapping on the next `handle` or `request` once
    // the retain-cycle fix elsewhere in this package started actually
    // deallocating things that used to leak forever. A strong reference
    // here is safe from creating a NEW cycle only because `Stack.start()`
    // captures `self` (`arpResponder`) WEAKLY in the NIC's `.arp` handler
    // closure — see the comment there. Without that, `nic.handlers ->
    // closure -> ARPResponder -> nic` would be a self-contained cycle
    // neither Stack nor anything else in this graph sits outside of.
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
