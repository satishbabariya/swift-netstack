import NIOCore

/// The IPv4 ingress and egress path for one NIC.
public final class IPv4Protocol {
    // `unowned`, not `let`. Stack owns the NIC, this protocol handler, and the
    // ARP responder; the NIC holds handler closures that capture this type, so
    // a strong reference back closes a retain cycle when Stack wires them
    // together. This cannot outlive the NIC that Stack owns alongside it.
    private unowned let nic: NIC
    private let routes: RouteTable
    private let arpCache: ARPCache
    private let arpResponder: ARPResponder
    private let reassembler: Reassembler
    private let allocator: ByteBufferAllocator

    /// The largest payload that can be carried in one IPv4 datagram.
    /// `IPv4Header.init(source:destination:protocolNumber:payloadLength:)`
    /// computes `UInt16(minimumLength + payloadLength)` with a non-failable
    /// conversion that TRAPS the process if the sum exceeds 65535. `send()`
    /// accepts an arbitrary caller-supplied payload, so it must reject
    /// anything over this bound before ever constructing a header — the same
    /// class of remotely-reachable non-failable-conversion crash already
    /// found once in the reassembler.
    private static let maximumPayload = 65535 - IPv4Header.minimumLength

    private var handlers: [IPProtocol: (IPv4Header, ByteBuffer) -> Void] = [:]
    /// Wraps at 65535, which is what the field allows. Collisions only matter
    /// between fragments of concurrent datagrams to the same peer, and 65536
    /// is far more headroom than that needs.
    public private(set) var identificationCounter: UInt16 = 0

    /// Accept and deliver packets addressed to a host other than this NIC.
    /// Mirrors `NIC.acceptsAnyDestination`, since the two must agree: a frame
    /// the link layer refuses never reaches here, but a frame it does accept
    /// for a foreign IP address should only be delivered onward when the NIC
    /// is deliberately promiscuous.
    public var acceptsAnyDestination: Bool { nic.acceptsAnyDestination }

    public init(
        nic: NIC, routes: RouteTable, arpCache: ARPCache, arpResponder: ARPResponder,
        reassembler: Reassembler, allocator: ByteBufferAllocator
    ) {
        self.nic = nic
        self.routes = routes
        self.arpCache = arpCache
        self.arpResponder = arpResponder
        self.reassembler = reassembler
        self.allocator = allocator
    }

    public func setHandler(for protocolNumber: IPProtocol, _ handler: @escaping (IPv4Header, ByteBuffer) -> Void) {
        handlers[protocolNumber] = handler
    }

    /// Detach every registered handler. `Stack.shutdown()` calls this
    /// alongside `NIC.removeAllHandlers()` for the same reason: a handler
    /// closure stored here can capture `self`, which otherwise keeps this
    /// type alive purely through its own handler table.
    public func removeAllHandlers() {
        handlers.removeAll()
    }

    // MARK: Ingress

    public func handleInbound(_ packet: PacketBuffer, _ ethernet: EthernetHeader) {
        var packet = packet
        guard let header = IPv4Header.parse(&packet) else { return }

        // The NIC's own Ethernet-layer filter only checks the frame's MAC
        // destination, which is ours whenever the frame was switched to us —
        // that says nothing about which IP address it was addressed to. A
        // gateway terminating a guest's connection to an arbitrary host
        // receives frames MAC-addressed to it but IP-addressed to that far
        // host; ordinary unicast to someone else's IP must still be dropped
        // unless this NIC is deliberately promiscuous.
        guard nic.acceptsAnyDestination || nic.hasAddress(header.destination) else { return }

        // A packet arriving with no time left is dead. We are a terminating
        // gateway, not a router, so nothing is forwarded and nothing is
        // decremented — but a zero TTL is still malformed, so it is dropped
        // before it is trusted for anything, including the opportunistic ARP
        // learning below.
        guard header.ttl > 0 else { return }

        // Learn the sender's link address from any packet that arrives, so a
        // reply does not need an ARP round trip.
        arpCache.record(header.source, ethernet.source)

        guard let (whole, payload) = reassembler.process(header: header, payload: packet.payload) else { return }

        if whole.protocolNumber == .icmp {
            handleICMP(whole, payload)
            return
        }
        handlers[whole.protocolNumber]?(whole, payload)
    }

    private func handleICMP(_ header: IPv4Header, _ payload: ByteBuffer) {
        var packet = PacketBuffer(received: payload)
        guard let icmp = ICMPv4Header.parse(&packet) else { return }

        // Only echo is answered here. Errors are delivered to whoever
        // registered for ICMP, so a transport can act on them — path MTU
        // discovery in Plan 2 needs fragmentation-needed.
        guard icmp.type == .echoRequest else {
            handlers[.icmp]?(header, payload)
            return
        }

        let reply = ICMPv4.echoReply(to: icmp, payload: packet.payload, allocator: allocator)
        // Answer from the address that was pinged, which under promiscuous
        // mode need not be one of ours.
        try? send(payload: reply, to: header.source, from: header.destination, protocolNumber: .icmp)
    }

    // MARK: Egress

    /// Transmit a payload. Throws `.noRoute` when there is no route, or when
    /// the next hop's link address is not yet known — in the latter case an
    /// ARP request goes out, so a retry shortly after will succeed. Throws
    /// `.messageTooLong` when `payload` cannot fit in a single IPv4 datagram
    /// at all, regardless of fragmentation.
    public func send(payload: ByteBuffer, to destination: IPv4Address, from source: IPv4Address?, protocolNumber: IPProtocol) throws {
        guard payload.readableBytes <= Self.maximumPayload else { throw StackError.messageTooLong }

        guard let route = routes.lookup(destination: destination, preferredSource: source) else {
            throw StackError.noRoute
        }
        guard let nextHopMAC = arpCache.lookup(route.nextHop) else {
            arpResponder.request(route.nextHop, from: route.source)
            throw StackError.noRoute
        }

        identificationCounter &+= 1
        var template = IPv4Header(
            source: route.source, destination: destination,
            protocolNumber: protocolNumber, payloadLength: payload.readableBytes)
        template.identification = identificationCounter

        let mtu = Int(nic.link.mtu)
        let fragments = Fragmenter.fragment(payload: payload, template: template, mtu: mtu, allocator: allocator)
        guard !fragments.isEmpty else { throw StackError.messageTooLong }

        for var fragment in fragments {
            nic.send(&fragment, to: nextHopMAC, etherType: .ipv4)
        }
    }
}
