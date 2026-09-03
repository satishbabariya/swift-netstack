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

    /// A datagram that had nowhere to go because the next hop's link address
    /// was not yet known, held until ARP answers.
    ///
    /// Held before fragmentation rather than after: what is waiting is a
    /// request to send, and re-running `send` when the address arrives is both
    /// less state and the only version that cannot disagree with the real path.
    private struct Deferred {
        let payload: ByteBuffer
        let destination: IPv4Address
        let source: IPv4Address?
        let protocolNumber: IPProtocol
        /// Insertion order across every next hop, so the global cap can evict
        /// the oldest rather than refuse the newest.
        let sequence: UInt64
    }

    /// Keyed by NEXT HOP, which is what ARP resolves -- not by destination,
    /// which for anything off-link is a different address entirely.
    private var deferred: [IPv4Address: [Deferred]] = [:]
    private var deferredBytes = 0
    private var deferredSequence: UInt64 = 0

    /// The first datagram to a guest is the one that has to wait for ARP, so
    /// without this it is always the one that is lost. TCP survived that by
    /// retransmitting; UDP has nothing to retransmit with, and a `nc -u` into a
    /// published port dropped its first datagram every time.
    ///
    /// Bounded on three axes because the alternative is a queue a peer chooses
    /// the size of. Linux's `unres_qlen` is 3 per neighbour and this matches it;
    /// the global and byte caps are this package's own, since one unreachable
    /// address must not be able to spend the budget of every other.
    static let maximumDeferredPerNextHop = 3
    static let maximumDeferredDatagrams = 32
    static let maximumDeferredBytes = 256 * 1024

    private var handlers: [IPProtocol: (IPv4Header, ByteBuffer) -> Void] = [:]
    /// Wraps at 65535, which is what the field allows. Collisions only matter
    /// between fragments of concurrent datagrams to the same peer, and 65536
    /// is far more headroom than that needs.
    public private(set) var identificationCounter: UInt16 = 0

    /// What happened to the packets that arrived.
    ///
    /// Every one of these is a place a packet is dropped and nothing is said,
    /// which is the state an operator cannot debug: the guest insists it sent
    /// something and the gateway behaves as though it did not. Upstream reports
    /// gVisor's whole counter tree for the same reason; these are the subset
    /// that names a decision this stack actually makes.
    public struct Counters: Sendable, Equatable {
        /// Frames that reached the IPv4 layer.
        public var received = 0
        /// Rejected by `IPv4Header.parse`: too short, wrong version, bad header
        /// checksum, or a length that does not describe the packet.
        public var malformed = 0
        /// Addressed to somebody else, on a NIC that is not promiscuous.
        public var notForThisStack = 0
        /// Arrived with no time left.
        public var expired = 0
        /// Held by the reassembler, waiting for the rest of the datagram.
        public var awaitingFragments = 0
        /// Handed to a transport, or answered here in the case of echo.
        public var delivered = 0
        /// A protocol nothing has registered for. Not an error -- a guest may
        /// send anything -- but a rising count is usually a guest doing
        /// something the gateway was never set up to carry.
        public var unknownProtocol = 0
        /// Held until ARP answered, rather than dropped for want of a link
        /// address. The pair is worth having together: a rising `dropped`
        /// against a flat `deferred` is a bound being hit, which is a different
        /// problem from an address that never answers.
        public var deferredForResolution = 0
        public var droppedUnresolved = 0
    }

    public private(set) var counters = Counters()

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
        observeResolutions()
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
        counters.received += 1
        guard let header = IPv4Header.parse(&packet) else {
            counters.malformed += 1
            return
        }

        // The NIC's own Ethernet-layer filter only checks the frame's MAC
        // destination, which is ours whenever the frame was switched to us —
        // that says nothing about which IP address it was addressed to. A
        // gateway terminating a guest's connection to an arbitrary host
        // receives frames MAC-addressed to it but IP-addressed to that far
        // host; ordinary unicast to someone else's IP must still be dropped
        // unless this NIC is deliberately promiscuous.
        guard nic.acceptsAnyDestination || nic.hasAddress(header.destination) else {
            counters.notForThisStack += 1
            return
        }

        // A packet arriving with no time left is dead. We are a terminating
        // gateway, not a router, so nothing is forwarded and nothing is
        // decremented — but a zero TTL is still malformed, so it is dropped
        // before it is trusted for anything, including the opportunistic ARP
        // learning below.
        guard header.ttl > 0 else {
            counters.expired += 1
            return
        }

        // Learn the sender's link address from any packet that arrives, so a
        // reply does not need an ARP round trip.
        arpCache.record(header.source, ethernet.source)

        guard let (whole, payload) = reassembler.process(header: header, payload: packet.payload) else {
            counters.awaitingFragments += 1
            return
        }

        if whole.protocolNumber == .icmp {
            counters.delivered += 1
            handleICMP(whole, payload)
            return
        }
        guard let handler = handlers[whole.protocolNumber] else {
            counters.unknownProtocol += 1
            return
        }
        counters.delivered += 1
        handler(whole, payload)
    }

    /// Offered every echo request before this stack answers one itself.
    ///
    /// Returning true means the request has been taken: something else will
    /// produce the reply, or there will not be one. Returning false leaves the
    /// local answer below, which is what a ping to the gateway's own address
    /// wants.
    ///
    /// A hook rather than a protocol handler because echo is not delivered to
    /// `handlers[.icmp]` -- that path carries ICMP *errors* up to a transport,
    /// and giving echo to it would mean every reader of ICMP errors had to know
    /// to ignore echo.
    public var echoRequestHandler: ((IPv4Header, ICMPv4Header, ByteBuffer) -> Bool)?

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

        // Offered to the forwarder first. If it takes the request, the reply
        // comes from the address that was actually pinged -- or does not come at
        // all, which is the answer a ping is for.
        if echoRequestHandler?(header, icmp, packet.payload) == true { return }

        let reply = ICMPv4.echoReply(to: icmp, payload: packet.payload, allocator: allocator)
        // Answer from the address that was pinged, which under promiscuous mode
        // need not be one of ours.
        //
        // **So a ping through this gateway is answered by this gateway**, for
        // any address at all, and a reader should know that before trusting one.
        // A guest that pings 8.8.8.8 gets a reply whether or not 8.8.8.8 is
        // reachable, so `ping` stops being a reachability test and becomes a
        // test of whether the guest's own stack works.
        //
        // This is the fallback now, not the policy. `ICMPForwarder` takes echo
        // requests for addresses that are not this gateway's and sends them for
        // real, which is upstream's behaviour and is installed by default there.
        // What is left here answers a ping addressed to the gateway itself, and
        // answers everything if no forwarder is installed.
        try? send(payload: reply, to: header.source, from: header.destination, protocolNumber: .icmp)
    }

    // MARK: Egress

    /// Transmit a payload. Throws `.noRoute` when there is no route, when the
    /// next hop's link address is not yet known — in the latter case an ARP
    /// request goes out, so a retry shortly after will succeed — or when
    /// `source` was given and the route could not send from it (the NIC
    /// neither owns that address nor is allowed to spoof it). That last case
    /// matters: silently substituting the NIC's own address there would
    /// answer from the WRONG source rather than not answer at all, which for
    /// something like a promiscuous-but-not-spoofing echo reply is worse
    /// than a dropped packet. Throws `.messageTooLong` when `payload` cannot
    /// fit in a single IPv4 datagram at all, regardless of fragmentation.
    public func send(payload: ByteBuffer, to destination: IPv4Address, from source: IPv4Address?, protocolNumber: IPProtocol) throws {
        guard payload.readableBytes <= Self.maximumPayload else { throw StackError.messageTooLong }

        // A limited broadcast is routed by definition, not by lookup.
        //
        // 255.255.255.255 is link-local: it goes out the interface and no
        // farther, so there is no next hop to choose and nothing for a route to
        // decide. Consulting the table would be worse than redundant -- with a
        // default route present it would pick the default gateway's next hop and
        // ARP for it, which is a unicast decision applied to an address that is
        // not one.
        //
        // ARP cannot help either: there is no host at 255.255.255.255 to answer,
        // so a broadcast that went through the cache would emit an ARP request
        // per attempt and never send anything. Not hypothetical -- a DHCP offer
        // is a broadcast precisely BECAUSE the client has no address yet and
        // therefore cannot answer an ARP for one, so without this a gateway can
        // never tell a guest what its address is.
        let localSource: IPv4Address
        let nextHopMAC: MACAddress
        if destination == .broadcast {
            nextHopMAC = .broadcast
            localSource = source ?? nic.primaryAddress ?? .any
        } else {
            guard let route = routes.lookup(destination: destination, preferredSource: source) else {
                throw StackError.noRoute
            }
            guard route.sourceWasHonoured else { throw StackError.noRoute }
            guard let resolved = arpCache.lookup(route.nextHop) else {
                arpResponder.request(route.nextHop, from: route.source)
                // Held rather than dropped, if there is room. `noRoute` still
                // means what it says -- there is nowhere to send this -- but
                // "not yet" and "never" used to be reported the same way, and
                // the caller cannot tell them apart either.
                guard
                    hold(
                        payload: payload, to: destination, from: source,
                        protocolNumber: protocolNumber, nextHop: route.nextHop)
                else {
                    counters.droppedUnresolved += 1
                    throw StackError.noRoute
                }
                counters.deferredForResolution += 1
                return
            }
            nextHopMAC = resolved
            localSource = route.source
        }

        identificationCounter &+= 1
        var template = IPv4Header(
            source: localSource, destination: destination,
            protocolNumber: protocolNumber, payloadLength: payload.readableBytes)
        template.identification = identificationCounter

        let mtu = Int(nic.link.mtu)
        let fragments = Fragmenter.fragment(payload: payload, template: template, mtu: mtu, allocator: allocator)
        guard !fragments.isEmpty else { throw StackError.messageTooLong }

        for var fragment in fragments {
            nic.send(&fragment, to: nextHopMAC, etherType: .ipv4)
        }
    }

    /// Hold one datagram for a next hop that is not yet resolved. Returns false
    /// when a bound refuses it, in which case the caller drops it as before.
    ///
    private func hold(
        payload: ByteBuffer, to destination: IPv4Address, from source: IPv4Address?,
        protocolNumber: IPProtocol, nextHop: IPv4Address
    ) -> Bool {
        // Per next hop this refuses, as Linux does: three is the depth one
        // conversation is worth, and a fourth says the address is not coming.
        let waiting = deferred[nextHop]?.count ?? 0
        guard waiting < Self.maximumDeferredPerNextHop else { return false }
        guard payload.readableBytes <= Self.maximumDeferredBytes else { return false }

        // The global caps EVICT rather than refuse. Nothing else releases an
        // entry -- a datagram leaves this queue when its address resolves, and
        // an address that never resolves never releases anything -- so a cap
        // that only refused would let a peer pin the whole budget permanently
        // and shut the queue for everybody else.
        //
        // Guest-reachable, and that is why it matters here: a guest that sends
        // SYNs with spoofed on-link sources makes this gateway answer addresses
        // only that guest could ARP for, and it simply does not answer. Eleven
        // of those would have taken every slot for good.
        while deferredCount >= Self.maximumDeferredDatagrams
            || deferredBytes + payload.readableBytes > Self.maximumDeferredBytes
        {
            guard evictOldestDeferred() else { return false }
        }

        deferredSequence &+= 1
        deferred[nextHop, default: []].append(
            Deferred(
                payload: payload, destination: destination, source: source,
                protocolNumber: protocolNumber, sequence: deferredSequence))
        deferredBytes += payload.readableBytes
        return true
    }

    /// Drop the datagram that has been waiting longest, anywhere. Returns false
    /// when there is nothing left to drop, which stops the caller looping.
    private func evictOldestDeferred() -> Bool {
        var oldestHop: IPv4Address?
        var oldest = UInt64.max
        for (hop, waiting) in deferred {
            guard let first = waiting.first, first.sequence < oldest else { continue }
            oldest = first.sequence
            oldestHop = hop
        }
        guard let hop = oldestHop, var waiting = deferred[hop], !waiting.isEmpty else { return false }
        deferredBytes -= waiting.removeFirst().payload.readableBytes
        if waiting.isEmpty {
            deferred.removeValue(forKey: hop)
        } else {
            deferred[hop] = waiting
        }
        counters.droppedUnresolved += 1
        return true
    }

    /// An address became known. Send what was waiting on it, oldest first.
    ///
    /// The entry is removed BEFORE anything is sent. A send that fails again
    /// takes the ordinary path -- including deferring itself, if the address
    /// has already expired -- and re-entering this function with the queue
    /// still holding the frame it is delivering would recurse.
    func resolved(_ address: IPv4Address) {
        guard let waiting = deferred.removeValue(forKey: address) else { return }
        for item in waiting {
            deferredBytes -= item.payload.readableBytes
            try? send(
                payload: item.payload, to: item.destination, from: item.source,
                protocolNumber: item.protocolNumber)
        }
    }

    /// How many datagrams are waiting on an address, over every address.
    var deferredCount: Int { deferred.values.reduce(0) { $0 + $1.count } }

    /// Subscribe to the cache's resolutions.
    ///
    /// Done here rather than by whoever assembles the graph, because a queue
    /// that is only drained when someone remembers to wire it is a queue that
    /// silently holds datagrams for ever -- and `onRecorded` has one owner, so
    /// a second assignment elsewhere would not add a listener, it would replace
    /// this one. Every `IPv4Protocol` therefore claims it itself, including the
    /// ones tests build directly.
    private func observeResolutions() {
        arpCache.onRecorded = { [weak self] address, _ in
            self?.resolved(address)
        }
    }
}
