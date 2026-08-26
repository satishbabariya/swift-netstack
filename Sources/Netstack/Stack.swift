import NIOCore

/// One virtual network stack, owning one event loop and one link.
///
/// Every method and every callback runs on `eventLoop`. That is the whole
/// concurrency design: no locks, because there is nothing to contend for.
///
/// `shutdown()` is not merely tidy — it is mandatory. The maintenance timer
/// started by `start()` is a `RepeatedTask`, and NIO's `RepeatedTask`
/// self-perpetuates: each firing reschedules the next one as a closure the
/// event loop retains internally, independent of any external reference.
/// Dropping every reference to this `Stack` — including this `Stack` itself
/// — does not stop it; only `cancel()`, which `shutdown()` calls, does. Skip
/// `shutdown()` and the timer keeps firing forever, holding the
/// `Reassembler` alive with it, even after the rest of the stack (`nic`,
/// `arpResponder`, `ipv4`, `routes`, `arpCache`) has been deallocated.
public final class Stack {
    public struct Configuration: Sendable {
        /// The address the stack answers for — the guest's default gateway.
        public var gatewayAddress: IPv4Address
        public var subnet: IPv4Subnet
        /// Accept frames addressed to other hosts. On by default: the gateway
        /// terminates connections to arbitrary destinations, so it must.
        public var acceptsAnyDestination: Bool
        /// Transmit from addresses we do not own. On by default, same reason.
        public var allowsAnySource: Bool
        public var reassemblyTimeout: TimeAmount
        public var maintenanceInterval: TimeAmount

        public init(
            gatewayAddress: IPv4Address,
            subnet: IPv4Subnet,
            acceptsAnyDestination: Bool = true,
            allowsAnySource: Bool = true,
            reassemblyTimeout: TimeAmount = .seconds(30),
            maintenanceInterval: TimeAmount = .seconds(10)
        ) {
            self.gatewayAddress = gatewayAddress
            self.subnet = subnet
            self.acceptsAnyDestination = acceptsAnyDestination
            self.allowsAnySource = allowsAnySource
            self.reassemblyTimeout = reassemblyTimeout
            self.maintenanceInterval = maintenanceInterval
        }
    }

    public let eventLoop: EventLoop
    public let configuration: Configuration
    public let nic: NIC
    public let routes: RouteTable
    public let arpCache: ARPCache
    public let arpResponder: ARPResponder
    public let reassembler: Reassembler
    public let ipv4: IPv4Protocol
    public let transportDemuxer = TransportDemuxer()

    private let allocator: ByteBufferAllocator
    private var maintenanceTask: RepeatedTask?

    public init(
        link: LinkEndpoint,
        configuration: Configuration,
        clock: NetstackClock = RealClock(),
        allocator: ByteBufferAllocator = ByteBufferAllocator()
    ) {
        self.eventLoop = link.eventLoop
        self.configuration = configuration
        self.allocator = allocator

        let nic = NIC(id: 1, link: link)
        nic.addAddress(configuration.gatewayAddress, prefixLength: configuration.subnet.prefixLength)
        nic.acceptsAnyDestination = configuration.acceptsAnyDestination
        nic.allowsAnySource = configuration.allowsAnySource
        self.nic = nic

        let routes = RouteTable()
        routes.register(nic)
        routes.add(Route(destination: configuration.subnet, gateway: nil, nicID: nic.id))
        // With spoofing on, everything else is reachable through this NIC too:
        // the stack answers as any host the guest tries to reach. This route
        // has a shorter prefix (0) than the subnet route above, so longest-
        // prefix selection in RouteTable still prefers the subnet route for
        // on-link destinations; this one only ever matches what the subnet
        // route did not.
        if configuration.allowsAnySource {
            routes.add(Route(destination: IPv4Subnet(cidr: "0.0.0.0/0")!, gateway: nil, nicID: nic.id))
        }
        self.routes = routes

        let arpCache = ARPCache(clock: clock)
        let arpResponder = ARPResponder(nic: nic, cache: arpCache, allocator: allocator)
        let reassembler = Reassembler(clock: clock, timeout: configuration.reassemblyTimeout)
        self.arpCache = arpCache
        self.arpResponder = arpResponder
        self.reassembler = reassembler

        self.ipv4 = IPv4Protocol(
            nic: nic, routes: routes, arpCache: arpCache, arpResponder: arpResponder,
            reassembler: reassembler, allocator: allocator)
    }

    /// Wire the protocol handlers to the NIC and start the maintenance timer.
    public func start() {
        nic.setHandler(for: .arp) { [arpResponder] packet, ethernet in
            arpResponder.handle(packet, ethernet)
        }
        nic.setHandler(for: .ipv4) { [ipv4] packet, ethernet in
            ipv4.handleInbound(packet, ethernet)
        }

        ipv4.setHandler(for: .udp) { [transportDemuxer, ipv4, allocator] header, payload in
            var packet = PacketBuffer(received: payload)
            guard let udp = UDPHeader.parse(&packet, header: header) else { return }
            let delivered = transportDemuxer.deliver(
                protocolNumber: .udp, header: header, payload: packet.payload,
                localPort: udp.destinationPort, remotePort: udp.sourcePort)
            guard !delivered else { return }

            // Nothing is listening. Tell the sender, so it fails fast instead
            // of retrying into a void.
            var quoted = ByteBuffer()
            quoted.writeInteger(udp.sourcePort, endianness: .big)
            quoted.writeInteger(udp.destinationPort, endianness: .big)
            // `udp.length` is already the full wire field (header plus
            // payload) — see UDPHeader.parse — so it is quoted as-is.
            quoted.writeInteger(udp.length, endianness: .big)
            quoted.writeInteger(udp.checksum, endianness: .big)
            let message = ICMPv4.destinationUnreachable(
                code: .port, quoting: header, quotedPayload: quoted, allocator: allocator)
            try? ipv4.send(payload: message, to: header.source, from: header.destination, protocolNumber: .icmp)
        }

        // A second start() would overwrite the reference to a task that keeps
        // rescheduling itself, leaving it unreachable and unstoppable. Cancel
        // first so it can never be orphaned.
        assert(maintenanceTask == nil, "Stack.start() called more than once")
        maintenanceTask?.cancel()

        maintenanceTask = eventLoop.scheduleRepeatedTask(
            initialDelay: configuration.maintenanceInterval,
            delay: configuration.maintenanceInterval
        ) { [reassembler] _ in
            reassembler.reapExpired()
        }
    }

    public func shutdown() -> EventLoopFuture<Void> {
        guard let task = maintenanceTask else {
            return eventLoop.makeSucceededVoidFuture()
        }
        maintenanceTask = nil
        let promise = eventLoop.makePromise(of: Void.self)
        task.cancel(promise: promise)
        return promise.futureResult
    }

    deinit {
        // The maintenance timer reschedules itself through the event loop's own
        // queue, so it outlives every external reference to this Stack. Only
        // `cancel()` breaks that chain. A bare cancel is safe here: it does not
        // require being on the event loop, captures no `self`, and takes no
        // promise — so it cannot deadlock the way awaiting `shutdown()` would.
        maintenanceTask?.cancel()
    }
}
