import Logging
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

    private let logger: Logger
    private var maintenanceTask: RepeatedTask?

    public init(
        link: LinkEndpoint,
        configuration: Configuration,
        clock: NetstackClock = RealClock(),
        allocator: ByteBufferAllocator = ByteBufferAllocator(),
        logger: Logger = Logger(label: "netstack")
    ) {
        self.eventLoop = link.eventLoop
        self.configuration = configuration
        self.logger = logger

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
}
