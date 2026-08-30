import Logging
import NIOCore
import NIOPosix

/// A whole gateway on one wire: the stack, the services a guest needs to
/// configure itself, and the forwarders that carry its traffic to the host.
///
/// This is the type a user of this package is expected to reach for. Everything
/// under it is public and can be assembled by hand -- and that is the right
/// thing to do when the arrangement is unusual -- but the ordinary arrangement
/// is one object, and having to know that a UDP forwarder must be built after
/// the DNS server, or that both must live on the link's event loop, is knowledge
/// this type exists to hold.
///
/// ## Starting one for Virtualization.framework
///
/// ```swift
/// // The host keeps one end of the pair and hands the other to the VM.
/// var pair: [Int32] = [0, 0]
/// socketpair(AF_UNIX, SOCK_DGRAM, 0, &pair)
/// let gateway = try await Gateway.start(
///     adoptingDatagramSocket: pair[0], group: group,
///     configuration: .init()).get()
/// // pair[1] goes to VZFileHandleNetworkDeviceAttachment.
/// ```
public final class Gateway: @unchecked Sendable {
    public struct Configuration: Sendable {
        /// The address the gateway answers on, and the one the guest is told to
        /// use as its router and resolver.
        public var gatewayAddress: IPv4Address
        public var subnet: IPv4Subnet
        public var linkAddress: MACAddress
        /// The address inside the subnet that means "the host".
        ///
        /// Separate from `gatewayAddress` because they are different things and
        /// upstream keeps them apart for a reason: the gateway is a router, and
        /// the host is a machine reachable through it. The gateway answers ARP
        /// for this address so a guest can address it, and `nat` rewrites a dial
        /// to it into a dial to the host's loopback -- which is where the host's
        /// own services actually are.
        public var hostAddress: IPv4Address
        /// Rewrites applied to the address a guest dialled, before it is dialled
        /// for real. Upstream's `NAT`; the default maps `hostAddress` to
        /// loopback and nothing else.
        public var nat: [IPv4Address: IPv4Address]
        /// Extra addresses the gateway answers ARP for. Upstream's
        /// `GatewayVirtualIPs`; `hostAddress` is added to this by default,
        /// because an address nothing answers ARP for is an address no guest can
        /// send to.
        public var gatewayVirtualAddresses: [IPv4Address]
        /// Whether guests may reach 169.254.0.0/16.
        ///
        /// **Off by default, and this is a security default rather than a
        /// preference.** 169.254.169.254 is the cloud instance metadata service,
        /// which hands credentials to whatever asks from the host. Upstream
        /// spells the same switch `Ec2MetadataAccess` and also defaults it off.
        public var allowsLinkLocal: Bool
        /// Write every frame in and out to a pcap file at this path. Upstream's
        /// `CaptureFile`. Bounded -- see `PacketCapture`.
        public var captureFile: String?
        /// The cap on that file. Reaching it stops the capture.
        public var captureMaximumBytes: Int
        /// A unix socket to tell about guests arriving and leaving. Upstream's
        /// notification socket; `nil` means send nothing at all.
        public var notificationSocketPath: String?
        public var mtu: UInt32
        /// Names this gateway answers itself. The zone of each is also owned:
        /// with `gateway.containers.internal` here, any other name under
        /// `containers.internal` is answered NXDOMAIN rather than forwarded.
        public var dnsRecords: [DNSServer.StaticRecord]
        /// Where to send names this gateway does not own. Empty means it will
        /// not forward at all, and says so with REFUSED rather than a timeout.
        public var upstreamResolvers: [SocketAddress]
        public var leaseSeconds: UInt32
        /// Addresses pinned to a hardware address. Upstream's
        /// `DHCPStaticLeases`, and how a caller gives a guest an address it can
        /// forward a port to before the guest has ever booted.
        public var dhcpStaticLeases: [MACAddress: IPv4Address]
        /// Search domains offered in every DHCP reply, so a guest can resolve
        /// short names. Upstream's `DNSSearchDomains`.
        public var dnsSearchDomains: [String]
        /// Every bound a guest can push against, in one place because they are
        /// one decision: how much of this process a guest may occupy.
        public var maximumTCPConnections: Int
        public var maximumUDPFlows: Int
        public var maximumHalfOpenConnections: Int
        /// How many guests may share one switch. Only read by
        /// `start(switchListeningOnStreamSocketAt:)`.
        public var maximumGuests: Int
        /// Applied to every forwarded connection's guest-side endpoint. On by
        /// default -- see `OutboundTCPForwarder.init` for why that is the
        /// opposite of `TCPEndpoint`'s default and right here.
        public var keepAlive: TCPEndpoint.KeepAliveConfiguration?
        /// Where this gateway reports what it refuses and why.
        ///
        /// Defaults to `Logger(label: "netstack")`, which routes through
        /// whatever the host process bootstrapped -- the ecosystem convention,
        /// and the one that means an embedder who has already configured
        /// logging gets these lines without asking. Every event a guest can
        /// cause is rate-limited before it reaches this; see
        /// `RateLimitedLogger` for why that is not optional.
        public var logger: Logger
        /// How often a repeating guest-caused event may be logged. See
        /// `RateLimitedLogger`.
        public var logWindow: TimeAmount

        public init(
            gatewayAddress: IPv4Address = IPv4Address("192.168.127.1")!,
            subnet: IPv4Subnet = IPv4Subnet(cidr: "192.168.127.0/24")!,
            linkAddress: MACAddress = MACAddress("5a:94:ef:e4:0c:ee")!,
            hostAddress: IPv4Address = IPv4Address("192.168.127.254")!,
            nat: [IPv4Address: IPv4Address]? = nil,
            gatewayVirtualAddresses: [IPv4Address]? = nil,
            allowsLinkLocal: Bool = false,
            captureFile: String? = nil,
            captureMaximumBytes: Int = 64 * 1024 * 1024,
            notificationSocketPath: String? = nil,
            mtu: UInt32 = 1500,
            dnsRecords: [DNSServer.StaticRecord]? = nil,
            upstreamResolvers: [SocketAddress] = [],
            leaseSeconds: UInt32 = 3600,
            dhcpStaticLeases: [MACAddress: IPv4Address] = [:],
            dnsSearchDomains: [String] = [],
            maximumTCPConnections: Int = 1024,
            maximumUDPFlows: Int = 512,
            maximumHalfOpenConnections: Int = 512,
            maximumGuests: Int = 32,
            keepAlive: TCPEndpoint.KeepAliveConfiguration? = TCPEndpoint.KeepAliveConfiguration(),
            logger: Logger = Logger(label: "netstack"),
            logWindow: TimeAmount = .seconds(10)
        ) {
            self.gatewayAddress = gatewayAddress
            self.subnet = subnet
            self.linkAddress = linkAddress
            self.hostAddress = hostAddress
            self.nat = nat ?? [hostAddress: IPv4Address("127.0.0.1")!]
            self.gatewayVirtualAddresses = gatewayVirtualAddresses ?? [hostAddress]
            self.allowsLinkLocal = allowsLinkLocal
            self.captureFile = captureFile
            self.captureMaximumBytes = captureMaximumBytes
            self.notificationSocketPath = notificationSocketPath
            self.mtu = mtu
            // The two names upstream publishes, so a guest written against
            // gvisor-tap-vsock finds what it expects. Both resolve to the
            // gateway: the host is reachable through it and only through it.
            // `host.containers.internal` resolves to the HOST address, not to
            // the gateway. They were the same here once, and that was wrong in a
            // way nothing failed on: a guest that resolved the name got the
            // gateway's address, dialled it, and the gateway then tried to reach
            // 192.168.127.1 on the host -- where nothing is listening, because
            // the host's own services are on its loopback. Reaching the host is
            // the headline feature of this whole package and it did not work.
            self.dnsRecords =
                dnsRecords ?? [
                    .init(name: "gateway.containers.internal", address: gatewayAddress),
                    .init(name: "host.containers.internal", address: hostAddress),
                ]
            self.upstreamResolvers = upstreamResolvers
            self.leaseSeconds = leaseSeconds
            self.dhcpStaticLeases = dhcpStaticLeases
            self.dnsSearchDomains = dnsSearchDomains
            self.maximumTCPConnections = maximumTCPConnections
            self.maximumUDPFlows = maximumUDPFlows
            self.maximumHalfOpenConnections = maximumHalfOpenConnections
            self.maximumGuests = maximumGuests
            self.keepAlive = keepAlive
            self.logger = logger
            self.logWindow = logWindow
        }
    }

    /// Either one guest on one wire, or a `NetworkSwitch` carrying several.
    public let link: GatewayLink
    /// The switch, when this gateway was started on one. `nil` for a gateway on
    /// a single wire, which is what makes "is this a network or a link?" a
    /// question a caller can answer rather than infer.
    public var networkSwitch: NetworkSwitch? { link as? NetworkSwitch }
    public let stack: Stack
    public let dhcp: DHCPServer
    public let dns: DNSServer
    public let tcp: OutboundTCPForwarder
    public let udp: UDPForwarder
    /// Sends guests' pings for real. See `ICMPForwarder` for why the gateway
    /// answering them itself is not good enough.
    public let icmp: ICMPForwarder
    /// The bounded logger every part of this gateway reports through. Public so
    /// an embedder assembling extra pieces can share the same window rather
    /// than opening a second, unbounded one alongside it.
    public let log: RateLimitedLogger
    /// Where this gateway reports guests arriving and leaving, if anywhere.
    public let notifications: NotificationSender?

    /// Live forwards, keyed by the host port they publish on. A dictionary
    /// rather than an array because the control plane addresses them by that
    /// port -- and because two forwards on one port is a state the type should
    /// not be able to represent.
    private var forwards: [Int: PortForwarder] = [:]
    /// UDP forwards, keyed by host port. A separate table from the TCP one
    /// because a host port is only unique **within** a protocol: 8080/tcp and
    /// 8080/udp are two different things and both may be published at once, which
    /// is why upstream keys its own proxies by protocol and port together.
    private var udpForwards: [Int: UDPPortForwarder] = [:]
    /// Forwards published on a unix socket, keyed by path.
    private var unixForwards: [String: PortForwarder] = [:]
    private let keepAlive: TCPEndpoint.KeepAliveConfiguration?

    public var eventLoop: EventLoop { link.eventLoop }

    private init(
        link: GatewayLink, stack: Stack, dhcp: DHCPServer, dns: DNSServer,
        tcp: OutboundTCPForwarder, udp: UDPForwarder, icmp: ICMPForwarder,
        keepAlive: TCPEndpoint.KeepAliveConfiguration?, log: RateLimitedLogger,
        notifications: NotificationSender?
    ) {
        self.keepAlive = keepAlive
        self.log = log
        self.notifications = notifications
        self.link = link
        self.stack = stack
        self.dhcp = dhcp
        self.dns = dns
        self.tcp = tcp
        self.udp = udp
        self.icmp = icmp
    }

    /// Start on an already-connected datagram socket -- the descriptor
    /// Virtualization.framework and vfkit hand over.
    public static func start(
        adoptingDatagramSocket descriptor: NIOBSDSocket.Handle, group: EventLoopGroup,
        configuration: Configuration = Configuration()
    ) -> EventLoopFuture<Gateway> {
        WireBootstrap.adoptingDatagramSocket(
            descriptor, group: group, linkAddress: configuration.linkAddress, mtu: configuration.mtu
        ).flatMap { link in
            assemble(on: link, group: group, configuration: configuration)
        }
    }

    /// Bind a unix datagram socket and serve whoever sends to it -- the shape
    /// vfkit expects, where the gateway listens and the VM dials.
    public static func start(
        listeningOnDatagramSocketAt path: String, group: EventLoopGroup,
        configuration: Configuration = Configuration()
    ) -> EventLoopFuture<Gateway> {
        WireBootstrap.listeningDatagramSocket(
            atPath: path, group: group, linkAddress: configuration.linkAddress, mtu: configuration.mtu
        ).flatMap { link in
            assemble(on: link, group: group, configuration: configuration)
        }
    }

    /// Bind a unix stream socket and serve the first guest to connect -- qemu's
    /// `-netdev socket,connect=`.
    ///
    /// The returned future completes when that guest arrives, not when the
    /// socket is bound: there is no link until there is a wire behind it.
    public static func start(
        listeningOnStreamSocketAt path: String, group: EventLoopGroup,
        configuration: Configuration = Configuration()
    ) -> EventLoopFuture<Gateway> {
        WireBootstrap.listeningStreamSocket(
            atPath: path, group: group, linkAddress: configuration.linkAddress, mtu: configuration.mtu
        ).flatMap { link in
            assemble(on: link, group: group, configuration: configuration)
        }
    }

    /// Start on a stream socket carrying length-prefixed frames -- qemu's
    /// `-netdev socket`.
    public static func start(
        adoptingStreamSocket descriptor: NIOBSDSocket.Handle, group: EventLoopGroup,
        configuration: Configuration = Configuration()
    ) -> EventLoopFuture<Gateway> {
        WireBootstrap.adoptingStreamSocket(
            descriptor, group: group, linkAddress: configuration.linkAddress, mtu: configuration.mtu
        ).flatMap { link in
            assemble(on: link, group: group, configuration: configuration)
        }
    }

    /// Bind a unix stream socket and serve **every** guest that connects, each
    /// on its own port of a `NetworkSwitch`.
    ///
    /// This is upstream's ordinary shape and the one `listeningStreamSocket`
    /// does not cover: gvisor-tap-vsock is a network, not a point-to-point link,
    /// and guests on it can reach each other without the gateway seeing the
    /// traffic at all. DHCP already leases per hardware address, so each guest
    /// gets its own.
    ///
    /// The future completes when the socket is bound rather than when a guest
    /// arrives -- a switch with no ports is a valid state, and a caller that had
    /// to wait for the first guest could not publish ports or answer its control
    /// socket until one turned up.
    public static func start(
        switchListeningOnStreamSocketAt path: String, group: EventLoopGroup,
        configuration: Configuration = Configuration()
    ) -> EventLoopFuture<Gateway> {
        WireBootstrap.switchedStreamSocket(
            atPath: path, group: group, linkAddress: configuration.linkAddress, mtu: configuration.mtu,
            maximumGuests: configuration.maximumGuests
        ).flatMap { netSwitch in
            assemble(on: netSwitch, group: group, configuration: configuration)
        }
    }

    /// Build everything on the link's own loop.
    ///
    /// The order is not arbitrary and this is the one place it is written down:
    /// the DHCP and DNS servers bind their UDP ports **before** the UDP
    /// forwarder installs its protocol handler, so that when the handler falls
    /// through -- which it does for anything addressed to the gateway -- there
    /// is something bound for the datagram to reach.
    private static func assemble(
        on wire: GatewayLink, group: EventLoopGroup, configuration: Configuration
    ) -> EventLoopFuture<Gateway> {
        wire.eventLoop.submit {
            // Wrapped before anything attaches to it, so the capture sees every
            // frame rather than every frame after the first. A capture that
            // fails to open is not a reason to refuse to start a network: it is
            // reported and the gateway runs without one.
            var link = wire
            if let path = configuration.captureFile {
                if let capture = try? PacketCapture(
                    path: path, snapshotLength: Int(configuration.mtu) + EthernetHeader.length,
                    maximumBytes: configuration.captureMaximumBytes)
                {
                    link = CapturingLink(wrapping: wire, capture: capture)
                } else {
                    configuration.logger.error("could not open the capture file at \(path)")
                }
            }
            let stack = Stack(
                link: link,
                configuration: Stack.Configuration(
                    gatewayAddress: configuration.gatewayAddress, subnet: configuration.subnet))
            stack.start()

            let dhcp = try DHCPServer(
                stack: stack, leaseSeconds: configuration.leaseSeconds,
                mtu: UInt16(truncatingIfNeeded: configuration.mtu),
                staticLeases: configuration.dhcpStaticLeases,
                searchDomains: configuration.dnsSearchDomains)
            let dns = try DNSServer(
                stack: stack, records: configuration.dnsRecords,
                upstream: configuration.upstreamResolvers)
            // Every virtual address the gateway answers for, added to the NIC
            // before anything can ask: ARP is answered from `NIC.hasAddress`,
            // so an address that is not here is one no guest can send to,
            // whatever the DNS says it resolves to.
            for address in configuration.gatewayVirtualAddresses {
                stack.nic.addAddress(address, prefixLength: configuration.subnet.prefixLength)
            }

            let tcp = OutboundTCPForwarder(
                stack: stack, maximumInFlight: configuration.maximumHalfOpenConnections,
                maximumConnections: configuration.maximumTCPConnections,
                keepAlive: configuration.keepAlive, nat: configuration.nat,
                allowsLinkLocal: configuration.allowsLinkLocal)
            let udp = UDPForwarder(
                stack: stack, maximumFlows: configuration.maximumUDPFlows, nat: configuration.nat,
                allowsLinkLocal: configuration.allowsLinkLocal)
            let icmp = ICMPForwarder(
                stack: stack, nat: configuration.nat,
                allowsLinkLocal: configuration.allowsLinkLocal)

            // One limiter shared by every part, not one each. Nine components
            // with a window apiece would let a guest that can drive several
            // events at once emit several lines per window -- the bound would
            // then be per event *per component*, which is not the bound this
            // was written to be. Sharing it also means the counts an operator
            // reads add up across the whole gateway.
            let log = RateLimitedLogger(
                logger: configuration.logger, clock: stack.clock, window: configuration.logWindow)
            link.log = log

            var notifications: NotificationSender?
            if let path = configuration.notificationSocketPath {
                let sender = NotificationSender(socketPath: path, eventLoop: link.eventLoop)
                sender.log = log
                (link as? NetworkSwitch)?.notifications = sender
                notifications = sender
            }
            dhcp.log = log
            dns.log = log
            tcp.log = log
            udp.log = log
            icmp.log = log
            return Gateway(
                link: link, stack: stack, dhcp: dhcp, dns: dns, tcp: tcp, udp: udp, icmp: icmp,
                keepAlive: configuration.keepAlive, log: log, notifications: notifications)
        }.flatMap { (gateway: Gateway) -> EventLoopFuture<Gateway> in
            gateway.dns.startForwarding(group: group).map { _ in gateway }
        }.flatMap { (gateway: Gateway) -> EventLoopFuture<Gateway> in
            // `ready` last, and on the loop: a supervisor that acts on it -- by
            // starting the VM, usually -- must not do so before the services it
            // will talk to are listening.
            gateway.eventLoop.submit {
                gateway.notifications?.send(.init(kind: .ready))
                return gateway
            }
        }
    }

    /// Publish a guest port on the host.
    ///
    /// `host` defaults to loopback rather than `0.0.0.0`: publishing a guest's
    /// port to the whole network the moment somebody forwards one is not what
    /// "publish a port to my machine" means, and is not a mistake the user would
    /// see. See `PortForwarder`.
    public func forward(
        hostPort: Int, toGuest guestAddress: IPv4Address, port guestPort: UInt16,
        host: String = "127.0.0.1"
    ) -> EventLoopFuture<PortForwarder> {
        let forwarder = PortForwarder(
            stack: stack, guestAddress: guestAddress, guestPort: guestPort, keepAlive: keepAlive)
        forwarder.log = log
        return forwarder.listen(host: host, port: hostPort).map { [weak self] _ -> PortForwarder in
            // Keyed on the port the LISTENER ended up with, not on the one that
            // was asked for: a caller may ask for zero and mean "anything free",
            // and a forward filed under zero is one nothing can ever address.
            let bound = forwarder.listeningAddress?.port ?? hostPort
            self?.forwards[bound] = forwarder
            return forwarder
        }
    }

    /// Publish a guest's **UDP** port on the host.
    public func forwardUDP(
        hostPort: Int, toGuest guestAddress: IPv4Address, port guestPort: UInt16,
        host: String = "127.0.0.1"
    ) -> EventLoopFuture<UDPPortForwarder> {
        let forwarder = UDPPortForwarder(
            stack: stack, guestAddress: guestAddress, guestPort: guestPort)
        forwarder.log = log
        return forwarder.listen(host: host, port: hostPort).map { [weak self] _ -> UDPPortForwarder in
            let bound = forwarder.listeningAddress?.port ?? hostPort
            self?.udpForwards[bound] = forwarder
            return forwarder
        }
    }

    /// Publish a guest's TCP port on a **unix socket** rather than a host port.
    ///
    /// Who may reach the guest is then decided by filesystem permissions, which
    /// is a stronger and more visible answer than "anything that can open a
    /// connection to a port on this machine".
    public func forward(
        unixSocketPath path: String, toGuest guestAddress: IPv4Address, port guestPort: UInt16
    ) -> EventLoopFuture<PortForwarder> {
        let forwarder = PortForwarder(
            stack: stack, guestAddress: guestAddress, guestPort: guestPort, keepAlive: keepAlive)
        forwarder.log = log
        return forwarder.listen(unixSocketPath: path).map { [weak self] _ -> PortForwarder in
            self?.unixForwards[path] = forwarder
            return forwarder
        }
    }

    /// Stop a UDP forward. Returns whether there was one to stop.
    @discardableResult
    public func stopForwardingUDP(hostPort: Int) -> Bool {
        guard let forwarder = udpForwards.removeValue(forKey: hostPort) else { return false }
        forwarder.close()
        return true
    }

    /// Stop a unix-socket forward. Returns whether there was one to stop.
    @discardableResult
    public func stopForwarding(unixSocketPath path: String) -> Bool {
        guard let forwarder = unixForwards.removeValue(forKey: path) else { return false }
        forwarder.close()
        return true
    }

    /// The host UDP ports currently published, ascending.
    public var forwardedUDPPorts: [Int] { udpForwards.keys.sorted() }
    /// The unix socket paths currently published, sorted.
    public var forwardedUnixPaths: [String] { unixForwards.keys.sorted() }

    /// The address leased to a guest, once it has asked for one. This is how a
    /// caller learns where to forward a port to without being told.
    public func leasedAddress(for hardware: MACAddress) -> IPv4Address? {
        dhcp.leasedAddress(for: hardware)
    }

    /// Stop publishing a port. Returns whether there was one to stop.
    ///
    /// Closing the listener does not close the connections already spliced
    /// through it, and that is the right behaviour rather than an omission: a
    /// forward being withdrawn means "accept no more", and tearing down live
    /// connections would make unexposing a port a way to cut off work in
    /// progress.
    @discardableResult
    public func stopForwarding(hostPort: Int) -> Bool {
        guard let forwarder = forwards.removeValue(forKey: hostPort) else { return false }
        forwarder.close()
        return true
    }

    /// The host ports currently published, ascending.
    public var forwardedPorts: [Int] { forwards.keys.sorted() }

    /// The forwarder on a given host port. For tests, and for a caller that
    /// wants to read where a forward actually landed.
    public func forwarderForTesting(hostPort: Int) -> PortForwarder? { forwards[hostPort] }

    /// Close everything, and complete when the gateway is **finished with the
    /// event loop** rather than when the wire's channel reports closed.
    ///
    /// The difference matters to any caller that shuts its `EventLoopGroup` down
    /// afterwards, which is every test here and most embedders. Channel teardown
    /// defers its last step -- `removeHandlers`, which is what breaks the
    /// channel/pipeline retain cycle -- to a later tick, so work is still queued
    /// when the close future fires. Shutting the group down at that moment
    /// leaves that work scheduling onto a dead loop, which NIO currently warns
    /// about and says it will turn into a crash.
    ///
    /// One extra hop is enough and no more: the deferred blocks were queued
    /// before this hop, and a loop runs its queue in order.
    public func close() -> EventLoopFuture<Void> {
        // Hopped onto the loop first, because everything below is loop-confined:
        // `forwards` is mutated by `forward` from a future callback on the loop,
        // and the services' `close` methods each touch state their own loop
        // owns. Reading them from the caller's thread -- which is what this did,
        // and what every test here does -- is a data race that happened to be
        // quiet. A `preconditionInEventLoop` added to `NetworkSwitch.close` is
        // what turned it into a crash and found it.
        eventLoop.flatSubmit { self.closeOnLoop() }
    }

    private func closeOnLoop() -> EventLoopFuture<Void> {
        eventLoop.preconditionInEventLoop()
        var closing = forwards.values.map { $0.close() }
        forwards.removeAll()
        closing.append(contentsOf: unixForwards.values.map { $0.close() })
        unixForwards.removeAll()
        closing.append(contentsOf: udpForwards.values.map { $0.close() })
        udpForwards.removeAll()
        closing.append(udp.close())
        closing.append(dns.close())
        closing.append(dhcp.close())
        closing.append(tcp.close())
        // Report what the last window was still holding. A flood that stopped
        // has a count nobody has seen yet, and close is the last chance to say
        // so.
        log.flush()
        closing.append(link.close())
        // `Stack.shutdown()` is documented by `Stack` itself as mandatory, and
        // this is the line that was missing. Its maintenance timer is a NIO
        // `RepeatedTask`, which reschedules itself through the loop's own queue:
        // dropping every reference to the gateway does not stop it, only
        // `cancel()` does. Without this, every gateway ever started leaves a
        // timer firing forever, holding the `Reassembler` and the `ARPCache` it
        // sweeps alive with it -- and once the caller shuts its group down, that
        // reschedule lands on a dead loop, which is what NIO was warning about.
        closing.append(stack.shutdown())
        let loop = eventLoop
        // Every host socket this gateway opened, awaited -- not just the wire.
        // The services each own real sockets on this loop and closing one is
        // asynchronous, so a `close()` that waited only on the wire reported
        // "done" with several closes still in flight. A caller that shuts its
        // group down on that report leaves them scheduling onto a dead loop.
        return EventLoopFuture.andAllSucceed(closing, on: loop)
            .flatMap { loop.submit {} }.flatMap { loop.submit {} }
    }
}
