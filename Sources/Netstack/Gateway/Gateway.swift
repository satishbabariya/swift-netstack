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
        public var mtu: UInt32
        /// Names this gateway answers itself. The zone of each is also owned:
        /// with `gateway.containers.internal` here, any other name under
        /// `containers.internal` is answered NXDOMAIN rather than forwarded.
        public var dnsRecords: [DNSServer.StaticRecord]
        /// Where to send names this gateway does not own. Empty means it will
        /// not forward at all, and says so with REFUSED rather than a timeout.
        public var upstreamResolvers: [SocketAddress]
        public var leaseSeconds: UInt32
        /// Every bound a guest can push against, in one place because they are
        /// one decision: how much of this process a guest may occupy.
        public var maximumTCPConnections: Int
        public var maximumUDPFlows: Int
        public var maximumHalfOpenConnections: Int
        /// Applied to every forwarded connection's guest-side endpoint. On by
        /// default -- see `OutboundTCPForwarder.init` for why that is the
        /// opposite of `TCPEndpoint`'s default and right here.
        public var keepAlive: TCPEndpoint.KeepAliveConfiguration?

        public init(
            gatewayAddress: IPv4Address = IPv4Address("192.168.127.1")!,
            subnet: IPv4Subnet = IPv4Subnet(cidr: "192.168.127.0/24")!,
            linkAddress: MACAddress = MACAddress("5a:94:ef:e4:0c:ee")!,
            mtu: UInt32 = 1500,
            dnsRecords: [DNSServer.StaticRecord]? = nil,
            upstreamResolvers: [SocketAddress] = [],
            leaseSeconds: UInt32 = 3600,
            maximumTCPConnections: Int = 1024,
            maximumUDPFlows: Int = 512,
            maximumHalfOpenConnections: Int = 512,
            keepAlive: TCPEndpoint.KeepAliveConfiguration? = TCPEndpoint.KeepAliveConfiguration()
        ) {
            self.gatewayAddress = gatewayAddress
            self.subnet = subnet
            self.linkAddress = linkAddress
            self.mtu = mtu
            // The two names upstream publishes, so a guest written against
            // gvisor-tap-vsock finds what it expects. Both resolve to the
            // gateway: the host is reachable through it and only through it.
            self.dnsRecords = dnsRecords ?? [
                .init(name: "gateway.containers.internal", address: gatewayAddress),
                .init(name: "host.containers.internal", address: gatewayAddress),
            ]
            self.upstreamResolvers = upstreamResolvers
            self.leaseSeconds = leaseSeconds
            self.maximumTCPConnections = maximumTCPConnections
            self.maximumUDPFlows = maximumUDPFlows
            self.maximumHalfOpenConnections = maximumHalfOpenConnections
            self.keepAlive = keepAlive
        }
    }

    public let link: WireLinkEndpoint
    public let stack: Stack
    public let dhcp: DHCPServer
    public let dns: DNSServer
    public let tcp: OutboundTCPForwarder
    public let udp: UDPForwarder

    /// Live forwards, keyed by the host port they publish on. A dictionary
    /// rather than an array because the control plane addresses them by that
    /// port -- and because two forwards on one port is a state the type should
    /// not be able to represent.
    private var forwards: [Int: PortForwarder] = [:]
    private let keepAlive: TCPEndpoint.KeepAliveConfiguration?

    public var eventLoop: EventLoop { link.eventLoop }

    private init(
        link: WireLinkEndpoint, stack: Stack, dhcp: DHCPServer, dns: DNSServer,
        tcp: OutboundTCPForwarder, udp: UDPForwarder,
        keepAlive: TCPEndpoint.KeepAliveConfiguration?
    ) {
        self.keepAlive = keepAlive
        self.link = link
        self.stack = stack
        self.dhcp = dhcp
        self.dns = dns
        self.tcp = tcp
        self.udp = udp
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

    /// Build everything on the link's own loop.
    ///
    /// The order is not arbitrary and this is the one place it is written down:
    /// the DHCP and DNS servers bind their UDP ports **before** the UDP
    /// forwarder installs its protocol handler, so that when the handler falls
    /// through -- which it does for anything addressed to the gateway -- there
    /// is something bound for the datagram to reach.
    private static func assemble(
        on link: WireLinkEndpoint, group: EventLoopGroup, configuration: Configuration
    ) -> EventLoopFuture<Gateway> {
        link.eventLoop.submit {
            let stack = Stack(
                link: link,
                configuration: Stack.Configuration(
                    gatewayAddress: configuration.gatewayAddress, subnet: configuration.subnet))
            stack.start()

            let dhcp = try DHCPServer(
                stack: stack, leaseSeconds: configuration.leaseSeconds,
                mtu: UInt16(truncatingIfNeeded: configuration.mtu))
            let dns = try DNSServer(
                stack: stack, records: configuration.dnsRecords,
                upstream: configuration.upstreamResolvers)
            let tcp = OutboundTCPForwarder(
                stack: stack, maximumInFlight: configuration.maximumHalfOpenConnections,
                maximumConnections: configuration.maximumTCPConnections,
                keepAlive: configuration.keepAlive)
            let udp = UDPForwarder(stack: stack, maximumFlows: configuration.maximumUDPFlows)
            return Gateway(
                link: link, stack: stack, dhcp: dhcp, dns: dns, tcp: tcp, udp: udp,
                keepAlive: configuration.keepAlive)
        }.flatMap { (gateway: Gateway) -> EventLoopFuture<Gateway> in
            gateway.dns.startForwarding(group: group).map { _ in gateway }
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
        return forwarder.listen(host: host, port: hostPort).map { [weak self] _ -> PortForwarder in
            // Keyed on the port the LISTENER ended up with, not on the one that
            // was asked for: a caller may ask for zero and mean "anything free",
            // and a forward filed under zero is one nothing can ever address.
            let bound = forwarder.listeningAddress?.port ?? hostPort
            self?.forwards[bound] = forwarder
            return forwarder
        }
    }

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

    public func close() -> EventLoopFuture<Void> {
        for forwarder in forwards.values { forwarder.close() }
        forwards.removeAll()
        udp.close()
        dns.close()
        dhcp.close()
        return link.close()
    }
}
