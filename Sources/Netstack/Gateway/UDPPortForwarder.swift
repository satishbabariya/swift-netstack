import NIOCore
import NIOPosix

/// A UDP port on the host, carried into the guest.
///
/// The datagram mirror of `PortForwarder`, and upstream's `udp` forwarding
/// protocol. Something on the host sends to a port here and the datagram arrives
/// at the guest; whatever the guest sends back goes to whoever sent it.
///
/// ## Why this needs flows at all
///
/// UDP has no connections, so there is nothing to accept and nothing that ends.
/// But a reply has to reach the right sender, and the only thing distinguishing
/// senders is the address a datagram came from -- so this keeps one guest-side
/// endpoint per host source address, and that mapping is what makes a reply
/// deliverable. It is a connection in everything but name, which is why it needs
/// the same two things a connection does: a bound on how many may exist, and a
/// way for one to end.
///
/// ## What bounds an attacker
///
/// - **`maximumFlows` bounds the table**, and with it the stack endpoints. The
///   peer is whatever can reach the listening socket, and a sender that varies
///   its source port makes a new flow per datagram -- so without this, one host
///   process can make this one grow without limit.
/// - **Idle flows are reclaimed.** Nothing ends a UDP flow, so without a timeout
///   the table only ever grows and the bound above turns into a permanent
///   refusal rather than a temporary one.
public final class UDPPortForwarder: @unchecked Sendable {
    private final class Flow {
        let endpoint: UDPEndpoint
        var lastUsed: NIODeadline

        init(endpoint: UDPEndpoint, lastUsed: NIODeadline) {
            self.endpoint = endpoint
            self.lastUsed = lastUsed
        }
    }

    private let stack: Stack
    private let eventLoop: EventLoop
    private let guestAddress: IPv4Address
    private let guestPort: UInt16
    private let maximumFlows: Int
    private let idleTimeout: TimeAmount
    private var listener: Channel?
    private var flows: [SocketAddress: Flow] = [:]

    /// The stack port each flow binds next. Ephemeral, and stepped rather than
    /// random because nothing here needs to be unguessable: the guest already
    /// sees every datagram this sends.
    private var nextSourcePort: UInt16 = 40000

    public var flowCount: Int { flows.count }
    public private(set) var refusedForLimit = 0
    public private(set) var reclaimed = 0

    public var log: RateLimitedLogger?

    public var listeningAddress: SocketAddress? { listener?.localAddress }

    public init(
        stack: Stack, guestAddress: IPv4Address, guestPort: UInt16, maximumFlows: Int = 256,
        idleTimeout: TimeAmount = .seconds(60)
    ) {
        self.stack = stack
        self.eventLoop = stack.eventLoop
        self.guestAddress = guestAddress
        self.guestPort = guestPort
        self.maximumFlows = max(1, maximumFlows)
        self.idleTimeout = idleTimeout
    }

    /// Bind the host port. Loopback by default, for the reason
    /// `PortForwarder` gives.
    public func listen(host: String = "127.0.0.1", port: Int) -> EventLoopFuture<Void> {
        DatagramBootstrap(group: eventLoop)
            .channelOption(.socketOption(.so_reuseaddr), value: 1)
            .channelInitializer { [weak self] channel in
                guard let self else { return channel.eventLoop.makeSucceededVoidFuture() }
                return channel.pipeline.addHandler(HostDatagramHandler(forwarder: self))
            }
            .bind(host: host, port: port)
            .map { [weak self] channel in
                self?.listener = channel
            }
    }

    /// A datagram from the host, on the forwarder's own loop.
    fileprivate func receive(_ payload: ByteBuffer, from source: SocketAddress) {
        eventLoop.preconditionInEventLoop()
        if let flow = flows[source] {
            flow.lastUsed = stack.clock.now()
            try? flow.endpoint.send(payload, to: guestAddress, port: guestPort)
            return
        }
        reclaimIdle()
        guard flows.count < maximumFlows else {
            refusedForLimit += 1
            log?.record(.udpRefusedByLimit, ["limit": .stringConvertible(maximumFlows)])
            return
        }

        let endpoint = UDPEndpoint(stack: stack)
        // A port of this stack's choosing, stepped until one binds. The guest
        // replies to it, and the reply is matched back to `source` by which
        // endpoint received it -- which is why each host sender needs one of its
        // own rather than all of them sharing.
        var bound = false
        for _ in 0..<1024 where !bound {
            let port = nextSourcePort
            nextSourcePort = nextSourcePort == UInt16.max ? 40000 : nextSourcePort + 1
            if (try? endpoint.bind(address: stack.configuration.gatewayAddress, port: port)) != nil {
                bound = true
            }
        }
        guard bound else { return }

        endpoint.onDatagram = { [weak self] reply, _, _ in
            guard let self, let listener = self.listener else { return }
            // Straight back to whoever sent, through the same socket they sent
            // to -- a reply from a different port is one their kernel will not
            // match to anything they have open.
            listener.writeAndFlush(AddressedEnvelope(remoteAddress: source, data: reply), promise: nil)
        }
        flows[source] = Flow(endpoint: endpoint, lastUsed: stack.clock.now())
        try? endpoint.send(payload, to: guestAddress, port: guestPort)
    }

    /// Close flows nothing has used for `idleTimeout`.
    private func reclaimIdle() {
        let now = stack.clock.now()
        for (source, flow) in flows where now - flow.lastUsed >= idleTimeout {
            flow.endpoint.close()
            flows.removeValue(forKey: source)
            reclaimed += 1
        }
    }

    @discardableResult
    public func close() -> EventLoopFuture<Void> {
        for flow in flows.values { flow.endpoint.close() }
        flows.removeAll()
        guard let listener else { return eventLoop.makeSucceededVoidFuture() }
        self.listener = nil
        return listener.close().recover { _ in () }
    }
}

/// Hands host datagrams to the forwarder, weakly: the forwarder owns the channel
/// and the channel's pipeline owns this.
private final class HostDatagramHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = AddressedEnvelope<ByteBuffer>

    private weak var forwarder: UDPPortForwarder?

    init(forwarder: UDPPortForwarder) {
        self.forwarder = forwarder
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let envelope = unwrapInboundIn(data)
        forwarder?.receive(envelope.data, from: envelope.remoteAddress)
    }
}
