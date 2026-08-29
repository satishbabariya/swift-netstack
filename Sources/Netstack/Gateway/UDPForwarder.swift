import NIOCore
import NIOPosix

/// Every UDP datagram the guest sends past the gateway, carried out on a real
/// socket and answered back.
///
/// ## Why this is a NAT table and not an endpoint
///
/// UDP has no connection to accept, so there is nothing to hold a socket the way
/// a TCP endpoint holds one. What identifies a flow is the four-tuple, and what
/// a flow needs is one host socket, reused for as long as the guest keeps using
/// it, so that replies come back to the port the guest is listening on. That is
/// a NAT table, and saying so is more honest than calling it a session.
///
/// ## What it does not take
///
/// Datagrams addressed to the gateway itself fall through untouched, which is
/// what leaves DHCP and DNS working: they are UDP endpoints bound on this stack,
/// and a forwarder that swallowed everything would take the guest's DHCP
/// DISCOVER and try to send it to the internet. The rule is the gateway's own
/// address, not a list of ports -- a port list would have to be kept in step
/// with every service ever added, and would be wrong the first time it was not.
///
/// ## What bounds a hostile guest
///
/// - **`maximumFlows` bounds the table**, and with it the host sockets. A guest
///   can vary its source port freely, so without a bound a loop over 65,536
///   ports opens 65,536 file descriptors -- and a process out of descriptors
///   takes everything in it down, not just the gateway.
/// - **Idle flows are reclaimed.** UDP has no close, so a flow that is merely
///   finished looks exactly like one that is quiet. Without expiry the table
///   only grows, and the bound above turns from a safety limit into a permanent
///   ceiling the gateway reaches once and never comes back from.
public final class UDPForwarder: @unchecked Sendable {
    fileprivate struct FlowKey: Hashable {
        let source: IPv4Address
        let sourcePort: UInt16
        let destination: IPv4Address
        let destinationPort: UInt16
    }

    private final class Flow {
        let channel: Channel
        var lastUsed: NIODeadline

        init(channel: Channel, lastUsed: NIODeadline) {
            self.channel = channel
            self.lastUsed = lastUsed
        }
    }

    private let stack: Stack
    private let gateway: IPv4Address
    private let maximumFlows: Int
    private let idleTimeout: TimeAmount
    private var flows: [FlowKey: Flow] = [:]
    /// Flows whose socket is still being opened. A guest sending a burst to one
    /// destination must not open one socket per datagram while the first is
    /// still connecting.
    private var opening: Set<FlowKey> = []

    public private(set) var refusedForLimit = 0
    public private(set) var reclaimed = 0

    /// Host sockets opened over this forwarder's life, which is not the same as
    /// `flowCount` and is the figure that shows a flow being reused.
    ///
    /// `flowCount` is a dictionary's size, so it cannot exceed one per
    /// four-tuple however many sockets were opened for it -- a forwarder that
    /// opened one per datagram and overwrote the entry each time would report a
    /// count of one and leak every socket but the last. The test for reuse was
    /// written against `flowCount` first and passed against exactly that
    /// mutation.
    public private(set) var openedSockets = 0

    /// Where refusals are reported, if anywhere. `Gateway` sets this; a
    /// hand-assembled arrangement opts in by setting it too.
    public var log: RateLimitedLogger?


    public var flowCount: Int { flows.count }

    public init(
        stack: Stack, maximumFlows: Int = 512, idleTimeout: TimeAmount = .seconds(60)
    ) {
        self.stack = stack
        self.gateway = stack.configuration.gatewayAddress
        self.maximumFlows = max(1, maximumFlows)
        self.idleTimeout = idleTimeout
        stack.transportDemuxer.setProtocolHandler(.udp, ownedBy: self) {
            [weak self] header, payload, localPort, remotePort in
            self?.handle(
                header: header, payload: payload, localPort: localPort, remotePort: remotePort) ?? false
        }
    }

    deinit {
        // Ownership-checked; see `TCPForwarder.deinit` for the defect the
        // unconditional form was.
        stack.transportDemuxer.clearProtocolHandler(.udp, ownedBy: self)
    }

    /// Returns true when the datagram was consumed.
    private func handle(
        header: IPv4Header, payload: ByteBuffer, localPort: UInt16, remotePort: UInt16
    ) -> Bool {
        // Anything for the gateway is the gateway's own business -- DHCP, DNS,
        // and whatever is bound next. Falling through is what leaves them
        // working.
        guard header.destination != gateway, header.destination != .broadcast else { return false }

        // The ports come from the demuxer, not from a header parsed here. By
        // the time a UDP datagram reaches a protocol handler the network layer
        // has already consumed its header -- `payload` is the datagram's body.
        // The first version of this parsed a UDP header that was not there,
        // fell through on every datagram, and left the forwarder silently doing
        // nothing at all.
        let key = FlowKey(
            source: header.source, sourcePort: remotePort,
            destination: header.destination, destinationPort: localPort)
        let datagram = payload

        if let flow = flows[key] {
            flow.lastUsed = stack.clock.now()
            send(datagram, on: flow)
            return true
        }

        // Consumed either way from here: the guest addressed something past this
        // gateway, and no endpoint on this stack is going to answer it.
        guard !opening.contains(key) else { return true }
        reclaimIdle()
        guard flows.count + opening.count < maximumFlows else {
            refusedForLimit += 1
            log?.record(.udpRefusedByLimit, ["limit": .stringConvertible(maximumFlows)])
            return true
        }
        open(key, firstDatagram: datagram)
        return true
    }

    private func open(_ key: FlowKey, firstDatagram: ByteBuffer) {
        guard let remote = try? SocketAddress(
            ipAddress: key.destination.description, port: Int(key.destinationPort))
        else { return }
        opening.insert(key)

        // On the stack's own loop, for the reason every other channel in this
        // package is: the reply path writes into the stack, and a reply arriving
        // on another thread would need a lock the datapath does not have.
        DatagramBootstrap(group: stack.eventLoop)
            .channelInitializer { [weak self] channel in
                guard let self else { return channel.eventLoop.makeSucceededVoidFuture() }
                return channel.pipeline.addHandler(UDPReplyHandler(forwarder: self, key: key))
            }
            .connect(to: remote)
            .whenComplete { [weak self] outcome in
                guard let self else { return }
                self.opening.remove(key)
                guard case .success(let channel) = outcome else { return }
                let flow = Flow(channel: channel, lastUsed: self.stack.clock.now())
                // Closed before being replaced. Overwriting the entry alone
                // would leave the previous socket open with nothing referring to
                // it -- a descriptor leaked per datagram, which is the bound
                // above defeated by the path that is supposed to respect it.
                self.flows[key]?.channel.close(promise: nil)
                self.openedSockets += 1
                self.flows[key] = flow
                self.send(firstDatagram, on: flow)
            }
    }

    private func send(_ datagram: ByteBuffer, on flow: Flow) {
        flow.channel.writeAndFlush(datagram, promise: nil)
    }

    /// Called by `UDPReplyHandler` when the host socket answers.
    fileprivate func deliverReply(_ datagram: ByteBuffer, for key: FlowKey) {
        guard let flow = flows[key] else { return }
        flow.lastUsed = stack.clock.now()
        // Sent from the address the guest addressed, not from the gateway's.
        //
        // The guest's socket is connected to that address; a reply from anywhere
        // else is one the kernel in the guest discards, and the application sees
        // a request that was never answered.
        let allocator = ByteBufferAllocator()
        guard let response = UDPHeader.serialize(
            payload: datagram, source: key.destination, destination: key.source,
            sourcePort: key.destinationPort, destinationPort: key.sourcePort, allocator: allocator)
        else { return }
        try? stack.ipv4.send(
            payload: response, to: key.source, from: key.destination, protocolNumber: .udp)
    }

    private func reclaimIdle() {
        let now = stack.clock.now()
        for (key, flow) in flows where flow.lastUsed + idleTimeout <= now {
            flow.channel.close(promise: nil)
            flows.removeValue(forKey: key)
            reclaimed += 1
        }
    }

    /// Close, and complete when every flow's host socket is closed.
    ///
    /// One future per flow rather than fire-and-forget: each of these is a host
    /// socket, and a caller shutting its group down when this completes has to
    /// be able to trust that "completes" means the sockets are gone. See
    /// `DNSServer.close`.
    @discardableResult
    public func close() -> EventLoopFuture<Void> {
        stack.transportDemuxer.clearProtocolHandler(.udp, ownedBy: self)
        let closing = flows.values.map { $0.channel.close().recover { _ in () } }
        flows.removeAll()
        return EventLoopFuture.andAllSucceed(closing, on: stack.eventLoop)
    }
}

private final class UDPReplyHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = AddressedEnvelope<ByteBuffer>

    private weak var forwarder: UDPForwarder?
    private let key: UDPForwarder.FlowKey

    init(forwarder: UDPForwarder, key: UDPForwarder.FlowKey) {
        self.forwarder = forwarder
        self.key = key
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        forwarder?.deliverReply(unwrapInboundIn(data).data, for: key)
    }
}
