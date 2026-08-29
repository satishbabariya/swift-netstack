import NIOCore

/// A connection a peer is trying to open, handed to the forwarder's handler
/// before this stack has answered it.
///
/// The handler must do exactly one of two things with it. `complete` accepts the
/// connection and returns an endpoint carrying it; `refuse` answers with a reset.
/// Doing neither is also a decision — the SYN goes unanswered and the peer
/// retries or gives up — and it is what happens to a request the handler simply
/// drops on the floor.
/// `@unchecked Sendable` because a request is confined to the stack's event
/// loop -- it is created there, settled there, and never handed anywhere else.
/// The compiler cannot see that; the alternative is a lock on the datapath,
/// which this package does not have anywhere.
public final class ForwarderRequest: @unchecked Sendable {
    /// Where the peer is dialling from and to.
    public let source: IPv4Address
    public let sourcePort: UInt16
    public let destination: IPv4Address
    public let destinationPort: UInt16

    private let onComplete: (ForwarderRequest) throws -> TCPEndpoint
    private let onRefuse: (ForwarderRequest) -> Void
    private var settled = false

    init(
        source: IPv4Address, sourcePort: UInt16, destination: IPv4Address, destinationPort: UInt16,
        onComplete: @escaping (ForwarderRequest) throws -> TCPEndpoint,
        onRefuse: @escaping (ForwarderRequest) -> Void
    ) {
        self.source = source
        self.sourcePort = sourcePort
        self.destination = destination
        self.destinationPort = destinationPort
        self.onComplete = onComplete
        self.onRefuse = onRefuse
    }

    /// Accept the connection. Answers the SYN and returns the endpoint holding it.
    ///
    /// Settling twice is a programming error and is ignored rather than trapped:
    /// a handler that completes and then refuses has a bug, and turning that into
    /// a crash of the whole gateway punishes every other connection for it.
    @discardableResult
    public func complete() throws -> TCPEndpoint? {
        guard !settled else { return nil }
        settled = true
        return try onComplete(self)
    }

    /// Refuse it with a reset, which is what tells a dialler *now* that nothing
    /// is listening rather than making it wait out a connect timeout.
    public func refuse() {
        guard !settled else { return }
        settled = true
        onRefuse(self)
    }

    var isSettled: Bool { settled }
}

/// Takes over TCP for a whole stack and hands each new connection to a handler.
///
/// This is gVisor's `tcp.Forwarder` in shape and in purpose: a gateway does not
/// know in advance which ports a guest will dial, so it cannot bind them. The
/// forwarder sees every SYN, asks the handler what to do, and only then builds
/// an endpoint.
///
/// **`maximumInFlight` is a SYN-flood bound and the reason this class needs one
/// at all.** Every unsettled request holds the memory of a half-open connection,
/// and the guest chooses how many to create. Past the limit a SYN is **dropped,
/// not reset** — a reset would confirm to a scanner that the gateway is there and
/// would spend a frame per probe, which is the amplification the RFC 5961 budget
/// exists to stop one layer down.
public final class TCPForwarder {
    private let stack: Stack
    private let maximumInFlight: Int
    private let handler: (ForwarderRequest) -> Void
    private var inFlight: [TransportEndpointID: ForwarderRequest] = [:]
    private var endpoints: [TransportEndpointID: TCPEndpoint] = [:]

    public init(stack: Stack, maximumInFlight: Int = 512, handler: @escaping (ForwarderRequest) -> Void) {
        self.stack = stack
        self.maximumInFlight = max(1, maximumInFlight)
        self.handler = handler
        install()
    }

    deinit {
        // Ownership-checked, and NOT what makes a dropped forwarder safe.
        //
        // The `[weak self]` capture is what does that: with it, a handler left
        // installed sees `self == nil`, returns false, and the segment falls
        // through to the stack's ordinary handling exactly as if nothing were
        // intercepting. Removing this line changes no observable behaviour, and
        // that was verified rather than assumed — the falsification was run and
        // did not fail, including against a test written specifically to catch
        // it.
        //
        // What it buys is releasing the closure the demuxer still holds -- a
        // small leak per forwarder created rather than a correctness matter.
        //
        // **The `ownedBy` is not decoration, and the earlier version of this
        // line was a defect.** It cleared the slot unconditionally, so replacing
        // a forwarder -- install the new one, release the old one -- had the old
        // one's teardown remove the NEW one's handler. Nothing errored; the
        // datapath simply stopped being intercepted, which presents as a gateway
        // that has silently stopped forwarding. The comment here used to say
        // removing this line changes no observable behaviour, and a test that
        // replaced a forwarder found otherwise.
        stack.transportDemuxer.clearProtocolHandler(.tcp, ownedBy: self)
    }

    private func install() {
        // The ports are handed in and deliberately not used: a TCP segment
        // arrives whole, so this parses the header anyway -- for the flags, the
        // sequence number and the options -- and reading the ports from
        // anywhere but that parse would be two sources for one fact.
        stack.transportDemuxer.setProtocolHandler(.tcp, ownedBy: self) { [weak self] header, payload, _, _ in
            guard let self else { return false }
            return self.handle(header: header, payload: payload)
        }
    }

    /// Returns true when the segment was consumed.
    private func handle(header: IPv4Header, payload: ByteBuffer) -> Bool {
        var parsable = PacketBuffer(received: payload)
        guard let tcp = TCPHeader.parse(&parsable, header: header) else { return false }
        let id = TransportEndpointID(
            localAddress: header.destination, localPort: tcp.destinationPort,
            remoteAddress: header.source, remotePort: tcp.sourcePort)

        // An established connection's segments go to the endpoint holding it,
        // ahead of any new-connection logic: a retransmitted SYN for a connection
        // already accepted must reach the state machine that knows about it, not
        // start a second request for the same four-tuple.
        if let endpoint = endpoints[id] {
            endpoint.deliver(
                header: header, payload: payload, localPort: tcp.destinationPort,
                remotePort: tcp.sourcePort)
            return true
        }

        // Only a bare SYN opens anything. Everything else for an unknown
        // four-tuple is left to the stack's ordinary handling, which answers it
        // with a reset -- the same answer, arrived at by the path that already
        // gets the reset's sequence numbers right.
        let opensAConnection =
            tcp.flags.contains(.syn) && !tcp.flags.contains(.ack) && !tcp.flags.contains(.rst)
        guard opensAConnection else { return false }

        // A repeat SYN for a request still in flight is the peer retransmitting
        // because we have not answered. It must not create a second request.
        if inFlight[id] != nil { return true }

        guard inFlight.count < maximumInFlight else {
            // Dropped in silence. See the type's own comment for why this is not
            // a reset.
            return true
        }

        let request = ForwarderRequest(
            source: header.source, sourcePort: tcp.sourcePort,
            destination: header.destination, destinationPort: tcp.destinationPort,
            onComplete: { [weak self] request in
                guard let self else { throw StackError.invalidEndpointState }
                return try self.accept(request, id: id, header: header, payload: payload)
            },
            onRefuse: { [weak self] _ in
                self?.inFlight.removeValue(forKey: id)
                guard let stack = self?.stack else { return }
                // RFC 9293 §3.10.7.1's answer to a SYN: SEQ=0, ACK=SEG.SEQ+1,
                // RST|ACK. Getting this wrong is a refusal the peer ignores,
                // which reads to the dialler exactly like a hang — the
                // distinction Task 8 of the TCP plan had to be corrected on.
                TCPWire.sendReset(
                    sequence: SequenceNumber(0), ack: tcp.sequence + 1,
                    sourcePort: tcp.destinationPort, destinationPort: tcp.sourcePort,
                    from: header.destination, to: header.source, via: stack.ipv4,
                    allocator: ByteBufferAllocator())
            })
        inFlight[id] = request
        handler(request)
        // A handler that neither completed nor refused leaves the request in
        // flight, holding a slot until something else clears it. That is the
        // behaviour `maximumInFlight` bounds.
        return true
    }

    private func accept(
        _ request: ForwarderRequest, id: TransportEndpointID, header: IPv4Header, payload: ByteBuffer
    ) throws -> TCPEndpoint {
        inFlight.removeValue(forKey: id)
        let endpoint = TCPEndpoint(stack: stack, initialSequenceNumbers: stack.initialSequenceNumbers)
        // Deliberately not `bind` + `listen`: see
        // `listenForForwardedConnection`. Binding would cap this forwarder at
        // one live connection per destination port.
        endpoint.listenForForwardedConnection()
        endpoints[id] = endpoint
        // Replay the SYN into the endpoint now that it exists. The endpoint has
        // not seen it -- the forwarder consumed it to build this request -- and
        // without the replay the handshake never starts and the peer waits out
        // its connect timeout for a connection we agreed to accept.
        endpoint.deliver(
            header: header, payload: payload, localPort: request.destinationPort,
            remotePort: request.sourcePort)
        return endpoint
    }

    /// How many requests are waiting on the handler. For tests and diagnostics.
    var inFlightCountForTesting: Int { inFlight.count }
}
