import NIOCore

/// A datagram endpoint. Bound, optionally connected.
///
/// Loop-confined like everything else: every method must be called on
/// `stack.eventLoop`, and `onDatagram` fires there.
public final class UDPEndpoint: TransportEndpointDelegate {
    private let stack: Stack
    private var boundID: TransportEndpointID?
    private var connectedPeer: (address: IPv4Address, port: UInt16)?

    /// Payload, peer address, peer port.
    public var onDatagram: ((ByteBuffer, IPv4Address, UInt16) -> Void)?

    public init(stack: Stack) {
        self.stack = stack
    }

    deinit {
        // The demuxer holds delegates weakly, so a dropped endpoint stops
        // receiving on its own; this only reclaims the table slot.
        if let boundID {
            stack.transportDemuxer.unregister(boundID, protocolNumber: .udp)
        }
    }

    /// Bind to a local address and port. Port 0 allocates an ephemeral one.
    public func bind(address: IPv4Address, port: UInt16) throws {
        guard boundID == nil else { throw StackError.invalidEndpointState }
        let localPort =
            port == 0
            ? try stack.transportDemuxer.allocateEphemeralPort(protocolNumber: .udp, localAddress: address)
            : port
        let id = TransportEndpointID(localAddress: address, localPort: localPort, remoteAddress: .any, remotePort: 0)
        try stack.transportDemuxer.register(id, protocolNumber: .udp, delegate: self)
        boundID = id
    }

    /// Fix the peer, so `send` needs no destination and datagrams from
    /// anyone else are ignored.
    public func connect(to address: IPv4Address, port: UInt16) throws {
        guard boundID != nil else { throw StackError.invalidEndpointState }
        connectedPeer = (address, port)
    }

    public func send(_ payload: ByteBuffer, to address: IPv4Address? = nil, port: UInt16? = nil) throws {
        guard let boundID else { throw StackError.notConnected }
        guard let destination = address ?? connectedPeer?.address,
            let destinationPort = port ?? connectedPeer?.port
        else { throw StackError.notConnected }

        // A wildcard bind (`localAddress == .any`, i.e. 0.0.0.0) has no real
        // address of its own to prefer: passing it straight through to
        // `ipv4.send` would either put 0.0.0.0 in the IP source field of the
        // emitted packet (`allowsAnySource == true`, since `RouteTable.lookup`
        // honours ANY preferred source when spoofing is allowed, `.any`
        // included), or fail the send outright (`allowsAnySource == false`,
        // since `lookup` cannot honour an address the NIC does not own and
        // falls back to `primaryAddress` while reporting that fallback as
        // NOT honoured, which `send` treats as `.noRoute`). `nil` means "no
        // preference", which is what a wildcard bind actually is: it lets
        // `lookup` pick the NIC's own address in both configurations, the
        // same way a real socket would.
        let preferredSource = boundID.localAddress == .any ? nil : boundID.localAddress

        // The UDP checksum's pseudo-header must be computed against the SAME
        // source address that ends up in the IP header, or the receiver's
        // checksum verification fails. For a non-wildcard bind that is just
        // `boundID.localAddress` — guaranteed to be what `ipv4.send`'s own
        // routing decides, since a preferred source is only ever not
        // honoured when it is `nil` to begin with (see `RouteTable.lookup`).
        // For a wildcard bind there is no such guarantee: the real source
        // is whatever the route table resolves to, which is not known until
        // routing runs. Resolve it here, before serializing, rather than
        // downstream where the payload is already checksummed — otherwise
        // a wildcard-bound send would carry a checksum computed against
        // 0.0.0.0 while the wire packet carries the NIC's real address, and
        // every such datagram would fail checksum verification on arrival.
        let checksumSource: IPv4Address
        if let preferredSource {
            checksumSource = preferredSource
        } else {
            guard let route = stack.routes.lookup(destination: destination, preferredSource: nil) else {
                throw StackError.noRoute
            }
            checksumSource = route.source
        }

        guard
            let datagram = UDPHeader.serialize(
                payload: payload,
                source: checksumSource, destination: destination,
                sourcePort: boundID.localPort, destinationPort: destinationPort,
                allocator: ByteBufferAllocator())
        else { throw StackError.messageTooLong }
        try stack.ipv4.send(payload: datagram, to: destination, from: preferredSource, protocolNumber: .udp)
    }

    public func close() {
        if let boundID {
            stack.transportDemuxer.unregister(boundID, protocolNumber: .udp)
        }
        boundID = nil
        onDatagram = nil
    }

    // MARK: TransportEndpointDelegate

    /// The stack's UDP handler has already consumed and validated the UDP
    /// header, so `payload` is the datagram body and the ports arrive
    /// alongside it.
    public func deliver(header: IPv4Header, payload: ByteBuffer, localPort: UInt16, remotePort: UInt16) {
        // A connected endpoint ignores anyone but its peer.
        if let peer = connectedPeer, peer.address != header.source || peer.port != remotePort { return }
        onDatagram?(payload, header.source, remotePort)
    }
}
