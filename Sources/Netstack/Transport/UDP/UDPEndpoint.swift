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

        guard
            let datagram = UDPHeader.serialize(
                payload: payload,
                source: boundID.localAddress, destination: destination,
                sourcePort: boundID.localPort, destinationPort: destinationPort,
                allocator: ByteBufferAllocator())
        else { throw StackError.messageTooLong }
        try stack.ipv4.send(payload: datagram, to: destination, from: boundID.localAddress, protocolNumber: .udp)
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
