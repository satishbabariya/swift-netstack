import NIOCore

/// Routes an inbound transport segment to the endpoint that owns its flow.
public final class TransportDemuxer {
    private struct Key: Hashable {
        let protocolNumber: UInt8
        let id: TransportEndpointID
    }

    /// Delegates are held weakly: an endpoint that goes away must not be kept
    /// alive by the table it registered in, and a stale entry must not deliver.
    private struct Registration {
        weak var delegate: (any TransportEndpointDelegate)?
    }

    private var registrations: [Key: Registration] = [:]
    private var protocolHandlers: [UInt8: (IPv4Header, ByteBuffer) -> Bool] = [:]
    private var nextEphemeral: UInt16 = 49152

    public init() {}

    public func register(_ id: TransportEndpointID, protocolNumber: IPProtocol, delegate: TransportEndpointDelegate) throws {
        let key = Key(protocolNumber: protocolNumber.rawValue, id: id)
        if let existing = registrations[key], existing.delegate != nil {
            throw StackError.portInUse
        }
        registrations[key] = Registration(delegate: delegate)
    }

    public func unregister(_ id: TransportEndpointID, protocolNumber: IPProtocol) {
        registrations.removeValue(forKey: Key(protocolNumber: protocolNumber.rawValue, id: id))
    }

    /// Install a handler that sees every segment for a protocol before any
    /// endpoint does. gVisor calls this `SetTransportProtocolHandler`; it is
    /// how the TCP and UDP forwarders take over the datapath.
    ///
    /// Return `true` to consume the segment, `false` to let normal endpoint
    /// matching proceed. Pass nil to remove.
    public func setProtocolHandler(_ protocolNumber: IPProtocol, _ handler: ((IPv4Header, ByteBuffer) -> Bool)?) {
        protocolHandlers[protocolNumber.rawValue] = handler
    }

    /// Returns false when nothing wanted the segment, so the caller can answer
    /// with an ICMP port-unreachable.
    public func deliver(
        protocolNumber: IPProtocol, header: IPv4Header, payload: ByteBuffer, localPort: UInt16, remotePort: UInt16
    ) -> Bool {
        if let handler = protocolHandlers[protocolNumber.rawValue], handler(header, payload) {
            return true
        }

        // Most specific first. A connected endpoint beats a listener bound to
        // the same port, and a listener on a specific address beats one on
        // any address.
        let candidates = [
            TransportEndpointID(localAddress: header.destination, localPort: localPort, remoteAddress: header.source, remotePort: remotePort),
            TransportEndpointID(localAddress: header.destination, localPort: localPort, remoteAddress: .any, remotePort: 0),
            TransportEndpointID(localAddress: .any, localPort: localPort, remoteAddress: .any, remotePort: 0),
        ]

        for candidate in candidates {
            let key = Key(protocolNumber: protocolNumber.rawValue, id: candidate)
            guard let registration = registrations[key] else { continue }
            guard let delegate = registration.delegate else {
                registrations.removeValue(forKey: key)
                continue
            }
            delegate.deliver(header: header, payload: payload, localPort: localPort, remotePort: remotePort)
            return true
        }
        return false
    }

    /// An unused port in the ephemeral range, for an endpoint that did not
    /// choose one. Scans the whole range before giving up.
    public func allocateEphemeralPort(protocolNumber: IPProtocol, localAddress: IPv4Address) throws -> UInt16 {
        let low: UInt16 = 49152
        let high: UInt16 = 65535
        for _ in 0...(high - low) {
            let candidate = nextEphemeral
            nextEphemeral = candidate == high ? low : candidate + 1

            let inUse = registrations.contains { key, registration in
                key.protocolNumber == protocolNumber.rawValue
                    && key.id.localPort == candidate
                    && registration.delegate != nil
            }
            if !inUse { return candidate }
        }
        throw StackError.noPortsAvailable
    }
}
