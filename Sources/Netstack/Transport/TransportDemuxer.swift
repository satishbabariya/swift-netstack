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
    private var protocolHandlers: [UInt8: (IPv4Header, ByteBuffer, UInt16, UInt16) -> Bool] = [:]
    private var nextEphemeral: UInt16 = 49152

    public init() {}

    /// How many table slots are occupied, live delegates and stale ones alike.
    ///
    /// Not `private`, because `@testable import` elevates `internal` and not
    /// `private`, and this is the ONLY observable consequence of an endpoint's
    /// `deinit` unregistering itself. Every other route is foreclosed: the
    /// delegate is held weakly, so `register` overwrites a slot whose delegate
    /// has gone (a rebind therefore succeeds either way),
    /// `allocateEphemeralPort` skips such slots, and `deliver` evicts them
    /// lazily as it finds them. What is left is the slot itself, which nothing
    /// reclaims if the port is never touched again -- one dictionary entry per
    /// dropped endpoint, for the life of the stack.
    ///
    /// Without this, `aDroppedTcpEndpointUnregistersItselfFromTheDemuxer`
    /// passes with the `deinit` deleted, which was measured rather than
    /// assumed.
    var registrationCountForTesting: Int { registrations.count }

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
    ///
    /// ## The `payload` is not the same shape for every protocol
    ///
    /// It is whatever the network layer handed the demuxer, and that differs by
    /// design: a TCP segment arrives whole, header and all, because a TCP
    /// endpoint parses its own; a UDP datagram arrives as its PAYLOAD, because
    /// the network layer has already parsed the header it needed for the ICMP
    /// port-unreachable it may have to send.
    ///
    /// That is why the ports are parameters. A handler that needed them and
    /// could only get them by parsing would work for one protocol and silently
    /// fail for the other -- which is exactly what the first UDP forwarder did,
    /// parsing a header that was not there and falling through on every
    /// datagram.
    public func setProtocolHandler(
        _ protocolNumber: IPProtocol, _ handler: ((IPv4Header, ByteBuffer, UInt16, UInt16) -> Bool)?
    ) {
        protocolHandlers[protocolNumber.rawValue] = handler
    }

    /// Whether something has already taken over a protocol's datapath.
    ///
    /// There is one slot per protocol, so installing a second handler displaces
    /// the first **silently**: the displaced one does not error, it simply stops
    /// being called. A caller that would install one asks this first so the
    /// collision surfaces as a failure rather than as a gateway that quietly
    /// sees no connections.
    public func hasProtocolHandler(_ protocolNumber: IPProtocol) -> Bool {
        protocolHandlers[protocolNumber.rawValue] != nil
    }

    /// Returns false when nothing wanted the segment, so the caller can answer
    /// with an ICMP port-unreachable.
    public func deliver(
        protocolNumber: IPProtocol, header: IPv4Header, payload: ByteBuffer, localPort: UInt16, remotePort: UInt16
    ) -> Bool {
        if let handler = protocolHandlers[protocolNumber.rawValue], handler(header, payload, localPort, remotePort) {
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

            // A registration on `.any` occupies the port on every local
            // address, so it conflicts regardless of `localAddress` here —
            // and allocating for `.any` itself must in turn conflict with
            // any address-specific registration, since that wildcard would
            // occupy the port everywhere too. Otherwise the port is only
            // taken for the exact local address it was registered on,
            // matching what `register()` actually allows.
            let inUse = registrations.contains { key, registration in
                key.protocolNumber == protocolNumber.rawValue
                    && key.id.localPort == candidate
                    && registration.delegate != nil
                    && (key.id.localAddress == localAddress || key.id.localAddress == .any || localAddress == .any)
            }
            if !inUse { return candidate }
        }
        throw StackError.noPortsAvailable
    }
}
