/// What an embedder decides about traffic leaving the gateway.
///
/// See `docs/adr/0001-egress-decision-hook.md` for where each decision sits and
/// what the guest sees when it is refused. This is the first slice of it:
/// `dial`, for TCP, UDP and ICMP echo. The DNS and TLS decisions come later,
/// and each will be a new requirement with no default, so a conformer's build
/// breaks and it has to write down a verdict. That is on purpose. A default of
/// `.allow` is how sandbox came to report "reaches nothing" while `ping
/// 1.1.1.1` was answered: nobody had written the ICMP gate.
///
/// ## A hook must not block
///
/// Every call runs on the stack's event loop, inline, and that loop carries
/// every frame for every guest on this gateway. A `dial` that writes an audit
/// record to a file stalls the whole network for the `write(2)`. Hand records
/// off the loop, to a queue of your own, and bound it.
///
/// A policy shared by gateways on different loops is called from several
/// threads at once, so its `Sendable` has to be real.
public protocol EgressPolicy: Sendable {
    /// A new TCP connection, a new UDP flow, or an ICMP echo request.
    ///
    /// Called once per new flow, never per packet: a segment on an established
    /// connection or a datagram on an open flow goes out without a call. A
    /// refused UDP destination is remembered nowhere, so each datagram to it
    /// asks again.
    func dial(_ flow: EgressFlow) -> EgressVerdict
}

public enum EgressVerdict: Sendable, Hashable {
    case allow
    case refuse
}

/// One flow the guest is trying to open.
public struct EgressFlow: Sendable, Hashable {
    public enum Transport: Sendable, Hashable {
        case tcp
        case udp
        case icmpEcho
    }

    public let transport: Transport
    public let source: IPv4Address
    /// `nil` for ICMP.
    public let sourcePort: UInt16?
    /// The destination as the guest dialled it. A policy about
    /// `host.containers.internal` needs this one.
    public let destination: IPv4Address
    /// The destination after `nat`: the address the gateway is about to dial.
    /// This is what sandbox's Go patch checks, so parity needs it.
    public let translatedDestination: IPv4Address
    /// `nil` for ICMP. sandbox's Go patch passes port 0 there so that a rule
    /// with a port does not grant ping; how `nil` is read is the policy's call.
    public let port: UInt16?

    public init(
        transport: Transport, source: IPv4Address, sourcePort: UInt16?, destination: IPv4Address,
        translatedDestination: IPv4Address, port: UInt16?
    ) {
        self.transport = transport
        self.source = source
        self.sourcePort = sourcePort
        self.destination = destination
        self.translatedDestination = translatedDestination
        self.port = port
    }
}
