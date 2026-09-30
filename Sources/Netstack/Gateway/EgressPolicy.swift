/// What an embedder decides about traffic leaving the gateway.
///
/// See `docs/adr/0001-egress-decision-hook.md` for where each decision sits and
/// what the guest sees when it is refused. `dial` covers TCP, UDP and ICMP
/// echo; `resolve` and `resolved` cover DNS; `clientHello` covers the server
/// name a TLS connection asks for. None of them has a default, so a conformer
/// has to write down a verdict for each. That is on purpose. A default of
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
    /// A DNS question the gateway would forward upstream, of any type.
    ///
    /// The gateway's own names (its static records and the zones it owns) are
    /// answered before this and never asked about: they are not egress. A
    /// refusal is `REFUSED` (rcode 5) to the guest, and nothing is sent
    /// upstream. Not NXDOMAIN, which a resolver would cache as the name not
    /// existing.
    func resolve(_ question: EgressQuestion) -> EgressVerdict

    /// An upstream reply to a question `resolve` allowed, before the guest
    /// sees it. A refusal replaces the reply with `REFUSED`.
    ///
    /// Every matched reply is passed, including ones with no addresses in
    /// them. A reply whose answer section cannot be read is refused without a
    /// call: a policy that keeps a record of what it handed out cannot record
    /// what it was never shown.
    func resolved(_ answer: EgressAnswer) -> EgressVerdict

    /// A new TCP connection, a new UDP flow, or an ICMP echo request.
    ///
    /// Called once per new flow, never per packet: a segment on an established
    /// connection or a datagram on an open flow goes out without a call. A
    /// refused UDP destination is remembered nowhere, so each datagram to it
    /// asks again.
    func dial(_ flow: EgressFlow) -> EgressVerdict

    /// The destination ports whose connections are read for a ClientHello
    /// before anything is sent upstream. Read once, when the gateway is
    /// assembled. A connection to any other port is spliced unread.
    var inspectedTLSPorts: Set<UInt16> { get }

    /// The server name a TLS connection on an inspected port asks for, after
    /// `dial` allowed it and the upstream has been dialled. A refusal resets
    /// the guest's connection, and the upstream is closed with none of the
    /// guest's bytes sent to it. The upstream has still seen a TCP handshake:
    /// the name arrives after the only point where the dial could have been
    /// refused.
    ///
    /// Asked only when there is a name. A stream that is not TLS, and a
    /// complete ClientHello with no `server_name`, are passed on without a
    /// call, because `dial` already allowed the address and there is no name
    /// to judge. A hello that cannot be read is refused without a call: it
    /// has not said which name it wants, and the server may still read one
    /// from it. That covers a hello that is malformed, over 16 KiB (or 32 KiB
    /// of records), cut short by the guest, or not complete within
    /// `clientHelloTimeout`.
    func clientHello(_ hello: EgressClientHello) -> EgressTLSVerdict
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

/// One question the guest asked, before it leaves the gateway.
public struct EgressQuestion: Sendable, Hashable {
    public enum Transport: Sendable, Hashable {
        case udp
        case tcp
    }

    public let source: IPv4Address
    /// Lowercased, with no trailing dot.
    public let name: String
    public let type: UInt16
    public let klass: UInt16
    public let transport: Transport

    public init(source: IPv4Address, name: String, type: UInt16, klass: UInt16, transport: Transport) {
        self.source = source
        self.name = name
        self.type = type
        self.klass = klass
        self.transport = transport
    }
}

/// What upstream answered, as far as a policy about addresses needs it.
public struct EgressAnswer: Sendable, Hashable {
    public struct Address: Sendable, Hashable {
        public let address: IPv4Address
        public let ttl: UInt32

        public init(address: IPv4Address, ttl: UInt32) {
            self.address = address
            self.ttl = ttl
        }
    }

    public let question: EgressQuestion
    /// The class IN A records owned by the question name or a name in
    /// `canonicalNames`. A record for any other name is not reachable from the
    /// question and is left out: an upstream can put anything in a reply.
    public let addresses: [Address]
    /// The CNAME targets followed from the question name, in order, lowercased.
    public let canonicalNames: [String]

    public init(question: EgressQuestion, addresses: [Address], canonicalNames: [String]) {
        self.question = question
        self.addresses = addresses
        self.canonicalNames = canonicalNames
    }
}

/// A TLS connection's server name, read from its ClientHello.
public struct EgressClientHello: Sendable, Hashable {
    /// The connection `dial` allowed.
    public let flow: EgressFlow
    /// From the `server_name` extension. Lowercased, with no trailing dot, and
    /// printable ASCII only: a hello whose name is not is refused as
    /// unreadable before this is built. With Encrypted ClientHello this is the
    /// outer name, the client-facing server's, and only that.
    public let serverName: String

    public init(flow: EgressFlow, serverName: String) {
        self.flow = flow
        self.serverName = serverName
    }
}

/// What `clientHello` decides. Separate from `EgressVerdict` because ADR 0001
/// gives TLS a third answer, handing the connection to the embedder, and that
/// case belongs here when it is built.
public enum EgressTLSVerdict: Sendable, Hashable {
    case allow
    case refuse
}
