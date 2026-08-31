import NIOCore

/// The gateway's DHCP server: how a guest learns its address, its route, and
/// where to ask about names.
///
/// ## What it hands out, and why the pool is what it is
///
/// One address per hardware address, allocated from the subnet the stack was
/// configured with, skipping the network address, the broadcast address and the
/// gateway's own. A guest that asks twice gets the same answer -- the lease is
/// keyed by hardware address and outlives the transaction -- so a reboot does
/// not renumber it, which is what makes a forwarded port keep working across
/// one.
///
/// ## Every field in the request is guest-supplied
///
/// - **The pool is bounded and so is the lease table.** A guest can put any
///   hardware address it likes in a DISCOVER, so a table keyed on that address
///   grows at whatever rate the guest can send datagrams. It is bounded by the
///   pool -- the table cannot hold more entries than there are addresses to give
///   -- and once the pool is empty a DISCOVER is answered with nothing rather
///   than with an eviction.
/// - **No eviction is deliberate.** Evicting the oldest lease to serve a new
///   one lets a guest with two hardware addresses take an address away from
///   itself, which presents as a working machine that intermittently loses its
///   network. Refusing is worse for the guest that asked and better for the one
///   that already has an address.
/// - **A REQUEST naming another server is ignored**, per RFC 2131 §4.3.2. On a
///   wire with one server that never happens; the check costs a comparison and
///   removes the case where two gateways answer the same client.
public final class DHCPServer {
    private let stack: Stack
    private let endpoint: UDPEndpoint
    private let gateway: IPv4Address
    private let subnet: IPv4Subnet
    private let leaseSeconds: UInt32
    /// Addresses pinned to a hardware address by configuration. Upstream's
    /// `DHCPStaticLeases`.
    private let staticLeases: [MACAddress: IPv4Address]
    /// Offered as DHCP option 119, so a guest can resolve short names.
    /// Upstream's `DNSSearchDomains`.
    private let searchDomains: [String]
    private let mtu: UInt16

    /// Hardware address to leased address. Bounded by the pool: see the type
    /// comment.
    private var leases: [MACAddress: IPv4Address] = [:]
    private var pool: [IPv4Address] = []

    /// Requests dropped because the pool had nothing left.
    public private(set) var exhausted = 0

    /// Where refusals are reported, if anywhere. `Gateway` sets this; a
    /// hand-assembled arrangement opts in by setting it too.
    public var log: RateLimitedLogger?

    /// How many hardware addresses hold a lease. The figure the pool bounds,
    /// and the one a test asking "did any of this reach the server" reads --
    /// `leasedAddress(for:)` cannot answer that when the addresses were forged.
    public var leaseCount: Int { leases.count }

    /// Every lease, hardware address to address. Upstream serves this on
    /// `GET /leases`, and it is how a caller finds a guest to forward a port to
    /// without being told where it is.
    public var allLeases: [MACAddress: IPv4Address] { leases }

    public static let serverPort: UInt16 = 67
    public static let clientPort: UInt16 = 68

    /// Addresses in `reserved` are ones the gateway already answers for and must
    /// never be leased to a guest. The gateway's own address is always one; the
    /// host address is the one that was missing.
    public init(
        stack: Stack, leaseSeconds: UInt32 = 3600, mtu: UInt16 = 1500,
        staticLeases: [MACAddress: IPv4Address] = [:], searchDomains: [String] = [],
        reserved: [IPv4Address] = []
    ) throws {
        self.staticLeases = staticLeases
        self.searchDomains = searchDomains
        self.stack = stack
        self.gateway = stack.configuration.gatewayAddress
        self.subnet = stack.configuration.subnet
        self.leaseSeconds = leaseSeconds
        self.mtu = mtu
        self.endpoint = UDPEndpoint(stack: stack)
        // The pool excludes every statically-assigned address as well as the
        // gateway's own, so a guest with no static lease is never handed one
        // that belongs to a guest that has one.
        self.pool = Self.addresses(in: subnet, excluding: [gateway] + reserved)
            .filter { !Set(staticLeases.values).contains($0) }
        // Bound to `.any`, not to the gateway's address. A client that does not
        // have an address yet broadcasts to 255.255.255.255, so a binding on the
        // gateway's own address matches nothing that a DHCP client ever sends.
        try endpoint.bind(address: .any, port: Self.serverPort)
        endpoint.onDatagram = { [weak self] payload, source, port in
            self?.handle(payload, from: source, port: port)
        }
    }

    /// Every usable address in the subnet, ascending, without the network
    /// address, the broadcast address, or the gateway's own.
    ///
    /// Capped, because a /8 has sixteen million addresses and materialising them
    /// to hand out a handful is a configuration mistake turning into an
    /// allocation. The cap is on the POOL, not on the subnet: a larger subnet
    /// still works, it simply does not lease past the first few thousand
    /// addresses in it.
    /// Every address a guest may be given: the subnet without its network and
    /// broadcast addresses, and without anything the gateway answers for.
    ///
    /// The exclusions used to be the gateway alone, so the pool contained the
    /// HOST address -- the one `host.containers.internal` resolves to and NAT
    /// translates to the host's loopback. A guest handed it believes it is the
    /// host: `host.containers.internal` names itself, and its ARP for that
    /// address collides with the gateway's.
    ///
    /// On the default /24 that needs two hundred and fifty guests, so it was
    /// invisible. On a /29 it is the fifth:
    ///
    ///     guest 4: leased 192.168.127.5
    ///     guest 5: leased 192.168.127.6   <- the host's address
    static func addresses(in subnet: IPv4Subnet, excluding reserved: [IPv4Address], limit: Int = 4096)
        -> [IPv4Address]
    {
        var out: [IPv4Address] = []
        let network = subnet.address.raw
        let broadcast = subnet.broadcast.raw
        guard broadcast > network else { return [] }
        let taken = Set(reserved)
        var candidate = network &+ 1
        while candidate < broadcast, out.count < limit {
            let address = IPv4Address(candidate)
            if !taken.contains(address) { out.append(address) }
            candidate &+= 1
        }
        return out
    }

    private func handle(_ payload: ByteBuffer, from source: IPv4Address, port: UInt16) {
        guard port == Self.clientPort, let request = DHCPCodec.parse(payload) else { return }
        guard request.operation == .request else { return }

        switch request.messageType {
        case .discover:
            guard let offered = lease(for: request.clientHardwareAddress) else {
                exhausted += 1
                log?.record(.dhcpPoolExhausted, ["mac": .string(request.clientHardwareAddress.description)])
                return
            }
            reply(.offer, to: request, address: offered)
        case .request:
            // RFC 2131 §4.3.2: a REQUEST naming a different server is that
            // server's to answer, and answering it anyway is how two gateways
            // hand one client two addresses.
            if let identifier = request.serverIdentifier, identifier != gateway { return }
            guard let offered = lease(for: request.clientHardwareAddress) else {
                exhausted += 1
                log?.record(.dhcpPoolExhausted, ["mac": .string(request.clientHardwareAddress.description)])
                return
            }
            // A client asking for an address that is not the one it holds is
            // told no, rather than quietly given a different one: RFC 2131
            // §4.3.2's NAK is what makes it restart, and a silent substitution
            // leaves it configured with an address the gateway will not route.
            if let wanted = request.requestedAddress, wanted != offered {
                reply(.nak, to: request, address: IPv4Address(0))
                return
            }
            reply(.ack, to: request, address: offered)
        case .release, .decline:
            leases.removeValue(forKey: request.clientHardwareAddress)
        default:
            break
        }
    }

    private func lease(for hardware: MACAddress) -> IPv4Address? {
        if let existing = leases[hardware] { return existing }
        // A static lease is the operator saying where this guest lives, so it is
        // honoured whether or not the address is inside the pool and whether or
        // not something else already holds it. That last part is deliberate:
        // silently handing out a different address would make a fixed address
        // that is merely misconfigured look like one that works, and the point of
        // asking for a fixed address is that something else is relying on it.
        if let fixed = staticLeases[hardware] {
            leases[hardware] = fixed
            return fixed
        }
        // Ascending, first free. A guest that comes back after a reboot with the
        // same hardware address gets the same entry above; this is only for one
        // it has not seen.
        let taken = Set(leases.values)
        guard let free = pool.first(where: { !taken.contains($0) }) else { return nil }
        leases[hardware] = free
        return free
    }

    /// RFC 3397's list of domain names, uncompressed.
    ///
    /// Compression is permitted and deliberately not used: the pointers are
    /// offsets into the option's own data, several clients have historically got
    /// that wrong, and the saving on two or three domains is a handful of bytes
    /// in a packet that has room.
    static func encodeSearchList(_ domains: [String]) -> [UInt8] {
        var out: [UInt8] = []
        for domain in domains {
            for label in domain.split(separator: ".") {
                // A label longer than 63 bytes cannot be encoded at all: the
                // length byte's top two bits mean "pointer". Skipped rather than
                // truncated, because a truncated label is a different name.
                guard label.utf8.count <= 63 else { continue }
                out.append(UInt8(label.utf8.count))
                out.append(contentsOf: Array(label.utf8))
            }
            out.append(0)
        }
        return out
    }

    private func reply(_ type: DHCPMessage.MessageType, to request: DHCPMessage, address: IPv4Address) {
        var message = request
        message.operation = .reply
        message.clientAddress = IPv4Address(0)
        message.yourAddress = address
        message.serverAddress = gateway

        var options: [(code: UInt8, value: [UInt8])] = [
            (53, [type.rawValue]),
            (54, gateway.bytes),
        ]
        if type != .nak {
            options += [
                (51, withUnsafeBytes(of: leaseSeconds.bigEndian) { Array($0) }),
                (1, subnet.mask.bytes),
                (3, gateway.bytes),
                // The gateway resolves names itself, so it is also the resolver.
                (6, gateway.bytes),
                (26, withUnsafeBytes(of: mtu.bigEndian) { Array($0) }),
            ]
            // RFC 3397 option 119: each domain encoded as DNS labels, one after
            // another. Sent only when there are some -- an empty option is not
            // the same as an absent one, and some clients treat a zero-length
            // 119 as "no search list" overriding what they had.
            if !searchDomains.isEmpty {
                options.append((119, Self.encodeSearchList(searchDomains)))
            }
        }

        let frame = DHCPCodec.serialize(message, options: options, allocator: ByteBufferAllocator())
        // Broadcast, always, and not to `yourAddress`.
        //
        // The client does not have the address yet -- that is what this message
        // is telling it -- so a unicast reply would have to be ARPed for, and the
        // client cannot answer an ARP for an address it has not accepted. RFC
        // 2131 §4.1 allows unicast only when the client already has one.
        try? endpoint.send(frame, to: .broadcast, port: Self.clientPort)
    }

    /// Close. Returns a future for symmetry with the services that own a host
    /// socket; this one owns none, so it is already complete.
    @discardableResult
    public func close() -> EventLoopFuture<Void> {
        endpoint.close()
        return stack.eventLoop.makeSucceededVoidFuture()
    }

    /// The address leased to a hardware address, if any. For tests and for a
    /// control plane that needs to know where a guest is.
    public func leasedAddress(for hardware: MACAddress) -> IPv4Address? {
        leases[hardware]
    }
}
