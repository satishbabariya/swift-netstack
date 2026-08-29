import NIOCore

/// A learning ethernet switch, so one gateway can serve several guests.
///
/// Upstream's `pkg/tap.Switch`, which is the piece that makes a
/// gvisor-tap-vsock network a *network* rather than a point-to-point link. Every
/// guest gets a port; frames addressed to another guest are forwarded between
/// ports and never touch the stack at all; frames addressed to the gateway, and
/// broadcasts, go up to it.
///
/// This is both ends of the link abstraction at once, which is what makes it
/// small: it receives from each of its ports (through a `PortDispatcher` shim
/// per port, so it knows which one) and it is a `LinkEndpoint` to the `Stack`
/// above. The stack cannot tell it apart from one wire, so nothing above this
/// file knows there is more than one guest.
///
/// ## The forwarding rules
///
/// From a guest (`receive`):
/// - the source address is learned against the port it arrived on;
/// - if the destination is not the gateway, it is forwarded onto the fabric;
/// - if the destination is the gateway *or* broadcast, it also goes up.
///
/// Both halves run for a broadcast, which is the case that matters: an ARP
/// request has to reach the other guests *and* the gateway, and a DHCP DISCOVER
/// has to reach the server while the other guests ignore it.
///
/// From the gateway (`write`):
/// - broadcast floods every port except the one the source is on;
/// - unicast goes to the one port the CAM names;
/// - **an unknown unicast destination is dropped, not flooded.**
///
/// That last rule is upstream's, and it is worth defending rather than
/// inheriting. A real switch floods unknown unicast, and a real switch is on a
/// network whose stations are not assumed hostile. Here they are: flooding would
/// let any guest make the switch replicate a frame to every port by addressing a
/// MAC nobody owns, which is a multiplier the guest chooses and nothing bounds.
/// Dropping costs the case of a station that has not spoken yet -- and on this
/// network every station speaks first, because it has to ask for an address by
/// DHCP before it can use one.
/// `@unchecked Sendable` on the same terms as `WireLinkEndpoint`: every stored
/// property here is loop-confined and every method preconditions on the loop, so
/// the safety is real but is enforced by those preconditions rather than by
/// anything the compiler can check.
public final class NetworkSwitch: GatewayLink, @unchecked Sendable {
    public let mtu: UInt32
    /// The gateway's own address. A frame addressed here goes up rather than
    /// across.
    public let linkAddress: MACAddress
    public let capabilities: LinkCapabilities = []
    public let eventLoop: EventLoop

    /// How many source addresses one port may claim.
    ///
    /// The bound upstream does not have, and the reason this type has one:
    /// upstream's CAM is a `map` that grows by an entry for every source address
    /// it ever sees, and the source address is a field the guest writes. A guest
    /// emitting frames with random source addresses at line rate makes that map
    /// grow without limit, in the host, on a network whose whole threat model is
    /// that the guest is hostile.
    ///
    /// The bound is **per port**, not global, and that is the point. A global cap
    /// would let one flooding guest fill the table and lock every other guest
    /// out of it; a per-port cap means a guest can only ever exhaust its own
    /// share, and the total is `ports x limit` by construction. Real switches
    /// call this port security and do it for the same reason.
    public let maximumAddressesPerPort: Int

    private var ports: [Int: WireLinkEndpoint] = [:]
    private var cam: [MACAddress: Int] = [:]
    /// How many addresses each port has claimed, so the bound above can be
    /// enforced without counting the CAM on every frame.
    private var claimed: [Int: Int] = [:]
    private var shims: [Int: PortDispatcher] = [:]
    private var nextPortID = 0
    private weak var dispatcher: (any LinkDispatcher)?

    /// Frames dropped because their destination was on no port this switch
    /// knows. See the unknown-unicast rule above.
    public private(set) var unknownUnicastDropped = 0
    /// Source addresses not learned because the port had claimed its limit.
    public private(set) var addressesRefused = 0
    /// Addresses that moved from one port to another. See `learn`.
    public private(set) var addressesMoved = 0

    public var log: RateLimitedLogger? {
        didSet {
            // Handed down, so a port's own rejected frames land in the same
            // window as everything else rather than in one nobody set.
            for link in ports.values { link.log = log }
        }
    }

    /// What the ports dropped, live ones and the ones that have gone.
    ///
    /// Summed rather than stored because a port owns its own counters and a
    /// switch owns no wire of its own. `retired` carries the totals of ports
    /// that have disconnected, so a guest leaving does not make the gateway's
    /// statistics go backwards -- which for a monotonic counter is not a smaller
    /// number, it is a counter reset, and a monitoring system reads that as a
    /// restart.
    public var inboundDropped: Int { retiredInbound + ports.values.reduce(0) { $0 + $1.inboundDropped } }
    public var outboundDropped: Int { retiredOutbound + ports.values.reduce(0) { $0 + $1.outboundDropped } }
    private var retiredInbound = 0
    private var retiredOutbound = 0

    /// The number of ports currently connected.
    public var portCount: Int { ports.count }

    public init(
        linkAddress: MACAddress, mtu: UInt32 = 1500, eventLoop: EventLoop,
        maximumAddressesPerPort: Int = 16
    ) {
        self.linkAddress = linkAddress
        self.mtu = mtu
        self.eventLoop = eventLoop
        self.maximumAddressesPerPort = max(1, maximumAddressesPerPort)
    }

    // MARK: - Ports

    /// Add a guest's wire, and start carrying its frames. Returns the port id.
    ///
    /// The wire must be on this switch's loop. Everything here is loop-confined
    /// and there are no locks; a port on another loop would deliver frames from
    /// a thread the CAM is not safe to touch from, which is a data race rather
    /// than a slow path.
    @discardableResult
    public func addPort(_ link: WireLinkEndpoint) -> Int {
        eventLoop.preconditionInEventLoop()
        precondition(link.eventLoop === eventLoop, "every port must share the switch's event loop")
        let id = nextPortID
        nextPortID += 1
        let shim = PortDispatcher(id: id, owner: self)
        shims[id] = shim
        ports[id] = link
        claimed[id] = 0
        link.log = log
        link.attach(shim)
        return id
    }

    /// Remove a port and forget everything learned on it.
    ///
    /// Purging the CAM is not tidiness: an entry left behind points at a port
    /// that is gone, so every frame for that address is delivered nowhere and
    /// silently, and it stays that way until the guest returns on the same port
    /// id -- which the next guest to connect will be given.
    @discardableResult
    public func removePort(_ id: Int) -> EventLoopFuture<Void> {
        eventLoop.preconditionInEventLoop()
        guard let link = ports.removeValue(forKey: id) else {
            return eventLoop.makeSucceededVoidFuture()
        }
        shims.removeValue(forKey: id)
        claimed.removeValue(forKey: id)
        retiredInbound += link.inboundDropped
        retiredOutbound += link.outboundDropped
        for (address, port) in cam where port == id {
            cam.removeValue(forKey: address)
        }
        return link.close()
    }

    /// The learned address table, as an operator would read it. Upstream serves
    /// the same thing on `GET /cam`.
    public var addressTable: [MACAddress: Int] {
        eventLoop.preconditionInEventLoop()
        return cam
    }

    // MARK: - LinkEndpoint

    public func attach(_ dispatcher: LinkDispatcher) {
        eventLoop.preconditionInEventLoop()
        self.dispatcher = dispatcher
    }

    /// Egress from the gateway's stack onto the fabric.
    public func write(_ packets: [PacketBuffer]) {
        eventLoop.preconditionInEventLoop()
        for packet in packets {
            guard let (destination, source) = Self.addresses(of: packet) else { continue }
            if destination.isBroadcast || destination.isMulticast {
                flood(packet, from: cam[source])
            } else if let port = cam[destination], let link = ports[port] {
                link.write([packet])
            } else {
                unknownUnicastDropped += 1
                log?.record(.switchUnknownUnicast, ["destination": .string(destination.description)])
            }
        }
    }

    // MARK: - LinkDispatcher, per port

    /// A frame arriving from the guest on `port`.
    fileprivate func receive(_ packet: PacketBuffer, from port: Int) {
        eventLoop.preconditionInEventLoop()
        guard let (destination, source) = Self.addresses(of: packet) else { return }
        learn(source, on: port)

        // Across the fabric, if it is not for the gateway. A broadcast is both:
        // it goes to the other guests here and up to the stack below.
        if destination != linkAddress {
            if destination.isBroadcast || destination.isMulticast {
                flood(packet, from: port)
            } else if let target = cam[destination], let link = ports[target] {
                // Never back out of the port it came in on. A guest that sends a
                // frame to its own address would otherwise have it echoed
                // straight back, and two guests briefly sharing an entry would
                // do it in a loop.
                if target != port { link.write([packet]) }
            } else {
                unknownUnicastDropped += 1
                log?.record(.switchUnknownUnicast, ["destination": .string(destination.description)])
            }
        }
        if destination == linkAddress || destination.isBroadcast || destination.isMulticast {
            dispatcher?.deliverInbound(packet)
        }
    }

    private func flood(_ packet: PacketBuffer, from source: Int?) {
        for (id, link) in ports where id != source {
            link.write([packet])
        }
    }

    /// Record that `address` is reachable on `port`.
    ///
    /// An address already on another port **moves**, which is the behaviour a
    /// switch has to have -- a guest that reconnects arrives on a new port and
    /// would otherwise be unreachable forever. It is also, on a network of
    /// mutually distrusting guests, how one guest steals another's traffic: claim
    /// its address and the CAM points at you. Nothing here can distinguish the
    /// two, so this does not pretend to; it counts moves and logs them, so an
    /// operator has something to look at. Upstream moves silently.
    private func learn(_ address: MACAddress, on port: Int) {
        if let existing = cam[address] {
            guard existing != port else { return }
            cam[address] = port
            claimed[existing, default: 1] -= 1
            claimed[port, default: 0] += 1
            addressesMoved += 1
            log?.record(
                .switchAddressMoved,
                ["mac": .string(address.description), "from": .stringConvertible(existing),
                 "to": .stringConvertible(port)])
            return
        }
        guard claimed[port, default: 0] < maximumAddressesPerPort else {
            addressesRefused += 1
            log?.record(
                .switchAddressRefused,
                ["port": .stringConvertible(port), "limit": .stringConvertible(maximumAddressesPerPort)])
            return
        }
        cam[address] = port
        claimed[port, default: 0] += 1
    }

    /// Destination and source, read without consuming the frame.
    ///
    /// `EthernetHeader.parse` advances the reader index, which is right for the
    /// stack -- it is about to look at what is underneath -- and wrong here,
    /// because this frame is about to be written to another port whole.
    private static func addresses(of packet: PacketBuffer) -> (MACAddress, MACAddress)? {
        let frame = packet.frame
        guard let bytes = frame.getBytes(at: frame.readerIndex, length: 12),
            let destination = MACAddress(bytes: Array(bytes[0..<6])),
            let source = MACAddress(bytes: Array(bytes[6..<12]))
        else { return nil }
        return (destination, source)
    }

    /// Close every port.
    @discardableResult
    public func close() -> EventLoopFuture<Void> {
        eventLoop.preconditionInEventLoop()
        for link in ports.values {
            retiredInbound += link.inboundDropped
            retiredOutbound += link.outboundDropped
        }
        let closing = ports.values.map { $0.close() }
        ports.removeAll()
        shims.removeAll()
        claimed.removeAll()
        cam.removeAll()
        return EventLoopFuture.andAllSucceed(closing, on: eventLoop)
    }
}

/// One port's dispatcher, which exists only to remember which port it is.
///
/// `LinkDispatcher.deliverInbound` does not say where the frame came from, and
/// for a switch that is the one thing it must know. A shim per port is the
/// cheapest way to carry it without widening the protocol for a case only this
/// type has.
private final class PortDispatcher: LinkDispatcher {
    let id: Int
    private weak var owner: NetworkSwitch?

    init(id: Int, owner: NetworkSwitch) {
        self.id = id
        self.owner = owner
    }

    func deliverInbound(_ frame: PacketBuffer) {
        owner?.receive(frame, from: id)
    }
}
