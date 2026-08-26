import NIOCore

/// One link, plus the addresses the stack answers for on it.
///
/// Every method here runs on `link.eventLoop`. The class is deliberately not
/// `Sendable`: it is loop-confined state, and the compiler should stop anyone
/// reaching for it from elsewhere.
public final class NIC: LinkDispatcher {
    public let id: Int
    public let link: LinkEndpoint

    /// Accept frames whose destination MAC is not ours. Upstream's
    /// `SetPromiscuousMode(1, true)`.
    public var acceptsAnyDestination = false
    /// Transmit from source addresses this NIC does not own. Upstream's
    /// `SetSpoofing(1, true)`. Consumed by `RouteTable`, not here.
    public var allowsAnySource = false

    private struct AssignedAddress {
        let address: IPv4Address
        let prefixLength: UInt8
    }
    private var assigned: [AssignedAddress] = []
    private var handlers: [EtherType: (PacketBuffer, EthernetHeader) -> Void] = [:]

    public init(id: Int, link: LinkEndpoint) {
        self.id = id
        self.link = link
        link.attach(self)
    }

    public func addAddress(_ address: IPv4Address, prefixLength: UInt8) {
        guard !assigned.contains(where: { $0.address == address }) else { return }
        assigned.append(AssignedAddress(address: address, prefixLength: prefixLength))
    }

    public func hasAddress(_ address: IPv4Address) -> Bool {
        assigned.contains { $0.address == address }
    }

    public var addresses: [IPv4Address] { assigned.map(\.address) }

    /// The address the stack speaks from by default. First assigned wins.
    public var primaryAddress: IPv4Address? { assigned.first?.address }

    public func subnet(for address: IPv4Address) -> IPv4Subnet? {
        assigned.first { $0.address == address }.map { IPv4Subnet(address: $0.address, prefixLength: $0.prefixLength) }
    }

    public func setHandler(for etherType: EtherType, _ handler: @escaping (PacketBuffer, EthernetHeader) -> Void) {
        handlers[etherType] = handler
    }

    /// Detach every registered handler. `Stack.shutdown()` calls this so a
    /// shut-down stack releases whatever its handler closures captured —
    /// historically including a strong reference back to this NIC itself —
    /// promptly, rather than only when every external reference to the
    /// `Stack` also happens to go away.
    public func removeAllHandlers() {
        handlers.removeAll()
    }

    // MARK: LinkDispatcher

    public func deliverInbound(_ frame: PacketBuffer) {
        var packet = frame
        guard let header = EthernetHeader.parse(&packet) else { return }
        guard header.destination == link.linkAddress || header.destination.isMulticast || acceptsAnyDestination else { return }
        guard let handler = handlers[header.etherType] else { return }
        handler(packet, header)
    }

    // MARK: Transmit

    public func send(_ packet: inout PacketBuffer, to destination: MACAddress, etherType: EtherType) {
        let header = EthernetHeader(destination: destination, source: link.linkAddress, etherType: etherType)
        header.prepend(to: &packet)
        link.write([packet])
    }
}
