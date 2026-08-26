import NIOCore

/// An Ethernet II header. No VLAN tags: the wires this stack attaches to are
/// point-to-point between a hypervisor and one guest, and nothing tags them.
public struct EthernetHeader: Sendable, Equatable {
    public static let length = 14

    public var destination: MACAddress
    public var source: MACAddress
    public var etherType: EtherType

    public init(destination: MACAddress, source: MACAddress, etherType: EtherType) {
        self.destination = destination
        self.source = source
        self.etherType = etherType
    }

    /// Consume the header from the front of `packet`, leaving the payload.
    /// Returns nil, leaving `packet` untouched, if the frame is too short.
    public static func parse(_ packet: inout PacketBuffer) -> EthernetHeader? {
        guard var header = packet.consumeHeader(length) else { return nil }
        guard
            let destinationBytes = header.readBytes(length: 6),
            let sourceBytes = header.readBytes(length: 6),
            let type = header.readInteger(endianness: .big, as: UInt16.self),
            let destination = MACAddress(bytes: destinationBytes),
            let source = MACAddress(bytes: sourceBytes)
        else { return nil }
        return EthernetHeader(destination: destination, source: source, etherType: EtherType(rawValue: type))
    }

    public func prepend(to packet: inout PacketBuffer) {
        packet.prepend(count: Self.length) { buffer, index in
            buffer.setBytes(destination.bytes, at: index)
            buffer.setBytes(source.bytes, at: index + 6)
            buffer.setInteger(etherType.rawValue, at: index + 12, endianness: .big)
        }
    }
}
