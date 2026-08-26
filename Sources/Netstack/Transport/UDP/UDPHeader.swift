import NIOCore

public struct UDPHeader: Sendable, Equatable {
    public static let length = 8

    public var sourcePort: UInt16
    public var destinationPort: UInt16
    /// Header plus payload, per the wire field.
    public var length: UInt16
    public var checksum: UInt16

    /// The sum over the IPv4 pseudo-header: source, destination, a zero byte,
    /// the protocol number, and the UDP length.
    static func pseudoHeaderSum(source: IPv4Address, destination: IPv4Address, length: UInt16) -> UInt32 {
        var sum: UInt32 = 0
        sum += UInt32(source.raw >> 16) + UInt32(source.raw & 0xffff)
        sum += UInt32(destination.raw >> 16) + UInt32(destination.raw & 0xffff)
        sum += UInt32(IPProtocol.udp.rawValue)
        sum += UInt32(length)
        return sum
    }

    public static func parse(_ packet: inout PacketBuffer, header: IPv4Header) -> UDPHeader? {
        guard packet.readableBytes >= length else { return nil }

        let declaredLength = packet.payload.getInteger(at: packet.payload.readerIndex + 4, endianness: .big, as: UInt16.self)
        guard let declaredLength, Int(declaredLength) >= length, Int(declaredLength) <= packet.readableBytes else { return nil }

        let onWireChecksum = packet.payload.getInteger(at: packet.payload.readerIndex + 6, endianness: .big, as: UInt16.self) ?? 0
        // Zero means the sender declined to compute one, which RFC 768 allows
        // over IPv4. Anything else must verify.
        if onWireChecksum != 0 {
            let pseudo = pseudoHeaderSum(source: header.source, destination: header.destination, length: declaredLength)
            let total = packet.payload.withUnsafeReadableBytes { bytes in
                Checksum.partial(UnsafeRawBufferPointer(rebasing: bytes[0..<Int(declaredLength)]), initial: pseudo)
            }
            guard Checksum.complete(total) == 0 else { return nil }
        }

        guard var fields = packet.consumeHeader(length) else { return nil }
        guard
            let sourcePort = fields.readInteger(endianness: .big, as: UInt16.self),
            let destinationPort = fields.readInteger(endianness: .big, as: UInt16.self),
            fields.readInteger(endianness: .big, as: UInt16.self) != nil,
            fields.readInteger(endianness: .big, as: UInt16.self) != nil
        else { return nil }

        packet.trimPayload(to: Int(declaredLength) - length)
        // `declaredLength` is the wire field as-is: header plus payload. The
        // brief's own draft here returned `declaredLength - length` (payload
        // only), which contradicts both this property's own doc comment and
        // `parsesAValidDatagram`, which asserts `header?.length == 10` for an
        // 8-byte header plus a 2-byte payload.
        return UDPHeader(sourcePort: sourcePort, destinationPort: destinationPort, length: declaredLength, checksum: onWireChecksum)
    }

    /// The largest payload one UDP datagram can carry: 65535 (the largest
    /// value the IPv4 total-length field can hold) minus the minimum IPv4
    /// header (20) minus this header (8) — 65507. `length + payload` below
    /// is a non-failable `UInt16` conversion that TRAPS the process once the
    /// sum exceeds 65535, and `IPv4Protocol.send`'s own guard against
    /// exactly that never runs: it lives one layer up and this serializer is
    /// called before it, so the trap fires first. A real UDP socket returns
    /// EMSGSIZE instead of crashing; this bound exists so this call can too.
    public static let maximumPayloadLength = 65535 - IPv4Header.minimumLength - length

    /// Build a complete datagram: header plus payload, checksum filled in.
    /// Returns `nil` when `payload` cannot fit in one UDP datagram — see
    /// `maximumPayloadLength` — rather than trapping.
    public static func serialize(
        payload: ByteBuffer, source: IPv4Address, destination: IPv4Address,
        sourcePort: UInt16, destinationPort: UInt16, allocator: ByteBufferAllocator
    ) -> ByteBuffer? {
        guard payload.readableBytes <= maximumPayloadLength else { return nil }
        let total = UInt16(length + payload.readableBytes)
        var datagram = allocator.buffer(capacity: Int(total))
        datagram.writeInteger(sourcePort, endianness: .big)
        datagram.writeInteger(destinationPort, endianness: .big)
        datagram.writeInteger(total, endianness: .big)
        datagram.writeInteger(UInt16(0), endianness: .big)
        datagram.writeImmutableBuffer(payload)

        let pseudo = pseudoHeaderSum(source: source, destination: destination, length: total)
        let sum = datagram.withUnsafeReadableBytes { Checksum.partial($0, initial: pseudo) }
        var checksum = Checksum.complete(sum)
        // A computed zero is transmitted as all-ones, because zero on the wire
        // means "no checksum here" and would disable verification entirely.
        if checksum == 0 { checksum = 0xffff }
        datagram.setInteger(checksum, at: datagram.readerIndex + 6, endianness: .big)
        return datagram
    }
}
