import NIOCore

public struct IPv4Header: Sendable, Equatable {
    public static let minimumLength = 20
    public static let defaultTTL: UInt8 = 64

    public struct Flags: OptionSet, Sendable {
        public let rawValue: UInt8
        public init(rawValue: UInt8) { self.rawValue = rawValue }
        public static let moreFragments = Flags(rawValue: 1 << 0)
        public static let dontFragment = Flags(rawValue: 1 << 1)
    }

    public var version: UInt8 = 4
    /// In bytes, not words. Always a multiple of four, at least 20.
    ///
    /// Setter is private: `PacketBuffer`'s headroom is sized for headers of
    /// minimum length (ethernet 14 + IPv4 20 + TCP 60 = 94 bytes, rounded up
    /// to 128). This stack never emits IPv4 options, so nothing outside this
    /// type may push `headerLength` past 20 and blow that budget. `parse` is
    /// a static method on this type, so it can still set it when decoding an
    /// incoming header that does carry options.
    public private(set) var headerLength: Int = IPv4Header.minimumLength
    public var dscp: UInt8 = 0
    /// Header plus payload, in bytes.
    public var totalLength: UInt16 = 0
    public var identification: UInt16 = 0
    public var flags: Flags = []
    /// In bytes. The wire encodes it in eight-byte units; this is decoded.
    public var fragmentOffset: Int = 0
    public var ttl: UInt8 = IPv4Header.defaultTTL
    public var protocolNumber: IPProtocol = .udp
    public var source: IPv4Address = .any
    public var destination: IPv4Address = .any

    public var payloadLength: Int { Int(totalLength) - headerLength }

    public init(source: IPv4Address, destination: IPv4Address, protocolNumber: IPProtocol, payloadLength: Int) {
        self.source = source
        self.destination = destination
        self.protocolNumber = protocolNumber
        self.totalLength = UInt16(Self.minimumLength + payloadLength)
    }

    private init() {}

    /// Consume and validate the header, leaving the payload trimmed to
    /// `totalLength`. Returns nil on anything malformed — a bad checksum, a
    /// wrong version, a length that overruns the frame.
    public static func parse(_ packet: inout PacketBuffer) -> IPv4Header? {
        let available = packet.readableBytes
        guard available >= minimumLength else { return nil }

        // Peek the first byte for the header length before consuming, because
        // options make the header a variable size.
        let firstByte = packet.payload.getInteger(at: packet.payload.readerIndex, as: UInt8.self)
        guard let firstByte, firstByte >> 4 == 4 else { return nil }
        let headerLength = Int(firstByte & 0x0f) * 4
        guard headerLength >= minimumLength, headerLength <= available else { return nil }

        // Validate the checksum over the header as it stands on the wire.
        let checksumValid = packet.payload.withUnsafeReadableBytes { bytes -> Bool in
            Checksum.compute(UnsafeRawBufferPointer(rebasing: bytes[0..<headerLength])) == 0
        }
        guard checksumValid else { return nil }

        guard var header = packet.consumeHeader(headerLength) else { return nil }
        var parsed = IPv4Header()
        parsed.version = 4
        parsed.headerLength = headerLength

        header.moveReaderIndex(forwardBy: 1)
        guard
            let dscp = header.readInteger(as: UInt8.self),
            let totalLength = header.readInteger(endianness: .big, as: UInt16.self),
            let identification = header.readInteger(endianness: .big, as: UInt16.self),
            let flagsAndOffset = header.readInteger(endianness: .big, as: UInt16.self),
            let ttl = header.readInteger(as: UInt8.self),
            let protocolNumber = header.readInteger(as: UInt8.self),
            header.readInteger(endianness: .big, as: UInt16.self) != nil,  // checksum, already verified
            let sourceBytes = header.readBytes(length: 4),
            let destinationBytes = header.readBytes(length: 4)
        else { return nil }

        parsed.dscp = dscp
        parsed.totalLength = totalLength
        parsed.identification = identification
        parsed.flags = Flags(rawValue: UInt8(flagsAndOffset >> 13) & 0x03)
        parsed.fragmentOffset = Int(flagsAndOffset & 0x1fff) * 8
        parsed.ttl = ttl
        parsed.protocolNumber = IPProtocol(rawValue: protocolNumber)
        parsed.source = IPv4Address(sourceBytes[0], sourceBytes[1], sourceBytes[2], sourceBytes[3])
        parsed.destination = IPv4Address(destinationBytes[0], destinationBytes[1], destinationBytes[2], destinationBytes[3])

        // Total length must cover the header and fit inside the frame.
        // Ethernet pads short frames, so the payload may be longer than
        // total length says; trim rather than reject.
        guard Int(totalLength) >= headerLength, Int(totalLength) <= available else { return nil }
        let declaredPayload = Int(totalLength) - headerLength
        if packet.readableBytes > declaredPayload {
            packet.trimPayload(to: declaredPayload)
        }
        return parsed
    }

    public func prepend(to packet: inout PacketBuffer) {
        let payloadLength = packet.readableBytes
        // Always exactly 20 bytes. A header returned by `parse` may report a longer
        // `headerLength` because the packet carried IPv4 options, but this stack
        // never emits options, and the checksum arithmetic below is only valid for
        // the ten fixed-field words. Re-emitting such a header — which the ICMP
        // error path does when it quotes an offending packet — therefore drops the
        // options rather than reserving space it would leave uninitialised and
        // unchecksummed. Receivers match a quoted header on its addresses and the
        // transport ports that follow it, not on its IHL.
        let length = Self.minimumLength
        packet.prepend(count: length) { buffer, index in
            buffer.setInteger(UInt8(0x40 | (length / 4)), at: index)
            buffer.setInteger(dscp, at: index + 1)
            buffer.setInteger(UInt16(length + payloadLength), at: index + 2, endianness: .big)
            buffer.setInteger(identification, at: index + 4, endianness: .big)
            let flagsAndOffset = UInt16(flags.rawValue) << 13 | UInt16(fragmentOffset / 8)
            buffer.setInteger(flagsAndOffset, at: index + 6, endianness: .big)
            buffer.setInteger(ttl, at: index + 8)
            buffer.setInteger(protocolNumber.rawValue, at: index + 9)
            buffer.setInteger(UInt16(0), at: index + 10, endianness: .big)
            buffer.setBytes(source.bytes, at: index + 12)
            buffer.setBytes(destination.bytes, at: index + 16)

            // Sum the header's ten 16-bit big-endian words directly. Reading
            // them back out of the buffer does not work here: `prepend`
            // writes below the reader index and only moves it afterwards, so
            // the bytes just written are not in the readable range yet. The
            // checksum word itself contributes zero. This arithmetic is only
            // valid because `headerLength` is guaranteed to be exactly 20 —
            // `headerLength`'s setter is private, so nothing outside this
            // type can grow it to include options.
            var sum: UInt32 = 0
            sum += UInt32(UInt16(0x4000 | (length / 4) << 8) | UInt16(dscp))
            sum += UInt32(UInt16(length + payloadLength))
            sum += UInt32(identification)
            sum += UInt32(flagsAndOffset)
            sum += UInt32(UInt16(ttl) << 8 | UInt16(protocolNumber.rawValue))
            sum += UInt32(source.raw >> 16) + UInt32(source.raw & 0xffff)
            sum += UInt32(destination.raw >> 16) + UInt32(destination.raw & 0xffff)
            buffer.setInteger(Checksum.complete(sum), at: index + 10, endianness: .big)
        }
    }
}
