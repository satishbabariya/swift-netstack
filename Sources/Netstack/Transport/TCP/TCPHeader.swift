import NIOCore

/// FIN/SYN/RST/PSH/ACK/URG — the classic (pre-ECN) TCP control bits, in
/// wire-bit order (bit 0 is FIN, matching the low byte of the flags field).
/// This stack does not model CWR/ECE/NS.
public struct TCPFlags: OptionSet, Sendable, Equatable {
    public let rawValue: UInt8
    public init(rawValue: UInt8) { self.rawValue = rawValue }

    public static let fin = TCPFlags(rawValue: 1 << 0)
    public static let syn = TCPFlags(rawValue: 1 << 1)
    public static let rst = TCPFlags(rawValue: 1 << 2)
    public static let psh = TCPFlags(rawValue: 1 << 3)
    public static let ack = TCPFlags(rawValue: 1 << 4)
    public static let urg = TCPFlags(rawValue: 1 << 5)
}

/// A parsed (or about-to-be-serialized) TCP segment header.
///
/// Deliberately independent of `Tests/NetstackTests/Support/VectorFrames.swift`'s
/// own hand-rolled TCP encoder/decoder — see that file's doc comment. The
/// two are cross-checked against each other in `TCPHeaderTests.swift`
/// rather than sharing any code, so that a defect one of them shares with
/// the other cannot cancel out and hide.
public struct TCPHeader: Equatable, Sendable {
    /// The fixed-field header length in bytes, before options. The wire's
    /// own "data offset" field (see `dataOffset` below) is in 32-bit words,
    /// not bytes.
    public static let minimumLength = 20

    public var sourcePort: UInt16
    public var destinationPort: UInt16
    public var sequence: SequenceNumber
    public var acknowledgement: SequenceNumber
    /// In 32-bit words, exactly as the wire field is defined (RFC 793 §3.1)
    /// — NOT bytes. Multiply by 4 to get the header length in bytes.
    /// `parse` only ever returns a value >= 5 (the fixed header alone).
    public var dataOffset: Int
    public var flags: TCPFlags
    public var window: UInt16
    public var checksum: UInt16
    public var urgentPointer: UInt16
    public var options: [TCPOption]

    public init(
        sourcePort: UInt16,
        destinationPort: UInt16,
        sequence: SequenceNumber,
        acknowledgement: SequenceNumber,
        dataOffset: Int,
        flags: TCPFlags,
        window: UInt16,
        checksum: UInt16,
        urgentPointer: UInt16,
        options: [TCPOption]
    ) {
        self.sourcePort = sourcePort
        self.destinationPort = destinationPort
        self.sequence = sequence
        self.acknowledgement = acknowledgement
        self.dataOffset = dataOffset
        self.flags = flags
        self.window = window
        self.checksum = checksum
        self.urgentPointer = urgentPointer
        self.options = options
    }

    /// The sum over the IPv4 pseudo-header: source, destination, a zero
    /// byte, protocol 6 (TCP), and the TCP length (header + options +
    /// payload). Same shape as `UDPHeader.pseudoHeaderSum` for protocol 17
    /// — mirrored deliberately, not shared, per this type's doc comment.
    static func pseudoHeaderSum(source: IPv4Address, destination: IPv4Address, length: UInt16) -> UInt32 {
        var sum: UInt32 = 0
        sum += UInt32(source.raw >> 16) + UInt32(source.raw & 0xffff)
        sum += UInt32(destination.raw >> 16) + UInt32(destination.raw & 0xffff)
        sum += UInt32(IPProtocol.tcp.rawValue)
        sum += UInt32(length)
        return sum
    }

    /// Parse a TCP segment from `packet`, whose remaining bytes are the
    /// entire segment — header, options, and payload — exactly what
    /// `IPv4Header.parse` leaves behind (TCP has no length field of its
    /// own; the segment's length is implicit from the IP layer). Returns
    /// nil, leaving `packet` untouched, for anything malformed: a runt
    /// segment, a data offset below 5 words, a data offset claiming more
    /// than the segment holds, a malformed option, or a bad checksum.
    ///
    /// Options are parsed before the checksum is validated. This is not
    /// just an ordering preference: an option list is parsed from a
    /// read-only view regardless, so parsing it first costs nothing, and it
    /// keeps a malformed-option rejection attributable to the option guard
    /// rather than to the checksum. Checksum-first would still reject a
    /// segment whose only problem is a bad option, but for the wrong
    /// reason — corrupting an option's length byte also corrupts the bytes
    /// the checksum covers, so a checksum-first ordering can silently mask
    /// whether the option-length guard (the thing that stands between a
    /// hostile segment and a hung parser) is even doing anything.
    public static func parse(_ packet: inout PacketBuffer, header ipHeader: IPv4Header) -> TCPHeader? {
        let available = packet.readableBytes
        guard available >= minimumLength else { return nil }

        guard let offsetByte = packet.payload.getInteger(at: packet.payload.readerIndex + 12, as: UInt8.self) else {
            return nil
        }
        let dataOffsetWords = Int(offsetByte >> 4)
        let headerLength = dataOffsetWords * 4
        guard dataOffsetWords >= 5, headerLength <= available else { return nil }

        var optionsView = packet.payload
        optionsView.moveReaderIndex(forwardBy: minimumLength)
        guard var optionSlice = optionsView.readSlice(length: headerLength - minimumLength) else { return nil }
        guard let options = TCPOptionCodec.parse(&optionSlice) else { return nil }

        let pseudo = pseudoHeaderSum(source: ipHeader.source, destination: ipHeader.destination, length: UInt16(available))
        let checksumValid = packet.payload.withUnsafeReadableBytes { bytes -> Bool in
            Checksum.complete(Checksum.partial(UnsafeRawBufferPointer(rebasing: bytes[0..<available]), initial: pseudo)) == 0
        }
        guard checksumValid else { return nil }

        guard var fields = packet.consumeHeader(headerLength) else { return nil }
        guard
            let sourcePort = fields.readInteger(endianness: .big, as: UInt16.self),
            let destinationPort = fields.readInteger(endianness: .big, as: UInt16.self),
            let sequenceValue = fields.readInteger(endianness: .big, as: UInt32.self),
            let ackValue = fields.readInteger(endianness: .big, as: UInt32.self),
            let offsetAndFlags = fields.readInteger(endianness: .big, as: UInt16.self),
            let window = fields.readInteger(endianness: .big, as: UInt16.self),
            let checksum = fields.readInteger(endianness: .big, as: UInt16.self),
            let urgentPointer = fields.readInteger(endianness: .big, as: UInt16.self)
        else { return nil }

        let flags = TCPFlags(rawValue: UInt8(truncatingIfNeeded: offsetAndFlags))
        return TCPHeader(
            sourcePort: sourcePort,
            destinationPort: destinationPort,
            sequence: SequenceNumber(sequenceValue),
            acknowledgement: SequenceNumber(ackValue),
            dataOffset: dataOffsetWords,
            flags: flags,
            window: window,
            checksum: checksum,
            urgentPointer: urgentPointer,
            options: options)
    }

    /// Build a complete segment: header, options, and payload, with the
    /// checksum filled in.
    public func serialize(
        payload: ByteBuffer, source: IPv4Address, destination: IPv4Address, allocator: ByteBufferAllocator
    ) -> ByteBuffer {
        let optionBytes = TCPOptionCodec.encode(options)
        let headerLength = Self.minimumLength + optionBytes.count
        let dataOffsetWords = headerLength / 4
        let totalLength = headerLength + payload.readableBytes

        var segment = allocator.buffer(capacity: totalLength)
        segment.writeInteger(sourcePort, endianness: .big)
        segment.writeInteger(destinationPort, endianness: .big)
        segment.writeInteger(sequence.value, endianness: .big)
        segment.writeInteger(acknowledgement.value, endianness: .big)
        segment.writeInteger(UInt16(dataOffsetWords) << 12 | UInt16(flags.rawValue), endianness: .big)
        segment.writeInteger(window, endianness: .big)
        segment.writeInteger(UInt16(0), endianness: .big)  // checksum, filled below
        segment.writeInteger(urgentPointer, endianness: .big)
        segment.writeBytes(optionBytes)
        segment.writeImmutableBuffer(payload)

        let pseudo = Self.pseudoHeaderSum(source: source, destination: destination, length: UInt16(totalLength))
        let sum = segment.withUnsafeReadableBytes { Checksum.partial($0, initial: pseudo) }
        segment.setInteger(Checksum.complete(sum), at: segment.readerIndex + 16, endianness: .big)
        return segment
    }
}
