import NIOCore

public struct ICMPv4Header: Sendable, Equatable {
    public static let length = 8

    public var type: ICMPv4Type
    public var code: UInt8
    /// The four bytes after type/code/checksum are reused across message
    /// types for unrelated purposes, so this is structural rather than a
    /// single field callers must remember to gate on `type`: `identifier`
    /// and `sequence` are set only for echo request/reply, and `nextHopMTU`
    /// only for a fragmentation-needed error (destination unreachable, code 4).
    public var identifier: UInt16?
    public var sequence: UInt16?
    /// Next-hop MTU, present only on a fragmentation-needed error.
    public var nextHopMTU: UInt16?

    public init(type: ICMPv4Type, code: UInt8, identifier: UInt16? = nil, sequence: UInt16? = nil, nextHopMTU: UInt16? = nil) {
        self.type = type
        self.code = code
        self.identifier = identifier
        self.sequence = sequence
        self.nextHopMTU = nextHopMTU
    }

    /// Consume and validate. ICMP checksums cover the whole message, header
    /// and payload together, with no pseudo-header.
    public static func parse(_ packet: inout PacketBuffer) -> ICMPv4Header? {
        guard packet.readableBytes >= length else { return nil }
        let valid = packet.payload.withUnsafeReadableBytes { Checksum.compute($0) == 0 }
        guard valid else { return nil }

        guard var header = packet.consumeHeader(length) else { return nil }
        guard
            let type = header.readInteger(as: UInt8.self),
            let code = header.readInteger(as: UInt8.self),
            header.readInteger(endianness: .big, as: UInt16.self) != nil,  // checksum, verified
            let high = header.readInteger(endianness: .big, as: UInt16.self),
            let low = header.readInteger(endianness: .big, as: UInt16.self)
        else { return nil }

        let icmpType = ICMPv4Type(rawValue: type)
        var parsed = ICMPv4Header(type: icmpType, code: code)
        switch (icmpType, code) {
        case (.echoRequest, _), (.echoReply, _):
            parsed.identifier = high
            parsed.sequence = low
        case (.destinationUnreachable, ICMPv4.UnreachableCode.fragmentationNeeded.rawValue):
            parsed.nextHopMTU = low
        default:
            break
        }
        return parsed
    }
}

public enum ICMPv4 {
    public enum UnreachableCode: UInt8, Sendable {
        case network = 0
        case host = 1
        case protocolUnreachable = 2
        case port = 3
        case fragmentationNeeded = 4
    }

    /// Mirror an echo request back. RFC 792 requires the payload be returned
    /// verbatim: `ping` uses it to carry a timestamp and measure RTT.
    public static func echoReply(to request: ICMPv4Header, payload: ByteBuffer, allocator: ByteBufferAllocator) -> ByteBuffer {
        var message = allocator.buffer(capacity: ICMPv4Header.length + payload.readableBytes)
        message.writeInteger(ICMPv4Type.echoReply.rawValue)
        message.writeInteger(UInt8(0))
        message.writeInteger(UInt16(0), endianness: .big)
        message.writeInteger(request.identifier ?? 0, endianness: .big)
        message.writeInteger(request.sequence ?? 0, endianness: .big)
        message.writeImmutableBuffer(payload)
        finalize(&message)
        return message
    }

    public static func destinationUnreachable(
        code: UnreachableCode, quoting header: IPv4Header, quotedPayload: ByteBuffer, allocator: ByteBufferAllocator
    ) -> ByteBuffer {
        error(type: .destinationUnreachable, code: code.rawValue, unusedWord: 0, quoting: header, quotedPayload: quotedPayload, allocator: allocator)
    }

    /// Destination unreachable, code 4, carrying the MTU that would have fit.
    /// This is the message path MTU discovery runs on.
    public static func fragmentationNeeded(
        nextHopMTU: UInt16, quoting header: IPv4Header, quotedPayload: ByteBuffer, allocator: ByteBufferAllocator
    ) -> ByteBuffer {
        error(
            type: .destinationUnreachable, code: UnreachableCode.fragmentationNeeded.rawValue,
            unusedWord: UInt32(nextHopMTU), quoting: header, quotedPayload: quotedPayload, allocator: allocator)
    }

    public static func timeExceeded(quoting header: IPv4Header, quotedPayload: ByteBuffer, allocator: ByteBufferAllocator) -> ByteBuffer {
        error(type: .timeExceeded, code: 0, unusedWord: 0, quoting: header, quotedPayload: quotedPayload, allocator: allocator)
    }

    /// RFC 792: an error quotes the offending IP header plus the first eight
    /// bytes of its payload. Those eight bytes are what let the far end match
    /// the error to a socket — for TCP and UDP they hold both port numbers.
    /// If the offending payload is shorter than eight bytes, whatever there
    /// is gets quoted; there is nothing else to quote.
    ///
    /// The quoted header declares the ORIGINAL packet's length while carrying
    /// only its first eight payload bytes. That is what RFC 792 requires, and
    /// it means `IPv4Header.parse` will refuse to re-parse it — correctly, since
    /// on live ingress a header claiming more bytes than are present is
    /// truncated or hostile. A consumer that needs to read a quoted header
    /// (path MTU discovery is the first) will need a parse path that trusts the
    /// declared length instead of checking it against what is attached.
    private static func error(
        type: ICMPv4Type, code: UInt8, unusedWord: UInt32,
        quoting header: IPv4Header, quotedPayload: ByteBuffer, allocator: ByteBufferAllocator
    ) -> ByteBuffer {
        var quoted = quotedPayload
        let quotedBytes = quoted.readSlice(length: min(8, quoted.readableBytes)) ?? allocator.buffer(capacity: 0)

        // Re-emit the offending header exactly as given, aside from the
        // options-stripping `prepend(to:)` always does now. The receiver
        // matches the quote on addresses and the transport ports that
        // follow, so it must reflect what was actually on the wire. Only
        // eight bytes of payload are quoted below, so `packet.readableBytes`
        // at prepend time is not the original length — declare the real
        // `totalLength` explicitly, since RFC 1191 path MTU discovery reads
        // it to identify the packet that was too large.
        var reQuoted = PacketBuffer(allocator: allocator, payload: quotedBytes)
        header.prepend(to: &reQuoted, declaringTotalLength: header.totalLength)

        var message = allocator.buffer(capacity: ICMPv4Header.length + reQuoted.readableBytes)
        message.writeInteger(type.rawValue)
        message.writeInteger(code)
        message.writeInteger(UInt16(0), endianness: .big)
        message.writeInteger(unusedWord, endianness: .big)
        message.writeImmutableBuffer(reQuoted.frame)
        finalize(&message)
        return message
    }

    /// The checksum covers the whole message — header and payload — with no
    /// pseudo-header, unlike TCP/UDP. `message` is always a buffer this
    /// module just allocated, whose reader index is 0, but the offset is
    /// computed relative to `readerIndex` rather than hardcoded so it stays
    /// correct if that ever changes.
    private static func finalize(_ message: inout ByteBuffer) {
        let checksum = message.withUnsafeReadableBytes { Checksum.compute($0) }
        message.setInteger(checksum, at: message.readerIndex + 2, endianness: .big)
    }
}
