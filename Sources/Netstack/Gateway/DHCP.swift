import NIOCore

/// A BOOTP/DHCP message, as far as this gateway needs one.
///
/// RFC 2131's fixed header is 236 bytes, then a four-byte magic cookie, then
/// options terminated by 255. Everything a server has to answer is in the
/// options, and every one of them is guest-supplied, so parsing them is the part
/// worth being careful about.
struct DHCPMessage: Equatable {
    enum Operation: UInt8 {
        case request = 1
        case reply = 2
    }

    /// RFC 2132 §9.6's message types, restricted to the ones a server sees or
    /// sends. A type this does not name is not an error -- it is a message for
    /// somebody else -- so parsing keeps the raw value.
    enum MessageType: UInt8, Equatable {
        case discover = 1
        case offer = 2
        case request = 3
        case decline = 4
        case ack = 5
        case nak = 6
        case release = 7
        case inform = 8
    }

    var operation: Operation
    var transaction: UInt32
    var flags: UInt16
    var clientAddress: IPv4Address
    var yourAddress: IPv4Address
    var serverAddress: IPv4Address
    var clientHardwareAddress: MACAddress
    var messageType: MessageType?
    /// Option 50, the address a client is asking to keep.
    var requestedAddress: IPv4Address?
    /// Option 54, which server the client is talking to. A REQUEST naming
    /// another server is one this gateway must stay out of.
    var serverIdentifier: IPv4Address?

    static let cookie: [UInt8] = [99, 130, 83, 99]
    static let fixedLength = 236

    /// The largest options area this parser will walk.
    ///
    /// Not a limit the RFC states -- it states none -- and that is why one is
    /// here. Options are a length-prefixed chain inside a guest-supplied
    /// datagram, so without a bound the walk is over whatever the guest sent,
    /// and the only thing stopping it is the datagram's own size. That is a
    /// bound, but it is the guest's to choose; this one is not.
    static let maximumOptionBytes = 1024
}

enum DHCPCodec {
    /// Parse a client message. Returns nil for anything that is not one --
    /// truncated, not BOOTP, or without the magic cookie.
    ///
    /// **Nil rather than throwing, and nil rather than a partial message.** This
    /// is the first thing a guest reaches on UDP 67, and every ill-formed
    /// datagram it can construct has to end the same way: dropped, with nothing
    /// allocated and nothing remembered.
    static func parse(_ buffer: ByteBuffer) -> DHCPMessage? {
        var buffer = buffer
        guard buffer.readableBytes >= DHCPMessage.fixedLength + 4 else { return nil }
        guard let op = buffer.readInteger(as: UInt8.self), let operation = DHCPMessage.Operation(rawValue: op)
        else { return nil }
        // htype, hlen, hops.
        guard let hardwareType = buffer.readInteger(as: UInt8.self),
            let hardwareLength = buffer.readInteger(as: UInt8.self),
            buffer.readInteger(as: UInt8.self) != nil
        else { return nil }
        // Ethernet, six bytes. A client claiming another hardware type is not
        // one this gateway can answer, and guessing would put a wrong address in
        // the lease table under a key nothing will match again.
        guard hardwareType == 1, hardwareLength == 6 else { return nil }

        guard let transaction = buffer.readInteger(endianness: .big, as: UInt32.self),
            buffer.readInteger(endianness: .big, as: UInt16.self) != nil,  // secs
            let flags = buffer.readInteger(endianness: .big, as: UInt16.self)
        else { return nil }

        guard let ciaddr = readAddress(&buffer), let yiaddr = readAddress(&buffer),
            let siaddr = readAddress(&buffer), readAddress(&buffer) != nil  // giaddr
        else { return nil }

        guard let chaddrBytes = buffer.readBytes(length: 16),
            let hardware = MACAddress(bytes: Array(chaddrBytes.prefix(6)))
        else { return nil }
        // sname and file, which this gateway neither reads nor sets.
        guard buffer.readSlice(length: 64) != nil, buffer.readSlice(length: 128) != nil else { return nil }
        guard let cookie = buffer.readBytes(length: 4), cookie == DHCPMessage.cookie else { return nil }

        var message = DHCPMessage(
            operation: operation, transaction: transaction, flags: flags, clientAddress: ciaddr,
            yourAddress: yiaddr, serverAddress: siaddr, clientHardwareAddress: hardware,
            messageType: nil, requestedAddress: nil, serverIdentifier: nil)

        var walked = 0
        while buffer.readableBytes > 0, walked < DHCPMessage.maximumOptionBytes {
            guard let code = buffer.readInteger(as: UInt8.self) else { break }
            walked += 1
            if code == 255 { break }  // end
            if code == 0 { continue }  // pad, no length byte
            guard let length = buffer.readInteger(as: UInt8.self) else { break }
            walked += 1 + Int(length)
            guard var value = buffer.readSlice(length: Int(length)) else { break }
            switch code {
            case 53:
                if let raw = value.readInteger(as: UInt8.self) {
                    message.messageType = DHCPMessage.MessageType(rawValue: raw)
                }
            case 50:
                if length == 4 { message.requestedAddress = readAddress(&value) }
            case 54:
                if length == 4 { message.serverIdentifier = readAddress(&value) }
            default:
                break
            }
        }
        return message
    }

    /// Build a server reply. `options` are appended in order, then the end
    /// marker, then padding to BOOTP's minimum length.
    static func serialize(
        _ message: DHCPMessage, options: [(code: UInt8, value: [UInt8])], allocator: ByteBufferAllocator
    ) -> ByteBuffer {
        var buffer = allocator.buffer(capacity: 512)
        buffer.writeInteger(message.operation.rawValue)
        buffer.writeInteger(UInt8(1))  // ethernet
        buffer.writeInteger(UInt8(6))
        buffer.writeInteger(UInt8(0))  // hops
        buffer.writeInteger(message.transaction, endianness: .big)
        buffer.writeInteger(UInt16(0), endianness: .big)  // secs
        buffer.writeInteger(message.flags, endianness: .big)
        buffer.writeBytes(message.clientAddress.bytes)
        buffer.writeBytes(message.yourAddress.bytes)
        buffer.writeBytes(message.serverAddress.bytes)
        buffer.writeBytes([0, 0, 0, 0])  // giaddr
        buffer.writeBytes(message.clientHardwareAddress.bytes)
        buffer.writeBytes([UInt8](repeating: 0, count: 10))  // chaddr padding
        buffer.writeBytes([UInt8](repeating: 0, count: 64))  // sname
        buffer.writeBytes([UInt8](repeating: 0, count: 128))  // file
        buffer.writeBytes(DHCPMessage.cookie)
        for option in options {
            buffer.writeInteger(option.code)
            buffer.writeInteger(UInt8(option.value.count))
            buffer.writeBytes(option.value)
        }
        buffer.writeInteger(UInt8(255))
        // RFC 951's minimum message size. Some clients discard anything shorter,
        // and the padding costs nothing.
        while buffer.readableBytes < 300 { buffer.writeInteger(UInt8(0)) }
        return buffer
    }

    private static func readAddress(_ buffer: inout ByteBuffer) -> IPv4Address? {
        guard let bytes = buffer.readBytes(length: 4) else { return nil }
        return IPv4Address(bytes[0], bytes[1], bytes[2], bytes[3])
    }
}
