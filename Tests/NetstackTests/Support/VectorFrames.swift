import NIOCore

@testable import Netstack

/// Errors `VectorFrames.encode` can throw building a wire frame from a
/// `VectorPacket` that does not describe one.
enum VectorFrameError: Error, Equatable {
    case unrecognizedTCPFlag(Character)
    case malformedTCPOption(String)
    case udpPayloadTooLarge
    case unknownICMPUnreachableCode(String)
}

/// Turns a `VectorPacket` into real wire bytes, and back.
///
/// This is a *second*, independent implementation of TCP-on-the-wire,
/// deliberately not built on `TCPHeader` (Task 7). The point of this whole
/// instrument is to compare an emitter against a parser that do not share an
/// assumption — Plan 1 shipped a defect pair that survived exactly because
/// its emitter and its parser agreed with each other. So: no extraction, no
/// shared helper with `TCPHeader`, even where the two would clearly overlap
/// (the pseudo-header sum, the flag bits, the option encoding). Every other
/// protocol here — Ethernet, IPv4, UDP, ICMP, ARP — already has exactly one
/// production implementation in `Sources/Netstack`, and this codec uses it
/// directly; TCP is the only place a second implementation belongs.
struct VectorFrames {
    private let gateway: IPv4Address
    private let gatewayMAC: MACAddress
    private let guest: IPv4Address
    private let guestMAC: MACAddress
    private let allocator = ByteBufferAllocator()

    /// `TCPLine` carries no port fields — a packetdrill-style vector
    /// describes one connection already in progress, and the port pair is
    /// never the thing under test — so any fixed, consistent pair works
    /// here. `decode` never reads these back, since `VectorPacket.tcp` has
    /// nowhere to put them.
    private static let tcpSourcePort: UInt16 = 50000
    private static let tcpDestinationPort: UInt16 = 8080

    init(gateway: IPv4Address, gatewayMAC: MACAddress, guest: IPv4Address, guestMAC: MACAddress) {
        self.gateway = gateway
        self.gatewayMAC = gatewayMAC
        self.guest = guest
        self.guestMAC = guestMAC
    }

    private struct Addresses {
        let source: IPv4Address
        let destination: IPv4Address
        let sourceMAC: MACAddress
        let destinationMAC: MACAddress
    }

    /// `.inbound` is guest -> gateway (a frame delivered to the stack);
    /// `.expectedOutbound` is gateway -> guest (a frame the stack must emit).
    private func addresses(for direction: VectorDirection) -> Addresses {
        switch direction {
        case .inbound:
            return Addresses(source: guest, destination: gateway, sourceMAC: guestMAC, destinationMAC: gatewayMAC)
        case .expectedOutbound:
            return Addresses(source: gateway, destination: guest, sourceMAC: gatewayMAC, destinationMAC: guestMAC)
        }
    }

    // MARK: - Encode

    func encode(_ packet: VectorPacket, direction: VectorDirection) throws -> ByteBuffer {
        let addr = addresses(for: direction)

        switch packet {
        case .arpRequest(let target, let sender):
            let arp = ARPPacket(
                operation: .request, senderMAC: addr.sourceMAC, senderIP: sender,
                targetMAC: MACAddress(bytes: [0, 0, 0, 0, 0, 0])!, targetIP: target)
            var frame = arp.serialize(into: allocator)
            EthernetHeader(destination: MACAddress.broadcast, source: addr.sourceMAC, etherType: .arp).prepend(to: &frame)
            return frame.frame

        case .arpReply(let address, let mac):
            let arp = ARPPacket(
                operation: .reply, senderMAC: mac, senderIP: address,
                targetMAC: addr.destinationMAC, targetIP: addr.destination)
            var frame = arp.serialize(into: allocator)
            EthernetHeader(destination: addr.destinationMAC, source: mac, etherType: .arp).prepend(to: &frame)
            return frame.frame

        default:
            let (transportBytes, protocolNumber) = try encodeIPv4Payload(packet, addr: addr)
            var frame = PacketBuffer(allocator: allocator, payload: transportBytes)
            IPv4Header(source: addr.source, destination: addr.destination, protocolNumber: protocolNumber, payloadLength: transportBytes.readableBytes)
                .prepend(to: &frame)
            EthernetHeader(destination: addr.destinationMAC, source: addr.sourceMAC, etherType: .ipv4).prepend(to: &frame)
            return frame.frame
        }
    }

    private func encodeIPv4Payload(_ packet: VectorPacket, addr: Addresses) throws -> (ByteBuffer, IPProtocol) {
        switch packet {
        case .tcp(let line):
            return (try encodeTCP(line, source: addr.source, destination: addr.destination), .tcp)

        case .udp(let sourcePort, let destinationPort, let length):
            var payload = allocator.buffer(capacity: length)
            payload.writeRepeatingByte(0, count: length)
            guard
                let datagram = UDPHeader.serialize(
                    payload: payload, source: addr.source, destination: addr.destination,
                    sourcePort: sourcePort, destinationPort: destinationPort, allocator: allocator)
            else { throw VectorFrameError.udpPayloadTooLarge }
            return (datagram, .udp)

        case .icmpEcho(let request, let identifier, let sequence):
            if request {
                return (encodeICMPEchoRequest(identifier: identifier, sequence: sequence), .icmp)
            }
            let requestHeader = ICMPv4Header(type: .echoRequest, code: 0, identifier: identifier, sequence: sequence)
            return (ICMPv4.echoReply(to: requestHeader, payload: allocator.buffer(capacity: 0), allocator: allocator), .icmp)

        case .icmpUnreachable(let code):
            guard let unreachableCode = Self.unreachableCode(named: code) else {
                throw VectorFrameError.unknownICMPUnreachableCode(code)
            }
            // The message must quote *some* offending IPv4 header; nothing in
            // `VectorPacket.icmpUnreachable` names the packet that provoked
            // it (only the code string), so this quotes a small synthetic
            // UDP packet. `decode` never inspects the quote for this case.
            let quotedHeader = IPv4Header(source: addr.destination, destination: addr.source, protocolNumber: .udp, payloadLength: 8)
            var quotedPayload = allocator.buffer(capacity: 8)
            quotedPayload.writeRepeatingByte(0, count: 8)
            return (
                ICMPv4.destinationUnreachable(code: unreachableCode, quoting: quotedHeader, quotedPayload: quotedPayload, allocator: allocator),
                .icmp
            )

        case .arpRequest, .arpReply:
            preconditionFailure("ARP is handled by encode(_:direction:) directly; it has no IPv4 layer")
        }
    }

    private func encodeICMPEchoRequest(identifier: UInt16, sequence: UInt16) -> ByteBuffer {
        var message = allocator.buffer(capacity: ICMPv4Header.length)
        message.writeInteger(ICMPv4Type.echoRequest.rawValue)
        message.writeInteger(UInt8(0))
        message.writeInteger(UInt16(0), endianness: .big)
        message.writeInteger(identifier, endianness: .big)
        message.writeInteger(sequence, endianness: .big)
        let checksum = message.withUnsafeReadableBytes { Checksum.compute($0) }
        message.setInteger(checksum, at: message.readerIndex + 2, endianness: .big)
        return message
    }

    private static let unreachableCodeNames: [(ICMPv4.UnreachableCode, String)] = [
        (.network, "network"),
        (.host, "host"),
        (.protocolUnreachable, "protocol"),
        (.port, "port"),
        (.fragmentationNeeded, "frag-needed"),
    ]

    private static func unreachableCode(named name: String) -> ICMPv4.UnreachableCode? {
        unreachableCodeNames.first { $0.1 == name }?.0
    }

    private static func unreachableCodeName(for code: UInt8) -> String? {
        unreachableCodeNames.first { $0.0.rawValue == code }?.1
    }

    // MARK: - TCP (hand-rolled; see the type doc comment for why)

    /// FIN/SYN/RST/PSH/ACK/URG/ECE/CWR, in wire-bit order. `.` stands for ACK,
    /// to match `TCPLine.flags`'s packetdrill-shaped notation ("S." is
    /// SYN+ACK); `E` and `W` are packetdrill's letters for the two ECN
    /// negotiation bits (RFC 3168 §6.1.1), which `TCPFlags` deliberately does
    /// not name but `TCPHeader.parse` carries through regardless. They are
    /// here so a vector can state that an ECN-setup SYN is treated as an
    /// ordinary SYN — a claim no dispatch on flag equality would satisfy, and
    /// one that cannot be written at all without a way to set the bits.
    private static let tcpFlagBits: [(Character, UInt8)] = [
        ("F", 0x01), ("S", 0x02), ("R", 0x04), ("P", 0x08), (".", 0x10), ("U", 0x20), ("E", 0x40), ("W", 0x80),
    ]

    /// The sum over the IPv4 pseudo-header: source, destination, a zero
    /// byte, protocol 6, and the TCP length. Same shape as
    /// `UDPHeader.pseudoHeaderSum` for protocol 17 — deliberately not
    /// shared with it or with `TCPHeader`'s own copy (Task 7); see the type
    /// doc comment.
    private func tcpPseudoHeaderSum(source: IPv4Address, destination: IPv4Address, length: UInt16) -> UInt32 {
        var sum: UInt32 = 0
        sum += UInt32(source.raw >> 16) + UInt32(source.raw & 0xffff)
        sum += UInt32(destination.raw >> 16) + UInt32(destination.raw & 0xffff)
        sum += UInt32(IPProtocol.tcp.rawValue)
        sum += UInt32(length)
        return sum
    }

    private func encodeTCP(_ line: TCPLine, source: IPv4Address, destination: IPv4Address) throws -> ByteBuffer {
        var flagsByte: UInt8 = 0
        for character in line.flags {
            guard let bit = Self.tcpFlagBits.first(where: { $0.0 == character })?.1 else {
                throw VectorFrameError.unrecognizedTCPFlag(character)
            }
            flagsByte |= bit
        }

        let optionBytes = try Self.encodeTCPOptions(line.options)
        let dataOffsetWords = (20 + optionBytes.count) / 4

        var payload = allocator.buffer(capacity: line.payloadLength)
        payload.writeRepeatingByte(0, count: line.payloadLength)

        var segment = allocator.buffer(capacity: dataOffsetWords * 4 + payload.readableBytes)
        segment.writeInteger(Self.tcpSourcePort, endianness: .big)
        segment.writeInteger(Self.tcpDestinationPort, endianness: .big)
        segment.writeInteger(line.seqStart, endianness: .big)
        segment.writeInteger(line.ack ?? 0, endianness: .big)
        segment.writeInteger(UInt16(dataOffsetWords) << 12 | UInt16(flagsByte), endianness: .big)
        segment.writeInteger(line.window ?? 0, endianness: .big)
        segment.writeInteger(UInt16(0), endianness: .big)  // checksum, filled below
        segment.writeInteger(UInt16(0), endianness: .big)  // urgent pointer
        segment.writeBytes(optionBytes)
        segment.writeImmutableBuffer(payload)

        let pseudo = tcpPseudoHeaderSum(source: source, destination: destination, length: UInt16(segment.readableBytes))
        let sum = segment.withUnsafeReadableBytes { Checksum.partial($0, initial: pseudo) }
        segment.setInteger(Checksum.complete(sum), at: segment.readerIndex + 16, endianness: .big)
        return segment
    }

    /// MSS: kind 2, length 4, `"mss <value>"`. Window scale: kind 3, length
    /// 3, `"wscale <shift>"`. SACK-permitted: kind 4, length 2, `"sackOK"`.
    /// Timestamps: kind 8, length 10, `"timestamp <value> <echo>"` — not
    /// exercised by any vector in this task, but implemented for symmetry
    /// with `decodeTCPOptions` and because Task 7 expects the codec to be
    /// able to emit it. Padded with NOP (kind 1) to a 4-byte boundary.
    private static func encodeTCPOptions(_ options: [String]) throws -> [UInt8] {
        var bytes: [UInt8] = []
        for option in options {
            let parts = option.split(separator: " ").map(String.init)
            switch parts.first {
            case "mss":
                guard parts.count == 2, let value = UInt16(parts[1]) else { throw VectorFrameError.malformedTCPOption(option) }
                bytes += [2, 4, UInt8(value >> 8), UInt8(value & 0xff)]
            case "wscale":
                guard parts.count == 2, let shift = UInt8(parts[1]) else { throw VectorFrameError.malformedTCPOption(option) }
                bytes += [3, 3, shift]
            case "sackOK":
                guard parts.count == 1 else { throw VectorFrameError.malformedTCPOption(option) }
                bytes += [4, 2]
            case "timestamp":
                guard parts.count == 3, let value = UInt32(parts[1]), let echo = UInt32(parts[2]) else {
                    throw VectorFrameError.malformedTCPOption(option)
                }
                bytes += [8, 10]
                bytes += [UInt8(value >> 24), UInt8((value >> 16) & 0xff), UInt8((value >> 8) & 0xff), UInt8(value & 0xff)]
                bytes += [UInt8(echo >> 24), UInt8((echo >> 16) & 0xff), UInt8((echo >> 8) & 0xff), UInt8(echo & 0xff)]
            default:
                throw VectorFrameError.malformedTCPOption(option)
            }
        }
        while bytes.count % 4 != 0 {
            bytes.append(1)  // NOP
        }
        return bytes
    }

    // MARK: - Decode

    func decode(_ frame: ByteBuffer) -> VectorPacket? {
        var packet = PacketBuffer(received: frame)
        guard let ethernet = EthernetHeader.parse(&packet) else { return nil }

        switch ethernet.etherType {
        case .arp:
            guard let arp = ARPPacket.parse(&packet) else { return nil }
            switch arp.operation {
            case .request: return .arpRequest(target: arp.targetIP, sender: arp.senderIP)
            case .reply: return .arpReply(address: arp.senderIP, mac: arp.senderMAC)
            }

        case .ipv4:
            guard let ip = IPv4Header.parse(&packet) else { return nil }
            switch ip.protocolNumber {
            case .tcp:
                return decodeTCP(packet.payload, header: ip)

            case .udp:
                guard let udp = UDPHeader.parse(&packet, header: ip) else { return nil }
                // `udp.length` is header-plus-payload on the wire; `VectorPacket.udp`'s
                // `length` field is payload only (see `VectorScript.parseUDP`'s comment).
                return .udp(source: udp.sourcePort, destination: udp.destinationPort, length: Int(udp.length) - UDPHeader.length)

            case .icmp:
                guard let icmp = ICMPv4Header.parse(&packet) else { return nil }
                switch icmp.type {
                case .echoRequest: return .icmpEcho(request: true, identifier: icmp.identifier ?? 0, sequence: icmp.sequence ?? 0)
                case .echoReply: return .icmpEcho(request: false, identifier: icmp.identifier ?? 0, sequence: icmp.sequence ?? 0)
                case .destinationUnreachable:
                    guard let name = Self.unreachableCodeName(for: icmp.code) else { return nil }
                    return .icmpUnreachable(code: name)
                default:
                    return nil
                }

            default:
                return nil
            }

        default:
            return nil
        }
    }

    private func decodeTCP(_ segment: ByteBuffer, header: IPv4Header) -> VectorPacket? {
        guard segment.readableBytes >= 20 else { return nil }

        let pseudo = tcpPseudoHeaderSum(source: header.source, destination: header.destination, length: UInt16(segment.readableBytes))
        let sum = segment.withUnsafeReadableBytes { Checksum.partial($0, initial: pseudo) }
        guard Checksum.complete(sum) == 0 else { return nil }

        var buffer = segment
        guard
            buffer.readInteger(endianness: .big, as: UInt16.self) != nil,  // source port
            buffer.readInteger(endianness: .big, as: UInt16.self) != nil,  // destination port
            let sequence = buffer.readInteger(endianness: .big, as: UInt32.self),
            let acknowledgement = buffer.readInteger(endianness: .big, as: UInt32.self),
            let offsetAndFlags = buffer.readInteger(endianness: .big, as: UInt16.self),
            let window = buffer.readInteger(endianness: .big, as: UInt16.self),
            buffer.readInteger(endianness: .big, as: UInt16.self) != nil,  // checksum, already verified
            buffer.readInteger(endianness: .big, as: UInt16.self) != nil  // urgent pointer
        else { return nil }

        let dataOffsetWords = Int(offsetAndFlags >> 12)
        let headerLength = dataOffsetWords * 4
        guard dataOffsetWords >= 5, headerLength <= segment.readableBytes else { return nil }

        guard let optionBytes = buffer.readSlice(length: headerLength - 20) else { return nil }
        guard let options = Self.decodeTCPOptions(optionBytes) else { return nil }

        let flagsByte = UInt8(truncatingIfNeeded: offsetAndFlags)
        let hasAck = flagsByte & 0x10 != 0
        let payloadLength = buffer.readableBytes

        return .tcp(
            TCPLine(
                flags: Self.decodeTCPFlags(flagsByte),
                seqStart: sequence,
                seqEnd: sequence &+ UInt32(payloadLength),
                payloadLength: payloadLength,
                ack: hasAck ? acknowledgement : nil,
                window: window,
                options: options))
    }

    /// Inverse of the loop in `encodeTCP`: characters in wire-bit order,
    /// ACK ('.') last, matching packetdrill's convention ("S.", not ".S").
    private static func decodeTCPFlags(_ byte: UInt8) -> String {
        var result = ""
        for (character, bit) in tcpFlagBits where character != "." {
            if byte & bit != 0 { result.append(character) }
        }
        if byte & 0x10 != 0 { result.append(".") }
        return result
    }

    /// Inverse of `encodeTCPOptions`. Guards against a zero-length option
    /// the way the loop it mirrors in Task 7's `TCPHeader.parse` must: an
    /// option kind is followed by a length byte covering itself, so a
    /// declared length below 2 can never be advanced past — looping forever
    /// on it is a real hang, not merely a wrong answer.
    private static func decodeTCPOptions(_ optionBytes: ByteBuffer) -> [String]? {
        var buffer = optionBytes
        var options: [String] = []
        while buffer.readableBytes > 0 {
            guard let kind = buffer.readInteger(as: UInt8.self) else { return nil }
            if kind == 0 { break }  // end of option list
            if kind == 1 { continue }  // NOP

            guard let length = buffer.readInteger(as: UInt8.self), length >= 2 else { return nil }
            let valueLength = Int(length) - 2
            guard valueLength <= buffer.readableBytes else { return nil }

            switch kind {
            case 2:
                guard valueLength == 2, let value = buffer.readInteger(endianness: .big, as: UInt16.self) else { return nil }
                options.append("mss \(value)")
            case 3:
                guard valueLength == 1, let shift = buffer.readInteger(as: UInt8.self) else { return nil }
                options.append("wscale \(shift)")
            case 4:
                guard valueLength == 0 else { return nil }
                options.append("sackOK")
            case 8:
                guard valueLength == 8, let value = buffer.readInteger(endianness: .big, as: UInt32.self),
                    let echo = buffer.readInteger(endianness: .big, as: UInt32.self)
                else { return nil }
                options.append("timestamp \(value) \(echo)")
            default:
                guard buffer.readSlice(length: valueLength) != nil else { return nil }
            }
        }
        return options
    }
}
