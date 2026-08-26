import Foundation
import NIOCore

@testable import Netstack

enum VectorDirection: Equatable {
    /// A frame delivered TO the stack.
    case inbound
    /// A frame the stack is required to emit.
    case expectedOutbound
}

struct TCPLine: Equatable {
    var flags: String
    var seqStart: UInt32
    var seqEnd: UInt32
    var payloadLength: Int
    var ack: UInt32?
    var window: UInt16?
    var options: [String]
}

enum VectorPacket: Equatable {
    case tcp(TCPLine)
    case icmpEcho(request: Bool, identifier: UInt16, sequence: UInt16)
    case icmpUnreachable(code: String)
    case udp(source: UInt16, destination: UInt16, length: Int)
    case arpRequest(target: IPv4Address, sender: IPv4Address)
    case arpReply(address: IPv4Address, mac: MACAddress)
}

struct VectorEvent: Equatable {
    var time: TimeAmount
    var direction: VectorDirection
    var packet: VectorPacket
}

enum VectorScriptError: Error, Equatable {
    case malformedLine(String)
    case malformedTime(String)
    case malformedSequence(String)
    case unknownPacketForm(String)
}

/// A packetdrill-shaped script.
///
/// `<` is a frame delivered to the stack; `>` is a frame the stack must emit.
/// Time is logical and drives a `ManualClock`, so nothing here races a wall
/// clock. The point of the format is that a vector states the expected wire
/// behaviour independently of the implementation that produces it.
struct VectorScript {
    var events: [VectorEvent]

    static func parse(_ text: String) throws -> VectorScript {
        var events: [VectorEvent] = []
        for rawLine in text.split(separator: "\n", omittingEmptySubsequences: false) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("#") { continue }
            events.append(try parseLine(line))
        }
        return VectorScript(events: events)
    }

    private static func parseLine(_ line: String) throws -> VectorEvent {
        var fields = line.split(separator: " ", omittingEmptySubsequences: true).map(String.init)
        guard fields.count >= 3 else { throw VectorScriptError.malformedLine(line) }

        let timeField = fields.removeFirst()
        guard let seconds = Double(timeField) else { throw VectorScriptError.malformedTime(line) }
        let time = TimeAmount.nanoseconds(Int64((seconds * 1_000_000_000).rounded()))

        let direction: VectorDirection
        switch fields.removeFirst() {
        case "<": direction = .inbound
        case ">": direction = .expectedOutbound
        default: throw VectorScriptError.malformedLine(line)
        }

        return VectorEvent(time: time, direction: direction, packet: try parsePacket(fields, line: line))
    }

    private static func parsePacket(_ fields: [String], line: String) throws -> VectorPacket {
        switch fields.first {
        case "arp": return try parseARP(fields, line: line)
        case "icmp": return try parseICMP(fields, line: line)
        case "udp": return try parseUDP(fields, line: line)
        default: return .tcp(try parseTCP(fields, line: line))
        }
    }

    private static func parseARP(_ fields: [String], line: String) throws -> VectorPacket {
        // arp who-has <target> tell <sender>   |   arp reply <addr> is-at <mac>
        if fields.count == 5, fields[1] == "who-has", fields[3] == "tell",
            let target = IPv4Address(fields[2]), let sender = IPv4Address(fields[4]) {
            return .arpRequest(target: target, sender: sender)
        }
        if fields.count == 5, fields[1] == "reply", fields[3] == "is-at",
            let address = IPv4Address(fields[2]), let mac = MACAddress(fields[4]) {
            return .arpReply(address: address, mac: mac)
        }
        throw VectorScriptError.unknownPacketForm(line)
    }

    private static func parseICMP(_ fields: [String], line: String) throws -> VectorPacket {
        // icmp echo_request id <n> seq <n>   |   icmp unreachable <code>
        if fields.count == 6, fields[2] == "id", fields[4] == "seq",
            let identifier = UInt16(fields[3]), let sequence = UInt16(fields[5]) {
            switch fields[1] {
            case "echo_request": return .icmpEcho(request: true, identifier: identifier, sequence: sequence)
            case "echo_reply": return .icmpEcho(request: false, identifier: identifier, sequence: sequence)
            default: throw VectorScriptError.unknownPacketForm(line)
            }
        }
        if fields.count == 3, fields[1] == "unreachable" {
            return .icmpUnreachable(code: fields[2])
        }
        throw VectorScriptError.unknownPacketForm(line)
    }

    private static func parseUDP(_ fields: [String], line: String) throws -> VectorPacket {
        // udp <sport> > <dport> (<payloadLength>)
        guard fields.count == 5, fields[2] == ">",
            let source = UInt16(fields[1]), let destination = UInt16(fields[3]),
            fields[4].hasPrefix("("), fields[4].hasSuffix(")"),
            let length = Int(fields[4].dropFirst().dropLast())
        else { throw VectorScriptError.unknownPacketForm(line) }
        return .udp(source: source, destination: destination, length: length)
    }

    private static func parseTCP(_ fields: [String], line: String) throws -> TCPLine {
        // <flags> <start>:<end>(<len>) [ack <n>] [win <n>] [<opt,opt>]
        var fields = fields
        guard fields.count >= 2 else { throw VectorScriptError.malformedLine(line) }
        let flags = fields.removeFirst()

        let sequence = fields.removeFirst()
        guard let colon = sequence.firstIndex(of: ":"),
            let openParen = sequence.firstIndex(of: "("), sequence.hasSuffix(")"),
            let start = UInt32(sequence[sequence.startIndex..<colon]),
            let end = UInt32(sequence[sequence.index(after: colon)..<openParen]),
            let length = Int(sequence[sequence.index(after: openParen)..<sequence.index(before: sequence.endIndex)])
        else { throw VectorScriptError.malformedSequence(line) }

        var ack: UInt32?
        var window: UInt16?
        var options: [String] = []
        var index = 0
        while index < fields.count {
            let field = fields[index]
            if field == "ack", index + 1 < fields.count {
                ack = UInt32(fields[index + 1]); index += 2
            } else if field == "win", index + 1 < fields.count {
                window = UInt16(fields[index + 1]); index += 2
            } else if field.hasPrefix("<") {
                // Options may contain spaces ("mss 1460"), so rejoin to the ">".
                // This loop is bounded by `fields.count` on every iteration, so it
                // cannot spin forever or read out of bounds. But an input that never
                // supplies the closing ">" (e.g. "<mss 1460" with nothing after it)
                // must not be treated as a valid option list: dropLast() would then
                // strip a real content character instead of the missing bracket,
                // silently corrupting the option instead of failing loudly.
                var joined = field
                while !joined.hasSuffix(">"), index + 1 < fields.count {
                    index += 1
                    joined += " " + fields[index]
                }
                guard joined.hasSuffix(">") else {
                    throw VectorScriptError.malformedLine(line)
                }
                options = joined.dropFirst().dropLast()
                    .split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
                index += 1
            } else {
                throw VectorScriptError.unknownPacketForm(line)
            }
        }

        return TCPLine(flags: flags, seqStart: start, seqEnd: end, payloadLength: length,
                       ack: ack, window: window, options: options)
    }
}
