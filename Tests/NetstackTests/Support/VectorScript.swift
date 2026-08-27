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

/// What one script line is about.
///
/// Six of these are frames. The last two are not: they are calls the local
/// APPLICATION makes, and they are here because a send-side vector cannot be
/// written without them. A packetdrill script interleaves system calls with
/// packets for exactly this reason — "the application wrote 100 bytes here,
/// and *this* is what appeared on the wire" is a statement about the stack
/// that no sequence of packets alone can make. Without them a vector for a
/// retransmission, a zero window or a local close would have to smuggle the
/// call into the harness, where its position in the script (and therefore in
/// logical time) would be invisible to a reader of the `.vec` file.
///
/// They are `.inbound` lines — something entering the stack, from above rather
/// than off the wire — and `VectorScript.parse` rejects them in the `>`
/// direction, where they would mean nothing. `VectorFrames.encode` refuses
/// them outright: they have no wire representation, and a runner that tried to
/// build one must fail loudly rather than emit a frame the script never asked
/// for.
enum VectorPacket: Equatable {
    case tcp(TCPLine)
    case icmpEcho(request: Bool, identifier: UInt16, sequence: UInt16)
    case icmpUnreachable(code: String)
    case udp(source: UInt16, destination: UInt16, length: Int)
    case arpRequest(target: IPv4Address, sender: IPv4Address)
    case arpReply(address: IPv4Address, mac: MACAddress)
    /// `write <n>`: the application queues `n` bytes for transmission.
    case applicationWrite(bytes: Int)
    /// `close`: the application closes the endpoint.
    case applicationClose
}

struct VectorEvent: Equatable {
    var time: TimeAmount
    var direction: VectorDirection
    var packet: VectorPacket
    /// The 1-based line this event came from in the original script text,
    /// counting comment and blank lines even though they produce no event —
    /// so this is the number a reader would see in an editor, not the index
    /// into `VectorScript.events`. Diagnostics (`VectorMismatch`) report
    /// this rather than the event index for exactly that reason: the
    /// validation vectors are deliberately comment-heavy, so "event 2" and
    /// "line 2" can name entirely different statements.
    var sourceLine: Int
}

enum VectorScriptError: Error, Equatable {
    case malformedLine(String)
    case malformedTime(String)
    case malformedSequence(String)
    case malformedField(String)
    case unknownPacketForm(String)
}

/// A packetdrill-shaped script.
///
/// `<` is a frame delivered to the stack; `>` is a frame the stack must emit.
/// `<` also carries the two application-call forms — `write <n>` and `close` —
/// which are not frames at all; see `VectorPacket`. Time is logical and drives
/// a `ManualClock`, so nothing here races a wall clock. The point of the format
/// is that a vector states the expected wire behaviour independently of the
/// implementation that produces it.
struct VectorScript {
    var events: [VectorEvent]

    static func parse(_ text: String) throws -> VectorScript {
        var events: [VectorEvent] = []
        // `enumerated()` here is what lets a diverging event be reported by
        // its real position in the file — `split` with
        // `omittingEmptySubsequences: false` keeps blank lines as empty
        // subsequences, so this index (1-based below) lines up with what an
        // editor shows, including comments and blanks that never become an
        // event of their own.
        for (offset, rawLine) in text.split(separator: "\n", omittingEmptySubsequences: false).enumerated() {
            let sourceLine = offset + 1
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("#") { continue }
            events.append(try parseLine(line, sourceLine: sourceLine))
        }
        return VectorScript(events: events)
    }

    private static func parseLine(_ line: String, sourceLine: Int) throws -> VectorEvent {
        var fields = line.split(separator: " ", omittingEmptySubsequences: true).map(String.init)
        guard fields.count >= 3 else { throw VectorScriptError.malformedLine(line) }

        let timeField = fields.removeFirst()
        guard let seconds = Double(timeField), seconds.isFinite, seconds >= 0 else {
            throw VectorScriptError.malformedTime(line)
        }
        // `Int64(Double)` traps rather than returning nil once the value no longer fits, so a
        // malformed vector must never reach it. `Int64(exactly:)` never traps: it returns nil for
        // non-finite, non-integral, or out-of-range values, which is exactly what we want here.
        guard let nanoseconds = Int64(exactly: (seconds * 1_000_000_000).rounded()) else {
            throw VectorScriptError.malformedTime(line)
        }
        let time = TimeAmount.nanoseconds(nanoseconds)

        let direction: VectorDirection
        switch fields.removeFirst() {
        case "<": direction = .inbound
        case ">": direction = .expectedOutbound
        default: throw VectorScriptError.malformedLine(line)
        }

        let packet = try parsePacket(fields, line: line)
        // An application call is something entering the stack from above, so it
        // is written with `<`. In the `>` direction it would be a claim that the
        // stack emits a system call, which is not a thing a script can mean —
        // reject it here rather than let it sit in a file reading as a
        // specification while the runner quietly does whatever it does with it.
        switch packet {
        case .applicationWrite, .applicationClose:
            guard direction == .inbound else { throw VectorScriptError.malformedLine(line) }
        case .tcp, .icmpEcho, .icmpUnreachable, .udp, .arpRequest, .arpReply:
            break
        }

        return VectorEvent(time: time, direction: direction, packet: packet, sourceLine: sourceLine)
    }

    private static func parsePacket(_ fields: [String], line: String) throws -> VectorPacket {
        switch fields.first {
        case "arp": return try parseARP(fields, line: line)
        case "icmp": return try parseICMP(fields, line: line)
        case "udp": return try parseUDP(fields, line: line)
        case "write", "close": return try parseApplicationCall(fields, line: line)
        default: return .tcp(try parseTCP(fields, line: line))
        }
    }

    /// `write <n>` and `close`. See `VectorPacket` for why a packet-only DSL
    /// cannot express a send-side vector at all.
    ///
    /// A zero-byte write is refused rather than accepted as a no-op: `write 0`
    /// in a file reads as "the application wrote", and `Sender.write` treats an
    /// empty buffer as a no-op that succeeds, so the line would sit there
    /// asserting nothing while looking like it asserted something.
    private static func parseApplicationCall(_ fields: [String], line: String) throws -> VectorPacket {
        if fields.count == 1, fields[0] == "close" {
            return .applicationClose
        }
        if fields.count == 2, fields[0] == "write", let bytes = Int(fields[1]), bytes > 0 {
            return .applicationWrite(bytes: bytes)
        }
        throw VectorScriptError.unknownPacketForm(line)
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
        // `Int(...)` alone accepts a negative literal like "(-12)" cleanly; `UInt32(exactly:)`
        // is the same guard the TCP path uses to reject a length that cannot be a real payload
        // size, without giving up the wider `Int` the field is stored as.
        guard fields.count == 5, fields[2] == ">",
            let source = UInt16(fields[1]), let destination = UInt16(fields[3]),
            fields[4].hasPrefix("("), fields[4].hasSuffix(")"),
            let length = Int(fields[4].dropFirst().dropLast()), let declaredLength = UInt32(exactly: length)
        else { throw VectorScriptError.unknownPacketForm(line) }
        return .udp(source: source, destination: destination, length: Int(declaredLength))
    }

    private static func parseTCP(_ fields: [String], line: String) throws -> TCPLine {
        // <flags> <start>:<end>(<len>) [ack <n>] [win <n>] [<opt,opt>]
        var fields = fields
        guard fields.count >= 2 else { throw VectorScriptError.malformedLine(line) }
        let flags = fields.removeFirst()
        // Known flag characters only: S SYN, . ACK, F FIN, R RST, P PSH, U URG, E ECE, W CWR.
        // This is also what stops an unrecognised first token (e.g. a typo'd protocol keyword)
        // from falling through `parsePacket`'s default case and being accepted as a "valid" TCP
        // packet with a garbage flags string.
        //
        // E and W are the two bits `TCPFlags` deliberately does not name, and they are spellable
        // here for one reason: an ECN-setup SYN (SYN with CWR and ECE also set, which Linux sends
        // by default in several configurations) is an ordinary SYN that any dispatch on flag
        // EQUALITY would drop, and a vector that cannot write one cannot say so. The letters are
        // packetdrill's.
        guard !flags.isEmpty, flags.allSatisfy({ "S.FRPUEW".contains($0) }) else {
            throw VectorScriptError.unknownPacketForm(line)
        }

        let sequence = fields.removeFirst()
        guard let colon = sequence.firstIndex(of: ":"),
            let openParen = sequence.firstIndex(of: "("), sequence.hasSuffix(")"),
            let start = UInt32(sequence[sequence.startIndex..<colon]),
            let end = UInt32(sequence[sequence.index(after: colon)..<openParen]),
            let length = Int(sequence[sequence.index(after: openParen)..<sequence.index(before: sequence.endIndex)])
        else { throw VectorScriptError.malformedSequence(line) }
        // The declared length must agree with the range it claims to describe. Sequence numbers
        // wrap at 2^32, so the difference must be computed with wrapping arithmetic rather than
        // signed comparison — and `UInt32(exactly:)` rejects a negative or oversized length in the
        // same step, since neither could ever equal a valid wrapping difference.
        guard let declaredLength = UInt32(exactly: length), end &- start == declaredLength else {
            throw VectorScriptError.malformedSequence(line)
        }

        var ack: UInt32?
        var window: UInt16?
        var options: [String] = []
        var index = 0
        while index < fields.count {
            let field = fields[index]
            if field == "ack", index + 1 < fields.count {
                // `nil` from a failed parse must mean "absent", and nothing else — so a
                // present-but-unparseable value, or a key repeated with a second value, has to
                // throw rather than silently leave the field looking unset (or overwrite it).
                guard ack == nil else { throw VectorScriptError.malformedField(line) }
                guard let value = UInt32(fields[index + 1]) else { throw VectorScriptError.malformedField(line) }
                ack = value; index += 2
            } else if field == "win", index + 1 < fields.count {
                guard window == nil else { throw VectorScriptError.malformedField(line) }
                guard let value = UInt16(fields[index + 1]) else { throw VectorScriptError.malformedField(line) }
                window = value; index += 2
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
                // Keep empty elements here (rather than the default omittingEmptySubsequences:
                // true) so "<mss 1460,,sackOK>" is caught below instead of silently losing the
                // element between the two commas.
                let rawOptions = joined.dropFirst().dropLast()
                    .split(separator: ",", omittingEmptySubsequences: false)
                    .map { $0.trimmingCharacters(in: .whitespaces) }
                guard rawOptions.allSatisfy({ !$0.isEmpty }) else {
                    throw VectorScriptError.unknownPacketForm(line)
                }
                options = rawOptions
                index += 1
            } else {
                throw VectorScriptError.unknownPacketForm(line)
            }
        }

        return TCPLine(flags: flags, seqStart: start, seqEnd: end, payloadLength: length,
                       ack: ack, window: window, options: options)
    }
}
