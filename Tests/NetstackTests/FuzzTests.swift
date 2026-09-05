import Foundation
import NIOCore
import NIOEmbedded
import Testing

@testable import Netstack

// The parsers are the first thing a hostile guest touches, and this package's
// README says the guest is hostile. `HostileGuestTests` covers the other half of
// that claim -- well-formed frames with hostile *values*, against the resource
// bounds. This covers malformed bytes.
//
// ## "It did not crash" is a weak oracle
//
// A parser that quietly corrupts state passes it, and so does one that stops
// working altogether. So every batch of garbage is followed by a known-good
// exchange that must still get the right answer: an ARP request for the
// gateway's address, and a DHCP DISCOVER that must still be offered a lease.
// That is what makes this able to fail for a reason other than a trap.
//
// ## The interesting inputs are near-valid
//
// Uniformly random bytes are rejected by the first length check and never reach
// anything. What finds bugs is a frame that is *almost* right: a valid one with
// its header length nibble corrupted, or its options truncated mid-TLV, or a
// length field claiming more than the frame holds. So the corpus is real frames
// and the fuzzer mutates them.

private let fuzzGatewayMAC = MACAddress("5a:94:ef:e4:0c:ee")!
private let fuzzGuestMAC = MACAddress("0a:0b:0c:0d:0e:0f")!
private let fuzzGateway = IPv4Address("192.168.127.1")!
private let fuzzGuest = IPv4Address("192.168.127.2")!

private struct FuzzRandom: RandomNumberGenerator {
    private var state: UInt64
    init(seed: UInt64) { state = seed &* 0x2545_F491_4F6C_DD1D | 1 }
    mutating func next() -> UInt64 {
        state ^= state << 13
        state ^= state >> 7
        state ^= state << 17
        return state
    }
}

/// A stack on an embedded loop, so the fuzzer is deterministic and fast: no
/// sockets, no threads, and a seed reproduces a failure exactly.
private final class FuzzHarness {
    let loop = EmbeddedEventLoop()
    let link: RecordingEndpoint
    let stack: Stack
    let dhcp: DHCPServer
    let dns: DNSServer

    init() throws {
        link = RecordingEndpoint(eventLoop: loop, linkAddress: fuzzGatewayMAC)
        stack = Stack(
            link: link,
            configuration: Stack.Configuration(
                gatewayAddress: fuzzGateway, subnet: IPv4Subnet(cidr: "192.168.127.0/24")!),
            clock: ManualClock())
        stack.start()
        dhcp = try DHCPServer(stack: stack)
        dns = try DNSServer(
            stack: stack, records: [.init(name: "gateway.containers.internal", address: fuzzGateway)])
    }

    func inject(_ bytes: [UInt8]) {
        guard !bytes.isEmpty else { return }
        link.inject(ByteBuffer(bytes: bytes))
    }

    func drain() -> [ByteBuffer] { link.drainTransmitted() }

    /// The oracle. A known-good ARP request for the gateway must still be
    /// answered, correctly, after whatever has just been done to the parsers.
    func arpStillWorks() -> Bool {
        _ = drain()
        inject(fuzzArpRequest())
        for frame in drain() {
            let bytes = Array(frame.readableBytesView)
            guard bytes.count >= 42, bytes[12] == 0x08, bytes[13] == 0x06 else { continue }
            // An ARP reply, from the gateway's own hardware and protocol
            // address -- not merely "a frame came back".
            guard bytes[20] == 0x00, bytes[21] == 0x02 else { continue }
            if Array(bytes[22..<28]) == fuzzGatewayMAC.bytes,
                Array(bytes[28..<32]) == fuzzGateway.bytes
            {
                return true
            }
        }
        return false
    }

    /// The second oracle, reaching further up: through IPv4 and UDP into a
    /// service. ARP alone would pass for a stack whose network layer had stopped
    /// working entirely.
    func dhcpStillWorks(transaction: UInt32) -> Bool {
        _ = drain()
        inject(fuzzDhcpDiscover(transaction: transaction))
        for frame in drain() {
            var packet = PacketBuffer(received: frame)
            guard let ethernet = EthernetHeader.parse(&packet), ethernet.etherType == .ipv4,
                let ip = IPv4Header.parse(&packet), ip.protocolNumber == .udp,
                let udp = UDPHeader.parse(&packet, header: ip),
                udp.destinationPort == DHCPServer.clientPort,
                let message = DHCPCodec.parse(packet.payload)
            else { continue }
            if message.messageType == .offer, message.transaction == transaction { return true }
        }
        return false
    }

    func shutdown() {
        dns.close()
        dhcp.close()
        // Not `.wait()`. On an `EmbeddedEventLoop` the future only completes
        // when the loop is driven, and `wait()` blocks the very thread that
        // would drive it -- a deadlock that presents as a test which never
        // finishes rather than one that fails. `run()` is what makes the
        // shutdown actually happen.
        _ = stack.shutdown()
        loop.run()
    }
}

// MARK: - The corpus, which is real frames rather than random bytes

private func fuzzEthernet(_ payload: [UInt8], etherType: UInt16 = 0x0800) -> [UInt8] {
    var out = fuzzGatewayMAC.bytes + fuzzGuestMAC.bytes
    out.append(UInt8(etherType >> 8))
    out.append(UInt8(truncatingIfNeeded: etherType))
    out += payload
    return out
}

private func fuzzArpRequest() -> [UInt8] {
    var arp: [UInt8] = [0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01]
    arp += fuzzGuestMAC.bytes + fuzzGuest.bytes
    arp += [UInt8](repeating: 0, count: 6) + fuzzGateway.bytes
    var frame = MACAddress.broadcast.bytes + fuzzGuestMAC.bytes
    frame += [0x08, 0x06]
    frame += arp
    return frame
}

private func fuzzIPv4(_ payload: [UInt8], protocolNumber: UInt8, destination: IPv4Address = fuzzGateway) -> [UInt8] {
    let allocator = ByteBufferAllocator()
    var packet = PacketBuffer(allocator: allocator, payload: ByteBuffer(bytes: payload))
    IPv4Header(
        source: fuzzGuest, destination: destination,
        protocolNumber: IPProtocol(rawValue: protocolNumber), payloadLength: payload.count
    ).prepend(to: &packet)
    return fuzzEthernet(Array(packet.frame.readableBytesView))
}

private func fuzzDhcpDiscover(transaction: UInt32) -> [UInt8] {
    var buffer = ByteBuffer()
    buffer.writeInteger(UInt8(1))
    buffer.writeInteger(UInt8(1))
    buffer.writeInteger(UInt8(6))
    buffer.writeInteger(UInt8(0))
    buffer.writeInteger(transaction, endianness: .big)
    buffer.writeInteger(UInt16(0), endianness: .big)
    buffer.writeInteger(UInt16(0x8000), endianness: .big)
    buffer.writeBytes([UInt8](repeating: 0, count: 16))
    buffer.writeBytes(fuzzGuestMAC.bytes)
    buffer.writeBytes([UInt8](repeating: 0, count: 10))
    buffer.writeBytes([UInt8](repeating: 0, count: 64 + 128))
    buffer.writeBytes([99, 130, 83, 99])
    buffer.writeBytes([53, 1, 1])
    buffer.writeInteger(UInt8(255))

    let allocator = ByteBufferAllocator()
    let datagram = UDPHeader.serialize(
        payload: buffer, source: .any, destination: .broadcast,
        sourcePort: DHCPServer.clientPort, destinationPort: DHCPServer.serverPort,
        allocator: allocator)!
    var packet = PacketBuffer(allocator: allocator, payload: datagram)
    IPv4Header(
        source: .any, destination: .broadcast, protocolNumber: .udp,
        payloadLength: datagram.readableBytes
    ).prepend(to: &packet)
    var frame = MACAddress.broadcast.bytes + fuzzGuestMAC.bytes
    frame += [0x08, 0x00]
    frame += Array(packet.frame.readableBytesView)
    return frame
}

private func fuzzTCPSynWithOptions() -> [UInt8] {
    // Built with the real serializer, so the checksum is right.
    //
    // The first version of this wrote the header by hand with a zero checksum
    // and a comment saying it would be fixed later. It never was, so every TCP
    // mutant was rejected at the checksum and the TCP parser -- the largest and
    // most intricate in this package, and the one with an options area a
    // mutator can most usefully corrupt -- was reached exactly zero times. The
    // fuzzer looked like it was working and was testing nothing.
    //
    // `mutatedFramesActuallyReachTheParsers` counts what each layer sees, which
    // is how that was found and what stops it recurring.
    let allocator = ByteBufferAllocator()
    let header = TCPHeader(
        sourcePort: 49152, destinationPort: 80, sequence: SequenceNumber(0x1000),
        acknowledgement: SequenceNumber(0), dataOffset: 10, flags: [.syn], window: 65535,
        checksum: 0, urgentPointer: 0,
        options: [
            .maximumSegmentSize(1460), .windowScale(7), .sackPermitted,
            .timestamps(value: 1, echo: 0),
        ])
    let segment = header.serialize(
        payload: ByteBuffer(), source: fuzzGuest, destination: fuzzGateway, allocator: allocator)
    return fuzzIPv4(Array(segment.readableBytesView), protocolNumber: 6)
}

private func fuzzDnsQuery() -> [UInt8] {
    var query = ByteBuffer()
    query.writeInteger(UInt16(0x1234), endianness: .big)
    query.writeInteger(UInt16(0x0100), endianness: .big)
    query.writeInteger(UInt16(1), endianness: .big)
    query.writeBytes([UInt8](repeating: 0, count: 6))
    for label in ["gateway", "containers", "internal"] {
        query.writeInteger(UInt8(label.utf8.count))
        query.writeBytes(Array(label.utf8))
    }
    query.writeInteger(UInt8(0))
    query.writeInteger(UInt16(1), endianness: .big)
    query.writeInteger(UInt16(1), endianness: .big)

    let allocator = ByteBufferAllocator()
    let datagram = UDPHeader.serialize(
        payload: query, source: fuzzGuest, destination: fuzzGateway, sourcePort: 40000,
        destinationPort: 53, allocator: allocator)!
    var packet = PacketBuffer(allocator: allocator, payload: datagram)
    IPv4Header(
        source: fuzzGuest, destination: fuzzGateway, protocolNumber: .udp,
        payloadLength: datagram.readableBytes
    ).prepend(to: &packet)
    return fuzzEthernet(Array(packet.frame.readableBytesView))
}

private func fuzzIcmpEcho() -> [UInt8] {
    var icmp: [UInt8] = [8, 0, 0, 0, 0x00, 0x01, 0x00, 0x01]
    icmp += [UInt8](repeating: 0x61, count: 32)
    return fuzzIPv4(icmp, protocolNumber: 1)
}

private func fuzzFragment(identification: UInt16 = 0x4321) -> [UInt8] {
    var payload: [UInt8] = [0xC0, 0x00, 0x00, 0x50]
    payload += [UInt8](repeating: 0x42, count: 60)
    let allocator = ByteBufferAllocator()
    var packet = PacketBuffer(allocator: allocator, payload: ByteBuffer(bytes: payload))
    var header = IPv4Header(
        source: fuzzGuest, destination: fuzzGateway, protocolNumber: .tcp,
        payloadLength: payload.count)
    header.flags = [.moreFragments]
    header.identification = identification
    header.prepend(to: &packet)
    return fuzzEthernet(Array(packet.frame.readableBytesView))
}

/// The corpus, rebuilt per draw so the entries that carry an identity can vary
/// it.
///
/// A fixed array looks equivalent and is not: every fragment then shares one
/// identification and one address pair, so they are all the *same* reassembly
/// key and only one pending entry ever exists. The reassembler's table bound is
/// then never approached, and the assertion on it passes with the bound deleted
/// -- which is what happened.
private func fuzzDraw(_ rng: inout FuzzRandom) -> [UInt8] {
    switch rng.next() % 6 {
    case 0: return fuzzArpRequest()
    case 1: return fuzzTCPSynWithOptions()
    case 2: return fuzzDhcpDiscover(transaction: UInt32(truncatingIfNeeded: rng.next()))
    case 3: return fuzzDnsQuery()
    case 4: return fuzzIcmpEcho()
    default: return fuzzFragment(identification: UInt16(truncatingIfNeeded: rng.next()))
    }
}

// MARK: - Mutators

/// One mutation of a valid frame. Each is a shape that has historically broken
/// a parser somewhere, rather than random noise.
private func fuzzMutate(_ input: [UInt8], _ rng: inout FuzzRandom) -> [UInt8] {
    guard !input.isEmpty else { return input }
    var out = input
    switch rng.next() % 8 {
    case 0:
        // A single bit, anywhere. The cheapest way to find a comparison that
        // should have been a bound.
        let index = Int(rng.next() % UInt64(out.count))
        out[index] ^= UInt8(1) << UInt8(rng.next() % 8)
    case 1:
        // Truncated. Every length in the frame now claims more than there is.
        let keep = Int(rng.next() % UInt64(out.count))
        out = Array(out.prefix(keep))
    case 2:
        // Extended with garbage: a frame longer than its headers describe.
        out += (0..<Int(rng.next() % 64)).map { _ in UInt8(truncatingIfNeeded: rng.next()) }
    case 3:
        // The IPv4 header-length nibble, which decides where everything after it
        // starts. 0 and 15 are the interesting values.
        if out.count > 14 { out[14] = (out[14] & 0xF0) | UInt8(rng.next() % 16) }
    case 4:
        // The IPv4 total-length field, claiming more or less than the frame has.
        if out.count > 18 {
            out[16] = UInt8(truncatingIfNeeded: rng.next())
            out[17] = UInt8(truncatingIfNeeded: rng.next())
        }
    case 5:
        // The TCP data-offset nibble, which is how an options area comes to
        // overlap the payload or run past the frame.
        if out.count > 46 { out[46] = UInt8(truncatingIfNeeded: rng.next()) & 0xF0 }
    case 6:
        // A whole byte replaced, which reaches option kinds and lengths that a
        // single bit flip rarely produces.
        let index = Int(rng.next() % UInt64(out.count))
        out[index] = UInt8(truncatingIfNeeded: rng.next())
    default:
        // Cut in the middle, which lands mid-TLV in an options area more often
        // than a truncation from the end does.
        if out.count > 20 {
            let start = 14 + Int(rng.next() % UInt64(out.count - 14))
            let length = Int(rng.next() % 8)
            out.removeSubrange(start..<min(out.count, start + length))
        }
    }
    return out
}

/// Recompute the checksums a mutation invalidated.
///
/// Without this the fuzzer tests the front door and nothing behind it. Every
/// checksum covers everything after it, so any mutation of a TCP segment makes
/// the checksum wrong and the segment is rejected before the options area is
/// read -- the TCP parser, which is the largest in this package and the one with
/// a variable-length options area, was reached by 52 mutants in 2000. Repairing
/// the checksums puts the mutation back in front of the parser it was aimed at.
///
/// Applied to *some* mutants rather than all: an unrepaired one tests that a
/// wrong checksum is still rejected, which is a property worth keeping, and a
/// fuzzer that repaired everything would stop testing it.
private func fuzzRepairChecksums(_ input: [UInt8]) -> [UInt8] {
    var out = input
    guard out.count >= 34, out[12] == 0x08, out[13] == 0x00 else { return out }
    let ipStart = 14
    var ihl = Int(out[ipStart] & 0x0F) * 4
    if ihl < 20 || ihl > out.count - ipStart {
        ihl = 20
        out[ipStart] = (out[ipStart] & 0xF0) | 5
    }
    // The total length has to describe what is actually here, or the IPv4
    // parser rejects it before any transport parser sees it.
    let ipTotal = out.count - ipStart
    out[ipStart + 2] = UInt8(truncatingIfNeeded: ipTotal >> 8)
    out[ipStart + 3] = UInt8(truncatingIfNeeded: ipTotal)
    out[ipStart + 10] = 0
    out[ipStart + 11] = 0
    let headerChecksum = out[ipStart..<(ipStart + ihl)].withUnsafeBytes { Checksum.compute($0) }
    out[ipStart + 10] = UInt8(truncatingIfNeeded: headerChecksum >> 8)
    out[ipStart + 11] = UInt8(truncatingIfNeeded: headerChecksum)

    let protocolNumber = out[ipStart + 9]
    let payloadStart = ipStart + ihl
    guard payloadStart < out.count else { return out }
    let source = IPv4Address(out[ipStart + 12], out[ipStart + 13], out[ipStart + 14], out[ipStart + 15])
    let destination = IPv4Address(out[ipStart + 16], out[ipStart + 17], out[ipStart + 18], out[ipStart + 19])
    let length = out.count - payloadStart
    let checksumOffset: Int
    switch protocolNumber {
    case 6: checksumOffset = payloadStart + 16
    case 17: checksumOffset = payloadStart + 6
    default: return out
    }
    guard checksumOffset + 1 < out.count else { return out }
    out[checksumOffset] = 0
    out[checksumOffset + 1] = 0

    var sum: UInt32 = 0
    sum += UInt32(source.raw >> 16) + UInt32(source.raw & 0xffff)
    sum += UInt32(destination.raw >> 16) + UInt32(destination.raw & 0xffff)
    sum += UInt32(protocolNumber)
    sum += UInt32(truncatingIfNeeded: length)
    let transport = out[payloadStart...].withUnsafeBytes {
        Checksum.complete(Checksum.partial($0, initial: sum))
    }
    out[checksumOffset] = UInt8(truncatingIfNeeded: transport >> 8)
    out[checksumOffset + 1] = UInt8(truncatingIfNeeded: transport)
    return out
}

// MARK: - The test

@Test func theParsersSurviveMutatedFramesAndKeepWorking() throws {
    // Iterations are env-tunable so this can be run as a soak without being one
    // in the ordinary suite. The default is chosen to stay well under a second.
    let iterations = Int(ProcessInfo.processInfo.environment["NETSTACK_FUZZ_ITERATIONS"] ?? "") ?? 4000
    let seed = UInt64(ProcessInfo.processInfo.environment["NETSTACK_FUZZ_SEED"] ?? "") ?? 0xC0FFEE

    let harness = try FuzzHarness()
    defer { harness.shutdown() }
    var rng = FuzzRandom(seed: seed)
    // The floor: the harness answers before any of this, so a failure below is
    // the fuzzing rather than a fixture that never worked.
    #expect(harness.arpStillWorks(), "the harness could not answer ARP before fuzzing began")
    #expect(harness.dhcpStillWorks(transaction: 1), "the harness could not lease before fuzzing began")

    for iteration in 0..<iterations {
        var frame = fuzzDraw(&rng)
        // Sometimes several mutations, because one is often repaired by a later
        // length check while two are not.
        for _ in 0...(rng.next() % 3) {
            frame = fuzzMutate(frame, &rng)
        }
        // Half repaired, half not: see `fuzzRepairChecksums`.
        if rng.next() % 2 == 0 { frame = fuzzRepairChecksums(frame) }
        harness.inject(frame)
        _ = harness.drain()

        // Checked periodically rather than every iteration, which would cost
        // more than the fuzzing. Any failure names the seed, so it replays.
        if iteration % 250 == 249 {
            #expect(
                harness.arpStillWorks(),
                "ARP stopped working after \(iteration + 1) mutations; replay with NETSTACK_FUZZ_SEED=\(seed)")
            #expect(
                harness.dhcpStillWorks(transaction: UInt32(iteration)),
                "DHCP stopped working after \(iteration + 1) mutations; replay with NETSTACK_FUZZ_SEED=\(seed)")
        }
    }

    #expect(harness.arpStillWorks(), "ARP stopped working; replay with NETSTACK_FUZZ_SEED=\(seed)")
    #expect(
        harness.dhcpStillWorks(transaction: 0xFFFF),
        "DHCP stopped working; replay with NETSTACK_FUZZ_SEED=\(seed)")

    // Nothing accumulated past what the reassembler is configured to hold.
    //
    // Against the CONFIGURED bound, not a number chosen here. The first version
    // asserted 64 and failed at 430 -- which was not a bug, because the limit is
    // 1024 and 430 is inside it. An arbitrary constant in an assertion is a
    // false failure waiting for the day the fuzzer gets better at reaching the
    // code, which is exactly what had just happened.
    let held = harness.stack.reassembler.pendingCount
    #expect(
        held <= Reassembler.defaultMaximumPendingDatagrams,
        "the reassembler held \(held) entries, past its bound of \(Reassembler.defaultMaximumPendingDatagrams)")
    // And the fuzzer really did press on it, or the bound above is satisfied by
    // never having created an entry.
    #expect(held > 0, "no fragment ever reached the reassembler")
}

@Test func mutatedFramesActuallyReachTheParsers() throws {
    // The floor under the test above, and the thing that makes it worth running:
    // uniformly random bytes are rejected by the first length check and never
    // reach anything, so a fuzzer that produced them would pass while testing
    // nothing at all.
    //
    // This asserts that the mutated corpus still parses often enough to be
    // exercising the parsers rather than the front door.
    var rng = FuzzRandom(seed: 0xBEEF)
    var parsedEthernet = 0
    var parsedIPv4 = 0
    var parsedTCP = 0
    var parsedUDP = 0
    var parsedICMP = 0

    for _ in 0..<2000 {
        var frame = fuzzMutate(fuzzDraw(&rng), &rng)
        if rng.next() % 2 == 0 { frame = fuzzRepairChecksums(frame) }
        guard !frame.isEmpty else { continue }
        var packet = PacketBuffer(received: ByteBuffer(bytes: frame))
        guard let ethernet = EthernetHeader.parse(&packet) else { continue }
        parsedEthernet += 1
        guard ethernet.etherType == .ipv4, let ip = IPv4Header.parse(&packet) else { continue }
        parsedIPv4 += 1
        switch ip.protocolNumber {
        case .tcp: if TCPHeader.parse(&packet, header: ip) != nil { parsedTCP += 1 }
        case .udp: if UDPHeader.parse(&packet, header: ip) != nil { parsedUDP += 1 }
        case .icmp: parsedICMP += 1
        default: break
        }
    }

    #expect(parsedEthernet > 1500, "only \(parsedEthernet)/2000 mutants had a readable ethernet header")
    #expect(parsedIPv4 > 500, "only \(parsedIPv4)/2000 mutants reached the IPv4 parser")
    // The layer that matters most and is hardest to reach: every checksum covers
    // everything after it, so an unrepaired mutation of a TCP segment never gets
    // past it. This was ZERO until the corpus frame was given a real checksum,
    // and 52 until mutants started being repaired -- so it is asserted, because
    // a fuzzer that stops reaching the TCP parser is one that has quietly
    // stopped testing the thing most worth testing.
    #expect(parsedTCP > 100, "only \(parsedTCP)/2000 mutants reached the TCP parser")
    #expect(parsedUDP > 100, "only \(parsedUDP)/2000 mutants reached the UDP parser")
    #expect(parsedICMP > 100, "only \(parsedICMP)/2000 mutants reached ICMP")
}

// MARK: - Mutated segments on a connection that is actually up

// Everything above stops at a TCP header. The corpus segment is a SYN to a port
// nothing listens on, so it is parsed, answered with a reset, and forgotten --
// and `TCPReassembler`, the largest structure a guest can drive, the one that
// holds the guest's bytes until a gap ahead of them fills, and the one whose
// every comparison runs in a wrapping sequence space, is reached by its own unit
// tests and by nothing that came off a wire.
//
// ## The oracle is the delivered stream, not "it did not crash"
//
// Every byte sent here is a function of its own absolute sequence number. So the
// bytes handed up to the channel must equal that function of their offset in the
// stream, at every offset. A reassembler that splices an overlapping
// retransmission at the wrong place, or that lets a wrapped comparison put a
// segment on the wrong side of the window, delivers bytes that are individually
// plausible and collectively wrong. Nothing about that is visible to a test
// that only asks whether the process is still running.
//
// ## Which is why the payload is refilled after the header is mutated
//
// The oracle only means anything if every segment stays truthful about itself.
// The mutators rewrite the header -- the sequence especially -- and the payload
// is then rebuilt for whatever sequence the mutated header now claims.
//
// A guest may retransmit overlapping data at any sequence it likes, and a
// correct reassembler has to handle that. A guest whose bytes disagree with its
// own sequence numbers is asking for garbage and getting it, so leaving the
// payload alone would fail this test for a reason that is not a bug.
//
// ## What it reaches, measured rather than assumed
//
// Slicing an arriving segment from the wrong offset in its own payload --
// `range.start` in place of `range.start - dataStart`, the classic
// misplacement -- is caught here. Six unit tests catch it too, and that is
// worth saying plainly: this is not the only thing that would notice, and the
// guard row on it claims nothing more than that this test can fail.
//
// Two mutations that look like they belong to it SURVIVED, which says where
// this actually goes. Removing `novelRanges`' clamp at RCV.NXT, and weakening
// the admission bound to check one end of a segment instead of both, both
// changed nothing observable here: `TCPStateMachine` applies the acceptance
// test first, so a segment that reaches `TCPReassembler` through a live
// connection is already in the window and already trimmed. Those bounds sit
// behind that as defence in depth, they have their own unit tests, and a
// fuzzer arriving by the front door is not what exercises them.
//
// So what this adds over those unit tests is the composition -- acceptance
// test, reassembly, and channel delivery, driven by frames rather than by
// constructed `Segment`s -- on connections whose sequence numbers were chosen
// to run across the 32-bit wrap while doing it.

/// A byte that is a function of where it belongs in the stream. Multiplied by a
/// large odd constant and taken from the top, rather than the sequence's low
/// byte: the low byte repeats every 256, so a misplacement of exactly a
/// multiple of 256 bytes -- the likeliest size for one to be -- would land on
/// the value it displaced and be invisible.
private func fuzzStreamByte(at sequence: UInt32) -> UInt8 {
    UInt8(truncatingIfNeeded: (sequence &* 0x9E37_79B1) >> 24)
}

/// 14 bytes of ethernet and 20 of IPv4: where the TCP header starts in a frame
/// this file built.
private let fuzzSegmentStart = 34

private func fuzzSegmentFrame(_ header: TCPHeader, payload: [UInt8]) -> [UInt8] {
    let allocator = ByteBufferAllocator()
    let segment = header.serialize(
        payload: ByteBuffer(bytes: payload), source: fuzzGuest, destination: fuzzGateway, allocator: allocator)
    var packet = PacketBuffer(allocator: allocator, payload: segment)
    IPv4Header(
        source: fuzzGuest, destination: fuzzGateway, protocolNumber: .tcp,
        payloadLength: segment.readableBytes
    ).prepend(to: &packet)
    return fuzzEthernet(Array(packet.frame.readableBytesView))
}

/// Rewrite the payload so it says what the (possibly mutated) header now claims
/// about where it belongs. Reads the data offset the same way the parser does,
/// so the payload starts where the parser will look for it.
private func fuzzRefillPayload(_ frame: [UInt8]) -> [UInt8] {
    var out = frame
    guard out.count >= fuzzSegmentStart + 20 else { return out }
    let dataOffset = Int(out[fuzzSegmentStart + 12] >> 4) * 4
    guard dataOffset >= 20, fuzzSegmentStart + dataOffset <= out.count else { return out }
    var sequence = UInt32(0)
    for byte in out[(fuzzSegmentStart + 4)..<(fuzzSegmentStart + 8)] { sequence = sequence << 8 | UInt32(byte) }
    let payloadStart = fuzzSegmentStart + dataOffset
    for index in payloadStart..<out.count {
        out[index] = fuzzStreamByte(at: sequence &+ UInt32(index - payloadStart))
    }
    return out
}

/// One mutation of a segment's header. Aimed rather than uniform: the fields
/// below are the ones whose mishandling has a name.
private func fuzzMutateSegment(_ frame: [UInt8], _ rng: inout FuzzRandom) -> [UInt8] {
    var out = frame
    let tcp = fuzzSegmentStart
    guard out.count >= tcp + 20 else { return out }

    func read32(_ offset: Int) -> UInt32 {
        var value = UInt32(0)
        for byte in out[(tcp + offset)..<(tcp + offset + 4)] { value = value << 8 | UInt32(byte) }
        return value
    }
    func write32(_ offset: Int, _ value: UInt32) {
        out[tcp + offset] = UInt8(truncatingIfNeeded: value >> 24)
        out[tcp + offset + 1] = UInt8(truncatingIfNeeded: value >> 16)
        out[tcp + offset + 2] = UInt8(truncatingIfNeeded: value >> 8)
        out[tcp + offset + 3] = UInt8(truncatingIfNeeded: value)
    }

    switch rng.next() % 8 {
    case 0:
        let index = tcp + Int(rng.next() % 20)
        out[index] ^= UInt8(1) << UInt8(rng.next() % 8)
    case 1:
        // The sequence, moved somewhere a comparison has to get right: just
        // outside the window, half a sequence space away, across the wrap.
        let offsets: [UInt32] = [1, 0xFFFF_FFFF, 65535, 0xFFFF_0001, 1 << 30, 1 << 31, 0x8000_0001]
        write32(4, read32(4) &+ offsets[Int(rng.next() % UInt64(offsets.count))])
    case 2:
        // The data offset, which decides where this header stops and the bytes
        // begin -- including values that put the payload before the header ends.
        out[tcp + 12] = UInt8(truncatingIfNeeded: rng.next())
    case 3:
        out[tcp + 13] = UInt8(truncatingIfNeeded: rng.next())
    case 4:
        out[tcp + 14] = UInt8(truncatingIfNeeded: rng.next())
        out[tcp + 15] = UInt8(truncatingIfNeeded: rng.next())
    case 5:
        // The options area, where a length byte decides how far the walk goes.
        let dataOffset = Int(out[tcp + 12] >> 4) * 4
        guard dataOffset > 20, tcp + dataOffset <= out.count else { break }
        for index in (tcp + 20)..<(tcp + dataOffset) { out[index] = UInt8(truncatingIfNeeded: rng.next()) }
    case 6:
        out = Array(out.prefix(Int(rng.next() % UInt64(out.count))))
    default:
        write32(8, UInt32(truncatingIfNeeded: rng.next()))
    }
    return out
}

private final class FuzzStreamRecorder: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    var received: [UInt8] = []
    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        received.append(contentsOf: unwrapInboundIn(data).readableBytesView)
    }
}

private final class FuzzChildCollector: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = NetstackStreamChannel
    var children: [(channel: NetstackStreamChannel, recorder: FuzzStreamRecorder)] = []
    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let child = unwrapInboundIn(data)
        let recorder = FuzzStreamRecorder()
        _ = child.pipeline.addHandler(recorder)
        children.append((child, recorder))
    }
}

@Test func mutatedSegmentsOnALiveConnectionDeliverACoherentStream() throws {
    let fixture = TCPFixture()
    let server = NetstackServerChannel(stack: fixture.stack)
    let collector = FuzzChildCollector()
    try server.pipeline.addHandler(collector).wait()
    try server.bind(to: SocketAddress(ipAddress: "192.168.127.1", port: 8080)).wait()

    var rng = FuzzRandom(seed: 0x5EED_F00D)
    var peerPort: UInt16 = 40000
    var established = 0
    // Where each accepted connection's stream begins, so a delivered byte can be
    // checked against the sequence it should have come from.
    var streamStart: [Int: UInt32] = [:]

    /// The connection currently being shot at: which child it is, where its
    /// stream started, and what the gateway is expecting to be acknowledged.
    var live: (index: Int, dataStart: UInt32, gatewayNext: UInt32)?

    func open() {
        peerPort &+= 1
        // A spread of initial sequence numbers, so some of these connections run
        // their data straight across the wrap rather than all sitting in the
        // comfortable middle of the space.
        let choices: [UInt32] = [7000, 0xFFFF_FF00, 0x7FFF_FFF0, 0x8000_0000, 123_456_789]
        let iss = choices[Int(rng.next() % UInt64(choices.count))] &+ UInt32(peerPort)
        let before = collector.children.count

        fixture.inject(
            guestSegment(sequence: iss, flags: [.syn], options: [.maximumSegmentSize(1460)], peerPort: peerPort))
        guard let synAck = fixture.drainSegments().first(where: { $0.header.flags.contains(.syn) }) else {
            live = nil
            return
        }
        let gatewayISS = synAck.header.sequence.value
        fixture.inject(
            guestSegment(sequence: iss &+ 1, ack: gatewayISS &+ 1, flags: [.ack], peerPort: peerPort))
        _ = fixture.drainSegments()

        guard collector.children.count > before else {
            live = nil
            return
        }
        let index = collector.children.count - 1
        streamStart[index] = iss &+ 1
        established += 1
        live = (index, iss &+ 1, gatewayISS &+ 1)
    }

    withExtendedLifetime(server) {
        open()
        for _ in 0..<1200 {
            guard let current = live, collector.children[current.index].channel.isActive else {
                open()
                continue
            }
            let recorder = collector.children[current.index].recorder
            // What the application has seen is what the stream is next expecting,
            // which keeps this honest when a gap stalls delivery: the sends go
            // back to the stall rather than running away from it.
            let next = current.dataStart &+ UInt32(recorder.received.count)
            let sequence: UInt32
            switch rng.next() % 4 {
            case 0: sequence = next &+ UInt32(rng.next() % 4096)  // ahead: opens a gap
            case 1: sequence = next &- UInt32(rng.next() % 2048)  // behind: overlaps
            default: sequence = next
            }
            let length = Int(rng.next() % 512) + 1
            let payload = (0..<length).map { fuzzStreamByte(at: sequence &+ UInt32($0)) }
            let header = guestSegment(
                sequence: sequence, ack: current.gatewayNext, flags: [.ack, .psh], peerPort: peerPort)

            var frame = fuzzMutateSegment(fuzzSegmentFrame(header, payload: payload), &rng)
            frame = fuzzRefillPayload(frame)
            // Mostly repaired, because an unrepaired mutation dies at the
            // checksum and reaches nothing -- but not always, so the checksum
            // itself stays on the path being tested.
            if rng.next() % 4 != 0 { frame = fuzzRepairChecksums(frame) }
            guard !frame.isEmpty else { continue }
            fixture.link.inject(ByteBuffer(bytes: frame))
            _ = fixture.drainSegments()
        }

        var delivered = 0
        for (index, child) in collector.children.enumerated() {
            guard let start = streamStart[index] else { continue }
            let bytes = child.recorder.received
            delivered += bytes.count
            for (offset, byte) in bytes.enumerated() where byte != fuzzStreamByte(at: start &+ UInt32(offset)) {
                Issue.record(
                    "byte \(offset) of a stream arrived as \(byte) where \(fuzzStreamByte(at: start &+ UInt32(offset))) belongs: the reassembler placed data at the wrong offset")
                break
            }
        }

        // Both floors are the point. Every mutated segment being rejected would
        // satisfy the oracle above perfectly and prove nothing, and so would a
        // stack that stopped accepting connections after the first reset.
        #expect(established >= 2, "only \(established) connections came up, so this never reached a live one")
        #expect(delivered > 8192, "only \(delivered) bytes were delivered, so this measured rejection and not reassembly")

        for child in collector.children { child.channel.close(promise: nil) }
    }
    server.close(promise: nil)
    fixture.drain()
}
