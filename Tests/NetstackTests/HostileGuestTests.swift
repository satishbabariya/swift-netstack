import NIOCore
import NIOPosix
import Testing

#if canImport(Darwin)
    import Darwin
#else
    import Glibc
#endif

@testable import Netstack

// The threat model, tested as a whole rather than a bound at a time.
//
// Every other test here drives one component with input it was designed for.
// This one drives the ASSEMBLED gateway with what a guest that is trying to
// break it would send: malformed frames, floods of half-open connections, a
// sweep of every source port, DHCP under forged hardware addresses, and names
// nobody would look up. What it asserts is not that any of it is answered
// correctly -- most of it should not be answered at all -- but that the process
// is still there afterwards and every bound still holds.
//
// A soak like this is worth more than its assertions suggest. It is the only
// test that runs the components against each other under load, and the failures
// it can produce -- a trap, a hang, a table that grew -- are ones no unit test
// is looking for.

private let hostileMAC = MACAddress("0a:0b:0c:0d:0e:0f")!
private let hostileGateway = MACAddress("5a:94:ef:e4:0c:ee")!

/// Deterministic, so a failure is reproducible from the seed alone.
private struct Xoshiro: RandomNumberGenerator {
    private var state: UInt64

    init(seed: UInt64) { state = seed &* 0x2545_F491_4F6C_DD1D | 1 }

    mutating func next() -> UInt64 {
        state ^= state << 13
        state ^= state >> 7
        state ^= state << 17
        return state
    }
}

private func ethernetPrefix(_ buffer: inout ByteBuffer, etherType: UInt16 = 0x0800) {
    buffer.writeBytes(hostileGateway.bytes)
    buffer.writeBytes(hostileMAC.bytes)
    buffer.writeInteger(etherType, endianness: .big)
}

/// One frame of the given kind.
///
/// The KIND is a parameter rather than a draw from the generator, and that is
/// the difference between a soak that covers everything and one that covers
/// whatever the random numbers happened to pick. The first version drew the
/// kind at random from a fixed budget of frames, so the cases competed: adding
/// a ninth kind thinned the eighth below the bound it was there to push on, and
/// a falsification that had failed the day before started passing. Sending a
/// fixed count of EACH kind makes the coverage a property of the loop rather
/// than of the seed.
private func hostileFrame(_ rng: inout Xoshiro, kind: UInt64, reachablePort: UInt16) -> [UInt8] {
    let choice = kind
    let allocator = ByteBufferAllocator()

    switch choice {
    case 0:
        // A SYN from a fresh source port, to a port nothing is listening on.
        // The half-open bound is what has to hold.
        return tcpFrame(
            rng: &rng, flags: [.syn], sourcePort: UInt16(truncatingIfNeeded: rng.next()),
            destination: IPv4Address(UInt32(truncatingIfNeeded: rng.next())))
    case 1:
        // A UDP datagram to a random destination, sweeping source ports. The
        // flow bound is what has to hold.
        var payload = ByteBuffer()
        payload.writeBytes([UInt8](repeating: 0x41, count: Int(rng.next() % 64)))
        return udpFrame(
            rng: &rng, sourcePort: UInt16(truncatingIfNeeded: rng.next()),
            destinationPort: UInt16(truncatingIfNeeded: rng.next()),
            destination: IPv4Address(UInt32(truncatingIfNeeded: rng.next())), payload: payload)
    case 2:
        // A DHCP DISCOVER under a hardware address nobody has ever used. The
        // lease pool is what has to hold.
        var buffer = ByteBuffer()
        buffer.writeInteger(UInt8(1))
        buffer.writeInteger(UInt8(1))
        buffer.writeInteger(UInt8(6))
        buffer.writeInteger(UInt8(0))
        buffer.writeInteger(UInt32(truncatingIfNeeded: rng.next()), endianness: .big)
        buffer.writeInteger(UInt16(0), endianness: .big)
        buffer.writeInteger(UInt16(0x8000), endianness: .big)
        buffer.writeBytes([UInt8](repeating: 0, count: 16))
        buffer.writeBytes((0..<6).map { _ in UInt8(truncatingIfNeeded: rng.next()) })
        buffer.writeBytes([UInt8](repeating: 0, count: 10 + 64 + 128))
        buffer.writeBytes([99, 130, 83, 99])
        buffer.writeBytes([53, 1, 1])
        buffer.writeInteger(UInt8(255))
        return udpFrame(
            rng: &rng, sourcePort: DHCPServer.clientPort, destinationPort: DHCPServer.serverPort,
            destination: .broadcast, payload: buffer, source: .any)
    case 3:
        // A DNS query for a name of the guest's choosing, including names that
        // are not names.
        var query = ByteBuffer()
        query.writeInteger(UInt16(truncatingIfNeeded: rng.next()), endianness: .big)
        query.writeInteger(UInt16(0x0100), endianness: .big)
        query.writeInteger(UInt16(1), endianness: .big)
        query.writeBytes([UInt8](repeating: 0, count: 6))
        let labels = Int(rng.next() % 6)
        for _ in 0..<labels {
            let length = UInt8(truncatingIfNeeded: rng.next())
            query.writeInteger(length)
            query.writeBytes((0..<Int(length % 40)).map { _ in UInt8(truncatingIfNeeded: rng.next()) })
        }
        query.writeInteger(UInt8(0))
        query.writeInteger(UInt16(1), endianness: .big)
        query.writeInteger(UInt16(1), endianness: .big)
        return udpFrame(
            rng: &rng, sourcePort: 40000, destinationPort: 53,
            destination: IPv4Address("192.168.127.1")!, payload: query)
    case 4:
        // Bytes. Not a frame, not an ethernet header, nothing.
        var buffer = ByteBuffer()
        let length = Int(rng.next() % 100)
        buffer.writeBytes((0..<length).map { _ in UInt8(truncatingIfNeeded: rng.next()) })
        return Array(buffer.readableBytesView)
    case 5:
        // An IPv4 header claiming a payload length it does not have, which is
        // the shape that finds a parser reading past its buffer.
        var packet = ByteBuffer()
        ethernetPrefix(&packet)
        packet.writeBytes([0x45, 0x00, 0xFF, 0xFF, 0, 0, 0, 0, 64, 6, 0, 0])
        packet.writeBytes(IPv4Address("192.168.127.2")!.bytes)
        packet.writeBytes(IPv4Address("192.168.127.1")!.bytes)
        packet.writeBytes((0..<Int(rng.next() % 40)).map { _ in UInt8(truncatingIfNeeded: rng.next()) })
        return Array(packet.readableBytesView)
    case 6:
        // A fragment that never completes, which is what the reassembler's
        // memory bound exists for.
        var packet = PacketBuffer(
            allocator: allocator, payload: ByteBuffer(bytes: [UInt8](repeating: 0x42, count: 8)))
        var header = IPv4Header(
            source: IPv4Address("192.168.127.2")!, destination: IPv4Address("192.168.127.1")!,
            protocolNumber: .udp, payloadLength: 8)
        header.identification = UInt16(truncatingIfNeeded: rng.next())
        header.flags = [.moreFragments]
        header.prepend(to: &packet)
        EthernetHeader(destination: hostileGateway, source: hostileMAC, etherType: .ipv4)
            .prepend(to: &packet)
        return Array(packet.frame.readableBytesView)
    case 7:
        // A SYN to a port that really is listening, from a fresh source port
        // every time.
        //
        // The other SYN case dials random addresses that never answer, so the
        // requests sit in the half-open table and the ESTABLISHED bound is never
        // approached -- which is how the first version of this test passed with
        // that bound removed. A destination the dial completes for is what makes
        // connections actually accumulate.
        return tcpFrame(
            rng: &rng, flags: [.syn], sourcePort: UInt16(truncatingIfNeeded: rng.next()),
            destination: IPv4Address("127.0.0.1")!, destinationPort: reachablePort)
    default:
        // An ARP frame that is not an ARP packet.
        var packet = ByteBuffer()
        ethernetPrefix(&packet, etherType: 0x0806)
        packet.writeBytes((0..<Int(rng.next() % 30)).map { _ in UInt8(truncatingIfNeeded: rng.next()) })
        return Array(packet.readableBytesView)
    }
}

private func tcpFrame(
    rng: inout Xoshiro, flags: TCPFlags, sourcePort: UInt16, destination: IPv4Address,
    destinationPort: UInt16? = nil
) -> [UInt8] {
    let allocator = ByteBufferAllocator()
    let source = IPv4Address("192.168.127.2")!
    let header = TCPHeader(
        sourcePort: sourcePort,
        destinationPort: destinationPort ?? UInt16(truncatingIfNeeded: rng.next()),
        sequence: SequenceNumber(UInt32(truncatingIfNeeded: rng.next())),
        acknowledgement: SequenceNumber(0), dataOffset: 5, flags: flags, window: 65535,
        checksum: 0, urgentPointer: 0, options: [])
    let segment = header.serialize(
        payload: ByteBuffer(), source: source, destination: destination, allocator: allocator)
    var packet = PacketBuffer(allocator: allocator, payload: segment)
    IPv4Header(
        source: source, destination: destination, protocolNumber: .tcp,
        payloadLength: segment.readableBytes
    ).prepend(to: &packet)
    EthernetHeader(destination: hostileGateway, source: hostileMAC, etherType: .ipv4)
        .prepend(to: &packet)
    return Array(packet.frame.readableBytesView)
}

private func udpFrame(
    rng: inout Xoshiro, sourcePort: UInt16, destinationPort: UInt16, destination: IPv4Address,
    payload: ByteBuffer, source: IPv4Address = IPv4Address("192.168.127.2")!
) -> [UInt8] {
    let allocator = ByteBufferAllocator()
    guard let datagram = UDPHeader.serialize(
        payload: payload, source: source, destination: destination,
        sourcePort: sourcePort, destinationPort: destinationPort, allocator: allocator)
    else { return [] }
    var packet = PacketBuffer(allocator: allocator, payload: datagram)
    IPv4Header(
        source: source, destination: destination, protocolNumber: .udp,
        payloadLength: datagram.readableBytes
    ).prepend(to: &packet)
    EthernetHeader(destination: hostileGateway, source: hostileMAC, etherType: .ipv4)
        .prepend(to: &packet)
    return Array(packet.frame.readableBytesView)
}

/// Read whatever the gateway sent back, so the guest's receive buffer does not
/// fill and stop the flood for a reason that is not the gateway's doing.
private func drainReturnPath(_ fd: Int32, limit: Int = 200) {
    for _ in 0..<limit {
        var back = [UInt8](repeating: 0, count: 4096)
        if back.withUnsafeMutableBytes({ recv(fd, $0.baseAddress, $0.count, MSG_DONTWAIT) }) <= 0 { return }
    }
}

@Test func anAssembledGatewaySurvivesAGuestTryingToBreakIt() async throws {
    var pair: [Int32] = [0, 0]
    #expect(makeSocketPair(AF_UNIX, .datagram, &pair) == 0)
    // A send buffer large enough that the flood is not throttled by the socket
    // before it reaches the stack, which is the thing under test.
    var size: Int32 = 4 * 1024 * 1024
    _ = setsockopt(pair[1], SOL_SOCKET, SO_SNDBUF, &size, socklen_t(MemoryLayout<Int32>.size))
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)

    // A listener the flood can actually connect to; see the SYN case above.
    let listener = try await ServerBootstrap(group: group)
        .childChannelInitializer { channel in channel.eventLoop.makeSucceededVoidFuture() }
        .bind(host: "127.0.0.1", port: 0).get()
    let reachablePort = UInt16(listener.localAddress!.port!)

    let gateway = try await Gateway.start(
        adoptingDatagramSocket: pair[0], group: group,
        // The half-open bound is deliberately NOT lowered with the others. The
        // flood's dials to unroutable addresses hold half-open slots until they
        // time out, so a small bound here starves the reachable-port case and
        // the ESTABLISHED bound below is never approached -- which is how an
        // earlier version of this test came to assert nothing about it.
        configuration: .init(maximumTCPConnections: 32, maximumUDPFlows: 32)
    ).get()

    // Sampled every round and kept as maxima, not read once at the end.
    //
    // Reclaim runs while the flood does, so a bound read afterwards can be well
    // under the peak -- which is how the first version of this test passed with
    // both bounds REMOVED. What has to hold is the bound at its highest, and
    // that is only visible while the guest is still pushing.
    var peakTCP = 0
    var peakUDP = 0
    var peakRegistrations = 0

    var rng = Xoshiro(seed: 0x5EED)
    for round in 0..<20 {
        for kind in UInt64(0)..<9 {
            for _ in 0..<40 {
                let frame = hostileFrame(&rng, kind: kind, reachablePort: reachablePort)
                guard !frame.isEmpty else { continue }
                _ = frame.withUnsafeBytes { send(pair[1], $0.baseAddress, $0.count, 0) }
            }
            drainReturnPath(pair[1])
        }
        if round % 5 == 0 { try await Task.sleep(nanoseconds: 20_000_000) }
        let sample = try await gateway.eventLoop.submit {
            (
                tcp: gateway.tcp.establishedCount,
                udp: gateway.udp.flowCount,
                registrations: gateway.stack.transportDemuxer.registrationCountForTesting
            )
        }.get()
        peakTCP = max(peakTCP, sample.tcp)
        peakUDP = max(peakUDP, sample.udp)
        peakRegistrations = max(peakRegistrations, sample.registrations)
    }
    // Wait for the gateway to have PROCESSED the flood, rather than for a fixed
    // interval to pass.
    //
    // A fixed settle worked on an idle machine and failed when the whole suite
    // ran: the loop had simply not got to the frames yet, and the positive
    // controls below failed for a reason that had nothing to do with the
    // gateway. Waiting on the counters is waiting for the thing actually being
    // measured -- and it finishes as soon as it is true, so the idle case does
    // not pay for the loaded one.
    for _ in 0..<600 {
        drainReturnPath(pair[1], limit: 400)
        let arrived = try await gateway.eventLoop.submit {
            gateway.dhcp.leaseCount > 0 && gateway.dns.refusedForNoUpstream > 0
                && (gateway.tcp.refusedForDial + gateway.tcp.refusedForLimit) > 0
        }.get()
        if arrived { break }
        try await Task.sleep(nanoseconds: 10_000_000)
    }
    drainReturnPath(pair[1], limit: 4000)

    // A POSITIVE CONTROL first, because without one this test passes against a
    // gateway that dropped every frame on the floor -- which is exactly what a
    // soak whose only assertions are upper bounds cannot tell from success.
    // The flood contains DHCP DISCOVERs under forged hardware addresses, so the
    // lease pool must have been drawn on; and SYNs to addresses nothing is
    // listening on, so the forwarder must have tried to dial.
    // A POSITIVE CONTROL first, because without one this test passes against a
    // gateway that dropped every frame on the floor -- which is exactly what a
    // soak whose only assertions are upper bounds cannot tell from success.
    let reached = try await gateway.eventLoop.submit {
        (
            leases: gateway.dhcp.leaseCount,
            dialled: gateway.tcp.refusedForDial + gateway.tcp.refusedForLimit,
            refusedNames: gateway.dns.refusedForNoUpstream
        )
    }.get()
    #expect(reached.leases > 0, "no DHCP request reached the server: the flood went nowhere")
    #expect(reached.refusedNames > 0, "no DNS query reached the server")
    #expect(reached.dialled > 0, "no connection attempt reached the forwarder")

    // Still there, and still answering: the strongest single statement this can
    // make, because it fails on a trap, a hang, and a wedged datapath alike.
    let alive = try await gateway.eventLoop.submit { gateway.stack.nic.addresses }.get()
    #expect(alive.contains(IPv4Address("192.168.127.1")!))

    // And every bound the guest was pushing on held, at its peak.
    //
    // Both are guarded: removing either bound fails this, and the TCP one found
    // a defect the single-bound test could not. `aGuestCannotOpenMoreConnections
    // ThanTheLimitAllows` opens connections one at a time, so it never has two
    // dials in flight at once and never sees that the slot was taken at the
    // SPLICE rather than at the decision -- which let the bound be exceeded by
    // however many dials were connecting. This measured 33 against a limit of
    // 32, and that figure was a property of how fast the dials happened to
    // complete rather than of anything in the code.
    //
    // Peaks, not final values: reclaim runs while the flood does, so a bound
    // read afterwards can be well under the highest it reached.
    #expect(peakTCP <= 32, "the TCP connection bound was exceeded: \(peakTCP)")
    #expect(peakUDP <= 32, "the UDP flow bound was exceeded: \(peakUDP)")
    // The demuxer's table is where every endpoint the guest caused to exist
    // ends up, so it is the one number that catches a leak in any of them.
    #expect(peakRegistrations < 5000, "the endpoint table grew unbounded: \(peakRegistrations)")

    try? await listener.close()
    _ = try? await gateway.close().get()
    close(pair[1])
    try? await group.shutdownGracefully()
}
