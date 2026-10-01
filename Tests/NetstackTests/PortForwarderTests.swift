import NIOCore
import NIOPosix
import Testing

@testable import Netstack

#if canImport(Darwin)
    import Darwin
#else
    import Glibc
#endif

// The mirror image of the outbound path: something on the host dials, and this
// process opens a connection INTO the guest for it. Without this, a service in
// the guest is reachable only from the guest, and "publish a port" has no
// meaning -- the guest's address is on a subnet that exists only in this
// process.

private let pfGuest = IPv4Address("192.168.127.2")!
private let pfGateway = IPv4Address("192.168.127.1")!
private let pfGuestMAC = MACAddress("0a:0b:0c:0d:0e:0f")!
private let pfGatewayMAC = MACAddress("5a:94:ef:e4:0c:ee")!

private final class PFHolder: @unchecked Sendable {
    var stack: Stack?
    var forwarder: PortForwarder?
    var link: WireLinkEndpoint?
}

private func portForwardingGateway(
    group: EventLoopGroup, guestSide: inout Int32, guestPort: UInt16, maximumConnections: Int = 256
) async throws -> PFHolder {
    var pair: [Int32] = [0, 0]
    #expect(makeSocketPair(AF_UNIX, .datagram, &pair) == 0)
    guestSide = pair[1]
    let link = try await WireBootstrap.adoptingDatagramSocket(
        pair[0], group: group, linkAddress: pfGatewayMAC, mtu: 1500
    ).get()
    let holder = PFHolder()
    holder.link = link
    try await link.eventLoop.submit {
        let stack = Stack(
            link: link,
            configuration: Stack.Configuration(
                gatewayAddress: pfGateway, subnet: IPv4Subnet(cidr: "192.168.127.0/24")!))
        stack.start()
        stack.arpCache.record(pfGuest, pfGuestMAC)
        holder.stack = stack
        holder.forwarder = PortForwarder(
            stack: stack, guestAddress: pfGuest, guestPort: guestPort,
            maximumConnections: maximumConnections)
    }.get()
    try await holder.forwarder!.listen(port: 0).get()
    return holder
}

/// Segments the gateway put on the wire.
private func pfDrain(_ fd: Int32) -> [(header: TCPHeader, payload: ByteBuffer)] {
    var out: [(header: TCPHeader, payload: ByteBuffer)] = []
    for _ in 0..<64 {
        var back = [UInt8](repeating: 0, count: 4096)
        let read = back.withUnsafeMutableBytes { recv(fd, $0.baseAddress, $0.count, dontWait) }
        guard read > 0 else { break }
        var packet = PacketBuffer(received: ByteBuffer(bytes: back[0..<read]))
        guard let ethernet = EthernetHeader.parse(&packet), ethernet.etherType == .ipv4 else { continue }
        guard let ip = IPv4Header.parse(&packet), ip.protocolNumber == .tcp else { continue }
        guard let tcp = TCPHeader.parse(&packet, header: ip) else { continue }
        out.append((tcp, packet.payload))
    }
    return out
}

private func pfAwait(
    _ fd: Int32, where predicate: ([(header: TCPHeader, payload: ByteBuffer)]) -> Bool
) async -> [(header: TCPHeader, payload: ByteBuffer)] {
    var collected: [(header: TCPHeader, payload: ByteBuffer)] = []
    for _ in 0..<400 {
        collected += pfDrain(fd)
        if predicate(collected) { return collected }
        try? await Task.sleep(nanoseconds: 5_000_000)
    }
    return collected
}

/// A segment from the guest, answering the gateway.
private func pfGuestSegment(
    sourcePort: UInt16, destinationPort: UInt16, sequence: UInt32, acknowledgement: UInt32,
    flags: TCPFlags, payload: [UInt8] = []
) -> [UInt8] {
    let allocator = ByteBufferAllocator()
    let header = TCPHeader(
        sourcePort: sourcePort, destinationPort: destinationPort,
        sequence: SequenceNumber(sequence), acknowledgement: SequenceNumber(acknowledgement),
        dataOffset: 5, flags: flags, window: 65535, checksum: 0, urgentPointer: 0, options: [])
    let segment = header.serialize(
        payload: ByteBuffer(bytes: payload), source: pfGuest, destination: pfGateway, allocator: allocator)
    var packet = PacketBuffer(allocator: allocator, payload: segment)
    IPv4Header(source: pfGuest, destination: pfGateway, protocolNumber: .tcp, payloadLength: segment.readableBytes)
        .prepend(to: &packet)
    EthernetHeader(destination: pfGatewayMAC, source: pfGuestMAC, etherType: .ipv4).prepend(to: &packet)
    return Array(packet.frame.readableBytesView)
}

@Test func aHostConnectionOpensOneIntoTheGuestAndCarriesBytes() async throws {
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    var guestSide: Int32 = -1
    let holder = try await portForwardingGateway(group: group, guestSide: &guestSide, guestPort: 8080)
    let hostPort = holder.forwarder!.listeningAddress!.port!

    // Something on the host dials the published port.
    let dialler = try await ClientBootstrap(group: group)
        .connect(host: "127.0.0.1", port: hostPort).get()

    // The gateway should now be dialling the guest.
    let syn = await pfAwait(guestSide) { $0.contains { $0.header.flags.contains(.syn) } }
    let opening = try #require(syn.first { $0.header.flags.contains(.syn) })
    #expect(!opening.header.flags.contains(.ack), "the gateway sent a SYN-ACK where a SYN belonged")
    #expect(opening.header.destinationPort == 8080, "the connection went to the wrong guest port")
    let gatewayISS = opening.header.sequence.value
    let guestPortUsed = opening.header.sourcePort

    // The guest accepts.
    let guestISS: UInt32 = 5000
    let bytes = pfGuestSegment(
        sourcePort: 8080, destinationPort: guestPortUsed, sequence: guestISS,
        acknowledgement: gatewayISS &+ 1, flags: [.syn, .ack])
    _ = bytes.withUnsafeBytes { send(guestSide, $0.baseAddress, $0.count, 0) }

    // The host writes; the bytes should reach the guest.
    var out = dialler.allocator.buffer(capacity: 5)
    out.writeString("hello")
    try await dialler.writeAndFlush(out)

    let data = await pfAwait(guestSide) { $0.contains { $0.payload.readableBytes > 0 } }
    let carried = data.first { $0.payload.readableBytes > 0 }
    #expect(
        carried.map { String(decoding: $0.payload.readableBytesView, as: UTF8.self) } == "hello",
        "the host's bytes did not reach the guest")

    try? await dialler.close()
    holder.forwarder?.close()
    _ = try? await holder.stack?.shutdown().get()
    _ = try? await holder.link?.close().get()
    close(guestSide)
    try? await group.shutdownGracefully()
    _ = holder.stack
}

@Test func aHostConnectionPastTheLimitIsClosedRatherThanQueued() async throws {
    // A host connection this gateway will not serve should fail now: the dialler
    // learns immediately, and nothing is held here waiting for room that may
    // never come.
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    var guestSide: Int32 = -1
    let holder = try await portForwardingGateway(
        group: group, guestSide: &guestSide, guestPort: 8080, maximumConnections: 1)
    let hostPort = holder.forwarder!.listeningAddress!.port!

    let first = try await ClientBootstrap(group: group).connect(host: "127.0.0.1", port: hostPort).get()
    _ = await pfAwait(guestSide) { $0.contains { $0.header.flags.contains(.syn) } }

    let second = try await ClientBootstrap(group: group).connect(host: "127.0.0.1", port: hostPort).get()
    // The second is accepted by the kernel and closed by us, which the dialler
    // sees as the connection ending.
    for _ in 0..<400 where second.isActive {
        try? await Task.sleep(nanoseconds: 5_000_000)
    }
    #expect(!second.isActive, "a connection past the limit was kept")
    let refused = try await holder.link!.eventLoop.submit { holder.forwarder?.refusedForLimit ?? 0 }.get()
    #expect(refused == 1)

    try? await first.close()
    holder.forwarder?.close()
    _ = try? await holder.stack?.shutdown().get()
    _ = try? await holder.link?.close().get()
    close(guestSide)
    try? await group.shutdownGracefully()
    _ = holder.stack
}

@Test func aGuestThatRefusesTheConnectionEndsTheHostsToo() async throws {
    // The only means a TCP server has of saying no to a dialler that has already
    // connected: the connection goes away. Leaving it open would present as a
    // service that accepts and never answers.
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    var guestSide: Int32 = -1
    let holder = try await portForwardingGateway(group: group, guestSide: &guestSide, guestPort: 8080)
    let hostPort = holder.forwarder!.listeningAddress!.port!

    let dialler = try await ClientBootstrap(group: group).connect(host: "127.0.0.1", port: hostPort).get()
    let syn = await pfAwait(guestSide) { $0.contains { $0.header.flags.contains(.syn) } }
    let opening = try #require(syn.first { $0.header.flags.contains(.syn) })

    // The guest resets it.
    let bytes = pfGuestSegment(
        sourcePort: 8080, destinationPort: opening.header.sourcePort, sequence: 0,
        acknowledgement: opening.header.sequence.value &+ 1, flags: [.rst, .ack])
    _ = bytes.withUnsafeBytes { send(guestSide, $0.baseAddress, $0.count, 0) }

    for _ in 0..<400 where dialler.isActive {
        try? await Task.sleep(nanoseconds: 5_000_000)
    }
    #expect(!dialler.isActive, "the host's connection outlived the guest's refusal")

    holder.forwarder?.close()
    _ = try? await holder.stack?.shutdown().get()
    _ = try? await holder.link?.close().get()
    close(guestSide)
    try? await group.shutdownGracefully()
    _ = holder.stack
}

@Test func aHostDatagramReachesTheGuestAndTheReplyGoesBackToItsSender() async throws {
    // UDP forwarding end to end. The control-plane test checks the bookkeeping;
    // this checks that a datagram actually crosses, in both directions, and that
    // the reply reaches the sender rather than being dropped for want of anything
    // to match it to.
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    var pair: [Int32] = [0, 0]
    #expect(makeSocketPair(AF_UNIX, .datagram, &pair) == 0)
    let guestSide = pair[1]
    defer { close(guestSide) }
    let link = try await WireBootstrap.adoptingDatagramSocket(
        pair[0], group: group, linkAddress: pfGatewayMAC, mtu: 1500
    ).get()
    let holder = PFHolder()
    holder.link = link
    let forwarder = try await link.eventLoop.submit { () -> UDPPortForwarder in
        let stack = Stack(
            link: link,
            configuration: Stack.Configuration(
                gatewayAddress: pfGateway, subnet: IPv4Subnet(cidr: "192.168.127.0/24")!))
        stack.start()
        stack.arpCache.record(pfGuest, pfGuestMAC)
        holder.stack = stack
        return UDPPortForwarder(stack: stack, guestAddress: pfGuest, guestPort: 9999)
    }.get()
    try await forwarder.listen(port: 0).get()
    let hostPort = forwarder.listeningAddress!.port!

    // A host sender, bound so it can be replied to.
    let sender = makeSocket(AF_INET, .datagram)
    #expect(sender >= 0)
    defer { close(sender) }
    _ = sendTo(sender, Array("ping".utf8), loopbackAddress(port: UInt16(hostPort)))

    // It should arrive at the guest, on the guest port that was published.
    var arrived: (source: UInt16, payload: [UInt8])?
    for _ in 0..<400 where arrived == nil {
        var back = [UInt8](repeating: 0, count: 4096)
        let read = back.withUnsafeMutableBytes { recv(guestSide, $0.baseAddress, $0.count, dontWait) }
        if read > 0 {
            var packet = PacketBuffer(received: ByteBuffer(bytes: back[0..<read]))
            guard let ethernet = EthernetHeader.parse(&packet), ethernet.etherType == .ipv4,
                let ip = IPv4Header.parse(&packet), ip.protocolNumber == .udp,
                let udp = UDPHeader.parse(&packet, header: ip), udp.destinationPort == 9999
            else { continue }
            arrived = (udp.sourcePort, Array(packet.payload.readableBytesView))
        } else {
            try? await Task.sleep(nanoseconds: 5_000_000)
        }
    }
    let request = try #require(arrived, "the host's datagram never reached the guest")
    #expect(String(decoding: request.payload, as: UTF8.self) == "ping")

    // The guest answers to the port the gateway used, which is what the reply
    // has to be matched by.
    let reply = udpGuestDatagram(
        sourcePort: 9999, destinationPort: request.source, payload: Array("pong".utf8))
    _ = reply.withUnsafeBytes { send(guestSide, $0.baseAddress, $0.count, 0) }

    var answer = [UInt8](repeating: 0, count: 128)
    var received = -1
    for _ in 0..<400 where received <= 0 {
        received = answer.withUnsafeMutableBytes { recv(sender, $0.baseAddress, $0.count, dontWait) }
        if received <= 0 { try? await Task.sleep(nanoseconds: 5_000_000) }
    }
    #expect(received == 4, "the guest's reply never came back to the host sender")
    #expect(String(decoding: answer[0..<max(0, received)], as: UTF8.self) == "pong")

    _ = try? await forwarder.close().get()
    _ = try? await holder.stack?.shutdown().get()
    _ = try? await holder.link?.close().get()
    try? await group.shutdownGracefully()
    _ = holder.stack
}

/// One UDP datagram from the guest to the gateway.
private func udpGuestDatagram(sourcePort: UInt16, destinationPort: UInt16, payload: [UInt8]) -> [UInt8] {
    let allocator = ByteBufferAllocator()
    let datagram = UDPHeader.serialize(
        payload: ByteBuffer(bytes: payload), source: pfGuest, destination: pfGateway,
        sourcePort: sourcePort, destinationPort: destinationPort, allocator: allocator)!
    var packet = PacketBuffer(allocator: allocator, payload: datagram)
    IPv4Header(
        source: pfGuest, destination: pfGateway, protocolNumber: .udp,
        payloadLength: datagram.readableBytes
    ).prepend(to: &packet)
    EthernetHeader(destination: pfGatewayMAC, source: pfGuestMAC, etherType: .ipv4).prepend(to: &packet)
    return Array(packet.frame.readableBytesView)
}

@Test func udpFlowsAreBoundedAndIdleOnesAreReclaimed() async throws {
    // UDP has no connections, so nothing here ends on its own. The peer is
    // whatever can reach the listening socket, and a sender that varies its
    // source port makes a new flow per datagram -- so without a bound one host
    // process makes this table grow without limit, and without a timeout the
    // bound turns into a permanent refusal rather than a temporary one.
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    var pair: [Int32] = [0, 0]
    #expect(makeSocketPair(AF_UNIX, .datagram, &pair) == 0)
    defer { close(pair[1]) }
    let link = try await WireBootstrap.adoptingDatagramSocket(
        pair[0], group: group, linkAddress: pfGatewayMAC, mtu: 1500
    ).get()
    let holder = PFHolder()
    holder.link = link
    let clock = ManualClock()
    let forwarder = try await link.eventLoop.submit { () -> UDPPortForwarder in
        let stack = Stack(
            link: link,
            configuration: Stack.Configuration(
                gatewayAddress: pfGateway, subnet: IPv4Subnet(cidr: "192.168.127.0/24")!),
            clock: clock)
        stack.start()
        stack.arpCache.record(pfGuest, pfGuestMAC)
        holder.stack = stack
        return UDPPortForwarder(
            stack: stack, guestAddress: pfGuest, guestPort: 9999, maximumFlows: 2,
            idleTimeout: .seconds(60))
    }.get()
    try await forwarder.listen(port: 0).get()
    let hostPort = forwarder.listeningAddress!.port!

    /// One datagram from a socket of its own, so each has its own source port
    /// and is therefore its own flow.
    func sendFromANewSocket() {
        let fd = makeSocket(AF_INET, .datagram)
        defer { close(fd) }
        _ = sendTo(fd, Array("x".utf8), loopbackAddress(port: UInt16(hostPort)))
    }

    for _ in 0..<12 { sendFromANewSocket() }
    var flows = 0
    for _ in 0..<200 where flows < 2 {
        flows = try await link.eventLoop.submit { forwarder.flowCount }.get()
        if flows < 2 { try? await Task.sleep(nanoseconds: 5_000_000) }
    }
    let settled = try await link.eventLoop.submit { forwarder.flowCount }.get()
    #expect(settled == 2, "the flow table grew to \(settled) against a limit of 2")
    let refused = try await link.eventLoop.submit { forwarder.refusedForLimit }.get()
    #expect(refused > 0, "twelve senders against a limit of two refused none")

    // Time passes with nothing sent, and the next datagram finds room: the
    // bound is a limit on concurrent flows, not a lifetime quota.
    clock.advance(by: .seconds(120))
    sendFromANewSocket()
    var reclaimed = 0
    for _ in 0..<200 where reclaimed == 0 {
        reclaimed = try await link.eventLoop.submit { forwarder.reclaimed }.get()
        if reclaimed == 0 { try? await Task.sleep(nanoseconds: 5_000_000) }
    }
    #expect(reclaimed >= 2, "idle flows were never reclaimed")

    _ = try? await forwarder.close().get()
    _ = try? await holder.stack?.shutdown().get()
    _ = try? await holder.link?.close().get()
    try? await group.shutdownGracefully()
    _ = holder.stack
}

@Test func aResetFromTheGuestReleasesTheSlotOfAHalfClosedForward() async throws {
    // With half-closure, the host hanging up no longer ends the guest side: it
    // sends a FIN and waits. So the slot is held until the guest agrees, and
    // the fastest way a guest says "I am finished" is a reset. If this does not
    // release the slot, nothing about the churn accounting below is measuring
    // what it claims to.
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    var guestSide: Int32 = -1
    let holder = try await portForwardingGateway(
        group: group, guestSide: &guestSide, guestPort: 8080, maximumConnections: 8)
    let hostPort = holder.forwarder!.listeningAddress!.port!

    let dialler = try await ClientBootstrap(group: group)
        .connect(host: "127.0.0.1", port: hostPort).get()
    let syn = await pfAwait(guestSide) { $0.contains { $0.header.flags.contains(.syn) } }
    let opening = try #require(syn.first { $0.header.flags.contains(.syn) })
    let accept = pfGuestSegment(
        sourcePort: 8080, destinationPort: opening.header.sourcePort, sequence: 5000,
        acknowledgement: opening.header.sequence.value &+ 1, flags: [.syn, .ack])
    _ = accept.withUnsafeBytes { send(guestSide, $0.baseAddress, $0.count, 0) }

    try? await dialler.close()
    // The gateway's FIN first: the reset is the guest's answer to it, and
    // sending it before the FIN has been seen would leave the test passing
    // for a reason it does not name.
    _ = await pfAwait(guestSide) { $0.contains { $0.header.flags.contains(.fin) } }
    let reset = pfGuestSegment(
        sourcePort: 8080, destinationPort: opening.header.sourcePort, sequence: 5001,
        acknowledgement: 0, flags: [.rst])
    _ = reset.withUnsafeBytes { send(guestSide, $0.baseAddress, $0.count, 0) }

    var settled = -1
    for _ in 0..<200 where settled != 0 {
        settled = try await holder.stack!.eventLoop.submit { holder.forwarder!.establishedCount }.get()
        if settled != 0 { try? await Task.sleep(nanoseconds: 10_000_000) }
    }
    #expect(settled == 0, "the reset left \(settled) slots held")

    holder.forwarder?.close()
    _ = try? await holder.stack?.shutdown().get()
    _ = try? await holder.link?.close().get()
    close(guestSide)
    try? await group.shutdownGracefully()
    _ = holder.stack
}

@Test func hostSideSlotsAreReturnedExactlyOnceAcrossManyConnections() async throws {
    // The mirror of the outbound forwarder's churn test, and the same hand-kept
    // counter: taken when a host connection is accepted, returned by whichever
    // of two close futures fires first.
    //
    // The failure paths here are different from the outbound side's, which is
    // why it needs its own: the guest may never answer the SYN, and the host may
    // hang up before it does.
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    var guestSide: Int32 = -1
    let holder = try await portForwardingGateway(
        group: group, guestSide: &guestSide, guestPort: 8080, maximumConnections: 8)
    let hostPort = holder.forwarder!.listeningAddress!.port!

    var peak = 0
    for round in 0..<100 {
        let dialler = try await ClientBootstrap(group: group)
            .connect(host: "127.0.0.1", port: hostPort).get()

        let syn = await pfAwait(guestSide) { $0.contains { $0.header.flags.contains(.syn) } }
        // Half the rounds the guest accepts; half it never answers and the host
        // hangs up first. Both have to return the slot.
        var lastGuestPort: UInt16 = 0
        if round % 2 == 0, let opening = syn.first(where: { $0.header.flags.contains(.syn) }) {
            lastGuestPort = opening.header.sourcePort
            let bytes = pfGuestSegment(
                sourcePort: 8080, destinationPort: opening.header.sourcePort, sequence: 5000,
                acknowledgement: opening.header.sequence.value &+ 1, flags: [.syn, .ack])
            _ = bytes.withUnsafeBytes { send(guestSide, $0.baseAddress, $0.count, 0) }
        }
        try? await dialler.close()
        if round % 2 == 0 {
            _ = await pfAwait(guestSide) { $0.contains { $0.header.flags.contains(.fin) } }
            // The host hanging up is a FIN, and a FIN is half of a close: the
            // guest side is left able to answer, which is the whole point of
            // half-closure. So the guest has to hang up too, and a reset is how
            // a guest that is finished says so without a four-way exchange this
            // test would otherwise have to sequence by hand. Its sequence is
            // exactly `rcv.nxt` -- the SYN-ACK at 5000 consumed one -- because a
            // reset outside the window is correctly ignored.
            let bytes = pfGuestSegment(
                sourcePort: 8080, destinationPort: lastGuestPort, sequence: 5001,
                acknowledgement: 0, flags: [.rst])
            _ = bytes.withUnsafeBytes { send(guestSide, $0.baseAddress, $0.count, 0) }
        }
        _ = pfDrain(guestSide)

        let live = try await holder.stack!.eventLoop.submit { holder.forwarder!.establishedCount }.get()
        peak = max(peak, live)
    }

    #expect(peak <= 8, "the live count reached \(peak) against a limit of 8")

    var settled = -1
    for _ in 0..<400 where settled != 0 {
        settled = try await holder.stack!.eventLoop.submit { holder.forwarder!.establishedCount }.get()
        if settled != 0 { try? await Task.sleep(nanoseconds: 10_000_000) }
    }
    #expect(settled == 0, "\(settled) slots were never returned after 100 connections")
    // The floor: the limit was never hit, so the churn was slots being returned
    // rather than connections being refused.
    #expect(holder.forwarder?.refusedForLimit == 0, "connections were refused, so nothing was churned")

    holder.forwarder?.close()
    _ = try? await holder.stack?.shutdown().get()
    _ = try? await holder.link?.close().get()
    close(guestSide)
    try? await group.shutdownGracefully()
    _ = holder.stack
}

// MARK: - Source-address propagation (upstream f9306b96)
//
// The guest should see who dialled a published port, not the gateway. Loopback
// is the exception that has to hold: the guest answers the source address
// through the gateway, and an answer to 127.0.0.1 on a real guest's link is a
// martian it drops. A loopback socket cannot present any other address, so the
// non-loopback cases hand the forwarder one through its seam and watch what the
// guest is sent; the loopback cases use the real socket's own address.

private let pfClient = IPv4Address("10.1.2.3")!
// Not 40000: that is where `UDPPortForwarder` starts stepping its own ports, and
// a client there could not tell propagation from the fallback.
private let pfClientPort: UInt16 = 51234

/// Segments the gateway put on the wire, with the IP addresses they carried.
private func pfAwaitAddressed(
    _ fd: Int32, where predicate: ([(ip: IPv4Header, tcp: TCPHeader, payload: ByteBuffer)]) -> Bool
) async -> [(ip: IPv4Header, tcp: TCPHeader, payload: ByteBuffer)] {
    var collected: [(ip: IPv4Header, tcp: TCPHeader, payload: ByteBuffer)] = []
    for _ in 0..<400 {
        for _ in 0..<64 {
            var back = [UInt8](repeating: 0, count: 4096)
            let read = back.withUnsafeMutableBytes { recv(fd, $0.baseAddress, $0.count, dontWait) }
            guard read > 0 else { break }
            var packet = PacketBuffer(received: ByteBuffer(bytes: back[0..<read]))
            guard let ethernet = EthernetHeader.parse(&packet), ethernet.etherType == .ipv4,
                let ip = IPv4Header.parse(&packet), ip.protocolNumber == .tcp,
                let tcp = TCPHeader.parse(&packet, header: ip)
            else { continue }
            collected.append((ip, tcp, packet.payload))
        }
        if predicate(collected) { return collected }
        try? await Task.sleep(nanoseconds: 5_000_000)
    }
    return collected
}

/// A segment from the guest to any address, which is what answering a
/// propagated source takes: it is addressed past the gateway, and reaches it
/// only because the gateway is the guest's default route.
private func pfGuestSegment(
    to destination: IPv4Address, sourcePort: UInt16, destinationPort: UInt16, sequence: UInt32,
    acknowledgement: UInt32, flags: TCPFlags, payload: [UInt8] = []
) -> [UInt8] {
    let allocator = ByteBufferAllocator()
    let header = TCPHeader(
        sourcePort: sourcePort, destinationPort: destinationPort,
        sequence: SequenceNumber(sequence), acknowledgement: SequenceNumber(acknowledgement),
        dataOffset: 5, flags: flags, window: 65535, checksum: 0, urgentPointer: 0, options: [])
    let segment = header.serialize(
        payload: ByteBuffer(bytes: payload), source: pfGuest, destination: destination, allocator: allocator)
    var packet = PacketBuffer(allocator: allocator, payload: segment)
    IPv4Header(source: pfGuest, destination: destination, protocolNumber: .tcp, payloadLength: segment.readableBytes)
        .prepend(to: &packet)
    EthernetHeader(destination: pfGatewayMAC, source: pfGuestMAC, etherType: .ipv4).prepend(to: &packet)
    return Array(packet.frame.readableBytesView)
}

/// Collects what a host-side channel reads.
private final class PFCollector: ChannelInboundHandler, @unchecked Sendable {
    // `@unchecked`: `received` is written only on the channel's loop and read
    // by the test through `channel.eventLoop.submit`, so every access is on
    // that one loop.
    typealias InboundIn = ByteBuffer
    var received = ""

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var buffer = unwrapInboundIn(data)
        received += buffer.readString(length: buffer.readableBytes) ?? ""
    }
}

@Test func aForwardedConnectionReachesTheGuestFromTheClientsAddressAndStillCarriesBothWays() async throws {
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    var guestSide: Int32 = -1
    let holder = try await portForwardingGateway(group: group, guestSide: &guestSide, guestPort: 8080)
    // The guest's egress forwarder, as `Gateway` installs it, so the guest's
    // answer to an address past the gateway has to get past it before it
    // reaches the connection that is waiting for it.
    let egress = try await holder.stack!.eventLoop.submit { () -> OutboundTCPForwarder in
        let stack = holder.stack!
        holder.forwarder!.clientAddress = { _ in
            try? SocketAddress(ipAddress: pfClient.description, port: Int(pfClientPort))
        }
        return OutboundTCPForwarder(stack: stack)
    }.get()
    let hostPort = holder.forwarder!.listeningAddress!.port!

    let collector = PFCollector()
    let dialler = try await ClientBootstrap(group: group)
        .channelInitializer { $0.pipeline.addHandler(collector) }
        .connect(host: "127.0.0.1", port: hostPort).get()

    let syn = await pfAwaitAddressed(guestSide) { $0.contains { $0.tcp.flags.contains(.syn) } }
    let opening = try #require(syn.first { $0.tcp.flags.contains(.syn) }, "the gateway never dialled the guest")
    #expect(
        opening.ip.source == pfClient,
        "the guest saw the connection come from \(opening.ip.source), not the client at \(pfClient)")
    #expect(opening.tcp.sourcePort == pfClientPort, "the guest saw source port \(opening.tcp.sourcePort)")

    // The guest answers the client's address. It reaches the gateway only as
    // its default route; if nothing here is waiting for it, the handshake
    // never completes and the guest sees the right address on a dead
    // connection.
    let accept = pfGuestSegment(
        to: pfClient, sourcePort: 8080, destinationPort: opening.tcp.sourcePort, sequence: 5000,
        acknowledgement: opening.tcp.sequence.value &+ 1, flags: [.syn, .ack])
    _ = accept.withUnsafeBytes { send(guestSide, $0.baseAddress, $0.count, 0) }

    var out = dialler.allocator.buffer(capacity: 5)
    out.writeString("hello")
    try await dialler.writeAndFlush(out)
    let data = await pfAwaitAddressed(guestSide) { $0.contains { $0.payload.readableBytes > 0 } }
    let carried = try #require(data.first { $0.payload.readableBytes > 0 }, "the host's bytes never reached the guest")
    #expect(String(decoding: carried.payload.readableBytesView, as: UTF8.self) == "hello")
    #expect(carried.ip.source == pfClient)

    // And back: the guest's bytes, addressed to the client, reach the dialler.
    let answer = pfGuestSegment(
        to: pfClient, sourcePort: 8080, destinationPort: opening.tcp.sourcePort, sequence: 5001,
        acknowledgement: opening.tcp.sequence.value &+ 6, flags: [.ack, .psh], payload: Array("world".utf8))
    _ = answer.withUnsafeBytes { send(guestSide, $0.baseAddress, $0.count, 0) }
    var received = ""
    for _ in 0..<400 where received != "world" {
        received = try await dialler.eventLoop.submit { collector.received }.get()
        if received != "world" { try? await Task.sleep(nanoseconds: 5_000_000) }
    }
    #expect(received == "world", "the guest's answer never reached the host client")

    try? await dialler.close()
    holder.forwarder?.close()
    _ = try? await holder.stack?.shutdown().get()
    _ = try? await holder.link?.close().get()
    close(guestSide)
    try? await group.shutdownGracefully()
    _ = holder.stack
    _ = egress
}

@Test func aLoopbackClientStillReachesTheGuestFromTheGateway() async throws {
    // The control. 127.0.0.1 propagated would be a martian to a real guest,
    // and the forward everyone uses -- 127.0.0.1:2222 to the guest's 22 --
    // would stop working.
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    var guestSide: Int32 = -1
    let holder = try await portForwardingGateway(group: group, guestSide: &guestSide, guestPort: 8080)
    let hostPort = holder.forwarder!.listeningAddress!.port!

    let dialler = try await ClientBootstrap(group: group).connect(host: "127.0.0.1", port: hostPort).get()
    let syn = await pfAwaitAddressed(guestSide) { $0.contains { $0.tcp.flags.contains(.syn) } }
    let opening = try #require(syn.first { $0.tcp.flags.contains(.syn) }, "the gateway never dialled the guest")
    #expect(opening.ip.source == pfGateway, "a loopback client reached the guest from \(opening.ip.source)")

    try? await dialler.close()
    holder.forwarder?.close()
    _ = try? await holder.stack?.shutdown().get()
    _ = try? await holder.link?.close().get()
    close(guestSide)
    try? await group.shutdownGracefully()
    _ = holder.stack
}

@Test func onlyRoutableIPv4ClientsArePropagated() async throws {
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    var guestSide: Int32 = -1
    let holder = try await portForwardingGateway(group: group, guestSide: &guestSide, guestPort: 8080)
    let results = try await holder.stack!.eventLoop.submit { () -> [String: String] in
        let stack = holder.stack!
        func bound(_ ip: String, _ port: Int) -> String {
            let address = try? SocketAddress(ipAddress: ip, port: port)
            return ForwardedSource.binding(for: address, on: stack).map { "\($0.address):\($0.port)" } ?? "gateway"
        }
        return [
            "10.0.2.50": bound("10.0.2.50", 1234),
            "::ffff:10.0.2.50": bound("::ffff:10.0.2.50", 1234),
            "127.0.0.1": bound("127.0.0.1", 2222),
            "127.1.2.3": bound("127.1.2.3", 2222),
            "::ffff:127.0.0.1": bound("::ffff:127.0.0.1", 2222),
            "0.0.0.0": bound("0.0.0.0", 0),
            "::1": bound("::1", 2222),
            "2001:db8::1": bound("2001:db8::1", 2222),
        ]
    }.get()
    #expect(results["10.0.2.50"] == "10.0.2.50:1234")
    #expect(results["::ffff:10.0.2.50"] == "10.0.2.50:1234")
    for kept in ["127.0.0.1", "127.1.2.3", "::ffff:127.0.0.1", "0.0.0.0", "::1", "2001:db8::1"] {
        #expect(results[kept] == "gateway", "\(kept) was propagated as \(results[kept] ?? "nil")")
    }
    // A unix-socket forward has no address to propagate at all.
    let unix = try SocketAddress(unixDomainSocketPath: "/tmp/x.sock")
    let unixResult = try await holder.stack!.eventLoop.submit {
        ForwardedSource.binding(for: unix, on: holder.stack!) == nil
    }.get()
    #expect(unixResult)

    holder.forwarder?.close()
    _ = try? await holder.stack?.shutdown().get()
    _ = try? await holder.link?.close().get()
    close(guestSide)
    try? await group.shutdownGracefully()
    _ = holder.stack
}

/// A UDP datagram from the guest to any address. See the TCP version above.
private func udpGuestDatagram(
    to destination: IPv4Address, sourcePort: UInt16, destinationPort: UInt16, payload: [UInt8]
) -> [UInt8] {
    let allocator = ByteBufferAllocator()
    let datagram = UDPHeader.serialize(
        payload: ByteBuffer(bytes: payload), source: pfGuest, destination: destination,
        sourcePort: sourcePort, destinationPort: destinationPort, allocator: allocator)!
    var packet = PacketBuffer(allocator: allocator, payload: datagram)
    IPv4Header(
        source: pfGuest, destination: destination, protocolNumber: .udp, payloadLength: datagram.readableBytes
    ).prepend(to: &packet)
    EthernetHeader(destination: pfGatewayMAC, source: pfGuestMAC, etherType: .ipv4).prepend(to: &packet)
    return Array(packet.frame.readableBytesView)
}

/// The first UDP datagram for `port` the gateway put on the wire.
private func pfAwaitDatagram(_ fd: Int32, toPort port: UInt16) async -> (ip: IPv4Header, udp: UDPHeader, payload: [UInt8])? {
    for _ in 0..<400 {
        var back = [UInt8](repeating: 0, count: 4096)
        let read = back.withUnsafeMutableBytes { recv(fd, $0.baseAddress, $0.count, dontWait) }
        if read > 0 {
            var packet = PacketBuffer(received: ByteBuffer(bytes: back[0..<read]))
            guard let ethernet = EthernetHeader.parse(&packet), ethernet.etherType == .ipv4,
                let ip = IPv4Header.parse(&packet), ip.protocolNumber == .udp,
                let udp = UDPHeader.parse(&packet, header: ip), udp.destinationPort == port
            else { continue }
            return (ip, udp, Array(packet.payload.readableBytesView))
        }
        try? await Task.sleep(nanoseconds: 5_000_000)
    }
    return nil
}

@Test func aForwardedDatagramReachesTheGuestFromTheSendersAddressAndTheReplyIsNotTakenForEgress() async throws {
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    var pair: [Int32] = [0, 0]
    #expect(makeSocketPair(AF_UNIX, .datagram, &pair) == 0)
    let guestSide = pair[1]
    defer { close(guestSide) }
    let link = try await WireBootstrap.adoptingDatagramSocket(
        pair[0], group: group, linkAddress: pfGatewayMAC, mtu: 1500
    ).get()
    let holder = PFHolder()
    holder.link = link
    let (forwarder, egress) = try await link.eventLoop.submit { () -> (UDPPortForwarder, UDPForwarder) in
        let stack = Stack(
            link: link,
            configuration: Stack.Configuration(
                gatewayAddress: pfGateway, subnet: IPv4Subnet(cidr: "192.168.127.0/24")!))
        stack.start()
        stack.arpCache.record(pfGuest, pfGuestMAC)
        holder.stack = stack
        // The guest's egress forwarder, as `Gateway` installs it. It sees every
        // datagram first, and the reply below is addressed past the gateway.
        return (UDPPortForwarder(stack: stack, guestAddress: pfGuest, guestPort: 9999), UDPForwarder(stack: stack))
    }.get()
    try await forwarder.listen(port: 0).get()

    let sender = try SocketAddress(ipAddress: pfClient.description, port: Int(pfClientPort))
    try await link.eventLoop.submit {
        forwarder.receive(ByteBuffer(string: "ping"), from: sender)
    }.get()

    let request = try #require(await pfAwaitDatagram(guestSide, toPort: 9999), "the datagram never reached the guest")
    #expect(
        request.ip.source == pfClient,
        "the guest saw the datagram come from \(request.ip.source), not the sender at \(pfClient)")
    #expect(request.udp.sourcePort == pfClientPort, "the guest saw source port \(request.udp.sourcePort)")
    #expect(String(decoding: request.payload, as: UTF8.self) == "ping")

    // The guest answers the address it was shown.
    let reply = udpGuestDatagram(
        to: request.ip.source, sourcePort: 9999, destinationPort: request.udp.sourcePort,
        payload: Array("pong".utf8))
    _ = reply.withUnsafeBytes { send(guestSide, $0.baseAddress, $0.count, 0) }

    var replies = 0
    for _ in 0..<400 where replies == 0 {
        replies = try await link.eventLoop.submit { forwarder.repliesForwarded }.get()
        if replies == 0 { try? await Task.sleep(nanoseconds: 5_000_000) }
    }
    #expect(replies == 1, "the guest's reply never reached the flow waiting for it")
    let leaked = try await link.eventLoop.submit { egress.openedSockets + egress.flowCount }.get()
    #expect(leaked == 0, "the guest's reply was opened as egress to the real network")

    _ = try? await forwarder.close().get()
    _ = try? await holder.stack?.shutdown().get()
    _ = try? await holder.link?.close().get()
    try? await group.shutdownGracefully()
    _ = holder.stack
    _ = egress
}

@Test func aLoopbackDatagramStillReachesTheGuestFromTheGateway() async throws {
    // The UDP control, through a real loopback socket.
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    var pair: [Int32] = [0, 0]
    #expect(makeSocketPair(AF_UNIX, .datagram, &pair) == 0)
    let guestSide = pair[1]
    defer { close(guestSide) }
    let link = try await WireBootstrap.adoptingDatagramSocket(
        pair[0], group: group, linkAddress: pfGatewayMAC, mtu: 1500
    ).get()
    let holder = PFHolder()
    holder.link = link
    let forwarder = try await link.eventLoop.submit { () -> UDPPortForwarder in
        let stack = Stack(
            link: link,
            configuration: Stack.Configuration(
                gatewayAddress: pfGateway, subnet: IPv4Subnet(cidr: "192.168.127.0/24")!))
        stack.start()
        stack.arpCache.record(pfGuest, pfGuestMAC)
        holder.stack = stack
        return UDPPortForwarder(stack: stack, guestAddress: pfGuest, guestPort: 9999)
    }.get()
    try await forwarder.listen(port: 0).get()
    let hostPort = forwarder.listeningAddress!.port!

    let sender = makeSocket(AF_INET, .datagram)
    #expect(sender >= 0)
    defer { close(sender) }
    _ = sendTo(sender, Array("ping".utf8), loopbackAddress(port: UInt16(hostPort)))

    let request = try #require(await pfAwaitDatagram(guestSide, toPort: 9999), "the datagram never reached the guest")
    #expect(request.ip.source == pfGateway, "a loopback sender reached the guest from \(request.ip.source)")

    _ = try? await forwarder.close().get()
    _ = try? await holder.stack?.shutdown().get()
    _ = try? await holder.link?.close().get()
    try? await group.shutdownGracefully()
    _ = holder.stack
}

@Test func onlyAnEndpointOnTheExactAddressKeepsADatagramFromTheEgressForwarder() async throws {
    // The egress forwarder steps aside for a datagram an endpoint here is bound
    // to exactly -- a propagated forward's flow. A wildcard bind must not count:
    // this stack's own service on 0.0.0.0:5353 is no claim on port 5353 at every
    // address the guest might reach.
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    var guestSide: Int32 = -1
    let holder = try await portForwardingGateway(group: group, guestSide: &guestSide, guestPort: 8080)
    let (wildcard, exact) = try await holder.stack!.eventLoop.submit { () -> (Bool, Bool) in
        let stack = holder.stack!
        let toClient = IPv4Header(source: pfGuest, destination: pfClient, protocolNumber: .udp, payloadLength: 8)
        let service = UDPEndpoint(stack: stack)
        try service.bind(address: .any, port: 5353)
        let wildcard = stack.transportDemuxer.hasEndpoint(
            protocolNumber: .udp, header: toClient, localPort: 5353, remotePort: 9999)
        let flow = UDPEndpoint(stack: stack)
        try flow.bind(address: pfClient, port: 5353)
        let exact = stack.transportDemuxer.hasEndpoint(
            protocolNumber: .udp, header: toClient, localPort: 5353, remotePort: 9999)
        _ = (service, flow)
        return (wildcard, exact)
    }.get()
    #expect(!wildcard, "a wildcard bind kept a guest's datagram to \(pfClient) from the egress forwarder")
    #expect(exact, "a flow bound to \(pfClient) was not seen")

    holder.forwarder?.close()
    _ = try? await holder.stack?.shutdown().get()
    _ = try? await holder.link?.close().get()
    close(guestSide)
    try? await group.shutdownGracefully()
    _ = holder.stack
}

@Test func aClientIsNotPropagatedWhereTheStackCouldNotSpeakForIt() async throws {
    // A stack that may not send from an address it does not own, or will not
    // take a packet addressed to one, would bind the connection to an address
    // it can neither speak from nor hear on. Both keep the gateway's address.
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    var outcomes: [String: Bool] = [:]
    for (name, spoofs, promiscuous) in [("no spoofing", false, true), ("not promiscuous", true, false), ("both", true, true)] {
        var pair: [Int32] = [0, 0]
        #expect(makeSocketPair(AF_UNIX, .datagram, &pair) == 0)
        let link = try await WireBootstrap.adoptingDatagramSocket(
            pair[0], group: group, linkAddress: pfGatewayMAC, mtu: 1500
        ).get()
        outcomes[name] = try await link.eventLoop.submit { () -> Bool in
            let stack = Stack(
                link: link,
                configuration: Stack.Configuration(
                    gatewayAddress: pfGateway, subnet: IPv4Subnet(cidr: "192.168.127.0/24")!,
                    acceptsAnyDestination: promiscuous, allowsAnySource: spoofs))
            let client = try? SocketAddress(ipAddress: "10.0.2.50", port: 1234)
            return ForwardedSource.binding(for: client, on: stack) != nil
        }.get()
        _ = try? await link.close().get()
        close(pair[1])
    }
    #expect(outcomes["no spoofing"] == false, "propagated on a stack that may not send from the client's address")
    #expect(outcomes["not promiscuous"] == false, "propagated on a stack that will not hear the guest's answer")
    #expect(outcomes["both"] == true, "the ordinary gateway configuration did not propagate")
    try? await group.shutdownGracefully()
}
