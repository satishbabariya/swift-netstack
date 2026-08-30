import NIOCore
import NIOPosix
import Testing

@testable import Netstack

#if canImport(Darwin)
    import Darwin
#else
    import Glibc
#endif

// The point of the whole package: a guest opens a TCP connection and it comes
// out of a real socket on the host.
//
// These tests use a real loopback listener rather than a stub, because the
// thing being tested is precisely the join between this stack and the operating
// system's -- and a stub on either side would be testing the join to the stub.

private let outboundGuestMAC = MACAddress("0a:0b:0c:0d:0e:0f")!
private let outboundGatewayMAC = MACAddress("5a:94:ef:e4:0c:ee")!

private final class Holder: @unchecked Sendable {
    var stack: Stack?
    var forwarder: OutboundTCPForwarder?
    var link: WireLinkEndpoint?
}

/// Everything a guest needs to reach the host: a socketpair for the wire, a
/// stack on it, and an outbound forwarder.
private func gateway(
    group: EventLoopGroup, guestSide: inout Int32, maximumConnections: Int = 1024,
    nat: [IPv4Address: IPv4Address] = [:], allowsLinkLocal: Bool = false
) async throws -> Holder {
    var pair: [Int32] = [0, 0]
    #expect(makeSocketPair(AF_UNIX, .datagram, &pair) == 0)
    guestSide = pair[1]
    let link = try await WireBootstrap.adoptingDatagramSocket(
        pair[0], group: group, linkAddress: outboundGatewayMAC, mtu: 1500
    ).get()
    let holder = Holder()
    holder.link = link
    try await link.eventLoop.submit {
        let stack = Stack(
            link: link,
            configuration: Stack.Configuration(
                gatewayAddress: IPv4Address("192.168.127.1")!,
                subnet: IPv4Subnet(cidr: "192.168.127.0/24")!))
        stack.start()
        // The guest's link address, which the gateway would otherwise have to
        // ARP for before it could answer anything.
        stack.arpCache.record(IPv4Address("192.168.127.2")!, outboundGuestMAC)
        holder.stack = stack
        holder.forwarder = OutboundTCPForwarder(
            stack: stack, maximumConnections: maximumConnections, nat: nat,
            allowsLinkLocal: allowsLinkLocal)
    }.get()
    return holder
}

/// One ethernet frame carrying one TCP segment from the guest.
private func guestFrame(
    to destination: IPv4Address, destinationPort: UInt16, sequence: UInt32, acknowledgement: UInt32 = 0,
    flags: TCPFlags, payload: [UInt8] = [], sourcePort: UInt16 = 50000
) -> [UInt8] {
    let allocator = ByteBufferAllocator()
    let header = TCPHeader(
        sourcePort: sourcePort, destinationPort: destinationPort,
        sequence: SequenceNumber(sequence), acknowledgement: SequenceNumber(acknowledgement),
        dataOffset: 5, flags: flags, window: 65535, checksum: 0, urgentPointer: 0, options: [])
    let source = IPv4Address("192.168.127.2")!
    let segment = header.serialize(
        payload: ByteBuffer(bytes: payload), source: source, destination: destination, allocator: allocator)
    var packet = PacketBuffer(allocator: allocator, payload: segment)
    IPv4Header(source: source, destination: destination, protocolNumber: .tcp, payloadLength: segment.readableBytes)
        .prepend(to: &packet)
    EthernetHeader(destination: outboundGatewayMAC, source: outboundGuestMAC, etherType: .ipv4)
        .prepend(to: &packet)
    return Array(packet.frame.readableBytesView)
}

/// Every TCP segment the gateway has emitted, drained without blocking.
private func drainSegments(_ fd: Int32) -> [(header: TCPHeader, payload: ByteBuffer)] {
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

private func send(_ fd: Int32, _ bytes: [UInt8]) {
    #expect(sendBytes(fd, bytes) == bytes.count)
}

/// Poll for segments rather than sleeping a fixed time: the work is on another
/// thread and its duration is not this test's to guess.
private func awaitSegments(
    _ fd: Int32, where predicate: ([(header: TCPHeader, payload: ByteBuffer)]) -> Bool
) async -> [(header: TCPHeader, payload: ByteBuffer)] {
    var collected: [(header: TCPHeader, payload: ByteBuffer)] = []
    for _ in 0..<400 {
        collected += drainSegments(fd)
        if predicate(collected) { return collected }
        try? await Task.sleep(nanoseconds: 5_000_000)
    }
    return collected
}

@Test func aGuestConnectionReachesARealListenerAndCarriesBytesBothWays() async throws {
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    var guestSide: Int32 = -1
    let holder = try await gateway(group: group, guestSide: &guestSide)

    // A real listener on loopback, echoing what it receives in upper case so
    // the bytes coming back cannot be the bytes that went out by accident.
    let listener = try await ServerBootstrap(group: group)
        .childChannelInitializer { channel in
            channel.pipeline.addHandler(UppercasingEcho())
        }
        .bind(host: "127.0.0.1", port: 0).get()
    let port = UInt16(listener.localAddress!.port!)

    // The guest dials it.
    send(
        guestSide,
        guestFrame(
            to: IPv4Address("127.0.0.1")!, destinationPort: port, sequence: 7000, flags: [.syn]))
    let synAck = await awaitSegments(guestSide) { $0.contains { $0.header.flags.contains(.syn) } }
    let answer = try #require(synAck.first { $0.header.flags.contains(.syn) })
    #expect(answer.header.flags.contains(.ack), "the SYN was not answered")
    let gatewayISS = answer.header.sequence.value

    // Third leg, then data.
    send(
        guestSide,
        guestFrame(
            to: IPv4Address("127.0.0.1")!, destinationPort: port, sequence: 7001,
            acknowledgement: gatewayISS &+ 1, flags: [.ack]))
    send(
        guestSide,
        guestFrame(
            to: IPv4Address("127.0.0.1")!, destinationPort: port, sequence: 7001,
            acknowledgement: gatewayISS &+ 1, flags: [.ack, .psh], payload: Array("hello".utf8)))

    let echoed = await awaitSegments(guestSide) { segments in
        segments.contains { $0.payload.readableBytes > 0 }
    }
    let data = echoed.first { $0.payload.readableBytes > 0 }
    let text = data.map { String(decoding: $0.payload.readableBytesView, as: UTF8.self) }
    #expect(text == "HELLO", "the listener's answer did not come back to the guest: \(String(describing: text))")

    try? await listener.close()
    // The forwarder owns the host socket this connection was spliced to, and
    // nothing else closes it: the guest side is going away with the link, but a
    // host socket outlives that until the forwarder is told to let go.
    _ = try? await holder.forwarder?.close().get()
    _ = try? await holder.stack?.shutdown().get()
    _ = try? await holder.link?.close().get()
    close(guestSide)
    try? await group.shutdownGracefully()
    _ = holder.stack
}

@Test func aGuestDiallingAPortNothingIsListeningOnIsResetImmediately() async throws {
    // The reason the dial happens BEFORE the SYN is answered. Answering first
    // is simpler and turns every failed connection into a successful one that
    // dies: `connect()` returns success and the first read fails, which is a
    // different error, arriving later, on a path applications handle worse.
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    var guestSide: Int32 = -1
    let holder = try await gateway(group: group, guestSide: &guestSide)

    // Bound and closed, so the port is one nothing can be listening on.
    let scout = try await ServerBootstrap(group: group).bind(host: "127.0.0.1", port: 0).get()
    let deadPort = UInt16(scout.localAddress!.port!)
    try await scout.close()

    send(
        guestSide,
        guestFrame(
            to: IPv4Address("127.0.0.1")!, destinationPort: deadPort, sequence: 7000, flags: [.syn]))

    let answer = await awaitSegments(guestSide) { !$0.isEmpty }
    let reset = try #require(answer.first)
    #expect(reset.header.flags.contains(.rst), "the guest was told the connection existed")
    #expect(reset.header.flags.contains(.ack), "a bare reset is one a dialler ignores")
    #expect(reset.header.acknowledgement == SequenceNumber(7001))
    #expect(holder.forwarder?.refusedForDial == 1)

    _ = try? await holder.stack?.shutdown().get()
    _ = try? await holder.link?.close().get()
    close(guestSide)
    try? await group.shutdownGracefully()
    _ = holder.stack
}

@Test func aGuestCannotOpenMoreConnectionsThanTheLimitAllows() async throws {
    // The bound the forwarder's own SYN limit does not provide. That one stops
    // counting the moment a request is settled, so without this a guest opens
    // connections that all SUCCEED and holds a host file descriptor per
    // connection until the process runs out -- and a process out of descriptors
    // takes everything else in it down, not just the gateway.
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    var guestSide: Int32 = -1
    let holder = try await gateway(group: group, guestSide: &guestSide, maximumConnections: 1)

    let listener = try await ServerBootstrap(group: group)
        .childChannelInitializer { channel in channel.eventLoop.makeSucceededVoidFuture() }
        .bind(host: "127.0.0.1", port: 0).get()
    let port = UInt16(listener.localAddress!.port!)

    // The first connection takes the only slot.
    send(
        guestSide,
        guestFrame(
            to: IPv4Address("127.0.0.1")!, destinationPort: port, sequence: 7000, flags: [.syn],
            sourcePort: 50001))
    let first = await awaitSegments(guestSide) { $0.contains { $0.header.flags.contains(.syn) } }
    #expect(first.contains { $0.header.flags.contains(.syn) }, "the first connection was refused")

    // The second is refused, and refused with a reset rather than in silence:
    // the forwarder consumed the segment, so silence would be a hang.
    send(
        guestSide,
        guestFrame(
            to: IPv4Address("127.0.0.1")!, destinationPort: port, sequence: 9000, flags: [.syn],
            sourcePort: 50002))
    let second = await awaitSegments(guestSide) { $0.contains { $0.header.flags.contains(.rst) } }
    let reset = try #require(second.first { $0.header.flags.contains(.rst) })
    #expect(reset.header.acknowledgement == SequenceNumber(9001))
    #expect(holder.forwarder?.refusedForLimit == 1)
    #expect(holder.forwarder?.establishedCount == 1, "the slot was not held by the live connection")

    try? await listener.close()
    // The connection that took the slot is still spliced to a host socket.
    _ = try? await holder.forwarder?.close().get()
    _ = try? await holder.stack?.shutdown().get()
    _ = try? await holder.link?.close().get()
    close(guestSide)
    try? await group.shutdownGracefully()
    _ = holder.stack
}

/// Echoes what it reads, upper-cased.
private final class UppercasingEcho: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let incoming = unwrapInboundIn(data)
        var out = context.channel.allocator.buffer(capacity: incoming.readableBytes)
        out.writeBytes(incoming.readableBytesView.map { $0 >= 97 && $0 <= 122 ? $0 - 32 : $0 })
        context.writeAndFlush(wrapOutboundOut(out), promise: nil)
    }
}

@Test func aGuestThatVanishesWithoutClosingIsGivenUpOnAndItsHostSocketReleased() async throws {
    // The case keep-alive exists for here, and the reason it defaults ON for
    // forwarded connections where RFC 1122 defaults it off: with no data
    // outstanding the retransmit timer never runs, so a guest that stops
    // answering holds an endpoint and the host socket spliced to it forever.
    //
    // The probe costs nothing on this wire -- it travels over a unix socket --
    // which is what makes the RFC's reason for defaulting it off not apply.
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    var guestSide: Int32 = -1
    let holder = try await gateway(group: group, guestSide: &guestSide)
    // A budget measured in milliseconds, so the test does not measure the
    // default two hours.
    try await holder.link!.eventLoop.submit {
        holder.forwarder = OutboundTCPForwarder(
            stack: holder.stack!,
            keepAlive: .init(idle: .milliseconds(20), interval: .milliseconds(10), count: 2))
    }.get()

    let listener = try await ServerBootstrap(group: group)
        .childChannelInitializer { channel in channel.eventLoop.makeSucceededVoidFuture() }
        .bind(host: "127.0.0.1", port: 0).get()
    let port = UInt16(listener.localAddress!.port!)

    send(
        guestSide,
        guestFrame(
            to: IPv4Address("127.0.0.1")!, destinationPort: port, sequence: 7000, flags: [.syn]))
    let synAck = await awaitSegments(guestSide) { $0.contains { $0.header.flags.contains(.syn) } }
    let answer = try #require(synAck.first { $0.header.flags.contains(.syn) })
    send(
        guestSide,
        guestFrame(
            to: IPv4Address("127.0.0.1")!, destinationPort: port, sequence: 7001,
            acknowledgement: answer.header.sequence.value &+ 1, flags: [.ack]))
    _ = await awaitSegments(guestSide) { _ in true }

    // The guest now vanishes: it answers nothing, including the probes.
    let reset = await awaitSegments(guestSide) { $0.contains { $0.header.flags.contains(.rst) } }
    #expect(
        reset.contains { $0.header.flags.contains(.rst) },
        "the connection was held open for a guest that stopped answering")

    // And the slot it held is back.
    for _ in 0..<200 {
        let live = try await holder.link!.eventLoop.submit { holder.forwarder?.establishedCount ?? -1 }.get()
        if live == 0 { break }
        try await Task.sleep(nanoseconds: 5_000_000)
    }
    let live = try await holder.link!.eventLoop.submit { holder.forwarder?.establishedCount ?? -1 }.get()
    #expect(live == 0, "the host socket was not released")

    try? await listener.close()
    _ = try? await holder.stack?.shutdown().get()
    _ = try? await holder.link?.close().get()
    close(guestSide)
    try? await group.shutdownGracefully()
    _ = holder.stack
}

@Test func aGuestReachingTheHostAddressIsDialledOnLoopback() async throws {
    // The headline feature of this whole package, and it did not work.
    //
    // `host.containers.internal` used to resolve to the gateway's own address,
    // so a guest that looked it up and dialled it had the gateway try to reach
    // 192.168.127.1 on the host -- where nothing is listening, because the
    // host's services are on its loopback. Nothing failed loudly: the guest
    // simply could not reach the host, which is the one thing it is here for.
    //
    // Upstream keeps the two apart and translates: the host has an address of
    // its own inside the subnet, and `nat` rewrites a dial to it into a dial to
    // 127.0.0.1.
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    var guestSide: Int32 = -1
    let hostAddress = IPv4Address("192.168.127.254")!
    let holder = try await gateway(
        group: group, guestSide: &guestSide,
        nat: [hostAddress: IPv4Address("127.0.0.1")!])

    // A real listener on loopback -- the shape of every host service a guest
    // would want.
    let listener = try await ServerBootstrap(group: group)
        .childChannelInitializer { channel in channel.pipeline.addHandler(UppercasingEcho()) }
        .bind(host: "127.0.0.1", port: 0).get()
    let port = UInt16(listener.localAddress!.port!)

    // The guest dials the HOST address, which exists on no host interface.
    send(
        guestSide,
        guestFrame(
            to: hostAddress, destinationPort: port, sequence: 7000, flags: [.syn], sourcePort: 50010))
    let answer = await awaitSegments(guestSide) { $0.contains { $0.header.flags.contains(.syn) } }

    #expect(
        answer.contains { $0.header.flags.contains(.syn) && $0.header.flags.contains(.ack) },
        "the guest could not reach the host: dialled \(hostAddress) and got no handshake")
    #expect(holder.forwarder?.refusedForDial == 0, "the dial was attempted without translation")

    try? await listener.close()
    _ = try? await holder.forwarder?.close().get()
    _ = try? await holder.stack?.shutdown().get()
    _ = try? await holder.link?.close().get()
    close(guestSide)
    try? await group.shutdownGracefully()
    _ = holder.stack
}

@Test func aGuestIsRefusedTheInstanceMetadataServiceByDefault() async throws {
    // 169.254.169.254 hands out credentials to whatever asks from the host. On
    // a host running in EC2, GCP or Azure, a gateway that dials on a guest's
    // behalf is exactly a way for a hostile guest to ask -- and this package's
    // whole threat model is that the guest is hostile.
    //
    // Refused before a slot or a dial is spent, and counted under its own name,
    // because "a guest tried to read the instance metadata service" is not the
    // same event as a busy gateway or an absent server.
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    var guestSide: Int32 = -1
    let holder = try await gateway(group: group, guestSide: &guestSide)

    send(
        guestSide,
        guestFrame(
            to: IPv4Address("169.254.169.254")!, destinationPort: 80, sequence: 8000, flags: [.syn],
            sourcePort: 50011))
    let answer = await awaitSegments(guestSide) { $0.contains { $0.header.flags.contains(.rst) } }

    let reset = try #require(answer.first { $0.header.flags.contains(.rst) })
    #expect(reset.header.acknowledgement == SequenceNumber(8001))
    #expect(holder.forwarder?.refusedForLinkLocal == 1)
    // Refused before the connection limit was consulted, so a guest hammering
    // link-local cannot also exhaust the slots for everything else.
    #expect(holder.forwarder?.refusedForLimit == 0)
    #expect(holder.forwarder?.establishedCount == 0)

    _ = try? await holder.forwarder?.close().get()
    _ = try? await holder.stack?.shutdown().get()
    _ = try? await holder.link?.close().get()
    close(guestSide)
    try? await group.shutdownGracefully()
    _ = holder.stack
}

@Test func linkLocalIsReachableWhenItIsDeliberatelyAllowed() async throws {
    // The floor under the test above: without this, a forwarder that refused
    // every connection would pass it. Also the switch an operator on a machine
    // that legitimately needs link-local has to be able to turn on, which is
    // what upstream's `Ec2MetadataAccess` is.
    //
    // The connection has to actually SUCCEED, which is why the address is
    // translated to a real listener. Asserting instead that the dial was
    // attempted and failed -- `refusedForDial == 1` -- reads the outcome of an
    // asynchronous connect to an unroutable address, and how long that takes is
    // a property of the machine. It passed alone and failed in the full suite.
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    var guestSide: Int32 = -1
    let metadata = IPv4Address("169.254.169.254")!
    let holder = try await gateway(
        group: group, guestSide: &guestSide, nat: [metadata: IPv4Address("127.0.0.1")!],
        allowsLinkLocal: true)

    let listener = try await ServerBootstrap(group: group)
        .childChannelInitializer { channel in channel.eventLoop.makeSucceededVoidFuture() }
        .bind(host: "127.0.0.1", port: 0).get()
    let port = UInt16(listener.localAddress!.port!)

    send(
        guestSide,
        guestFrame(
            to: metadata, destinationPort: port, sequence: 8100, flags: [.syn], sourcePort: 50012))
    let answer = await awaitSegments(guestSide) { $0.contains { $0.header.flags.contains(.syn) } }

    #expect(
        answer.contains { $0.header.flags.contains(.syn) && $0.header.flags.contains(.ack) },
        "link-local was blocked despite being allowed")
    #expect(holder.forwarder?.refusedForLinkLocal == 0)

    try? await listener.close()
    _ = try? await holder.forwarder?.close().get()
    _ = try? await holder.stack?.shutdown().get()
    _ = try? await holder.link?.close().get()
    close(guestSide)
    try? await group.shutdownGracefully()
    _ = holder.stack
}

@Test func slotsAreReturnedExactlyOnceAcrossManyConnections() async throws {
    // The counter that decides `maximumConnections` is maintained by hand: taken
    // at the decision, returned by whichever of two close futures fires first.
    // Both fire on a clean close, and every failure path in between has to
    // return it too.
    //
    // Nothing here tested that across churn. The existing checks open one
    // connection, and a slot leaked or double-returned once per connection is
    // invisible at one. It matters because it drifts in one direction: leak, and
    // the forwarder refuses everything long before the limit; double-return, and
    // the limit stops limiting.
    //
    // This is the shape that has already broken twice in this package -- a bound
    // exceeded by concurrent dials, and the switch's per-port counts -- so it is
    // worth a test that runs it hundreds of times rather than once.
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    var guestSide: Int32 = -1
    let holder = try await gateway(group: group, guestSide: &guestSide, maximumConnections: 8)

    let listener = try await ServerBootstrap(group: group)
        .childChannelInitializer { channel in channel.eventLoop.makeSucceededVoidFuture() }
        .bind(host: "127.0.0.1", port: 0).get()
    let port = UInt16(listener.localAddress!.port!)
    // A port nothing answers on, so half the connections fail at the dial --
    // the path that returns the slot without ever splicing.
    let scout = try await ServerBootstrap(group: group).bind(host: "127.0.0.1", port: 0).get()
    let deadPort = UInt16(scout.localAddress!.port!)
    try await scout.close()

    var peak = 0
    var sourcePort: UInt16 = 40000
    for round in 0..<120 {
        let reachable = round % 2 == 0
        sourcePort &+= 1
        send(
            guestSide,
            guestFrame(
                to: IPv4Address("127.0.0.1")!, destinationPort: reachable ? port : deadPort,
                sequence: UInt32(round) &* 1000 &+ 7000, flags: [.syn], sourcePort: sourcePort))
        let answer = await awaitSegments(guestSide) { !$0.isEmpty }

        // Close whatever was opened, from the guest's side.
        if let opened = answer.first(where: {
            $0.header.flags.contains(.syn) && $0.header.flags.contains(.ack)
        }) {
            send(
                guestSide,
                guestFrame(
                    to: IPv4Address("127.0.0.1")!, destinationPort: port,
                    sequence: UInt32(round) &* 1000 &+ 7001,
                    acknowledgement: opened.header.sequence.value &+ 1, flags: [.rst],
                    sourcePort: sourcePort))
        }
        _ = await awaitSegments(guestSide) { _ in true }

        let live = try await holder.stack!.eventLoop.submit { holder.forwarder!.establishedCount }.get()
        peak = max(peak, live)
    }

    #expect(peak <= 8, "the live count reached \(peak) against a limit of 8")

    // And it comes back to zero. Polled, because the last closes are in flight:
    // a fixed wait is either flaky or slow depending on the machine.
    var settled = -1
    for _ in 0..<400 where settled != 0 {
        settled = try await holder.stack!.eventLoop.submit { holder.forwarder!.establishedCount }.get()
        if settled != 0 { try? await Task.sleep(nanoseconds: 10_000_000) }
    }
    #expect(settled == 0, "\(settled) slots were never returned after 120 connections")

    // The floor: connections really were made, so "no slots outstanding" is not
    // satisfied by a forwarder that refused everything.
    let dialled = try await holder.stack!.eventLoop.submit {
        (holder.forwarder!.refusedForDial, holder.forwarder!.refusedForLimit)
    }.get()
    #expect(dialled.0 > 0, "no connection ever reached the dial")
    #expect(dialled.1 == 0, "connections were refused by the limit, so the churn never exercised it")

    try? await listener.close()
    _ = try? await holder.forwarder?.close().get()
    _ = try? await holder.stack?.shutdown().get()
    _ = try? await holder.link?.close().get()
    close(guestSide)
    try? await group.shutdownGracefully()
    _ = holder.stack
}
