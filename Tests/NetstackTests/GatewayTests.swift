import Foundation
import NIOCore
import NIOPosix
import Testing

#if canImport(Darwin)
    import Darwin
#else
    import Glibc
#endif

@testable import Netstack

// The whole thing, assembled the way a user would assemble it: one descriptor
// in, a working network out. Everything below this has its own tests; what
// these check is that the pieces fit, and that the ORDER they are built in --
// which is the only knowledge this type exists to hold -- is right.

let gwGuestMAC = MACAddress("0a:0b:0c:0d:0e:0f")!

/// A DISCOVER, then the REQUEST for what it offers, as a guest would.
func dhcpDiscover(hardware: MACAddress, transaction: UInt32) -> ByteBuffer {
    var buffer = ByteBuffer()
    buffer.writeInteger(UInt8(1))
    buffer.writeInteger(UInt8(1))
    buffer.writeInteger(UInt8(6))
    buffer.writeInteger(UInt8(0))
    buffer.writeInteger(transaction, endianness: .big)
    buffer.writeInteger(UInt16(0), endianness: .big)
    buffer.writeInteger(UInt16(0x8000), endianness: .big)
    buffer.writeBytes([UInt8](repeating: 0, count: 16))
    buffer.writeBytes(hardware.bytes)
    buffer.writeBytes([UInt8](repeating: 0, count: 10))
    buffer.writeBytes([UInt8](repeating: 0, count: 64 + 128))
    buffer.writeBytes([99, 130, 83, 99])
    buffer.writeBytes([53, 1, 1])
    buffer.writeInteger(UInt8(255))
    return buffer
}

func frame(
    from source: IPv4Address, to destination: IPv4Address, sourcePort: UInt16, destinationPort: UInt16,
    payload: ByteBuffer, destinationMAC: MACAddress, sourceMAC: MACAddress = gwGuestMAC
) -> [UInt8] {
    let allocator = ByteBufferAllocator()
    let datagram = UDPHeader.serialize(
        payload: payload, source: source, destination: destination,
        sourcePort: sourcePort, destinationPort: destinationPort, allocator: allocator)!
    var packet = PacketBuffer(allocator: allocator, payload: datagram)
    IPv4Header(
        source: source, destination: destination, protocolNumber: .udp, payloadLength: datagram.readableBytes
    ).prepend(to: &packet)
    EthernetHeader(destination: destinationMAC, source: sourceMAC, etherType: .ipv4).prepend(to: &packet)
    return Array(packet.frame.readableBytesView)
}

private func awaitUDP(_ fd: Int32, fromPort: UInt16) async -> ByteBuffer? {
    for _ in 0..<400 {
        var back = [UInt8](repeating: 0, count: 4096)
        let read = back.withUnsafeMutableBytes { recv(fd, $0.baseAddress, $0.count, MSG_DONTWAIT) }
        if read > 0 {
            var packet = PacketBuffer(received: ByteBuffer(bytes: back[0..<read]))
            guard let ethernet = EthernetHeader.parse(&packet), ethernet.etherType == .ipv4 else { continue }
            guard let ip = IPv4Header.parse(&packet), ip.protocolNumber == .udp else { continue }
            guard let udp = UDPHeader.parse(&packet, header: ip), udp.sourcePort == fromPort else { continue }
            return packet.payload
        }
        try? await Task.sleep(nanoseconds: 5_000_000)
    }
    return nil
}

@Test func aGatewayStartedOnADescriptorLeasesAnAddressAndResolvesItsOwnName() async throws {
    // The order this type exists to hold, checked end to end: DHCP and DNS bind
    // their ports BEFORE the UDP forwarder installs its protocol handler, so
    // that when the handler falls through for anything addressed to the gateway
    // there is something bound for the datagram to reach. Built the other way
    // round, both services answer nothing and the failure looks like a bug in
    // whichever one is tested first.
    var pair: [Int32] = [0, 0]
    #expect(socketpair(AF_UNIX, SOCK_DGRAM, 0, &pair) == 0)
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)

    let gateway = try await Gateway.start(
        adoptingDatagramSocket: pair[0], group: group, configuration: .init()
    ).get()

    // A guest asks for an address.
    let discover = frame(
        from: .any, to: .broadcast, sourcePort: DHCPServer.clientPort,
        destinationPort: DHCPServer.serverPort, payload: dhcpDiscover(hardware: gwGuestMAC, transaction: 7),
        destinationMAC: .broadcast)
    _ = discover.withUnsafeBytes { send(pair[1], $0.baseAddress, $0.count, 0) }

    let offer = try #require(await awaitUDP(pair[1], fromPort: DHCPServer.serverPort))
    let parsed = try #require(DHCPCodec.parse(offer))
    #expect(parsed.messageType == .offer)
    let leased = parsed.yourAddress
    #expect(IPv4Subnet(cidr: "192.168.127.0/24")!.contains(leased))

    let known = try await gateway.eventLoop.submit { gateway.leasedAddress(for: gwGuestMAC) }.get()
    #expect(known == leased, "the gateway cannot say where the guest it just addressed is")

    // And the guest can resolve the name every upstream guest expects.
    var query = ByteBuffer()
    query.writeInteger(UInt16(0x2222), endianness: .big)
    query.writeInteger(UInt16(0x0100), endianness: .big)
    query.writeInteger(UInt16(1), endianness: .big)
    query.writeBytes([UInt8](repeating: 0, count: 6))
    for label in ["host", "containers", "internal"] {
        query.writeInteger(UInt8(label.utf8.count))
        query.writeBytes(Array(label.utf8))
    }
    query.writeInteger(UInt8(0))
    query.writeInteger(UInt16(1), endianness: .big)
    query.writeInteger(UInt16(1), endianness: .big)

    let ask = frame(
        from: leased, to: IPv4Address("192.168.127.1")!, sourcePort: 40000, destinationPort: 53,
        payload: query, destinationMAC: MACAddress("5a:94:ef:e4:0c:ee")!)
    _ = ask.withUnsafeBytes { send(pair[1], $0.baseAddress, $0.count, 0) }

    let answer = try #require(await awaitUDP(pair[1], fromPort: 53))
    #expect(
        answer.getInteger(at: answer.readerIndex + 6, endianness: .big, as: UInt16.self) == 1,
        "host.containers.internal was not answered")

    _ = try? await gateway.close().get()
    close(pair[1])
    try? await group.shutdownGracefully()
}

@Test func aGatewayCarriesAGuestConnectionToTheHostAndBackAgain() async throws {
    // One descriptor in, a working network out. This is the shape of the whole
    // package in one test: the guest's TCP reaches a real listener, and the
    // answer comes back.
    var pair: [Int32] = [0, 0]
    #expect(socketpair(AF_UNIX, SOCK_DGRAM, 0, &pair) == 0)
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    let gateway = try await Gateway.start(
        adoptingDatagramSocket: pair[0], group: group, configuration: .init()
    ).get()

    let listener = try await ServerBootstrap(group: group)
        .childChannelInitializer { channel in channel.pipeline.addHandler(GatewayEcho()) }
        .bind(host: "127.0.0.1", port: 0).get()
    let port = UInt16(listener.localAddress!.port!)

    // The guest needs the gateway to know its link address before the gateway
    // can answer it; an ARP request from the guest is how that happens in
    // reality, and is what the DHCP exchange above would also have done.
    try await gateway.eventLoop.submit {
        gateway.stack.arpCache.record(IPv4Address("192.168.127.2")!, gwGuestMAC)
    }.get()

    let allocator = ByteBufferAllocator()
    let header = TCPHeader(
        sourcePort: 50000, destinationPort: port, sequence: SequenceNumber(9000),
        acknowledgement: SequenceNumber(0), dataOffset: 5, flags: [.syn], window: 65535,
        checksum: 0, urgentPointer: 0, options: [])
    let segment = header.serialize(
        payload: ByteBuffer(), source: IPv4Address("192.168.127.2")!,
        destination: IPv4Address("127.0.0.1")!, allocator: allocator)
    var packet = PacketBuffer(allocator: allocator, payload: segment)
    IPv4Header(
        source: IPv4Address("192.168.127.2")!, destination: IPv4Address("127.0.0.1")!,
        protocolNumber: .tcp, payloadLength: segment.readableBytes
    ).prepend(to: &packet)
    EthernetHeader(
        destination: MACAddress("5a:94:ef:e4:0c:ee")!, source: gwGuestMAC, etherType: .ipv4
    ).prepend(to: &packet)
    let bytes = Array(packet.frame.readableBytesView)
    _ = bytes.withUnsafeBytes { send(pair[1], $0.baseAddress, $0.count, 0) }

    var sawSynAck = false
    for _ in 0..<400 where !sawSynAck {
        var back = [UInt8](repeating: 0, count: 4096)
        let read = back.withUnsafeMutableBytes { recv(pair[1], $0.baseAddress, $0.count, MSG_DONTWAIT) }
        if read > 0 {
            var reply = PacketBuffer(received: ByteBuffer(bytes: back[0..<read]))
            guard let ethernet = EthernetHeader.parse(&reply), ethernet.etherType == .ipv4 else { continue }
            guard let ip = IPv4Header.parse(&reply), ip.protocolNumber == .tcp else { continue }
            guard let tcp = TCPHeader.parse(&reply, header: ip) else { continue }
            if tcp.flags.contains(.syn), tcp.flags.contains(.ack) { sawSynAck = true }
        } else {
            try? await Task.sleep(nanoseconds: 5_000_000)
        }
    }
    #expect(sawSynAck, "the guest's connection was never accepted")

    try? await listener.close()
    _ = try? await gateway.close().get()
    close(pair[1])
    try? await group.shutdownGracefully()
}

private final class GatewayEcho: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        context.writeAndFlush(data, promise: nil)
    }
}

@Test func aGatewayReportsWhatItRefusedThroughItsLoggerAndItsStatistics() async throws {
    // The wiring test. Everything in `ObservabilityTests` checks the limiter in
    // isolation, where it works whether or not a single line of it is connected
    // to anything -- so this drives a real refusal through a real gateway and
    // looks for it in both places it is supposed to appear.
    //
    // The refusal chosen is the one an operator is most likely to hit and least
    // likely to diagnose: a gateway configured with no upstream resolver
    // answers REFUSED to every name it does not own, and before this it did so
    // in complete silence. The guest sees "DNS is broken", the host sees
    // nothing at all, and the cause is one missing line of configuration.
    var pair: [Int32] = [0, 0]
    #expect(socketpair(AF_UNIX, SOCK_DGRAM, 0, &pair) == 0)
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    let (logger, lines) = makeLogger()

    let gateway = try await Gateway.start(
        adoptingDatagramSocket: pair[0], group: group,
        configuration: .init(upstreamResolvers: [], logger: logger)
    ).get()

    let discover = frame(
        from: .any, to: .broadcast, sourcePort: DHCPServer.clientPort,
        destinationPort: DHCPServer.serverPort,
        payload: dhcpDiscover(hardware: gwGuestMAC, transaction: 11), destinationMAC: .broadcast)
    _ = discover.withUnsafeBytes { send(pair[1], $0.baseAddress, $0.count, 0) }
    let offer = try #require(await awaitUDP(pair[1], fromPort: DHCPServer.serverPort))
    let leased = try #require(DHCPCodec.parse(offer)).yourAddress

    // A name this gateway does not own, asked for twenty times. One line, not
    // twenty -- and the twenty are all inside the default window, so this is
    // also the rate limit doing its job on a real datapath rather than in a
    // unit test holding a `ManualClock`.
    for transaction in 0..<20 {
        var query = ByteBuffer()
        query.writeInteger(UInt16(0x3000 + transaction), endianness: .big)
        query.writeInteger(UInt16(0x0100), endianness: .big)
        query.writeInteger(UInt16(1), endianness: .big)
        query.writeBytes([UInt8](repeating: 0, count: 6))
        for label in ["example", "com"] {
            query.writeInteger(UInt8(label.utf8.count))
            query.writeBytes(Array(label.utf8))
        }
        query.writeInteger(UInt8(0))
        query.writeInteger(UInt16(1), endianness: .big)
        query.writeInteger(UInt16(1), endianness: .big)

        let ask = frame(
            from: leased, to: IPv4Address("192.168.127.1")!, sourcePort: UInt16(41000 + transaction),
            destinationPort: 53, payload: query, destinationMAC: MACAddress("5a:94:ef:e4:0c:ee")!)
        _ = ask.withUnsafeBytes { send(pair[1], $0.baseAddress, $0.count, 0) }
        _ = await awaitUDP(pair[1], fromPort: 53)
    }

    let stats = try await gateway.statistics().get()
    // The counter has no window and counts every one, which is exactly why the
    // statistics exist alongside the log rather than instead of it.
    #expect(stats.dnsRefusedNoUpstream == 20)
    #expect(stats.dhcpLeases == 1)
    #expect(stats.dnsAnsweredLocally == 0)

    let refusals = lines.withLockedValue { $0.filter { $0.message == "dnsRefusedNoUpstream" } }
    #expect(refusals.count == 1, "twenty refusals produced \(refusals.count) log lines")
    // The name reached the line, sanitized. Without the metadata an operator
    // knows something was refused but not what, which for a resolver is most of
    // what they needed.
    #expect(refusals.first?.metadata["name"].map(String.init(describing:)) == "example.com")
    #expect(refusals.first?.level == .warning)

    _ = try? await gateway.close().get()
    close(pair[1])
    try? await group.shutdownGracefully()
}

@Test func closingAGatewayShutsDownItsStackRatherThanLeavingATimerRunning() async throws {
    // `Stack` documents `shutdown()` as mandatory, and for a reason worth
    // repeating here: the maintenance timer is a NIO `RepeatedTask`, which
    // reschedules itself through the event loop's own queue. Dropping every
    // reference to the stack does not stop it. Only `cancel()` does.
    //
    // So a `Gateway` that closed everything else and forgot this left a timer
    // firing forever, holding the `Reassembler` and the `ARPCache` it sweeps
    // alive with it -- once per gateway, for the life of the process. Nothing
    // failed, no test noticed, and the only outward sign was NIO complaining
    // about a task scheduled on a dead loop *after* the group shut down, which
    // reads like a test-teardown race and was dismissed as one.
    var pair: [Int32] = [0, 0]
    #expect(socketpair(AF_UNIX, SOCK_DGRAM, 0, &pair) == 0)
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    let gateway = try await Gateway.start(
        adoptingDatagramSocket: pair[0], group: group, configuration: .init()
    ).get()

    // The floor: without this the assertion below passes for a gateway whose
    // timer never started, which is a different bug that would make this test
    // vacuous rather than failing.
    let runningBefore = try await gateway.eventLoop.submit { gateway.stack.isRunningForTesting }.get()
    #expect(runningBefore, "the stack's maintenance timer was never started")

    _ = try? await gateway.close().get()

    let runningAfter = try await gateway.eventLoop.submit { gateway.stack.isRunningForTesting }.get()
    #expect(!runningAfter, "the gateway closed but left its stack's maintenance timer running")

    close(pair[1])
    try? await group.shutdownGracefully()
}

@Test func theNameGuestsAreGivenForTheHostIsAnAddressTheGatewayTranslates() async throws {
    // Two settings that have to agree, in different parts of the configuration,
    // with nothing connecting them: the DNS record a guest resolves for
    // `host.containers.internal`, and the `nat` table that decides what a dial
    // to that address becomes.
    //
    // When they drifted apart -- the record pointed at the gateway, the table
    // translated the host address -- nothing failed. A guest resolved the name,
    // dialled what it was given, and the gateway tried to reach 192.168.127.1 on
    // the host, where nothing listens because the host's services are on its
    // loopback. Reaching the host is what this package is for, and it was quietly
    // broken.
    //
    // So this asserts the relationship rather than either value: whatever the
    // name resolves to must be an address `nat` rewrites. Change either one alone
    // and this fails.
    var pair: [Int32] = [0, 0]
    #expect(socketpair(AF_UNIX, SOCK_DGRAM, 0, &pair) == 0)
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    let configuration = Gateway.Configuration()
    let gateway = try await Gateway.start(
        adoptingDatagramSocket: pair[0], group: group, configuration: configuration
    ).get()

    let discover = frame(
        from: .any, to: .broadcast, sourcePort: DHCPServer.clientPort,
        destinationPort: DHCPServer.serverPort, payload: dhcpDiscover(hardware: gwGuestMAC, transaction: 61),
        destinationMAC: .broadcast)
    _ = discover.withUnsafeBytes { send(pair[1], $0.baseAddress, $0.count, 0) }
    let offer = try #require(await awaitUDP(pair[1], fromPort: DHCPServer.serverPort))
    let leased = try #require(DHCPCodec.parse(offer)).yourAddress

    var query = ByteBuffer()
    query.writeInteger(UInt16(0x4242), endianness: .big)
    query.writeInteger(UInt16(0x0100), endianness: .big)
    query.writeInteger(UInt16(1), endianness: .big)
    query.writeBytes([UInt8](repeating: 0, count: 6))
    for label in ["host", "containers", "internal"] {
        query.writeInteger(UInt8(label.utf8.count))
        query.writeBytes(Array(label.utf8))
    }
    query.writeInteger(UInt8(0))
    query.writeInteger(UInt16(1), endianness: .big)
    query.writeInteger(UInt16(1), endianness: .big)

    let ask = frame(
        from: leased, to: configuration.gatewayAddress, sourcePort: 40100, destinationPort: 53,
        payload: query, destinationMAC: configuration.linkAddress)
    _ = ask.withUnsafeBytes { send(pair[1], $0.baseAddress, $0.count, 0) }
    let answer = try #require(await awaitUDP(pair[1], fromPort: 53))

    // The A record is the last four bytes of a single-answer reply.
    #expect(
        answer.getInteger(at: answer.readerIndex + 6, endianness: .big, as: UInt16.self) == 1,
        "host.containers.internal was not answered")
    let bytes = Array(answer.readableBytesView.suffix(4))
    #expect(bytes.count == 4)
    let resolved = IPv4Address(bytes[0], bytes[1], bytes[2], bytes[3])

    #expect(
        configuration.nat[resolved] != nil,
        "guests are told the host is at \(resolved), which the gateway does not translate")
    // And it translates to loopback, which is where a host's own services are.
    #expect(configuration.nat[resolved] == IPv4Address("127.0.0.1")!)
    // The gateway also has to answer ARP for it, or no guest can send there at
    // all whatever the DNS says.
    let reachable = try await gateway.eventLoop.submit { gateway.stack.nic.hasAddress(resolved) }.get()
    #expect(reachable, "nothing answers ARP for the address guests are given for the host")

    _ = try? await gateway.close().get()
    close(pair[1])
    try? await group.shutdownGracefully()
}

@Test func aGatewayWithACaptureFileRecordsTheTrafficThatCrossesIt() async throws {
    // End to end, because the capture is wrapped around the link during assembly
    // and a wrapper applied after something has already attached would see
    // nothing. The unit tests cover the file format; this covers the wiring.
    let path = "/tmp/netstack-gateway-capture-\(UInt32.random(in: 0...UInt32.max)).pcap"
    defer { try? FileManager.default.removeItem(atPath: path) }
    var pair: [Int32] = [0, 0]
    #expect(socketpair(AF_UNIX, SOCK_DGRAM, 0, &pair) == 0)
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    let gateway = try await Gateway.start(
        adoptingDatagramSocket: pair[0], group: group, configuration: .init(captureFile: path)
    ).get()

    let discover = frame(
        from: .any, to: .broadcast, sourcePort: DHCPServer.clientPort,
        destinationPort: DHCPServer.serverPort, payload: dhcpDiscover(hardware: gwGuestMAC, transaction: 71),
        destinationMAC: .broadcast)
    _ = discover.withUnsafeBytes { send(pair[1], $0.baseAddress, $0.count, 0) }
    _ = try #require(await awaitUDP(pair[1], fromPort: DHCPServer.serverPort))

    // Closed rather than flushed: `close()` is what an embedder calls, and a
    // capture that only reaches the disk when something else asks it to is a
    // capture that is empty exactly when it is wanted.
    _ = try? await gateway.close().get()

    let data = try [UInt8](Data(contentsOf: URL(fileURLWithPath: path)))
    #expect(data.count > 24, "the capture file has only a header")
    let magic = UInt32(data[0]) | UInt32(data[1]) << 8 | UInt32(data[2]) << 16 | UInt32(data[3]) << 24
    #expect(magic == 0xa1b2_c3d4)
    // Both directions: the guest's DISCOVER went in and the offer came back out.
    let captured = data.count
    #expect(captured >= 24 + 2 * 16, "expected at least the request and the reply: \(captured) bytes")

    close(pair[1])
    try? await group.shutdownGracefully()
}
