import NIOConcurrencyHelpers
import NIOCore
import NIOPosix
import Testing

@testable import Netstack

#if canImport(Darwin)
    import Darwin
#else
    import Glibc
#endif

// ADR 0001's `dial`, observed from the guest's side of the wire. Each test runs
// the same three probes -- a SYN, a datagram, a ping -- through a whole
// `Gateway`, at the host address, which `nat` sends to real listeners on
// loopback. Deny-all and allow-all are the same code with one verdict changed,
// so each is the other's control: a gateway that answered nothing would pass
// the first, and one that ignored the policy would pass the second.

/// Records every flow it is asked about. A lock because the policy is called on
/// the gateway's loop and read from the test's task.
private final class Verdicts: EgressPolicy {
    let verdict: EgressVerdict
    let asked = NIOLockedValueBox<[EgressFlow]>([])
    init(_ verdict: EgressVerdict) { self.verdict = verdict }
    func resolve(_ question: EgressQuestion) -> EgressVerdict { verdict }
    func resolved(_ answer: EgressAnswer) -> EgressVerdict { .allow }
    func dial(_ flow: EgressFlow) -> EgressVerdict {
        asked.withLockedValue { $0.append(flow) }
        return verdict
    }
}

private let egressGuest = IPv4Address("192.168.127.2")!

private struct Probed {
    var synAck = false
    var reset: TCPHeader?
    var datagramReply: [UInt8]?
    var echoReplyFrom: IPv4Address?
    var statistics: Gateway.Statistics
}

/// Frames the gateway put on the wire, collected for `duration` or until
/// `enough` is satisfied.
private func collect(
    _ fd: Int32, for duration: Int = 400, until enough: ([(IPv4Header, PacketBuffer)]) -> Bool = { _ in false }
) async -> [(IPv4Header, PacketBuffer)] {
    var out: [(IPv4Header, PacketBuffer)] = []
    for _ in 0..<(duration / 5) {
        while true {
            var back = [UInt8](repeating: 0, count: 4096)
            let read = back.withUnsafeMutableBytes { recv(fd, $0.baseAddress, $0.count, dontWait) }
            guard read > 0 else { break }
            var packet = PacketBuffer(received: ByteBuffer(bytes: back[0..<read]))
            guard let ethernet = EthernetHeader.parse(&packet), ethernet.etherType == .ipv4,
                let ip = IPv4Header.parse(&packet)
            else { continue }
            out.append((ip, packet))
        }
        if enough(out) { break }
        try? await Task.sleep(nanoseconds: 5_000_000)
    }
    return out
}

private func ethernetFrame(_ payload: ByteBuffer, to destination: IPv4Address, _ proto: IPProtocol, gatewayMAC: MACAddress) -> [UInt8] {
    var packet = PacketBuffer(allocator: ByteBufferAllocator(), payload: payload)
    IPv4Header(source: egressGuest, destination: destination, protocolNumber: proto, payloadLength: payload.readableBytes)
        .prepend(to: &packet)
    EthernetHeader(destination: gatewayMAC, source: gwGuestMAC, etherType: .ipv4).prepend(to: &packet)
    return Array(packet.frame.readableBytesView)
}

private func echoRequest(identifier: UInt16) -> ByteBuffer {
    var message = ByteBuffer(bytes: [8, 0, 0, 0])
    message.writeInteger(identifier, endianness: .big)
    message.writeInteger(UInt16(1), endianness: .big)
    message.writeBytes([UInt8](repeating: 0x61, count: 32))
    let checksum = message.readableBytesView.withUnsafeBytes { Checksum.compute($0) }
    message.setInteger(checksum, at: 2, endianness: .big)
    return message
}

private func sendFrame(_ fd: Int32, _ bytes: [UInt8]) {
    #expect(sendBytes(fd, bytes) == bytes.count)
}

private func echoReply(_ frames: [(IPv4Header, PacketBuffer)]) -> IPv4Address? {
    for (ip, packet) in frames where ip.protocolNumber == .icmp {
        var packet = packet
        if ICMPv4Header.parse(&packet)?.type == .echoReply { return ip.source }
    }
    return nil
}

/// A SYN, a datagram and a ping, each to the host address, under `policy`.
private func probe(_ policy: (any EgressPolicy)?) async throws -> Probed {
    var pair: [Int32] = [0, 0]
    #expect(makeSocketPair(AF_UNIX, .datagram, &pair) == 0)
    let fd = pair[1]
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    var configuration = Gateway.Configuration()
    configuration.egressPolicy = policy
    let host = configuration.hostAddress
    let mac = configuration.linkAddress
    let gateway = try await Gateway.start(adoptingDatagramSocket: pair[0], group: group, configuration: configuration).get()
    let listener = try await ServerBootstrap(group: group)
        .childChannelInitializer { $0.eventLoop.makeSucceededVoidFuture() }
        .bind(host: "127.0.0.1", port: 0).get()
    let echo = try await DatagramBootstrap(group: group)
        .channelInitializer { $0.pipeline.addHandler(UDPEcho()) }
        .bind(host: "127.0.0.1", port: 0).get()

    // The control for every silence below: the wire carries an echo both ways,
    // and the gateway's own address is not egress, so it answers under any policy.
    sendFrame(fd, ethernetFrame(echoRequest(identifier: 0x0101), to: configuration.gatewayAddress, .icmp, gatewayMAC: mac))
    #expect(echoReply(await collect(fd, for: 2000, until: { echoReply($0) != nil })) == configuration.gatewayAddress, "the gateway did not answer a ping to itself")

    let tcpPort = UInt16(listener.localAddress!.port!)
    let syn = TCPHeader(
        sourcePort: 50100, destinationPort: tcpPort, sequence: SequenceNumber(9000), acknowledgement: SequenceNumber(0),
        dataOffset: 5, flags: [.syn], window: 65535, checksum: 0, urgentPointer: 0, options: [])
    sendFrame(
        fd,
        ethernetFrame(
            syn.serialize(payload: ByteBuffer(), source: egressGuest, destination: host, allocator: ByteBufferAllocator()),
            to: host, .tcp, gatewayMAC: mac))
    var result = Probed(statistics: try await gateway.statistics().get())
    for (ip, packet) in await collect(fd, for: 2000, until: { $0.contains { $0.0.protocolNumber == .tcp } }) where ip.protocolNumber == .tcp {
        var packet = packet
        guard let tcp = TCPHeader.parse(&packet, header: ip) else { continue }
        if tcp.flags.contains(.syn) && tcp.flags.contains(.ack) { result.synAck = true }
        if tcp.flags.contains(.rst) { result.reset = tcp }
    }

    let datagram = UDPHeader.serialize(
        payload: ByteBuffer(string: "hello"), source: egressGuest, destination: host, sourcePort: 40100,
        destinationPort: UInt16(echo.localAddress!.port!), allocator: ByteBufferAllocator())!
    sendFrame(fd, ethernetFrame(datagram, to: host, .udp, gatewayMAC: mac))
    for (ip, packet) in await collect(fd, for: 1000, until: { $0.contains { $0.0.protocolNumber == .udp } }) where ip.protocolNumber == .udp {
        var packet = packet
        if UDPHeader.parse(&packet, header: ip) != nil { result.datagramReply = Array(packet.payload.readableBytesView) }
    }

    sendFrame(fd, ethernetFrame(echoRequest(identifier: 0x0202), to: host, .icmp, gatewayMAC: mac))
    result.echoReplyFrom = echoReply(await collect(fd, for: 1000, until: { echoReply($0) != nil }))

    // A question for a name the gateway does not own, so `Gateway` has to have
    // handed the policy to its resolver for it to be asked.
    var query = ByteBuffer(bytes: [0, 7, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7])
    query.writeString("example")
    query.writeBytes([3] + Array("com".utf8) + [0, 0, 1, 0, 1])
    let question = UDPHeader.serialize(
        payload: query, source: egressGuest, destination: configuration.gatewayAddress, sourcePort: 40200,
        destinationPort: DNSServer.port, allocator: ByteBufferAllocator())!
    sendFrame(fd, ethernetFrame(question, to: configuration.gatewayAddress, .udp, gatewayMAC: mac))
    _ = await collect(fd, for: 1000, until: { $0.contains { $0.0.protocolNumber == .udp } })

    result.statistics = try await gateway.statistics().get()
    try? await listener.close()
    try? await echo.close()
    _ = try? await gateway.close().get()
    close(fd)
    try? await group.shutdownGracefully()
    return result
}

private final class UDPEcho: ChannelInboundHandler, Sendable {
    typealias InboundIn = AddressedEnvelope<ByteBuffer>
    typealias OutboundOut = AddressedEnvelope<ByteBuffer>
    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        context.writeAndFlush(data, promise: nil)
    }
}

@Test func aDenyAllPolicyResetsTheSynAndLeavesTheDatagramAndThePingUnanswered() async throws {
    let policy = Verdicts(.refuse)
    let probed = try await probe(policy)

    let reset = try #require(probed.reset, "the refused SYN got no reset")
    #expect(reset.flags.contains(.ack), "the reset to a SYN has to be RST|ACK")
    #expect(reset.acknowledgement == SequenceNumber(9001))
    #expect(!probed.synAck, "a refused dial was answered with a SYN-ACK")
    #expect(probed.datagramReply == nil, "a refused datagram was carried and answered")
    // The ADR's trap: refusing a ping with `decline()` has the gateway answer it
    // from the pinged address, so a refused ping would come back.
    #expect(probed.echoReplyFrom == nil, "a refused ping was answered, from \(probed.echoReplyFrom.map { "\($0)" } ?? "")")

    let stats = probed.statistics
    #expect(stats.tcpRefusedByPolicy == 1)
    #expect(stats.udpRefusedByPolicy == 1)
    #expect(stats.udpSocketsOpened == 0, "a host socket was opened for a refused flow")
    #expect(stats.icmpRefusedByPolicy == 1)
    #expect(stats.icmpForwarded == 0, "a refused ping was sent")
    // One, the control. A second would be the refused ping answered locally.
    #expect(stats.icmpDeclined == 1, "a refused ping was declined, which answers it")
    #expect(stats.dnsRefusedByPolicy == 1, "the resolver was not given the policy")
}

@Test func anAllowAllPolicyLeavesTheSameProbesAnswered() async throws {
    let policy = Verdicts(.allow)
    let probed = try await probe(policy)
    let host = Gateway.Configuration().hostAddress

    #expect(probed.synAck, "an allowed dial got no SYN-ACK")
    #expect(probed.reset == nil)
    #expect(probed.datagramReply == Array("hello".utf8), "an allowed datagram got no answer")
    #expect(probed.echoReplyFrom == host, "an allowed ping went unanswered")
    #expect(probed.statistics.tcpRefusedByPolicy + probed.statistics.udpRefusedByPolicy + probed.statistics.icmpRefusedByPolicy == 0)
    // No upstream is configured, so an allowed question is refused for that.
    #expect(probed.statistics.dnsRefusedByPolicy == 0)
    #expect(probed.statistics.dnsRefusedNoUpstream == 1)

    // Asked once per flow, with the address the guest dialled and the one
    // `nat` turned it into. The gateway's own address is not egress and is
    // not asked about.
    let loopback = IPv4Address("127.0.0.1")!
    let asked = policy.asked.withLockedValue { $0 }
    #expect(asked.map(\.transport) == [.tcp, .udp, .icmpEcho])
    #expect(asked.allSatisfy { $0.source == egressGuest && $0.destination == host && $0.translatedDestination == loopback })
    #expect(asked.map(\.sourcePort) == [50100, 40100, nil])
    #expect(asked.last?.port == nil, "a ping was given a port")
}
