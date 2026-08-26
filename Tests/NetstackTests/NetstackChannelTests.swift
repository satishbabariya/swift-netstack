import NIOCore
import NIOEmbedded
import Testing

@testable import Netstack

private final class EnvelopeCollector: ChannelInboundHandler {
    typealias InboundIn = AddressedEnvelope<ByteBuffer>
    var received: [(bytes: [UInt8], remote: SocketAddress)] = []

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let envelope = unwrapInboundIn(data)
        received.append((Array(envelope.data.readableBytesView), envelope.remoteAddress))
    }
}

private func makeStack(_ link: RecordingEndpoint) -> Stack {
    let stack = Stack(
        link: link,
        configuration: Stack.Configuration(
            gatewayAddress: IPv4Address("192.168.127.1")!,
            subnet: IPv4Subnet(cidr: "192.168.127.0/24")!),
        clock: ManualClock())
    stack.start()
    stack.arpCache.record(IPv4Address("192.168.127.2")!, MACAddress("0a:0b:0c:0d:0e:0f")!)
    return stack
}

@Test func aBoundChannelReportsItsAddressAndLoop() throws {
    let loop = EmbeddedEventLoop()
    let link = RecordingEndpoint(eventLoop: loop, linkAddress: MACAddress("5a:94:ef:e4:0c:ee")!)
    let stack = makeStack(link)

    let channel = try StackBootstrap(stack: stack)
        .bind(host: IPv4Address("192.168.127.1")!, port: 53)
        .wait()

    #expect(channel.isActive)
    #expect(channel.eventLoop === stack.eventLoop)
    #expect(try channel.localAddress?.port == 53)
}

@Test func inboundDatagramsArriveAsEnvelopes() throws {
    let loop = EmbeddedEventLoop()
    let link = RecordingEndpoint(eventLoop: loop, linkAddress: MACAddress("5a:94:ef:e4:0c:ee")!)
    let stack = makeStack(link)
    let collector = EnvelopeCollector()

    let channel = try StackBootstrap(stack: stack)
        .channelInitializer { $0.pipeline.addHandler(collector) }
        .bind(host: IPv4Address("192.168.127.1")!, port: 53)
        .wait()
    _ = channel

    injectUDP(into: link, from: "192.168.127.2", to: "192.168.127.1", sourcePort: 4000, destinationPort: 53, payload: [0xde, 0xad])

    #expect(collector.received.count == 1)
    #expect(collector.received[0].bytes == [0xde, 0xad])
    #expect(collector.received[0].remote.port == 4000)
}

@Test func writingAnEnvelopeEmitsADatagram() throws {
    let loop = EmbeddedEventLoop()
    let link = RecordingEndpoint(eventLoop: loop, linkAddress: MACAddress("5a:94:ef:e4:0c:ee")!)
    let stack = makeStack(link)

    let channel = try StackBootstrap(stack: stack)
        .bind(host: IPv4Address("192.168.127.1")!, port: 53)
        .wait()
    _ = link.drainTransmitted()

    let peer = try SocketAddress.makeAddressResolvingHost("192.168.127.2", port: 4000)
    let envelope = AddressedEnvelope(remoteAddress: peer, data: ByteBuffer(bytes: [0xbe, 0xef]))
    try channel.writeAndFlush(envelope).wait()

    let frames = link.drainTransmitted()
    #expect(frames.count == 1)
    var packet = PacketBuffer(received: frames[0])
    _ = EthernetHeader.parse(&packet)
    let ipHeader = IPv4Header.parse(&packet)!
    let udp = UDPHeader.parse(&packet, header: ipHeader)
    #expect(udp?.sourcePort == 53)
    #expect(udp?.destinationPort == 4000)
    #expect(Array(packet.payload.readableBytesView) == [0xbe, 0xef])
}

@Test func aDNSStyleRoundTripWorksEndToEnd() throws {
    // The M3 exit criterion: a query in, a response out, entirely through
    // the pipeline.
    let loop = EmbeddedEventLoop()
    let link = RecordingEndpoint(eventLoop: loop, linkAddress: MACAddress("5a:94:ef:e4:0c:ee")!)
    let stack = makeStack(link)

    final class Echoer: ChannelInboundHandler {
        typealias InboundIn = AddressedEnvelope<ByteBuffer>
        typealias OutboundOut = AddressedEnvelope<ByteBuffer>
        func channelRead(context: ChannelHandlerContext, data: NIOAny) {
            let incoming = unwrapInboundIn(data)
            var response = incoming.data
            response.writeBytes([0xff])
            context.writeAndFlush(wrapOutboundOut(AddressedEnvelope(remoteAddress: incoming.remoteAddress, data: response)), promise: nil)
        }
    }

    _ = try StackBootstrap(stack: stack)
        .channelInitializer { $0.pipeline.addHandler(Echoer()) }
        .bind(host: IPv4Address("192.168.127.1")!, port: 53)
        .wait()
    _ = link.drainTransmitted()

    injectUDP(into: link, from: "192.168.127.2", to: "192.168.127.1", sourcePort: 4000, destinationPort: 53, payload: [0x12, 0x34])

    let frames = link.drainTransmitted()
    #expect(frames.count == 1)
    var packet = PacketBuffer(received: frames[0])
    _ = EthernetHeader.parse(&packet)
    let ipHeader = IPv4Header.parse(&packet)!
    #expect(ipHeader.source == IPv4Address("192.168.127.1"))
    #expect(ipHeader.destination == IPv4Address("192.168.127.2"))
    let udp = UDPHeader.parse(&packet, header: ipHeader)
    #expect(udp?.destinationPort == 4000)
    #expect(Array(packet.payload.readableBytesView) == [0x12, 0x34, 0xff])
}

@Test func closingTheChannelReleasesThePort() throws {
    let loop = EmbeddedEventLoop()
    let link = RecordingEndpoint(eventLoop: loop, linkAddress: MACAddress("5a:94:ef:e4:0c:ee")!)
    let stack = makeStack(link)

    let channel = try StackBootstrap(stack: stack).bind(host: IPv4Address("192.168.127.1")!, port: 53).wait()
    try channel.close().wait()
    #expect(!channel.isActive)

    // Rebinding proves the demuxer entry is gone.
    _ = try StackBootstrap(stack: stack).bind(host: IPv4Address("192.168.127.1")!, port: 53).wait()
}

@Test func bindingAnOccupiedPortFailsTheFuture() throws {
    let loop = EmbeddedEventLoop()
    let link = RecordingEndpoint(eventLoop: loop, linkAddress: MACAddress("5a:94:ef:e4:0c:ee")!)
    let stack = makeStack(link)

    _ = try StackBootstrap(stack: stack).bind(host: IPv4Address("192.168.127.1")!, port: 53).wait()
    #expect(throws: StackError.portInUse) {
        try StackBootstrap(stack: stack).bind(host: IPv4Address("192.168.127.1")!, port: 53).wait()
    }
}

/// Same helper as UDPTests; keep the two in sync.
private func injectUDP(into link: RecordingEndpoint, from source: String, to destination: String, sourcePort: UInt16, destinationPort: UInt16, payload: [UInt8]) {
    let datagram = UDPHeader.serialize(
        payload: ByteBuffer(bytes: payload),
        source: IPv4Address(source)!, destination: IPv4Address(destination)!,
        sourcePort: sourcePort, destinationPort: destinationPort,
        allocator: ByteBufferAllocator())
    var ipPacket = PacketBuffer(allocator: ByteBufferAllocator(), payload: datagram)
    var header = IPv4Header(
        source: IPv4Address(source)!, destination: IPv4Address(destination)!,
        protocolNumber: .udp, payloadLength: datagram.readableBytes)
    header.prepend(to: &ipPacket)
    var frame = ByteBuffer()
    frame.writeBytes(MACAddress("5a:94:ef:e4:0c:ee")!.bytes)
    frame.writeBytes(MACAddress("0a:0b:0c:0d:0e:0f")!.bytes)
    frame.writeInteger(UInt16(0x0800), endianness: .big)
    var body = ipPacket.frame
    frame.writeBuffer(&body)
    link.inject(frame)
}
