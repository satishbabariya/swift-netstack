import NIOCore
import NIOEmbedded
import Testing

@testable import Netstack

private func makeStack() -> (Stack, RecordingEndpoint, EmbeddedEventLoop) {
    let loop = EmbeddedEventLoop()
    let link = RecordingEndpoint(eventLoop: loop, linkAddress: MACAddress("5a:94:ef:e4:0c:ee")!)
    let stack = Stack(
        link: link,
        configuration: Stack.Configuration(
            gatewayAddress: IPv4Address("192.168.127.1")!,
            subnet: IPv4Subnet(cidr: "192.168.127.0/24")!
        ),
        clock: ManualClock(),
        allocator: ByteBufferAllocator()
    )
    stack.start()
    return (stack, link, loop)
}

private func arpRequestFrame(for target: String, from sender: String, senderMAC: String) -> ByteBuffer {
    var frame = ByteBuffer()
    frame.writeBytes(MACAddress.broadcast.bytes)
    frame.writeBytes(MACAddress(senderMAC)!.bytes)
    frame.writeInteger(UInt16(0x0806), endianness: .big)
    frame.writeInteger(UInt16(1), endianness: .big)
    frame.writeInteger(UInt16(0x0800), endianness: .big)
    frame.writeInteger(UInt8(6))
    frame.writeInteger(UInt8(4))
    frame.writeInteger(UInt16(1), endianness: .big)
    frame.writeBytes(MACAddress(senderMAC)!.bytes)
    frame.writeBytes(IPv4Address(sender)!.bytes)
    frame.writeBytes([0, 0, 0, 0, 0, 0])
    frame.writeBytes(IPv4Address(target)!.bytes)
    return frame
}

@Test func aFreshStackAnswersARPForItsGatewayAddress() {
    let (_, link, _) = makeStack()
    link.inject(arpRequestFrame(for: "192.168.127.1", from: "192.168.127.2", senderMAC: "0a:0b:0c:0d:0e:0f"))

    let frames = link.drainTransmitted()
    #expect(frames.count == 1)
    var reply = PacketBuffer(received: frames[0])
    #expect(EthernetHeader.parse(&reply)?.etherType == .arp)
    let arp = ARPPacket.parse(&reply)
    #expect(arp?.operation == .reply)
    #expect(arp?.senderIP == IPv4Address("192.168.127.1"))
}

@Test func aGuestCanPingTheGateway() {
    let (_, link, _) = makeStack()
    // ARP first, so the stack learns the guest's link address.
    link.inject(arpRequestFrame(for: "192.168.127.1", from: "192.168.127.2", senderMAC: "0a:0b:0c:0d:0e:0f"))
    _ = link.drainTransmitted()

    var echo = ByteBuffer()
    echo.writeInteger(UInt8(8))
    echo.writeInteger(UInt8(0))
    echo.writeInteger(UInt16(0), endianness: .big)
    echo.writeInteger(UInt16(0x1111), endianness: .big)
    echo.writeInteger(UInt16(42), endianness: .big)
    echo.writeBytes(Array(repeating: UInt8(0x5a), count: 56))  // ping's default payload size
    let checksum = echo.withUnsafeReadableBytes { Checksum.compute($0) }
    echo.setInteger(checksum, at: 2, endianness: .big)

    var ipPacket = PacketBuffer(allocator: ByteBufferAllocator(), payload: echo)
    let header = IPv4Header(
        source: IPv4Address("192.168.127.2")!, destination: IPv4Address("192.168.127.1")!,
        protocolNumber: .icmp, payloadLength: echo.readableBytes)
    var mutableHeader = header
    mutableHeader.prepend(to: &ipPacket)

    var frame = ByteBuffer()
    frame.writeBytes(MACAddress("5a:94:ef:e4:0c:ee")!.bytes)
    frame.writeBytes(MACAddress("0a:0b:0c:0d:0e:0f")!.bytes)
    frame.writeInteger(UInt16(0x0800), endianness: .big)
    var body = ipPacket.frame
    frame.writeBuffer(&body)
    link.inject(frame)

    let frames = link.drainTransmitted()
    #expect(frames.count == 1)
    var reply = PacketBuffer(received: frames[0])
    #expect(EthernetHeader.parse(&reply)?.destination == MACAddress("0a:0b:0c:0d:0e:0f"))
    let replyHeader = IPv4Header.parse(&reply)
    #expect(replyHeader?.source == IPv4Address("192.168.127.1"))
    #expect(replyHeader?.destination == IPv4Address("192.168.127.2"))
    let icmp = ICMPv4Header.parse(&reply)
    #expect(icmp?.type == .echoReply)
    #expect(icmp?.sequence == 42)
    #expect(reply.readableBytes == 56)
}

@Test func promiscuousAndSpoofingAreOnByDefault() {
    let (stack, _, _) = makeStack()
    #expect(stack.nic.acceptsAnyDestination)
    #expect(stack.nic.allowsAnySource)
}

@Test func maintenanceReapsExpiredFragments() {
    let loop = EmbeddedEventLoop()
    let clock = ManualClock()
    let link = RecordingEndpoint(eventLoop: loop, linkAddress: MACAddress("5a:94:ef:e4:0c:ee")!)
    let stack = Stack(
        link: link,
        configuration: Stack.Configuration(
            gatewayAddress: IPv4Address("192.168.127.1")!,
            subnet: IPv4Subnet(cidr: "192.168.127.0/24")!,
            reassemblyTimeout: .seconds(30),
            maintenanceInterval: .seconds(10)
        ),
        clock: clock,
        allocator: ByteBufferAllocator()
    )
    stack.start()

    // A first fragment that never completes.
    var header = IPv4Header(
        source: IPv4Address("192.168.127.2")!, destination: IPv4Address("192.168.127.1")!,
        protocolNumber: .udp, payloadLength: 8)
    header.identification = 77
    header.flags = [.moreFragments]
    _ = stack.reassembler.process(header: header, payload: ByteBuffer(bytes: Array(repeating: UInt8(0), count: 8)))
    #expect(stack.reassembler.pendingCount == 1)

    clock.advance(by: .seconds(31))
    loop.advanceTime(by: .seconds(31))
    #expect(stack.reassembler.pendingCount == 0)
}

@Test func shutdownStopsMaintenance() {
    // `.wait()` cannot be used here: RepeatedTask.cancel schedules its
    // promise onto the loop, and an EmbeddedEventLoop only advances when
    // something drives it — so waiting deadlocks. Drive the loop instead.
    let (stack, _, loop) = makeStack()
    var completed = false
    stack.shutdown().whenSuccess { completed = true }
    loop.run()
    #expect(completed)

    // Advancing after shutdown must neither fire the cancelled task nor trap.
    loop.advanceTime(by: .seconds(60))
}
