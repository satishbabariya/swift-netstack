import NIOCore
import NIOEmbedded
import NIOPosix
import Testing

@testable import Netstack

#if canImport(Darwin)
    import Darwin
#else
    import Glibc
#endif

private let wireMAC = MACAddress("5a:94:ef:e4:0c:ee")!

/// Keeps the stack alive for the length of a test that builds it on another
/// thread. `@unchecked Sendable` for the same reason the test support types
/// above are: everything here is confined to one event loop.
private final class StackHolder: @unchecked Sendable {
    var stack: Stack?
}

/// `@unchecked Sendable` on the same terms as the library types it stands in
/// for: it is touched only on the link's event loop, and the safety comes from
/// that confinement rather than from anything the compiler checked.
private final class FrameCollector: LinkDispatcher, @unchecked Sendable {
    var frames: [[UInt8]] = []
    func deliverInbound(_ frame: PacketBuffer) {
        frames.append(Array(frame.frame.readableBytesView))
    }
}

private func ethernetFrame(payload: Int) -> ByteBuffer {
    var buffer = ByteBuffer()
    buffer.writeBytes(MACAddress("0a:0b:0c:0d:0e:0f")!.bytes)
    buffer.writeBytes(wireMAC.bytes)
    buffer.writeInteger(UInt16(0x0800), endianness: .big)
    buffer.writeBytes([UInt8](repeating: 0x5a, count: payload))
    return buffer
}

// MARK: - The link's own rules, driven without a socket

@Test func anInboundFrameReachesTheDispatcher() throws {
    let channel = EmbeddedChannel()
    let link = WireLinkEndpoint(channel: channel, linkAddress: wireMAC)
    let collector = FrameCollector()
    try channel.pipeline.syncOperations.addHandler(WireInboundHandler(link: link))
    link.attach(collector)

    try channel.writeInbound(ethernetFrame(payload: 40))

    #expect(collector.frames.count == 1)
    #expect(collector.frames.first?.count == 54)
    _ = try channel.finish()
}

@Test func anInboundFrameLargerThanTheMtuIsDroppedAtTheLink() throws {
    // The link declares the MTU, so the link is where a frame contradicting it
    // stops. Letting it up would mean every layer above had to be written
    // against frames the link said could not exist.
    //
    // This is separate from the stream decoder's bound and both are needed: the
    // decoder protects the buffer a length prefix could grow, and this protects
    // everything above from a datagram transport, where there is no length
    // prefix and the kernel hands over whatever arrived.
    let channel = EmbeddedChannel()
    let link = WireLinkEndpoint(channel: channel, linkAddress: wireMAC, mtu: 1500)
    let collector = FrameCollector()
    try channel.pipeline.syncOperations.addHandler(WireInboundHandler(link: link))
    link.attach(collector)

    try channel.writeInbound(ethernetFrame(payload: 1501))

    #expect(collector.frames.isEmpty)
    #expect(link.inboundDropped == 1)
    _ = try channel.finish()
}

@Test func aFrameExactlyAtTheMtuIsCarried() throws {
    // The boundary from the other side. Without it the test above passes against
    // a link that drops everything.
    let channel = EmbeddedChannel()
    let link = WireLinkEndpoint(channel: channel, linkAddress: wireMAC, mtu: 1500)
    let collector = FrameCollector()
    try channel.pipeline.syncOperations.addHandler(WireInboundHandler(link: link))
    link.attach(collector)

    try channel.writeInbound(ethernetFrame(payload: 1500))

    #expect(collector.frames.count == 1)
    #expect(link.inboundDropped == 0)
    _ = try channel.finish()
}

@Test func anOutboundFrameLargerThanTheMtuIsDroppedRatherThanTruncated() throws {
    // Truncation is the tempting alternative and it is worse than dropping. A
    // truncated ethernet frame is not a smaller frame, it is a corrupt one --
    // and on the stream transport its length prefix would be honest about a
    // size the frame no longer has, taking every frame after it down too.
    let channel = EmbeddedChannel()
    let link = WireLinkEndpoint(channel: channel, linkAddress: wireMAC, mtu: 1500)

    link.write([PacketBuffer(received: ethernetFrame(payload: 1501))])

    #expect(link.outboundDropped == 1)
    #expect(try channel.readOutbound(as: ByteBuffer.self) == nil, "an oversized frame reached the wire")
    _ = try channel.finish()
}

@Test func aBatchOfFramesIsWrittenAndFlushedOnce() throws {
    // Why `write` takes an array. The syscall is the expensive part of a wire,
    // and a flush per frame spends one per frame; `EmbeddedChannel` only makes
    // written data readable at a flush, so reading three frames back after one
    // call is the observable form of "they were batched".
    let channel = EmbeddedChannel()
    let link = WireLinkEndpoint(channel: channel, linkAddress: wireMAC)

    link.write((0..<3).map { _ in PacketBuffer(received: ethernetFrame(payload: 20)) })

    for _ in 0..<3 {
        #expect(try channel.readOutbound(as: ByteBuffer.self) != nil)
    }
    #expect(try channel.readOutbound(as: ByteBuffer.self) == nil)
    _ = try channel.finish()
}

@Test func aFramingErrorClosesTheWire() throws {
    // The peer and the decoder no longer agree about where frames begin, so
    // every byte after the error is noise. Closing is the only honest response.
    let channel = EmbeddedChannel()
    let link = WireLinkEndpoint(channel: channel, linkAddress: wireMAC, mtu: 1500)
    try channel.pipeline.syncOperations.addHandler(
        ByteToMessageHandler(FrameDecoder(maximumFrame: link.maximumFrame)))
    try channel.pipeline.syncOperations.addHandler(WireInboundHandler(link: link))
    link.attach(FrameCollector())

    var claim = ByteBuffer()
    claim.writeInteger(UInt32.max, endianness: .big)
    // Not `#expect(throws:)`: `ByteToMessageHandler` turns the decoder's error
    // into an `errorCaught` rather than letting it out of `writeInbound`, so a
    // throwing assertion here would be asserting about NIO's plumbing. What
    // matters is what the link did about it.
    _ = try? channel.writeInbound(claim)

    #expect(!channel.isActive, "the wire stayed open after a framing error")
    _ = try? channel.finish()
}

@Test func theHandlerDoesNotKeepItsLinkAlive() throws {
    // The link owns the channel and the channel's pipeline owns the handler, so
    // a strong reference back would close a cycle around a wire that is never
    // released -- and with it the whole stack behind it.
    let channel = EmbeddedChannel()
    weak var weakLink: WireLinkEndpoint?
    try {
        let link = WireLinkEndpoint(channel: channel, linkAddress: wireMAC)
        weakLink = link
        try channel.pipeline.syncOperations.addHandler(WireInboundHandler(link: link))
    }()

    #expect(weakLink == nil, "the pipeline is holding the link alive")
    _ = try channel.finish()
}

// MARK: - A real socket, which is the only thing that proves the descriptor path

@Test func aDatagramSocketPairCarriesFramesInBothDirections() async throws {
    // The path Virtualization.framework actually uses: the host makes a
    // `socketpair(AF_UNIX, SOCK_DGRAM)`, hands one end to the VM and keeps the
    // other. There is no address to connect to and no listener to accept, only
    // a descriptor that is already connected — so nothing above can be tested
    // through a bootstrap that takes a path.
    //
    // This is also the only test here that shows the premise holding on a real
    // kernel: one datagram in, one whole frame out, boundaries preserved with no
    // framing of our own.
    var pair: [Int32] = [0, 0]
    #expect(makeSocketPair(AF_UNIX, .datagram, &pair) == 0, "the platform refused a datagram socketpair")
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)

    let link = try await WireBootstrap.adoptingDatagramSocket(
        pair[0], group: group, linkAddress: wireMAC, mtu: 1500
    ).get()
    let collector = FrameCollector()
    try await link.eventLoop.submit { link.attach(collector) }.get()

    // Guest to gateway.
    let sent = ethernetFrame(payload: 100)
    let bytes = Array(sent.readableBytesView)
    #expect(bytes.withUnsafeBytes { send(pair[1], $0.baseAddress, $0.count, 0) } == bytes.count)

    // The read happens on the group's own thread; poll the link's loop rather
    // than sleeping, so the test is bounded by the work and not by a guess.
    var received: [[UInt8]] = []
    for _ in 0..<200 where received.isEmpty {
        received = try await link.eventLoop.submit { collector.frames }.get()
        if received.isEmpty { try await Task.sleep(nanoseconds: 5_000_000) }
    }
    #expect(received.first?.count == bytes.count, "the frame did not arrive whole")

    // Gateway to guest, two frames at once — the case that broke.
    //
    // NIO writes several pending buffers with `writev`, and an `iovec` of two
    // buffers on a datagram socket produces ONE datagram containing both. Two
    // ethernet frames written together would arrive as a single datagram, and
    // the premise the whole gateway rests on would be broken by an
    // efficiency. Measured before it was fixed: 30 and 40 bytes came back as
    // one datagram of 70.
    try await link.eventLoop.submit {
        link.write([
            PacketBuffer(received: ethernetFrame(payload: 60)),
            PacketBuffer(received: ethernetFrame(payload: 100)),
        ])
    }.get()
    var sizes: [Int] = []
    for _ in 0..<200 where sizes.count < 2 {
        var back = [UInt8](repeating: 0, count: 4096)
        let read = back.withUnsafeMutableBytes { recv(pair[1], $0.baseAddress, $0.count, dontWait) }
        if read > 0 {
            sizes.append(read)
        } else {
            try await Task.sleep(nanoseconds: 5_000_000)
        }
    }
    #expect(sizes == [74, 114], "two frames did not arrive as two datagrams: \(sizes)")

    _ = try? await link.close().get()
    close(pair[1])
    try? await group.shutdownGracefully()
}

@Test func aGuestOnARealSocketGetsAnArpReplyFromTheStack() async throws {
    // End to end over the wire that matters: a descriptor, a kernel, and the
    // whole stack behind it. Everything above tests one layer with the others
    // stubbed; this is the only test that says the layers fit together on a
    // real socket.
    //
    // ARP rather than TCP deliberately. It is the shortest exchange that
    // requires the frame to have survived intact in both directions — a
    // truncated, merged or misframed request produces no reply at all — and it
    // needs no handshake, no timers and no clock control to complete.
    var pair: [Int32] = [0, 0]
    #expect(makeSocketPair(AF_UNIX, .datagram, &pair) == 0)
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)

    let link = try await WireBootstrap.adoptingDatagramSocket(
        pair[0], group: group, linkAddress: wireMAC, mtu: 1500
    ).get()
    // Built ON the link's loop, not merely started there. `NIC.init` attaches
    // to the link, and `attach` requires the loop -- a stack constructed on the
    // test's thread traps before it can be started.
    let holder = StackHolder()
    try await link.eventLoop.submit {
        let stack = Stack(
            link: link,
            configuration: Stack.Configuration(
                gatewayAddress: IPv4Address("192.168.127.1")!,
                subnet: IPv4Subnet(cidr: "192.168.127.0/24")!))
        stack.start()
        holder.stack = stack
    }.get()

    // The guest asks who has the gateway's address.
    var request = ByteBuffer()
    request.writeBytes([UInt8](repeating: 0xff, count: 6))  // broadcast
    request.writeBytes(MACAddress("0a:0b:0c:0d:0e:0f")!.bytes)
    request.writeInteger(UInt16(0x0806), endianness: .big)  // ARP
    request.writeInteger(UInt16(1), endianness: .big)  // ethernet
    request.writeInteger(UInt16(0x0800), endianness: .big)  // IPv4
    request.writeInteger(UInt8(6))
    request.writeInteger(UInt8(4))
    request.writeInteger(UInt16(1), endianness: .big)  // request
    request.writeBytes(MACAddress("0a:0b:0c:0d:0e:0f")!.bytes)
    request.writeBytes(IPv4Address("192.168.127.2")!.bytes)
    request.writeBytes([UInt8](repeating: 0, count: 6))
    request.writeBytes(IPv4Address("192.168.127.1")!.bytes)
    let bytes = Array(request.readableBytesView)
    #expect(bytes.withUnsafeBytes { send(pair[1], $0.baseAddress, $0.count, 0) } == bytes.count)

    var reply: [UInt8] = []
    for _ in 0..<400 where reply.isEmpty {
        var back = [UInt8](repeating: 0, count: 4096)
        let read = back.withUnsafeMutableBytes { recv(pair[1], $0.baseAddress, $0.count, dontWait) }
        if read > 0 {
            reply = Array(back[0..<read])
        } else {
            try await Task.sleep(nanoseconds: 5_000_000)
        }
    }

    #expect(!reply.isEmpty, "no ARP reply came back over the wire")
    #expect(Array(reply[12..<14]) == [0x08, 0x06], "the reply was not ARP")
    #expect(Array(reply[20..<22]) == [0x00, 0x02], "the reply was not an ARP REPLY")
    #expect(Array(reply[22..<28]) == wireMAC.bytes, "the gateway answered with the wrong hardware address")
    #expect(Array(reply[28..<32]) == IPv4Address("192.168.127.1")!.bytes)

    // `Stack` documents `shutdown()` as mandatory: its maintenance timer is a
    // NIO `RepeatedTask` that reschedules itself through the loop's queue, so
    // dropping the stack does not stop it and the next firing lands on a loop
    // this test is about to shut down.
    _ = try? await holder.stack?.shutdown().get()
    _ = try? await link.close().get()
    close(pair[1])
    try? await group.shutdownGracefully()
    _ = holder.stack
}

@Test func aStreamSocketCarriesLengthPrefixedFramesEndToEnd() async throws {
    // qemu's `-netdev socket` wire, on a real stream socket. The datagram test
    // above proves the kernel keeps the boundaries; this one proves the decoder
    // does, where the kernel does not.
    //
    // Two frames are written together on purpose. On the datagram wire that
    // would merge them and each must be flushed alone; here the length prefix
    // carries the boundary, so batching is not only safe but the point — and a
    // stream link that inherited `flushPerFrame` would spend a syscall per
    // frame for nothing.
    var pair: [Int32] = [0, 0]
    #expect(makeSocketPair(AF_UNIX, .stream, &pair) == 0)
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)

    let link = try await WireBootstrap.adoptingStreamSocket(
        pair[0], group: group, linkAddress: wireMAC, mtu: 1500
    ).get()
    let collector = FrameCollector()
    try await link.eventLoop.submit { link.attach(collector) }.get()

    // Guest to gateway, both frames in one write, so the decoder has to split
    // a single read into two frames.
    var wire = ByteBuffer()
    for payload in [40, 100] {
        let frame = ethernetFrame(payload: payload)
        wire.writeInteger(UInt32(frame.readableBytes), endianness: .big)
        wire.writeImmutableBuffer(frame)
    }
    let bytes = Array(wire.readableBytesView)
    #expect(bytes.withUnsafeBytes { send(pair[1], $0.baseAddress, $0.count, 0) } == bytes.count)

    var received: [[UInt8]] = []
    for _ in 0..<400 where received.count < 2 {
        received = try await link.eventLoop.submit { collector.frames }.get()
        if received.count < 2 { try await Task.sleep(nanoseconds: 5_000_000) }
    }
    #expect(received.map(\.count) == [54, 114], "the two frames did not arrive as two frames")

    // Gateway to guest, with the prefix this side writes.
    try await link.eventLoop.submit {
        link.write([PacketBuffer(received: ethernetFrame(payload: 60))])
    }.get()
    var back = [UInt8](repeating: 0, count: 4096)
    var read = 0
    for _ in 0..<400 where read == 0 {
        let n = back.withUnsafeMutableBytes { recv(pair[1], $0.baseAddress, $0.count, dontWait) }
        if n > 0 { read = n } else { try await Task.sleep(nanoseconds: 5_000_000) }
    }
    #expect(read == 4 + 74, "the frame did not arrive with its four-byte length: \(read)")
    #expect(Array(back[0..<4]) == [0, 0, 0, 74], "the length prefix is not four bytes big-endian")

    _ = try? await link.close().get()
    close(pair[1])
    try? await group.shutdownGracefully()
}

@Test func theHyperkitFramingIsTwoBytesLittleEndian() throws {
    // Upstream's second stream framing, and the default its own `/connect`
    // endpoint uses. qemu writes four bytes big-endian; hyperkit and vpnkit
    // write two bytes little-endian. They are not compatible and nothing on the
    // wire says which is in use, so a client that guesses wrong sees a framing
    // error rather than anything naming the mismatch.
    let channel = EmbeddedChannel()
    let link = WireLinkEndpoint(channel: channel, linkAddress: wireMAC, mtu: 1500)
    try channel.pipeline.syncOperations.addHandler(
        ByteToMessageHandler(FrameDecoder(maximumFrame: 1514, framing: .hyperkit)))
    try channel.pipeline.syncOperations.addHandler(
        MessageToByteHandler(FrameEncoder(maximumFrame: 1514, framing: .hyperkit)))
    try channel.pipeline.syncOperations.addHandler(WireInboundHandler(link: link))

    let payload = ByteBuffer(bytes: [UInt8](repeating: 0xab, count: 300))
    link.write([PacketBuffer(received: payload)])
    channel.flush()
    let encoded = try #require(try channel.readOutbound(as: ByteBuffer.self))

    // 300 is 0x012C: little-endian puts the low byte first, which is what
    // distinguishes this from qemu's framing rather than merely the width.
    #expect(Array(encoded.readableBytesView.prefix(2)) == [0x2C, 0x01])
    #expect(encoded.readableBytes == 302)

    let collector = FramingCollector()
    link.attach(collector)
    try channel.writeInbound(encoded)
    #expect(collector.frames.count == 1, "the frame it wrote did not decode")
    #expect(collector.frames.first?.readableBytes == 300)
    _ = try? channel.finish()
}

@Test func aTwoByteFramingWillNotAcceptALengthItsOwnPrefixCouldNotWrite() throws {
    // The bound is the smaller of the MTU and what the prefix can express. A
    // decoder built for a jumbo link with a two-byte prefix would otherwise
    // accept lengths it could never have written -- and the encoder on the far
    // side would have truncated them, so the two ends would disagree about where
    // the next frame starts.
    let decoder = FrameDecoder(maximumFrame: 200_000, framing: .hyperkit)
    #expect(decoder.maximumFrame == 65535)

    // The floor: qemu's four bytes are not clamped to hyperkit's ceiling.
    let wide = FrameDecoder(maximumFrame: 200_000, framing: .qemu)
    #expect(wide.maximumFrame == 200_000)
}

/// Collects what a link delivered upward. `ListeningWireTests` has its own,
/// file-private; one per file is cheaper than making either shared.
private final class FramingCollector: LinkDispatcher, @unchecked Sendable {
    var frames: [ByteBuffer] = []
    func deliverInbound(_ frame: PacketBuffer) {
        frames.append(frame.frame)
    }
}
