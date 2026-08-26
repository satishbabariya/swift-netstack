import NIOCore
import NIOEmbedded
import NIOPosix
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
    // `stack` must stay alive for the test's duration: `link` only holds a
    // *weak* reference to the NIC it is attached to (see
    // `RecordingEndpoint.dispatcher`), and the NIC is owned by `stack`, not
    // by `link`. Discarding `stack` here used to work only because of the
    // retain cycle `start()` created — every previously-leaked object kept
    // itself, and therefore the NIC, alive regardless. Now that the cycle is
    // fixed, dropping `stack` immediately deallocates the NIC and trips
    // `RecordingEndpoint`'s "dispatcher deallocated while still attached"
    // assertion on the very next `inject`.
    let (stack, link, _) = makeStack()
    _ = stack
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
    // See the comment in `aFreshStackAnswersARPForItsGatewayAddress`: `stack`
    // must be kept alive here too, now that it is no longer implicitly kept
    // alive by the retain cycle `start()` used to create.
    let (stack, link, _) = makeStack()
    _ = stack
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

@Test func startingTwiceDoesNotOrphanTheMaintenanceTimer() async {
    // A second start() must not leave the first timer unreachable. Assert
    // in debug would trip on a genuine double-start, so this exercises the
    // release-path behaviour: the old timer is cancelled, not orphaned.
    //
    // `assert` is compiled in under `swift test`'s debug build, so calling
    // `start()` twice in-process traps the whole test process rather than
    // failing just this test. An exit test isolates that trap to a child
    // process instead, which is what proves the guard is actually wired up:
    // a genuine double-start is caught before anything can be orphaned. The
    // no-guard, assertions-disabled release path — where the guard falls
    // through to a bare `maintenanceTask?.cancel()` instead of trapping —
    // was verified separately by building with `-Xswiftc -assert-config
    // Release`, since NIO's `RepeatedTask` exposes no way to observe "did
    // the old task stop rescheduling" from inside a normal, assertion-
    // enabled test run.
    await #expect(processExitsWith: .failure) {
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
        stack.start()
    }
}

@Test func aStartedStackIsReleasedWhenDropped() {
    // start() stores closures that capture the protocol handlers, which
    // reach back to the NIC through RouteTable. Without breaking those
    // edges the entire graph — NIC, RouteTable, IPv4Protocol, ARPCache,
    // Reassembler, TransportDemuxer and the LinkEndpoint — leaks for the
    // life of the host process, once per sandbox.
    //
    // `.wait()` on `shutdown()`'s future deadlocks on an `EmbeddedEventLoop`
    // — see `shutdownStopsMaintenance` above — so the loop is driven instead.
    weak var weakNIC: NIC?
    weak var weakRoutes: RouteTable?
    weak var weakIPv4: IPv4Protocol?
    weak var weakLink: RecordingEndpoint?
    do {
        let (stack, link, loop) = makeStack()
        weakNIC = stack.nic
        weakRoutes = stack.routes
        weakIPv4 = stack.ipv4
        weakLink = link
        var completed = false
        stack.shutdown().whenSuccess { completed = true }
        loop.run()
        #expect(completed)
    }
    #expect(weakNIC == nil)
    #expect(weakRoutes == nil)
    #expect(weakIPv4 == nil)
    #expect(weakLink == nil)
}

@Test func arpResponderOutlivesTheStackItCameFrom() {
    // `stack.arpResponder` is public, so nothing stops a caller from
    // holding it past the `Stack` — and therefore the `NIC` — it came from
    // going away. Before the retain-cycle fix elsewhere in this package,
    // that scenario was unreachable in practice: nothing in this graph
    // ever actually deallocated, so a dangling reference here never came
    // up. Now that dropping a `Stack` really does deallocate its `NIC`,
    // `ARPResponder.nic` being `unowned` (mirroring `IPv4Protocol.nic`,
    // which is safe only because `RouteTable` backstops it) was a
    // reachable dangling reference with no such backstop of its own —
    // `request`/`handle` would trap.
    weak var weakStack: Stack?
    weak var weakNIC: NIC?

    func makeOrphanedResponder() -> ARPResponder {
        let (stack, _, _) = makeStack()
        weakStack = stack
        weakNIC = stack.nic
        return stack.arpResponder
        // `stack` — and, with it, `nic`, `routes`, and `ipv4` — becomes
        // unreachable here except through the `ARPResponder` returned.
    }

    let responder = makeOrphanedResponder()

    // The `Stack` itself is gone...
    #expect(weakStack == nil)
    // ...but the `NIC` is deliberately NOT: `ARPResponder.nic` is now a
    // strong reference, so holding `responder` keeps `nic` alive on its
    // own, independent of `Stack`. This is what closes the dangle — under
    // the old `unowned` field, `weakNIC` would be nil here too, and the
    // `request` call below would trap.
    #expect(weakNIC != nil)

    // Must not trap.
    responder.request(IPv4Address("192.168.127.99")!, from: IPv4Address("192.168.127.1")!)
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

@Test func shutdownMarshalsOntoTheLoopWhenCalledOffLoop() async throws {
    // `shutdown()` is documented as safe to call from any thread, unlike
    // everything else in this package — it must earn that by marshaling
    // onto `eventLoop` before clearing `nic`/`ipv4`'s handler tables, which
    // the ingress path reads. `EmbeddedEventLoop` cannot exercise this: its
    // own `inEventLoop` is hardcoded to always return `true`, and it traps
    // outright if actually touched from a thread other than the one that
    // created it — so a genuinely off-loop call needs a real, threaded
    // event loop.
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    let eventLoop = group.next()

    // `RecordingEndpoint.attach` (called from `NIC`'s init) preconditions
    // that it is itself on `eventLoop`, so construction and `start()` have
    // to happen there — off-loop is the scenario under test for `shutdown`
    // specifically, not for building the stack in the first place.
    let stack = try await eventLoop.submit {
        let link = RecordingEndpoint(eventLoop: eventLoop, linkAddress: MACAddress("5a:94:ef:e4:0c:ee")!)
        let stack = Stack(
            link: link,
            configuration: Stack.Configuration(
                gatewayAddress: IPv4Address("192.168.127.1")!,
                subnet: IPv4Subnet(cidr: "192.168.127.0/24")!
            ),
            clock: ManualClock())
        stack.start()
        return stack
    }.get()

    // Resumed on Swift concurrency's own executor after the `await` above,
    // not on `eventLoop`'s dedicated thread — a genuinely off-loop call.
    // Completing at all (rather than hanging or racing the ingress path)
    // is what this test is checking; awaiting it is itself the assertion.
    try await stack.shutdown().get()

    try await group.shutdownGracefully()
}

@Test func shutdownCompletesWithoutDrivingTheLoopWhenNothingIsLeftToCancel() throws {
    // The deadlock shape `StackBootstrap.bind`'s own doc comment warns
    // about, applied to `shutdown()`. A FIRST call still needs the loop
    // driven regardless of how `shutdown()` itself routes onto the loop:
    // `RepeatedTask.cancel`'s promise is fulfilled through the loop's own
    // queue, which is why even the callback-based `shutdownStopsMaintenance`
    // test above calls `loop.run()`. A SECOND call is different —
    // `maintenanceTask` is already nil, so `shutdownOnLoop`'s fast path
    // returns an already-succeeded future with no `RepeatedTask` involved
    // at all — PROVIDED `shutdown()` actually calls it directly rather
    // than routing it through `flatSubmit`. `EventLoop.submit`/
    // `flatSubmit` always go through `execute` even when already on the
    // loop — they never check `inEventLoop` themselves — and on an
    // `EmbeddedEventLoop`, `execute` only enqueues; nothing runs until the
    // loop is driven again. An unconditional `flatSubmit` would therefore
    // make even this trivial second call deadlock under `.wait()`, with
    // the loop never driven a second time below. The `inEventLoop` check
    // must bypass `flatSubmit` entirely here and call straight through
    // instead, completing synchronously.
    let (stack, _, loop) = makeStack()
    var firstCompleted = false
    stack.shutdown().whenSuccess { firstCompleted = true }
    loop.run()
    #expect(firstCompleted)

    try stack.shutdown().wait()
}
