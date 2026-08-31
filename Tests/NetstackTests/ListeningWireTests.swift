import Dispatch
import Foundation
import NIOCore
import NIOPosix
import Testing

@testable import Netstack

#if canImport(Darwin)
    import Darwin
#else
    import Glibc
#endif

// The other way round from `WireLinkEndpointTests`: there the host owns a
// descriptor and hands one end to the VM, here the gateway LISTENS and the guest
// dials it. That is what vfkit and qemu do, and without it this package can only
// be used by a process that can create the socket pair itself.

private let listenMAC = MACAddress("5a:94:ef:e4:0c:ee")!
private let listenGuestMAC = MACAddress("0a:0b:0c:0d:0e:0f")!

private final class Collector: LinkDispatcher, @unchecked Sendable {
    var frames: [[UInt8]] = []
    func deliverInbound(_ frame: PacketBuffer) {
        frames.append(Array(frame.frame.readableBytesView))
    }
}

private func temporaryPath(_ name: String) -> String {
    NSTemporaryDirectory() + "netstack-\(name)-\(UInt32.random(in: 0..<UInt32.max)).sock"
}

private func ethernetFrame(payload: Int) -> [UInt8] {
    var buffer = ByteBuffer()
    buffer.writeBytes(listenMAC.bytes)
    buffer.writeBytes(listenGuestMAC.bytes)
    buffer.writeInteger(UInt16(0x0800), endianness: .big)
    buffer.writeBytes([UInt8](repeating: 0x5a, count: payload))
    return Array(buffer.readableBytesView)
}

/// Connect a unix socket of the given type to `path`, as a guest would.
private func dial(_ path: String, type: SocketKind) -> Int32 {
    let fd = makeSocket(AF_UNIX, type)
    #expect(fd >= 0)
    // A write to a socket the far end has closed raises SIGPIPE, whose default
    // disposition kills the process -- so one test writing to a connection the
    // gateway has (correctly) closed takes the whole suite down, reported as
    // "exited with unexpected signal code 13" and pointing at no test in
    // particular. Asking for EPIPE instead makes it a return value the caller
    // can see.
    #if canImport(Darwin)
        var on: Int32 = 1
        _ = setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &on, socklen_t(MemoryLayout<Int32>.size))
    #endif
    let connected = connectTo(fd, unixAddress(path: path))
    #expect(connected == 0, "could not dial \(path): \(String(cString: strerror(errno)))")
    return fd
}

@Test func aDatagramWireLearnsItsPeerFromTheFirstFrameAndAnswersThere() async throws {
    // A bound datagram socket has no peer until something sends to it, and there
    // is nothing to configure it with — so the peer is learned. Replies go to
    // whoever last sent, which is upstream's `unixgram` rule and correct for the
    // one thing this wire carries: a single guest.
    let path = temporaryPath("dgram")
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    let link = try await WireBootstrap.listeningDatagramSocket(
        atPath: path, group: group, linkAddress: listenMAC, mtu: 1500
    ).get()
    let collector = Collector()
    try await link.eventLoop.submit { link.attach(collector) }.get()

    // The guest has to bind a name of its own: a reply to an unnamed datagram
    // socket has nowhere to go, and this is the case that would otherwise look
    // like a gateway that never answers.
    let guestPath = temporaryPath("guest")
    let guest = makeSocket(AF_UNIX, .datagram)
    #expect(bindTo(guest, unixAddress(path: guestPath)) == 0)

    let outbound = ethernetFrame(payload: 40)
    let sent = sendTo(guest, outbound, unixAddress(path: path))
    #expect(sent == outbound.count)

    var received: [[UInt8]] = []
    for _ in 0..<400 where received.isEmpty {
        received = try await link.eventLoop.submit { collector.frames }.get()
        if received.isEmpty { try await Task.sleep(nanoseconds: 5_000_000) }
    }
    #expect(received.first?.count == outbound.count, "the guest's frame did not arrive")

    // And the answer goes back to the address it learned.
    try await link.eventLoop.submit {
        link.write([PacketBuffer(received: ByteBuffer(bytes: ethernetFrame(payload: 60)))])
    }.get()
    var back = [UInt8](repeating: 0, count: 4096)
    var read = 0
    for _ in 0..<400 where read == 0 {
        let n = back.withUnsafeMutableBytes { recv(guest, $0.baseAddress, $0.count, dontWait) }
        if n > 0 { read = n } else { try await Task.sleep(nanoseconds: 5_000_000) }
    }
    #expect(read == 74, "the gateway's answer did not reach the guest: \(read)")

    _ = try? await link.close().get()
    close(guest)
    try? FileManager.default.removeItem(atPath: guestPath)
    try? FileManager.default.removeItem(atPath: path)
    try? await group.shutdownGracefully()
}

@Test func aWriteBeforeAnyFrameHasArrivedIsRefusedRatherThanQueued() async throws {
    // There is no address to send to, so dropping is the only honest option. A
    // link that queued for a peer it might never learn would be holding frames
    // against a guest that never booted.
    //
    // In practice a gateway never speaks first — it answers a guest's DHCP, ARP
    // and SYN — so this is a case a working setup does not reach, which is
    // exactly why it is worth pinning: nothing else would notice if it changed.
    let path = temporaryPath("silent")
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    let link = try await WireBootstrap.listeningDatagramSocket(
        atPath: path, group: group, linkAddress: listenMAC, mtu: 1500
    ).get()

    try await link.eventLoop.submit {
        link.write([PacketBuffer(received: ByteBuffer(bytes: ethernetFrame(payload: 60)))])
    }.get()

    // Nothing crashed, and nothing is held: the drop is silent by design, so
    // what this pins is that the write did not trap and did not block.
    let dropped = try await link.eventLoop.submit { link.outboundDropped }.get()
    #expect(dropped == 0, "the frame was counted as an MTU drop, which is a different failure")

    _ = try? await link.close().get()
    try? FileManager.default.removeItem(atPath: path)
    try? await group.shutdownGracefully()
}

@Test func aStreamWireServesTheFirstGuestAndClosesTheSecond() async throws {
    // One guest. This wire carries one ethernet segment, and two guests on it
    // would need a switch that learns which addresses are behind which socket --
    // so the second connection is closed rather than served, which tells the
    // second guest immediately instead of leaving it to wonder why nothing
    // answers.
    let path = temporaryPath("stream")
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    let pending = WireBootstrap.listeningStreamSocket(
        atPath: path, group: group, linkAddress: listenMAC, mtu: 1500)

    // Wait for the socket to exist before dialling it.
    for _ in 0..<400 where !FileManager.default.fileExists(atPath: path) {
        try await Task.sleep(nanoseconds: 5_000_000)
    }
    let first = dial(path, type: .stream)
    let link = try await pending.get()
    let collector = Collector()
    try await link.eventLoop.submit { link.attach(collector) }.get()

    // A framed frame from the first guest.
    var wire = ByteBuffer()
    let frame = ethernetFrame(payload: 40)
    wire.writeInteger(UInt32(frame.count), endianness: .big)
    wire.writeBytes(frame)
    let bytes = Array(wire.readableBytesView)
    #expect(bytes.withUnsafeBytes { write(first, $0.baseAddress, $0.count) } == bytes.count)

    var received: [[UInt8]] = []
    for _ in 0..<400 where received.isEmpty {
        received = try await link.eventLoop.submit { collector.frames }.get()
        if received.isEmpty { try await Task.sleep(nanoseconds: 5_000_000) }
    }
    #expect(received.first?.count == frame.count)

    // A second guest is closed rather than served.
    let second = dial(path, type: .stream)
    var probe = [UInt8](repeating: 0, count: 16)
    var closed = false
    for _ in 0..<400 where !closed {
        let n = probe.withUnsafeMutableBytes { recv(second, $0.baseAddress, $0.count, dontWait) }
        if n == 0 { closed = true } else { try await Task.sleep(nanoseconds: 5_000_000) }
    }
    #expect(closed, "a second guest was left connected to a wire that carries one")

    _ = try? await link.close().get()
    close(first)
    close(second)
    try? FileManager.default.removeItem(atPath: path)
    try? await group.shutdownGracefully()
}

// The test above holds the first guest open, which is the case a test author
// writes and not the one a VM lives. A VM reboots: its connection dies, and the
// next one is the same guest coming back.
//
// That connection used to be accepted and closed. The slot was taken once and
// never released, so a rebooted guest could not reconnect and the gateway had to
// be restarted alongside the VM. The datagram wire never had the problem — its
// peer is whoever last sent — which is exactly why nothing noticed.
@Test func aGuestThatGoesAwayReleasesTheWireForTheNextOne() async throws {
    let path = temporaryPath("stream")
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    let pending = WireBootstrap.listeningStreamSocket(
        atPath: path, group: group, linkAddress: listenMAC, mtu: 1500)
    for _ in 0..<400 where !FileManager.default.fileExists(atPath: path) {
        try await Task.sleep(nanoseconds: 5_000_000)
    }

    let first = dial(path, type: .stream)
    let link = try await pending.get()
    let collector = Collector()
    try await link.eventLoop.submit { link.attach(collector) }.get()

    func sendFrame(_ descriptor: Int32) {
        var wire = ByteBuffer()
        let frame = ethernetFrame(payload: 40)
        wire.writeInteger(UInt32(frame.count), endianness: .big)
        wire.writeBytes(frame)
        let bytes = Array(wire.readableBytesView)
        _ = bytes.withUnsafeBytes { write(descriptor, $0.baseAddress, $0.count) }
    }

    func awaitFrames(_ count: Int) async throws -> Int {
        var seen = 0
        for _ in 0..<400 where seen < count {
            seen = try await link.eventLoop.submit { collector.frames.count }.get()
            if seen < count { try await Task.sleep(nanoseconds: 5_000_000) }
        }
        return seen
    }

    sendFrame(first)
    #expect(try await awaitFrames(1) == 1)

    // The guest goes away, the way a rebooting VM does. Waited for rather than
    // assumed: the link learns of it on its own loop, and dialling before it has
    // is a race that would make this test pass for the wrong reason.
    close(first)
    var released = false
    for _ in 0..<400 where !released {
        released = try await link.eventLoop.submit { !link.isActiveForTesting }.get()
        if !released { try await Task.sleep(nanoseconds: 5_000_000) }
    }
    #expect(released, "the link never noticed the guest had gone")

    // And comes back. The same link has to carry it: that is what the stack
    // above is attached to, so a second link would be one nobody is listening
    // to -- which is why this asserts on frames reaching `collector` rather than
    // merely on the connection staying open.
    let second = dial(path, type: .stream)
    sendFrame(second)
    #expect(
        try await awaitFrames(2) == 2,
        "the returning guest's frames did not reach the link the stack is attached to")
    #expect(
        try await link.eventLoop.submit { link.guestsAdopted }.get() == 2,
        "the link did not record a second guest taking it over")

    _ = try? await link.close().get()
    close(second)
    try? FileManager.default.removeItem(atPath: path)
    try? await group.shutdownGracefully()
}

// The guest limit, under the condition it exists for.
//
// `maximumGuests` was checked against the switch's port count -- and the port
// appears a tick after the admission, because the pipeline is configured through
// a `submit`. So every connection in a burst read the same count of zero and
// every one was admitted: the limit was checkable and not enforced, in a package
// whose threat model is that the guest is hostile.
//
// One at a time never showed it. A burst is not a contrived case here; it is
// what a supervisor restarting a pod of VMs does.
@Test func guestsArrivingAtOnceAreBoundedByTheLimitRatherThanAllAdmitted() async throws {
    let path = temporaryPath("switch")
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    let netSwitch = try await WireBootstrap.switchedStreamSocket(
        atPath: path, group: group, linkAddress: listenMAC, mtu: 1500, maximumGuests: 2
    ).get()

    // The loop is held while the connections are made, and that is what makes
    // this a test rather than a coin toss.
    //
    // The window is one hop wide: `configure` finishes on a later tick, so a
    // connection admitted in the same burst as another sees a port count that
    // does not include it yet. Dialling six sockets and hoping they land in one
    // burst reproduces that on this machine and not on CI's -- the guard
    // SURVIVED there, which is a falsification reporting the opposite of the
    // truth. Blocking the loop first removes the timing from the question: every
    // connection is waiting in the backlog before a single accept runs.
    //
    // Blocking an event loop is otherwise forbidden and is exactly the control
    // this needs.
    let held = DispatchSemaphore(value: 0)
    netSwitch.eventLoop.execute { held.wait() }
    let dialled = (0..<6).map { _ in dial(path, type: .stream) }
    held.signal()

    // Given time to settle: the assertion is about where it settles, and an
    // immediate read would pass with the bug simply by looking too early.
    var ports = 0
    for _ in 0..<200 {
        ports = try await netSwitch.eventLoop.submit { netSwitch.portCount }.get()
        if ports >= 2 { break }
        try await Task.sleep(nanoseconds: 5_000_000)
    }
    try await Task.sleep(nanoseconds: 50_000_000)
    ports = try await netSwitch.eventLoop.submit { netSwitch.portCount }.get()

    #expect(ports == 2, "six guests arrived at once and \(ports) were given ports where 2 was the limit")

    for descriptor in dialled { close(descriptor) }
    _ = try? await netSwitch.close().get()
    try? FileManager.default.removeItem(atPath: path)
    try? await group.shutdownGracefully()
}

// And a guest that leaves gives its place back, so the limit is a limit on
// guests present rather than on guests ever seen.
@Test func aGuestLeavingTheSwitchReturnsItsPlace() async throws {
    let path = temporaryPath("switch")
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    let netSwitch = try await WireBootstrap.switchedStreamSocket(
        atPath: path, group: group, linkAddress: listenMAC, mtu: 1500, maximumGuests: 1
    ).get()

    func portsSettleAt(_ wanted: Int) async throws -> Int {
        var ports = 0
        for _ in 0..<200 {
            ports = try await netSwitch.eventLoop.submit { netSwitch.portCount }.get()
            if ports == wanted { return ports }
            try await Task.sleep(nanoseconds: 5_000_000)
        }
        return ports
    }

    let first = dial(path, type: .stream)
    #expect(try await portsSettleAt(1) == 1)
    close(first)
    #expect(try await portsSettleAt(0) == 0, "the departed guest kept its port")

    let second = dial(path, type: .stream)
    #expect(try await portsSettleAt(1) == 1, "the freed place was not given to the next guest")

    close(second)
    _ = try? await netSwitch.close().get()
    try? FileManager.default.removeItem(atPath: path)
    try? await group.shutdownGracefully()
}

// hyperkit's opening exchange, byte for byte.
//
// The sizes are hyperkit's and they are exact: 49 in, 49 back, 41 in, 258 out.
// There is nothing to negotiate and no version to check, which means a
// generously-written implementation -- one that accepted a short message, or
// replied with as many bytes as it had -- would be wrong in a way that only
// hyperkit itself could tell you about.
@Test func theVpnKitHandshakeIsExactlyTheSizesHyperkitExpects() async throws {
    let path = temporaryPath("vpnkit")
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    let told = MACAddress("aa:bb:cc:dd:ee:01")!
    let uuid = "1e0a4f1a-0000-4000-8000-0123456789ab"
    let netSwitch = try await WireBootstrap.vpnKitStreamSocket(
        atPath: path, group: group, linkAddress: listenMAC, mtu: 1500,
        macForUUID: { asked in asked == uuid ? told : MACAddress("00:00:00:00:00:00")! }
    ).get()

    let guest = dial(path, type: .stream)

    // Sent in two writes, deliberately: a socket delivers bytes, not messages,
    // and an implementation that read whatever one `read` returned would pass a
    // single-write test and fail on a real hyperkit.
    let initial = [UInt8]("VMN3T".utf8) + [UInt8](repeating: 0, count: 44)
    #expect(initial.count == 49)
    _ = Array(initial[0..<20]).withUnsafeBytes { write(guest, $0.baseAddress, $0.count) }
    try await Task.sleep(nanoseconds: 20_000_000)
    _ = Array(initial[20...]).withUnsafeBytes { write(guest, $0.baseAddress, $0.count) }

    func readExactly(_ count: Int) async throws -> [UInt8] {
        var collected = [UInt8]()
        var buffer = [UInt8](repeating: 0, count: count)
        // Ten seconds, not two. A loaded CI runner took nineteen seconds over
        // tests that finish here in milliseconds, and a budget that runs out
        // does not report a slow machine -- it reports whatever the assertions
        // below make of an empty array.
        for _ in 0..<2000 where collected.count < count {
            let read = buffer.withUnsafeMutableBytes {
                recv(guest, $0.baseAddress, count - collected.count, dontWait)
            }
            if read > 0 {
                collected.append(contentsOf: buffer[0..<read])
            } else {
                try await Task.sleep(nanoseconds: 5_000_000)
            }
        }
        return collected
    }

    let echoed = try await readExactly(49)
    #expect(echoed == initial, "the init message was not echoed back verbatim")

    let command = [UInt8(1)] + [UInt8](uuid.utf8) + [UInt8](repeating: 0, count: 4)
    #expect(command.count == 41)
    _ = command.withUnsafeBytes { write(guest, $0.baseAddress, $0.count) }

    let reply = try await readExactly(258)
    // Required before anything indexes into it. A short read here used to reach
    // the assertions below, index an empty array, and kill the process with
    // "Index out of range" -- which takes down every other test in the run and
    // reports a crash where a failure belonged.
    try #require(reply.count == 258, "the reply was \(reply.count) bytes where hyperkit reads 258")
    #expect(reply.first == 0x01)
    #expect(UInt16(reply[1]) | UInt16(reply[2]) << 8 == 1500, "the MTU was not what the switch was built with")
    // The frame size, which is the MTU plus an ethernet header. A reply that
    // forgot the header would have hyperkit truncating every full-sized frame.
    #expect(UInt16(reply[3]) | UInt16(reply[4]) << 8 == 1514)
    #expect(Array(reply[5..<11]) == told.bytes, "the guest was given the wrong address for its UUID")
    #expect(Array(reply[11...]).allSatisfy { $0 == 0 }, "the tail of the reply is meant to be zero")

    close(guest)
    _ = try? await netSwitch.close().get()
    try? FileManager.default.removeItem(atPath: path)
    try? await group.shutdownGracefully()
}

// A peer that connects to the vpnkit wire and says nothing.
//
// It holds a place on the switch it has not earned. Thirty-two of those -- the
// default guest limit -- and no real guest can join, for as long as the attacker
// leaves the sockets open, which is forever:
//
//     silent connections held open: 32
//     a real guest was CLOSED OUT by peers that never spoke
//
// Everything else guest-reachable in this package is bounded on the premise that
// a connection held open is a resource. This was written without a bound, in a
// package whose threat model is that the guest is hostile, and measured before
// it was fixed rather than reasoned about after.
@Test func aPeerThatNeverFinishesTheVpnKitHandshakeGivesItsPlaceBack() async throws {
    let path = temporaryPath("vpnkit")
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    // Short, so the test measures the rule and not the clock.
    let netSwitch = try await WireBootstrap.vpnKitStreamSocket(
        atPath: path, group: group, linkAddress: listenMAC, mtu: 1500, maximumGuests: 2,
        handshakeAllowance: .milliseconds(200)
    ).get()

    func portsSettleAt(_ wanted: Int) async throws -> Int {
        var ports = 0
        for _ in 0..<200 {
            ports = try await netSwitch.eventLoop.submit { netSwitch.portCount }.get()
            if ports == wanted { return ports }
            try await Task.sleep(nanoseconds: 5_000_000)
        }
        return ports
    }

    // Two peers that connect and never speak: the whole wire, by the limit.
    let silent = (0..<2).map { _ in dial(path, type: .stream) }

    // Waited out, because a guest arriving before the allowance has expired is
    // refused and should be -- the wire really is full until then. The claim is
    // that the places come back, not that they were never taken.
    // No assertion on the port count here, and that is deliberate: a port is
    // only granted at the END of the handshake, so a silent peer never has one
    // and the count is zero whether the allowance works or not. An assertion
    // there cannot fail, which makes it worse than none -- it would read as
    // coverage of exactly the rule it cannot see.
    //
    // What the silent peers hold is an admission, and the thing that can be
    // observed from outside is its consequence: whether a real guest gets in.
    try await Task.sleep(nanoseconds: 500_000_000)

    // A real guest, arriving to a wire the silent peers have been let go of.
    //
    // Both messages in one write. This test is about the allowance, and sending
    // them separately makes it about the allowance AND how fast the test can
    // poll: the guest's own clock starts when it connects, and on a slow machine
    // the gap between the two writes ate the two hundred milliseconds and the
    // gateway closed a guest that was doing everything right. Partial reads are
    // the subject of `theVpnKitHandshakeIsExactlyTheSizesHyperkitExpects`, which
    // splits the init deliberately.
    //
    // Retried, because the allowance expires on the gateway's own loop and a
    // guest that arrives a moment early is refused -- correctly. Bounded, and
    // far short of "never": with the allowance gone the places are never given
    // back and no number of attempts helps.
    let uuid = "1e0a4f1a-0000-4000-8000-0123456789ab"
    let opening =
        [UInt8]("VMN3T".utf8) + [UInt8](repeating: 0, count: 44)
        + [UInt8(1)] + [UInt8](uuid.utf8) + [UInt8](repeating: 0, count: 4)
    var guest: Int32 = -1
    var ports = 0
    for _ in 0..<20 where ports != 1 {
        if guest >= 0 { close(guest) }
        guest = dial(path, type: .stream)
        _ = opening.withUnsafeBytes { write(guest, $0.baseAddress, $0.count) }
        ports = try await portsSettleAt(1)
        if ports != 1 { try await Task.sleep(nanoseconds: 25_000_000) }
    }
    #expect(
        ports == 1,
        "a guest that completed the handshake got no port: the silent peers never let go")

    for descriptor in silent { close(descriptor) }
    close(guest)
    _ = try? await netSwitch.close().get()
    try? FileManager.default.removeItem(atPath: path)
    try? await group.shutdownGracefully()
}

// Closing a switch stops the thing that puts guests on it.
//
// It used to close the ports and leave the listener behind: the socket path
// stayed bound, and a guest connecting afterwards was still accepted -- onto a
// switch whose ports had all been closed. Measured before it was fixed:
//
//     PROBE: connecting after the switch closed -> ACCEPTED (listener still open)
//
// For the seqpacket wire it is worse, because that listener is a thread blocked
// in `accept`: every gateway a long-running embedder created and closed left one
// behind. Nothing can reach that thread except closing the descriptor it is
// waiting on, which is what `stopListening` does there.
@Test func closingASwitchStopsItsListener() async throws {
    let path = temporaryPath("switch")
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    let netSwitch = try await WireBootstrap.switchedStreamSocket(
        atPath: path, group: group, linkAddress: listenMAC, mtu: 1500
    ).get()

    // Open first, so the test is about closing rather than about binding.
    let before = dial(path, type: .stream)
    close(before)

    _ = try? await netSwitch.close().get()

    // The listener is gone when a connection is refused. Retried, because the
    // close completes on the switch's loop and the socket goes with it.
    var refused = false
    for _ in 0..<200 where !refused {
        let after = makeSocket(AF_UNIX, .stream)
        refused = connectTo(after, unixAddress(path: path)) != 0
        close(after)
        if !refused { try await Task.sleep(nanoseconds: 5_000_000) }
    }
    #expect(refused, "a guest was accepted onto a switch that had been closed")

    try? FileManager.default.removeItem(atPath: path)
    try? await group.shutdownGracefully()
}
