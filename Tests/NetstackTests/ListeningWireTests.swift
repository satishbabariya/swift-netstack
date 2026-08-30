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

    // Dialled without waiting in between, so every connection is accepted before
    // any of them finishes being configured. That window is the whole bug.
    let dialled = (0..<6).map { _ in dial(path, type: .stream) }

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
