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
private func dial(_ path: String, type: Int32) -> Int32 {
    let fd = socket(AF_UNIX, type, 0)
    #expect(fd >= 0)
    var address = sockaddr_un()
    address.sun_family = sa_family_t(AF_UNIX)
    address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
    _ = withUnsafeMutablePointer(to: &address.sun_path) { raw in
        path.withCString { source in
            raw.withMemoryRebound(to: CChar.self, capacity: 104) { destination in
                strncpy(destination, source, 103)
            }
        }
    }
    let connected = withUnsafePointer(to: &address) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
        }
    }
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
    let guest = socket(AF_UNIX, SOCK_DGRAM, 0)
    var guestAddress = sockaddr_un()
    guestAddress.sun_family = sa_family_t(AF_UNIX)
    guestAddress.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
    _ = withUnsafeMutablePointer(to: &guestAddress.sun_path) { raw in
        guestPath.withCString { source in
            raw.withMemoryRebound(to: CChar.self, capacity: 104) { strncpy($0, source, 103) }
        }
    }
    #expect(withUnsafePointer(to: &guestAddress) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            bind(guest, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
        }
    } == 0)
    var target = sockaddr_un()
    target.sun_family = sa_family_t(AF_UNIX)
    target.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
    _ = withUnsafeMutablePointer(to: &target.sun_path) { raw in
        path.withCString { source in
            raw.withMemoryRebound(to: CChar.self, capacity: 104) { strncpy($0, source, 103) }
        }
    }

    let outbound = ethernetFrame(payload: 40)
    let sent = outbound.withUnsafeBytes { bytes in
        withUnsafePointer(to: &target) { addr in
            addr.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                sendto(guest, bytes.baseAddress, bytes.count, 0, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
    }
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
        let n = back.withUnsafeMutableBytes { recv(guest, $0.baseAddress, $0.count, MSG_DONTWAIT) }
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
    let first = dial(path, type: SOCK_STREAM)
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
    let second = dial(path, type: SOCK_STREAM)
    var probe = [UInt8](repeating: 0, count: 16)
    var closed = false
    for _ in 0..<400 where !closed {
        let n = probe.withUnsafeMutableBytes { recv(second, $0.baseAddress, $0.count, MSG_DONTWAIT) }
        if n == 0 { closed = true } else { try await Task.sleep(nanoseconds: 5_000_000) }
    }
    #expect(closed, "a second guest was left connected to a wire that carries one")

    _ = try? await link.close().get()
    close(first)
    close(second)
    try? FileManager.default.removeItem(atPath: path)
    try? await group.shutdownGracefully()
}
