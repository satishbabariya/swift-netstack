import Foundation
import NIOCore
import NIOPosix
import Testing

@testable import Netstack

// What happens when the guest stops reading.
//
// It is not a hypothetical: a VM that is paused, migrating, or simply slow stops
// draining its side of the socket, and the gateway keeps answering into a queue
// that is already full. A unix datagram queue holds about forty frames --
// `net.local.dgram.recvspace` is 4096 on macOS -- so it does not take long.

private let backpressureMAC = MACAddress("0a:0b:0c:0d:0e:0f")!

@Test func aGuestThatStopsReadingDoesNotTakeTheGatewaysWireWithIt() async throws {
    // Before this, it did. A full unix datagram queue reports ENOBUFS on BSD
    // where Linux reports EAGAIN; NIO retries the second and treats the first as
    // an unrecoverable write error, so it closed the channel. The gateway was
    // then permanently off the network -- not slow, not backed up, closed -- and
    // nothing above it noticed: `outboundDropped` was still zero.
    //
    // Upstream has the same failure and the same fix. `pkg/tap/switch.go`
    // retries on ENOBUFS and cites gvisor-tap-vsock#367.
    var pair: [Int32] = [0, 0]
    #expect(makeSocketPair(AF_UNIX, .datagram, &pair) == 0)
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    let gateway = try await Gateway.start(
        adoptingDatagramSocket: pair[0], group: group, configuration: .init()
    ).get()

    // The guest asks two hundred times and reads nothing back, which fills the
    // return queue several times over.
    for transaction in 0..<200 {
        let discover = frame(
            from: .any, to: .broadcast, sourcePort: DHCPServer.clientPort,
            destinationPort: DHCPServer.serverPort,
            payload: dhcpDiscover(hardware: backpressureMAC, transaction: UInt32(transaction)),
            destinationMAC: .broadcast)
        _ = discover.withUnsafeBytes { send(pair[1], $0.baseAddress, $0.count, 0) }
        try await Task.sleep(nanoseconds: 1_000_000)
    }

    let wire = try await gateway.eventLoop.submit {
        (
            open: (gateway.link as? WireLinkEndpoint)?.isActiveForTesting ?? false,
            read: gateway.link.bytesReceived
        )
    }.get()
    #expect(wire.open, "the wire closed because the guest stopped reading")
    // And it kept working while the guest was not reading, rather than stopping
    // at the first refused write.
    #expect(wire.read > 10_000, "the gateway stopped reading after only \(wire.read) bytes")

    // The guest starts reading again.
    for _ in 0..<4000 {
        var back = [UInt8](repeating: 0, count: 4096)
        if back.withUnsafeMutableBytes({ recv(pair[1], $0.baseAddress, $0.count, dontWait) }) <= 0 {
            break
        }
    }

    // And is served again. This is the assertion that matters: a link may drop
    // while its peer is not listening -- that is what a link does -- but it has
    // to come back when the peer does.
    var recovered = false
    for transaction in 900..<960 where !recovered {
        let discover = frame(
            from: .any, to: .broadcast, sourcePort: DHCPServer.clientPort,
            destinationPort: DHCPServer.serverPort,
            payload: dhcpDiscover(hardware: backpressureMAC, transaction: UInt32(transaction)),
            destinationMAC: .broadcast)
        _ = discover.withUnsafeBytes { send(pair[1], $0.baseAddress, $0.count, 0) }
        for _ in 0..<50 where !recovered {
            var back = [UInt8](repeating: 0, count: 4096)
            let read = back.withUnsafeMutableBytes { recv(pair[1], $0.baseAddress, $0.count, dontWait) }
            if read > 42 { recovered = true } else { try await Task.sleep(nanoseconds: 2_000_000) }
        }
    }
    #expect(recovered, "the gateway never answered again after the guest resumed reading")

    _ = try? await gateway.close().get()
    close(pair[1])
    try? await group.shutdownGracefully()
}

// The same question for a stream wire, which had a different and worse answer.
//
// A datagram queue is small and fills; NIO reports the failure and the fix there
// was to stop closing the channel over it. A stream wire has no such limit
// above the socket: NIO holds whatever cannot be written yet, so a guest that
// asks questions and never reads the answers grows that queue as fast as it can
// ask. Four hundred thousand ARP requests, reading nothing:
//
//     rss before:   8432 KiB
//     rss after:  153568 KiB
//
// Every multi-guest wire is a stream wire, so this was the one that mattered
// most and the one nothing looked at. The link drops when its queue is full now,
// which is what a link does.
@Test func aStreamWireDropsRatherThanQueueingForAGuestThatIsNotReading() async throws {
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    var pair: [Int32] = [-1, -1]
    #expect(makeSocketPair(AF_UNIX, .stream, &pair) == 0)

    let link = try await WireBootstrap.adoptingStreamSocket(
        pair[0], group: group, linkAddress: backpressureMAC, mtu: 1500
    ).get()

    // The far end never reads. Its receive buffer fills, then the sending
    // socket's, and after that NIO is holding everything.
    // `let`, because the closure below is `@Sendable` and a captured `var` is
    // not something the compiler will vouch for.
    let frame: ByteBuffer = {
        var buffer = ByteBuffer()
        buffer.writeBytes([UInt8](repeating: 0xAB, count: 1500))
        return buffer
    }()

    // Far more than any buffer between here and there.
    let attempts = 20_000
    try await link.eventLoop.submit {
        for _ in 0..<attempts { link.write([PacketBuffer(allocator: ByteBufferAllocator(), payload: frame)]) }
    }.get()

    let dropped = try await link.eventLoop.submit { link.outboundDropped }.get()
    let backedUp = try await link.eventLoop.submit { link.outboundBackedUp }.get()
    #expect(
        dropped > 0,
        "\(attempts) frames were written to a wire nobody is reading and none was dropped")
    #expect(backedUp > 0, "the wire never reported itself backed up")
    // Bounded by the write watermark rather than by the guest's patience: what
    // matters is that the great majority never entered a queue at all.
    #expect(
        dropped > attempts / 2,
        "only \(dropped) of \(attempts) were dropped, so the rest are still queued")

    _ = try? await link.close().get()
    close(pair[1])
    try? await group.shutdownGracefully()
}

// The same question again for the wire the program actually uses.
//
// `adoptingDatagramSocket` was given a direct-write path because NIO closes a
// datagram channel when a write returns ENOBUFS, and a full unix datagram queue
// returns exactly that on BSD. The LISTENING datagram wire -- `--listen-vfkit`,
// the default, and the one vfkit uses -- was not, and the test above could not
// see it because it adopts a socketpair.
//
// So the fix was in the library and absent from the default path. A guest that
// paused took the gateway's network down for good:
//
//     guest A drained 27 frames it had ignored
//     guest A got no answer -- the wire is dead
//     guest B could not join: ECONNREFUSED
//
// Down for good, and worse than down: the socket was gone, so a replacement
// guest could not connect either. Nothing said anything.
@Test func theListeningDatagramWireSurvivesAGuestThatStopsReading() async throws {
    let path = FileManager.default.temporaryDirectory
        .appendingPathComponent("netstack-flood-\(getpid())-\(UInt32.random(in: 0..<UInt32.max)).sock")
        .path
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    let link = try await WireBootstrap.listeningDatagramSocket(
        atPath: path, group: group, linkAddress: backpressureMAC, mtu: 1500
    ).get()

    // A guest that speaks once, so the peer is learned, and then never reads.
    let guest = makeSocket(AF_UNIX, .datagram)
    let guestPath = path + ".guest"
    try? FileManager.default.removeItem(atPath: guestPath)
    #expect(bindTo(guest, unixAddress(path: guestPath)) == 0)
    #expect(connectTo(guest, unixAddress(path: path)) == 0)
    _ = sendBytes(guest, [UInt8](repeating: 0, count: 64))

    // Waited for, so the link has somewhere to send.
    for _ in 0..<200 {
        let learned = try await link.eventLoop.submit { link.bytesReceived > 0 }.get()
        if learned { break }
        try await Task.sleep(nanoseconds: 5_000_000)
    }

    let frame: ByteBuffer = {
        var buffer = ByteBuffer()
        buffer.writeBytes([UInt8](repeating: 0xCD, count: 1400))
        return buffer
    }()
    try await link.eventLoop.submit {
        for _ in 0..<5000 {
            link.write([PacketBuffer(allocator: ByteBufferAllocator(), payload: frame)])
        }
    }.get()

    // The wire is still there. That is the whole claim: not that every frame
    // arrived -- a link drops when its queue is full -- but that the link is
    // still a link afterwards.
    let alive = try await link.eventLoop.submit { link.isActiveForTesting }.get()
    #expect(alive, "a guest that stopped reading closed the gateway's wire")
    // `outboundBackedUp` rather than `outboundDropped`: the direct-write path
    // keeps them apart on purpose. A frame the kernel refused for a reason that
    // is not "full" is rejected and counted as dropped; a frame the queue had no
    // room for is backed up. Only the second happens here, and asserting on the
    // first passed nothing and proved nothing.
    let backedUp = try await link.eventLoop.submit { link.outboundBackedUp }.get()
    #expect(backedUp > 0, "five thousand frames into a queue of about forty and none backed up")

    close(guest)
    _ = try? await link.close().get()
    try? FileManager.default.removeItem(atPath: guestPath)
    try? FileManager.default.removeItem(atPath: path)
    try? await group.shutdownGracefully()
}
