import NIOConcurrencyHelpers
import NIOCore
import Testing

@testable import Netstack

// The channel types are where the stack stops speaking in callbacks. The tests
// that matter are not "bytes arrived" — they are the two backpressure paths,
// because a channel that got those wrong would still pass every functional test
// and would turn a bounded receive buffer into an unbounded one.

private final class Recorder: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    var received: [UInt8] = []
    var readComplete = 0
    var inactive = false
    var writabilityChanges: [Bool] = []

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        received.append(contentsOf: unwrapInboundIn(data).readableBytesView)
    }
    func channelReadComplete(context: ChannelHandlerContext) { readComplete += 1 }
    func channelInactive(context: ChannelHandlerContext) { inactive = true }
    func channelWritabilityChanged(context: ChannelHandlerContext) {
        writabilityChanges.append(context.channel.isWritable)
    }
}

/// Accepted children, kept so a test can talk to one.
private final class ChildCollector: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = NetstackStreamChannel
    var children: [NetstackStreamChannel] = []
    let recorder = Recorder()
    let installRecorder: Bool

    init(installRecorder: Bool = true) { self.installRecorder = installRecorder }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let child = unwrapInboundIn(data)
        children.append(child)
        if installRecorder { _ = child.pipeline.addHandler(recorder) }
    }
}

/// A server channel bound to everything, with its accepted children collected.
private func servingFixture(
    _ fixture: TCPFixture, port: Int = 0, autoRead: Bool = true, installRecorder: Bool = true
) throws -> (server: NetstackServerChannel, collector: ChildCollector) {
    let server = NetstackServerChannel(stack: fixture.stack)
    let collector = ChildCollector(installRecorder: installRecorder)
    try server.pipeline.addHandler(collector).wait()
    if !autoRead { try server.setOption(ChannelOptions.autoRead, value: false).wait() }
    try server.bind(to: SocketAddress(ipAddress: "192.168.127.1", port: port)).wait()
    return (server, collector)
}

/// The forwarder builds its own endpoint, so the gateway's ISS is whatever that
/// endpoint chose. Read it off the SYN-ACK rather than assuming a fixture value.
@discardableResult
private func handshakeThroughForwarder(_ fixture: TCPFixture, peerPort: UInt16 = tcpPeerPort) -> UInt32 {
    fixture.inject(
        guestSegment(sequence: guestISS, flags: [.syn], options: [.maximumSegmentSize(1460)], peerPort: peerPort))
    let synAck = fixture.drainSegments().first { $0.header.flags.contains(.syn) }
    let iss = synAck?.header.sequence.value ?? 0
    fixture.inject(guestSegment(sequence: guestISS + 1, ack: iss &+ 1, flags: [.ack], peerPort: peerPort))
    return iss
}

@Test func aConnectionTheGuestOpensArrivesAsAChildChannel() throws {
    let fixture = TCPFixture()
    do {
        let (server, collector) = try servingFixture(fixture)
        try withExtendedLifetime(server) {
            handshakeThroughForwarder(fixture)
            let child = try #require(collector.children.first)
            #expect(child.isActive)
            #expect(child.parent === server)
            // The four-tuple comes from the request, which is the only thing
            // that knows it: the endpoint holds the connection but the channel
            // was never told which port the guest dialled.
            #expect(child.remoteAddress?.port == Int(tcpPeerPort))
            #expect(child.localAddress?.port == 8080)
        }
    }
    fixture.drain()
}

@Test func aChildChannelDeliversTheGuestsBytesToItsPipeline() throws {
    let fixture = TCPFixture()
    do {
        let (server, collector) = try servingFixture(fixture)
        try withExtendedLifetime(server) {
            let iss = handshakeThroughForwarder(fixture)
            _ = fixture.drainSegments()
            fixture.inject(
                guestSegment(sequence: guestISS + 1, ack: iss &+ 1, flags: [.ack, .psh]), payload: tcpPayload(120))
            #expect(collector.recorder.received.count == 120)
            #expect(collector.recorder.readComplete == 1, "one burst, one completion")
        }
    }
    fixture.drain()
}

@Test func aChildChannelWithAutoReadOffLeavesTheBytesWhereTheyShrinkTheWindow() throws {
    // The property the whole `read`/`onData` split exists for, now expressed in
    // NIO's terms. A handler that does not read must not cause a queue to grow
    // anywhere; it must cause the guest to be told to stop.
    //
    // Falsified by draining in `onData` regardless of a pending read — the shape
    // a channel naturally takes if it treats `onData` as a delivery. Both
    // assertions below fail under that edit: the bytes arrive at a handler that
    // never asked, and the window never moves.
    let fixture = TCPFixture()
    do {
        let (server, collector) = try servingFixture(fixture)
        try withExtendedLifetime(server) {
            let iss = handshakeThroughForwarder(fixture)
            _ = fixture.drainSegments()
            let child = try #require(collector.children.first)
            try child.setOption(ChannelOptions.autoRead, value: false).wait()

            var offset = UInt32(1)
            var lastWindow = UInt16(TCPEndpoint.receiveWindowBytes)
            // Sized, not guessed. The guest offered no window scale, so the
            // advertised window is capped at 65535 whatever the buffer holds;
            // it only starts falling once more than `rcvWndMax - 65535` is
            // held. Anything less than that and this watches a window that was
            // never going to move.
            for _ in 0..<250 {
                fixture.inject(
                    guestSegment(sequence: guestISS + offset, ack: iss &+ 1, flags: [.ack, .psh]),
                    payload: tcpPayload(1000))
                offset += 1000
                fixture.advance(by: TCPEndpoint.delayedAckTimeout)
                if let window = fixture.drainSegments().last?.header.window { lastWindow = window }
            }

            #expect(collector.recorder.received.isEmpty, "bytes were delivered to a handler that never read")
            #expect(
                lastWindow < UInt16(TCPEndpoint.receiveWindowBytes),
                "the guest was never told to stop: the bytes went somewhere unbounded")

            // And nothing was lost by holding them: one read takes what the
            // window was being held open... shut... for.
            child.read()
            #expect(collector.recorder.received.count > 0, "the held bytes were unreachable")
        }
    }
    fixture.drain()
}

@Test func aWriteTheSendBufferRefusesMakesTheChannelUnwritableUntilItDrains() throws {
    // The outbound half. `send` refuses rather than truncating, so the channel
    // holds the write; what a handler needs is to be TOLD, and to be told again
    // when it can resume. Before `onWritable` existed there was no second
    // signal at all — the retry rode on inbound data, so a peer that went quiet
    // stalled the write forever.
    let fixture = TCPFixture()
    do {
        let (server, collector) = try servingFixture(fixture)
        try withExtendedLifetime(server) {
            let iss = handshakeThroughForwarder(fixture)
            _ = fixture.drainSegments()
            let child = try #require(collector.children.first)

            // Never acknowledged, so the send buffer fills and stays full.
            // A future has no "is it done yet"; counting completions as they
            // land is the only way to ask, and it is also the honest question:
            // a write promise means the send buffer took the bytes.
            let completed = Counter()
            var issued = 0
            var written = 0
            while child.isWritable && written < 2_000_000 {
                child.writeAndFlush(tcpPayload(16 * 1024)).whenComplete { _ in completed.increment() }
                issued += 1
                written += 16 * 1024
            }
            #expect(!child.isWritable, "the send buffer never refused: the rest proves nothing")
            #expect(
                collector.recorder.writabilityChanges == [false],
                "the handler was not told, or was told more than once")

            let onTheWire = fixture.drainSegments().map(\.payload.readableBytes).reduce(0, +)
            #expect(onTheWire > 0)
            let unfinished = issued - completed.value
            #expect(unfinished > 0, "everything was accepted: nothing is waiting on the drain")

            // The guest acknowledges as the data lands, which is what frees
            // buffer space. One acknowledgement is not enough and that is not a
            // test artefact: the peer's window is 64 KiB and the buffer holds
            // 256, so the transfer genuinely takes several rounds.
            var acknowledged = UInt32(onTheWire)
            for _ in 0..<64 where !child.isWritable {
                fixture.inject(
                    guestSegment(
                        sequence: guestISS + 1, ack: iss &+ 1 &+ acknowledged, flags: [.ack], window: 65535))
                acknowledged += UInt32(fixture.drainSegments().map(\.payload.readableBytes).reduce(0, +))
            }

            #expect(child.isWritable, "the channel never recovered: the write is stalled forever")
            #expect(collector.recorder.writabilityChanges == [false, true])
            #expect(
                issued - completed.value < unfinished,
                "writability was announced but nothing actually drained")
        }
    }
    fixture.drain()
}

@Test func closingTheGuestsEndOfAChildChannelEndsThePipeline() throws {
    let fixture = TCPFixture()
    do {
        let (server, collector) = try servingFixture(fixture)
        try withExtendedLifetime(server) {
            let iss = handshakeThroughForwarder(fixture)
            _ = fixture.drainSegments()
            // Bytes and the FIN together: the FIN says no more will arrive, not
            // that what arrived is void.
            fixture.inject(
                guestSegment(sequence: guestISS + 1, ack: iss &+ 1, flags: [.ack, .fin]), payload: tcpPayload(40))
            #expect(collector.recorder.received.count == 40, "the last bytes were dropped with the FIN")
            #expect(collector.recorder.inactive)
            #expect(collector.children.first?.isActive == false)
        }
    }
    fixture.drain()
}

@Test func aServerBoundToOnePortResetsConnectionsToAnyOther() throws {
    let fixture = TCPFixture()
    do {
        // The guest dials 8080; this server wants 9090 only.
        let (server, collector) = try servingFixture(fixture, port: 9090)
        try withExtendedLifetime(server) {
            fixture.inject(guestSegment(sequence: guestISS, flags: [.syn], peerPort: tcpPeerPort))
            #expect(collector.children.isEmpty)
            let answer = try #require(fixture.drainSegments().first).header
            // Reset, not silence. The forwarder consumed the segment, so nothing
            // else in this process will answer; silence is a hang on the guest.
            #expect(answer.flags.contains(.rst))
            #expect(answer.flags.contains(.ack))
        }
    }
    fixture.drain()
}

@Test func aSecondServerChannelRefusesToDisplaceTheFirstSilently() throws {
    let fixture = TCPFixture()
    do {
        let (first, _) = try servingFixture(fixture)
        let second = NetstackServerChannel(stack: fixture.stack)
        try withExtendedLifetime((first, second)) {
            // There is one demuxer slot per protocol. A second forwarder would
            // take it, and the first would not error — it would simply stop
            // seeing connections, which is the worst way to find out.
            #expect(throws: StackError.portInUse) {
                try second.bind(to: SocketAddress(ipAddress: "192.168.127.1", port: 0)).wait()
            }
            #expect(!second.isActive)
        }
    }
    fixture.drain()
}

@Test func aServerWithAutoReadOffLeavesTheSynUnansweredUntilItAccepts() throws {
    // Accept backpressure, and the reason it needed no queue: an unaccepted
    // request is simply unsettled, so the SYN goes unanswered and the guest
    // retransmits. The bound on how many can pile up is the forwarder's
    // existing SYN-flood bound, not a second one invented here.
    let fixture = TCPFixture()
    do {
        let (server, collector) = try servingFixture(fixture, autoRead: false, installRecorder: false)
        try withExtendedLifetime(server) {
            fixture.inject(guestSegment(sequence: guestISS, flags: [.syn], peerPort: 50001))
            fixture.inject(guestSegment(sequence: guestISS, flags: [.syn], peerPort: 50002))
            #expect(collector.children.isEmpty)
            #expect(fixture.drainSegments().isEmpty, "a SYN was answered before anyone accepted it")

            server.read()
            #expect(collector.children.count == 1, "one read accepted more than one connection")
            #expect(fixture.drainSegments().count == 1, "the second SYN was answered too")

            server.read()
            #expect(collector.children.count == 2)
        }
    }
    fixture.drain()
}
