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

@Test func aSecondCloseWhileTheFirstIsWaitingDoesNotStrandIt() async throws {
    // A deferred close stores its promise. A second close arriving while the
    // first still waits used to overwrite it, and the first caller was then
    // waiting on a completion that had been discarded -- a promise that never
    // reaches a terminal state, which in NIO is a leak with a precondition
    // failure attached to it.
    //
    // Closing twice is not exotic: a splice closes from either side, and both
    // sides can end at once.
    let fixture = TCPFixture()
    do {
        let (server, collector) = try servingFixture(fixture, installRecorder: false)
        try withExtendedLifetime(server) {
            fixture.inject(
                guestSegment(sequence: guestISS, flags: [.syn], options: [.maximumSegmentSize(1460)]))
            let synAck = fixture.drainSegments().first { $0.header.flags.contains(.syn) }
            let iss = synAck?.header.sequence.value ?? 0
            fixture.inject(
                guestSegment(sequence: guestISS + 1, ack: iss &+ 1, flags: [.ack], window: 200))
            let child = try #require(collector.children.first)
            _ = fixture.drainSegments()

            var written = 0
            while written < TCPEndpoint.sendBufferBytes + 64 * 1024 {
                var payload = ByteBufferAllocator().buffer(capacity: 64 * 1024)
                payload.writeBytes([UInt8](repeating: 0x5a, count: 64 * 1024))
                child.writeAndFlush(payload, promise: nil)
                written += 64 * 1024
            }
            _ = fixture.drainSegments()

            let first = child.eventLoop.makePromise(of: Void.self)
            let firstOutcome = Outcome()
            first.futureResult.whenComplete { firstOutcome.result = $0 }
            child.close(promise: first)

            let second = child.eventLoop.makePromise(of: Void.self)
            let secondOutcome = Outcome()
            second.futureResult.whenComplete { secondOutcome.result = $0 }
            child.close(promise: second)

            guard case .failure(let error) = secondOutcome.result else {
                Issue.record("the second close was accepted: \(String(describing: secondOutcome.result))")
                return
            }
            #expect(error as? ChannelError == .alreadyClosed)

            // And the first still finishes, rather than being forgotten.
            var acknowledged = UInt32(0)
            for _ in 0..<400 where firstOutcome.result == nil {
                fixture.inject(
                    guestSegment(
                        sequence: guestISS + 1, ack: iss &+ 1 &+ acknowledged, flags: [.ack],
                        window: 32000))
                acknowledged += UInt32(
                    fixture.drainSegments().reduce(0) { $0 + $1.payload.readableBytes })
            }
            #expect(
                firstOutcome.result != nil,
                "the first close never completed, so its caller waits for ever")
        }
    }
    fixture.drain()
}

@Test func aClosedChannelDoesNotTakeItsConnectionWithItMidSend() async throws {
    // The channel is normally the last strong reference to its endpoint -- the
    // demuxer holds delegates weakly, deliberately -- and `close()` is
    // asynchronous, because the FIN waits behind the payload and the payload
    // waits on the peer's window. So releasing the channel the moment its own
    // queue empties deallocates a connection with bytes still to send.
    //
    // What this test does NOT do is prove that, and neither does anything else
    // here. It was written to, and it cannot: mutating the retention away
    // leaves it passing, because ARC is under no obligation to release a local
    // at the end of its scope and in a debug build it generally does not. The
    // acceptance script's reset check does not falsify it either -- the
    // symptom it was written for is a race, seen twice and not reproducible on
    // demand.
    //
    // So the retention is justified by the endpoint's contract rather than by a
    // guard: the demuxer holds its delegates weakly, this channel is the last
    // strong reference, and `close()` is asynchronous by that type's own
    // documentation -- "`onClosed` is the only way to learn it finished".
    // Releasing the endpoint before then can only end a connection early. It is
    // not in `guards.tsv`, because a row there would report an outcome it did
    // not earn.
    //
    // What this test does keep is worth keeping on its own: the connection
    // finishes what it was given, and ends, with the channel closed.
    let fixture = TCPFixture()
    do {
        var acknowledged = UInt32(0)
        var written = 0
        weak var observed: TCPEndpoint?
        do {
            let endpoint = try listeningEndpoint(fixture)
            let channel = NetstackStreamChannel(
                eventLoop: fixture.stack.eventLoop, endpoint: endpoint, owns: true, parent: nil)
            channel.installCallbacks()
            channel.registerAlreadyConfigured0(promise: nil)

            fixture.inject(guestSegment(sequence: guestISS, flags: [.syn]))
            _ = fixture.drainSegments()
            fixture.inject(
                guestSegment(sequence: guestISS + 1, ack: gatewayISS &+ 1, flags: [.ack], window: 200))
            _ = fixture.drainSegments()

            while written < TCPEndpoint.sendBufferBytes {
                var payload = ByteBufferAllocator().buffer(capacity: 64 * 1024)
                payload.writeBytes([UInt8](repeating: 0x5a, count: 64 * 1024))
                channel.writeAndFlush(payload, promise: nil)
                written += 64 * 1024
            }
            acknowledged = UInt32(fixture.drainSegments().reduce(0) { $0 + $1.payload.readableBytes })
            channel.close(promise: nil)
            #expect(
                endpoint.owedBytes > 0,
                "positive control: the connection should still owe bytes when the channel goes")
            observed = endpoint
        }
        // Driven so that `finish`'s deferred handler removal actually runs.
        // That is what breaks the channel <-> pipeline cycle and releases the
        // channel, and with it the only strong reference to the endpoint --
        // without it the references linger and this test measures nothing.
        fixture.advance(by: .milliseconds(1))
        #expect(
            observed != nil,
            "the connection was deallocated with bytes still owed, so nothing can send them")

        // The channel and every reference this test held are gone.
        var delivered = Int(acknowledged)
        var sawFin = false
        for _ in 0..<400 where !sawFin {
            fixture.inject(
                guestSegment(
                    sequence: guestISS + 1, ack: gatewayISS &+ 1 &+ UInt32(delivered), flags: [.ack],
                    window: 32000))
            let more = fixture.drainSegments()
            delivered += more.reduce(0) { $0 + $1.payload.readableBytes }
            sawFin = more.contains { $0.header.flags.contains(.fin) }
        }
        #expect(delivered == written, "\(written - delivered) bytes died with the channel")
        #expect(sawFin, "the connection stopped mid-stream and never ended")
    }
    fixture.drain()
}

@Test func aDeferredCloseEndsWithAFinRatherThanSilence() async throws {
    // The channel the outbound forwarder builds OWNS its endpoint, so its close
    // is the whole close: nobody else will send the FIN. A close deferred
    // behind a full queue therefore has to arrive at one, or the peer is left
    // waiting on a stream nothing will ever end.
    //
    // A real guest saw exactly that. A host reset mid-transfer, the gateway
    // handed on the 539,085 bytes it was holding, and then sent nothing at all
    // -- no FIN, no reset -- until the guest's own timeout gave up 40 seconds
    // later. Note the shape: the server-child tests above cannot see this,
    // because a child does not own its endpoint and its owner sends the FIN.
    let fixture = TCPFixture()
    do {
        let endpoint = try listeningEndpoint(fixture)
        let channel = NetstackStreamChannel(
            eventLoop: fixture.stack.eventLoop, endpoint: endpoint, owns: true, parent: nil)
        withExtendedLifetime(channel) {
            channel.allowHalfClosure()
            channel.installCallbacks()
            channel.registerAlreadyConfigured0(promise: nil)

            fixture.inject(guestSegment(sequence: guestISS, flags: [.syn]))
            _ = fixture.drainSegments()
            fixture.inject(
                guestSegment(sequence: guestISS + 1, ack: gatewayISS &+ 1, flags: [.ack], window: 200))
            _ = fixture.drainSegments()

            var written = 0
            while written < TCPEndpoint.sendBufferBytes + 128 * 1024 {
                var payload = ByteBufferAllocator().buffer(capacity: 64 * 1024)
                payload.writeBytes([UInt8](repeating: 0x5a, count: 64 * 1024))
                channel.writeAndFlush(payload, promise: nil)
                written += 64 * 1024
            }
            var delivered = fixture.drainSegments().reduce(0) { $0 + $1.payload.readableBytes }

            channel.close(promise: nil)

            var acknowledged = UInt32(delivered)
            var sawFin = false
            for _ in 0..<400 where !sawFin {
                fixture.inject(
                    guestSegment(
                        sequence: guestISS + 1, ack: gatewayISS &+ 1 &+ acknowledged, flags: [.ack],
                        window: 32000))
                let more = fixture.drainSegments()
                delivered += more.reduce(0) { $0 + $1.payload.readableBytes }
                acknowledged = UInt32(delivered)
                sawFin = more.contains { $0.header.flags.contains(.fin) }
            }
            #expect(delivered == written, "\(written - delivered) bytes were discarded by the close")
            #expect(sawFin, "the queue drained and the connection was left open in silence")
        }
    }
    fixture.drain()
}

@Test func aCloseWaitingOnAPeerThatStopsReadingGivesUp() async throws {
    // The deferral above waits for the peer's window, and a peer can decline to
    // open it for ever. That would be a channel, an endpoint and -- on a
    // gateway -- the host socket spliced to it, held by a guest that has only
    // to stop reading.
    //
    // The first version of this test asserted that the CONNECTION bounded it:
    // persist, then keep-alive, then a reset. It does not, and it must not --
    // RFC 1122 §4.2.2.17 makes timing out a zero-window connection a MUST NOT,
    // and this package honours that deliberately. The counterweight RFC 6429 §4
    // names is the application's close, which is exactly what the deferral had
    // taken away. So the bound is the channel's own, and this test is what
    // found that out: written to confirm a claim, it failed, and the claim was
    // wrong rather than the test.
    let fixture = TCPFixture()
    do {
        let (server, collector) = try servingFixture(fixture, installRecorder: false)
        try withExtendedLifetime(server) {
            fixture.inject(
                guestSegment(sequence: guestISS, flags: [.syn], options: [.maximumSegmentSize(1460)]))
            let synAck = fixture.drainSegments().first { $0.header.flags.contains(.syn) }
            let iss = synAck?.header.sequence.value ?? 0
            fixture.inject(
                guestSegment(sequence: guestISS + 1, ack: iss &+ 1, flags: [.ack], window: 200))
            let child = try #require(collector.children.first)
            _ = fixture.drainSegments()

            var written = 0
            while written < TCPEndpoint.sendBufferBytes + 128 * 1024 {
                var payload = ByteBufferAllocator().buffer(capacity: 64 * 1024)
                payload.writeBytes([UInt8](repeating: 0x5a, count: 64 * 1024))
                child.writeAndFlush(payload, promise: nil)
                written += 64 * 1024
            }
            _ = fixture.drainSegments()

            let closed = child.eventLoop.makePromise(of: Void.self)
            // Read through a box rather than waited on. Without the linger this
            // promise is never settled at all, so a `wait()` here would hang
            // the falsification instead of failing it -- and a gate that hangs
            // reports nothing. It hung, which is how this got noticed.
            let outcome = Outcome()
            closed.futureResult.whenComplete { outcome.result = $0 }
            child.close(promise: closed)
            #expect(child.isActive, "positive control: the close is waiting, not done")

            // A guest that is present, answering, and simply not reading:
            // every probe is acknowledged with a window of zero. This is the
            // case the linger is for, and the only one where it is the thing
            // that ends the wait -- a guest that stopped answering ALTOGETHER
            // is ended by the connection's own retransmission budget instead,
            // which would have made this test pass without a linger at all.
            var acknowledged = UInt32(0)
            for _ in 0..<20 where child.isActive {
                fixture.advance(by: .seconds(10))
                acknowledged = UInt32(fixture.link.drainTransmitted().count)
                fixture.inject(
                    guestSegment(
                        sequence: guestISS + 1, ack: iss &+ 1 &+ min(acknowledged, 200),
                        flags: [.ack], window: 0))
            }
            #expect(
                !child.isActive,
                "the close is still waiting on a guest that has taken nothing for minutes")
            guard case .success = outcome.result else {
                Issue.record("the close never completed: \(String(describing: outcome.result))")
                return
            }
        }
    }
    fixture.drain()
}

@Test func closingAChannelWithWritesStillQueuedSendsThemFirst() async throws {
    // A close is not a discard. The splice writes with no promise, so a close
    // that failed what was queued lost the bytes AND said nothing -- and this
    // is the ordinary end of every proxied connection: the far side finishes,
    // the glue closes this side, and whatever the peer's window had not yet
    // allowed out went with it.
    //
    // Measured against a real guest before this: a host sending 1,000,000
    // bytes had its `sendall` complete, and the guest received 400,160 of
    // them. The gateway's own log said `finish … pending=10`, ten chunks
    // failed on the way out.
    let fixture = TCPFixture()
    do {
        let (server, collector) = try servingFixture(fixture, installRecorder: false)
        try withExtendedLifetime(server) {
            // A window of 200 bytes, so most of what is written cannot go yet.
            fixture.inject(
                guestSegment(sequence: guestISS, flags: [.syn], options: [.maximumSegmentSize(1460)]))
            let synAck = fixture.drainSegments().first { $0.header.flags.contains(.syn) }
            let iss = synAck?.header.sequence.value ?? 0
            fixture.inject(
                guestSegment(sequence: guestISS + 1, ack: iss &+ 1, flags: [.ack], window: 200))
            let child = try #require(collector.children.first)
            _ = fixture.drainSegments()

            // More than the send buffer holds, so the writes past it stay in
            // the CHANNEL's queue rather than the endpoint's. That is the queue
            // a close discards, and reaching it is the whole point: 4000 bytes
            // would sit entirely in the send buffer and this test would pass
            // without ever touching the path it is named for.
            let total = TCPEndpoint.sendBufferBytes + 128 * 1024
            let chunk = 64 * 1024
            var written = 0
            while written < total {
                var payload = ByteBufferAllocator().buffer(capacity: chunk)
                payload.writeBytes([UInt8](repeating: 0x5a, count: chunk))
                child.writeAndFlush(payload, promise: nil)
                written += chunk
            }
            let firstBurst = fixture.drainSegments().reduce(0) { $0 + $1.payload.readableBytes }
            #expect(
                firstBurst < written,
                "positive control: the window let all \(firstBurst) bytes out at once")

            // The far side of the splice has finished, so the glue closes this.
            child.close(promise: nil)

            // The guest reads what it took and opens up, repeatedly, the way a
            // draining reader does.
            var delivered = firstBurst
            var acknowledged = UInt32(firstBurst)
            for _ in 0..<400 where delivered < written {
                fixture.inject(
                    guestSegment(
                        sequence: guestISS + 1, ack: iss &+ 1 &+ acknowledged, flags: [.ack],
                        window: 32000))
                let more = fixture.drainSegments()
                delivered += more.reduce(0) { $0 + $1.payload.readableBytes }
                acknowledged = UInt32(delivered)
            }
            #expect(
                delivered == written,
                "the close discarded \(written - delivered) of \(written) bytes it had accepted")
        }
    }
    fixture.drain()
}

@Test func aWriteAfterTheOutputIsClosedIsRefusedRatherThanQueued() async throws {
    // Half-closure gives this channel a state it never had: open for reading,
    // finished for writing. A write there cannot be honoured. Queueing it would
    // be worse than refusing -- the FIN either has already gone, making these
    // bytes data past the end of the stream, or is still waiting behind the
    // queue this write would join, which postpones the close for as long as
    // anything keeps writing.
    let fixture = TCPFixture()
    do {
        let (server, collector) = try servingFixture(fixture)
        try withExtendedLifetime(server) {
            handshakeThroughForwarder(fixture)
            let child = try #require(collector.children.first)
            try child.setOption(ChannelOptions.allowRemoteHalfClosure, value: true).wait()

            let closed = child.eventLoop.makePromise(of: Void.self)
            child.close(mode: .output, promise: closed)
            #expect(throws: Never.self) { try closed.futureResult.wait() }
            #expect(child.isActive, "an output close is not a close")

            var payload = ByteBufferAllocator().buffer(capacity: 4)
            payload.writeString("late")
            let refused = child.eventLoop.makePromise(of: Void.self)
            // Not `wait()`. The behaviour this guards against is a write that is
            // QUEUED rather than refused, and a queued write's promise is never
            // settled at all -- so a check that waited on it would hang instead
            // of failing, and a gate that hangs reports nothing.
            let outcome = Outcome()
            refused.futureResult.whenComplete { outcome.result = $0 }
            child.writeAndFlush(payload, promise: refused)
            guard case .failure(let error) = outcome.result else {
                Issue.record("the write was queued rather than refused after the output was closed")
                return
            }
            #expect(error as? ChannelError == .outputClosed)
        }
    }
    fixture.drain()
}

@Test func aChannelBuiltOverAnAlreadyHalfClosedEndpointStillHearsAboutIt() async throws {
    // The FIN can be older than the channel. The outbound forwarder builds the
    // guest-side channel only once the host has been dialled, so a guest that
    // hangs up its send side immediately -- `nc` with no stdin does it within a
    // millisecond of the handshake -- reaches CLOSE-WAIT before there is a
    // pipeline to tell. A FIN is not re-sent, and the next segment that would
    // raise the state again may never come, so the channel has to ask.
    //
    // Deterministic where the forwarder tests are not: the endpoint is driven
    // to CLOSE-WAIT here, in order, before the channel exists at all.
    let fixture = TCPFixture()
    do {
        let endpoint = try listeningEndpoint(fixture)
        try withExtendedLifetime(endpoint) {
            fixture.inject(guestSegment(sequence: guestISS, flags: [.syn]))
            _ = fixture.drainSegments()
            fixture.inject(guestSegment(sequence: guestISS + 1, ack: gatewayISS &+ 1, flags: [.ack]))
            fixture.inject(guestSegment(sequence: guestISS + 1, ack: gatewayISS &+ 1, flags: [.fin, .ack]))
            _ = fixture.drainSegments()

            let channel = NetstackStreamChannel(
                eventLoop: fixture.stack.eventLoop, endpoint: endpoint, owns: false, parent: nil)
            channel.allowHalfClosure()
            channel.installCallbacks()
            let watcher = HalfCloseWatcher()
            try channel.pipeline.syncOperations.addHandler(watcher)
            channel.registerAlreadyConfigured0(promise: nil)

            #expect(watcher.inputClosed, "the FIN that arrived before the channel was never reported")
            #expect(!watcher.inactive, "the channel closed instead of half-closing")
        }
    }
    fixture.drain()
}

/// A promise's outcome, read back on the same loop turn that settled it.
///
/// `@unchecked` for the reason everything else in this fixture is: the callback
/// and the read both happen on the one loop this test drives, and the compiler
/// cannot see that through `whenComplete`'s `@Sendable`.
private final class Outcome: @unchecked Sendable {
    var result: Result<Void, Error>?
}

/// Records the half-close events a splice depends on.
private final class HalfCloseWatcher: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    var inputClosed = false
    var inactive = false

    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        if case ChannelEvent.inputClosed = event { inputClosed = true }
        context.fireUserInboundEventTriggered(event)
    }
    func channelInactive(context: ChannelHandlerContext) { inactive = true }
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
        withExtendedLifetime(server) {
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
        withExtendedLifetime(server) {
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
        withExtendedLifetime((first, second)) {
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
        withExtendedLifetime(server) {
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

// A write issued before the connection is established.
//
// Every test above writes to a channel that is already active, which is the
// ordering a test author picks and not the one a client uses. A client connects
// and writes at once -- an HTTP request is in flight long before any handshake
// downstream of it has finished -- and on a forwarded host port those bytes
// reach a guest-side channel that is still connecting.
//
// They were dropped there, in silence. The channel refused a write before
// `.active` by failing its promise, and `GlueHandler` writes with no promise, so
// a real connection lost real data and nothing anywhere said so: the handshake
// completed, the connection stayed open, and the request simply never arrived.
// Found by opening a forwarded port through the built executable and sending on
// it the way a client does; every test in this file passed throughout.
@Test func aWriteBeforeTheConnectionIsEstablishedIsQueuedRatherThanDropped() throws {
    let fixture = TCPFixture()
    do {
        let endpoint = TCPEndpoint(stack: fixture.stack)
        let channel = NetstackStreamChannel(
            eventLoop: fixture.loop, endpoint: endpoint, owns: true, parent: nil)
        channel.installCallbacks()
        try channel.setOption(ChannelOptions.autoRead, value: false).wait()
        channel.register0(promise: nil)
        channel.connect0(
            to: try SocketAddress(ipAddress: tcpGuest.description, port: 8080), promise: nil)

        // The SYN is on the wire and nothing has answered it yet.
        let syn = try #require(fixture.drainSegments().first { $0.header.flags.contains(.syn) })
        #expect(!channel.isActive, "the channel cannot be active before the peer has answered")

        // Written exactly as the splice writes: through the pipeline, with no
        // promise, so a refusal here has nowhere to be reported.
        var out = channel.allocator.buffer(capacity: 5)
        out.writeString("hello")
        channel.writeAndFlush(out, promise: nil)
        #expect(
            fixture.drainSegments().allSatisfy { $0.payload.readableBytes == 0 },
            "bytes went out before the peer accepted the connection")

        // Only now does the peer accept.
        fixture.inject(
            TCPHeader(
                sourcePort: 8080, destinationPort: syn.header.sourcePort,
                sequence: SequenceNumber(guestISS),
                acknowledgement: syn.header.sequence + 1,
                dataOffset: 5, flags: [.syn, .ack], window: 65535, checksum: 0,
                urgentPointer: 0, options: []))

        let carried = fixture.drainSegments().first { $0.payload.readableBytes > 0 }
        #expect(
            carried.map { String(decoding: $0.payload.readableBytesView, as: UTF8.self) } == "hello",
            "the queued bytes were dropped rather than sent once the peer accepted")

        channel.close0(error: ChannelError.alreadyClosed, mode: .all, promise: nil)
    }
    fixture.drain()
}
