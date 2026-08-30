import NIOCore
import Testing

@testable import Netstack

// M6's exit criterion: a forwarded connection splices end to end with correct
// backpressure. The interesting half is the second one — a splice is exactly
// where an unbounded queue appears if nobody stops it.

@Test func aSpliceCarriesBytesFromOneConnectionToTheOther() throws {
    let left = TCPFixture()
    let right = TCPFixture()
    do {
        let a = try listeningEndpoint(left)
        let b = try listeningEndpoint(right)
        let splice = TCPSplice(a, b)
        withExtendedLifetime((a, b, splice)) {
            completeHandshake(left)
            completeHandshake(right)
            _ = left.drainSegments()
            _ = right.drainSegments()

            left.inject(
                guestSegment(sequence: guestISS + 1, ack: gatewayISS + 1, flags: [.ack, .psh]),
                payload: tcpPayload(500))

            // The bytes left by the other side, as data on the wire.
            let forwarded = right.drainSegments().filter { $0.payload.readableBytes > 0 }
            #expect(forwarded.map(\.payload.readableBytes).reduce(0, +) == 500)
            #expect(splice.heldForTesting == 0, "nothing had to be held: the far side took it")
        }
    }
    left.drain()
    right.drain()
}

@Test func aSpliceStopsReadingWhenTheFarSideIsFullRatherThanBuffering() throws {
    // The property the whole design is for. The guest can send faster than the
    // far side drains; a splice that read everything offered and kept what would
    // not fit is a guest-controlled allocation with a helpful name.
    //
    // The far side here never acknowledges, so its send buffer fills and stops
    // taking writes. What must NOT happen is the splice growing.
    let left = TCPFixture()
    let right = TCPFixture()
    do {
        let a = try listeningEndpoint(left)
        let b = try listeningEndpoint(right)
        let splice = TCPSplice(a, b)
        withExtendedLifetime((a, b, splice)) {
            completeHandshake(left)
            completeHandshake(right)
            _ = left.drainSegments()
            _ = right.drainSegments()

            var offset = UInt32(0)
            var lastWindow = UInt16(TCPEndpoint.receiveWindowBytes)
            // Sized deliberately. The far side's send buffer takes 256 KiB
            // before it refuses; the splice then holds one 32 KiB chunk and
            // stops reading; only after that does the SOURCE's receive buffer
            // start filling, and the wire window only falls once more than
            // `rcvWndMax - 65535` is held there. Anything less than this and the
            // test watches a window that was never going to move.
            for _ in 0..<700 {
                left.inject(
                    guestSegment(
                        sequence: guestISS + 1 + offset, ack: gatewayISS + 1, flags: [.ack, .psh]),
                    payload: tcpPayload(1000))
                offset += 1000
                left.advance(by: TCPEndpoint.delayedAckTimeout)
                if let window = left.drainSegments().last?.header.window { lastWindow = window }
                _ = right.drainSegments()
            }

            // The splice holds at most one refused write, not the difference
            // between what arrived and what left.
            #expect(
                splice.heldForTesting <= 32 * 1024,
                "the splice buffered without bound: \(splice.heldForTesting) bytes")

            // And the pressure reached the source: the window this stack
            // advertises to the guest fell, which is how the guest is told to
            // stop. Without it the splice would be quietly dropping.
            #expect(
                lastWindow < UInt16(TCPEndpoint.receiveWindowBytes),
                "the source was never told to slow down")
        }
    }
    left.drain()
    right.drain()
}

@Test func closingOneSideOfASpliceClosesTheOther() throws {
    // A half-closed splice is a connection nobody will ever finish. The peer on
    // the far side waits out its own timeouts for a stream that ended.
    let left = TCPFixture()
    let right = TCPFixture()
    do {
        let a = try listeningEndpoint(left)
        let b = try listeningEndpoint(right)
        let splice = TCPSplice(a, b)
        withExtendedLifetime((a, b, splice)) {
            completeHandshake(left)
            completeHandshake(right)
            _ = left.drainSegments()
            _ = right.drainSegments()

            left.inject(guestSegment(sequence: guestISS + 1, ack: gatewayISS + 1, flags: [.ack, .fin]))
            _ = left.drainSegments()

            let closing = right.drainSegments().filter { $0.header.flags.contains(.fin) }
            #expect(closing.count == 1, "the far side was told the stream ended")
        }
    }
    left.drain()
    right.drain()
}


@Test func aSpliceUnderBackpressureLosesNothing() throws {
    // The property the buffering bound does NOT imply, and the one a splice is
    // actually for.
    //
    // Found by falsification: removing the loop's refusal guard left every other
    // splice test green. The retry at the top of `pump` still stopped the *next*
    // pass, so the held-bytes bound held and the window still shrank — but within
    // a pass the splice went on reading and overwriting the one buffer it holds,
    // **silently dropping everything in between**. A bound on what is held says
    // nothing about what arrives.
    //
    // So this counts bytes end to end, with the far side acknowledging as it goes
    // so the pressure comes and goes rather than simply stopping.
    let left = TCPFixture()
    let right = TCPFixture()
    do {
        let a = try listeningEndpoint(left)
        let b = try listeningEndpoint(right)
        let splice = TCPSplice(a, b)
        withExtendedLifetime((a, b, splice)) {
            completeHandshake(left)
            completeHandshake(right)
            _ = left.drainSegments()
            _ = right.drainSegments()

            let total = 200
            var offset = UInt32(0)
            var forwarded = 0
            var farSideAck = UInt32(gatewayISS + 1)
            for _ in 0..<total {
                left.inject(
                    guestSegment(
                        sequence: guestISS + 1 + offset, ack: gatewayISS + 1, flags: [.ack, .psh]),
                    payload: tcpPayload(1000))
                offset += 1000
                left.advance(by: TCPEndpoint.delayedAckTimeout)
                _ = left.drainSegments()

                // Count what left by the far side, and acknowledge it so its
                // send buffer drains and the splice can make progress again.
                for segment in right.drainSegments() where segment.payload.readableBytes > 0 {
                    forwarded += segment.payload.readableBytes
                    farSideAck += UInt32(segment.payload.readableBytes)
                }
                right.inject(
                    guestSegment(sequence: guestISS + 1, ack: farSideAck, flags: [.ack]))
                right.advance(by: TCPEndpoint.delayedAckTimeout)
                for segment in right.drainSegments() where segment.payload.readableBytes > 0 {
                    forwarded += segment.payload.readableBytes
                    farSideAck += UInt32(segment.payload.readableBytes)
                }
            }

            // Drain whatever is still in flight.
            for _ in 0..<20 {
                right.inject(guestSegment(sequence: guestISS + 1, ack: farSideAck, flags: [.ack]))
                right.advance(by: TCPEndpoint.delayedAckTimeout)
                for segment in right.drainSegments() where segment.payload.readableBytes > 0 {
                    forwarded += segment.payload.readableBytes
                    farSideAck += UInt32(segment.payload.readableBytes)
                }
                left.advance(by: TCPEndpoint.delayedAckTimeout)
                _ = left.drainSegments()
            }

            #expect(forwarded == total * 1000, "\(forwarded) of \(total * 1000) bytes arrived")
        }
    }
    left.drain()
    right.drain()
}

@Test func aSpliceDeliversItsHeldChunkOnceTheFarSideDrains() throws {
    // Liveness, which the bound and the no-loss test between them do not cover.
    // Both of those describe a splice under *continuing* pressure — the source
    // keeps sending, so `onData` keeps firing, so the held chunk keeps getting
    // retried. Neither says what happens when the source goes quiet.
    //
    // It went nowhere. The retry lived only on the source's `onData`, so a
    // source that had sent its last byte left the tail of the stream held
    // forever: the far side drained, took acknowledgements, had room — and
    // nothing ever asked it again. A stalled transfer, not a dropped one, which
    // is why no existing assertion saw it.
    let left = TCPFixture()
    let right = TCPFixture()
    do {
        let a = try listeningEndpoint(left)
        let b = try listeningEndpoint(right)
        let splice = TCPSplice(a, b)
        withExtendedLifetime((a, b, splice)) {
            completeHandshake(left)
            completeHandshake(right)
            _ = left.drainSegments()
            _ = right.drainSegments()

            // Push until the far side refuses and the splice is holding.
            var offset = UInt32(0)
            var forwarded = 0
            while splice.heldForTesting == 0 && offset < 400_000 {
                left.inject(
                    guestSegment(
                        sequence: guestISS + 1 + offset, ack: gatewayISS + 1, flags: [.ack, .psh]),
                    payload: tcpPayload(1000))
                offset += 1000
                left.advance(by: TCPEndpoint.delayedAckTimeout)
                _ = left.drainSegments()
                forwarded += right.drainSegments().map(\.payload.readableBytes).reduce(0, +)
            }
            #expect(splice.heldForTesting > 0, "the far side never filled: the rest proves nothing")

            // The source now goes quiet. This is the whole point: no further
            // `onData` will fire on `a`, so anything that only retries there
            // is about to stall.
            let held = splice.heldForTesting

            // The far side drains: it acknowledges everything it was sent, so
            // its send buffer empties and it can take writes again.
            right.inject(
                guestSegment(
                    sequence: guestISS + 1, ack: gatewayISS + 1 + UInt32(forwarded), flags: .ack))
            let delivered = right.drainSegments().map(\.payload.readableBytes).reduce(0, +)

            #expect(delivered >= held, "the held chunk never left: the splice stalled with the source quiet")
            #expect(splice.heldForTesting == 0, "the splice is still holding after the far side drained")
        }
    }
    left.drain()
    right.drain()
}
