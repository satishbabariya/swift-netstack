import NIOCore
import NIOEmbedded
import Testing

@testable import Netstack

// This file is the seam: nine components that have only ever been tested
// against each other's *tests* meet each other's *behaviour* here.
//
// Almost every property worth stating about an endpoint is also true of an
// endpoint that does nothing at all -- "nothing is delivered before the
// handshake completes", "a closed endpoint stops receiving", "the weak
// reference went nil", "deinit unregisters" are all satisfied perfectly by
// empty method bodies. Every one of them below is therefore paired with a
// positive control: that data IS delivered when it should be, that the port WAS
// occupied before it was freed, that the timer DID fire while the endpoint was
// alive. The paired assertion is the only reason these tests mean anything, and
// the whole file was run against a do-nothing stub before it was implemented.

// MARK: - Fixture

private let tcpGateway = IPv4Address("192.168.127.1")!
private let tcpGuest = IPv4Address("192.168.127.2")!
private let tcpOtherGuest = IPv4Address("192.168.127.3")!
private let tcpGatewayMAC = MACAddress("5a:94:ef:e4:0c:ee")!
private let tcpGuestMAC = MACAddress("0a:0b:0c:0d:0e:0f")!

/// The port the endpoint under test listens on, and the guest port that talks
/// to it. Fixed rather than ephemeral so an emitted frame can be identified by
/// its ports alone.
private let tcpLocalPort: UInt16 = 8080
private let tcpPeerPort: UInt16 = 50000

/// One `EmbeddedEventLoop`, one `ManualClock` and one started `Stack`, advanced
/// together.
///
/// The clock and the loop must move in lockstep for the same reason
/// `TCPTimerTests` says: `TCPTimers` computes deadlines from the clock while
/// the loop decides what has come due from its own time, and letting them drift
/// makes a deadline meaningless.
private final class TCPFixture {
    let loop = EmbeddedEventLoop()
    let clock = ManualClock(start: .uptimeNanoseconds(0))
    let link: RecordingEndpoint
    let stack: Stack

    init() {
        link = RecordingEndpoint(eventLoop: loop, linkAddress: tcpGatewayMAC)
        stack = Stack(
            link: link,
            configuration: Stack.Configuration(
                gatewayAddress: tcpGateway,
                subnet: IPv4Subnet(cidr: "192.168.127.0/24")!),
            clock: clock)
        stack.start()

        // `IPv4Protocol.send` throws `.noRoute` (and emits an ARP request
        // instead of the segment) until the next hop's link address is known.
        // An inbound TCP segment primes that on its own -- `handleInbound`
        // records the sender -- but an ACTIVE open sends before anything has
        // arrived, so the cache is primed here for every test rather than in
        // the two that would otherwise silently emit ARP where a SYN was
        // expected.
        primeARP()
    }

    private func primeARP() {
        for guest in [tcpGuest, tcpOtherGuest] {
            stack.arpCache.record(guest, tcpGuestMAC)
        }
    }

    func advance(by amount: TimeAmount) {
        clock.advance(by: amount)
        // `ARPCache`'s entries live sixty seconds, and this stands in for a
        // guest that is still on the link and still answers ARP.
        //
        // Not a convenience. Any test that crosses that TTL without it stops
        // measuring TCP: `IPv4Protocol.send` throws `.noRoute` and emits an ARP
        // REQUEST when the next hop is unknown, so a FIN retransmission on a
        // backed-off sixty-second timer produces an ARP frame and no segment,
        // and `drainSegments` -- which filters non-TCP frames -- reports
        // silence. That is correct production behaviour (the retransmission
        // simply waits for the next backoff), and it is exactly the kind of
        // second cause that makes an assertion about TCP pass or fail for
        // reasons of its own. Inbound frames re-prime the cache on their own
        // (`IPv4Protocol.handleInbound` records every sender), so only
        // timer-driven emissions on an otherwise idle connection are affected.
        primeARP()
        loop.advanceTime(by: amount)
    }

    /// Drive every armed timer to expiry.
    ///
    /// `EmbeddedEventLoop.deinit` traps on an outstanding scheduled task, which
    /// would kill the runner before it printed a summary; draining keeps a
    /// genuine assertion failure legible as one. Called after the endpoint
    /// under test has gone out of scope, so nothing is left to re-arm.
    func drain() {
        advance(by: .hours(1))
        _ = link.drainTransmitted()
    }

    /// Deliver one TCP segment as though the guest had sent it.
    func inject(
        _ header: TCPHeader, payload: ByteBuffer = ByteBuffer(), from source: IPv4Address = tcpGuest
    ) {
        let allocator = ByteBufferAllocator()
        let segment = header.serialize(payload: payload, source: source, destination: tcpGateway, allocator: allocator)
        var packet = PacketBuffer(allocator: allocator, payload: segment)
        IPv4Header(source: source, destination: tcpGateway, protocolNumber: .tcp, payloadLength: segment.readableBytes)
            .prepend(to: &packet)
        EthernetHeader(destination: tcpGatewayMAC, source: tcpGuestMAC, etherType: .ipv4).prepend(to: &packet)
        link.inject(packet.frame)
    }

    /// Every TCP segment emitted since the last drain, parsed. Frames that are
    /// not TCP (an ARP reply, an ICMP error) are dropped rather than failing:
    /// the tests below assert about TCP, and a stray ARP request would
    /// otherwise turn a clear failure into a confusing one.
    func drainSegments() -> [(header: TCPHeader, payload: ByteBuffer)] {
        var out: [(header: TCPHeader, payload: ByteBuffer)] = []
        for frame in link.drainTransmitted() {
            var packet = PacketBuffer(received: frame)
            guard let ethernet = EthernetHeader.parse(&packet), ethernet.etherType == .ipv4 else { continue }
            guard let ip = IPv4Header.parse(&packet), ip.protocolNumber == .tcp else { continue }
            guard let tcp = TCPHeader.parse(&packet, header: ip) else { continue }
            out.append((tcp, packet.payload))
        }
        return out
    }
}

/// A guest-side segment, built with production `TCPHeader` -- the same codec
/// `TCPHeaderTests` cross-checks against `VectorFrames`' independent one.
private func guestSegment(
    sequence: UInt32, ack: UInt32 = 0, flags: TCPFlags, window: UInt16 = 65535,
    options: [TCPOption] = [], peerPort: UInt16 = tcpPeerPort
) -> TCPHeader {
    TCPHeader(
        sourcePort: peerPort,
        destinationPort: tcpLocalPort,
        sequence: SequenceNumber(sequence),
        acknowledgement: SequenceNumber(ack),
        dataOffset: 5 + TCPOptionCodec.encode(options).count / 4,
        flags: flags,
        window: window,
        checksum: 0,
        urgentPointer: 0,
        options: options)
}

private func tcpPayload(_ count: Int, fill: UInt8 = 0x5a) -> ByteBuffer {
    var buffer = ByteBufferAllocator().buffer(capacity: count)
    buffer.writeBytes([UInt8](repeating: fill, count: count))
    return buffer
}

/// Reference-typed recorders, so an escaping callback and the assertion after
/// it look at the same storage -- and so a test never captures the endpoint
/// inside its own callback, which would be a retain cycle the lifetime tests
/// here could not tell from a real leak.
private final class DataRecorder {
    private(set) var bytes: [UInt8] = []
    private(set) var establishedCount = 0
    private(set) var closedCount = 0

    func attach(to endpoint: TCPEndpoint) {
        endpoint.onData = { [self] buffer in bytes += Array(buffer.readableBytesView) }
        endpoint.onEstablished = { [self] in establishedCount += 1 }
        endpoint.onClosed = { [self] in closedCount += 1 }
    }
}

private final class EmissionRecorder {
    var headers: [TCPHeader] = []
    var count: Int { headers.count }
}

/// A reference-typed flag for a future's completion callback. `whenSuccess`
/// takes a `@Sendable` closure, so mutating a captured `var` from it warns;
/// this is the same loop-confined access every other callback in this suite
/// makes, expressed in a way the compiler can see is not a data race on a
/// stack slot.
/// `@unchecked` for the same reason `Stack`'s own `ShutdownBox` and
/// `TCPTimers`' `TimerBody` are: the callback runs on the event loop, which is
/// this package's only concurrency discipline. `private`, so nothing else can
/// launder anything through it.
private final class CompletionFlag: @unchecked Sendable {
    var value = false
}

/// The guest's ISS. Kept away from the gateway's so a confusion between the two
/// directions cannot pass unnoticed.
private let guestISS: UInt32 = 7000
private let gatewayISS: UInt32 = 1000

/// Drive a passive open to ESTABLISHED and return the endpoint's SYN-ACK.
///
/// `mss` is what the GUEST advertises, which becomes the size of the segments
/// the endpoint cuts -- set it to 1 and a four-byte write becomes four
/// segments, which is what the duplicate-ACK tests need.
@discardableResult
private func completeHandshake(
    _ fixture: TCPFixture, mss: UInt16 = 1460, peerPort: UInt16 = tcpPeerPort, from source: IPv4Address = tcpGuest
) -> [(header: TCPHeader, payload: ByteBuffer)] {
    fixture.inject(
        guestSegment(sequence: guestISS, flags: [.syn], options: [.maximumSegmentSize(mss)], peerPort: peerPort),
        from: source)
    let synAck = fixture.drainSegments()
    fixture.inject(
        guestSegment(sequence: guestISS + 1, ack: gatewayISS + 1, flags: [.ack], peerPort: peerPort), from: source)
    return synAck
}

private func listeningEndpoint(_ fixture: TCPFixture, backlog: Int = 8, iss: UInt32 = gatewayISS) throws -> TCPEndpoint {
    let endpoint = TCPEndpoint(stack: fixture.stack, initialSequenceNumbers: FixedInitialSequenceNumbers(iss))
    try endpoint.bind(address: tcpGateway, port: tcpLocalPort)
    try endpoint.listen(backlog: backlog)
    return endpoint
}

// MARK: - The handshake, and the options we do and do not advertise

@Test func aSynToAListeningEndpointIsAnsweredWithASynAckAdvertisingOnlyAnMss() throws {
    let fixture = TCPFixture()
    do {
        let endpoint = try listeningEndpoint(fixture)
        try withExtendedLifetime(endpoint) {
            fixture.inject(guestSegment(sequence: guestISS, flags: [.syn], options: [.maximumSegmentSize(1460)]))

            let emitted = fixture.drainSegments()
            #expect(emitted.count == 1)
            let synAck = try #require(emitted.first).header
            #expect(synAck.flags.contains(.syn))
            #expect(synAck.flags.contains(.ack))
            #expect(synAck.sequence == SequenceNumber(gatewayISS))
            #expect(synAck.acknowledgement == SequenceNumber(guestISS + 1))
            #expect(synAck.sourcePort == tcpLocalPort)
            #expect(synAck.destinationPort == tcpPeerPort)

            // The whole of the option list, not a search for what must be
            // absent: `.maximumSegmentSize` present is the positive control
            // that makes "no window scale, no SACK-permitted" mean something
            // rather than being true of an empty list.
            //
            // `wscale` is omitted because nothing in this stack applies a
            // scale: advertising 7 would promise 8 MB against a reassembler
            // that caps at 256 KiB, and RFC 7323 §2.2 turns scaling off in both
            // directions when either side omits the option. `sackOK` is omitted
            // because RFC 2018 expects a receiver that sent it to send SACK
            // blocks, and this stack discards them.
            #expect(synAck.options == [.maximumSegmentSize(1460)])
        }
    }
    fixture.drain()
}

@Test func aGuestSynOfferingAWindowScaleGetsOneBackAndAnUnscaledHandshakeWindow() throws {
    // The ordering guard for window scaling, at the one place it is observable:
    // on the wire.
    //
    // `TCB.negotiateWindowScale(fromSynOptions:)` now runs on this SYN and
    // records the negotiation, so "nothing in this stack records a scale" has
    // stopped being the reason the SYN-ACK carries no `wscale`. The reason is
    // `TCPEndpoint.windowScaleToOffer`, which is nil — and RFC 7323 §2.2 scales
    // nothing unless both sides sent the option, so both of this connection's
    // shifts are zero however generous the guest's offer.
    //
    // Answering the offer before the shifts are applied is the defect this
    // ordering exists to prevent: `wscale 7` alongside a 65535 window promises
    // the guest 8 MB — at the maximum shift of 14, 1 GB — against a reassembler
    // that caps at 256 KiB. The guest fills the pipe it was promised, most of it
    // is dropped, and it presents as packet loss with no error raised anywhere.
    //
    // So this asserts both halves: no option, and a window that still means
    // exactly the number of bytes it says.
    let fixture = TCPFixture()
    do {
        let endpoint = try listeningEndpoint(fixture)
        try withExtendedLifetime(endpoint) {
            fixture.inject(
                guestSegment(
                    sequence: guestISS, flags: [.syn],
                    options: [.maximumSegmentSize(1460), .windowScale(7)]))

            let emitted = fixture.drainSegments()
            #expect(emitted.count == 1)
            let synAck = try #require(emitted.first).header
            #expect(synAck.flags.contains(.syn))
            #expect(synAck.flags.contains(.ack))
            #expect(synAck.options == [.maximumSegmentSize(1460), .windowScale(TCPEndpoint.derivedWindowScale)])
            // Still 65535, and still meaning 65535: RFC 7323 §2.2 forbids
            // scaling the window in a SYN or SYN-ACK, so the shift this very
            // segment negotiates does not apply to the segment negotiating it.
            #expect(synAck.window == UInt16(TCPEndpoint.receiveWindowBytes))
        }
    }
    fixture.drain()
}

@Test func theWindowWeAdvertiseGrowsPastTheHandshakeCeilingOnceScalingIsInEffect() throws {
    // The point of the whole four-step sequence. Until a scale is negotiated
    // *and* applied, `RCV.WND` cannot exceed 65535, because that is all the
    // header field holds. With a scale in effect the field carries
    // `RCV.WND >> scale`, so the real window this connection offers is larger
    // than any unscaled connection could express -- which is the only reason to
    // have built any of it.
    //
    // Asserted on the REAL window rather than the wire field. The wire field
    // legitimately *falls* as the scale rises, so a test watching it would read
    // a growing window as a shrinking one.
    let fixture = TCPFixture()
    do {
        let endpoint = try listeningEndpoint(fixture)
        try withExtendedLifetime(endpoint) {
            fixture.inject(
                guestSegment(
                    sequence: guestISS, flags: [.syn],
                    options: [.maximumSegmentSize(1460), .windowScale(7)]))
            let synAck = try #require(fixture.drainSegments().first).header

            // The handshake itself is unscaled, so it is stuck at the ceiling.
            #expect(synAck.window == UInt16(TCPEndpoint.receiveWindowBytes))

            fixture.inject(guestSegment(sequence: guestISS + 1, ack: gatewayISS + 1, flags: [.ack]))
            fixture.inject(
                guestSegment(sequence: guestISS + 1, ack: gatewayISS + 1, flags: [.ack, .psh]),
                payload: ByteBuffer(bytes: [0xaa]))
            let ack = try #require(fixture.drainSegments().last).header

            let scale = TCPEndpoint.derivedWindowScale
            let realWindow = Int(ack.window) << Int(scale)
            #expect(scale > 0, "a scale of zero would make this test vacuous")
            #expect(realWindow > TCPEndpoint.receiveWindowBytes, "real window \(realWindow) did not clear the unscaled ceiling")

            // The honesty half: we may not promise more than the queue holds.
            //
            // Against `TCPReassembler.defaultMaximumBytes`, NOT against
            // `TCPEndpoint.maximumReceiveWindowBytes`. Falsifying this task by
            // raising the endpoint's cap past the queue's capacity left the
            // second form green, because the bound moved with the thing it was
            // bounding -- the self-referential assertion this project has found
            // three times now. The queue's own constant is the fixed point.
            //
            // Being exact about what this does and does not catch: raising
            // `maximumReceiveWindowBytes` past the queue's capacity still does
            // not fail here, because `Receiver.advertisedWindow` derives its
            // ceiling from `reassembler.availableBytes` and the queue forecloses
            // the overrun on its own. The honesty is structural, not enforced by
            // this line. What this line pins is that nothing later introduces a
            // path around the queue -- and the vector
            // `aPassiveOpenCompletesTheThreeWayHandshakeOnTheWire` is what
            // actually fails on that mutation today.
            #expect(realWindow <= TCPReassembler.defaultMaximumBytes)
        }
    }
    fixture.drain()
}

@Test func theScaleWeOfferIsTheSmallestThatExpressesOurCapacity() {
    // Derived rather than written down, because a literal and the cap drift
    // apart silently and the failure is a window we cannot honour. The boundary
    // is closer than it looks: at a 256 KiB cap, `65535 << 2` is 262,140 --
    // four bytes short -- so an off-by-one here is not academic.
    let scale = Int(TCPEndpoint.derivedWindowScale)
    let cap = TCPEndpoint.maximumReceiveWindowBytes
    #expect(Int(UInt16.max) << scale >= cap, "scale \(scale) cannot express the \(cap)-byte cap")
    // And that the derived value is the one actually offered. Without this,
    // replacing the offer with a literal leaves every assertion above green:
    // falsifying `windowScaleToOffer` alone did not fail this test until here.
    #expect(TCPEndpoint.windowScaleToOffer == TCPEndpoint.derivedWindowScale)
    if scale > 0 {
        #expect(Int(UInt16.max) << (scale - 1) < cap, "scale \(scale) is larger than it needs to be")
    }
}

@Test func aRetransmittedSynReproducesTheSameSynAck() throws {
    // Task 15's vector sends the same SYN twice and requires the same SYN-ACK
    // both times. RFC 6528's function is deterministic in the four-tuple, but
    // that alone is not enough: its `M` term is a 4-microsecond timer, so a
    // second SYN answered from a FRESH block would draw a different sequence
    // number, and a guest that has already recorded the first either fails to
    // connect or resets. What actually holds this is reusing the TCB the first
    // SYN created, which is why the endpoint under test here is given the real
    // generator rather than a constant one.
    let fixture = TCPFixture()
    do {
        let endpoint = TCPEndpoint(stack: fixture.stack)
        try endpoint.bind(address: tcpGateway, port: tcpLocalPort)
        try endpoint.listen(backlog: 8)
        try withExtendedLifetime(endpoint) {
            fixture.inject(guestSegment(sequence: guestISS, flags: [.syn]))
            let first = try #require(fixture.drainSegments().first).header
            // Assert what it IS, not merely that two frames matched. Against a
            // do-nothing endpoint the SYN falls through to `Stack`'s
            // no-endpoint handler and draws a reset both times -- two identical
            // frames, and this test passed on exactly that before the flags
            // were checked.
            #expect(first.flags.contains(.syn))
            #expect(first.flags.contains(.ack))

            // Two hundred milliseconds of the 4-microsecond timer: 50,000
            // ticks, so a regenerated ISS could not coincide with the first.
            fixture.advance(by: .milliseconds(200))

            fixture.inject(guestSegment(sequence: guestISS, flags: [.syn]))
            let second = try #require(fixture.drainSegments().first).header

            #expect(second.sequence == first.sequence)
            #expect(second.acknowledgement == first.acknowledgement)
            #expect(second.flags == first.flags)
            #expect(second.options == first.options)
        }
    }
    fixture.drain()
}

@Test func nothingIsDeliveredToTheApplicationBeforeTheHandshakeCompletes() throws {
    let fixture = TCPFixture()
    do {
        let endpoint = try listeningEndpoint(fixture)
        let recorder = DataRecorder()
        recorder.attach(to: endpoint)
        withExtendedLifetime(endpoint) {
            fixture.inject(guestSegment(sequence: guestISS, flags: [.syn]))
            _ = fixture.drainSegments()

            // In SYN-RECEIVED, carrying an old duplicate acknowledgement of our
            // own SYN|ACK, which is the one shape that reaches step 5 with the
            // state still SYN-RECEIVED. There is no established connection to
            // deliver to, so the segment is dropped and the peer retransmits.
            fixture.inject(
                guestSegment(sequence: guestISS + 1, ack: gatewayISS - 1, flags: [.ack]), payload: tcpPayload(4, fill: 0x11))
            #expect(recorder.bytes.isEmpty)
            #expect(recorder.establishedCount == 0)

            // Positive control: the identical write, once the handshake is
            // complete, IS delivered. Without this the assertion above is
            // satisfied by an endpoint that delivers nothing, ever.
            fixture.inject(guestSegment(sequence: guestISS + 1, ack: gatewayISS + 1, flags: [.ack]))
            #expect(recorder.establishedCount == 1)
            fixture.inject(
                guestSegment(sequence: guestISS + 1, ack: gatewayISS + 1, flags: [.ack]), payload: tcpPayload(4, fill: 0x11))
            #expect(recorder.bytes == [0x11, 0x11, 0x11, 0x11])
        }
    }
    fixture.drain()
}

@Test func anOutOfOrderSegmentIsHeldUntilTheGapFillsAndThenDeliveredInOrder() throws {
    // The reassembler, the receiver and the state machine's trim, driven
    // through the endpoint for the first time.
    let fixture = TCPFixture()
    do {
        let endpoint = try listeningEndpoint(fixture)
        let recorder = DataRecorder()
        recorder.attach(to: endpoint)
        withExtendedLifetime(endpoint) {
            completeHandshake(fixture)
            _ = fixture.drainSegments()

            // Bytes 5..<9 arrive before bytes 1..<5.
            fixture.inject(
                guestSegment(sequence: guestISS + 5, ack: gatewayISS + 1, flags: [.ack]), payload: tcpPayload(4, fill: 0xbb))
            #expect(recorder.bytes.isEmpty, "a segment ahead of RCV.NXT must not be delivered early")

            fixture.inject(
                guestSegment(sequence: guestISS + 1, ack: gatewayISS + 1, flags: [.ack]), payload: tcpPayload(4, fill: 0xaa))
            #expect(recorder.bytes == [0xaa, 0xaa, 0xaa, 0xaa, 0xbb, 0xbb, 0xbb, 0xbb])
        }
    }
    fixture.drain()
}

@Test func aGuestsFinTellsTheApplicationTheStreamIsOverExactlyOnce() throws {
    let fixture = TCPFixture()
    do {
        let endpoint = try listeningEndpoint(fixture)
        let recorder = DataRecorder()
        recorder.attach(to: endpoint)
        withExtendedLifetime(endpoint) {
            completeHandshake(fixture)
            _ = fixture.drainSegments()
            // Positive control: the connection is alive and NOT reported closed
            // before the FIN arrives.
            #expect(recorder.establishedCount == 1)
            #expect(recorder.closedCount == 0)

            fixture.inject(guestSegment(sequence: guestISS + 1, ack: gatewayISS + 1, flags: [.fin, .ack]))
            #expect(recorder.closedCount == 1)

            // A retransmitted FIN is acknowledged again but must not report a
            // second end of stream.
            fixture.inject(guestSegment(sequence: guestISS + 1, ack: gatewayISS + 1, flags: [.fin, .ack]))
            #expect(recorder.closedCount == 1)

            let acks = fixture.drainSegments()
            #expect(acks.allSatisfy { $0.header.flags.contains(.ack) })
            #expect(acks.count >= 1, "a FIN must be acknowledged")
        }
    }
    fixture.drain()
}

@Test func aResetAtRcvNxtTearsTheConnectionDownAndFreesIt() throws {
    let fixture = TCPFixture()
    do {
        let endpoint = try listeningEndpoint(fixture)
        let recorder = DataRecorder()
        recorder.attach(to: endpoint)
        withExtendedLifetime(endpoint) {
            completeHandshake(fixture)
            _ = fixture.drainSegments()
            // Positive control: there IS a connection to tear down.
            #expect(endpoint.connectionCountForTesting == 1)
            #expect(recorder.closedCount == 0)

            fixture.inject(guestSegment(sequence: guestISS + 1, ack: gatewayISS + 1, flags: [.rst]))
            #expect(endpoint.connectionCountForTesting == 0)
            #expect(recorder.closedCount == 1)
            #expect(fixture.drainSegments().isEmpty, "a reset is not answered")
        }
    }
    fixture.drain()
}

@Test func aBlindResetSomewhereInTheWindowIsChallengedRatherThanHonoured() throws {
    // RFC 5961 §3.2, driven end to end: only a reset naming RCV.NXT exactly
    // tears the connection down. This is the state machine's rule, and this
    // test exists because the endpoint is what turns `.sendAck` into a frame --
    // a wiring that dropped the challenge would leave the security property
    // stated in a file nothing calls.
    let fixture = TCPFixture()
    do {
        let endpoint = try listeningEndpoint(fixture)
        withExtendedLifetime(endpoint) {
            completeHandshake(fixture)
            _ = fixture.drainSegments()

            fixture.inject(guestSegment(sequence: guestISS + 100, ack: gatewayISS + 1, flags: [.rst]))
            #expect(endpoint.connectionCountForTesting == 1, "an off-position reset must not kill the connection")
            let challenge = fixture.drainSegments()
            #expect(challenge.count == 1)
            #expect(challenge.first?.header.flags.contains(.ack) == true)
            #expect(challenge.first?.header.acknowledgement == SequenceNumber(guestISS + 1))

            // Positive control: the same guest, naming RCV.NXT, does kill it.
            fixture.inject(guestSegment(sequence: guestISS + 1, ack: gatewayISS + 1, flags: [.rst]))
            #expect(endpoint.connectionCountForTesting == 0)
        }
    }
    fixture.drain()
}

// MARK: - The send path

@Test func dataWrittenByTheApplicationIsSegmentedAndSent() throws {
    let fixture = TCPFixture()
    do {
        let endpoint = try listeningEndpoint(fixture)
        try withExtendedLifetime(endpoint) {
            completeHandshake(fixture)
            _ = fixture.drainSegments()

            try endpoint.send(tcpPayload(3, fill: 0x77))
            let emitted = fixture.drainSegments()
            #expect(emitted.count == 1)
            let segment = try #require(emitted.first)
            #expect(segment.header.sequence == SequenceNumber(gatewayISS + 1))
            #expect(segment.header.acknowledgement == SequenceNumber(guestISS + 1))
            #expect(segment.header.flags.contains(.ack))
            #expect(Array(segment.payload.readableBytesView) == [0x77, 0x77, 0x77])
        }
    }
    fixture.drain()
}

@Test func dataWrittenAfterAnAcknowledgementIsStillTransmitted() throws {
    // The SND.UNA seam, stated as behaviour rather than as a field.
    //
    // `TCPStateMachine` decides an acknowledgement is acceptable and hands it
    // to `Sender`, which is the single advancer of SND.UNA over data. If the
    // machine ALSO assigned SND.UNA -- which it did until this task -- the
    // sender would read `advanced == 0`, classify a genuine acknowledgement as
    // a duplicate, retire nothing, and keep the acknowledged segment
    // outstanding forever. `segmentsToTransmit` then fails closed for good,
    // because SND.NXT - SND.UNA no longer matches its own accounting, and every
    // subsequent write silently emits nothing at all.
    //
    // That is why this asserts the SECOND write, not the first: a first write
    // goes out either way.
    let fixture = TCPFixture()
    do {
        let endpoint = try listeningEndpoint(fixture)
        try withExtendedLifetime(endpoint) {
            completeHandshake(fixture)
            _ = fixture.drainSegments()

            try endpoint.send(tcpPayload(3, fill: 0x01))
            #expect(fixture.drainSegments().count == 1, "positive control: the first write goes out")

            fixture.inject(guestSegment(sequence: guestISS + 1, ack: gatewayISS + 4, flags: [.ack]))

            try endpoint.send(tcpPayload(3, fill: 0x02))
            let second = fixture.drainSegments()
            #expect(second.count == 1)
            #expect(second.first?.header.sequence == SequenceNumber(gatewayISS + 4))
            #expect(second.first.map { Array($0.payload.readableBytesView) } == [0x02, 0x02, 0x02])
        }
    }
    fixture.drain()
}

@Test func threeDuplicateAcknowledgementsFastRetransmitTheOldestSegment() throws {
    // RFC 5681 §3.2. `Sender.lossDetected` and `fastRetransmitPending` are
    // wired in Task 12; this is the test that the endpoint actually DRIVES
    // them, because a public function with no caller is how the last three
    // seams in this plan were found.
    let fixture = TCPFixture()
    do {
        let endpoint = try listeningEndpoint(fixture)
        try withExtendedLifetime(endpoint) {
            // A one-byte MSS from the guest, so four bytes become four
            // segments and there is an "oldest" one to retransmit.
            completeHandshake(fixture, mss: 1)
            _ = fixture.drainSegments()

            try endpoint.send(tcpPayload(4, fill: 0x33))
            #expect(fixture.drainSegments().count == 4)

            // A duplicate acknowledgement by RFC 5681's definition: it
            // acknowledges no new data, carries none itself, and repeats the
            // window.
            let duplicate = guestSegment(sequence: guestISS + 1, ack: gatewayISS + 1, flags: [.ack])
            fixture.inject(duplicate)
            fixture.inject(duplicate)
            #expect(fixture.drainSegments().isEmpty, "two duplicates are ordinary reordering, not a loss signal")

            fixture.inject(duplicate)
            let retransmitted = fixture.drainSegments()
            #expect(retransmitted.count == 1)
            #expect(retransmitted.first?.header.sequence == SequenceNumber(gatewayISS + 1))
        }
    }
    fixture.drain()
}

@Test func aWriteThatWouldOverrunTheSendBufferIsRefusedRatherThanTruncated() throws {
    let fixture = TCPFixture()
    do {
        let endpoint = try listeningEndpoint(fixture)
        try withExtendedLifetime(endpoint) {
            // A zero window from the guest, so nothing drains and the buffer
            // is the only thing that can bind.
            fixture.inject(guestSegment(sequence: guestISS, flags: [.syn], options: [.maximumSegmentSize(1460)]))
            _ = fixture.drainSegments()
            fixture.inject(guestSegment(sequence: guestISS + 1, ack: gatewayISS + 1, flags: [.ack], window: 0))

            var accepted = 0
            var refused = false
            do {
                for _ in 0..<2048 {
                    try endpoint.send(tcpPayload(1024))
                    accepted += 1
                }
            } catch StackError.wouldBlock {
                refused = true
            }
            // Positive control: writes ARE accepted, so the refusal below is a
            // bound rather than an endpoint that refuses everything.
            #expect(accepted > 0)
            #expect(refused, "the send buffer must be bounded, and refuse rather than truncate")
            #expect(accepted < 2048, "2 MB of writes against a peer that never acknowledges must not all be retained")
        }
    }
    fixture.drain()
}

// MARK: - Egress goes through one point

@Test func everyFrameLeavesThroughOnePointIncludingOnesEmittedFromATimerBody() throws {
    // A carried constraint from the differential harness. Its Go side once
    // reported `emitted: []` on 100% of runs because gVisor's forwarder
    // dispatched on an untracked goroutine and the collector only saw frames
    // produced inline; ARP-only validation could never have caught it, because
    // ARP is synchronous and TCP is not.
    //
    // This endpoint emits from two places -- inline while handling a delivered
    // segment, and later from a retransmit timer body -- and both must be
    // visible to one observer. `onEmit` is that point.
    let fixture = TCPFixture()
    do {
        let endpoint = try listeningEndpoint(fixture)
        try withExtendedLifetime(endpoint) {
            completeHandshake(fixture)
            _ = fixture.drainSegments()

            let emissions = EmissionRecorder()
            endpoint.onEmit = { header, _ in emissions.headers.append(header) }

            try endpoint.send(tcpPayload(3, fill: 0x44))
            #expect(emissions.count == 1, "positive control: an inline emission is observed")
            let inline = fixture.drainSegments()
            #expect(inline.count == 1)

            // Past the initial RTO (RFC 6298 §2.1's one second), so the
            // retransmission timer body runs.
            fixture.advance(by: .seconds(2))

            #expect(emissions.count == 2, "a frame emitted from a timer body must reach the SAME observation point")
            let fromTimer = fixture.drainSegments()
            #expect(fromTimer.count == 1)
            #expect(fromTimer.first?.header.sequence == inline.first?.header.sequence)
            #expect(emissions.headers.last?.sequence == fromTimer.first?.header.sequence)
        }
    }
    fixture.drain()
}

// MARK: - The backlog

@Test func theBacklogRefusesNewConnectionsAndNeverEvictsAnEstablishedOne() throws {
    // A backlog is the classic SYN-flood surface. The policy here is REFUSE,
    // never evict: an evicting backlog hands a guest a way to destroy other
    // connections' state for the price of one segment each, which is the same
    // ruling `TCPReassembler` makes for its own caps -- when a cap binds, the
    // newcomer loses and nothing already held is disturbed.
    let fixture = TCPFixture()
    do {
        let endpoint = try listeningEndpoint(fixture, backlog: 2)
        withExtendedLifetime(endpoint) {
            for port: UInt16 in [50001, 50002] {
                fixture.inject(guestSegment(sequence: guestISS, flags: [.syn], peerPort: port))
            }
            #expect(fixture.drainSegments().count == 2, "positive control: the backlog admits up to its bound")
            #expect(endpoint.connectionCountForTesting == 2)

            fixture.inject(guestSegment(sequence: guestISS, flags: [.syn], peerPort: 50003))
            #expect(fixture.drainSegments().isEmpty, "a SYN past the backlog is refused, not answered")
            #expect(endpoint.connectionCountForTesting == 2, "and nothing already admitted is evicted")

            // The two that were admitted are still live: the flood cost them
            // nothing.
            fixture.inject(guestSegment(sequence: guestISS + 1, ack: gatewayISS + 1, flags: [.ack], peerPort: 50001))
            #expect(endpoint.connectionCountForTesting == 2)
        }
    }
    fixture.drain()
}

// MARK: - Ports, registration and lifetime

@Test func aBoundTcpPortIsOccupiedUntilTheEndpointIsClosed() throws {
    let fixture = TCPFixture()
    do {
        let first = try listeningEndpoint(fixture)
        try withExtendedLifetime(first) {
            // Positive control: the port really is taken.
            let rival = TCPEndpoint(stack: fixture.stack)
            #expect(throws: StackError.portInUse) {
                try rival.bind(address: tcpGateway, port: tcpLocalPort)
            }
            withExtendedLifetime(rival) {}

            first.close()

            // Immediately rebindable: `close()` frees the four-tuple rather
            // than leaving it held until deallocation.
            let successor = TCPEndpoint(stack: fixture.stack)
            try successor.bind(address: tcpGateway, port: tcpLocalPort)
            withExtendedLifetime(successor) {}
        }
    }
    fixture.drain()
}

@Test func aClosedTcpEndpointStopsReceiving() throws {
    let fixture = TCPFixture()
    do {
        let endpoint = try listeningEndpoint(fixture)
        let recorder = DataRecorder()
        recorder.attach(to: endpoint)
        withExtendedLifetime(endpoint) {
            completeHandshake(fixture)
            _ = fixture.drainSegments()
            fixture.inject(
                guestSegment(sequence: guestISS + 1, ack: gatewayISS + 1, flags: [.ack]), payload: tcpPayload(2, fill: 0x09))
            // Positive control: it WAS receiving.
            #expect(recorder.bytes == [0x09, 0x09])

            endpoint.close()
            _ = fixture.drainSegments()

            fixture.inject(
                guestSegment(sequence: guestISS + 3, ack: gatewayISS + 1, flags: [.ack]), payload: tcpPayload(2, fill: 0x0a))
            #expect(recorder.bytes == [0x09, 0x09], "a closed endpoint delivers nothing more")
        }
    }
    fixture.drain()
}

@Test func aDroppedTcpEndpointReclaimsItsSlotInTheDemuxer() throws {
    // `TransportDemuxer` holds delegates weakly, so a dropped endpoint stops
    // receiving, and a later `bind` on the same port succeeds, WITHOUT any help
    // from `deinit`: `register` overwrites a slot whose weak delegate has gone.
    //
    // That was measured, not assumed. The first version of this test asserted
    // exactly the rebinding, and deleting `deinit`'s `unregister` left the
    // whole suite green -- a test named for a property that something else
    // already foreclosed. What `deinit` actually buys is the table SLOT: one
    // dictionary entry per dropped endpoint, held for the life of the stack on
    // any port that is never touched again. `registrationCountForTesting` is
    // the only thing that can see it.
    let fixture = TCPFixture()
    do {
        weak var weakEndpoint: TCPEndpoint?
        do {
            let endpoint = try listeningEndpoint(fixture)
            weakEndpoint = endpoint
            // Positive controls: the endpoint is alive, its slot is occupied,
            // and the port really is taken while it lives.
            #expect(weakEndpoint != nil)
            #expect(fixture.stack.transportDemuxer.registrationCountForTesting == 1)

            let rival = TCPEndpoint(stack: fixture.stack)
            #expect(throws: StackError.portInUse) {
                try rival.bind(address: tcpGateway, port: tcpLocalPort)
            }
            withExtendedLifetime(rival) {}
            withExtendedLifetime(endpoint) {}
        }
        #expect(weakEndpoint == nil)
        #expect(
            fixture.stack.transportDemuxer.registrationCountForTesting == 0,
            "a dropped endpoint must not leave its table slot behind")

        let successor = TCPEndpoint(stack: fixture.stack)
        try successor.bind(address: tcpGateway, port: tcpLocalPort)
        withExtendedLifetime(successor) {}
    }
    fixture.drain()
}

@Test func aTcpEndpointWithAnArmedTimerIsReleasedWhenDropped() throws {
    // `TCPTimers`' bodies run UNCONDITIONALLY when their owner is gone -- Task
    // 13 chose that deliberately, so a broken `deinit` is observable rather
    // than silent. The consequence lands here: this endpoint's timer bodies
    // must capture it weakly, or the loop's own queue keeps the whole
    // connection graph alive until the deadline and then drives a connection
    // that no longer exists.
    let fixture = TCPFixture()
    weak var weakEndpoint: TCPEndpoint?
    do {
        let endpoint = try listeningEndpoint(fixture)
        try withExtendedLifetime(endpoint) {
            completeHandshake(fixture)
            _ = fixture.drainSegments()
            try endpoint.send(tcpPayload(3, fill: 0x55))
            #expect(fixture.drainSegments().count == 1)

            // Positive control: the retransmission timer really is armed and
            // really does fire while the endpoint is alive.
            fixture.advance(by: .seconds(2))
            #expect(fixture.drainSegments().count == 1, "the timer fires while the endpoint lives")

            weakEndpoint = endpoint
            #expect(weakEndpoint != nil)
        }
    }
    #expect(weakEndpoint == nil, "the demuxer holds delegates weakly; the timer bodies must too")

    // Whatever is left on the loop's queue must not drive a dead connection.
    fixture.advance(by: .seconds(600))
    #expect(fixture.drainSegments().isEmpty)
    fixture.drain()
}

@Test func aStartedStackWithTcpIsReleasedWhenDropped() {
    // The companion of `aStartedStackIsReleasedWhenDropped`, with a TCP
    // endpoint registered. Registering TCP adds a third handler closure to a
    // function that has already produced two retain cycles.
    //
    // This is the SAFE path -- `shutdown()` empties the handler tables, and an
    // emptied table breaks exactly the same cycles the weak captures do, so
    // neither fix is individually falsifiable through this test. The one that
    // can see them is the drop-without-shutdown companion below, which is also
    // the path production actually takes.
    weak var weakNIC: NIC?
    weak var weakIPv4: IPv4Protocol?
    weak var weakLink: RecordingEndpoint?
    weak var weakEndpoint: TCPEndpoint?
    do {
        let fixture = TCPFixture()
        let endpoint = TCPEndpoint(stack: fixture.stack)
        try? endpoint.bind(address: tcpGateway, port: tcpLocalPort)
        try? endpoint.listen(backlog: 4)
        weakNIC = fixture.stack.nic
        weakIPv4 = fixture.stack.ipv4
        weakLink = fixture.link
        weakEndpoint = endpoint
        #expect(weakNIC != nil)
        #expect(weakIPv4 != nil)
        #expect(weakLink != nil)
        #expect(weakEndpoint != nil)

        let completed = CompletionFlag()
        fixture.stack.shutdown().whenSuccess { completed.value = true }
        fixture.loop.run()
        #expect(completed.value)
        withExtendedLifetime(endpoint) {}
        withExtendedLifetime(fixture) {}
    }
    #expect(weakNIC == nil)
    #expect(weakIPv4 == nil)
    #expect(weakLink == nil)
    #expect(weakEndpoint == nil)
}

@Test func aStartedStackWithTcpIsReleasedWhenDroppedWithoutShutdown() {
    // The production path, and the only one that can see the `[weak ...]`
    // captures in `start()` on their own.
    //
    // A falsification audit of this repository found the shutdown-first shape
    // above guarding NOTHING: four separate deletions -- `[weak ipv4]` in the
    // NIC handler, `[weak ipv4]` in `IPv4Protocol`'s handler, `[weak
    // arpResponder]`, and both `removeAllHandlers()` calls -- each left the
    // whole suite green, because an emptied handler table breaks exactly the
    // cycles the weak captures do, and each fix hid the other's absence. The
    // masking also ran the wrong way for the real failure: a sandbox is torn
    // down by DROPPING its stack, which is the path that test does not take.
    //
    // Dropping a started stack without shutting it down leaves the handler
    // tables fully populated, so the weak captures -- including the TCP one
    // added by this task -- are the only thing left breaking the cycles.
    weak var weakNIC: NIC?
    weak var weakRoutes: RouteTable?
    weak var weakIPv4: IPv4Protocol?
    weak var weakARPResponder: ARPResponder?
    weak var weakLink: RecordingEndpoint?
    weak var weakEndpoint: TCPEndpoint?
    do {
        let fixture = TCPFixture()
        let endpoint = TCPEndpoint(stack: fixture.stack, initialSequenceNumbers: FixedInitialSequenceNumbers(gatewayISS))
        try? endpoint.bind(address: tcpGateway, port: tcpLocalPort)
        try? endpoint.listen(backlog: 4)
        // A live connection, so the graph under test is the real one: a TCB, a
        // reassembly queue, a retransmit queue and a pair of timers, all
        // reachable from the endpoint and from the loop's own queue.
        completeHandshake(fixture)
        _ = fixture.drainSegments()
        weakNIC = fixture.stack.nic
        weakRoutes = fixture.stack.routes
        weakIPv4 = fixture.stack.ipv4
        weakARPResponder = fixture.stack.arpResponder
        weakLink = fixture.link
        weakEndpoint = endpoint
        // Positive control: everything is genuinely alive while the stack is,
        // so the assertions below cannot pass merely because nothing was ever
        // constructed.
        #expect(weakNIC != nil)
        #expect(weakRoutes != nil)
        #expect(weakIPv4 != nil)
        #expect(weakARPResponder != nil)
        #expect(weakLink != nil)
        #expect(weakEndpoint != nil)
        withExtendedLifetime(endpoint) {}
        withExtendedLifetime(fixture) {}
    }
    #expect(weakNIC == nil)
    #expect(weakRoutes == nil)
    #expect(weakIPv4 == nil)
    #expect(weakARPResponder == nil)
    #expect(weakLink == nil)
    #expect(weakEndpoint == nil)
}

// MARK: - A port nobody is listening on

@Test func aSegmentForAPortWithNoEndpointIsAnsweredWithAReset() {
    // The TCP counterpart of the ICMP port-unreachable the UDP handler sends:
    // a guest's connect() must fail fast rather than retry into a void.
    let fixture = TCPFixture()
    fixture.inject(guestSegment(sequence: guestISS, flags: [.syn]))

    let emitted = fixture.drainSegments()
    #expect(emitted.count == 1)
    #expect(emitted.first?.header.flags.contains(.rst) == true)
    // RFC 9293 §3.10.7.1: no ACK to reuse, so the reset is
    // <SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK> -- a SYN occupies one sequence
    // number, so the acknowledgement is one past it.
    #expect(emitted.first?.header.flags.contains(.ack) == true)
    #expect(emitted.first?.header.sequence == SequenceNumber(0))
    #expect(emitted.first?.header.acknowledgement == SequenceNumber(guestISS + 1))
    fixture.drain()
}

@Test func aResetIsNeverAnsweredWithAnotherReset() {
    // Otherwise two stacks that both refuse a connection trade resets forever.
    let fixture = TCPFixture()
    fixture.inject(guestSegment(sequence: guestISS, ack: 1, flags: [.rst]))
    #expect(fixture.drainSegments().isEmpty)
    fixture.drain()
}

// MARK: - The initial send sequence number

@Test func theInitialSendSequenceIsAKeyedFunctionOfTheFourTupleAndNotACounter() {
    // RFC 6528 §3. A predictable ISS lets an OFF-PATH attacker inject data into
    // a connection it cannot see: it needs one sequence number inside the
    // receive window, and a counter hands it one from any single connection it
    // can observe. A guest is on-path for its own connections, but not for
    // another sandbox's, nor for one between the gateway and an external host.
    let clock = ManualClock(start: .uptimeNanoseconds(0))
    let generator = RFC6528SequenceNumbers(clock: clock, secret: [UInt8](repeating: 0x5a, count: 16))

    let base = generator.initialSendSequence(
        localAddress: tcpGateway, localPort: 8080, remoteAddress: tcpGuest, remotePort: 50000)

    // Deterministic in the four-tuple at one instant: the same connection asked
    // twice gets the same answer.
    #expect(
        generator.initialSendSequence(
            localAddress: tcpGateway, localPort: 8080, remoteAddress: tcpGuest, remotePort: 50000) == base)

    // Every neighbouring four-tuple lands somewhere unrelated, rather than one
    // step away as a counter would.
    let neighbours = [
        generator.initialSendSequence(
            localAddress: tcpGateway, localPort: 8080, remoteAddress: tcpGuest, remotePort: 50001),
        generator.initialSendSequence(
            localAddress: tcpGateway, localPort: 8081, remoteAddress: tcpGuest, remotePort: 50000),
        generator.initialSendSequence(
            localAddress: tcpGateway, localPort: 8080, remoteAddress: tcpOtherGuest, remotePort: 50000),
    ]
    for neighbour in neighbours {
        #expect(neighbour != base)
        // The distance to a neighbouring four-tuple must not be small. A
        // counter, or a scheme that merely adds the ports in, would put these
        // within a receive window of each other -- which is exactly the
        // guessing an attacker does.
        let distance = neighbour - base
        #expect(abs(distance) > 65535, "a neighbouring four-tuple must not land inside one receive window")
    }

    // A different secret gives a different answer for the same four-tuple:
    // without the secret there is nothing to know.
    let other = RFC6528SequenceNumbers(clock: clock, secret: [UInt8](repeating: 0xa5, count: 16))
    #expect(
        other.initialSendSequence(localAddress: tcpGateway, localPort: 8080, remoteAddress: tcpGuest, remotePort: 50000)
            != base)
}

@Test func theInitialSendSequenceAdvancesWithRfc6528sFourMicrosecondTimer() {
    // The `M` term. RFC 793's original reason for a clock-driven ISS: an old
    // duplicate from a previous incarnation of the same four-tuple must not
    // fall inside the new connection's window.
    let clock = ManualClock(start: .uptimeNanoseconds(0))
    let generator = RFC6528SequenceNumbers(clock: clock, secret: [UInt8](repeating: 0x11, count: 16))
    let before = generator.initialSendSequence(
        localAddress: tcpGateway, localPort: 8080, remoteAddress: tcpGuest, remotePort: 50000)

    clock.advance(by: .milliseconds(400))
    let after = generator.initialSendSequence(
        localAddress: tcpGateway, localPort: 8080, remoteAddress: tcpGuest, remotePort: 50000)

    // 400 ms is 100,000 ticks of a 4-microsecond timer.
    #expect(after - before == 100_000)
}

@Test func sha256MatchesTheFips1804Vectors() {
    // The hash under RFC 6528's `F`. Checked against digests produced by
    // `shasum -a 256`, which shares no code with this implementation -- the
    // only kind of check worth making on a hash, since an implementation
    // checked against itself agrees with itself by construction.
    func hex(_ bytes: [UInt8]) -> String {
        bytes.map { String(format: "%02x", $0) }.joined()
    }
    #expect(hex(SHA256.hash([])) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    #expect(hex(SHA256.hash(Array("abc".utf8))) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    #expect(
        hex(SHA256.hash(Array("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".utf8)))
            == "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1")
    // 55 and 56 bytes bracket the padding boundary: at 56 the length no longer
    // fits in the final block and a second one is appended. An implementation
    // that pads with `% 64 == 56` reversed passes the short vectors and fails
    // exactly here.
    #expect(
        hex(SHA256.hash(Array(0..<55).map { UInt8($0) }))
            == "463eb28e72f82e0a96c0a4cc53690c571281131f672aa229e0d45ae59b598b59")
    #expect(
        hex(SHA256.hash(Array(0..<56).map { UInt8($0) }))
            == "da2ae4d6b36748f2a318f23e7ab1dfdf45acdc9d049bd80e59de82a60895f562")
    #expect(
        hex(SHA256.hash(Array(0..<64).map { UInt8($0) }))
            == "fdeab9acf3710362bd2658cdc9a29e8f9c757fcf9811603a8c447cd1d9151108")
}

// MARK: - Active open

@Test func connectSendsASynAndTheHandshakeCompletesOnTheSynAck() throws {
    let fixture = TCPFixture()
    do {
        let endpoint = TCPEndpoint(stack: fixture.stack, initialSequenceNumbers: FixedInitialSequenceNumbers(gatewayISS))
        let recorder = DataRecorder()
        recorder.attach(to: endpoint)
        try withExtendedLifetime(endpoint) {
            try endpoint.bind(address: tcpGateway, port: tcpLocalPort)
            try endpoint.connect(to: tcpGuest, port: tcpPeerPort)

            let emitted = fixture.drainSegments()
            #expect(emitted.count == 1)
            let syn = try #require(emitted.first).header
            #expect(syn.flags.contains(.syn))
            #expect(!syn.flags.contains(.ack))
            #expect(syn.sequence == SequenceNumber(gatewayISS))
            #expect(syn.options == [.maximumSegmentSize(1460), .windowScale(TCPEndpoint.derivedWindowScale)])
            #expect(recorder.establishedCount == 0, "positive control: not established until the SYN-ACK arrives")

            fixture.inject(
                guestSegment(sequence: guestISS, ack: gatewayISS + 1, flags: [.syn, .ack]))
            #expect(recorder.establishedCount == 1)

            let ack = fixture.drainSegments()
            #expect(ack.count == 1)
            #expect(ack.first?.header.flags.contains(.ack) == true)
            #expect(ack.first?.header.acknowledgement == SequenceNumber(guestISS + 1))
        }
    }
    fixture.drain()
}

@Test func closeSendsAFinOnEveryEstablishedConnection() throws {
    let fixture = TCPFixture()
    do {
        let endpoint = try listeningEndpoint(fixture)
        withExtendedLifetime(endpoint) {
            completeHandshake(fixture)
            _ = fixture.drainSegments()
            // Positive control: silence after `close()` would otherwise be
            // indistinguishable from there having been no connection at all.
            #expect(endpoint.connectionCountForTesting == 1)

            endpoint.close()
            let fin = fixture.drainSegments()
            #expect(fin.count == 1)
            #expect(fin.first?.header.flags.contains(.fin) == true)
            #expect(fin.first?.header.flags.contains(.ack) == true)
            #expect(fin.first?.header.sequence == SequenceNumber(gatewayISS + 1))
            // The connection is NOT discarded: it is in FIN-WAIT-1, holding its
            // own four-tuple until the close completes. Dropping it here is what
            // made TIME-WAIT unreachable in this endpoint's first version.
            #expect(endpoint.connectionCountForTesting == 1)
        }
    }
    fixture.drain()
}

// MARK: - Teardown: FIN retransmission, TIME-WAIT, and the cap on it

/// Take one connection from ESTABLISHED to TIME-WAIT: our FIN is acknowledged,
/// then the peer sends its own.
///
/// `finSequence` is where our FIN sat, which is SND.NXT - 1 after
/// `TCPStateMachine.close` reserved it -- for a connection that sent no data,
/// `gatewayISS + 1`.
private func driveToTimeWait(_ fixture: TCPFixture, peerPort: UInt16 = tcpPeerPort, finSequence: UInt32 = gatewayISS + 1) {
    fixture.inject(guestSegment(sequence: guestISS + 1, ack: finSequence + 1, flags: [.ack], peerPort: peerPort))
    fixture.inject(guestSegment(sequence: guestISS + 1, ack: finSequence + 1, flags: [.fin, .ack], peerPort: peerPort))
}

/// A segment that plausibly belongs to a connection that has just closed: in
/// window for the old block, and carrying an acknowledgement it would accept.
private func lateSegment(peerPort: UInt16 = tcpPeerPort) -> TCPHeader {
    guestSegment(sequence: guestISS + 2, ack: gatewayISS + 2, flags: [.ack], peerPort: peerPort)
}

@Test func aClosedConnectionHoldsItsFourTupleThroughTimeWaitWhileThePortIsRebindable() throws {
    // The two halves of "close" are different, and this is the one that was
    // wrong. A LISTENING key has nothing in flight and is released at once. A
    // CONNECTED four-tuple is held for 2*MSL, because that is the entire purpose
    // of TIME-WAIT: a late or duplicate segment from the old connection must be
    // absorbed by the dying block rather than delivered into a NEW connection
    // that has reused the tuple. An endpoint that releases it immediately has
    // the timer and none of the protection.
    let fixture = TCPFixture()
    do {
        let endpoint = try listeningEndpoint(fixture)
        let successor = TCPEndpoint(stack: fixture.stack, initialSequenceNumbers: FixedInitialSequenceNumbers(9000))
        try withExtendedLifetime((endpoint, successor)) {
            completeHandshake(fixture)
            _ = fixture.drainSegments()

            // Positive control: the port is genuinely taken before the close.
            #expect(throws: StackError.portInUse) {
                try successor.bind(address: tcpGateway, port: tcpLocalPort)
            }

            endpoint.close()
            #expect(fixture.drainSegments().count == 1, "the FIN")

            // The LISTENING key is free the instant `close()` returns...
            try successor.bind(address: tcpGateway, port: tcpLocalPort)
            try successor.listen(backlog: 4)

            driveToTimeWait(fixture)
            _ = fixture.drainSegments()
            #expect(endpoint.timeWaitCountForTesting == 1)

            // ...but the CONNECTED four-tuple is not. A late segment for it is
            // absorbed by the dying block, which acknowledges it -- it does not
            // reach the successor, which would answer a segment for an unknown
            // connection with a reset.
            fixture.inject(lateSegment())
            let absorbed = fixture.drainSegments()
            #expect(absorbed.count == 1)
            #expect(absorbed.first?.header.flags.contains(.ack) == true)
            #expect(absorbed.first?.header.flags.contains(.rst) == false, "TIME-WAIT absorbs; it does not refuse")
            #expect(successor.connectionCountForTesting == 0)

            // 2*MSL later the block is gone and the tuple really is reusable:
            // the identical segment now reaches the successor and is refused.
            fixture.advance(by: .seconds(60))
            #expect(endpoint.connectionCountForTesting == 0)

            fixture.inject(lateSegment())
            let refused = fixture.drainSegments()
            #expect(refused.count == 1)
            #expect(refused.first?.header.flags.contains(.rst) == true, "the tuple is free, so this is a new connection's problem")
        }
    }
    fixture.drain()
}

@Test func timeWaitBlocksAreCappedAndEvictedOldestFirst() throws {
    // A TIME-WAIT block is guest-reachable state that outlives its connection by
    // sixty seconds, so it is capped like everything else a guest can drive. It
    // is the one table here that EVICTS rather than refusing: a connection that
    // has already closed cannot be refused, so the only question is which block
    // to give up, and the oldest is the one whose late segments have had longest
    // to drain.
    let fixture = TCPFixture()
    do {
        let endpoint = TCPEndpoint(
            stack: fixture.stack, initialSequenceNumbers: FixedInitialSequenceNumbers(gatewayISS),
            maximumTimeWaitConnections: 2)
        try endpoint.bind(address: tcpGateway, port: tcpLocalPort)
        try endpoint.listen(backlog: 8)
        withExtendedLifetime(endpoint) {
            for port: UInt16 in [50001, 50002, 50003] {
                completeHandshake(fixture, peerPort: port)
            }
            _ = fixture.drainSegments()
            #expect(endpoint.connectionCountForTesting == 3)

            endpoint.close()
            _ = fixture.drainSegments()

            driveToTimeWait(fixture, peerPort: 50001)
            driveToTimeWait(fixture, peerPort: 50002)
            _ = fixture.drainSegments()
            // Positive control, and the one that matters: the table DOES hold
            // blocks. "It did not grow without bound" is satisfied perfectly by
            // an endpoint that holds nothing at all.
            #expect(endpoint.timeWaitCountForTesting == 2)

            driveToTimeWait(fixture, peerPort: 50003)
            _ = fixture.drainSegments()
            #expect(endpoint.timeWaitCountForTesting == 2, "the cap binds")

            // And it is the OLDEST that went. A late segment for 50001 no longer
            // finds a block and is refused; the identical segment for 50002 is
            // still absorbed.
            fixture.inject(lateSegment(peerPort: 50001))
            let evicted = fixture.drainSegments()
            #expect(evicted.count == 1)
            #expect(evicted.first?.header.flags.contains(.rst) == true)

            fixture.inject(lateSegment(peerPort: 50002))
            let retained = fixture.drainSegments()
            #expect(retained.count == 1)
            #expect(retained.first?.header.flags.contains(.rst) == false)
            #expect(retained.first?.header.flags.contains(.ack) == true)
        }
    }
    fixture.drain()
}

@Test func aLostFinIsRetransmittedOnABackingOffTimerUntilItIsAcknowledged() throws {
    // Tasks 16 and 17 need this: a peer that loses our FIN must see it again, or
    // the close never completes and every teardown sequence in the differential
    // diverges for a reason that has nothing to do with what is under test.
    //
    // `Sender` cannot carry it -- an in-flight record for a FIN has no bytes in
    // its chunk queue, so `retransmitOldest`'s bounds guard fails and it stops
    // retransmitting DATA as well -- so the endpoint owns it.
    let fixture = TCPFixture()
    do {
        let endpoint = try listeningEndpoint(fixture)
        withExtendedLifetime(endpoint) {
            completeHandshake(fixture)
            _ = fixture.drainSegments()

            endpoint.close()
            let first = fixture.drainSegments()
            #expect(first.count == 1)
            #expect(first.first?.header.flags.contains(.fin) == true)

            // RFC 6298 §2.1's initial one second, then §5.5's doubling. Each
            // advance produces exactly one retransmission, at the same sequence
            // number -- a FIN that moved would be a different FIN.
            fixture.advance(by: .seconds(1))
            let second = fixture.drainSegments()
            #expect(second.count == 1)
            #expect(second.first?.header.flags.contains(.fin) == true)
            #expect(second.first?.header.sequence == first.first?.header.sequence)

            fixture.advance(by: .seconds(1))
            #expect(fixture.drainSegments().isEmpty, "the timer backed off; one second is no longer enough")

            fixture.advance(by: .seconds(1))
            let third = fixture.drainSegments()
            #expect(third.count == 1)
            #expect(third.first?.header.sequence == first.first?.header.sequence)

            // Acknowledged: it must stop.
            fixture.inject(guestSegment(sequence: guestISS + 1, ack: gatewayISS + 2, flags: [.ack]))
            _ = fixture.drainSegments()
            for _ in 0..<5 {
                fixture.advance(by: .seconds(120))
            }
            #expect(fixture.drainSegments().isEmpty, "an acknowledged FIN is not retransmitted")
        }
    }
    fixture.drain()
}

@Test func aPeerCannotDeferOurFinRetransmissionBySendingSegments() throws {
    // The FIN's retransmission deadline is ABSOLUTE, and this is why.
    //
    // Every arriving segment re-arms the retransmission timer, and
    // `TCPTimers.scheduleRetransmit` cancels what was pending before it
    // schedules. A deadline recomputed as `now + timeout` on each re-arm
    // therefore slips forward by whatever the peer chooses, and a peer that
    // sends any acceptable segment just under the RTO -- a one-byte write, a
    // window probe, anything -- defers our FIN indefinitely and holds the
    // connection, its four-tuple and its timer open for free.
    //
    // Falsifying the absolute deadline was INERT before this test existed: no
    // other test sends anything to a connection between two FIN retransmissions.
    let fixture = TCPFixture()
    do {
        let endpoint = try listeningEndpoint(fixture)
        withExtendedLifetime(endpoint) {
            completeHandshake(fixture)
            _ = fixture.drainSegments()

            endpoint.close()
            #expect(fixture.drainSegments().count == 1, "the FIN")

            // Half an RTO in, the peer sends something acceptable. It draws an
            // acknowledgement, which is the positive control that the segment
            // really was processed and really did re-arm the timer.
            fixture.advance(by: .milliseconds(500))
            fixture.inject(
                guestSegment(sequence: guestISS + 1, ack: gatewayISS + 1, flags: [.ack]), payload: tcpPayload(1))
            let answered = fixture.drainSegments()
            #expect(answered.count == 1)
            #expect(answered.first?.header.flags.contains(.fin) == false)

            // The rest of the original RTO. The FIN is due now, not half a
            // second from now.
            fixture.advance(by: .milliseconds(500))
            let retransmitted = fixture.drainSegments().filter { $0.header.flags.contains(.fin) }
            #expect(retransmitted.count == 1, "an arriving segment must not push our FIN's deadline out")
            #expect(retransmitted.first?.header.sequence == SequenceNumber(gatewayISS + 1))
        }
    }
    fixture.drain()
}

@Test func aFinThatIsNeverAcknowledgedGivesTheConnectionUpRatherThanPinningIt() throws {
    // RFC 1122 §4.2.3.5's R2. Without a budget a peer that simply never answers
    // pins the block, its four-tuple registration and its timer for the life of
    // the process -- and it costs the peer nothing to do it.
    let fixture = TCPFixture()
    do {
        let endpoint = try listeningEndpoint(fixture)
        withExtendedLifetime(endpoint) {
            completeHandshake(fixture)
            _ = fixture.drainSegments()

            endpoint.close()
            var fins = fixture.drainSegments().count
            // Positive control: the connection and its registration exist to be
            // given up.
            #expect(endpoint.connectionCountForTesting == 1)
            #expect(fixture.stack.transportDemuxer.registrationCountForTesting == 1)

            for _ in 0..<12 {
                fixture.advance(by: .seconds(120))
                fins += fixture.drainSegments().count
            }
            #expect(fins == TCPEndpoint.maximumFinTransmissions)
            #expect(endpoint.connectionCountForTesting == 0)
            #expect(
                fixture.stack.transportDemuxer.registrationCountForTesting == 0,
                "giving the connection up must release its four-tuple too")
        }
    }
    fixture.drain()
}

@Test func aConnectionInTimeWaitIsReleasedWhenTheEndpointIsDropped() throws {
    // The TIME-WAIT timer's `[weak self]`, which was unfalsifiable while
    // `close()` released the four-tuple: no connection could reach TIME-WAIT at
    // all, so making the capture strong failed nothing. It is reachable now.
    let fixture = TCPFixture()
    weak var weakEndpoint: TCPEndpoint?
    do {
        let endpoint = try listeningEndpoint(fixture)
        withExtendedLifetime(endpoint) {
            completeHandshake(fixture)
            _ = fixture.drainSegments()
            endpoint.close()
            driveToTimeWait(fixture)
            _ = fixture.drainSegments()

            // Positive control: there really is an armed 2*MSL timer and a
            // registration held open by it.
            #expect(endpoint.timeWaitCountForTesting == 1)
            #expect(fixture.stack.transportDemuxer.registrationCountForTesting == 1)
            weakEndpoint = endpoint
            #expect(weakEndpoint != nil)
        }
    }
    #expect(weakEndpoint == nil, "a 2*MSL timer must not keep a dropped endpoint alive for a minute")
    #expect(
        fixture.stack.transportDemuxer.registrationCountForTesting == 0,
        "and `deinit` must release the four-tuple it was holding")
    fixture.advance(by: .seconds(120))
    #expect(fixture.drainSegments().isEmpty)
    fixture.drain()
}

// MARK: - RFC 5961 §7: the challenge-ACK budget

// Every count below is the literal 100, never `ChallengeACKBudget.defaultPerSecond`.
// An assertion derived from the code under test goes vacuous exactly when the
// constant it reads is the thing that broke: a budget silently retuned to five,
// or to five million, would keep every one of these green. 100 is
// `ChallengeACKBudget.defaultPerSecond`, and changing that constant is meant to
// break this file loudly.

/// A zero-length segment sitting far behind RCV.NXT, carrying nothing that any
/// of this stack's exact-position exceptions recognise: no FIN (so it is not a
/// TIME-WAIT FIN retransmission) and no SYN (so it is not the SYN-RECEIVED
/// handshake retransmission). It fails RFC 9293 §3.10.7.4's acceptability test
/// and therefore draws step 1's acknowledge-and-drop — the cheapest
/// challenge-ACK provocation a guest has, and the one the differential recorded
/// as an amplification the guest controls.
private func unacceptableSegment() -> TCPHeader {
    guestSegment(sequence: guestISS &- 20_000, ack: gatewayISS + 1, flags: [.ack])
}

/// An in-window RST that is not at RCV.NXT: RFC 5961 §3.2's challenge, not a
/// reset this stack will honour.
private func blindResetInTheWindow() -> TCPHeader {
    guestSegment(sequence: guestISS + 2, flags: [.rst])
}

/// A SYN on a synchronized connection: RFC 5961 §4's challenge. At RCV.NXT, so
/// it passes the acceptability test and reaches step 3 rather than step 2.
private func synOnASynchronizedConnection() -> TCPHeader {
    guestSegment(sequence: guestISS + 1, flags: [.syn])
}

/// An acceptable segment acknowledging data that was never sent: RFC 5961 §5's
/// challenge, reached at step 4.
private func acknowledgementOfDataNeverSent() -> TCPHeader {
    guestSegment(sequence: guestISS + 1, ack: gatewayISS + 5000, flags: [.ack])
}

/// Bare acknowledgements only. A challenge ACK carries no payload and no
/// SYN/FIN/RST, so counting every drained frame would also count a SYN-ACK or a
/// retransmission and make an exhausted budget look busy.
private func challengeAcks(_ fixture: TCPFixture) -> Int {
    fixture.drainSegments().filter { emitted in
        emitted.payload.readableBytes == 0
            && emitted.header.flags.contains(.ack)
            && !emitted.header.flags.contains(.syn)
            && !emitted.header.flags.contains(.fin)
            && !emitted.header.flags.contains(.rst)
    }.count
}

private func flood(_ fixture: TCPFixture, _ header: TCPHeader, times: Int) {
    for _ in 0..<times {
        fixture.inject(header)
    }
}

@Test func aFloodOfUnacceptableSegmentsIsBoundedByTheChallengeAckBudget() throws {
    // The gap the differential recorded: N unacceptable segments drew N ACKs,
    // and the guest chose N. RFC 5961 §7 bounds it.
    let fixture = TCPFixture()
    do {
        let endpoint = try listeningEndpoint(fixture)
        withExtendedLifetime(endpoint) {
            completeHandshake(fixture)
            _ = fixture.drainSegments()

            flood(fixture, unacceptableSegment(), times: 2000)

            // No clock advance anywhere above, so nothing has been earned back:
            // this is the whole of one bucket and not a token more.
            #expect(challengeAcks(fixture) == 100)
        }
    }
    fixture.drain()
}

@Test func aFloodOfUnacceptableSegmentsCarryingDataIsBoundedToo() throws {
    // gVisor exempts a data-bearing segment from its own out-of-window ACK
    // throttle (`maybeSendOutOfWindowAck`: "Data packets are unlikely to be part
    // of an ACK loop"). This stack deliberately does not, and the difference is
    // recorded in `differential/README.md`. gVisor is guarding against ACK loops,
    // where the reasoning holds; the threat here is amplification, and an
    // exemption keyed on "carries a payload" is a bypass of the entire budget for
    // the price of one byte per segment.
    let fixture = TCPFixture()
    do {
        let endpoint = try listeningEndpoint(fixture)
        withExtendedLifetime(endpoint) {
            completeHandshake(fixture)
            _ = fixture.drainSegments()

            for _ in 0..<2000 {
                fixture.inject(unacceptableSegment(), payload: tcpPayload(1))
            }

            #expect(challengeAcks(fixture) == 100)
        }
    }
    fixture.drain()
}

@Test func oneIsolatedUnacceptableSegmentStillDrawsItsChallengeAck() throws {
    // The floor the flood test above cannot supply. "Bounded by 100" is
    // satisfied perfectly by a stack that answers nothing at all, and answering
    // nothing breaks RFC 9293 §3.10.7.4 step 1: the ACK is how a peer whose
    // idea of RCV.NXT has drifted is told where this connection actually is.
    let fixture = TCPFixture()
    do {
        let endpoint = try listeningEndpoint(fixture)
        try withExtendedLifetime(endpoint) {
            completeHandshake(fixture)
            _ = fixture.drainSegments()

            fixture.inject(unacceptableSegment())

            let emitted = fixture.drainSegments()
            #expect(emitted.count == 1)
            let challenge = try #require(emitted.first).header
            // Assert what it IS. A count of one is also true of a stack that
            // answered with something else entirely.
            #expect(challenge.flags.contains(.ack))
            #expect(!challenge.flags.contains(.rst))
            #expect(challenge.acknowledgement == SequenceNumber(guestISS + 1), "RCV.NXT, which is the point of sending it")
            #expect(challenge.sequence == SequenceNumber(gatewayISS + 1))
        }
    }
    fixture.drain()
}

@Test func theChallengeAckBudgetRefillsAsTheClockAdvances() throws {
    // The second floor, and the one a test that only floods will never notice:
    // a limiter that latches shut on first exhaustion is a denial of service
    // this stack inflicts on itself, and it passes the flood test above.
    //
    // The refill is also asserted at a rate rather than as "unlatched by any
    // clock movement at all" — a hundred milliseconds must buy ten challenge
    // ACKs and not a fresh hundred.
    let fixture = TCPFixture()
    do {
        let endpoint = try listeningEndpoint(fixture)
        withExtendedLifetime(endpoint) {
            completeHandshake(fixture)
            _ = fixture.drainSegments()

            flood(fixture, unacceptableSegment(), times: 2000)
            #expect(challengeAcks(fixture) == 100)

            // Exhausted, and still exhausted while the clock stands still.
            fixture.inject(unacceptableSegment())
            #expect(challengeAcks(fixture) == 0)

            fixture.advance(by: .milliseconds(100))
            flood(fixture, unacceptableSegment(), times: 2000)
            #expect(challengeAcks(fixture) == 10, "a tenth of a second earns a tenth of a bucket")

            fixture.advance(by: .seconds(1))
            flood(fixture, unacceptableSegment(), times: 2000)
            #expect(challengeAcks(fixture) == 100, "and a second earns the whole of one, never more")
        }
    }
    fixture.drain()
}

@Test func everyChallengeAckPathDrawsOnOneBudget() throws {
    // The attacker does not care which branch it provokes, so a limit that
    // binds one path and not the others is not a limit. Exhaust the budget
    // through RFC 9293 §3.10.7.4 step 1 and every other challenge must fall
    // silent with it: RFC 5961 §3.2's blind reset, §4's SYN, and §5's
    // acknowledgement of data never sent.
    let fixture = TCPFixture()
    do {
        let endpoint = try listeningEndpoint(fixture)
        withExtendedLifetime(endpoint) {
            completeHandshake(fixture)
            _ = fixture.drainSegments()

            flood(fixture, unacceptableSegment(), times: 100)
            #expect(challengeAcks(fixture) == 100)

            fixture.inject(blindResetInTheWindow())
            #expect(challengeAcks(fixture) == 0, "RFC 5961 §3.2's challenge draws on the same budget")
            fixture.inject(synOnASynchronizedConnection())
            #expect(challengeAcks(fixture) == 0, "RFC 5961 §4's challenge draws on the same budget")
            fixture.inject(acknowledgementOfDataNeverSent())
            #expect(challengeAcks(fixture) == 0, "RFC 5961 §5's challenge draws on the same budget")

            // The positive control, without which every assertion above is
            // equally true of a stack that never challenges these three at all
            // — which is the state this whole task is guarding against.
            fixture.advance(by: .seconds(1))
            fixture.inject(blindResetInTheWindow())
            #expect(challengeAcks(fixture) == 1)
            fixture.inject(synOnASynchronizedConnection())
            #expect(challengeAcks(fixture) == 1)
            fixture.inject(acknowledgementOfDataNeverSent())
            #expect(challengeAcks(fixture) == 1)

            // And none of the three disturbed the connection, which is the
            // other half of what RFC 5961 asks: challenge, do not honour.
            #expect(endpoint.connectionCountForTesting == 1)
        }
    }
    fixture.drain()
}

@Test func theChallengeAckBudgetIsSharedAcrossConnections() throws {
    // The budget is per-stack, not per-connection. A guest that could earn a
    // fresh hundred per connection would still choose the multiplier — it would
    // only have to pay a SYN for each hundred.
    let secondPeerPort: UInt16 = tcpPeerPort + 1
    let fixture = TCPFixture()
    do {
        let endpoint = try listeningEndpoint(fixture)
        withExtendedLifetime(endpoint) {
            completeHandshake(fixture)
            completeHandshake(fixture, peerPort: secondPeerPort)
            _ = fixture.drainSegments()
            #expect(endpoint.connectionCountForTesting == 2)

            flood(fixture, unacceptableSegment(), times: 2000)
            #expect(challengeAcks(fixture) == 100)

            let onTheOtherConnection = guestSegment(
                sequence: guestISS &- 20_000, ack: gatewayISS + 1, flags: [.ack], peerPort: secondPeerPort)
            fixture.inject(onTheOtherConnection)
            #expect(challengeAcks(fixture) == 0, "a second connection does not come with a second budget")

            fixture.advance(by: .seconds(1))
            fixture.inject(onTheOtherConnection)
            #expect(challengeAcks(fixture) == 1, "and the second connection is challenged again once the budget refills")
        }
    }
    fixture.drain()
}

@Test func anAcknowledgementOfRealDataIsNeverRateLimited() throws {
    // The line between the two kinds of ACK. RFC 5961 §7 throttles the ACK sent
    // for a segment being DROPPED; the ACK that acknowledges received data is
    // the connection's flow control, and a limiter that swallowed it would stop
    // a guest's data transfer dead for every second it kept the budget empty —
    // an attack on the connection, delivered by the defence.
    let fixture = TCPFixture()
    let recorder = DataRecorder()
    do {
        let endpoint = try listeningEndpoint(fixture)
        recorder.attach(to: endpoint)
        withExtendedLifetime(endpoint) {
            completeHandshake(fixture)
            _ = fixture.drainSegments()

            flood(fixture, unacceptableSegment(), times: 2000)
            #expect(challengeAcks(fixture) == 100)

            for index in 0..<20 {
                fixture.inject(
                    guestSegment(sequence: guestISS + 1 + UInt32(index * 10), ack: gatewayISS + 1, flags: [.ack]),
                    payload: tcpPayload(10))
            }

            #expect(challengeAcks(fixture) == 20, "every in-order segment is acknowledged, budget or no budget")
            #expect(recorder.bytes.count == 200)
        }
    }
    fixture.drain()
}

@Test func theChallengeAckBudgetBindsInTimeWaitWhileTheTwoMslRestartDoesNot() throws {
    // TIME-WAIT answers unacceptable and acceptable segments alike, from two
    // sites of its own, and both are gated. Without this the two arms would be
    // gated code nothing could fail on: every other test here works on an
    // ESTABLISHED connection, which reaches neither.
    //
    // The second half is the more important one. The ACK is throttled; the 2*MSL
    // restart that travels with it is NOT. Gating the restart would hand a guest
    // a way to expire a TIME-WAIT block early -- empty the budget through any
    // path at all and the FIN retransmissions keeping the block alive stop
    // refreshing it -- and that block is exactly the protection RFC 1337 §3 says
    // a peer must not be able to remove.
    let finRetransmission = guestSegment(sequence: guestISS + 1, ack: gatewayISS + 2, flags: [.fin, .ack])
    let fixture = TCPFixture()
    do {
        let endpoint = try listeningEndpoint(fixture)
        withExtendedLifetime(endpoint) {
            completeHandshake(fixture)
            endpoint.close()
            driveToTimeWait(fixture)
            _ = fixture.drainSegments()
            #expect(endpoint.timeWaitCountForTesting == 1)

            // Step 4's TIME-WAIT arm: an acceptable segment nothing is done
            // with, answered with an ACK the peer has no use for.
            flood(fixture, lateSegment(), times: 2000)
            #expect(challengeAcks(fixture) == 100)

            // Thirty seconds into a sixty-second block, with the budget emptied
            // through a path that does NOT restart the timer, so the only
            // restart that can be at t=30 is the FIN retransmission's.
            fixture.advance(by: .seconds(30))
            flood(fixture, unacceptableSegment(), times: 2000)
            #expect(challengeAcks(fixture) == 100)

            fixture.inject(finRetransmission)
            #expect(challengeAcks(fixture) == 0, "step 2's TIME-WAIT arm is gated too")

            // Past where the original block would have expired. It is still here
            // only if the token-less FIN retransmission restarted it.
            fixture.advance(by: .seconds(31))
            #expect(endpoint.timeWaitCountForTesting == 1, "the 2*MSL restart must not be contingent on a token")

            // And the positive control: the block is not immortal, so the
            // assertion above is about the restart and not about a timer that
            // never fires.
            fixture.advance(by: .seconds(31))
            #expect(endpoint.timeWaitCountForTesting == 0)
        }
    }
    fixture.drain()
}
