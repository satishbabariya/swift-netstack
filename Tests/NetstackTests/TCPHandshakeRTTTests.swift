import NIOCore
import NIOEmbedded
import Testing

@testable import Netstack

// `HandshakeRTT`, and the one direction of it no vector can reach.
//
// `tcp-data.vec` pins the PASSIVE open on the wire, three times over
// (`the-handshake-seeds-the-retransmission-timeout`,
// `a-handshake-sample-makes-the-first-data-sample-a-subsequent-one`,
// `an-ambiguous-handshake-is-not-sampled`), and those vectors are the
// specification. This file covers what they structurally cannot: the vector
// harness binds and listens, so every scenario in it is a passive open, and the
// ACTIVE open -- SYN out, SYN-ACK back -- has no line in any `.vec` file.
//
// The endpoint test below still reads its answer off WHEN a retransmission
// appears rather than off `Sender.retransmissionTimeout`. Reading the
// estimator's own field would prove less: it can hold exactly the right numbers
// while the timer that was armed from it holds the wrong ones, which is
// precisely the ordering defect this task had to avoid.

// MARK: - The type

@Test func aHandshakeSentOnceIsSampledAsTheElapsedRoundTrip() throws {
    var handshake = HandshakeRTT()
    let start = NIODeadline.uptimeNanoseconds(0)
    handshake.recordTransmission(at: start)
    #expect(handshake.sample(at: start + .milliseconds(400)) == .milliseconds(400))
}

/// Karn's algorithm (RFC 6298 §3). This is the whole reason the type counts
/// rather than merely remembering a time.
@Test func aHandshakeSentTwiceIsNotSampledAtAll() throws {
    var handshake = HandshakeRTT()
    let start = NIODeadline.uptimeNanoseconds(0)
    handshake.recordTransmission(at: start)
    handshake.recordTransmission(at: start + .milliseconds(400))
    // Both readings a Karn-less implementation might take are wrong, and the
    // point is that NEITHER is returned: 1400 ms measured from the first
    // transmission, 1000 ms measured from the second.
    #expect(handshake.sample(at: start + .milliseconds(1400)) == nil)
}

@Test func aHandshakeThatWasNeverSentHasNoSample() throws {
    let handshake = HandshakeRTT()
    #expect(handshake.sample(at: .uptimeNanoseconds(1_000_000)) == nil)
}

/// The failure that raises nothing. A host-local handshake completes in
/// microseconds, and under a clock coarser than that both deadlines are the
/// same instant -- so the sample is zero, `RTTEstimator.measure` would discard
/// it anyway, and the whole effect disappears with no error anywhere. Pinned
/// here so that "no sample" is a decision this type makes rather than an
/// accident of two subtractions.
@Test func aRoundTripThatMeasuredZeroIsNotASample() throws {
    var handshake = HandshakeRTT()
    let start = NIODeadline.uptimeNanoseconds(5_000_000)
    handshake.recordTransmission(at: start)
    #expect(handshake.sample(at: start) == nil)
    // And a clock that ran backwards, which is the same refusal for the same
    // reason: a negative sample would drag SRTT down rather than describe a path.
    #expect(handshake.sample(at: start - .milliseconds(1)) == nil)
}

// MARK: - The active open, on the wire

private let rttGateway = IPv4Address("192.168.127.1")!
private let rttGuest = IPv4Address("192.168.127.2")!
private let rttGatewayMAC = MACAddress("5a:94:ef:e4:0c:ee")!
private let rttGuestMAC = MACAddress("0a:0b:0c:0d:0e:0f")!
private let rttLocalPort: UInt16 = 8080
private let rttPeerPort: UInt16 = 50000
private let rttGatewayISS: UInt32 = 1000
private let rttGuestISS: UInt32 = 7000

private struct FixedISS: InitialSequenceNumbers {
    let value: UInt32
    func initialSendSequence(
        localAddress: IPv4Address, localPort: UInt16, remoteAddress: IPv4Address, remotePort: UInt16
    ) -> SequenceNumber {
        SequenceNumber(value)
    }
}

/// One loop, one clock, one started stack, advanced together -- the same
/// lockstep rule `TCPTimerTests` states, because `TCPTimers` computes deadlines
/// from the clock while the loop decides what has come due from its own time.
private final class RTTFixture {
    let loop = EmbeddedEventLoop()
    let clock = ManualClock(start: .uptimeNanoseconds(0))
    let link: RecordingEndpoint
    let stack: Stack

    init() {
        link = RecordingEndpoint(eventLoop: loop, linkAddress: rttGatewayMAC)
        stack = Stack(
            link: link,
            configuration: Stack.Configuration(gatewayAddress: rttGateway, subnet: IPv4Subnet(cidr: "192.168.127.0/24")!),
            clock: clock)
        stack.start()
        primeARP()
    }

    /// An active open sends before anything has arrived, so nothing has taught
    /// the ARP cache the next hop yet and `IPv4Protocol.send` would emit a
    /// REQUEST where the SYN is expected. Re-primed on every advance because the
    /// entries expire after sixty seconds.
    private func primeARP() { stack.arpCache.record(rttGuest, rttGuestMAC) }

    func advance(by amount: TimeAmount) {
        clock.advance(by: amount)
        primeARP()
        loop.advanceTime(by: amount)
    }

    /// `EmbeddedEventLoop.deinit` traps on an outstanding scheduled task, which
    /// would kill the runner before it printed a summary.
    func drain() {
        advance(by: .hours(1))
        _ = link.drainTransmitted()
    }

    func inject(_ header: TCPHeader, payload: ByteBuffer = ByteBuffer()) {
        let allocator = ByteBufferAllocator()
        let segment = header.serialize(payload: payload, source: rttGuest, destination: rttGateway, allocator: allocator)
        var packet = PacketBuffer(allocator: allocator, payload: segment)
        IPv4Header(source: rttGuest, destination: rttGateway, protocolNumber: .tcp, payloadLength: segment.readableBytes)
            .prepend(to: &packet)
        EthernetHeader(destination: rttGatewayMAC, source: rttGuestMAC, etherType: .ipv4).prepend(to: &packet)
        link.inject(packet.frame)
    }

    /// Non-TCP frames are dropped rather than failing: a stray ARP request would
    /// otherwise turn a clear assertion failure into a confusing one.
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

private func rttGuestSegment(sequence: UInt32, ack: UInt32, flags: TCPFlags, options: [TCPOption] = []) -> TCPHeader {
    TCPHeader(
        sourcePort: rttPeerPort,
        destinationPort: rttLocalPort,
        sequence: SequenceNumber(sequence),
        acknowledgement: SequenceNumber(ack),
        dataOffset: 5 + TCPOptionCodec.encode(options).count / 4,
        flags: flags,
        window: 65535,
        checksum: 0,
        urgentPointer: 0,
        options: options)
}

/// An active open samples SYN -> SYN-ACK, and the sample has to survive the one
/// thing that happens between them.
///
/// **The SYN-ACK carries an MSS option, and that is the point of the test.**
/// `TCPEndpoint.deliver` reacts to an MSS on a SYN in SYN-SENT by REBUILDING
/// `connection.sender` from scratch (`adoptPeerSegmentSize`), which discards the
/// RTT estimator along with everything else the old sender held. So an
/// implementation that seeded the estimator anywhere ahead of that rebuild would
/// pass every passive-open vector in `tcp-data.vec` and lose the sample here,
/// silently: no error, no missing frame, and an active open that quietly keeps
/// the unseeded RTO for the rest of its life.
///
/// The handshake takes 400 ms, so SRTT = 400, RTTVAR = 200 and RTO = 400 +
/// 4 * 200 = 1.200 s -- above the one-second floor, which is what makes the two
/// answers distinguishable at all.
@Test func anActiveOpenSamplesItsHandshakeAndKeepsItAcrossTheSenderRebuild() throws {
    let fixture = RTTFixture()
    do {
        let endpoint = TCPEndpoint(stack: fixture.stack, initialSequenceNumbers: FixedISS(value: rttGatewayISS))
        try withExtendedLifetime(endpoint) {
            try endpoint.bind(address: rttGateway, port: rttLocalPort)
            try endpoint.connect(to: rttGuest, port: rttPeerPort)
            #expect(fixture.drainSegments().count == 1, "positive control: the SYN went out, so there is a round trip to measure")

            fixture.advance(by: .milliseconds(400))
            fixture.inject(
                rttGuestSegment(
                    sequence: rttGuestISS, ack: rttGatewayISS + 1, flags: [.syn, .ack],
                    options: [.maximumSegmentSize(1460)]))
            // The third leg. Drained so that what follows is only data.
            #expect(fixture.drainSegments().count == 1)

            var payload = ByteBufferAllocator().buffer(capacity: 100)
            payload.writeRepeatingByte(0x5a, count: 100)
            try endpoint.send(payload)
            #expect(fixture.drainSegments().count == 1, "the data segment itself")

            // 1.199 s after the send. This is the assertion that discriminates:
            // an unseeded estimator sits on RFC 6298 §2.1's initial one-second
            // RTO and would ALREADY have retransmitted by now.
            fixture.advance(by: .milliseconds(1199))
            #expect(fixture.drainSegments().isEmpty, "a 1.200 s RTO has not expired yet")

            // And it does fire, one millisecond later, rather than never -- the
            // half that stops the assertion above from being satisfied by a
            // stack that simply gave up retransmitting.
            fixture.advance(by: .milliseconds(1))
            let retransmission = fixture.drainSegments()
            #expect(retransmission.count == 1)
            #expect(retransmission.first?.header.sequence == SequenceNumber(rttGatewayISS + 1))
            #expect(retransmission.first?.payload.readableBytes == 100)
        }
    }
    fixture.drain()
}

/// A box for the callback below. `onEstablished` is an escaping closure, so a
/// local `var` cannot be mutated from inside it.
private final class EstablishedCounter: @unchecked Sendable {
    var calls = 0
}

/// The ordering that actually matters, which is NOT the one it looks like.
///
/// The obvious ordering bug -- "feed the sample after the first data send" --
/// turns out to be unreachable, and it is worth saying why rather than leaving
/// the next reader to re-derive it. `TCPEndpoint.send` throws in every state
/// before ESTABLISHED, so nothing can be queued when the establishing segment is
/// processed, and the `transmit` in that same pass therefore has nothing to put
/// on the wire. Moving the seed to after that `transmit` changes no frame in any
/// vector in this package, because the first data send is always a LATER call.
///
/// The reachable version is this one. `onEstablished` is application code and it
/// runs inside that same pass, and an application is entitled to write from it
/// -- that is the earliest moment it is allowed to write at all. So the sample
/// has to be in the estimator BEFORE the callback runs, not merely before the
/// endpoint's own `transmit`. Seed it after `onEstablished` and the very first
/// segment of a connection that writes at the first opportunity is timed by RFC
/// 6298 §2.1's unmeasured one-second RTO, while the estimator sitting next to it
/// holds the right number all along.
@Test func anApplicationWritingFromOnEstablishedIsTimedByTheSeededTimeout() throws {
    let fixture = RTTFixture()
    do {
        let endpoint = TCPEndpoint(stack: fixture.stack, initialSequenceNumbers: FixedISS(value: rttGatewayISS))
        let established = EstablishedCounter()
        try withExtendedLifetime(endpoint) {
            try endpoint.bind(address: rttGateway, port: rttLocalPort)
            try endpoint.listen(backlog: 8)
            endpoint.onEstablished = { [weak endpoint] in
                established.calls += 1
                var payload = ByteBufferAllocator().buffer(capacity: 100)
                payload.writeRepeatingByte(0x5a, count: 100)
                try? endpoint?.send(payload)
            }

            fixture.inject(
                rttGuestSegment(sequence: rttGuestISS, ack: 0, flags: [.syn], options: [.maximumSegmentSize(1460)]))
            #expect(fixture.drainSegments().count == 1, "the SYN-ACK")

            // A 400 ms handshake, so SRTT = 400, RTTVAR = 200, RTO = 1.200 s --
            // above the one-second floor, which is the only reason the seeded
            // and unseeded answers differ at all.
            fixture.advance(by: .milliseconds(400))
            fixture.inject(rttGuestSegment(sequence: rttGuestISS + 1, ack: rttGatewayISS + 1, flags: [.ack]))
            #expect(established.calls == 1, "positive control: the callback ran, so there was a write to time")
            #expect(fixture.drainSegments().count == 1, "the data segment, written from inside onEstablished")

            // The discriminating assertion: an unseeded estimator would have
            // retransmitted 199 ms ago.
            fixture.advance(by: .milliseconds(1199))
            #expect(fixture.drainSegments().isEmpty, "a 1.200 s RTO has not expired yet")

            fixture.advance(by: .milliseconds(1))
            #expect(fixture.drainSegments().count == 1, "and it does fire, rather than never")
        }
    }
    fixture.drain()
}
