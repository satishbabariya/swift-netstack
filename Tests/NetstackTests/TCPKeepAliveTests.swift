import NIOCore
import Testing

@testable import Netstack

// RFC 1122 §4.2.3.6. Off unless a caller turns it on, which the RFC states as a
// MUST -- a probe on an idle connection can tear down one that is merely quiet,
// and costs traffic on links that charge for it.
//
// A gateway is one of the places it earns that cost: a guest that goes away
// without closing leaves an endpoint and a spliced host socket held for as long
// as the connection is nominally established, and nothing else ever notices,
// because there is no data to retransmit.

private func keepAliveEndpoint(
    _ fixture: TCPFixture, idle: TimeAmount = .seconds(100), interval: TimeAmount = .seconds(10),
    count: Int = 3
) throws -> TCPEndpoint {
    let endpoint = try listeningEndpoint(fixture)
    endpoint.keepAlive = TCPEndpoint.KeepAliveConfiguration(
        idle: idle, interval: interval, count: count)
    return endpoint
}

@Test func anIdleConnectionIsProbedAtTheSequenceThePeerHasAlreadyAcknowledged() throws {
    // The sequence number is the whole trick. A segment at SND.NXT would be new
    // data the peer has not seen; one below SND.UNA would be out of window.
    // `SND.NXT - 1` is a byte the peer has already acknowledged, so it is
    // unambiguously a duplicate and every TCP answers it.
    let fixture = TCPFixture()
    do {
        let endpoint = try keepAliveEndpoint(fixture)
        try withExtendedLifetime(endpoint) {
            completeHandshake(fixture)
            _ = fixture.drainSegments()

            fixture.advance(by: .seconds(100))

            let probes = fixture.drainSegments()
            #expect(probes.count == 1)
            let probe = try #require(probes.first)
            #expect(probe.payload.readableBytes == 0, "the probe carried data")
            #expect(probe.header.sequence == SequenceNumber(gatewayISS), "the probe is not at SND.NXT - 1")
            #expect(probe.header.flags.contains(.ack))
        }
    }
    fixture.drain()
}

@Test func aConnectionWithKeepAliveOffIsNeverProbed() throws {
    // The default, and the RFC's MUST. Without this test the one above shows
    // that a probe happens, not that it happens only when asked for.
    let fixture = TCPFixture()
    do {
        let endpoint = try listeningEndpoint(fixture)
        try withExtendedLifetime(endpoint) {
            completeHandshake(fixture)
            _ = fixture.drainSegments()

            fixture.advance(by: .hours(3))

            #expect(fixture.drainSegments().isEmpty, "an idle connection was probed with keep-alive off")
        }
    }
    fixture.drain()
}

@Test func anAnsweredProbePushesTheNextOneOutByAFullIdlePeriod() throws {
    // Any sign of life resets the clock. A peer that answers must not be probed
    // again on the shorter between-probes interval -- that is the schedule for a
    // peer that has stopped answering, and applying it to one that has not turns
    // a two-hour keep-alive into a seventy-five-second one.
    let fixture = TCPFixture()
    do {
        let endpoint = try keepAliveEndpoint(fixture)
        try withExtendedLifetime(endpoint) {
            completeHandshake(fixture)
            _ = fixture.drainSegments()

            fixture.advance(by: .seconds(100))
            #expect(fixture.drainSegments().count == 1)

            // The peer answers, as any TCP answers a duplicate segment.
            fixture.inject(guestSegment(sequence: guestISS + 1, ack: gatewayISS + 1, flags: [.ack]))
            _ = fixture.drainSegments()

            // The between-probes interval passes and nothing goes out.
            fixture.advance(by: .seconds(10))
            #expect(fixture.drainSegments().isEmpty, "the answered connection was probed on the short interval")

            // The full idle period does produce one.
            fixture.advance(by: .seconds(90))
            #expect(fixture.drainSegments().count == 1)
        }
    }
    fixture.drain()
}

@Test func aPeerThatNeverAnswersIsGivenUpOnAfterTheProbeBudget() throws {
    // The point of the feature. Holding a connection open for a peer that will
    // never answer holds an endpoint -- and on a gateway, the host socket
    // spliced to it -- forever.
    let fixture = TCPFixture()
    let recorder = Counter()
    do {
        let endpoint = try keepAliveEndpoint(fixture, count: 3)
        try withExtendedLifetime(endpoint) {
            endpoint.onClosed = { recorder.increment() }
            completeHandshake(fixture)
            _ = fixture.drainSegments()

            fixture.advance(by: .seconds(100))
            for _ in 0..<3 { fixture.advance(by: .seconds(10)) }

            let segments = fixture.drainSegments()
            #expect(segments.filter { !$0.header.flags.contains(.rst) }.count == 3, "the probe budget was not three")
            let reset = try #require(segments.last)
            // A reset, because there is nobody left to send a FIN to and
            // anything downstream has to be told the connection is over.
            #expect(reset.header.flags.contains(.rst))
            #expect(recorder.value == 1, "the application was not told the connection ended")
            #expect(endpoint.connectionCountForTesting == 0, "the connection was left behind")
        }
    }
    fixture.drain()
}

@Test func aConnectionWithDataInFlightIsNotProbed() throws {
    // Running both timers means the keep-alive fires during a transfer that is
    // merely slow, and its probe -- a segment below SND.NXT -- draws a duplicate
    // acknowledgement the sender counts toward fast retransmit. A keep-alive
    // that can cause a spurious retransmission is worse than none.
    let fixture = TCPFixture()
    do {
        let endpoint = try keepAliveEndpoint(fixture, idle: .seconds(100))
        try withExtendedLifetime(endpoint) {
            completeHandshake(fixture)
            _ = fixture.drainSegments()
            try endpoint.send(tcpPayload(100))
            _ = fixture.drainSegments()

            // Long enough for the idle timer, but the data is unacknowledged.
            fixture.advance(by: .seconds(100))

            let segments = fixture.drainSegments()
            // Retransmissions are expected; a keep-alive probe is not. The probe
            // is the only zero-length segment the endpoint would send here.
            #expect(
                segments.allSatisfy { $0.payload.readableBytes > 0 },
                "a keep-alive probe went out while data was in flight")
        }
    }
    fixture.drain()
}

@Test func turningKeepAliveOffOnALiveConnectionStopsTheProbeAlreadyScheduled() throws {
    // Two nil-checks read `keepAlive`: one before scheduling a timer, one before
    // acting on it. Falsification found they mask each other -- removing either
    // alone changes nothing observable -- and this is the case that separates
    // them.
    //
    // A caller that turns keep-alive off has already had a timer armed for every
    // established connection, and nothing re-arms it until a segment arrives.
    // Without the second check the probe that was already scheduled still goes
    // out, on a connection whose owner has said it should not be probed.
    let fixture = TCPFixture()
    do {
        let endpoint = try keepAliveEndpoint(fixture, idle: .seconds(100))
        try withExtendedLifetime(endpoint) {
            completeHandshake(fixture)
            _ = fixture.drainSegments()

            // Armed by the handshake; now switched off with nothing arriving to
            // re-arm it.
            endpoint.keepAlive = nil
            fixture.advance(by: .seconds(100))

            #expect(fixture.drainSegments().isEmpty, "the scheduled probe outlived the setting that asked for it")
        }
    }
    fixture.drain()
}
