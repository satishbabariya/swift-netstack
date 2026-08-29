import NIOCore
import Testing

@testable import Netstack

// The forwarder is how a gateway serves ports it cannot know in advance. It sees
// every SYN, asks a handler what to do, and only then builds an endpoint —
// gVisor's `tcp.Forwarder` in shape and purpose.

@Test func aForwarderHandsEachNewConnectionToItsHandlerBeforeAnsweringIt() throws {
    let fixture = TCPFixture()
    var seen: [(UInt16, UInt16)] = []
    let forwarder = TCPForwarder(stack: fixture.stack) { request in
        seen.append((request.sourcePort, request.destinationPort))
    }
    try withExtendedLifetime(forwarder) {
        fixture.inject(guestSegment(sequence: guestISS, flags: [.syn], peerPort: 9999))

        #expect(seen.count == 1)
        #expect(seen.first?.1 == 8080, "the port the guest dialled, which nothing had bound")
        // Nothing on the wire yet: the handler has not decided. A stack that
        // answered first and asked afterwards would have committed to a
        // connection the handler may refuse.
        #expect(fixture.drainSegments().isEmpty, "the SYN is unanswered until the handler settles")
    }
    fixture.drain()
}

@Test func refusingAnswersWithAResetThatNamesTheSynsSequence() throws {
    let fixture = TCPFixture()
    let forwarder = TCPForwarder(stack: fixture.stack) { $0.refuse() }
    try withExtendedLifetime(forwarder) {
        fixture.inject(guestSegment(sequence: guestISS, flags: [.syn], peerPort: 9999))
        let reset = try #require(fixture.drainSegments().first).header
        #expect(reset.flags.contains(.rst))
        // RFC 9293 §3.10.7.1: the answer to a SYN carries the ACK bit and
        // acknowledges SEG.SEQ + 1. A bare reset is one a dialler ignores, which
        // reads exactly like a hang — the distinction the TCP plan had to be
        // corrected on once already.
        #expect(reset.flags.contains(.ack), "a refusal a dialler will believe")
        #expect(reset.acknowledgement == SequenceNumber(guestISS + 1))
    }
    fixture.drain()
}

@Test func completingAnswersTheSynAndTheHandshakeFinishes() throws {
    let fixture = TCPFixture()
    var accepted: TCPEndpoint?
    let forwarder = TCPForwarder(stack: fixture.stack) { request in
        accepted = try? request.complete()
    }
    try withExtendedLifetime(forwarder) {
        fixture.inject(guestSegment(sequence: guestISS, flags: [.syn], peerPort: 9999))
        let synAck = try #require(fixture.drainSegments().first).header
        #expect(synAck.flags.contains(.syn))
        #expect(synAck.flags.contains(.ack))
        #expect(accepted != nil, "the handler got an endpoint holding the connection")
    }
    fixture.drain()
}

@Test func aFloodOfSynsIsBoundedAndTheExcessIsDroppedRatherThanReset() throws {
    // The SYN-flood bound. Every unsettled request holds a half-open
    // connection's memory and the guest chooses how many to make.
    //
    // Dropped, NOT reset, and the distinction is the point: a reset confirms to a
    // scanner that the gateway is there, and spends a frame per probe — the
    // amplification RFC 5961's budget exists to stop one layer down. Silence
    // costs the attacker a timeout and costs us nothing.
    let fixture = TCPFixture()
    let forwarder = TCPForwarder(stack: fixture.stack, maximumInFlight: 4) { _ in
        // Neither completes nor refuses: the handler that leaks slots, which is
        // exactly the case the bound is for.
    }
    withExtendedLifetime(forwarder) {
        for port in UInt16(20000)..<UInt16(20050) {
            fixture.inject(guestSegment(sequence: guestISS, flags: [.syn], peerPort: port))
        }
        #expect(forwarder.inFlightCountForTesting == 4, "bounded, and bounded at what was asked for")
        #expect(fixture.drainSegments().isEmpty, "and not one frame was spent answering the flood")
    }
    fixture.drain()
}

@Test func aRetransmittedSynDoesNotCreateASecondRequest() throws {
    // A peer whose SYN went unanswered retransmits. Treating the repeat as a new
    // connection would let one dialler consume the whole in-flight budget on its
    // own, which turns a slow handler into a denial of service against every
    // other connection.
    let fixture = TCPFixture()
    var requests = 0
    let forwarder = TCPForwarder(stack: fixture.stack, maximumInFlight: 4) { _ in requests += 1 }
    withExtendedLifetime(forwarder) {
        for _ in 0..<10 {
            fixture.inject(guestSegment(sequence: guestISS, flags: [.syn], peerPort: 9999))
        }
        #expect(requests == 1, "one four-tuple, one request")
        #expect(forwarder.inFlightCountForTesting == 1)
    }
    fixture.drain()
}

@Test func aDroppedForwarderIsReleased() {
    // The demuxer's protocol handler holds a closure and the closure holds the
    // forwarder. A strong capture would keep the whole graph alive for as long
    // as the stack lives — the retain cycle an audit found four unguarded fixes
    // for one layer down.
    //
    // This guards the CAPTURE and nothing else. See the test below for why that
    // distinction had to be made explicit.
    let fixture = TCPFixture()
    weak var weakForwarder: TCPForwarder?
    do {
        let forwarder = TCPForwarder(stack: fixture.stack) { $0.refuse() }
        weakForwarder = forwarder
        #expect(weakForwarder != nil, "positive control: it was alive a moment ago")
    }
    #expect(weakForwarder == nil, "the forwarder outlived its owner")
    fixture.drain()
}

@Test func aDroppedForwarderStopsInterceptingSegments() {
    // The behaviour that matters: once the forwarder is gone, a SYN reaches the
    // stack's ordinary handling — which answers a port nothing is listening on
    // with a reset — rather than being swallowed by a handler whose owner no
    // longer exists. A handler that returned `true` forever would consume every
    // TCP segment on the stack, presenting as a network that had silently
    // stopped rather than as anything failing.
    //
    // **What makes it true is the `[weak self]` capture, not `deinit`'s
    // uninstall.** That was established by falsification rather than by reading:
    // removing the uninstall leaves this test green, because a handler whose
    // `self` is nil returns false and the segment falls through anyway. The
    // uninstall is housekeeping — it releases the closure the demuxer holds —
    // and no test here distinguishes it. Said plainly in `TCPForwarder.deinit`
    // too, so a reader does not assume this test covers that line.
    let fixture = TCPFixture()
    do {
        let forwarder = TCPForwarder(stack: fixture.stack) { _ in
            // Swallows everything: neither completes nor refuses.
        }
        withExtendedLifetime(forwarder) {
            fixture.inject(guestSegment(sequence: guestISS, flags: [.syn], peerPort: 9999))
            #expect(fixture.drainSegments().isEmpty, "positive control: it really was intercepting")
        }
    }
    fixture.inject(guestSegment(sequence: guestISS, flags: [.syn], peerPort: 9998))
    let answered = fixture.drainSegments()
    #expect(answered.count == 1, "the stack answers it now that nothing is intercepting")
    #expect(answered.first?.header.flags.contains(.rst) == true, "with a reset, because nothing is listening")
    fixture.drain()
}

@Test func aForwarderAcceptsManyConnectionsToTheSameDestinationPort() throws {
    // The defect this catches made the forwarder useless for its actual job.
    //
    // `accept` used to `bind` each new endpoint to the destination port, and
    // that registration is the exclusive wildcard key `(local, port, any, 0)`.
    // The first connection to port 8080 took it; every later one failed with
    // `portInUse` inside `complete()`. A browser opens six connections to the
    // same host and port, so this was not an edge case — it was every real
    // workload, failing in the quietest possible way: `complete()` threw, the
    // request was already consumed, and the connection simply never appeared.
    //
    // It surfaced from an accept-backpressure test one layer up that asked for
    // its second connection and got nothing back.
    let fixture = TCPFixture()
    var accepted: [TCPEndpoint] = []
    let forwarder = TCPForwarder(stack: fixture.stack) { request in
        if let endpoint = try? request.complete() { accepted.append(endpoint) }
    }
    try withExtendedLifetime(forwarder) {
        for peerPort in UInt16(50001)...UInt16(50006) {
            fixture.inject(guestSegment(sequence: guestISS, flags: [.syn], peerPort: peerPort))
        }
        #expect(accepted.count == 6, "connections after the first were refused by our own port table")
        // Each was answered, and answered separately: six SYN-ACKs, not one
        // endpoint quietly serving six four-tuples.
        let synAcks = fixture.drainSegments().filter { $0.header.flags.contains(.syn) }
        #expect(synAcks.count == 6)
        #expect(Set(synAcks.map(\.header.destinationPort)).count == 6)
    }
    accepted.removeAll()
    fixture.drain()
}
