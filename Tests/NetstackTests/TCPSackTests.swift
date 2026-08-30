import NIOCore
import Testing

@testable import Netstack

// RFC 2018, receiver half: report what arrived out of order so the peer can
// retransmit the hole instead of everything after it.
//
// Reporting and acting on reports are separate features and land separately.
// A stack can negotiate SACK, report faithfully, and still recover by RFC
// 5681's duplicate-ACK rules — which is exactly what this stack does between
// the two halves.

/// Handshake offering SACK (and, optionally, timestamps) from the guest.
@discardableResult
private func sackHandshake(_ fixture: TCPFixture, timestamps: Bool = false) -> [TCPOption] {
    var options: [TCPOption] = [.maximumSegmentSize(1460), .sackPermitted]
    if timestamps { options.append(.timestamps(value: 1, echo: 0)) }
    fixture.inject(guestSegment(sequence: guestISS, flags: [.syn], options: options))
    let synAck = fixture.drainSegments().first?.header.options ?? []
    fixture.inject(guestSegment(sequence: guestISS + 1, ack: gatewayISS + 1, flags: [.ack]))
    _ = fixture.drainSegments()
    return synAck
}

/// Every TCP header emitted since the last drain, **and how many frames could
/// not be parsed back**.
///
/// `TCPFixture.drainSegments` drops what it cannot parse, which is the right
/// default for tests asserting about TCP and exactly wrong for a test about
/// how large a header may be: the malformed header is the evidence.
private func parsedFrames(_ fixture: TCPFixture) -> (headers: [TCPHeader], unparsed: Int) {
    var headers: [TCPHeader] = []
    var unparsed = 0
    for frame in fixture.link.drainTransmitted() {
        var packet = PacketBuffer(received: frame)
        guard let ethernet = EthernetHeader.parse(&packet), ethernet.etherType == .ipv4 else { continue }
        guard let ip = IPv4Header.parse(&packet), ip.protocolNumber == .tcp else { continue }
        guard let tcp = TCPHeader.parse(&packet, header: ip) else {
            unparsed += 1
            continue
        }
        headers.append(tcp)
    }
    return (headers, unparsed)
}

/// The SACK blocks on the last segment emitted, or none.
private func lastSackBlocks(_ fixture: TCPFixture) -> [SACKBlock] {
    guard let last = fixture.drainSegments().last else { return [] }
    for option in last.header.options {
        if case .selectiveAcknowledgement(let blocks) = option { return blocks }
    }
    return []
}

@Test func aSynAckAnsweringASackOfferSaysSackPermittedBack() throws {
    let fixture = TCPFixture()
    do {
        let endpoint = try listeningEndpoint(fixture)
        withExtendedLifetime(endpoint) {
            let answered = sackHandshake(fixture)
            #expect(answered.contains(.sackPermitted))
        }
    }
    fixture.drain()
}

@Test func aSynAckDoesNotOfferSackToAGuestThatDidNotAskForIt() throws {
    // The option is an agreement, not an announcement. Sending it back to a
    // guest that never offered would claim an exchange that did not happen —
    // and would invite blocks this connection's peer has no reason to expect.
    let fixture = TCPFixture()
    do {
        let endpoint = try listeningEndpoint(fixture)
        withExtendedLifetime(endpoint) {
            let synAck = completeHandshake(fixture).first?.header.options ?? []
            #expect(!synAck.contains(.sackPermitted))
        }
    }
    fixture.drain()
}

@Test func anOutOfOrderSegmentIsReportedAsASackBlock() throws {
    let fixture = TCPFixture()
    do {
        let endpoint = try listeningEndpoint(fixture)
        withExtendedLifetime(endpoint) {
            sackHandshake(fixture)
            // A hole at [1, 501), then data at [501, 1001).
            fixture.inject(
                guestSegment(sequence: guestISS + 501, ack: gatewayISS + 1, flags: [.ack]),
                payload: tcpPayload(500))
            let blocks = lastSackBlocks(fixture)
            #expect(blocks.count == 1)
            #expect(blocks.first?.left == SequenceNumber(guestISS + 501))
            #expect(blocks.first?.right == SequenceNumber(guestISS + 1001))
        }
    }
    fixture.drain()
}

@Test func aConnectionThatNeverNegotiatedSackReportsNothingHowever() throws {
    // Falsification target for the negotiation guard: without it a peer that
    // never asked for SACK receives blocks anyway, and a peer that did not ask
    // is a peer entitled to assume the option is absent.
    let fixture = TCPFixture()
    do {
        let endpoint = try listeningEndpoint(fixture)
        withExtendedLifetime(endpoint) {
            completeHandshake(fixture)
            _ = fixture.drainSegments()
            fixture.inject(
                guestSegment(sequence: guestISS + 501, ack: gatewayISS + 1, flags: [.ack]),
                payload: tcpPayload(500))
            #expect(lastSackBlocks(fixture).isEmpty)
        }
    }
    fixture.drain()
}

@Test func contiguousQueuedRunsAreReportedAsOneBlock() throws {
    // The queue holds pieces; the peer needs ranges. Two adjacent pieces are
    // one range, and reporting them separately would spend two of the four
    // available blocks saying one thing.
    let fixture = TCPFixture()
    do {
        let endpoint = try listeningEndpoint(fixture)
        withExtendedLifetime(endpoint) {
            sackHandshake(fixture)
            for offset in [UInt32(501), UInt32(1001)] {
                fixture.inject(
                    guestSegment(sequence: guestISS + offset, ack: gatewayISS + 1, flags: [.ack]),
                    payload: tcpPayload(500))
            }
            let blocks = lastSackBlocks(fixture)
            #expect(blocks.count == 1, "two adjacent runs were reported as two blocks: \(blocks)")
            #expect(blocks.first?.right == SequenceNumber(guestISS + 1501))
        }
    }
    fixture.drain()
}

@Test func theBlockHoldingTheMostRecentSegmentIsReportedFirst() throws {
    // RFC 2018 §4's MUST. A receiver reporting in sequence order would be
    // describing its state correctly and would still be wrong: the first block
    // is how the sender knows which segment triggered this acknowledgement.
    let fixture = TCPFixture()
    do {
        let endpoint = try listeningEndpoint(fixture)
        withExtendedLifetime(endpoint) {
            sackHandshake(fixture)
            // LOW first, then HIGH, and the order matters to the test as much
            // as to the RFC. The first draft injected high then low, so the
            // most recent run was also the lowest — sequence order and recency
            // order agreed, and the assertion held under either rule. It passed
            // with the reordering removed, which is how the flaw was found.
            fixture.inject(
                guestSegment(sequence: guestISS + 1001, ack: gatewayISS + 1, flags: [.ack]),
                payload: tcpPayload(500))
            fixture.inject(
                guestSegment(sequence: guestISS + 3001, ack: gatewayISS + 1, flags: [.ack]),
                payload: tcpPayload(500))
            let blocks = lastSackBlocks(fixture)
            #expect(blocks.count == 2)
            #expect(
                blocks.first?.left == SequenceNumber(guestISS + 3001),
                "the block reported first was not the one that triggered this ACK")
            #expect(blocks.last?.left == SequenceNumber(guestISS + 1001))
        }
    }
    fixture.drain()
}

@Test func theBlockCountIsWhateverTheOptionsAreaHasRoomFor() throws {
    // Four blocks alone; three beside a timestamp. RFC 2018 §3's "four" is the
    // figure for an empty options area, and a constant would have been silently
    // wrong from the moment timestamps were negotiated — wrong in the worst
    // way, by overflowing the 40-byte area into a header the peer cannot parse.
    for (timestamps, expected) in [(false, 4), (true, 3)] {
        let fixture = TCPFixture()
        do {
            let endpoint = try listeningEndpoint(fixture)
            withExtendedLifetime(endpoint) {
                sackHandshake(fixture, timestamps: timestamps)
                // Five separate runs offered; only as many as fit are reported.
                for run in 0..<5 {
                    fixture.inject(
                        guestSegment(
                            sequence: guestISS + 1001 + UInt32(run) * 1000, ack: gatewayISS + 1,
                            flags: [.ack], options: timestamps ? [.timestamps(value: 2, echo: 0)] : []),
                        payload: tcpPayload(500))
                }
                // Every frame, not the last one, and the count of frames that
                // FAILED to parse alongside them.
                //
                // The first draft asked `drainSegments().last` for its block
                // count and could not fail. Overflowing the options area makes
                // the header's four-bit data offset wrap, so the very segments
                // the bug produces stop being parseable — and `drainSegments`
                // drops what it cannot parse. Under the mutation the oversized
                // ACKs vanished, `.last` returned an earlier, smaller one, and
                // the assertion read exactly as it does when the code is right.
                // A test whose evidence is destroyed by the failure it looks
                // for is not a test.
                let frames = parsedFrames(fixture)
                #expect(frames.unparsed == 0, "a segment went out that cannot be parsed back")
                let widest =
                    frames.headers.map { header in
                        header.options.compactMap { option -> Int? in
                            if case .selectiveAcknowledgement(let blocks) = option { return blocks.count }
                            return nil
                        }.first ?? 0
                    }.max() ?? 0
                #expect(widest == expected, "timestamps: \(timestamps)")
                for header in frames.headers {
                    #expect(
                        TCPOptionCodec.encode(header.options).count <= TCPOptionCodec.maximumOptionsBytes,
                        "options overflowed the area the data offset can address")
                }
            }
        }
        fixture.drain()
    }
}

// The three tests below exist because the differential found what the ones
// above did not. Enabling `sackOK` in the generator and running against gVisor
// broke immediately, in ways no unit test here reached; the constraint is back
// in place until RFC 6675 lands, so these are what carries the findings.

@Test func aDataSegmentCarryingSackBlocksStillFitsTheSegmentSize() throws {
    // Options come out of the payload (RFC 6691), and SACK is an option that
    // appears *after* a segment has been cut. Without a payload budget that
    // knows about it, a full-sized segment plus a timestamp plus blocks
    // overflows the 40-byte options area, the header's four-bit data offset
    // wraps, and the frame goes on the wire unparseable by anyone.
    let fixture = TCPFixture()
    do {
        let endpoint = try listeningEndpoint(fixture)
        try withExtendedLifetime(endpoint) {
            sackHandshake(fixture, timestamps: true)
            // Three separate runs held, which is the most that fits beside a
            // timestamp — the worst case the budget has to survive.
            for run in 0..<3 {
                fixture.inject(
                    guestSegment(
                        sequence: guestISS + 1001 + UInt32(run) * 2000, ack: gatewayISS + 1, flags: [.ack],
                        options: [.timestamps(value: 2, echo: 0)]),
                    payload: tcpPayload(500))
            }
            _ = fixture.drainSegments()

            try endpoint.send(tcpPayload(8000))
            let frames = parsedFrames(fixture)
            #expect(frames.unparsed == 0, "a data segment went out that cannot be parsed back")
            let data = frames.headers.filter {
                $0.options.contains { option in
                    if case .selectiveAcknowledgement = option { return true } else { return false }
                }
            }
            #expect(!data.isEmpty, "no segment carried blocks: the budget was never tested")
            for header in data {
                #expect(TCPOptionCodec.encode(header.options).count <= TCPOptionCodec.maximumOptionsBytes)
            }
        }
    }
    fixture.drain()
}

@Test func aRetransmissionCarryingMoreBlocksThanTheOriginalStillFits() throws {
    // The half a per-segment budget cannot fix, and the reason the budget is the
    // connection's worst case rather than the options present when the segment
    // was cut.
    //
    // A segment is cut once and retransmitted much later. If it was cut while
    // nothing was held out of order and is retransmitted while three runs are,
    // the header grows by twenty-eight bytes over a payload that was sized
    // without them. Nothing in the sender remembers what the header cost the
    // first time, and nothing should.
    let fixture = TCPFixture()
    do {
        let endpoint = try listeningEndpoint(fixture)
        try withExtendedLifetime(endpoint) {
            sackHandshake(fixture, timestamps: true)
            _ = fixture.drainSegments()

            // Cut while nothing is held.
            try endpoint.send(tcpPayload(4000))
            let firstPass = parsedFrames(fixture)
            #expect(firstPass.unparsed == 0)
            #expect(!firstPass.headers.isEmpty)

            // Now hold three runs, and let the retransmission timer fire.
            for run in 0..<3 {
                fixture.inject(
                    guestSegment(
                        sequence: guestISS + 1001 + UInt32(run) * 2000, ack: gatewayISS + 1, flags: [.ack],
                        options: [.timestamps(value: 2, echo: 0)]),
                    payload: tcpPayload(500))
            }
            _ = fixture.drainSegments()
            fixture.advance(by: .seconds(2))

            let retransmitted = parsedFrames(fixture)
            #expect(retransmitted.unparsed == 0, "the retransmission overflowed its options area")
            let withData = retransmitted.headers.filter { header in
                header.options.contains { option in
                    if case .selectiveAcknowledgement = option { return true } else { return false }
                }
            }
            #expect(!withData.isEmpty, "nothing was retransmitted: the timer never fired")
            for header in withData {
                #expect(TCPOptionCodec.encode(header.options).count <= TCPOptionCodec.maximumOptionsBytes)
            }
        }
    }
    fixture.drain()
}

@Test func theSecondMostRecentRunKeepsItsPlaceWhenAThirdArrives() throws {
    // RFC 2018 §4's SHOULD, and the one the first version skipped. gVisor keeps
    // its previous ordering and prepends the new run; a receiver that re-sorts
    // ascending disagrees from the second out-of-order arrival onward.
    //
    // It is not cosmetic when more runs exist than fit: the block dropped by the
    // limit is chosen by this order, so sorting ascending drops the *highest*
    // run rather than the stalest one.
    let fixture = TCPFixture()
    do {
        let endpoint = try listeningEndpoint(fixture)
        withExtendedLifetime(endpoint) {
            sackHandshake(fixture)
            // 3001, then 5001, then 1001 — chosen so recency order and sequence
            // order differ in the TAIL, not just at the head. The first draft
            // used 5001, 3001, 1001, where descending arrival makes the recency
            // order identical to ascending sequence order: it passed with the
            // ranking removed entirely, which is how the flaw was found.
            for start in [UInt32(3001), UInt32(5001), UInt32(1001)] {
                fixture.inject(
                    guestSegment(sequence: guestISS + start, ack: gatewayISS + 1, flags: [.ack]),
                    payload: tcpPayload(500))
            }
            let blocks = lastSackBlocks(fixture)
            #expect(blocks.count == 3)
            #expect(
                blocks.map(\.left) == [
                    SequenceNumber(guestISS + 1001), SequenceNumber(guestISS + 5001),
                    SequenceNumber(guestISS + 3001),
                ], "the report is not in the order the runs were touched")
        }
    }
    fixture.drain()
}

@Test func theSackOptionsSequenceNumbersLandOnAFourByteBoundary() throws {
    // Why the alignment is there. The option carries 32-bit sequence numbers
    // behind a two-byte kind and length, so its edges land on a word boundary
    // only when the option starts two bytes short of one. RFC 2018 §3 lays it
    // out this way and every real stack emits it so.
    //
    // Written after the alignment survived its own falsification — removing it
    // failed no test, because nothing else here looks at the layout rather than
    // at the decoded values — and it immediately failed against the code as
    // written. The implementation emitted the customary literal `NOP NOP`, which
    // is only correct from an already-aligned position: beside a ten-byte
    // timestamp it put the edges at byte 14. Checking BOTH cases is the point,
    // since the alone case was right and the combined case was not.
    let block = SACKBlock(left: SequenceNumber(1000), right: SequenceNumber(1500))
    for others in [[], [TCPOption.timestamps(value: 1, echo: 2)]] {
        let encoded = TCPOptionCodec.encode(others + [.selectiveAcknowledgement([block])])
        // The kind byte is found by walking the options rather than searching
        // for the value 5, which could appear inside a timestamp or a sequence
        // number and would make this test read its own arithmetic back.
        var index = 0
        var kind: Int?
        while index < encoded.count {
            if encoded[index] == 1 {
                index += 1
                continue
            }
            if encoded[index] == 5 {
                kind = index
                break
            }
            index += Int(encoded[index + 1])
        }
        let start = try #require(kind, "no SACK option in \(encoded)")
        #expect(
            (start + 2) % 4 == 0,
            "the edges start at byte \(start + 2) of \(encoded), which is not a word boundary")
        #expect(encoded.count <= TCPOptionCodec.maximumOptionsBytes)
    }
}
