import Foundation
import NIOCore
import NIOEmbedded
import Testing

@testable import Netstack

// Replays `Vectors/tcp-data.vec` and `Vectors/tcp-close.vec` against a real
// `Stack`.
//
// The vector files are the specification and this file is only the machinery
// that runs them: nothing here restates what a line in a `.vec` says, and no
// assertion below is allowed to be looser than the line it accompanies. The
// extra `#expect`s that do appear are all of two kinds — checks that a vector
// was actually CAPABLE of failing, and checks on the one thing a wire vector
// structurally cannot see: which bytes reached the application. Several
// scenarios here (`fin-ahead-of-rcv-nxt`, `data-past-the-fin`,
// `right-edge-trim`) exist precisely because the wire and the application can
// disagree, so that second kind is not decoration.

// MARK: - Fixture

private let transferGateway = IPv4Address("192.168.127.1")!
private let transferGuest = IPv4Address("192.168.127.2")!
private let transferGatewayMAC = MACAddress("5a:94:ef:e4:0c:ee")!
private let transferGuestMAC = MACAddress("0a:0b:0c:0d:0e:0f")!

/// `VectorFrames` pins every TCP line's ports at 50000 -> 8080, so the listener
/// has to be on 8080 or the vectors would describe a connection to somewhere
/// else. Same reason as `TCPHandshakeVectorTests`.
private let transferLocalPort: UInt16 = 8080

private let transferBaseISS: UInt32 = 1000
private let transferISSStep: UInt32 = 1_000_000

/// An ISS generator that answers a **different** number on every call.
///
/// Every scenario in these two files opens exactly one connection, and every
/// expected line is written against ISS 1000. A constant generator would make
/// those lines true of a stack that built a second connection block half way
/// through a scenario — the second block would draw the same constant. Stepping
/// by a million per call means `1000` on the wire is a statement that ONE block
/// was created, which is what `transferHarness`'s `sequenceNumbers.calls == 1`
/// check below then says directly.
///
/// `@unchecked Sendable` for the call counter: everything here is confined to
/// one `EmbeddedEventLoop`, and the package's no-locks rule is about
/// `Sources/Netstack`.
private final class TransferSequenceNumbers: InitialSequenceNumbers, @unchecked Sendable {
    private(set) var calls = 0

    func initialSendSequence(
        localAddress: IPv4Address, localPort: UInt16, remoteAddress: IPv4Address, remotePort: UInt16
    ) -> SequenceNumber {
        let value = transferBaseISS &+ UInt32(truncatingIfNeeded: calls) &* transferISSStep
        calls += 1
        return SequenceNumber(value)
    }
}

/// One delivery to the application: how many bytes, and the logical time they
/// arrived at.
///
/// The time is what makes "nothing was delivered until the gap filled" an
/// assertion rather than a hope. A total-bytes check alone passes equally on a
/// stack that delivered out-of-order data immediately, which is the defect
/// `out-of-order-data` exists to catch on the application side.
private struct TransferDelivery {
    var bytes: Int
    var at: NIODeadline
}

/// `@unchecked Sendable` for the same reason as the generator above: one loop,
/// no threads, and this lives in the test target.
private final class TransferApplicationState: @unchecked Sendable {
    var deliveries: [TransferDelivery] = []
    var closedReports = 0

    var deliveredBytes: Int { deliveries.reduce(0) { $0 + $1.bytes } }
}

private struct TransferHarness {
    let loop: EmbeddedEventLoop
    let clock: ManualClock
    let link: RecordingEndpoint
    let stack: Stack
    let endpoint: TCPEndpoint
    let sequenceNumbers: TransferSequenceNumbers
    let application: TransferApplicationState
}

private func transferHarness() throws -> TransferHarness {
    let loop = EmbeddedEventLoop()
    let clock = ManualClock(start: .uptimeNanoseconds(0))
    let link = RecordingEndpoint(eventLoop: loop, linkAddress: transferGatewayMAC)
    let stack = Stack(
        link: link,
        configuration: Stack.Configuration(
            gatewayAddress: transferGateway,
            subnet: IPv4Subnet(cidr: "192.168.127.0/24")!),
        clock: clock)
    stack.start()
    // Without this, the first frame out would be an ARP request rather than the
    // SYN-ACK the vector expects, for reasons that have nothing to do with TCP.
    // Every later inbound packet re-records it (`IPv4Protocol.handleInbound`),
    // which is what keeps the three sixty-second scenarios in `tcp-close.vec`
    // safe; see that file's header.
    stack.arpCache.record(transferGuest, transferGuestMAC)

    let sequenceNumbers = TransferSequenceNumbers()
    // The internal ISS seam. The public `init(stack:)` would take the stack's
    // RFC 6528 generator, whose numbers no absolute vector can state.
    let endpoint = TCPEndpoint(stack: stack, initialSequenceNumbers: sequenceNumbers)
    try endpoint.bind(address: transferGateway, port: transferLocalPort)
    try endpoint.listen(backlog: 8)

    let application = TransferApplicationState()
    endpoint.onData = { buffer in
        application.deliveries.append(TransferDelivery(bytes: buffer.readableBytes, at: clock.now()))
    }
    endpoint.onClosed = { application.closedReports += 1 }

    return TransferHarness(
        loop: loop, clock: clock, link: link, stack: stack, endpoint: endpoint,
        sequenceNumbers: sequenceNumbers, application: application)
}

private func transferCodec() -> VectorFrames {
    VectorFrames(
        gateway: transferGateway, gatewayMAC: transferGatewayMAC,
        guest: transferGuest, guestMAC: transferGuestMAC)
}

// MARK: - Reading one scenario out of a file

private let transferScenarioMarker = "# scenario: "

private func transferVectorText(_ resource: String) throws -> String {
    let url = try #require(Bundle.module.url(forResource: "Vectors/\(resource)", withExtension: "vec"))
    return try String(contentsOf: url, encoding: .utf8)
}

private func transferVectorLines(_ resource: String) throws -> [String] {
    try transferVectorText(resource).split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
}

private func transferScenarioNames(_ resource: String) throws -> [String] {
    try transferVectorLines(resource).compactMap { line in
        let trimmed = line.trimmingCharacters(in: .whitespaces)
        guard trimmed.hasPrefix(transferScenarioMarker) else { return nil }
        return String(trimmed.dropFirst(transferScenarioMarker.count))
    }
}

/// One scenario's text, with every line belonging to another scenario replaced
/// by an EMPTY line rather than removed.
///
/// The blanking is `TCPHandshakeVectorTests`' convention and the reason is the
/// same: `VectorScript` counts source lines including comments and blanks so
/// that `VectorMismatch` can name the line a reader sees in an editor, and
/// deleting other scenarios' lines would renumber every diagnostic in the file.
private func transferScenarioText(_ resource: String, _ name: String) throws -> String {
    var current: String?
    var kept: [String] = []
    for line in try transferVectorLines(resource) {
        let trimmed = line.trimmingCharacters(in: .whitespaces)
        if trimmed.hasPrefix(transferScenarioMarker) {
            current = String(trimmed.dropFirst(transferScenarioMarker.count))
        }
        kept.append(current == name ? line : "")
    }
    return kept.joined(separator: "\n")
}

/// Play one scenario and hand back the harness for whatever else the caller
/// wants to check.
///
/// The `events.isEmpty` guard is not a formality: a misspelled scenario name
/// would otherwise select nothing, and `VectorRunner.run` on an empty script
/// passes trivially — a test that appears to check a data transfer while
/// injecting nothing at all.
@discardableResult
private func runTransferScenario(_ resource: String, _ name: String) throws -> TransferHarness {
    let script = try VectorScript.parse(try transferScenarioText(resource, name))
    #expect(!script.events.isEmpty, "scenario '\(name)' selected no events — is the name spelled as the file spells it?")

    let harness = try transferHarness()
    let endpoint = harness.endpoint
    let allocator = ByteBufferAllocator()
    // What a `write <n>` and a `close` line in the `.vec` actually do. Both
    // throw rather than swallow: a refused write is a divergence, and a script
    // that quietly wrote nothing would fail two lines later on the missing
    // frame, naming the wrong line.
    let application = VectorApplication(
        write: { bytes in
            var payload = allocator.buffer(capacity: bytes)
            payload.writeRepeatingByte(0, count: bytes)
            try endpoint.send(payload)
        },
        close: { endpoint.close() })

    let runner = VectorRunner(script: script, codec: transferCodec())
    try withExtendedLifetime(endpoint) {
        try runner.run(
            against: harness.stack, link: harness.link, clock: harness.clock, loop: harness.loop,
            application: application)
    }
    // Every scenario in both files opens exactly one connection. Stated here,
    // once, rather than in fourteen tests: with `TransferSequenceNumbers`
    // stepping by a million, a second block would also have failed the vector's
    // sequence numbers, and this says the same thing directly.
    #expect(harness.sequenceNumbers.calls == 1)
    return harness
}

private let dataVectors = "tcp-data"
private let closeVectors = "tcp-close"

// MARK: - The file is fully executed

/// The `.vec` file and this file must name the same set of scenarios.
///
/// Without this, a scenario added to the file and forgotten here would sit
/// unexecuted — present, reviewed, believed, and never once run. The list is
/// written out literally rather than derived from the file, so it can disagree.
@Test func everyScenarioInTheDataVectorFileIsRunByATestInThisFile() throws {
    let run = [
        "in-order-data", "out-of-order-data", "retransmission-after-rto",
        "zero-window", "sequence-wrap", "rtt-sample-drives-the-rto",
        "push-on-the-last-segment-of-a-write", "write-under-a-small-window",
        "a-retransmission-keeps-the-push-bit",
        "window-updates-are-not-duplicate-acknowledgements",
        "three-identical-duplicate-acknowledgements-still-fast-retransmit",
        "a-timeout-keeps-retransmitting",
        "the-handshake-seeds-the-retransmission-timeout",
        "a-handshake-sample-makes-the-first-data-sample-a-subsequent-one",
        "an-ambiguous-handshake-is-not-sampled",
        "a-lost-window-update-is-recovered-by-a-zero-window-probe",
        "zero-window-probes-back-off-and-do-not-give-up",
    ]
    #expect(try transferScenarioNames(dataVectors) == run)
}

@Test func everyScenarioInTheCloseVectorFileIsRunByATestInThisFile() throws {
    let run = [
        "four-way-close", "simultaneous-close", "peer-fin-in-established",
        "time-wait-expiry", "fin-retransmission-restarts-time-wait",
        "bare-ack-does-not-restart-time-wait", "fin-ahead-of-rcv-nxt",
        "right-edge-trim", "data-past-the-fin",
        "a-reset-does-not-assassinate-time-wait",
    ]
    #expect(try transferScenarioNames(closeVectors) == run)
}

/// Every event in each file is claimed by some scenario.
///
/// The name check above cannot see this one. A vector line written ABOVE the
/// first `# scenario:` marker — or under a marker whose spelling drifted — is
/// replayed by nothing and leaves no trace: it reads in review as a
/// specification and is not one. Blanking rather than deleting other scenarios'
/// lines is what makes this comparison possible, since it leaves every event at
/// the source line the whole-file parse gives it.
@Test func everyEventInTheDataAndCloseVectorFilesBelongsToExactlyOneScenario() throws {
    for resource in [dataVectors, closeVectors] {
        let whole = try VectorScript.parse(try transferVectorText(resource))
        var covered: [VectorEvent] = []
        for name in try transferScenarioNames(resource) {
            covered += try VectorScript.parse(try transferScenarioText(resource, name)).events
        }
        #expect(covered == whole.events, "\(resource).vec has events outside every scenario")
        // Positive control: the file is not empty, so the equality above is not
        // `[] == []`.
        #expect(!whole.events.isEmpty)
    }
}

/// A script that makes an application call and is run without an application
/// must fail loudly.
///
/// The alternative is worse than it looks. Skipping the call silently would
/// leave the scenario failing on the frame the write was supposed to produce —
/// a `VectorMismatch` naming a correct line, about a correct stack, because a
/// harness forgot an argument.
@Test func aScriptWithAnApplicationCallRefusesToRunWithoutAnApplication() throws {
    let script = try VectorScript.parse("0.000 < write 100")
    let harness = try transferHarness()
    let runner = VectorRunner(script: script, codec: transferCodec())
    let endpoint = harness.endpoint
    #expect(throws: VectorScriptNeedsAnApplication.self) {
        try runner.run(against: harness.stack, link: harness.link, clock: harness.clock, loop: harness.loop)
    }
    // Keeps the endpoint registered for the duration, the way
    // `runTransferScenario`'s `withExtendedLifetime` does — spelled as a use
    // rather than as a wrapper, because the wrapper's result is discarded here
    // and `#expect` swallows the throw that would otherwise consume it.
    #expect(endpoint.connectionCountForTesting == 0)
}

// MARK: - tcp-data.vec

@Test func inOrderDataIsAcknowledgedOnceForBothSegments() throws {
    let harness = try runTransferScenario(dataVectors, "in-order-data")
    // Two segments in, two deliveries out, and nothing merged or lost. The wire
    // lines pin the acknowledgements; this pins that the bytes reached the
    // application at all, which no `>` line can say.
    #expect(harness.application.deliveries.map(\.bytes) == [100, 100])
}

@Test func outOfOrderDataDrawsADuplicateAckAndIsDeliveredWhenTheGapFills() throws {
    let harness = try runTransferScenario(dataVectors, "out-of-order-data")
    #expect(harness.application.deliveredBytes == 200)
    // NOTHING was delivered by the out-of-order segment at 0.020. A stack that
    // handed the application bytes it had not yet acknowledged would satisfy
    // both wire lines and fail here — the vector's `ack 1` says RCV.NXT did not
    // move, and this says the data did not move either.
    #expect(harness.application.deliveries.allSatisfy { $0.at == .uptimeNanoseconds(30_000_000) })
}

@Test func anUnacknowledgedSegmentIsRetransmittedIdenticallyWhenTheRtoExpires() throws {
    let harness = try runTransferScenario(dataVectors, "retransmission-after-rto")
    // The connection survived the loss episode rather than being given up.
    #expect(harness.endpoint.connectionCountForTesting == 1)
}

@Test func aZeroWindowStopsTransmissionUntilAWindowUpdateReopensIt() throws {
    let harness = try runTransferScenario(dataVectors, "zero-window")
    #expect(harness.endpoint.connectionCountForTesting == 1)
}

@Test func sequenceNumbersThatWrapAreComparedSeriallyAndNotAsIntegers() throws {
    let harness = try runTransferScenario(dataVectors, "sequence-wrap")
    // Ninety-five bytes up to the wrap, then the fifty that were queued past
    // it, released by the same segment — 145 bytes in one delivery pass. Under
    // integer order the queued fifty were never admitted at all, so this reads
    // `[95]`, which is the half the wire line cannot show as sharply.
    #expect(harness.application.deliveries.map(\.bytes) == [95, 50])
}

@Test func anRttSampleAboveTheFloorSetsTheRtoTheRetransmissionIsThenTimedBy() throws {
    let harness = try runTransferScenario(dataVectors, "rtt-sample-drives-the-rto")
    #expect(harness.endpoint.connectionCountForTesting == 1)
}

// The three PSH scenarios below were written from a divergence the Task 17
// differential found, not from a reading of this stack's code — see the
// comments above each one in `tcp-data.vec`.

@Test func onlyTheSegmentThatEmptiesAWriteCarriesPush() throws {
    let harness = try runTransferScenario(dataVectors, "push-on-the-last-segment-of-a-write")
    #expect(harness.endpoint.connectionCountForTesting == 1)
}

@Test func aWriteSplitByThePeersWindowPushesOnEveryPiece() throws {
    let harness = try runTransferScenario(dataVectors, "write-under-a-small-window")
    #expect(harness.endpoint.connectionCountForTesting == 1)
}

@Test func aRetransmissionReproducesThePushBitOfTheSegmentItLost() throws {
    let harness = try runTransferScenario(dataVectors, "a-retransmission-keeps-the-push-bit")
    #expect(harness.endpoint.connectionCountForTesting == 1)
}

@Test func aResetArrivingInTimeWaitIsIgnored() throws {
    let harness = try runTransferScenario(closeVectors, "a-reset-does-not-assassinate-time-wait")
    // The block outlived the reset AND then really did expire: a stack that
    // ignored everything forever would satisfy the wire lines up to 61.000 and
    // fail here.
    #expect(harness.endpoint.connectionCountForTesting == 0)
}

@Test func windowUpdatesRepeatingTheAcknowledgementNumberDoNotFastRetransmit() throws {
    let harness = try runTransferScenario(dataVectors, "window-updates-are-not-duplicate-acknowledgements")
    // Nothing was lost, so nothing was declared lost: the congestion window is
    // still where slow start left it. Without this the scenario would also
    // pass on a stack that halved cwnd and then failed to act on it.
    #expect(harness.endpoint.congestionWindowForTesting == 10 * 1460)
}

@Test func threeDuplicateAcknowledgementsWithAnUnchangedWindowStillFastRetransmit() throws {
    let harness = try runTransferScenario(dataVectors, "three-identical-duplicate-acknowledgements-still-fast-retransmit")
    #expect(harness.endpoint.connectionCountForTesting == 1)
}

@Test func aTimeoutRecoversTheWholeBurstOnOneExpiryWithoutInflatingTheWindow() throws {
    let harness = try runTransferScenario(dataVectors, "a-timeout-keeps-retransmitting")
    #expect(harness.endpoint.connectionCountForTesting == 1)
    // The window the connection LEAVES the episode holding, which no `>` line
    // can say and which is the half of this change most easily got wrong. The
    // timeout collapsed cwnd to one segment and set ssthresh to
    // max(7300 / 2, 2 * 1460) = 3650; the five acknowledgements then grew it
    // and nothing else did. 1460 -> 2920 -> 4380 in slow start, then RFC 5681
    // 3.1's congestion-avoidance form SMSS * SMSS / cwnd three times:
    // 2131600 / 4380 = 486, 2131600 / 4866 = 438, 2131600 / 5304 = 401.
    //
    // Every byte of that was paid for by an acknowledgement. A stack that
    // called `timeout(flightSize:)` again per retransmission would be at 1460
    // here, and one that grew cwnd per retransmitted segment would be far above
    // 5705 -- and both would satisfy every line of the vector, because the
    // window is not on the wire.
    #expect(harness.endpoint.congestionWindowForTesting == 5705)
}

// The three handshake-RTT scenarios below. All three read the RTO off WHEN a
// retransmission appears rather than off `Sender.retransmissionTimeout`, which
// is the bar `rtt-sample-drives-the-rto` set: an estimator field can hold the
// right number while the timer that was armed from it holds the wrong one, and
// only the second of those is on the wire.

@Test func theHandshakeRoundTripSeedsTheEstimatorBeforeAnyDataIsSent() throws {
    let harness = try runTransferScenario(dataVectors, "the-handshake-seeds-the-retransmission-timeout")
    #expect(harness.endpoint.connectionCountForTesting == 1)
}

@Test func aSeededEstimatorGivesTheFirstDataSampleALowerRtoThanAnUnseededOne() throws {
    let harness = try runTransferScenario(
        dataVectors, "a-handshake-sample-makes-the-first-data-sample-a-subsequent-one")
    #expect(harness.endpoint.connectionCountForTesting == 1)
}

@Test func aHandshakeWhoseSynAckWentOutTwiceIsNotSampled() throws {
    let harness = try runTransferScenario(dataVectors, "an-ambiguous-handshake-is-not-sampled")
    // One connection, not two. The second SYN is a RETRANSMISSION of the first
    // and must be answered from the block that already exists -- a stack that
    // built a second block would draw a second ISS, and `runTransferScenario`
    // already checks `sequenceNumbers.calls == 1`. Stated again here because
    // this is the one scenario in the file that sends the same SYN twice, so it
    // is the only one where that check is doing real work rather than
    // restating something no line could violate.
    #expect(harness.endpoint.connectionCountForTesting == 1)
}

// The two zero-window-probe scenarios. Neither is covered by the differential
// harness and neither ever will be: the generator floors its offered window at
// `DiffLimits.minimumOfferedWindow` on purpose, so a green differential run says
// nothing whatever about persist. See `differential/README.md`.

@Test func aWindowUpdateLostInFlightIsRecoveredByAZeroWindowProbe() throws {
    let harness = try runTransferScenario(dataVectors, "a-lost-window-update-is-recovered-by-a-zero-window-probe")
    // The wire lines pin the probe and the recovery; this pins the half no `>`
    // line can state, which is that the connection was not merely noisy but
    // actually delivered. Without a persist timer nothing at all is emitted
    // after 0.020 and the scenario fails on the missing frame at 1.020.
    #expect(harness.endpoint.connectionCountForTesting == 1)
    #expect(harness.endpoint.hasPersistScheduledForTesting == false, "persist ended when the window reopened")
}

@Test func aReceiverThatStaysFullIsProbedRepeatedlyAndTheConnectionIsNotGivenUp() throws {
    let harness = try runTransferScenario(dataVectors, "zero-window-probes-back-off-and-do-not-give-up")
    // Still here after five unanswered probes: RFC 1122 §4.2.5's "Sender
    // timeout OK conn with zero wind" is a MUST NOT, so no ladder in this stack
    // may count this connection down. A stack with a give-up budget would have
    // removed the block and reported it closed.
    #expect(harness.endpoint.connectionCountForTesting == 1)
    #expect(harness.application.closedReports == 0)
}

// MARK: - tcp-close.vec

@Test func aLocallyInitiatedCloseCompletesTheFourWayHandshakeOnTheWire() throws {
    let harness = try runTransferScenario(closeVectors, "four-way-close")
    // The block is held, not deleted: this end sent the first FIN, so it owns
    // TIME-WAIT and the four-tuple that goes with it.
    #expect(harness.endpoint.connectionCountForTesting == 1)
    #expect(harness.endpoint.timeWaitCountForTesting == 1)
}

@Test func aSimultaneousCloseReachesTimeWaitThroughClosing() throws {
    let harness = try runTransferScenario(closeVectors, "simultaneous-close")
    #expect(harness.endpoint.timeWaitCountForTesting == 1)
}

@Test func aPeersFinInEstablishedIsAcknowledgedAndTheBlockGoesOnTheLastAck() throws {
    let harness = try runTransferScenario(closeVectors, "peer-fin-in-established")
    // No TIME-WAIT on the passive-close path: the peer sent the first FIN, so
    // the block is deleted outright on the final acknowledgement.
    #expect(harness.endpoint.connectionCountForTesting == 0)
    // "This stream is over" is reported once, even though the connection met
    // both the peer's FIN and its own deletion.
    #expect(harness.application.closedReports == 1)
}

@Test func aTimeWaitBlockLastsTwoMslAndIsThenGone() throws {
    let harness = try runTransferScenario(closeVectors, "time-wait-expiry")
    #expect(harness.endpoint.connectionCountForTesting == 0)
}

@Test func aRetransmittedFinRestartsTheTwoMslTimer() throws {
    let harness = try runTransferScenario(closeVectors, "fin-retransmission-restarts-time-wait")
    // Still there at 61 seconds, twenty-one past the original deadline.
    #expect(harness.endpoint.timeWaitCountForTesting == 1)
}

@Test func aBareAcknowledgementDoesNotRestartTheTwoMslTimer() throws {
    let harness = try runTransferScenario(closeVectors, "bare-ack-does-not-restart-time-wait")
    #expect(harness.endpoint.connectionCountForTesting == 0)
}

@Test func aFinAheadOfReceiveNextIsRefusedAndTheDataBehindItStillArrives() throws {
    let harness = try runTransferScenario(closeVectors, "fin-ahead-of-rcv-nxt")
    // The half the wire cannot show. Had the forged FIN at 51 been honoured,
    // the application would have received FIFTY bytes and a clean end of
    // stream, with the other fifty dropped and no error anywhere.
    #expect(harness.application.deliveredBytes == 100)
    // And the end of stream was reported once, by the REAL FIN at 0.040 — not
    // twice, and not at 0.020.
    #expect(harness.application.closedReports == 1)
}

@Test func aSegmentOverlappingTheRightWindowEdgeIsTrimmedRatherThanAcceptedWhole() throws {
    let harness = try runTransferScenario(closeVectors, "right-edge-trim")
    // Exactly the window, and not a byte more: 999 bytes to fill the gap plus
    // 64536 kept from the 65000-byte segment. An untrimmed queue delivers
    // 65999.
    #expect(harness.application.deliveredBytes == 65535)
}

@Test func dataQueuedPastAPeersFinIsDiscardedWhenTheFinLands() throws {
    let harness = try runTransferScenario(closeVectors, "data-past-the-fin")
    // Fifty bytes, not a hundred: the run queued at the FIN's own position is
    // dropped rather than delivered past it.
    #expect(harness.application.deliveredBytes == 50)
    // And the stream really did end, which is the half that wedges without the
    // discard — RCV.NXT would jump over the FIN's position and the equality
    // that reaches it would be false forever.
    #expect(harness.application.closedReports == 1)
    #expect(harness.endpoint.connectionCountForTesting == 1)
}
