import Foundation
import NIOCore
import NIOEmbedded
import Testing

@testable import Netstack

// Replays `Vectors/tcp-handshake.vec` against a real `Stack`.
//
// The vector file is the specification and this file is only the machinery
// that runs it: nothing here restates what a line in the `.vec` says, and no
// assertion below is allowed to be looser than the line it accompanies. The
// extra `#expect`s that do appear are all of one kind — checks that the vector
// was actually CAPABLE of failing, which is the failure mode this plan has
// produced more than once.

// MARK: - Fixture

private let handshakeGateway = IPv4Address("192.168.127.1")!
private let handshakeGuest = IPv4Address("192.168.127.2")!
private let handshakeGatewayMAC = MACAddress("5a:94:ef:e4:0c:ee")!
private let handshakeGuestMAC = MACAddress("0a:0b:0c:0d:0e:0f")!

/// `VectorFrames` pins every TCP line's ports at 50000 -> 8080 (its own doc
/// comment says why: a packetdrill-style script describes one connection whose
/// port pair is never under test). The listener therefore has to be on 8080,
/// or the vectors would be describing a connection to somewhere else.
private let handshakeLocalPort: UInt16 = 8080

/// The ISS the FIRST connection built in a scenario gets, and the distance to
/// the next one. See `SteppingInitialSequenceNumbers`.
private let handshakeBaseISS: UInt32 = 1000
private let handshakeISSStep: UInt32 = 1_000_000

/// An ISS generator that answers a **different** number on every call.
///
/// This is the whole reason the retransmitted-SYN vectors can fail. Injecting
/// `FixedInitialSequenceNumbers` would make "the second SYN-ACK carries 1000"
/// true of a stack that reuses the connection's block AND of one that
/// regenerates the ISS from scratch for every SYN — the constant comes back
/// either way, and the vector would pin nothing. Stepping by a million per
/// call means the second SYN-ACK can only read 1000 if the number was taken
/// from the block the first SYN created.
///
/// It models the real hazard rather than inventing one: `RFC6528SequenceNumbers`
/// is deterministic in the four-tuple but adds RFC 6528's `M` term, a
/// 4-microsecond timer, so two calls for the same four-tuple at two different
/// times genuinely do disagree. A stack that answered a retransmitted SYN from
/// a fresh block would break a real guest, not just this test.
///
/// `@unchecked Sendable` for the call counter: everything here is confined to
/// one `EmbeddedEventLoop`, and the package's no-locks rule is about
/// `Sources/Netstack`.
private final class SteppingInitialSequenceNumbers: InitialSequenceNumbers, @unchecked Sendable {
    private(set) var calls = 0

    func initialSendSequence(
        localAddress: IPv4Address, localPort: UInt16, remoteAddress: IPv4Address, remotePort: UInt16
    ) -> SequenceNumber {
        let value = handshakeBaseISS &+ UInt32(truncatingIfNeeded: calls) &* handshakeISSStep
        calls += 1
        return SequenceNumber(value)
    }
}

/// Whether the scenario's stack has a listener on `handshakeLocalPort`.
///
/// Both settings are exercised, and they reach two different implementations of
/// RFC 9293 §3.10.7.1's refusal: `.none` reaches `Stack`'s own TCP handler (the
/// `closed-port` scenario), `.listening` reaches `TCPEndpoint.respondAsClosed`
/// (the `stray-ack` scenario).
private enum HandshakeListener {
    case listening
    case none
}

private struct HandshakeHarness {
    let loop: EmbeddedEventLoop
    let clock: ManualClock
    let link: RecordingEndpoint
    let stack: Stack
    let endpoint: TCPEndpoint?
    let sequenceNumbers: SteppingInitialSequenceNumbers
}

private func handshakeHarness(_ listener: HandshakeListener) throws -> HandshakeHarness {
    let loop = EmbeddedEventLoop()
    let clock = ManualClock(start: .uptimeNanoseconds(0))
    let link = RecordingEndpoint(eventLoop: loop, linkAddress: handshakeGatewayMAC)
    let stack = Stack(
        link: link,
        configuration: Stack.Configuration(
            gatewayAddress: handshakeGateway,
            subnet: IPv4Subnet(cidr: "192.168.127.0/24")!),
        clock: clock)
    stack.start()
    // Without this, `IPv4Protocol.send` throws `.noRoute` and emits an ARP
    // REQUEST where the vector expects a segment — the first expected line of
    // every scenario would fail against an ARP frame, for reasons that have
    // nothing to do with TCP.
    stack.arpCache.record(handshakeGuest, handshakeGuestMAC)

    let sequenceNumbers = SteppingInitialSequenceNumbers()
    var endpoint: TCPEndpoint?
    if case .listening = listener {
        // The internal ISS seam. The public `init(stack:)` would take the
        // stack's RFC 6528 generator, whose numbers no absolute vector can
        // state.
        let listening = TCPEndpoint(stack: stack, initialSequenceNumbers: sequenceNumbers)
        try listening.bind(address: handshakeGateway, port: handshakeLocalPort)
        try listening.listen(backlog: 8)
        endpoint = listening
    }

    return HandshakeHarness(
        loop: loop, clock: clock, link: link, stack: stack, endpoint: endpoint, sequenceNumbers: sequenceNumbers)
}

private func handshakeCodec() -> VectorFrames {
    VectorFrames(
        gateway: handshakeGateway, gatewayMAC: handshakeGatewayMAC,
        guest: handshakeGuest, guestMAC: handshakeGuestMAC)
}

// MARK: - Reading one scenario out of the file

private let handshakeScenarioMarker = "# scenario: "

private func handshakeVectorText() throws -> String {
    let url = try #require(Bundle.module.url(forResource: "Vectors/tcp-handshake", withExtension: "vec"))
    return try String(contentsOf: url, encoding: .utf8)
}

private func handshakeVectorLines() throws -> [String] {
    try handshakeVectorText().split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
}

private func handshakeScenarioNames() throws -> [String] {
    try handshakeVectorLines().compactMap { line in
        let trimmed = line.trimmingCharacters(in: .whitespaces)
        guard trimmed.hasPrefix(handshakeScenarioMarker) else { return nil }
        return String(trimmed.dropFirst(handshakeScenarioMarker.count))
    }
}

/// One scenario's text, with every line belonging to another scenario replaced
/// by an EMPTY line rather than removed.
///
/// The blanking is the point. `VectorScript` counts source lines including
/// comments and blanks precisely so `VectorMismatch` can name the line a reader
/// sees in an editor; deleting other scenarios' lines instead would renumber
/// every diagnostic in the file and make that promise false.
private func handshakeScenarioText(_ name: String) throws -> String {
    var current: String?
    var kept: [String] = []
    for line in try handshakeVectorLines() {
        let trimmed = line.trimmingCharacters(in: .whitespaces)
        if trimmed.hasPrefix(handshakeScenarioMarker) {
            current = String(trimmed.dropFirst(handshakeScenarioMarker.count))
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
/// passes trivially — a test that appears to check a handshake while injecting
/// nothing at all.
@discardableResult
private func runHandshakeScenario(_ name: String, listener: HandshakeListener) throws -> HandshakeHarness {
    let script = try VectorScript.parse(try handshakeScenarioText(name))
    #expect(!script.events.isEmpty, "scenario '\(name)' selected no events — is the name spelled as the file spells it?")

    let harness = try handshakeHarness(listener)
    let runner = VectorRunner(script: script, codec: handshakeCodec())
    try withExtendedLifetime(harness.endpoint) {
        try runner.run(against: harness.stack, link: harness.link, clock: harness.clock, loop: harness.loop)
    }
    return harness
}

// MARK: - The scenarios

/// The `.vec` file and this file must name the same set of scenarios.
///
/// Without this, a scenario added to the file and forgotten here would sit
/// unexecuted — present, reviewed, believed, and never once run. The list is
/// written out literally rather than derived from the file, so it can disagree.
@Test func everyScenarioInTheHandshakeVectorFileIsRunByATestInThisFile() throws {
    let run = [
        "passive-open", "closed-port", "stray-ack", "syn-retransmission",
        "ecn-setup-syn", "syn-with-payload", "different-iss",
    ]
    #expect(try handshakeScenarioNames() == run)
}

/// Every event in the file is claimed by some scenario.
///
/// The name check above cannot see this one. A vector line written ABOVE the
/// first `# scenario:` marker — or under a marker whose spelling drifted from
/// the one in the list — belongs to no scenario, is replayed by nothing, and
/// leaves no trace: it reads in review as a specification and is not one.
/// Blanking rather than deleting other scenarios' lines is what makes this
/// comparison possible at all, since it leaves every event at the source line
/// the whole-file parse gives it.
@Test func everyEventInTheHandshakeVectorFileBelongsToExactlyOneScenario() throws {
    let whole = try VectorScript.parse(try handshakeVectorText())
    var covered: [VectorEvent] = []
    for name in try handshakeScenarioNames() {
        covered += try VectorScript.parse(try handshakeScenarioText(name)).events
    }
    #expect(covered == whole.events)
    // Positive control: the file is not empty, so the equality above is not
    // `[] == []`.
    #expect(!whole.events.isEmpty)
}

@Test func aPassiveOpenCompletesTheThreeWayHandshakeOnTheWire() throws {
    let harness = try runHandshakeScenario("passive-open", listener: .listening)
    let endpoint = try #require(harness.endpoint)
    // The vector's own last line is a statement that the third leg draws
    // nothing back, which is equally true of a stack that ignored it. This is
    // the positive control: the connection really did reach ESTABLISHED and is
    // still there.
    #expect(endpoint.connectionCountForTesting == 1)
}

@Test func aSynForAPortWithNoListenerIsRefusedWithAnAckBearingReset() throws {
    try runHandshakeScenario("closed-port", listener: .none)
}

@Test func aStrayAckWithNoConnectionIsRefusedWithAnAckLessReset() throws {
    let harness = try runHandshakeScenario("stray-ack", listener: .listening)
    let endpoint = try #require(harness.endpoint)
    // Refusing the segment must not also have built a block for it. A
    // half-open connection created by any unauthenticated ACK is a free
    // allocation for anyone who can reach the port.
    #expect(endpoint.connectionCountForTesting == 0)
    // And it must not have consumed an ISS: reaching the generator at all
    // would mean a block was constructed and then discarded.
    #expect(harness.sequenceNumbers.calls == 0)
}

@Test func aRetransmittedSynResendsTheSameSynAckFromTheSameBlock() throws {
    let harness = try runHandshakeScenario("syn-retransmission", listener: .listening)
    let endpoint = try #require(harness.endpoint)
    // Two independent statements of the same property, because the vector
    // alone cannot make both:
    //
    // 1. The generator was called ONCE. A stack that regenerated the ISS would
    //    have called it twice — and, because the generator steps by a million,
    //    would have failed the vector's second SYN-ACK line as well. This says
    //    directly what that line says by construction.
    // 2. There is still exactly ONE connection. The second SYN did not open a
    //    second one.
    #expect(harness.sequenceNumbers.calls == 1)
    #expect(endpoint.connectionCountForTesting == 1)
}

@Test func anEcnSetupSynIsHandledExactlyLikeAPlainSyn() throws {
    let harness = try runHandshakeScenario("ecn-setup-syn", listener: .listening)
    let endpoint = try #require(harness.endpoint)
    #expect(endpoint.connectionCountForTesting == 1)
}

@Test func aSynCarryingDataAcknowledgesTheSynAloneAndNotTheData() throws {
    let harness = try runHandshakeScenario("syn-with-payload", listener: .listening)
    let endpoint = try #require(harness.endpoint)
    #expect(endpoint.connectionCountForTesting == 1)
}

@Test func aSecondSynWithADifferentInitialSequenceNumberIsChallengedNotAdopted() throws {
    let harness = try runHandshakeScenario("different-iss", listener: .listening)
    let endpoint = try #require(harness.endpoint)
    // Same pair as the retransmission case, and for the same reason: the
    // challenge ACK's `1001` is only evidence of a reused block if no second
    // ISS was ever drawn.
    #expect(harness.sequenceNumbers.calls == 1)
    #expect(endpoint.connectionCountForTesting == 1)
}
