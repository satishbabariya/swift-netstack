import Foundation
import NIOConcurrencyHelpers
import NIOCore
import NIOEmbedded
import NIOPosix
import Testing

@testable import Netstack

// ADR 0001's `clientHello`. Three layers, because each can be wrong in a way
// the others cannot see:
//
// - Through a whole `Gateway`, with the harness in `tls` mode as the guest:
//   gVisor's TCP carrying Go's crypto/tls client, whose hello is re-framed into
//   two records the way sandbox patch 0013's test does it, to a crypto/tls
//   server on loopback. What the server saw is the verdict. The Swift side
//   never writes a byte of the hello.
// - `ClientHelloInspector` on an embedded loop, for what the harness cannot
//   time: a hello that stalls until the deadline, and one the guest cuts short.
// - `ClientHelloReassembler` alone: re-framing, the bounds, and a fuzz test.

// MARK: Through a gateway, with a real client and server

/// Refuses the names it is given and allows everything else. Records every
/// hello it is asked about.
private final class ServerNames: EgressPolicy {
    let refused: Set<String>
    let inspectedTLSPorts: Set<UInt16>
    let asked = NIOLockedValueBox<[EgressClientHello]>([])

    init(refusing refused: Set<String>, inspecting ports: Set<UInt16>) {
        self.refused = refused
        self.inspectedTLSPorts = ports
    }

    func resolve(_ question: EgressQuestion) -> EgressVerdict { .allow }
    func resolved(_ answer: EgressAnswer) -> EgressVerdict { .allow }
    func dial(_ flow: EgressFlow) -> EgressVerdict { .allow }
    func clientHello(_ hello: EgressClientHello) -> EgressTLSVerdict {
        asked.withLockedValue { $0.append(hello) }
        return refused.contains(hello.serverName) ? .refuse : .allow
    }
}

/// What the harness reports. See `differential/harness/tls.go`.
private struct TLSCase: Decodable {
    let clientError: String
    let reply: String
    let connections: Int
    let upstreamName: String
    let upstreamError: String
    let upstreamBytes: Int
    let upstreamReceived: String
}

private struct Carried {
    let result: TLSCase
    let statistics: Gateway.Statistics
    let asked: [EgressClientHello]
}

/// The name the upstream's certificate covers and that no test refuses.
private let allowedName = "api.example.test"
/// Covered by the same certificate, on the same address, and refused. The
/// shared-address case the SNI check exists for.
private let deniedName = "gist.example.test"

/// One connection from a real guest to a real TLS server, through a gateway
/// whose policy refuses `refusing`.
///
/// `split` cuts the client's first record after that many bytes of handshake,
/// 0 for one record. `plain` sends those bytes instead of a handshake.
private func carry(
    name: String, split: Int, plain: String? = nil, refusing: Set<String>, inspect: Bool = true
) async throws -> Carried? {
    guard let harness = requireDifferentialHarness() else { return nil }
    let process = Process()
    let input = Pipe()
    let output = Pipe()
    let diagnostics = Pipe()
    process.executableURL = URL(fileURLWithPath: harness)
    process.arguments = ["tls", allowedName, deniedName]
    process.standardInput = input
    process.standardOutput = output
    process.standardError = diagnostics
    try process.run()
    defer {
        try? input.fileHandleForWriting.close()
        process.waitUntilExit()
    }
    var lines = LineReader(output: output, diagnostics: diagnostics)

    struct Port: Decodable { let port: UInt16 }
    let port = try JSONDecoder().decode(Port.self, from: try lines.next()).port

    let policy = ServerNames(refusing: refusing, inspecting: inspect ? [port] : [])
    var configuration = Gateway.Configuration()
    configuration.egressPolicy = policy
    // /tmp rather than the temporary directory: on macOS that path is long
    // enough to overflow an AF_UNIX address.
    let tag = UInt32.random(in: 0..<UInt32.max)
    let wire = "/tmp/ns-tls-\(tag).sock"
    let local = "/tmp/ns-tls-\(tag)-guest.sock"
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    let gateway = try await Gateway.start(listeningOnDatagramSocketAt: wire, group: group, configuration: configuration)
        .get()

    var request: [String: Any] = [
        "wire": wire, "local": local, "destination": configuration.hostAddress.description, "name": name,
        "split": split,
    ]
    if let plain { request["plain"] = plain }
    var line = try JSONSerialization.data(withJSONObject: request)
    line.append(0x0a)
    try input.fileHandleForWriting.write(contentsOf: line)
    let result = try JSONDecoder().decode(TLSCase.self, from: try lines.next())

    let statistics = try await gateway.statistics().get()
    // Closed before the harness is told to exit, so the gateway's last frames
    // still have a guest to go to.
    _ = try? await gateway.close().get()
    try? await group.shutdownGracefully()
    return Carried(result: result, statistics: statistics, asked: policy.asked.withLockedValue { $0 })
}

/// Lines from the harness, blocking, as `GVisorPeer` reads them.
private struct LineReader {
    let output: Pipe
    let diagnostics: Pipe
    var pending = Data()

    mutating func next() throws -> Data {
        while true {
            if let newline = pending.firstIndex(of: 0x0a) {
                let line = pending[pending.startIndex..<newline]
                pending = Data(pending[pending.index(after: newline)...])
                return Data(line)
            }
            let chunk = output.fileHandleForReading.availableData
            guard !chunk.isEmpty else {
                let errors = diagnostics.fileHandleForReading.availableData
                throw GVisorPeerError.exited(String(data: errors, encoding: .utf8) ?? "")
            }
            pending.append(chunk)
        }
    }
}

/// 0 is one record. 38 ends the first record after the handshake header,
/// version and random, so the name is only in the second.
private let splits = [0, 38]

@Test(arguments: splits)
func aHelloForADeniedNameIsResetAndTheUpstreamNeverSeesIt(split: Int) async throws {
    guard let carried = try await carry(name: deniedName, split: split, refusing: [deniedName]) else { return }
    let result = carried.result

    #expect(result.clientError.contains("reset"), "the client was told \(result.clientError.debugDescription), not a reset")
    #expect(result.upstreamName == "", "the upstream handshook for \(result.upstreamName)")
    #expect(result.upstreamBytes == 0, "the upstream received \(result.upstreamBytes) bytes of a refused hello")
    // Closed by the gateway, not left open until the upstream's own deadline.
    #expect(result.upstreamError == "EOF", "the upstream's connection ended with \(result.upstreamError.debugDescription)")
    // The dial happens before the name is known, so the upstream saw a
    // connection. The ADR says so, and this is where it shows.
    #expect(result.connections == 1)
    #expect(carried.statistics.tlsRefusedByPolicy == 1)
    #expect(carried.statistics.tlsRefusedUnreadable == 0)

    let asked = try #require(carried.asked.first, "the policy was not asked")
    #expect(carried.asked.count == 1)
    #expect(asked.serverName == deniedName)
    #expect(asked.flow.transport == .tcp)
    #expect(asked.flow.destination == Gateway.Configuration().hostAddress)
    #expect(asked.flow.translatedDestination == IPv4Address("127.0.0.1")!)
}

/// The control for the test above: the same client, the same split, a name the
/// policy allows. A gateway that broke every split hello would pass the refusal.
@Test(arguments: splits)
func theSameHelloForAnAllowedNameCompletesItsHandshake(split: Int) async throws {
    guard let carried = try await carry(name: allowedName, split: split, refusing: [deniedName]) else { return }
    let result = carried.result

    #expect(result.clientError == "", "the client's handshake failed: \(result.clientError)")
    #expect(result.upstreamError == "", "the upstream's handshake failed: \(result.upstreamError)")
    #expect(result.upstreamName == allowedName)
    #expect(carried.statistics.tlsRefusedByPolicy == 0)
    #expect(carried.asked.map(\.serverName) == [allowedName])
}

/// The control that the verdict is what refuses: the denied name, inspected
/// and asked about, under a policy that allows it, completes.
@Test func anAllowAllPolicyLetsTheSameDeniedNameThrough() async throws {
    guard let carried = try await carry(name: deniedName, split: 38, refusing: []) else { return }

    #expect(carried.result.clientError == "", "the client's handshake failed: \(carried.result.clientError)")
    #expect(carried.result.upstreamName == deniedName)
    #expect(carried.asked.map(\.serverName) == [deniedName], "the name was not read, so nothing was decided")
    #expect(carried.statistics.tlsRefusedByPolicy == 0)
}

/// A port not in `inspectedTLSPorts` is spliced unread, even for a name the
/// policy refuses.
@Test func aPortThatIsNotInspectedIsNotAskedAbout() async throws {
    guard let carried = try await carry(name: deniedName, split: 38, refusing: [deniedName], inspect: false) else {
        return
    }

    #expect(carried.result.clientError == "")
    #expect(carried.result.upstreamName == deniedName)
    #expect(carried.asked.isEmpty)
}

/// A complete hello with no `server_name` has no name to judge, and `dial`
/// already allowed the address. It goes through unasked.
@Test func aHelloWithNoServerNamePassesUnasked() async throws {
    guard let carried = try await carry(name: "", split: 38, refusing: [deniedName, allowedName]) else { return }

    #expect(carried.result.clientError == "", "the client's handshake failed: \(carried.result.clientError)")
    #expect(carried.result.upstreamError == "")
    #expect(carried.result.upstreamName == "")
    #expect(carried.asked.isEmpty)
    #expect(carried.statistics.tlsRefusedByPolicy + carried.statistics.tlsRefusedUnreadable == 0)
}

/// Not TLS at all, on an inspected port: every byte reaches the upstream in
/// order, the half-close after it, and the answer comes back.
@Test func plainTextOnAnInspectedPortPassesIntact() async throws {
    let request = "GET / HTTP/1.0\r\nHost: \(deniedName)\r\n\r\n"
    guard let carried = try await carry(name: "", split: 0, plain: request, refusing: [deniedName]) else { return }

    #expect(carried.result.clientError == "", "the client failed: \(carried.result.clientError)")
    #expect(carried.result.upstreamReceived == request)
    #expect(carried.result.reply == "ok")
    #expect(carried.asked.isEmpty)
}

/// The start of a hello, then the guest's FIN. The hello can never be whole, so
/// no name will come, and the server might still have read one from the rest.
/// Refused without asking the policy, and counted apart from a policy refusal.
@Test func aHelloTheGuestCutsShortIsRefusedUnaskedAndCounted() async throws {
    // A handshake record claiming 64 bytes, carrying 4 of a ClientHello.
    let truncated = String(decoding: [0x16, 0x03, 0x01, 0x00, 0x40, 0x01, 0x00, 0x00, 0x3c], as: UTF8.self)
    guard let carried = try await carry(name: "", split: 0, plain: truncated, refusing: []) else { return }

    #expect(carried.result.upstreamBytes == 0, "the upstream received \(carried.result.upstreamBytes) bytes of an unreadable hello")
    #expect(carried.result.upstreamError == "", "the upstream's connection ended with \(carried.result.upstreamError.debugDescription)")
    #expect(carried.result.upstreamReceived == "")
    #expect(carried.result.clientError.contains("reset"), "the client was told \(carried.result.clientError.debugDescription)")
    #expect(carried.statistics.tlsRefusedUnreadable == 1)
    #expect(carried.statistics.tlsRefusedByPolicy == 0)
    #expect(carried.asked.isEmpty, "the policy was asked about a hello with no name in it")
}

// MARK: The inspector, on an embedded loop

/// Everything the inspector let through, and whether it asked to refuse.
private final class Downstream: ChannelInboundHandler {
    typealias InboundIn = ByteBuffer
    var bytes: [UInt8] = []
    var inputClosed = false
    var inputClosedAfterBytes = 0

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        bytes += Array(unwrapInboundIn(data).readableBytesView)
    }

    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        if case ChannelEvent.inputClosed = event {
            inputClosed = true
            inputClosedAfterBytes = bytes.count
        }
    }
}

private final class Inspected {
    let channel = EmbeddedChannel()
    let downstream = Downstream()
    var judged: [ClientHelloReassembler.Outcome] = []
    var refused = 0
    var loop: EmbeddedEventLoop { channel.embeddedEventLoop }

    init(pass: Bool = true, timeout: TimeAmount = .seconds(15)) throws {
        let loop = channel.embeddedEventLoop
        let inspector = ClientHelloInspector(
            timeout: timeout,
            schedule: { amount, work in loop.scheduleTask(in: amount, work) },
            judge: { [unowned self] outcome in
                self.judged.append(outcome)
                if case .unreadable = outcome { return false }
                return pass
            },
            refuse: { [unowned self] in self.refused += 1 })
        try channel.pipeline.syncOperations.addHandler(inspector)
        try channel.pipeline.syncOperations.addHandler(downstream)
    }

    func send(_ bytes: [UInt8]) throws {
        try channel.writeInbound(ByteBuffer(bytes: bytes))
    }
}

@Test func aHelloThatStallsIsRefusedAtTheDeadlineAndNotBefore() throws {
    let inspected = try Inspected(timeout: .seconds(15))
    let hello = records(clientHello(serverName: allowedName), size: 38)
    try inspected.send(Array(hello.prefix(43)))

    inspected.loop.advanceTime(by: .seconds(14))
    #expect(inspected.judged.isEmpty, "judged before the deadline: \(inspected.judged)")
    inspected.loop.advanceTime(by: .seconds(1))
    #expect(inspected.judged == [.unreadable(.timedOut)])
    #expect(inspected.refused == 1)
    #expect(inspected.downstream.bytes.isEmpty, "a refused hello was passed on")

    // The rest of the hello, arriving late, is not a second decision.
    try inspected.send(Array(hello.dropFirst(43)))
    #expect(inspected.judged.count == 1)
    #expect(inspected.downstream.bytes.isEmpty)
}

@Test func aHelloTheGuestCutsShortIsRefusedAndItsFinIsNotPassedOn() throws {
    let inspected = try Inspected()
    let hello = records(clientHello(serverName: allowedName), size: 38)
    try inspected.send(Array(hello.prefix(60)))
    inspected.channel.pipeline.fireUserInboundEventTriggered(ChannelEvent.inputClosed)

    #expect(inspected.judged == [.unreadable(.ended)])
    #expect(inspected.refused == 1)
    #expect(inspected.downstream.bytes.isEmpty)
    #expect(!inspected.downstream.inputClosed, "the FIN went upstream without the refusal")
}

@Test func aPassedHelloGoesOnWholeAndInOrderWithItsFinAfterIt() throws {
    let inspected = try Inspected()
    let hello = records(clientHello(serverName: allowedName), size: 38)
    let trailing = Array("next flight".utf8)
    try inspected.send(Array(hello.prefix(10)))
    #expect(inspected.downstream.bytes.isEmpty, "bytes passed before the hello was judged")
    try inspected.send(Array(hello.dropFirst(10)) + trailing)
    #expect(inspected.judged == [.serverName(allowedName)])

    try inspected.send(Array("after".utf8))
    inspected.channel.pipeline.fireUserInboundEventTriggered(ChannelEvent.inputClosed)
    #expect(inspected.downstream.bytes == hello + trailing + Array("after".utf8))
    #expect(inspected.downstream.inputClosed)
    #expect(inspected.refused == 0)
    // Removed itself: the deadline no longer applies to a passed connection.
    inspected.loop.advanceTime(by: .seconds(60))
    #expect(inspected.judged.count == 1)
}

@Test func aStreamThatIsNotTLSIsPassedOnItsFirstByteAndAnEmptyOneOnItsFin() throws {
    // Decided on one byte: a protocol that sends a byte and waits must not be
    // held until the deadline.
    let plain = try Inspected()
    try plain.send(Array("G".utf8))
    #expect(plain.judged == [.notTLS])
    #expect(plain.downstream.bytes == Array("G".utf8))

    let empty = try Inspected()
    empty.channel.pipeline.fireUserInboundEventTriggered(ChannelEvent.inputClosed)
    #expect(empty.judged == [.notTLS], "a stream that ended before sending anything is not TLS")
    #expect(empty.downstream.inputClosed)
    #expect(empty.refused == 0)
}

// MARK: The reassembler

/// A ClientHello body with a `server_name` of `serverName`, or none if `nil`,
/// among the extensions a real one carries around it.
private func clientHello(serverName: String?, extraExtensions: [UInt8] = []) -> [UInt8] {
    var body: [UInt8] = [0x03, 0x03] + [UInt8](repeating: 0x11, count: 32)
    body += [32] + [UInt8](repeating: 0x22, count: 32)
    body += [0x00, 0x04, 0x13, 0x01, 0x13, 0x02]
    body += [0x01, 0x00]
    var extensions: [UInt8] = []
    // supported_versions, TLS 1.3
    extensions += [0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04]
    if let serverName {
        let name = Array(serverName.utf8)
        let entry: [UInt8] = [0x00] + be16(name.count) + name
        let list = be16(entry.count) + entry
        extensions += [0x00, 0x00] + be16(list.count) + list
    }
    // key_share with a dummy X25519 share
    extensions += [0x00, 0x33] + be16(38) + be16(36) + [0x00, 0x1d] + be16(32) + [UInt8](repeating: 0x33, count: 32)
    extensions += extraExtensions
    body += be16(extensions.count) + extensions
    return [0x01] + be24(body.count) + body
}

/// `message` carried in handshake records of at most `size` bytes each.
private func records(_ message: [UInt8], size: Int) -> [UInt8] {
    var out: [UInt8] = []
    var rest = message[...]
    while !rest.isEmpty {
        let part = rest.prefix(size)
        out += [0x16, 0x03, 0x01] + be16(part.count) + part
        rest = rest.dropFirst(part.count)
    }
    return out
}

private func be16(_ value: Int) -> [UInt8] { [UInt8(value >> 8 & 0xff), UInt8(value & 0xff)] }
private func be24(_ value: Int) -> [UInt8] { [UInt8(value >> 16 & 0xff)] + be16(value) }

private func feedAll(_ bytes: [UInt8], chunk: Int = .max) -> ClientHelloReassembler.Outcome {
    var reassembler = ClientHelloReassembler()
    var rest = bytes[...]
    while !rest.isEmpty {
        let outcome = reassembler.feed(ByteBuffer(bytes: rest.prefix(chunk)))
        rest = rest.dropFirst(chunk)
        if outcome != .needMore { return outcome }
    }
    return .needMore
}

@Test func aHelloSplitIntoRecordsOfAnySizeIsReadTheSame() {
    let hello = clientHello(serverName: "Gist.Example.Test.")
    // 1 is the finest split a client can make; 38 puts nothing that names a
    // host in the first record.
    for size in [1, 4, 38, 100, hello.count / 2, hello.count] {
        #expect(feedAll(records(hello, size: size)) == .serverName("gist.example.test"), "records of \(size)")
        #expect(feedAll(records(hello, size: size), chunk: 1) == .serverName("gist.example.test"), "records of \(size), a byte at a time")
    }
}

@Test func whatIsNotAHelloIsToldApartFromAHelloWithNoName() {
    #expect(feedAll(Array("GET / HTTP/1.1\r\n".utf8)) == .notTLS)
    #expect(feedAll([0x16]) == .needMore, "one byte of a handshake record decided early")
    #expect(feedAll(records(clientHello(serverName: nil), size: 38)) == .noServerName)
    #expect(feedAll(records(clientHello(serverName: ""), size: 38)) == .noServerName)
}

@Test func aHandshakeThatGoesWrongIsUnreadableNotNotTLS() {
    let firstRecord = Array(records(clientHello(serverName: "example.com"), size: 38).prefix(5 + 38))
    let cases: [String: [UInt8]] = [
        "application data before the hello is whole": firstRecord + [0x17, 0x03, 0x03, 0x00, 0x01, 0x00],
        "zero-length handshake record": [0x16, 0x03, 0x01, 0x00, 0x00],
        "record over the TLS limit": [0x16, 0x03, 0x01, 0x40, 0x01],
        "handshake that is not a ClientHello": [0x16, 0x03, 0x01, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00],
        "hello claiming more than 16 KiB": [0x16, 0x03, 0x01, 0x00, 0x04, 0x01, 0x00, 0x40, 0x01],
        "a name with a NUL in it": records(clientHello(serverName: "evil\u{0}.example.com"), size: 38),
        "an extension longer than the hello": records(
            clientHello(serverName: nil, extraExtensions: [0x00, 0x10, 0x00, 0xff]), size: 38),
    ]
    for (name, input) in cases {
        #expect(feedAll(input) == .unreadable(.malformed), "\(name)")
    }
}

/// A hello header claiming just under 16 KiB, then one byte per record for as
/// long as the reader keeps taking them. Six bytes of records per byte of
/// hello would pass 32 KiB long before the hello was whole.
@Test func splittingAHelloFinelyIsStoppedAtTheRecordBound() {
    var reassembler = ClientHelloReassembler()
    var outcome = ClientHelloReassembler.Outcome.needMore
    for byte: UInt8 in [0x01, 0x00, 0x3f, 0xf0] {
        outcome = reassembler.feed(ByteBuffer(bytes: [0x16, 0x03, 0x01, 0x00, 0x01, byte]))
    }
    while outcome == .needMore {
        outcome = reassembler.feed(ByteBuffer(bytes: [0x16, 0x03, 0x01, 0x00, 0x01, 0x00]))
        #expect(reassembler.consumed.readableBytes <= 32 * 1024 + 6)
    }
    #expect(outcome == .unreadable(.malformed))
    // The documented bound, not the constant, so raising the constant fails.
    #expect(reassembler.consumed.readableBytes <= 32 * 1024)
}

/// Mutated hellos, re-framed at random and fed in random chunks.
///
/// "It did not crash" is the weak half. The strong half is that the outcome
/// does not depend on how the bytes were chunked: the guest chooses its segment
/// boundaries, so a reader whose verdict moved with them would let the guest
/// choose its verdict. And a name is only ever reported from a hello that
/// actually carries it: every mutation that still yields a name yields one of
/// the bytes the hello held.
@Test func theReassemblerSurvivesMutatedHellosAndChunkingNeverChangesItsAnswer() {
    let iterations = Int(ProcessInfo.processInfo.environment["NETSTACK_FUZZ_ITERATIONS"] ?? "") ?? 4000
    let seed = UInt64(ProcessInfo.processInfo.environment["NETSTACK_FUZZ_SEED"] ?? "") ?? 0x7115
    var random = HelloRandom(seed: seed)
    let corpus = [
        clientHello(serverName: "gist.example.test"), clientHello(serverName: nil),
        clientHello(serverName: "a.b"), clientHello(serverName: String(repeating: "x", count: 200)),
    ]
    for iteration in 0..<iterations {
        var hello = corpus[Int(random.next() % UInt64(corpus.count))]
        for _ in 0..<(1 + Int(random.next() % 4)) {
            let at = Int(random.next() % UInt64(hello.count))
            switch random.next() % 4 {
            case 0: hello[at] = UInt8(truncatingIfNeeded: random.next())
            case 1: hello[at] ^= 0x80
            case 2: hello.removeSubrange(at...)
            default: hello.insert(UInt8(truncatingIfNeeded: random.next()), at: at)
            }
            if hello.isEmpty { hello = [0x01] }
        }
        let framed = records(hello, size: 1 + Int(random.next() % 300))
        let whole = feedAll(framed)
        let chunked = feedAll(framed, chunk: 1 + Int(random.next() % 64))
        #expect(whole == chunked, "chunking changed the answer at iteration \(iteration); replay with NETSTACK_FUZZ_SEED=\(seed)")
        if case .serverName(let name) = whole {
            #expect(!name.isEmpty && name.utf8.allSatisfy { $0 > 0x20 && $0 < 0x7f && !($0 >= 0x41 && $0 <= 0x5a) })
        }
    }
    // The oracle that the reader still works after all of that.
    #expect(feedAll(records(corpus[0], size: 38)) == .serverName("gist.example.test"))
}

private struct HelloRandom: RandomNumberGenerator {
    private var state: UInt64
    init(seed: UInt64) { state = seed &* 0x2545_F491_4F6C_DD1D | 1 }
    mutating func next() -> UInt64 {
        state ^= state << 13
        state ^= state >> 7
        state ^= state << 17
        return state
    }
}
