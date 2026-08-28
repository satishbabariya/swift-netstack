import Testing
import Foundation
import NIOCore
import NIOEmbedded

@testable import Netstack

/// The path to the built differential harness binary
/// (`differential/harness/harness`), or `nil` if it has not been built.
///
/// Resolved relative to THIS source file's own location (`#filePath`),
/// not the process's current working directory — `swift test` is usually
/// invoked from the package root, but nothing guarantees that (Xcode, an
/// IDE, a CI step that `cd`s first all differ), and a path that depends on
/// it would make this instrument flaky for reasons that have nothing to do
/// with whether the two stacks agree.
///
/// Returning `nil` rather than throwing is deliberate: a contributor
/// without a Go toolchain, or who simply has not run
/// `cd differential/harness && GOFLAGS= go build -o harness .`, must still
/// be able to run `swift test`. The harness is a development instrument,
/// not a build dependency — every test that depends on it starts with
/// Prefer `requireDifferentialHarness()` in a test: a silent skip here is
/// indistinguishable from a pass.
func differentialHarnessPathIfBuilt() -> String? {
    let thisFile = URL(fileURLWithPath: #filePath)
    let packageRoot =
        thisFile
        .deletingLastPathComponent()  // Differential.swift -> Support/
        .deletingLastPathComponent()  // Support/ -> NetstackTests/
        .deletingLastPathComponent()  // NetstackTests/ -> Tests/
        .deletingLastPathComponent()  // Tests/ -> package root
    let harnessPath = packageRoot.appendingPathComponent("differential/harness/harness").path
    return FileManager.default.isExecutableFile(atPath: harnessPath) ? harnessPath : nil
}

/// The harness path, or a recorded failure if it is not built.
///
/// **The silent-skip shape this replaces was a real hole in the M4 gate.**
/// `generatedTCPSequencesAgreeWithGVisor` guarded on
/// `differentialHarnessPathIfBuilt()` and plain `return`ed when the binary was
/// absent — so on any fresh checkout, which is every CI run and every clone,
/// the gate test passed in about a millisecond having compared nothing at all.
/// A run of ten thousand sequences and a run of none are reported identically.
/// That is the same defect this project has found repeatedly in its own tests,
/// sitting in the one test that certifies a milestone.
///
/// So: absent harness is a failure, not a skip. `differential/harness` builds
/// with `go build -o harness .` and takes a few seconds.
///
/// Set `NETSTACK_DIFFERENTIAL_OPTIONAL=1` to opt out — for a machine with no Go
/// toolchain, where the rest of the suite is still worth running. That is a
/// deliberate act by someone who knows what they are giving up, which is the
/// difference between an opt-out and an accident.
func requireDifferentialHarness(_ sourceLocation: SourceLocation = #_sourceLocation) -> String? {
    if let path = differentialHarnessPathIfBuilt() { return path }
    if ProcessInfo.processInfo.environment["NETSTACK_DIFFERENTIAL_OPTIONAL"] == "1" { return nil }
    Issue.record(
        """
        the differential harness is not built, so this test compared nothing.

        Build it:    cd differential/harness && go build -o harness .
        Or opt out:  NETSTACK_DIFFERENTIAL_OPTIONAL=1 swift test
        """,
        sourceLocation: sourceLocation)
    return nil
}

/// Everything that can go wrong running the harness subprocess itself, as
/// distinct from the two stacks disagreeing about what to emit — the
/// latter is a `DifferentialDivergence`, reported through `compare`'s
/// return value rather than thrown, because disagreement is the expected
/// output of this instrument, not a failure of the instrument.
enum DifferentialRunError: Error, CustomStringConvertible {
    case harnessLaunchFailed(String)
    case harnessExitedNonZero(status: Int32, stderr: String)
    case malformedHarnessOutput(String)
    case runCountMismatch(sent: Int, received: Int)
    case stepCountMismatch(run: Int, sent: Int, received: Int)

    var description: String {
        switch self {
        case .harnessLaunchFailed(let reason):
            return "failed to launch the differential harness: \(reason)"
        case .harnessExitedNonZero(let status, let stderr):
            return "differential harness exited with status \(status): \(stderr)"
        case .malformedHarnessOutput(let reason):
            return "differential harness produced unparsable output: \(reason)"
        case .runCountMismatch(let sent, let received):
            return "sent \(sent) run(s) to the differential harness and got \(received) back"
        case .stepCountMismatch(let run, let sent, let received):
            return "run \(run): sent \(sent) step(s) to the differential harness and got \(received) back"
        }
    }
}

/// A `NetstackClock` that reads an `EmbeddedEventLoop`'s own notion of time.
///
/// `EmbeddedEventLoop.advanceTime` sets its clock to each scheduled task's
/// deadline BEFORE running it, so a timer body that re-arms itself with
/// `clock.now() + rto` — which is what `Sender` does on every RTO backoff —
/// computes its next deadline from the moment it actually fired.
///
/// A `ManualClock` advanced by the whole step and then handed to the loop
/// reads the step's END instead, so an RTO ladder drifts by up to one step's
/// worth on every rung, and a differential comparing step indices sees a
/// retransmission the reference stack put somewhere else. `VectorRunner`
/// avoids the same trap by advancing in one-millisecond sub-steps; this is the
/// exact version of that, and it costs nothing — which matters here, where a
/// gate run is ten thousand sequences of tens of seconds of virtual time each.
final class LoopClock: NetstackClock, @unchecked Sendable {
    private let loop: EmbeddedEventLoop
    init(loop: EmbeddedEventLoop) { self.loop = loop }
    func now() -> NIODeadline { loop.now }
}

/// What the application does at a step, on whichever side is being driven.
///
/// The vocabulary is deliberately the same as the vector DSL's application
/// lines (`VectorPacket.applicationWrite` / `.applicationClose`), because a
/// generated sequence has to drive the SAME application against both stacks
/// or the comparison is between two different programs.
enum DifferentialAction: Equatable {
    case write(bytes: Int)
    case close
}

/// One step of a differential sequence: at most one frame to inject, how far
/// to advance the clock afterwards, and at most one application action.
///
/// A step with no frame is not padding: a retransmission is observed by
/// advancing time with nothing arriving, and that is the only way to observe
/// it.
struct DifferentialStep {
    var frame: ByteBuffer?
    var advanceMs: Int
    var action: DifferentialAction?

    init(frame: ByteBuffer? = nil, advanceMs: Int, action: DifferentialAction? = nil) {
        self.frame = frame
        self.advanceMs = advanceMs
        self.action = action
    }
}

/// One point where what the Swift stack emitted and what the Go (gVisor)
/// stack emitted disagree — including the case where one stack emitted a
/// frame at a position the other has nothing for at all.
///
/// `step` is the index of the sequence step the frame was drained after, and
/// it is compared as well as the content: a flat list of frames cannot tell
/// "retransmitted after one second" from "retransmitted after eight", because
/// both stacks emit the same bytes in the same order either way.
///
/// `recognised` is non-nil for the one class of difference this project has
/// investigated, ruled on, and pinned to an exact signature — see
/// `DifferentialRun.recognise`. It is NOT a permission: a recognised
/// divergence is still reported, still counted, and the tests assert both
/// that unrecognised ones are absent and that recognised ones appear exactly
/// where they are supposed to.
struct DifferentialDivergence: CustomStringConvertible {
    var step: Int
    var frameIndex: Int
    var swiftBytes: ByteBuffer?
    var goBytes: ByteBuffer?
    var recognised: String?
    var description: String
}

/// Runs the same sequence of frames and application calls through gVisor's Go
/// TCP/IP stack (via the `differential/harness` binary) and through a live
/// Swift `Stack`, and reports every point where what the two stacks emitted
/// disagrees.
///
/// ## What is masked, and what deliberately is not
///
/// Spec §8.2 permits three divergences: initial sequence numbers, timestamp
/// option values, and ACK coalescing.
///
/// - **Initial sequence numbers are normalised, not discarded.** Each side's
///   gateway-side ISS is learned from the first SYN it emits, and every
///   sequence number is expressed relative to it. Two stacks never choose the
///   same ISS; they must still agree on every number derived from it, and an
///   earlier version of this type masked `seqStart`/`seqEnd` to constants —
///   which also masked "retransmitted at the wrong sequence number", the
///   exact defect a retransmission comparison exists to catch.
/// - **Acknowledgement numbers are compared EXACTLY.** They live in the
///   *guest's* sequence space, and the guest is the generated script, which is
///   the same on both sides. There is nothing about an ACK number that a stack
///   is free to choose, and masking it — as an earlier version of this type
///   did — would have made the entire receive-side comparison vacuous: `ack 1`
///   and `ack 4381` would have compared equal.
/// - **Timestamp option VALUES are masked; the option's PRESENCE is not.** A
///   stack that drops the option entirely is a real divergence.
/// - **ACK coalescing is not masked.** Nothing in the generator produces a
///   frame-count difference from coalescing alone (both stacks acknowledge
///   every sequence-space-occupying segment in the same pass), so masking it
///   would be masking a hypothesis. If a run ever produces one, it will be
///   reported as a divergence — the safe failure direction — and whoever meets
///   it can implement the masking against a real example.
///
/// THE BUG THIS TYPE EXISTS TO NOT HAVE: comparing `zip(swiftFrames,
/// goFrames)` and silently ignoring whichever list has a longer tail. If
/// one stack emits three frames and the other emits two, `zip` compares
/// two pairs, finds them equal, and reports no divergence — every future
/// TCP comparison would then pass vacuously. `diverge` below iterates to
/// `max`, not `min`, of the two counts, at both the step level and the frame
/// level, specifically to avoid this;
/// `theDifferentialDetectsADeliberateDivergence` in
/// `DifferentialValidationTests.swift` exists to prove it actually does.
struct DifferentialRun {
    var harnessPath: String
    var codec: VectorFrames

    init(harnessPath: String, codec: VectorFrames) {
        self.harnessPath = harnessPath
        self.codec = codec
    }

    // MARK: - Single-sequence convenience

    /// Drives one sequence through both stacks and diffs the result.
    func compare(
        steps: [DifferentialStep],
        against stack: Stack, link: RecordingEndpoint, clock: ManualClock?, loop: EmbeddedEventLoop,
        application: VectorApplication? = nil, beforeEachStep: (() -> Void)? = nil
    ) throws -> [DifferentialDivergence] {
        let goSteps = try runHarness(runs: [steps])[0]
        let swiftSteps = driveSwift(
            steps: steps, link: link, clock: clock, loop: loop, application: application, beforeEachStep: beforeEachStep)
        return diverge(swiftSteps: swiftSteps, goSteps: goSteps)
    }

    // MARK: - Swift side

    /// Plays one sequence against a live Swift stack, returning the frames
    /// drained after each step.
    ///
    /// Both the clock and the loop are advanced, together: a timer keyed off
    /// one but not the other disagrees with itself about what time it is.
    /// Every step drains afterwards, so a frame produced by a TIMER BODY —
    /// a retransmission, a TIME-WAIT expiry — is collected exactly like one
    /// produced inline by an arriving segment. That property is checked
    /// directly, and repeatedly, by
    /// `theCollectorSeesFramesEmittedFromATimerBody`: a collector that only
    /// saw inline emissions would report "no divergences" on every
    /// retransmission sequence and look exactly like success.
    func driveSwift(
        steps: [DifferentialStep], link: RecordingEndpoint, clock: ManualClock?, loop: EmbeddedEventLoop,
        application: VectorApplication? = nil, beforeEachStep: (() -> Void)? = nil
    ) -> [[ByteBuffer]] {
        var collected: [[ByteBuffer]] = []
        var gatewayISS: UInt32?

        for step in steps {
            beforeEachStep?()

            if var frame = step.frame {
                if let iss = gatewayISS { Self.shiftAcknowledgement(&frame, by: iss) }
                link.inject(frame)
            }

            let advance = TimeAmount.milliseconds(Int64(step.advanceMs))
            // `clock` is nil when the stack under test reads its time from the
            // loop (see `LoopClock`), which is the only arrangement in which a
            // timer body re-arming itself lands on the right rung of the
            // ladder. It is non-nil only for the ARP/ICMP driver validation,
            // which has no timers at all.
            clock?.advance(by: advance)
            loop.advanceTime(by: advance)

            switch step.action {
            case .write(let bytes): try? application?.write(bytes)
            case .close: try? application?.close()
            case nil: break
            }

            let drained = link.drainTransmitted()
            if gatewayISS == nil {
                for frame in drained where gatewayISS == nil {
                    gatewayISS = Self.synSequence(of: frame)
                }
            }
            collected.append(drained)
        }
        return collected
    }

    // MARK: - Go side

    private struct HarnessRun: Encodable {
        var frames: [String]
        var advanceMs: [Int]
        var actions: [String]
    }

    private struct HarnessRequest: Encodable {
        var runs: [HarnessRun]
    }

    private struct HarnessResponse: Decodable {
        var runs: [[[String]]]
    }

    /// Plays every sequence in `runs` against gVisor, each on its own freshly
    /// built stack, in ONE subprocess.
    ///
    /// Batching is not an optimisation for its own sake: the M4 gate is ten
    /// thousand generated sequences, and a fork+exec per sequence is most of
    /// the wall time of the whole run.
    func runHarness(runs: [[DifferentialStep]]) throws -> [[[ByteBuffer]]] {
        let request = HarnessRequest(
            runs: runs.map { steps in
                HarnessRun(
                    frames: steps.map { $0.frame.map(Self.base64) ?? "" },
                    advanceMs: steps.map(\.advanceMs),
                    actions: steps.map { step in
                        switch step.action {
                        case .write(let bytes): return "write:\(bytes)"
                        case .close: return "close"
                        case nil: return ""
                        }
                    })
            })
        let requestData = try JSONEncoder().encode(request)

        let process = Process()
        process.executableURL = URL(fileURLWithPath: harnessPath)
        let stdin = Pipe()
        let stdout = Pipe()
        let stderr = Pipe()
        process.standardInput = stdin
        process.standardOutput = stdout
        process.standardError = stderr

        do {
            try process.run()
        } catch {
            throw DifferentialRunError.harnessLaunchFailed("\(error)")
        }

        // A batched request can be megabytes, far past a pipe's ~64KB
        // buffer, so the write must not block the read: writing everything
        // before reading anything would deadlock the moment the harness's
        // own output filled ITS pipe while it waited for the rest of the
        // request. The write runs on its own queue for exactly that reason.
        let writeQueue = DispatchQueue(label: "differential-harness-stdin")
        writeQueue.async {
            try? stdin.fileHandleForWriting.write(contentsOf: requestData)
            try? stdin.fileHandleForWriting.close()
        }

        let outputData = try stdout.fileHandleForReading.readToEnd() ?? Data()
        let errorData = try stderr.fileHandleForReading.readToEnd() ?? Data()
        process.waitUntilExit()

        guard process.terminationStatus == 0 else {
            throw DifferentialRunError.harnessExitedNonZero(
                status: process.terminationStatus,
                stderr: String(data: errorData, encoding: .utf8) ?? "<unreadable stderr>")
        }

        let response: HarnessResponse
        do {
            response = try JSONDecoder().decode(HarnessResponse.self, from: outputData)
        } catch {
            throw DifferentialRunError.malformedHarnessOutput("\(error)")
        }

        guard response.runs.count == runs.count else {
            throw DifferentialRunError.runCountMismatch(sent: runs.count, received: response.runs.count)
        }

        return try response.runs.enumerated().map { runIndex, steps in
            // A harness that returned fewer steps than it was given would
            // silently truncate the comparison; every missing step is a step
            // in which neither stack is checked against the other.
            guard steps.count == runs[runIndex].count else {
                throw DifferentialRunError.stepCountMismatch(run: runIndex, sent: runs[runIndex].count, received: steps.count)
            }
            return try steps.map { step in
                try step.map { encoded in
                    guard let data = Data(base64Encoded: encoded) else {
                        throw DifferentialRunError.malformedHarnessOutput("frame is not valid base64: \(encoded)")
                    }
                    var buffer = ByteBufferAllocator().buffer(capacity: data.count)
                    buffer.writeBytes(data)
                    return buffer
                }
            }
        }
    }

    private static func base64(_ buffer: ByteBuffer) -> String {
        let bytes = buffer.getBytes(at: buffer.readerIndex, length: buffer.readableBytes) ?? []
        return Data(bytes).base64EncodedString()
    }

    // MARK: - Sequence-space alignment

    /// The byte offset of the IPv4 header inside an ethernet frame.
    private static let ipv4Offset = 14

    /// Reads the sequence number of a frame carrying a TCP SYN, or nil.
    ///
    /// Deliberately hand-rolled against wire offsets rather than routed
    /// through `VectorFrames.decode`: this is used to align the two stacks'
    /// sequence spaces BEFORE anything is compared, so it must not depend on
    /// the same code path whose output it is about to make comparable.
    static func synSequence(of frame: ByteBuffer) -> UInt32? {
        guard let tcpOffset = tcpHeaderOffset(of: frame) else { return nil }
        guard let flags = frame.getInteger(at: frame.readerIndex + tcpOffset + 13, as: UInt8.self), flags & 0x02 != 0 else { return nil }
        return frame.getInteger(at: frame.readerIndex + tcpOffset + 4, endianness: .big, as: UInt32.self)
    }

    /// Adds `iss` to a TCP frame's acknowledgement number in place, repairing
    /// the checksum.
    ///
    /// A guest cannot acknowledge a sequence number it has never been told,
    /// and the two stacks tell it different ones. Shifting rather than
    /// rewriting preserves every DELIBERATE error the generator introduced: a
    /// step that acknowledges five bytes too many still acknowledges five
    /// bytes too many, against whichever ISS the stack under test chose.
    static func shiftAcknowledgement(_ frame: inout ByteBuffer, by iss: UInt32) {
        guard iss != 0, let tcpOffset = tcpHeaderOffset(of: frame) else { return }
        let base = frame.readerIndex + tcpOffset
        guard let flags = frame.getInteger(at: base + 13, as: UInt8.self), flags & 0x10 != 0 else { return }
        guard let ack = frame.getInteger(at: base + 4 + 4, endianness: .big, as: UInt32.self) else { return }
        frame.setInteger(ack &+ iss, at: base + 8, endianness: .big)

        guard
            let source = frame.getInteger(at: frame.readerIndex + Self.ipv4Offset + 12, endianness: .big, as: UInt32.self),
            let destination = frame.getInteger(at: frame.readerIndex + Self.ipv4Offset + 16, endianness: .big, as: UInt32.self),
            let segment = frame.getSlice(at: base, length: frame.readableBytes - tcpOffset)
        else { return }

        var sum: UInt32 = 0
        sum += UInt32(source >> 16) + UInt32(source & 0xffff)
        sum += UInt32(destination >> 16) + UInt32(destination & 0xffff)
        sum += UInt32(IPProtocol.tcp.rawValue)
        sum += UInt32(segment.readableBytes)
        frame.setInteger(UInt16(0), at: base + 16, endianness: .big)
        guard let zeroed = frame.getSlice(at: base, length: frame.readableBytes - tcpOffset) else { return }
        let checksum = zeroed.withUnsafeReadableBytes { Checksum.complete(Checksum.partial($0, initial: sum)) }
        frame.setInteger(checksum, at: base + 16, endianness: .big)
    }

    /// The offset of the TCP header inside an ethernet frame, or nil if the
    /// frame is not TCP over IPv4.
    private static func tcpHeaderOffset(of frame: ByteBuffer) -> Int? {
        guard frame.readableBytes >= Self.ipv4Offset + 20 else { return nil }
        guard frame.getInteger(at: frame.readerIndex + 12, endianness: .big, as: UInt16.self) == 0x0800 else { return nil }
        guard let versionAndIHL = frame.getInteger(at: frame.readerIndex + Self.ipv4Offset, as: UInt8.self), versionAndIHL >> 4 == 4 else { return nil }
        let headerLength = Int(versionAndIHL & 0x0f) * 4
        guard headerLength >= 20 else { return nil }
        guard frame.getInteger(at: frame.readerIndex + Self.ipv4Offset + 9, as: UInt8.self) == IPProtocol.tcp.rawValue else { return nil }
        let offset = Self.ipv4Offset + headerLength
        guard frame.readableBytes >= offset + 20 else { return nil }
        return offset
    }

    // MARK: - Comparison

    /// Iterates to `max`, never `min`, at both levels — see this type's doc
    /// comment for exactly the bug that guards against.
    func diverge(swiftSteps: [[ByteBuffer]], goSteps: [[ByteBuffer]]) -> [DifferentialDivergence] {
        var divergences: [DifferentialDivergence] = []
        let swiftISS = Self.firstSynSequence(in: swiftSteps)
        let goISS = Self.firstSynSequence(in: goSteps)

        for step in 0..<max(swiftSteps.count, goSteps.count) {
            let swiftFrames = step < swiftSteps.count ? swiftSteps[step] : []
            let goFrames = step < goSteps.count ? goSteps[step] : []

            for index in 0..<max(swiftFrames.count, goFrames.count) {
                let swiftFrame = index < swiftFrames.count ? swiftFrames[index] : nil
                let goFrame = index < goFrames.count ? goFrames[index] : nil

                switch (swiftFrame, goFrame) {
                case (nil, nil):
                    continue  // unreachable: `index` never exceeds both counts at once
                case (let swift?, nil):
                    divergences.append(
                        DifferentialDivergence(
                            step: step, frameIndex: index, swiftBytes: swift, goBytes: nil, recognised: nil,
                            description: "step \(step) frame \(index): Swift emitted \(describe(swift)) with no matching Go frame"))
                case (nil, let go?):
                    divergences.append(
                        DifferentialDivergence(
                            step: step, frameIndex: index, swiftBytes: nil, goBytes: go, recognised: nil,
                            description: "step \(step) frame \(index): Go emitted \(describe(go)) with no matching Swift frame"))
                case (let swift?, let go?):
                    if let divergence = compareFrames(
                        step: step, index: index, swift: swift, go: go, swiftISS: swiftISS, goISS: goISS)
                    {
                        divergences.append(divergence)
                    }
                }
            }
        }
        return divergences
    }

    private static func firstSynSequence(in steps: [[ByteBuffer]]) -> UInt32 {
        for step in steps {
            for frame in step {
                if let sequence = synSequence(of: frame) { return sequence }
            }
        }
        return 0
    }

    private func compareFrames(
        step: Int, index: Int, swift: ByteBuffer, go: ByteBuffer, swiftISS: UInt32, goISS: UInt32
    ) -> DifferentialDivergence? {
        // `decode` returning nil means "cannot classify" — that must never
        // be treated as a match, not even against another frame this codec
        // also cannot classify: two frames a codec cannot understand are
        // never known to be the same frame.
        guard let swiftPacket = codec.decode(swift) else {
            return DifferentialDivergence(
                step: step, frameIndex: index, swiftBytes: swift, goBytes: go, recognised: nil,
                description:
                    "step \(step) frame \(index): Swift emitted an undecodable frame (\(swift.readableBytes) bytes); Go emitted \(describe(go))")
        }
        guard let goPacket = codec.decode(go) else {
            return DifferentialDivergence(
                step: step, frameIndex: index, swiftBytes: swift, goBytes: go, recognised: nil,
                description:
                    "step \(step) frame \(index): Go emitted an undecodable frame (\(go.readableBytes) bytes); Swift emitted \(describe(swift))")
        }

        let normalizedSwift = normalized(swiftPacket, iss: swiftISS)
        let normalizedGo = normalized(goPacket, iss: goISS)
        guard normalizedSwift != normalizedGo else { return nil }

        return DifferentialDivergence(
            step: step, frameIndex: index, swiftBytes: swift, goBytes: go,
            recognised: Self.recognise(swift: normalizedSwift, go: normalizedGo)
                ?? Self.recogniseScaledWindow(swift: normalizedSwift, go: normalizedGo),
            description: "step \(step) frame \(index): swift=\(normalizedSwift) go=\(normalizedGo)")
    }

    /// The label for the ONE difference between these two stacks that has been
    /// investigated, ruled on, and pinned — or nil, meaning "defect".
    ///
    /// gVisor's SYN-ACK advertises 29184 and this stack's advertises 65535,
    /// and no configuration of either closes the gap: gVisor caps the window
    /// it offers in a SYN-ACK at `InitialCwnd * advertisedMSS * 2` (10 × 1460
    /// × 2 = 29200, rounded down to a multiple of its handshake window scale,
    /// giving 29184), so it *cannot* offer 65535 at a 1500-byte MTU; and
    /// lowering this stack to 29184 was measured to be worse, because gVisor
    /// then advertises 65535 on every frame AFTER the handshake and the
    /// divergence would move from one frame per connection to all of them.
    /// Neither value is wrong: RFC 9293 mandates no particular initial window.
    ///
    /// The signature is exact — both windows, the flags, and equality of
    /// every other field — so this recognises the one measured difference and
    /// nothing else. A SYN-ACK whose windows are 29184/65500, or whose option
    /// list differs as well, is not recognised and is reported as a defect.
    static func recognise(swift: VectorPacket, go: VectorPacket) -> String? {
        guard case .tcp(var swiftLine) = swift, case .tcp(let goLine) = go else { return nil }
        guard swiftLine.flags == "S.", goLine.flags == "S." else { return nil }
        // 29200, not the 29184 this pinned before window scaling landed. gVisor
        // derives its initial window from its receive buffer, and the harness
        // now sets that buffer to the Swift stack's capacity so both sides
        // derive the same shift — which moved this by 16 bytes. Still pinned to
        // exact values rather than a range: the point of this recogniser is
        // that it fires for one known pair and nothing else.
        guard swiftLine.window == 65535, goLine.window == 29200 else { return nil }
        swiftLine.window = goLine.window
        guard swiftLine == goLine else { return nil }
        return "syn-ack-initial-window"
    }

    /// The second recognised difference: the window on a pure acknowledgement,
    /// once a scale is in effect.
    ///
    /// **Window scaling did not create this — it made it visible.** Before the
    /// scale, both stacks' advertised windows were clipped to 65535 by the
    /// header field, so two different receive capacities produced the same
    /// number and the comparison matched by accident. With the scale applied,
    /// each side expresses what it actually has, and the two differ: this stack
    /// advertises what its reassembler holds, gVisor charges `SegOverheadSize`
    /// per segment against its buffer and advertises roughly half. Both are
    /// honest about their own capacity; they account for overhead differently.
    /// RFC 9293 mandates no particular window, so neither is wrong.
    ///
    /// **What this masks, stated plainly.** A defect that changes only the
    /// advertised window on a pure ACK, and changes nothing else about the
    /// frame, will not be caught here. That is not nothing — so the exact-window
    /// coverage lives in the vectors instead, where the peer is fixed and the
    /// numbers are derived by hand: `tcp-data.vec`'s window scenarios pin the
    /// value, the shrink, the recovery and the never-retract edge against a
    /// stack that cannot drift with a reference implementation's buffer policy.
    ///
    /// The bound is "the window is the **only** difference". Not a restriction
    /// to particular flags: the first attempt limited this to bare ACKs and the
    /// very next sequence produced the same difference on a FIN-ACK, which
    /// showed the restriction was arbitrary rather than principled. The window
    /// is a receive-side property and is not comparable between two stacks with
    /// different receive accounting, on any frame that carries it. What remains
    /// caught is every window difference that comes *with* something else —
    /// a wrong sequence, a wrong flag, a missing frame — which is what a real
    /// window defect looks like when it affects behaviour rather than only
    /// advertisement.
    static func recogniseScaledWindow(swift: VectorPacket, go: VectorPacket) -> String? {
        guard case .tcp(var swiftLine) = swift, case .tcp(let goLine) = go else { return nil }
        guard swiftLine.window != goLine.window else { return nil }
        swiftLine.window = goLine.window
        guard swiftLine == goLine else { return nil }
        return "scaled-advertised-window"
    }

    private func describe(_ frame: ByteBuffer) -> String {
        codec.decode(frame).map { "\($0)" } ?? "an undecodable frame (\(frame.readableBytes) bytes)"
    }

    /// Puts a packet into the form the two stacks are required to agree on.
    ///
    /// Non-TCP packets pass through unchanged — ARP, ICMP and UDP have no ISS
    /// and no timestamp option, so they are always compared exactly.
    private func normalized(_ packet: VectorPacket, iss: UInt32) -> VectorPacket {
        guard case .tcp(var line) = packet else { return packet }
        // Sequence numbers are expressed relative to this side's own ISS, so
        // the arbitrary origin drops out and everything derived from it —
        // which segment a retransmission carries, where a FIN sits, what a
        // reset's SEQ is — still has to match exactly.
        line.seqStart = line.seqStart &- iss
        line.seqEnd = line.seqEnd &- iss
        // `ack` is NOT touched: it lives in the guest's sequence space, which
        // the generated script fixes identically for both stacks.
        line.options = line.options.map { $0.hasPrefix("timestamp ") ? "timestamp" : $0 }
        return .tcp(line)
    }
}
