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
/// `guard let harness = differentialHarnessPathIfBuilt() else { return }`.
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

/// Everything that can go wrong running the harness subprocess itself, as
/// distinct from the two stacks disagreeing about what to emit — the
/// latter is a `DifferentialDivergence`, reported through `compare`'s
/// return value rather than thrown, because disagreement is the expected
/// output of this instrument, not a failure of the instrument.
enum DifferentialRunError: Error, CustomStringConvertible {
    case frameAdvanceCountMismatch(frames: Int, advanceMs: Int)
    case harnessLaunchFailed(String)
    case harnessExitedNonZero(status: Int32, stderr: String)
    case malformedHarnessOutput(String)

    var description: String {
        switch self {
        case .frameAdvanceCountMismatch(let frames, let advanceMs):
            return "frames (\(frames)) and advanceMs (\(advanceMs)) must be the same length"
        case .harnessLaunchFailed(let reason):
            return "failed to launch the differential harness: \(reason)"
        case .harnessExitedNonZero(let status, let stderr):
            return "differential harness exited with status \(status): \(stderr)"
        case .malformedHarnessOutput(let reason):
            return "differential harness produced unparsable output: \(reason)"
        }
    }
}

/// One point where what the Swift stack emitted and what the Go (gVisor)
/// stack emitted disagree — including the case where one stack emitted a
/// frame at an index the other has nothing for at all.
///
/// `swiftBytes`/`goBytes` are `nil` exactly when that side has no frame at
/// `frameIndex` (the other stack emitted more frames overall); `description`
/// is rendered eagerly, decoded back to a `VectorPacket` where possible, so
/// a failing `#expect` names what actually diverged (e.g. "an ICMP echo
/// reply with the wrong sequence number") rather than forcing a reader to
/// decode raw wire bytes by hand.
struct DifferentialDivergence: CustomStringConvertible {
    var frameIndex: Int
    var swiftBytes: ByteBuffer?
    var goBytes: ByteBuffer?
    var description: String
}

/// Runs the same sequence of frames through gVisor's Go TCP/IP stack (via
/// the `differential/harness` binary, Task 4) and through a live Swift
/// `Stack`, and reports every point where what the two stacks emitted
/// disagrees.
///
/// PERMITTED DIVERGENCES (spec §8.2): initial sequence numbers and
/// timestamp option values. Everything else is a defect. Two
/// independently-implemented stacks never choose the same ISN, so raw TCP
/// sequence/ack numbers, and timestamp option values, are masked to a
/// fixed, comparable form before comparison — see `normalized(_:)`. Those
/// two are the only things actually excluded from the diff.
///
/// ACK-coalescing decisions (whether a stack piggybacks an ACK on data or
/// sends it separately) are ALSO a permitted divergence per spec §8.2, but
/// this type does NOT mask them: nothing in this task's vectors exercises
/// that path (Task 5 is validated only against ARP and ICMP, which carry no
/// TCP fields at all), so a frame-count difference caused purely by
/// ACK-coalescing will currently be reported as a divergence rather than
/// silently permitted. This is the safe failure direction — a permitted
/// divergence surfacing as a false-positive defect is noisy but harmless,
/// whereas masking a real defect would be dangerous — but it is still
/// wrong, and it is documented here rather than guessed at. Whichever TCP
/// task first produces such a frame-count difference must implement the
/// masking then, against a real example it can falsify.
///
/// THE BUG THIS TYPE EXISTS TO NOT HAVE: comparing `zip(swiftFrames,
/// goFrames)` and silently ignoring whichever list has a longer tail. If
/// one stack emits three frames and the other emits two, `zip` compares
/// two pairs, finds them equal, and reports no divergence — every future
/// TCP comparison would then pass vacuously. `diverge(swiftFrames:goFrames:)`
/// below iterates to `max`, not `min`, of the two counts specifically to
/// avoid this; `theDifferentialDetectsADeliberateDivergence` in
/// `DifferentialValidationTests.swift` exists to prove it actually does.
struct DifferentialRun {
    var harnessPath: String
    var codec: VectorFrames

    init(harnessPath: String, codec: VectorFrames) {
        self.harnessPath = harnessPath
        self.codec = codec
    }

    /// Injects `frames[i]` into both stacks and advances both by
    /// `advanceMs[i]` milliseconds, one index at a time — mirroring exactly
    /// what the Go harness does internally (see `differential/harness/main.go`'s
    /// `run`) so the two sides collect frames under the same step-by-step
    /// model, not just the same total input.
    func compare(
        frames: [ByteBuffer], advanceMs: [Int],
        against stack: Stack, link: RecordingEndpoint, clock: ManualClock, loop: EmbeddedEventLoop
    ) throws -> [DifferentialDivergence] {
        guard frames.count == advanceMs.count else {
            throw DifferentialRunError.frameAdvanceCountMismatch(frames: frames.count, advanceMs: advanceMs.count)
        }

        let goFrames = try runHarness(frames: frames, advanceMs: advanceMs)
        let swiftFrames = driveSwift(frames: frames, advanceMs: advanceMs, link: link, clock: clock, loop: loop)
        return diverge(swiftFrames: swiftFrames, goFrames: goFrames)
    }

    // MARK: - Swift side

    private func driveSwift(
        frames: [ByteBuffer], advanceMs: [Int], link: RecordingEndpoint, clock: ManualClock, loop: EmbeddedEventLoop
    ) -> [ByteBuffer] {
        var emitted: [ByteBuffer] = []
        for (frame, ms) in zip(frames, advanceMs) {
            link.inject(frame)
            let step = TimeAmount.milliseconds(Int64(ms))
            // Advance BOTH the clock and the loop — a timer keyed off one
            // but not the other disagrees with itself about what time it is.
            clock.advance(by: step)
            loop.advanceTime(by: step)
            emitted.append(contentsOf: link.drainTransmitted())
        }
        // Defensive final drain: every step above already drains after its
        // own advance, so nothing should genuinely surface here — but a
        // frame with no step to attribute it to is exactly the kind of bug
        // this instrument exists to catch, not paper over by never checking.
        emitted.append(contentsOf: link.drainTransmitted())
        return emitted
    }

    // MARK: - Go side

    private struct HarnessRequest: Encodable {
        var frames: [String]
        var advanceMs: [Int]
    }

    private struct HarnessResponse: Decodable {
        var emitted: [String]
    }

    private func runHarness(frames: [ByteBuffer], advanceMs: [Int]) throws -> [ByteBuffer] {
        let request = HarnessRequest(frames: frames.map(Self.base64), advanceMs: advanceMs)
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

        // Write-then-read, not concurrent: the request bodies this
        // instrument sends are a handful of small frames (kilobytes at
        // most), nowhere near a pipe's ~64KB buffer, so this cannot
        // deadlock the way it could for a general-purpose subprocess driver
        // with unbounded input.
        try stdin.fileHandleForWriting.write(contentsOf: requestData)
        try stdin.fileHandleForWriting.close()

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

        return try response.emitted.map { encoded in
            guard let data = Data(base64Encoded: encoded) else {
                throw DifferentialRunError.malformedHarnessOutput("frame is not valid base64: \(encoded)")
            }
            var buffer = ByteBufferAllocator().buffer(capacity: data.count)
            buffer.writeBytes(data)
            return buffer
        }
    }

    private static func base64(_ buffer: ByteBuffer) -> String {
        let bytes = buffer.getBytes(at: buffer.readerIndex, length: buffer.readableBytes) ?? []
        return Data(bytes).base64EncodedString()
    }

    // MARK: - Comparison

    /// Iterates to `max(swiftFrames.count, goFrames.count)`, never `min` —
    /// see this type's doc comment for exactly the bug that guards against.
    private func diverge(swiftFrames: [ByteBuffer], goFrames: [ByteBuffer]) -> [DifferentialDivergence] {
        var divergences: [DifferentialDivergence] = []
        for index in 0..<max(swiftFrames.count, goFrames.count) {
            let swiftFrame = index < swiftFrames.count ? swiftFrames[index] : nil
            let goFrame = index < goFrames.count ? goFrames[index] : nil

            switch (swiftFrame, goFrame) {
            case (nil, nil):
                continue  // unreachable: `index` never exceeds both counts at once
            case (let swift?, nil):
                divergences.append(
                    DifferentialDivergence(
                        frameIndex: index, swiftBytes: swift, goBytes: nil,
                        description: "frame \(index): Swift emitted \(describe(swift)) with no matching Go frame"))
            case (nil, let go?):
                divergences.append(
                    DifferentialDivergence(
                        frameIndex: index, swiftBytes: nil, goBytes: go,
                        description: "frame \(index): Go emitted \(describe(go)) with no matching Swift frame"))
            case (let swift?, let go?):
                if let divergence = compareFrames(index: index, swift: swift, go: go) {
                    divergences.append(divergence)
                }
            }
        }
        return divergences
    }

    private func compareFrames(index: Int, swift: ByteBuffer, go: ByteBuffer) -> DifferentialDivergence? {
        // `decode` returning nil means "cannot classify" — that must never
        // be treated as a match, not even against another frame this codec
        // also cannot classify: two frames a codec cannot understand are
        // never known to be the same frame.
        guard let swiftPacket = codec.decode(swift) else {
            return DifferentialDivergence(
                frameIndex: index, swiftBytes: swift, goBytes: go,
                description:
                    "frame \(index): Swift emitted an undecodable frame (\(swift.readableBytes) bytes); Go emitted \(describe(go))")
        }
        guard let goPacket = codec.decode(go) else {
            return DifferentialDivergence(
                frameIndex: index, swiftBytes: swift, goBytes: go,
                description:
                    "frame \(index): Go emitted an undecodable frame (\(go.readableBytes) bytes); Swift emitted \(describe(swift))")
        }

        guard normalized(swiftPacket) == normalized(goPacket) else {
            return DifferentialDivergence(
                frameIndex: index, swiftBytes: swift, goBytes: go,
                description: "frame \(index): swift=\(swiftPacket) go=\(goPacket)")
        }
        return nil
    }

    private func describe(_ frame: ByteBuffer) -> String {
        codec.decode(frame).map { "\($0)" } ?? "an undecodable frame (\(frame.readableBytes) bytes)"
    }

    /// Masks the permitted divergences named on this type's doc comment.
    /// Non-TCP packets pass through unchanged — ARP, ICMP and UDP have no
    /// ISN, no timestamp option and no ACK to mask, so they are always
    /// compared exactly.
    private func normalized(_ packet: VectorPacket) -> VectorPacket {
        guard case .tcp(var line) = packet else { return packet }
        // Two independently-implemented stacks never agree on an ISN;
        // only the segment's length is comparable, and it is already
        // carried separately via `payloadLength`.
        line.seqStart = 0
        line.seqEnd = UInt32(line.payloadLength)
        line.ack = line.ack == nil ? nil : 0
        // Timestamp option VALUES are permitted to differ; the option's
        // PRESENCE is not masked away — a stack that drops it entirely is
        // a real divergence.
        line.options = line.options.map { $0.hasPrefix("timestamp ") ? "timestamp" : $0 }
        return .tcp(line)
    }
}
