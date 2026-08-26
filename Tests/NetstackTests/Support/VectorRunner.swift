import NIOCore
import NIOEmbedded

@testable import Netstack

/// Thrown by `VectorRunner.run` on the first point where the stack's actual
/// behaviour diverges from what the script says it must be.
///
/// `line` is the 1-based position of the diverging event within
/// `VectorScript.events` — the only numbering the parser preserves, since
/// blank lines and comments are dropped rather than counted. `expected` and
/// `actual` are rendered eagerly (not lazily, from the packets/frames
/// themselves) so the failure message always says what diverged, which is
/// the entire point of building this as an instrument rather than a
/// pass/fail bit.
struct VectorMismatch: Error, CustomStringConvertible {
    var line: Int
    var expected: String
    var actual: String

    var description: String {
        "line \(line): expected \(expected), got \(actual)"
    }
}

/// Plays a `VectorScript` against a live `Stack` and checks that every
/// `.expectedOutbound` event is matched, in order, by a real frame the stack
/// emits — compared SEMANTICALLY (decoded back to a `VectorPacket`), never
/// byte-for-byte. Byte comparison is not viable here: IP identification,
/// TTL and checksums legitimately differ between a script's idea of a frame
/// and what the stack actually produces, and `VectorFrames`'s TCP source and
/// destination ports are fixed constants that never round-trip through
/// `TCPLine` at all (see `VectorFrames`'s own doc comment) — a byte compare
/// would fail on that alone, for reasons that have nothing to do with
/// whether the stack is correct.
struct VectorRunner {
    var script: VectorScript
    var codec: VectorFrames

    /// Frames drained from the link but not yet matched against an event.
    /// Kept across events (not re-drained per event) so several
    /// `.expectedOutbound` lines in a row correctly consume frames the stack
    /// emitted together from a single `.inbound` injection, one at a time,
    /// rather than each line silently re-draining and only ever seeing
    /// whatever arrived most recently.
    private func nextTransmittedFrame(_ pending: inout [ByteBuffer], link: RecordingEndpoint) -> ByteBuffer? {
        if pending.isEmpty {
            pending = link.drainTransmitted()
        }
        guard !pending.isEmpty else { return nil }
        return pending.removeFirst()
    }

    func run(against stack: Stack, link: RecordingEndpoint, clock: ManualClock, loop: EmbeddedEventLoop) throws {
        var elapsed = TimeAmount.zero
        var pending: [ByteBuffer] = []

        for (index, event) in script.events.enumerated() {
            let lineNumber = index + 1

            // Advance BOTH the clock and the loop to this event's time, or
            // scheduled work (the maintenance timer) and timer deadlines
            // disagree about what time it currently is.
            let delta = event.time - elapsed
            if delta > .zero {
                clock.advance(by: delta)
                loop.advanceTime(by: delta)
            }
            elapsed = event.time

            switch event.direction {
            case .inbound:
                let frame = try codec.encode(event.packet, direction: .inbound)
                link.inject(frame)

            case .expectedOutbound:
                guard let frame = nextTransmittedFrame(&pending, link: link) else {
                    throw VectorMismatch(line: lineNumber, expected: "\(event.packet)", actual: "no frame")
                }
                // `decode` returning nil means "cannot classify" — that must
                // never be treated as a match, only ever as a mismatch.
                guard let decoded = codec.decode(frame) else {
                    throw VectorMismatch(line: lineNumber, expected: "\(event.packet)", actual: "an undecodable frame")
                }
                guard decoded == event.packet else {
                    throw VectorMismatch(line: lineNumber, expected: "\(event.packet)", actual: "\(decoded)")
                }
            }
        }

        // A stack that emits MORE than the script accounts for is also
        // wrong: drain once more after the last event and fail if anything
        // — buffered-but-unconsumed, or freshly transmitted — remains.
        let leftover = pending + link.drainTransmitted()
        guard leftover.isEmpty else {
            let decoded = leftover.map { codec.decode($0).map { "\($0)" } ?? "an undecodable frame" }
            throw VectorMismatch(
                line: script.events.count,
                expected: "no further frames",
                actual: "\(leftover.count) extra frame(s): \(decoded.joined(separator: ", "))")
        }
    }
}
