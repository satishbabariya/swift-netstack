import NIOCore
import NIOEmbedded

@testable import Netstack

/// Thrown by `VectorRunner.run` on the first point where the stack's actual
/// behaviour diverges from what the script says it must be.
///
/// `line` is the 1-based SOURCE line (`VectorEvent.sourceLine`), not the
/// index into `VectorScript.events` — the validation vectors are
/// deliberately comment-heavy, so those two numbers routinely disagree, and
/// only the source line is what a reader staring at the `.vec` file can
/// actually use. `expected` and `actual` are rendered eagerly (not lazily,
/// from the packets/frames themselves) so the failure message always says
/// what diverged, which is the entire point of building this as an
/// instrument rather than a pass/fail bit. Both strings include emission
/// time as well as content: a frame can diverge on either axis
/// independently (right bytes at the wrong time is exactly the failure mode
/// a retransmission vector exists to catch), so the message says which.
struct VectorMismatch: Error, CustomStringConvertible {
    var line: Int
    var expected: String
    var actual: String

    var description: String {
        "line \(line): expected \(expected), got \(actual)"
    }
}

/// Thrown when a script's own events are not in non-decreasing time order.
///
/// This is a malformed-script condition, not a stack divergence — nothing
/// about the frames the stack emitted is in question — so it gets its own
/// type rather than overloading `VectorMismatch`, whose `expected`/`actual`
/// are about wire content. Left unchecked, `VectorRunner.run` would advance
/// `elapsed` backwards, and every event after the offending line would have
/// its delta computed against a floor that no longer matches the time the
/// clock and loop were actually advanced to — silently, with no error at
/// the point the file was actually wrong.
struct VectorScriptOutOfOrder: Error, CustomStringConvertible {
    var line: Int
    var previous: TimeAmount
    var attempted: TimeAmount

    var description: String {
        "line \(line): time \(attempted) is before the previous event's time \(previous) — a script's events must be non-decreasing in time"
    }
}

/// A frame drained from the link, stamped with the logical time it was
/// observed at and the script event whose processing produced it.
private struct TimedFrame {
    var frame: ByteBuffer
    var emittedAt: TimeAmount
    /// The source line of the event being processed when this frame was
    /// drained — not necessarily the line that "caused" it in any deep
    /// sense, but the closest thing to provenance the runner can report: it
    /// is either the `.inbound` line whose injection produced this frame
    /// synchronously, or the line whose time advance caused a timer
    /// (maintenance, retransmission, ...) to fire.
    var sourceLine: Int
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
///
/// Content equality alone is not enough, though: a frame that is
/// byte-for-byte (semantically) what an `.expectedOutbound` line wants, but
/// arrived at the wrong logical time, is exactly the failure mode a
/// retransmission vector exists to catch (fired too early; or never fired,
/// with an unrelated stale duplicate sitting in the buffer instead). So
/// every frame drained from the link is stamped with the logical time it
/// was observed at, and a match requires both the content AND the emission
/// time to agree with the expectation.
///
/// TOLERANCE POLICY: emission time must match EXACTLY, not "close enough".
/// This is deliberate, not an oversight. Both `ManualClock` and
/// `EmbeddedEventLoop` are advanced by this runner itself, one script event
/// at a time, and neither one ever moves except when `run` tells it to —
/// there is no wall-clock jitter, no scheduler noise, nothing that could
/// make a correct stack miss an exact time by a little. Any deviation, no
/// matter how small, reflects a real disagreement between the script and
/// the stack about when something should happen, which is precisely what
/// this instrument exists to surface. A tolerance window would only ever
/// serve to hide that disagreement instead of reporting it.
struct VectorRunner {
    var script: VectorScript
    var codec: VectorFrames

    func run(against stack: Stack, link: RecordingEndpoint, clock: ManualClock, loop: EmbeddedEventLoop) throws {
        var elapsed = TimeAmount.zero
        var pending: [TimedFrame] = []

        for event in script.events {
            // A script whose events go backwards in time is malformed —
            // reject it outright rather than let `elapsed` drift out of
            // sync with what the clock and loop were actually advanced to.
            // See `VectorScriptOutOfOrder`'s doc comment.
            guard event.time >= elapsed else {
                throw VectorScriptOutOfOrder(line: event.sourceLine, previous: elapsed, attempted: event.time)
            }

            // Advance BOTH the clock and the loop to this event's time, or
            // scheduled work (the maintenance timer, a retransmission
            // timer) and timer deadlines disagree about what time it
            // currently is.
            let delta = event.time - elapsed
            if delta > .zero {
                clock.advance(by: delta)
                loop.advanceTime(by: delta)
            }
            elapsed = event.time

            if event.direction == .inbound {
                let frame = try codec.encode(event.packet, direction: .inbound)
                link.inject(frame)
            }

            // Drain and stamp EVERY iteration, regardless of direction —
            // not only when an `.expectedOutbound` line needs a frame. This
            // is what gives frames their timestamp: `RecordingEndpoint`
            // itself carries no timing, so `elapsed` (the time this
            // iteration just advanced to) is the only granularity available
            // to attribute "when" a frame was actually emitted, whether it
            // came from the `.inbound` injection just above or from a timer
            // that fired as a side effect of advancing the clock/loop to
            // reach this event's time.
            for frame in link.drainTransmitted() {
                pending.append(TimedFrame(frame: frame, emittedAt: elapsed, sourceLine: event.sourceLine))
            }

            if event.direction == .expectedOutbound {
                guard !pending.isEmpty else {
                    throw VectorMismatch(line: event.sourceLine, expected: "\(event.packet) at \(event.time)", actual: "no frame")
                }
                let timed = pending.removeFirst()
                // `decode` returning nil means "cannot classify" — that
                // must never be treated as a match, only ever as a
                // mismatch. The raw bytes are included because `decode`
                // returns nil for at least five structurally different
                // reasons (unknown ethertype, ARP parse failure, IP parse
                // failure, unknown protocol number, bad checksum), and
                // without them a debugger has nothing to work from.
                guard let decoded = codec.decode(timed.frame) else {
                    throw VectorMismatch(
                        line: event.sourceLine, expected: "\(event.packet) at \(event.time)",
                        actual: "an undecodable frame emitted at \(timed.emittedAt): \(timed.frame)")
                }
                guard decoded == event.packet, timed.emittedAt == event.time else {
                    throw VectorMismatch(
                        line: event.sourceLine, expected: "\(event.packet) at \(event.time)",
                        actual: "\(decoded) at \(timed.emittedAt)")
                }
            }
        }

        // A stack that emits MORE than the script accounts for is also
        // wrong: drain once more after the last event and fail if anything
        // — buffered-but-unconsumed, or freshly transmitted — remains.
        // Each leftover frame reports the source line whose processing
        // actually produced it (see `TimedFrame.sourceLine`), not the last
        // line of the script regardless of where the extra frame came from.
        let final = link.drainTransmitted().map { TimedFrame(frame: $0, emittedAt: elapsed, sourceLine: event(at: elapsed)) }
        let leftover = pending + final
        guard leftover.isEmpty else {
            let rendered = leftover.map { timed -> String in
                let content = codec.decode(timed.frame).map { "\($0)" } ?? "an undecodable frame: \(timed.frame)"
                return "line \(timed.sourceLine): \(content) at \(timed.emittedAt)"
            }
            throw VectorMismatch(
                line: leftover[0].sourceLine,
                expected: "no further frames",
                actual: "\(leftover.count) extra frame(s): \(rendered.joined(separator: "; "))")
        }
    }

    /// The source line of the last event at or before `time` — used only to
    /// attribute a frame drained in the FINAL post-loop drain (which has no
    /// event of its own) to the closest thing it has to provenance: the
    /// last event actually processed.
    private func event(at time: TimeAmount) -> Int {
        script.events.last(where: { $0.time <= time })?.sourceLine ?? script.events.last?.sourceLine ?? 0
    }
}
