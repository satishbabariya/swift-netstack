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

/// The application side of a script: what `write <n>` and `close` lines drive.
///
/// Two closures rather than a reference to the endpoint, because the runner
/// deliberately knows nothing about TCP — it drives a `Stack` through a link,
/// and which endpoint a script's `write` reaches is the harness's business.
/// Both are `throws`: a refused write (`.wouldBlock`) or a refused close is a
/// divergence the script must not survive, and a script that quietly wrote
/// nothing would then fail on the *missing frame* two lines later, naming the
/// wrong line.
struct VectorApplication {
    var write: (Int) throws -> Void
    var close: () throws -> Void
}

/// Thrown when a script contains an application call and `run` was given no
/// `VectorApplication` to drive it.
///
/// Not a `VectorMismatch`: nothing about the stack is in question. Without it
/// the call would be silently skipped, and the script would fail on the frame
/// the write was supposed to produce — reporting a line that is correct, about
/// a stack that is correct, because of a harness that forgot to pass an
/// argument.
struct VectorScriptNeedsAnApplication: Error, CustomStringConvertible {
    var line: Int

    var description: String {
        "line \(line): this script makes an application call, but `run` was given no VectorApplication to drive it"
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
///
/// STAMPING GRANULARITY: a frame's timestamp is made true BY CONSTRUCTION,
/// not by convention. Advancing straight to an event's declared time in one
/// jump and draining once afterward would stamp every frame found with that
/// jump's DESTINATION, regardless of when inside the jump it actually
/// appeared — invisible as long as a vector only ever crosses one timer
/// deadline per step, but a silent false-positive the moment it crosses
/// two (exactly what an RTO vector does: a stack that retransmits too
/// early would get its early frame stamped with the *correct*, later,
/// destination time, matching the script by accident). So `run` never
/// jumps straight to an event's time: it advances in `subStep`-sized
/// increments and drains after each one, so a frame's stamp is always the
/// increment boundary nearest its true emission time — never a distant
/// jump's endpoint it merely happened to be swept up in. Deliberately not
/// solved by documentation ("checkpoint a script at every emission time")
/// or a stricter assertion ("at most one frame per step", which would
/// wrongly reject a stack that legitimately emits two frames from one
/// inbound packet): both rely on someone remembering or guessing correctly,
/// where this makes the property structural instead.
struct VectorRunner {
    var script: VectorScript
    var codec: VectorFrames

    /// The granularity `run` advances the clock and loop in, rather than
    /// jumping straight to each event's declared time. 1 ms: fine enough
    /// that no vector in this plan (RTO deadlines are on the order of
    /// hundreds of milliseconds to tens of seconds) can hide two distinct
    /// emissions behind one stamp, coarse enough that even a 60 s gap costs
    /// only 60,000 loop iterations of an integer add plus a `loop.run()`
    /// with nothing scheduled — measured at a few milliseconds of wall time
    /// for the existing suite, immaterial next to the run times already
    /// logged for this package's cache/reassembler stress tests.
    private static let subStep = TimeAmount.milliseconds(1)

    func run(
        against stack: Stack, link: RecordingEndpoint, clock: ManualClock, loop: EmbeddedEventLoop,
        application: VectorApplication? = nil
    ) throws {
        var elapsed = TimeAmount.zero
        var pending: [TimedFrame] = []

        func drainAndStamp(sourceLine: Int) {
            for frame in link.drainTransmitted() {
                pending.append(TimedFrame(frame: frame, emittedAt: elapsed, sourceLine: sourceLine))
            }
        }

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
            // currently is — in `subStep` increments, draining (and
            // stamping with the increment's own time, not the eventual
            // destination) after each one. See the STAMPING GRANULARITY
            // note on this type for why a single jump is not enough.
            while elapsed < event.time {
                let step = min(Self.subStep, event.time - elapsed)
                clock.advance(by: step)
                loop.advanceTime(by: step)
                elapsed += step
                drainAndStamp(sourceLine: event.sourceLine)
            }

            // An application call and an inbound frame are both "something
            // enters the stack now", and both are followed by the same drain —
            // the frames a `write` produces are captured exactly as the frames
            // an injected segment produces are.
            switch event.packet {
            case .applicationWrite(let bytes):
                guard let application else { throw VectorScriptNeedsAnApplication(line: event.sourceLine) }
                try application.write(bytes)
            case .applicationClose:
                guard let application else { throw VectorScriptNeedsAnApplication(line: event.sourceLine) }
                try application.close()
            case .tcp, .icmpEcho, .icmpUnreachable, .udp, .arpRequest, .arpReply:
                if event.direction == .inbound {
                    let frame = try codec.encode(event.packet, direction: .inbound)
                    link.inject(frame)
                }
            }

            // Drain and stamp again after the event's own action — this is
            // what captures a frame emitted synchronously by an `.inbound`
            // injection (the sub-step loop above only covers time ADVANCE;
            // an injection at unchanged time needs its own drain).
            drainAndStamp(sourceLine: event.sourceLine)

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
        // — buffered-but-unconsumed, or freshly transmitted — remains. This
        // final drain is defensive: every event iteration above already
        // drains after both its sub-step advances and its own action, so
        // nothing should genuinely surface here with no line of its own —
        // but if it does, it is attributed to the last event actually
        // processed, the closest thing available to provenance.
        let final = link.drainTransmitted().map {
            TimedFrame(frame: $0, emittedAt: elapsed, sourceLine: script.events.last?.sourceLine ?? 0)
        }
        // Each leftover frame reports the source line whose processing
        // actually produced it (see `TimedFrame.sourceLine`), not the last
        // line of the script regardless of where the extra frame came from.
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
}
