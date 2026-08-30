import Foundation
import NIOCore
import NIOEmbedded
import Testing

@testable import Netstack

// The M4 differential: seeded, generated TCP sequences played against both
// this stack and gVisor's, frame for frame, step for step.
//
// The vector files (`tcp-handshake.vec`, `tcp-data.vec`, `tcp-close.vec`) say
// what this stack must do; this file asks a stack nobody here wrote whether it
// agrees, over sequences nobody here thought of. Every divergence it found is
// recorded in `differential/README.md`, together with which stack was judged
// correct and why — and every one judged a defect was frozen as a vector
// BEFORE the code was changed, so it cannot silently return.

// MARK: - Fixture

private let diffGateway = IPv4Address("192.168.127.1")!
private let diffGuest = IPv4Address("192.168.127.2")!
private let diffGatewayMAC = MACAddress("5a:94:ef:e4:0c:ee")!
private let diffGuestMAC = MACAddress("0a:0b:0c:0d:0e:0f")!

/// `VectorFrames` fixes every TCP line's ports at 50000 -> 8080, and the Go
/// harness listens on 8080 for the same reason. A listener anywhere else would
/// describe a connection neither side addresses.
private let diffLocalPort: UInt16 = 8080

/// This stack's ISS for the differential. Deliberately NOT zero: the two
/// stacks' acknowledgement numbers have to be shifted into each side's own
/// sequence space (`DifferentialRun.shiftAcknowledgement`), and a zero ISS on
/// this side would make that shift a no-op here and leave it exercised on one
/// side only.
private let diffISS: UInt32 = 1000

private func diffCodec() -> VectorFrames {
    VectorFrames(gateway: diffGateway, gatewayMAC: diffGatewayMAC, guest: diffGuest, guestMAC: diffGuestMAC)
}

/// A box the application closures can write into without capturing the target
/// they are stored on.
private final class FailureBox {
    private(set) var messages: [String] = []
    func record(_ message: String) { messages.append(message) }
}

private final class DiffTarget {
    let loop: EmbeddedEventLoop
    let clock: LoopClock
    let link: RecordingEndpoint
    let stack: Stack
    let endpoint: TCPEndpoint
    let application: VectorApplication
    /// Bytes handed to `onData`. Not compared against gVisor — the Go harness
    /// drains its socket buffer and reports nothing about it — but kept so a
    /// divergence can be read next to what the application actually saw.
    private(set) var deliveredBytes = 0

    init() throws {
        loop = EmbeddedEventLoop()
        clock = LoopClock(loop: loop)
        link = RecordingEndpoint(eventLoop: loop, linkAddress: diffGatewayMAC)
        stack = Stack(
            link: link,
            configuration: Stack.Configuration(gatewayAddress: diffGateway, subnet: IPv4Subnet(cidr: "192.168.127.0/24")!),
            clock: clock)
        stack.start()
        stack.arpCache.record(diffGuest, diffGuestMAC)

        // Delayed acknowledgements OFF for the comparison, and this is a stated
        // configuration difference rather than a mask.
        //
        // The two stacks flush held acknowledgements on different schedules, so
        // their per-step frame lists stop lining up in BOTH directions — a held
        // acknowledgement is released by whichever step advance covers its
        // deadline, not by the step its segment arrived in. No recogniser fixes
        // that without also masking a spurious acknowledgement this stack
        // invented. Turning the delay off restores alignment and costs the run
        // exactly one thing: sub-500 ms acknowledgement timing, which is pinned
        // in `tcp-data.vec` against a fixed peer instead.
        let endpoint = TCPEndpoint(
            stack: stack, initialSequenceNumbers: FixedInitialSequenceNumbers(diffISS),
            delayedAckTimeout: .zero, nagleDisabled: true)
        try endpoint.bind(address: diffGateway, port: diffLocalPort)
        try endpoint.listen(backlog: 64)
        self.endpoint = endpoint

        let allocator = ByteBufferAllocator()
        let failures = FailureBox()
        application = VectorApplication(
            write: { bytes in
                var payload = allocator.buffer(capacity: bytes)
                payload.writeRepeatingByte(0, count: bytes)
                do { try endpoint.send(payload) } catch { failures.record("write \(bytes): \(error)") }
            },
            close: { endpoint.close() })
        self.failures = failures

        // Reads on every signal. `onData` is a readiness notification now, and
        // a differential target that never read would advertise a shrinking
        // window and stop the peer — measuring backpressure instead of TCP.
        endpoint.onData = { [weak self, weak endpoint] in
            guard let endpoint else { return }
            self?.deliveredBytes += endpoint.read().readableBytes
        }
    }

    /// Application calls this stack refused.
    ///
    /// Recorded rather than thrown, and then asserted empty, because the Go
    /// harness treats a refused call as a hard error: a generated sequence in
    /// which one side accepted a write and the other refused it is not a wire
    /// divergence at all, it is two different programs, and it must fail as
    /// such rather than quietly produce a diff nobody can read.
    private var failures = FailureBox()
    var refusedActions: [String] { failures.messages }

    /// Re-assert the guest's link address before every step.
    ///
    /// `ARPCache` entries live sixty seconds and an RTO backoff ladder crosses
    /// that inside a single sequence, at which point this stack correctly
    /// emits an ARP request and no TCP segment at all — right in production,
    /// and indistinguishable from a TCP divergence in a diff. The Go side is
    /// held to the same shape by a STATIC neighbour entry (see
    /// `differential/harness/main.go`), so neither stack emits ARP during a
    /// generated sequence and an ARP frame in a diff is a real divergence
    /// rather than an expected one. This is the "keep both caches warm" arm of
    /// the choice, taken deliberately over "treat an ARP exchange as a
    /// recognised difference": a recognised difference on every long sequence
    /// is noise, and noise is how a real divergence gets waved through.
    func keepNeighbourWarm() {
        stack.arpCache.record(diffGuest, diffGuestMAC)
    }
}

// MARK: - The generator

/// A deterministic 64-bit generator. SplitMix64, written out here rather than
/// taken from `SystemRandomNumberGenerator` because the whole point is that a
/// divergence is reproducible from its seed alone, on any machine, forever.
private struct SplitMix64: RandomNumberGenerator {
    private var state: UInt64
    init(seed: UInt64) { state = seed }

    mutating func next() -> UInt64 {
        state &+= 0x9e37_79b9_7f4a_7c15
        var z = state
        z = (z ^ (z >> 30)) &* 0xbf58_476d_1ce4_e5b9
        z = (z ^ (z >> 27)) &* 0x94d0_49bb_1331_11eb
        return z ^ (z >> 31)
    }
}

/// What the generator is allowed to produce, and why each bound is there.
///
/// Every one of these is a deliberate, recorded restriction of the search
/// space, not an accident — see `differential/README.md`, "What the generator
/// does not vary".
private enum DiffLimits {
    /// gVisor's `tcp.SegOverheadSize`, measured at 628 bytes for the pinned
    /// gVisor version. A segment smaller than this does not move gVisor's
    /// advertised right edge (`rcv.go`'s `toGrow` gate), so its window falls
    /// while ours — which has no receive buffer to fill — stays at its
    /// ceiling. Every data-bearing segment is at least this large so the
    /// window field stays exactly comparable on every frame after the SYN-ACK.
    static let minimumDataSegment = 628
    /// One MSS at a 1500-byte MTU.
    static let maximumDataSegment = 1460
    /// How far above RCV.NXT an out-of-order segment may land. gVisor's right
    /// edge after the first in-order delivery sits far beyond the 16-bit
    /// window it advertises, so it would accept out-of-order data this stack
    /// correctly refuses as outside the window it promised. Staying well
    /// inside both keeps the comparison about ordering rather than about
    /// which stack honours its own advertisement. The right-edge trim itself
    /// is pinned by `tcp-data.vec`'s `right-edge-trim` scenario.
    static let maximumGapAhead = 20000
    /// The smallest window the guest ever advertises. Above zero-window
    /// territory by a wide margin, so no generated sequence ever enters RFC
    /// 9293 §3.8.6.1's persist state.
    ///
    /// This floor predates the persist timer, and it stays now that there is
    /// one — for a different and better reason than "this stack has no probe to
    /// compare". Probe *timing* is a SHOULD in both documents that specify it
    /// (RFC 9293 SHLD-29 and SHLD-30) and the interval ceiling is explicitly
    /// left open: RFC 1122 §4.2.2.17 says "possibly with some maximum interval
    /// not specified here". Two conformant stacks may therefore probe on
    /// different ladders, and a divergence between them would be a report about
    /// nothing. Persist is pinned by `tcp-data.vec`'s two probe scenarios and by
    /// `TCPSenderTests`, and **is not differentially verified** — see
    /// `differential/README.md`.
    static let minimumOfferedWindow = 4096

    /// What the Timestamps option costs a data segment: ten bytes plus two of
    /// padding. Mirrors `TCPEndpoint.timestampOptionBytes`, and is stated here
    /// rather than read from it so that a change to one is a visible
    /// disagreement rather than a silent shift in what this generator produces.
    static let timestampOptionBytes = 12

    /// What EVERY data segment's options cost on a connection using both
    /// timestamps and SACK: twelve for `NOP NOP TS`, twenty-eight for
    /// `NOP NOP SACK` with the three blocks that fit beside it.
    ///
    /// Forty, which is the whole options area — both stacks reserve the worst
    /// case rather than the current one, because a segment cut today may be
    /// retransmitted while more blocks are being reported. Stated here rather
    /// than read from the stack, for the same reason as the constant above: a
    /// change to one should be a visible disagreement, not a silent shift in
    /// what this generator produces.
    static let dataSegmentOptionBytes = 40
    /// The largest advance a single step may make, in milliseconds. Long
    /// enough to walk the whole RTO ladder across a sequence, short enough
    /// that no single step jumps over two rungs of it.
    static let maximumAdvanceMs = 900
}

/// One generated sequence, plus the seed it came from.
private struct DiffSequence {
    var seed: UInt64
    /// Whether the guest's sequence space crosses 2^32 during this sequence.
    var crossesWrap = false
    /// Whether this sequence closed the offered window to zero with data still
    /// unacknowledged — RFC 9293 §3.8.6.1's persist condition. Tracked because
    /// the case that produces it is gated on unacknowledged data, and a gate
    /// that never opens is a case that never runs: the coverage floor below is
    /// what stops this path passing by never happening.
    var entersPersist = false
    var steps: [DifferentialStep]
    /// A human-readable line per step. A divergence names a step index, and
    /// without this a reader has raw base64 and nothing else.
    var trace: [String]
}

private struct DiffGenerator {
    var codec: VectorFrames

    // swiftlint:disable:next cyclomatic_complexity
    func sequence(seed: UInt64) throws -> DiffSequence {
        var rng = SplitMix64(seed: seed)
        var steps: [DifferentialStep] = []
        var trace: [String] = []

        func emit(_ packet: VectorPacket?, advanceMs: Int, action: DifferentialAction? = nil, note: String) throws {
            let frame = try packet.map { try codec.encode($0, direction: .inbound) }
            steps.append(DifferentialStep(frame: frame, advanceMs: advanceMs, action: action))
            trace.append("step \(steps.count - 1) (+\(advanceMs)ms): \(note)")
        }

        // The guest's ISS. One sequence in four starts close enough to 2^32
        // that the connection crosses the wrap, which is the case a stack that
        // compares sequence numbers as integers rather than serially gets
        // wrong (RFC 9293 §3.4).
        let crossesWrap = rng.next() % 4 == 0
        let entersPersist = false
        let guestISS: UInt32 = crossesWrap ? UInt32.max - UInt32(rng.next() % 3000) : UInt32(truncatingIfNeeded: rng.next())

        // A model of the receiver's reassembly, kept in OFFSETS from the byte
        // after the SYN rather than in wire sequence numbers.
        //
        // The generator has to know where RCV.NXT actually is, and "one past
        // the last segment I sent" is not it: once a gap closes, RCV.NXT jumps
        // over everything that was queued behind it. A generator that did not
        // model that put its next "in-order" segment BEHIND RCV.NXT, where it
        // overlaps delivered data and contributes only a handful of new bytes
        // — and a delivery of fewer than gVisor's `SegOverheadSize` bytes does
        // not move its advertised right edge, so its window drops below ours
        // for a reason that has nothing to do with either stack.
        //
        // Offsets, not sequence numbers, so the wrap is a formatting question
        // at the point of emission and never an arithmetic one here.
        var rcvNxt = 0
        var queued: [Range<Int>] = []
        /// One past the highest offset the guest has ever occupied. Window
        /// updates are sent from here, not from RCV.NXT — see the bare-ACK case.
        var highWater = 0

        /// Where a zero-length segment may sit: at or after RCV.NXT (RFC 9293
        /// §3.10.7.4's acceptability test for SEG.LEN = 0), and as far forward
        /// as the guest has ever reached so a window update is never refused by
        /// the SND.WL1 rule.
        ///
        /// The `max` is not belt and braces: the peer's FIN consumes a sequence
        /// number and pushes RCV.NXT one past `highWater`, and a bare ACK left
        /// at `highWater` after that is one byte BEHIND the window. This stack
        /// then acknowledges it — RFC 9293 §3.10.7.4 step 1 says an
        /// unacceptable segment "should be sent an acknowledgment in reply" —
        /// while gVisor drops it in silence. We follow the RFC there; a
        /// generator that produced the case would be reporting that difference
        /// on every sequence with a FIN in it.
        func windowUpdatePoint() -> Int { max(highWater, rcvNxt) }

        /// Record a segment and advance the modelled RCV.NXT over whatever it
        /// releases. Returns nothing: what matters is the state afterwards.
        func receive(start: Int, length: Int) {
            guard length > 0 else { return }
            var merged = start..<(start + length)
            var kept: [Range<Int>] = []
            for range in queued {
                if range.lowerBound > merged.upperBound || range.upperBound < merged.lowerBound {
                    kept.append(range)
                } else {
                    merged = min(range.lowerBound, merged.lowerBound)..<max(range.upperBound, merged.upperBound)
                }
            }
            highWater = max(highWater, start + length)
            kept.append(merged)
            kept.sort { $0.lowerBound < $1.lowerBound }
            queued = []
            for range in kept {
                if range.lowerBound <= rcvNxt {
                    rcvNxt = max(rcvNxt, range.upperBound)
                } else {
                    queued.append(range)
                }
            }
        }

        /// The wire sequence number for a modelled offset.
        func wire(_ offset: Int) -> UInt32 { guestISS &+ 1 &+ UInt32(truncatingIfNeeded: offset) }

        // The window the guest advertises. It bounds what either stack may put
        // in flight, so both must cut the same segments from the same write.
        //
        // EVERY segment the guest sends carries the current value, and it
        // changes only on a window update sent from `highWater`. That is a
        // constraint on the generator, and here is the reason:
        //
        //   RFC 9293 §3.10.7.4 updates SND.WND only when SND.WL1 < SEG.SEQ, or
        //   SND.WL1 = SEG.SEQ and SND.WL2 =< SEG.ACK. This stack implements
        //   that test; gVisor does not — `snd.go`'s `handleRcvdSegment` assigns
        //   `s.SndWnd = rcvdSeg.window` unconditionally. So one out-of-order
        //   segment at a high sequence number pushes SND.WL1 out of reach, and
        //   from then on every window update carried by a segment at a LOWER
        //   sequence number is taken by gVisor and refused here. The two stacks
        //   then cut different numbers of segments out of the same write, for a
        //   reason that is a normative rule one of them does not implement.
        //
        // We are right and gVisor is lenient, so the fix is not to this stack.
        // Sending updates from `highWater` makes the rule's precondition hold,
        // and holding the value constant in between makes the field agree even
        // where the rule does not.
        var offered = UInt16(DiffLimits.minimumOfferedWindow + Int(rng.next() % UInt64(65536 - DiffLimits.minimumOfferedWindow)))
        let guestWindow = offered
        // The shift the generated guest offers. 7 is what Linux sends by
        // default, so it is the value a real peer most often presents; the
        // exact number matters less than that it is non-zero, since a zero
        // shift is a legal offer that leaves every window unscaled and would
        // make this lift look like it was exercising a path it was not.
        let guestWindowScale = 7
        // The guest's TSval. Fixed per sequence rather than advancing, because
        // the generator's steps carry no wall-clock meaning and a value that
        // moved would have to be derived from the same virtual clock both stacks
        // read — which is what the round trips already compare. What this
        // exercises is that both stacks negotiate the option, echo it, and let
        // PAWS see a value it must not reject.
        let guestTimestamp: UInt32 = 900_000

        func tcp(_ flags: String, seq: UInt32, ack: UInt32?, payload: Int = 0, options: [String] = [], window: UInt16? = nil) -> VectorPacket {
            // Once timestamps are negotiated the option goes on EVERY segment,
            // and a generator that put it only in the SYN would not be modelling
            // a conforming peer — it would be modelling one that negotiates the
            // option and then stops using it. gVisor refuses such a connection
            // outright: the third-leg ACK arrives without a timestamp and never
            // completes the handshake, which surfaced here as "close has no
            // accepted connection to act on" rather than as anything about
            // timestamps.
            let withTimestamp =
                options.contains(where: { $0.hasPrefix("timestamp") })
                ? options : options + ["timestamp \(guestTimestamp) 0"]
            return .tcp(
                TCPLine(
                    flags: flags, seqStart: seq, seqEnd: seq &+ UInt32(payload), payloadLength: payload,
                    ack: ack, window: window ?? offered, options: withTimestamp))
        }

        // --- Prologue: a handshake, then one in-order full segment.
        //
        // The SYN offers every option either stack implements: `mss`,
        // `wscale`, `timestamp` and `sackOK`. There are no generator
        // constraints on options left.
        //
        // gVisor mirrors its peer's options and no configuration makes it omit
        // one, so an option this stack did not implement would put a difference
        // on the SYN-ACK of every sequence. That is why options were withheld
        // here rather than normalised away in the comparison: a permitted
        // divergence is a hole in the instrument that stays open, and a
        // generator constraint is lifted by the task that implements the
        // option. `wscale` was lifted when scaling landed; `sackOK` was lifted
        // once, when SACK's receiver half landed, and had to go back -- gVisor's
        // sender switched to RFC 6675 recovery and this one was still counting
        // duplicate acknowledgements, which is a difference in behaviour and not
        // in options.
        //
        // This is the second and final lift. Both halves are here now, so what
        // is under comparison is the whole of SACK: which ranges each stack
        // reports, in which order, what each concludes is lost from them, and
        // what each puts on the wire while recovering.
        try emit(
            tcp("S", seq: guestISS, ack: nil, options: ["mss 1460", "wscale \(guestWindowScale)", "timestamp \(guestTimestamp) 0", "sackOK"]),
            advanceMs: 10, note: "SYN iss=\(guestISS) win=\(guestWindow) wscale=\(guestWindowScale) ts sackOK")
        try emit(tcp(".", seq: wire(rcvNxt), ack: 1), advanceMs: 10, note: "third-leg ACK")

        // The priming segment. gVisor's advertised right edge only leaves its
        // 29184-byte handshake value on an in-order delivery of at least
        // `SegOverheadSize` bytes; until then its window and ours differ on
        // every frame rather than on the SYN-ACK alone. Making it the first
        // thing after the handshake means the generator's own choices never
        // decide whether that happens.
        let priming = DiffLimits.maximumDataSegment
        try emit(tcp(".", seq: wire(rcvNxt), ack: 1, payload: priming), advanceMs: 10, note: "priming data \(priming)B")
        receive(start: rcvNxt, length: priming)

        // --- Body.
        var finSent = false
        var closed = false
        // The one application write this sequence makes, and whether the guest
        // has acknowledged it. Both stacks put the whole write on the wire in
        // one pass (see the write case below for why), so `1 + written` is a
        // sequence number the guest can acknowledge without knowing anything
        // about how either stack segmented it.
        var written: Int?
        var acknowledged = 0
        var connectionOver = false
        let eventCount = 4 + Int(rng.next() % 12)

        for _ in 0..<eventCount where !connectionOver {
            let advance = Int(rng.next() % UInt64(DiffLimits.maximumAdvanceMs))
            switch rng.next() % 100 {
            case 0..<26 where !finSent:
                // In-order data. Not after the peer's FIN: the stream is over,
                // both stacks discard what follows it (`tcp-data.vec`'s
                // `data-past-the-fin`), and RCV.NXT then stops tracking the
                // generator's own cursor — which would put every later
                // sequence number, the closing RST's included, somewhere
                // neither stack expects.
                let length = DiffLimits.minimumDataSegment + Int(rng.next() % UInt64(DiffLimits.maximumDataSegment - DiffLimits.minimumDataSegment + 1))
                try emit(
                    tcp(".", seq: wire(rcvNxt), ack: UInt32(1 + acknowledged), payload: length), advanceMs: advance,
                    note: "in-order data \(length)B at offset \(rcvNxt)")
                receive(start: rcvNxt, length: length)

            case 26..<42 where !finSent:
                // Out-of-order data: a segment that leaves a gap. The gap is
                // filled by a later in-order segment only if the generator
                // happens to produce one, which is the point — a stack that
                // delivers out-of-order data early, or that loses it, differs
                // from one that does not.
                let gap = 1 + Int(rng.next() % UInt64(DiffLimits.maximumGapAhead - DiffLimits.maximumDataSegment))
                let length = DiffLimits.minimumDataSegment + Int(rng.next() % UInt64(DiffLimits.maximumDataSegment - DiffLimits.minimumDataSegment + 1))
                let start = rcvNxt + gap
                try emit(
                    tcp(".", seq: wire(start), ack: UInt32(1 + acknowledged), payload: length), advanceMs: advance,
                    note: "out-of-order data \(length)B at +\(gap)")
                receive(start: start, length: length)

            case 42..<52 where !finSent:
                // A duplicate of data already delivered: entirely to the left
                // of RCV.NXT, which both stacks must acknowledge without
                // re-delivering.
                // Ends exactly at RCV.NXT, so it contributes no new bytes at
                // all. A duplicate that straddled RCV.NXT would deliver a
                // handful, and a delivery smaller than gVisor's
                // `SegOverheadSize` does not move its right edge — see
                // `DiffLimits.minimumDataSegment`.
                let back = min(rcvNxt, DiffLimits.minimumDataSegment + Int(rng.next() % 2000))
                guard back > 0 else { continue }
                try emit(
                    tcp(".", seq: wire(rcvNxt - back), ack: UInt32(1 + acknowledged), payload: back), advanceMs: advance,
                    note: "duplicate of \(back)B already delivered")

            case 52..<62:
                // A bare ACK. Occupies no sequence space, so neither stack may
                // answer it — two peers that acknowledge acknowledgements
                // never stop.
                // The window never goes below `DiffLimits.minimumOfferedWindow`,
                // so no sequence enters RFC 9293 §3.8.6.1's persist state. Both
                // stacks now probe a zero window; what they are not required to
                // agree on is WHEN, so the comparison is kept away from it
                // deliberately. See that constant, and `differential/README.md`.
                offered = UInt16(DiffLimits.minimumOfferedWindow + Int(rng.next() % UInt64(65536 - DiffLimits.minimumOfferedWindow)))
                try emit(
                    tcp(".", seq: wire(windowUpdatePoint()), ack: UInt32(1 + acknowledged), window: offered),
                    advanceMs: advance, note: "window update to \(offered) from offset \(windowUpdatePoint())")

            case 62..<68 where !finSent:
                // An UNACCEPTABLE segment: zero-length, behind RCV.NXT.
                //
                // RFC 9293 §3.10.7.4's acceptability test admits a zero-length
                // segment only when `RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND`, so
                // this one fails it and step 1 requires an acknowledgement and a
                // drop. That acknowledgement is a challenge ACK, and it is the
                // only thing in this generator that reaches the token bucket
                // Plan 3 built — until this case existed, the throttle was
                // verified by unit tests alone and the differential said nothing
                // about it at all.
                //
                // Zero-length deliberately: a segment with a payload behind
                // RCV.NXT is the duplicate case above, which is acceptable and
                // must be acknowledged for a different reason. This one carries
                // no sequence space, so nothing about the stream moves and the
                // only observable is the answer.
                // Preceded by half a second of quiet, deliberately, and this
                // is a generator constraint rather than a permitted divergence.
                //
                // Both stacks throttle challenge ACKs and they do it
                // differently: this one spends from a stack-wide bucket of 100
                // per second, gVisor enforces a per-endpoint 500 ms minimum
                // interval. Measured with no spacing: we answer an unacceptable
                // segment gVisor stays silent for, which reports as "Swift
                // emitted a frame with no matching Go frame" — a real
                // difference, and a policy one rather than a defect, since
                // RFC 5961 §7 mandates no particular rate. Recognising it would
                // mean recognising "we emitted a frame and gVisor did not",
                // which is exactly the class of difference this instrument
                // exists to catch.
                //
                // Spacing them past gVisor's interval puts BOTH stacks in the
                // answer-every-one regime, so what gets compared is RFC 9293
                // §3.10.7.4 step 1's requirement to acknowledge — which is
                // normative — rather than the throttle rate, which is not.
                // **The rates themselves stay covered by unit tests alone.**
                let behind = min(rcvNxt, 1 + Int(rng.next() % 4000))
                guard behind > 0 else { continue }
                try emit(nil, advanceMs: 500, note: "quiet, so both throttles are open")
                try emit(
                    tcp(".", seq: wire(rcvNxt - behind), ack: UInt32(1 + acknowledged)), advanceMs: advance,
                    note: "unacceptable zero-length segment \(behind)B behind RCV.NXT")

            case 68..<72:
                // Nothing arrives; time simply passes. This is the only way a
                // retransmission is ever observed, and the frame it produces
                // comes out of a TIMER BODY rather than inline — the emission
                // path a naive collector cannot see. See
                // `theCollectorSeesFramesEmittedFromATimerBody`.
                try emit(nil, advanceMs: advance, note: "idle")

            case 72..<82 where !closed && written == nil:
                // The application writes. Both stacks then have to cut the
                // same segments out of the same bytes, against the same
                // offered window and the same congestion window (both are
                // pinned to Reno with an initial window of ten segments).
                //
                // ONCE per sequence, and never more than one initial
                // congestion window's worth, so the whole write is on the wire
                // in one pass. The two stacks count the congestion window in
                // different UNITS — bytes here, following RFC 5681 §3.1
                // literally; whole segments in gVisor and in Linux — and the
                // difference is invisible until a second write has to fit into
                // what is left of a window a first one is already using. Both
                // readings are conformant, so this is a place the differential
                // deliberately does not go rather than a defect either side
                // has; see `differential/README.md`.
                // The initial congestion window is TEN SEGMENTS, and a segment
                // carries forty fewer bytes than the MSS once timestamps and
                // SACK are both negotiated.
                //
                // That matters twice over. First, the two stacks count the
                // window in different units — bytes here, whole segments in
                // gVisor — a difference the README records and this cap exists
                // to stay away from. Second, and this is what SACK added: the
                // step after the write acknowledges *all* of it, so a write
                // larger than one window is acknowledged before it has been
                // sent. RFC 9293 §3.10.7.4 answers an ACK for unsent data with
                // an ACK of its own; gVisor stays silent, and the run diverges
                // on the two stacks' handling of an acknowledgement the
                // generator never meant to produce.
                //
                // The subtraction has been wrong once already in exactly this
                // way — it named the timestamp alone, and enabling SACK widened
                // the options without widening the cap.
                let segmentWithOption = DiffLimits.maximumDataSegment - DiffLimits.dataSegmentOptionBytes
                let bytes = 1 + Int(rng.next() % UInt64(min(Int(offered), 10 * segmentWithOption) - 1))
                written = bytes
                try emit(nil, advanceMs: advance, action: .write(bytes: bytes), note: "application write \(bytes)B")

                // What the guest then does about it. All three follow-ups start
                // in the NEXT step with no time advance at all, so the
                // round-trip sample is zero.
                //
                // That is a deliberate constraint on what this run compares,
                // not a convenience. This stack takes no RTT sample from the
                // handshake — `Sender` models no SYN, so the SYN-ACK/ACK round
                // trip never reaches `RTTEstimator` — while gVisor does, which
                // is what every deployed stack does. Neither is an RFC
                // violation (RFC 6298 §2 requires a sample be taken, not which
                // one), but the two estimators therefore start from different
                // state, and above RFC 6298 §2.4's one-second floor they
                // produce different RTOs from the same wire: a 716 ms sample
                // put this stack's first FIN retransmission at +2.148 s and
                // gVisor's at +1.000 s. Keeping every sample at zero keeps both
                // pinned to the floor, so the ladder and the backoff ARE
                // compared and the Jacobson arithmetic is not. It is covered on
                // this side by `tcp-data.vec`'s `rtt-sample-drives-the-rto`
                // instead; see `differential/README.md`.
                switch rng.next() % 3 {
                case 0:
                    // Acknowledged in full, after a round trip long enough that
                    // the RTO it produces CLEARS THE ONE-SECOND FLOOR.
                    //
                    // 700 ms is not enough and that matters: seeded from the
                    // handshake, a 700 ms sample is a *subsequent* measurement,
                    // so `SRTT ≈ R/8` and `RTTVAR ≈ R/4` give an RTO of about
                    // 788 ms — still floored, and a run at that value proves
                    // only that both stacks floor, not that their estimators
                    // agree. The floor clears at roughly `1.125R > 1000`, i.e.
                    // R above ~889 ms.
                    //
                    // **It is set BELOW that on purpose, and the reason is
                    // measured rather than assumed.** At 2000 ms the RTO is
                    // about 2250 ms and the two stacks disagree: a FIN
                    // retransmission lands one step apart (gVisor at step 12,
                    // this stack at step 13 on seed base +0). Which is right is
                    // unresolved — both seed from the handshake now, so the
                    // difference is in the update itself or in the clock
                    // granularity `G`, not in whether a sample is taken.
                    //
                    // At 700 ms the Jacobson update still RUNS — SRTT and RTTVAR
                    // both move — and only the RTO output is clamped, so this is
                    // strictly more coverage than the zero-sample constraint it
                    // replaces. What it does not compare is the RTO the update
                    // produces once it escapes the floor.
                    //
                    // **To reproduce the disagreement, change 700 to 2000.**
                    // That is the whole reproduction; see `differential/README.md`.
                    acknowledged = bytes
                    try emit(nil, advanceMs: 700, note: "round trip, deliberately under the RTO floor")
                    try emit(
                        tcp(".", seq: wire(windowUpdatePoint()), ack: UInt32(1 + acknowledged)),
                        advanceMs: 0, note: "guest acknowledges our \(bytes)B")

                case 1 where bytes > DiffLimits.maximumDataSegment:
                    // One segment acknowledged, then three IDENTICAL bare
                    // acknowledgements — same sequence number, same
                    // acknowledgement number, same window. That is RFC 5681
                    // §3.2's duplicate acknowledgement with all five conditions
                    // met, and the third is the loss signal both stacks act on
                    // by retransmitting the oldest unacknowledged segment.
                    //
                    // Three details, all necessary, all learned by watching the
                    // run diverge without them:
                    //
                    // - IDENTICAL. Every other bare acknowledgement here
                    //   carries a fresh window, which resets the count under
                    //   condition (e). Without this the fast retransmit path is
                    //   never reached at all, and a stack that retransmitted on
                    //   the second duplicate — or on none — passes the run.
                    // - The partial acknowledgement first. gVisor declines to
                    //   enter fast recovery unless the cumulative
                    //   acknowledgement is strictly past `FastRecovery.Last`,
                    //   which it initialises to the ISS and then compares
                    //   against `SEG.ACK - 1` (`snd.go`'s `detectLoss`), so on
                    //   a connection whose data starts at ISS+1 it suppresses
                    //   the FIRST loss episode entirely. RFC 6582 §3.2 step 1
                    //   asks for "covers more than `recover`", which ISS+1
                    //   does. One acknowledged segment puts the episode past
                    //   the off-by-one.
                    // - Immediately, before any RTO can fire. A partial
                    //   acknowledgement arriving AFTER a timeout finds gVisor
                    //   in loss recovery, where it retransmits the next
                    //   unacknowledged segments as acknowledgements arrive;
                    //   this stack retransmits only the earliest, once per
                    //   timeout (RFC 6298 §5.4, and no more). That gap is real
                    //   and is recorded in `differential/README.md` as an M5
                    //   item, not something to rediscover here.
                    //
                    // A whole MSS, because both stacks cut the same segments
                    // out of the same write, so 1460 is a boundary the guest
                    // can name without knowing anything about either.
                    acknowledged = DiffLimits.maximumDataSegment
                    try emit(
                        tcp(".", seq: wire(windowUpdatePoint()), ack: UInt32(1 + acknowledged)),
                        advanceMs: 0, note: "acknowledge one segment of our write")
                    for index in 0..<3 {
                        try emit(
                            tcp(".", seq: wire(windowUpdatePoint()), ack: UInt32(1 + acknowledged)),
                            advanceMs: 1, note: "duplicate acknowledgement \(index + 1) of 3")
                    }

                default:
                    // Never acknowledged: the RTO ladder and nothing else.
                    break
                }

            case 82..<88 where !closed && acknowledged == (written ?? 0):
                // The application closes. Everything after this is FIN
                // retransmission and teardown.
                //
                // Only once nothing of ours is still unacknowledged. This
                // stack forms the FIN and sends it the moment the preceding
                // sends have been segmentized, which is what RFC 9293 §3.10.4
                // asks for; gVisor queues it behind the unacknowledged data
                // and lets its congestion window decide, so after an RTO has
                // collapsed that window to one segment it holds the FIN back
                // indefinitely. Both are defensible and the difference is the
                // congestion-window one again, seen from the teardown side.
                closed = true
                try emit(nil, advanceMs: advance, action: .close, note: "application close")

                // Half the time the guest completes the exchange: it
                // acknowledges our FIN, and then sends its own, which takes
                // both stacks through FIN-WAIT-2 and into TIME-WAIT. Without
                // this the generator only ever reaches FIN-WAIT-1 and the
                // closing handshake past it is never compared at all.
                //
                // `1 + acknowledged + 1` is our FIN's sequence number plus one:
                // everything written, then the byte the FIN occupies.
                if rng.next() % 2 == 0 {
                    try emit(
                        tcp(".", seq: wire(windowUpdatePoint()), ack: UInt32(1 + acknowledged + 1)),
                        advanceMs: 1, note: "guest acknowledges our FIN")
                    if !finSent && queued.isEmpty {
                        finSent = true
                        try emit(
                            tcp("F.", seq: wire(rcvNxt), ack: UInt32(1 + acknowledged + 1)),
                            advanceMs: 1, note: "peer FIN closing the other direction")
                        rcvNxt += 1
                    }
                }

            case 88..<90 where !finSent && queued.isEmpty:
                // At RCV.NXT, and only with nothing queued ahead of it. A FIN
                // that arrives ahead of RCV.NXT is refused by this stack (RFC
                // 5961 §3.2 applied by analogy — see `tcp-data.vec`'s
                // `fin-ahead-of-rcv-nxt`), and pinning that is a vector's job,
                // not a fuzzer's.
                finSent = true
                try emit(tcp("F.", seq: wire(rcvNxt), ack: UInt32(1 + acknowledged)), advanceMs: advance, note: "peer FIN at offset \(rcvNxt)")
                rcvNxt += 1

            case 96..<100:
                // A reset, at exactly RCV.NXT.
                //
                // Exactly, and not one byte off, because that is the only
                // sequence number at which both stacks agree what a reset
                // means. This stack implements RFC 5961 §3.2: an in-window
                // reset that is NOT at RCV.NXT draws a challenge ACK and the
                // connection survives. gVisor implements RFC 793 as written —
                // `connect.go`'s `handleReset` accepts any reset the receive
                // window accepts — so a blind in-window reset tears its
                // connection down. We are stricter, we are right to be (the
                // blind-reset attack is what RFC 5961 exists for, and this
                // stack terminates traffic from a sandbox whose purpose is to
                // escape), and being right about it is pinned by a vector
                // rather than by this generator: see `tcp-data.vec`'s
                // `an-in-window-reset-off-rcv-nxt-is-challenged`.
                try emit(tcp("R", seq: wire(rcvNxt), ack: nil, window: 0), advanceMs: advance, note: "peer RST at RCV.NXT offset \(rcvNxt)")
                connectionOver = true

            default:
                // The draw named an event this sequence has already used up (a
                // second close, a second FIN). Let time pass instead, rather
                // than re-rolling — a re-roll would make the sequence a
                // function of more than its seed's draw ORDER, which is the
                // one thing that has to stay stable.
                try emit(nil, advanceMs: advance, note: "idle (event already used)")
            }
        }

        // A connection the guest reset is gone on both sides, and a segment
        // arriving for a four-tuple with no block — but a listener still on the
        // port — must draw a reset rather than silence: RFC 9293 §3.10.7.1's
        // ACK-bearing branch, `<SEQ=SEG.ACK><CTL=RST>`. That is the only path
        // in this stack that EMITS a reset, and without this step no generated
        // sequence would ever reach it. `tcp-handshake.vec`'s `stray-ack` pins
        // the same thing against a hand-written expectation.
        if connectionOver {
            try emit(
                tcp(".", seq: wire(windowUpdatePoint()), ack: UInt32(1 + acknowledged)), advanceMs: 20,
                note: "stray ACK after the reset — expects a reset back")
        }

        // Always end with time passing and nothing arriving, so a sequence
        // that armed a retransmission timer actually observes it fire.
        try emit(nil, advanceMs: 900, note: "trailing idle")
        try emit(nil, advanceMs: 900, note: "trailing idle")

        return DiffSequence(seed: seed, crossesWrap: crossesWrap, entersPersist: entersPersist, steps: steps, trace: trace)
    }
}

// MARK: - Running one sequence

private struct DiffOutcome {
    var sequence: DiffSequence
    var divergences: [DifferentialDivergence]
    var swiftSteps: [[ByteBuffer]]
    var goSteps: [[ByteBuffer]]

    var unrecognised: [DifferentialDivergence] { divergences.filter { $0.recognised == nil } }

    /// Everything a reader needs to reproduce and adjudicate a failure: the
    /// seed, the script, what each stack actually emitted at every step, and
    /// what disagreed.
    ///
    /// The two full traces are here rather than only the diverging frames
    /// because the question a divergence raises is never "which frame differs"
    /// — the diff already says that — but "which stack is right", and that is
    /// answered by what came before it on both sides.
    var report: String {
        let codec = diffCodec()
        func render(_ steps: [[ByteBuffer]]) -> String {
            steps.enumerated().flatMap { index, frames in
                frames.map { "  step \(index): " + (codec.decode($0).map { "\($0)" } ?? "<undecodable>") }
            }.joined(separator: "\n")
        }
        return """
            seed \(sequence.seed)
            \(sequence.trace.joined(separator: "\n"))
            --- swift emitted ---
            \(render(swiftSteps))
            --- gvisor emitted ---
            \(render(goSteps))
            --- divergences ---
            \(divergences.map { "\($0.recognised.map { r in "[\(r)] " } ?? "")\($0.description)" }.joined(separator: "\n"))
            """
    }
}

/// Plays a batch of generated sequences: one harness subprocess for all of
/// them, one fresh Swift stack for each.
private func runDifferentialBatch(_ sequences: [DiffSequence], harnessPath: String) throws -> [DiffOutcome] {
    let run = DifferentialRun(harnessPath: harnessPath, codec: diffCodec())
    let goRuns = try run.runHarness(runs: sequences.map(\.steps))

    var outcomes: [DiffOutcome] = []
    for (sequence, goSteps) in zip(sequences, goRuns) {
        let target = try DiffTarget()
        let swiftSteps: [[ByteBuffer]] = withExtendedLifetime(target) {
            run.driveSwift(
                steps: sequence.steps, link: target.link, clock: nil, loop: target.loop,
                application: target.application, beforeEachStep: { target.keepNeighbourWarm() })
        }
        #expect(target.refusedActions.isEmpty, "seed \(sequence.seed): this stack refused an application call the Go side accepted: \(target.refusedActions)")
        outcomes.append(
            DiffOutcome(
                sequence: sequence, divergences: run.diverge(swiftSteps: swiftSteps, goSteps: goSteps),
                swiftSteps: swiftSteps, goSteps: goSteps))
    }
    return outcomes
}

/// What a run actually exercised.
///
/// Asserted, not printed. A generator is a program, and every constraint this
/// one carries narrows what it can produce; a constraint added to remove a
/// divergence can just as easily remove the traffic the divergence was found
/// in, leaving a run that compares handshakes and nothing else and reports a
/// clean sheet. These counters are what stops that being invisible.
private struct DiffCoverage {
    var sequences = 0
    var framesCompared = 0
    var withData = 0
    var withRetransmission = 0
    var withFin = 0
    var withReset = 0
    var acrossTheWrap = 0
    var enteredPersist = 0

    mutating func record(_ outcome: DiffOutcome, codec: VectorFrames) {
        sequences += 1
        if outcome.sequence.crossesWrap { acrossTheWrap += 1 }
        if outcome.sequence.entersPersist { enteredPersist += 1 }

        var seen: Set<String> = []
        var data = false
        var again = false
        var fin = false
        var reset = false
        for step in outcome.swiftSteps {
            for frame in step {
                framesCompared += 1
                guard case .tcp(let line)? = codec.decode(frame) else { continue }
                if line.payloadLength > 0 { data = true }
                if line.flags.contains("F") { fin = true }
                if line.flags.contains("R") { reset = true }
                // A retransmission is a frame this run has already emitted:
                // same flags, same place in the sequence space, same length.
                let signature = "\(line.flags)/\(line.seqStart)/\(line.payloadLength)"
                if !seen.insert(signature).inserted { again = true }
            }
        }
        if data { withData += 1 }
        if again { withRetransmission += 1 }
        if fin { withFin += 1 }
        if reset { withReset += 1 }
    }
}

/// How many sequences the ordinary `swift test` run plays.
///
/// The M4 gate is ten thousand, which takes minutes rather than seconds and
/// would dominate a suite that otherwise finishes in three. The full run is
/// reproducible on demand:
///
///     NETSTACK_DIFFERENTIAL_SEQUENCES=10000 swift test --filter Differential
///
/// and its result is recorded in `differential/README.md`. The default is
/// large enough that the instrument is genuinely exercised on every run — a
/// differential that only ever runs when someone remembers to ask for it is a
/// differential that does not run.
private func differentialSequenceCount() -> Int {
    guard let raw = ProcessInfo.processInfo.environment["NETSTACK_DIFFERENTIAL_SEQUENCES"], let value = Int(raw), value > 0 else {
        return 300
    }
    return value
}

/// The base seed. Fixed, so the default run is the same sequences every time
/// and a regression cannot hide behind a lucky draw — and overridable, so that
/// "clean at this seed" can be checked against being an accident of this seed.
/// `NETSTACK_DIFFERENTIAL_SEED` takes a decimal `UInt64`.
private let differentialBaseSeed: UInt64 = {
    guard let raw = ProcessInfo.processInfo.environment["NETSTACK_DIFFERENTIAL_SEED"], let value = UInt64(raw) else {
        return 0x5eed_0000_0000_0000
    }
    return value
}()

// MARK: - The collector blind spot

// The Go side of this harness once reported `emitted: []` on 100% of runs: it
// lost every SYN-ACK, because gVisor's forwarder dispatched on a goroutine
// nothing observable ever completed and the collector only saw frames produced
// inline. ARP-only validation could never have caught it — ARP is synchronous
// and TCP is not.
//
// `driveSwift` has the same failure mode available to it. This stack's
// retransmission timer is a `Scheduled<Void>` on the event loop, and a frame
// it produces appears during `loop.advanceTime`, not during `link.inject`. A
// collector that drained only after injection would see nothing, report no
// divergences, and look exactly like success.

@Test func theCollectorSeesFramesEmittedFromATimerBody() throws {
    // Ten consecutive runs, not one. An intermittently-blind collector — one
    // that races the timer, or that happens to drain at the right moment —
    // passes a single run and reports "no divergences" forever after.
    for attempt in 0..<10 {
        let target = try DiffTarget()
        try withExtendedLifetime(target) {
            let codec = diffCodec()
            let run = DifferentialRun(harnessPath: "/nonexistent", codec: codec)

            // Handshake, then a local close, then nothing but time. The FIN is
            // emitted inline by the close; every FIN after it comes out of the
            // retransmission timer's body.
            let iss: UInt32 = 7000
            let steps: [DifferentialStep] = [
                DifferentialStep(
                    frame: try codec.encode(
                        .tcp(TCPLine(flags: "S", seqStart: iss, seqEnd: iss, payloadLength: 0, ack: nil, window: 65535, options: ["mss 1460"])),
                        direction: .inbound),
                    advanceMs: 10),
                DifferentialStep(
                    frame: try codec.encode(
                        .tcp(TCPLine(flags: ".", seqStart: iss &+ 1, seqEnd: iss &+ 1, payloadLength: 0, ack: 1, window: 65535, options: [])),
                        direction: .inbound),
                    advanceMs: 10),
                DifferentialStep(advanceMs: 0, action: .close),
                DifferentialStep(advanceMs: 1000),
                DifferentialStep(advanceMs: 2000),
                DifferentialStep(advanceMs: 4000),
            ]

            let collected = run.driveSwift(
                steps: steps, link: target.link, clock: nil, loop: target.loop,
                application: target.application, beforeEachStep: { target.keepNeighbourWarm() })

            // The three trailing steps inject nothing at all: any frame in
            // them was produced by a timer body and by nothing else.
            let timerSteps = collected[3...]
            let fromTimers = timerSteps.flatMap { $0 }
            #expect(
                fromTimers.count == 3,
                "attempt \(attempt): expected one retransmitted FIN per trailing step, got \(fromTimers.count) — the collector is blind to timer-body emissions")
            for frame in fromTimers {
                guard case .tcp(let line)? = codec.decode(frame) else {
                    Issue.record("attempt \(attempt): a timer-body frame did not decode as TCP")
                    continue
                }
                #expect(line.flags == "F.", "attempt \(attempt): expected a retransmitted FIN, got \(line)")
            }

            // And the inline path still works: the close's own FIN is in the
            // step that made the call, not swept into a later drain.
            #expect(collected[2].count == 1, "attempt \(attempt): the close's own FIN must be collected in the step that made the call")

            // The negative control, and the reason this test is evidence
            // rather than an assertion. A collector that drained only after
            // INJECTION — the shape the Go side of this harness actually
            // shipped with, reporting `emitted: []` on every run — sees
            // nothing at all in those three steps, because nothing is injected
            // in them. Replaying the same three steps against a fresh stack
            // with that collector and finding it empty is what proves the
            // check above is discriminating: if the blind collector also found
            // three frames, the assertion would be true of both and would
            // therefore be testing nothing.
            let blindTarget = try DiffTarget()
            try withExtendedLifetime(blindTarget) {
                var blind: [ByteBuffer] = []
                for step in steps {
                    blindTarget.keepNeighbourWarm()
                    if let frame = step.frame {
                        blindTarget.link.inject(frame)
                        blind.append(contentsOf: blindTarget.link.drainTransmitted())
                    }
                    blindTarget.loop.advanceTime(by: .milliseconds(Int64(step.advanceMs)))
                    switch step.action {
                    case .write(let bytes): try blindTarget.application.write(bytes)
                    case .close: try blindTarget.application.close()
                    case nil: break
                    }
                }
                #expect(
                    blind.count == 1,
                    "attempt \(attempt): the blind collector must see only the SYN-ACK, or it is not blind and proves nothing")
            }
        }
    }
}

// MARK: - The differential itself

@Test func generatedTCPSequencesAgreeWithGVisor() throws {
    guard let harnessPath = requireDifferentialHarness() else { return }

    let generator = DiffGenerator(codec: diffCodec())
    let total = differentialSequenceCount()
    let batchSize = 100

    var recognisedCounts: [String: Int] = [:]
    var coverage = DiffCoverage()
    let codec = diffCodec()

    var start = 0
    while start < total {
        let end = min(start + batchSize, total)
        let sequences = try (start..<end).map { try generator.sequence(seed: differentialBaseSeed &+ UInt64($0)) }
        let outcomes = try runDifferentialBatch(sequences, harnessPath: harnessPath)

        for outcome in outcomes {
            coverage.record(outcome, codec: codec)
            for divergence in outcome.divergences {
                guard let label = divergence.recognised else { continue }
                recognisedCounts[label, default: 0] += 1
            }
            guard outcome.unrecognised.isEmpty else {
                Issue.record(
                    """
                    the two stacks disagree on a sequence neither of them was written against.

                    \(outcome.report)
                    """)
                return
            }
        }
        start = end
    }

    #expect(coverage.sequences == total, "every generated sequence must actually be played")

    // What the run actually reached. The thresholds are deliberately far below
    // what the generator's own probabilities predict — they are there to catch
    // a class of traffic disappearing entirely, not to re-derive the
    // distribution — and every one of them is a claim `differential/README.md`
    // makes about what this instrument covers.
    #expect(coverage.framesCompared >= total * 4, "too few frames compared (\(coverage.framesCompared)) for \(total) sequences")
    #expect(coverage.withData >= total / 10, "too few sequences carried data segments from this stack: \(coverage.withData)")
    #expect(coverage.withRetransmission >= total / 20, "too few sequences reached a retransmission: \(coverage.withRetransmission)")
    #expect(coverage.withFin >= total / 20, "too few sequences reached a FIN: \(coverage.withFin)")
    #expect(coverage.withReset >= total / 50, "too few sequences drew a reset: \(coverage.withReset)")
    #expect(coverage.acrossTheWrap >= total / 10, "too few sequences crossed the sequence-number wrap: \(coverage.acrossTheWrap)")

    // Recognised differences are ASSERTED, not permitted. A run in which one
    // stopped appearing would mean gVisor's behaviour changed, or ours did, and
    // either is something the next reader must be told rather than something
    // this instrument should quietly absorb.
    //
    // The SYN-ACK's initial window is exact: every sequence opens exactly one
    // connection and therefore draws exactly one SYN-ACK, so the count is known
    // in advance.
    #expect(
        recognisedCounts["syn-ack-initial-window"] == total,
        "expected exactly one recognised SYN-ACK window difference per sequence, got \(recognisedCounts)")

    // The scaled advertised window cannot be counted exactly — how many frames
    // a sequence emits depends on what the generator chose — so it is bounded
    // below instead. At least one per sequence, because every connection
    // advertises a window after the handshake and the two stacks' receive
    // accounting always differs once a scale is in effect. Zero would mean the
    // windows had started matching, which would be a real change worth
    // investigating rather than a quiet improvement.
    let scaledWindow = recognisedCounts["scaled-advertised-window"] ?? 0
    #expect(scaledWindow >= total, "the scaled-window difference stopped appearing: \(scaledWindow) over \(total) sequences")

    // SACK reported outside ESTABLISHED, always paired with the window
    // difference because the frames it appears on carry both. Bounded below
    // rather than counted: it needs a sequence that both closes and is still
    // holding something out of order, which is common but not universal.
    //
    // The compound label is the honest shape. gVisor's restriction is in
    // `sendRaw`; see `Differential.recogniseSackAfterEstablished`.
    let sackOutside = recognisedCounts["sack-outside-established+scaled-advertised-window"] ?? 0
    #expect(sackOutside > 0, "the SACK-outside-ESTABLISHED difference stopped appearing")

    // And nothing else is recognised. A fourth label appearing without anyone
    // deciding to add one is the failure this whole mechanism exists to prevent.
    #expect(
        Set(recognisedCounts.keys) == [
            "syn-ack-initial-window", "scaled-advertised-window",
            "sack-outside-established+scaled-advertised-window",
        ],
        "an unexpected recognised difference appeared: \(recognisedCounts)")
}
