import Logging
import NIOConcurrencyHelpers
import NIOCore
import Testing

@testable import Netstack

// Logging is a guest-reachable resource, and this package claims every one of
// those is bounded. These tests are that claim, checked.
//
// The shape to watch for here is the one this repository has caught itself
// making repeatedly: an upper bound with no floor. "At most one line per
// window" is satisfied perfectly by a logger that never logs anything, so every
// suppression test below is paired with one that fails if nothing is emitted.

/// Collects what was logged, so a test can count lines rather than read them.
///
/// A lock, in a package that has one everywhere else only in `ManualClock`, and
/// for the same reason: `LogHandler` must be `Sendable` and swift-log gives no
/// promise about which thread calls it. Nothing in `Sources/Netstack` depends on
/// this type.
/// `@unchecked` because `LogHandler` refines `Sendable` and requires `metadata`
/// and `logLevel` to be settable `var`s -- a protocol requirement that cannot be
/// met by a checked `Sendable` class. The captured lines, which are the part a
/// test reads from another thread, are behind the lock; these two are written
/// once at construction and never again.
final class CapturingLogHandler: LogHandler, @unchecked Sendable {
    struct Line: Sendable {
        var level: Logger.Level
        var message: String
        var metadata: Logger.Metadata
    }

    private let box: NIOLockedValueBox<[Line]>
    var metadata: Logger.Metadata = [:]
    var logLevel: Logger.Level = .trace

    init(_ box: NIOLockedValueBox<[Line]>) {
        self.box = box
    }

    subscript(metadataKey key: String) -> Logger.Metadata.Value? {
        get { metadata[key] }
        set { metadata[key] = newValue }
    }

    // `log(event:)` rather than the older `log(level:message:...)`. swift-log
    // deprecated satisfying the protocol through the default implementation, and
    // the deprecation is the kind of thing that sits in a build log until
    // somebody turns warnings into errors -- which is what this change did.
    func log(event: LogEvent) {
        box.withLockedValue {
            $0.append(
                Line(
                    level: event.level, message: event.message.description,
                    metadata: event.metadata ?? [:]))
        }
    }
}

func makeLogger() -> (Logger, NIOLockedValueBox<[CapturingLogHandler.Line]>) {
    let box = NIOLockedValueBox<[CapturingLogHandler.Line]>([])
    return (Logger(label: "test") { _ in CapturingLogHandler(box) }, box)
}

@Test
func theFirstOccurrenceOfAnEventIsLoggedImmediately() {
    let (logger, lines) = makeLogger()
    let limiter = RateLimitedLogger(logger: logger, clock: ManualClock(), window: .seconds(10))

    limiter.record(.inboundFrameRejected)

    // The floor. Without this, `suppressionHoldsEverythingAfterTheFirst` below
    // passes for a limiter that logs nothing at all, which is the exact shape
    // this repository keeps having to delete.
    #expect(lines.withLockedValue { $0.count } == 1)
    #expect(lines.withLockedValue { $0.first?.message } == "inboundFrameRejected")
}

@Test
func suppressionHoldsEverythingAfterTheFirstWithinTheWindow() {
    let (logger, lines) = makeLogger()
    let clock = ManualClock()
    let limiter = RateLimitedLogger(logger: logger, clock: clock, window: .seconds(10))

    for _ in 0..<1000 {
        limiter.record(.inboundFrameRejected)
    }

    // One line for a thousand frames. Remove the window comparison in `record`
    // and this is a thousand.
    #expect(lines.withLockedValue { $0.count } == 1)
    #expect(limiter.suppressedCountForTesting(.inboundFrameRejected) == 999)
}

@Test
func aWindowThatHasExpiredLogsAgainAndSaysHowMuchItHeldBack() {
    let (logger, lines) = makeLogger()
    let clock = ManualClock()
    let limiter = RateLimitedLogger(logger: logger, clock: clock, window: .seconds(10))

    for _ in 0..<50 {
        limiter.record(.inboundFrameRejected)
    }
    clock.advance(by: .seconds(11))
    limiter.record(.inboundFrameRejected)

    let captured = lines.withLockedValue { $0 }
    #expect(captured.count == 2)
    // The count is the point: a second line that did not say what it stood for
    // would make a flood look like two frames.
    #expect(captured.last?.metadata["suppressed"].map(String.init(describing:)) == "49")
    // And the window restarts empty, rather than carrying the total forward.
    #expect(limiter.suppressedCountForTesting(.inboundFrameRejected) == 0)
}

@Test
func eachEventKindGetsItsOwnWindow() {
    let (logger, lines) = makeLogger()
    let limiter = RateLimitedLogger(logger: logger, clock: ManualClock(), window: .seconds(10))

    // One of each, all inside a single window. A limiter keyed on nothing --
    // one global window rather than one per event -- logs the first and hides
    // the other eight, which is how a flood of rejected frames would hide the
    // one line saying DNS has no upstream configured.
    for event in NetstackEvent.allCases {
        limiter.record(event)
    }

    #expect(lines.withLockedValue { $0.count } == NetstackEvent.allCases.count)
}

@Test
func aFloodThatStoppedIsStillReportedAtFlush() {
    let (logger, lines) = makeLogger()
    let limiter = RateLimitedLogger(logger: logger, clock: ManualClock(), window: .seconds(10))

    for _ in 0..<20 {
        limiter.record(.udpRefusedByLimit)
    }
    limiter.flush()

    let captured = lines.withLockedValue { $0 }
    #expect(captured.count == 2)
    #expect(captured.last?.metadata["suppressed"].map(String.init(describing:)) == "19")
}

@Test
func flushSaysNothingWhenNothingWasSuppressed() {
    let (logger, lines) = makeLogger()
    let limiter = RateLimitedLogger(logger: logger, clock: ManualClock(), window: .seconds(10))

    limiter.record(.udpRefusedByLimit)
    limiter.flush()

    // Exactly the first line, and no empty summary after it. `Gateway.close`
    // calls `flush`, so without this every clean shutdown appends a second copy
    // of every event that happened once.
    #expect(lines.withLockedValue { $0.count } == 1)
}

@Test
func suppressedEventsDoNotPayForTheMetadataTheyWouldHaveCarried() {
    let (logger, _) = makeLogger()
    let limiter = RateLimitedLogger(logger: logger, clock: ManualClock(), window: .seconds(10))
    let built = NIOLockedValueBox(0)

    for _ in 0..<100 {
        limiter.record(
            .tcpDialFailed,
            {
                built.withLockedValue { $0 += 1 }
                return ["destination": .string("10.0.0.1:80")]
            }())
    }

    // Once, not a hundred times. Drop the `@autoclosure` and this is 100: the
    // interpolation of an address happens for every suppressed event, on the
    // datapath, in exactly the flood case the limiter exists to make cheap.
    #expect(built.withLockedValue { $0 } == 1)
}

@Test
func guestControlledTextCannotForgeALogLine() {
    // A DNS name is bytes the guest chose. This one ends the line and starts a
    // new one that reads like an authentic entry from somewhere else.
    let forged = "evil.example\n2026-01-01 gateway: lease granted to 00:00:00:00:00:00"
    let safe = sanitizedForLog(forged)

    #expect(!safe.contains("\n"))
    #expect(!safe.contains("\r"))
    // The text is still there, so the operator can see what was asked for --
    // this is escaping, not redaction.
    #expect(safe.hasPrefix("evil.example?"))
}

@Test
func sanitizingCapsTheLengthAGuestCanChoose() {
    let long = String(repeating: "a", count: 4096)
    let safe = sanitizedForLog(long, limit: 32)

    // 32 characters plus the ellipsis that says it was cut.
    #expect(safe.count == 35)
    #expect(safe.hasSuffix("..."))
}

@Test
func sanitizingLeavesOrdinaryNamesExactlyAlone() {
    // The floor for the two above: a sanitizer that returned "" would satisfy
    // both of them.
    #expect(sanitizedForLog("gateway.containers.internal") == "gateway.containers.internal")
}

@Test
func nonAsciiIsReplacedRatherThanPassedThrough() {
    // Not paranoia about the character itself: a name is bytes, a log file is
    // read by things that make their own assumptions about encoding, and this
    // package does not get to choose the reader.
    #expect(sanitizedForLog("caf\u{00E9}.example") == "caf?.example")
}
