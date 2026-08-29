import Logging
import NIOCore

/// The things this stack reports, as a **closed** set.
///
/// Closed is the whole design. A rate limiter keyed on anything the guest
/// chooses -- a destination address, a queried name, a port -- is not a bound on
/// anything: the guest picks a new key per packet, the limiter allocates a
/// counter per key, and the flood has moved out of the log file and into the
/// limiter's own table, where nothing is watching it. Keying on a fixed enum
/// makes the limiter's memory a compile-time constant.
///
/// Guest-chosen detail still reaches the log, as *metadata* on a line the
/// limiter has already decided to emit. It is never what decides.
public enum NetstackEvent: String, Sendable, CaseIterable {
    /// A frame from the guest that was not a frame this wire carries -- empty,
    /// or longer than the MTU allows.
    case inboundFrameRejected
    /// A frame this stack tried to send and could not. Not guest-driven in the
    /// ordinary case, which is why it is worth a higher level than the rest.
    case outboundFrameRejected
    /// A guest connection refused because `maximumTCPConnections` was reached.
    case tcpRefusedByLimit
    /// A guest connection refused because the destination did not accept.
    case tcpDialFailed
    /// A guest datagram dropped because `maximumUDPFlows` was reached.
    case udpRefusedByLimit
    /// A query this gateway does not own, with nowhere configured to send it.
    case dnsRefusedNoUpstream
    /// A query dropped because too many were already outstanding.
    case dnsRefusedByLimit
    /// A reply from an upstream resolver that matched no outstanding query.
    case dnsUnmatchedReply
    /// A lease request with no free address left in the pool.
    case dhcpPoolExhausted
    /// A frame for an address on no port the switch knows, dropped rather than
    /// flooded. See `NetworkSwitch`.
    case switchUnknownUnicast
    /// A source address not learned because its port had claimed its limit.
    case switchAddressRefused
    /// An address that moved from one port to another: a guest reconnecting, or
    /// one guest claiming another's address.
    case switchAddressMoved

    /// What a first occurrence is worth. A guest can cause every one of these,
    /// so none of them is an error -- they are the stack working as designed
    /// against a guest doing something wrong or something hostile. The one
    /// exception is an outbound frame this stack itself could not send.
    var level: Logger.Level {
        switch self {
        case .outboundFrameRejected: return .error
        case .dnsRefusedNoUpstream: return .warning
        // Either a guest came back on a new port or one is claiming another's
        // address, and nothing here can tell which. An operator should see it.
        case .switchAddressMoved: return .warning
        default: return .notice
        }
    }
}

/// A logger for events a hostile guest can cause, which is nearly all of them.
///
/// ## Why this exists rather than a plain `Logger`
///
/// The README claims every guest-reachable resource in this package is bounded.
/// A log line is a guest-reachable resource: it costs CPU to format, a syscall
/// to write, and disk to keep, and a guest that sends malformed frames in a loop
/// spends all three at line rate. Logging the datapath with a plain `Logger`
/// would put a hole in that claim -- and a nasty one, because the damage lands
/// on the *host's* disk rather than on anything the stack's own bounds cover.
///
/// So: the first occurrence of each event logs immediately, because an operator
/// debugging a broken guest wants it now and one line is not a flood. Everything
/// inside the window after it is counted and not logged. The count is reported
/// on the next occurrence after the window expires.
///
/// ## What that trades away, said plainly
///
/// A flood that **stops** leaves its final count unreported until something else
/// of the same kind happens, or until `flush()` runs at close. That is the price
/// of not owning a timer per event kind, and it is the right side of the trade:
/// a suppressed count is a number, and it arrives late; a timer per event kind
/// is nine repeating timers on the datapath's own event loop, forever, to make a
/// number punctual. The count is never *lost* -- `Gateway.statistics` carries
/// the same totals with no window at all, and that is where a monitoring system
/// should read them from.
///
/// No locks: like everything else here this lives on one event loop. It reads
/// the stack's clock rather than `NIODeadline.now()`, so a test can drive the
/// window instead of sleeping through it.
public final class RateLimitedLogger {
    public let logger: Logger
    private let clock: NetstackClock
    private let window: TimeAmount

    private struct Bucket {
        var windowEnds: NIODeadline
        var suppressed: Int
    }

    private var buckets: [NetstackEvent: Bucket] = [:]

    public init(logger: Logger, clock: NetstackClock, window: TimeAmount = .seconds(10)) {
        self.logger = logger
        self.clock = clock
        self.window = window
    }

    /// Record an occurrence, and log it if the window allows.
    ///
    /// `metadata` is built by an autoclosure so a suppressed event costs a
    /// dictionary lookup and a comparison -- not the string interpolation of
    /// whatever address or name it would have carried. On the datapath that
    /// difference is the point: the flood case is the common case.
    public func record(_ event: NetstackEvent, _ metadata: @autoclosure () -> Logger.Metadata = [:]) {
        let now = clock.now()
        guard var bucket = buckets[event] else {
            buckets[event] = Bucket(windowEnds: now + window, suppressed: 0)
            logger.log(level: event.level, "\(event.rawValue)", metadata: metadata())
            return
        }
        guard now >= bucket.windowEnds else {
            bucket.suppressed += 1
            buckets[event] = bucket
            return
        }
        let suppressed = bucket.suppressed
        buckets[event] = Bucket(windowEnds: now + window, suppressed: 0)
        var combined = metadata()
        if suppressed > 0 {
            combined["suppressed"] = .stringConvertible(suppressed)
        }
        logger.log(level: event.level, "\(event.rawValue)", metadata: combined)
    }

    /// Report every count still held, and forget the windows.
    ///
    /// Called at close so a flood that stopped is still accounted for. Also the
    /// only way a test can observe a suppressed count without arranging a tenth
    /// occurrence after the window.
    public func flush() {
        for (event, bucket) in buckets where bucket.suppressed > 0 {
            logger.log(
                level: event.level, "\(event.rawValue)",
                metadata: ["suppressed": .stringConvertible(bucket.suppressed)])
        }
        buckets.removeAll()
    }

    /// How many occurrences of `event` are currently held back. For tests.
    public func suppressedCountForTesting(_ event: NetstackEvent) -> Int {
        buckets[event]?.suppressed ?? 0
    }
}

/// Guest-controlled text, made safe to put in a log line.
///
/// A DNS name comes off the wire as bytes the guest chose, and this package
/// logs it because an operator debugging resolution needs to see what was asked
/// for. A name containing a newline would end the log line and start one the
/// guest wrote -- which is how a guest fabricates a log entry claiming whatever
/// it likes, in a file an operator or an intrusion-detection system reads as
/// authoritative.
///
/// So every guest-derived string goes through here: anything outside printable
/// ASCII becomes `?`, and the result is capped. The cap is the second half of
/// the same argument -- a 255-byte name is fine, but nothing stops a guest
/// putting one at every label boundary of every query, and a log line's length
/// is as much a resource as its existence.
func sanitizedForLog(_ text: String, limit: Int = 128) -> String {
    var out = String()
    out.reserveCapacity(min(text.utf8.count, limit))
    var count = 0
    for scalar in text.unicodeScalars {
        if count == limit {
            out += "..."
            break
        }
        // Printable ASCII only. Everything else -- control characters, newlines,
        // and anything non-ASCII whose rendering depends on the reader's
        // terminal -- becomes one question mark.
        out.unicodeScalars.append(scalar.value >= 0x20 && scalar.value < 0x7F ? scalar : "?")
        count += 1
    }
    return out
}
