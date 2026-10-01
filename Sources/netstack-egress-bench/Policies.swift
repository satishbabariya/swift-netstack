import NIOConcurrencyHelpers
import Netstack

#if canImport(Darwin)
    import Darwin
#else
    import Glibc
#endif

/// Allows everything, the cheapest conformer `EgressPolicy` can have: three
/// returns and a set literal, nothing to look up. This is the benchmark's
/// floor -- what installing a policy costs before the policy does any work of
/// its own.
///
/// `NETSTACK_BENCH_SLOW_ALLOW_ALL` makes it sleep 50 µs in each hook instead.
/// That exists for one reason: to prove this benchmark would notice a slow
/// policy. A measurement nobody has ever seen fail is a measurement nobody
/// should trust, so the bench's own CI job runs with this set and checks the
/// reported p99 crossed the 10 µs line in `docs/adr/0001-egress-decision-hook.md`.
struct AllowAllPolicy: EgressPolicy {
    static let sleepsSlow: Bool = getenv("NETSTACK_BENCH_SLOW_ALLOW_ALL").map { String(cString: $0) == "1" } ?? false

    private func maybeSleep() {
        if Self.sleepsSlow {
            usleep(50)
        }
    }

    func resolve(_ question: EgressQuestion) -> EgressVerdict {
        maybeSleep()
        return .allow
    }
    func resolved(_ answer: EgressAnswer) -> EgressVerdict { .allow }
    func dial(_ flow: EgressFlow) -> EgressVerdict {
        maybeSleep()
        return .allow
    }
    let inspectedTLSPorts: Set<UInt16> = [443]
    func clientHello(_ hello: EgressClientHello) -> EgressTLSVerdict {
        maybeSleep()
        return .allow
    }
}

/// A conformer shaped like ADR 0001's "sandbox-shaped policy": a table of rules
/// to match the flow, question or server name against, plus a ledger it writes
/// to once it has decided. 1,000 rules, per this benchmark's brief -- the ADR's
/// own sketch used 8,192, but nothing was ever built to pick a number, so this
/// follows the issue that asked for the benchmark instead of the ADR's guess.
///
/// Every rule table is built so that none of the benchmark's fixed inputs
/// match any entry. That is deliberate: the interesting cost of a rule-based
/// policy is the full scan it does before falling through to a default, not
/// the early-exit it gets lucky into. A policy that matched on rule one would
/// be benchmarking the matcher's best case, not a guest asking for something
/// the table has never seen before.
final class ThousandRulePolicy: EgressPolicy {
    private struct DialRule: Sendable {
        let destination: UInt32
        let port: UInt16
    }

    private let dialRules: [DialRule]
    private let nameRules: [String]
    private let sniRules: [String]
    /// Decisions this policy has made, the way a real embedder's audit log or
    /// NAT ledger would be. Read with a lock because a policy shared across
    /// gateways on different loops is called from more than one thread, same
    /// as production (`EgressPolicy`'s doc comment on `Sendable`).
    private let ledger = NIOLockedValueBox<[UInt32: UInt64]>([:])

    init(count: Int = 1000) {
        // 10.0.0.0/8 addresses that are not `198.51.100.*`, the TEST-NET-2
        // block this benchmark's flows use below, so no dial rule matches.
        dialRules = (0..<count).map { DialRule(destination: 0x0a00_0000 &+ UInt32($0), port: UInt16(1 + ($0 % 60000))) }
        nameRules = (0..<count).map { "rule-\($0).example.internal" }
        sniRules = (0..<count).map { "sni-\($0).example.internal" }
    }

    func resolve(_ question: EgressQuestion) -> EgressVerdict {
        var matched = false
        for rule in nameRules where rule == question.name {
            matched = true
            break
        }
        precondition(!matched, "benchmark input must not match a rule")
        return .allow
    }

    func resolved(_ answer: EgressAnswer) -> EgressVerdict { .allow }

    func dial(_ flow: EgressFlow) -> EgressVerdict {
        var matched = false
        for rule in dialRules where rule.destination == flow.translatedDestination.raw && rule.port == flow.port {
            matched = true
            break
        }
        precondition(!matched, "benchmark input must not match a rule")
        ledger.withLockedValue { $0[flow.translatedDestination.raw, default: 0] += 1 }
        return .allow
    }

    let inspectedTLSPorts: Set<UInt16> = [443]

    func clientHello(_ hello: EgressClientHello) -> EgressTLSVerdict {
        var matched = false
        for rule in sniRules where rule == hello.serverName {
            matched = true
            break
        }
        precondition(!matched, "benchmark input must not match a rule")
        return .allow
    }
}
