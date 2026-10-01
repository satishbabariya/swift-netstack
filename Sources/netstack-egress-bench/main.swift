import Foundation
import Netstack

// ADR 0001 (docs/adr/0001-egress-decision-hook.md, "Performance") sets a 10 µs
// p99 budget for a hook, measured on the event loop from call to return, and
// says plainly that no number here has ever been measured. This is that
// measurement: `dial`, `resolve` and `clientHello`, each with no policy
// installed, with `AllowAllPolicy`, and with `ThousandRulePolicy`.
//
// Each hook is timed through the same `if let policy, policy.hook(...)`
// (or `guard policy.hook(...) else`) shape its real call site uses --
// `OutboundTCPForwarder.swift` for `dial` and `clientHello`, `DNSServer.swift`
// for `resolve` -- so the "nil" column measures what production actually pays
// with no policy installed (one Optional check), not an invented baseline.
// `clientHello` has no nil column: production never calls it without a policy,
// because `inspectedTLSPorts` is empty without one (`OutboundTCPForwarder.init`),
// so there is nothing to time there.
//
// This does not fail the build on the threshold. It prints p50 and p99 per
// hook per policy and says, per row, whether that p99 is under 10 µs. Gating
// CI on it is a later, separate decision -- one line of noise on a guest's
// clock is not the same claim as "this number must never move."

private let budgetMicroseconds = 10.0

private func microseconds(_ duration: Duration) -> Double {
    let (seconds, attoseconds) = duration.components
    return Double(seconds) * 1_000_000 + Double(attoseconds) * 1e-12
}

private struct Timings {
    private var samples: [Duration]

    init(reserving count: Int) {
        samples = []
        samples.reserveCapacity(count)
    }

    mutating func record(_ duration: Duration) {
        samples.append(duration)
    }

    private func percentile(_ p: Double) -> Duration {
        let sorted = samples.sorted()
        let rank = Int((p * Double(sorted.count - 1)).rounded())
        return sorted[rank]
    }

    var p50: Duration { percentile(0.50) }
    var p99: Duration { percentile(0.99) }
}

/// Runs `body` `warmup` times unmeasured, to let the allocator and the branch
/// predictor settle, then `iterations` times measured.
private func measure(iterations: Int, warmup: Int = 2_000, _ body: () -> Void) -> Timings {
    for _ in 0..<warmup { body() }
    var timings = Timings(reserving: iterations)
    for _ in 0..<iterations {
        let start = ContinuousClock.now
        body()
        timings.record(ContinuousClock.now - start)
    }
    return timings
}

// Fixed inputs. The destination sits in TEST-NET-2 (198.51.100.0/24, RFC
// 5737) so it is guaranteed not to collide with `ThousandRulePolicy`'s
// 10.0.0.0/8 rule table above.
private let benchFlow = EgressFlow(
    transport: .tcp,
    source: IPv4Address(10, 0, 2, 15),
    sourcePort: 51000,
    destination: IPv4Address(198, 51, 100, 7),
    translatedDestination: IPv4Address(198, 51, 100, 7),
    port: 443
)
private let benchQuestion = EgressQuestion(
    source: IPv4Address(10, 0, 2, 15), name: "bench.invalid", type: 1, klass: 1, transport: .udp
)
private let benchClientHello = EgressClientHello(flow: benchFlow, serverName: "bench.invalid")

// The three guard shapes production actually calls through. Kept free
// functions, `@inline(never)`, so what is timed is the call-site cost a real
// gateway pays, not whatever the optimizer collapses a one-line closure into.

@inline(never)
private func dialSite(_ policy: (any EgressPolicy)?) {
    // OutboundTCPForwarder.swift: `if let policy, policy.dial(...) == .refuse`.
    if let policy, policy.dial(benchFlow) == .refuse {
        return
    }
}

@inline(never)
private func resolveSite(_ policy: (any EgressPolicy)?) {
    // DNSServer.swift: `if let policy, policy.resolve(asked) == .refuse`.
    if let policy, policy.resolve(benchQuestion) == .refuse {
        return
    }
}

@inline(never)
private func clientHelloSite(_ policy: any EgressPolicy) {
    // OutboundTCPForwarder.swift: `guard policy.clientHello(...) == .refuse else { ... }`,
    // reached only once `dial` has already allowed the flow and the port is
    // one of `policy.inspectedTLSPorts`.
    _ = policy.clientHello(benchClientHello) == .refuse
}

private let iterations = 50_000

private struct Row {
    let hook: String
    let policyName: String
    let p50: Double?
    let p99: Double?
    let note: String?
}

private var rows: [Row] = []

let allowAll = AllowAllPolicy()
let thousandRule = ThousandRulePolicy()

for (name, policy) in [("nil", nil), ("allow-all", allowAll), ("1000-rule", thousandRule)] as [(String, (any EgressPolicy)?)] {
    let dial = measure(iterations: iterations) { dialSite(policy) }
    rows.append(Row(hook: "dial", policyName: name, p50: microseconds(dial.p50), p99: microseconds(dial.p99), note: nil))

    let resolve = measure(iterations: iterations) { resolveSite(policy) }
    rows.append(Row(hook: "resolve", policyName: name, p50: microseconds(resolve.p50), p99: microseconds(resolve.p99), note: nil))
}

rows.append(Row(hook: "clientHello", policyName: "nil", p50: nil, p99: nil, note: "not called without a policy"))
for (name, policy) in [("allow-all", allowAll), ("1000-rule", thousandRule)] as [(String, any EgressPolicy)] {
    let clientHello = measure(iterations: iterations) { clientHelloSite(policy) }
    rows.append(
        Row(hook: "clientHello", policyName: name, p50: microseconds(clientHello.p50), p99: microseconds(clientHello.p99), note: nil))
}

/// Left-pads with Foundation's `padding`, not `String(format: "%@")`: the
/// latter bridges through `NSString` and behaves differently enough across
/// Darwin and swift-corelibs-foundation that it is not worth trusting for
/// table columns here.
private func column(_ text: String, _ width: Int) -> String {
    text.count >= width ? text + " " : text.padding(toLength: width, withPad: " ", startingAt: 0)
}

if AllowAllPolicy.sleepsSlow {
    print("NETSTACK_BENCH_SLOW_ALLOW_ALL=1: allow-all sleeps 50 µs per call. This run is a self-test, not a real measurement.")
}
print("")
print(column("hook", 13) + column("policy", 11) + column("p50(µs)", 10) + column("p99(µs)", 10) + "  p99 < 10µs?")
for row in rows {
    if let p50 = row.p50, let p99 = row.p99 {
        let underBudget = p99 < budgetMicroseconds
        let p50Text = String(format: "%.3f", p50)
        let p99Text = String(format: "%.3f", p99)
        print(column(row.hook, 13) + column(row.policyName, 11) + column(p50Text, 10) + column(p99Text, 10) + "  " + (underBudget ? "yes" : "NO"))
    } else {
        print(column(row.hook, 13) + column(row.policyName, 11) + "  " + (row.note ?? "n/a"))
    }
}
