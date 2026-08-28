import NIOCore

/// RFC 5961 §7's ACK throttle: the shared allowance every challenge ACK draws
/// on, as a token bucket refilled from the injected `NetstackClock`.
///
/// ## What a challenge ACK is here, exactly
///
/// **Every ACK this stack emits in response to a segment it is dropping.** Not
/// the ACK that acknowledges received data, and not the SYN-ACK that answers a
/// handshake — those are the connection making progress, and throttling them
/// would be an attack on the connection delivered by the defence. The
/// distinction exists only inside `TCPStateMachine`, which is why the budget is
/// drawn there and not at `TCPEndpoint`'s egress point: by the time an action
/// list reaches the endpoint, `.sendAck` for a dropped segment and `.sendAck`
/// for a delivered one are the same case of the same enum, and on the wire they
/// are the same frame.
///
/// **No exemption for a segment that carries data**, which is where this parts
/// company with gVisor (`maybeSendOutOfWindowAck` always answers a segment with a
/// payload, on the reasoning that data packets are unlikely to be part of an ACK
/// loop). That reasoning is about ACK loops and this is about amplification: an
/// exemption keyed on "carries a payload" is a bypass of the whole budget for the
/// price of one byte per segment, and a guest that is trying to escape will pay
/// it. See `differential/README.md`.
///
/// The differential run against gVisor recorded the gap this closes: this stack
/// acknowledged *every* unacceptable segment, which is RFC 9293 §3.10.7.4 step 1
/// as written and is also an amplification whose multiplier, timing and cost the
/// guest picks. The guest here is a sandbox whose purpose is to escape, so "the
/// peer will not do that on purpose" is not an assumption available to us.
///
/// ## Where it lives, and what that costs
///
/// One budget per `Stack`, shared by every connection on it (`Stack.tcpChallengeACKs`).
/// Per-connection would have been simpler — it is where the rest of the state
/// machine's state sits, and it needs no new route — but a guest opens
/// connections as freely as it sends segments, so a per-connection bucket is a
/// limit whose multiplier is still the guest's: `backlog` × 100 per second, for
/// the price of a SYN each.
///
/// The cost of sharing is real and worth stating. A guest flooding one
/// connection suppresses challenge ACKs on all of them, so a peer that
/// legitimately needed to resynchronize waits for the bucket instead. That
/// matters much less here than it would in a general-purpose stack: there is one
/// guest, it is the only peer, and traffic it starves is its own. It is also the
/// shape behind CVE-2016-5696, where Linux's *global* challenge-ACK counter let
/// one connection infer that another had been challenged — an off-path side
/// channel that needs two mutually untrusted peers to be worth anything, and
/// this stack has one peer.
///
/// ## The rate
///
/// RFC 5961 §7 leaves the number to the implementation and offers "no more than
/// 10 challenge ACKs in any 5 second window" as its example. 100 per second is
/// Linux's `net.ipv4.tcp_challenge_ack_limit` default and what this stack takes:
/// it is far above anything a working connection needs (a peer that has drifted
/// resynchronizes on the first challenge, not the hundredth) and far below what
/// makes the amplification worth a guest's while.
///
/// No lock, and no `NIODeadline.now()`: this is a `struct` mutated on the
/// stack's event loop like every other piece of connection state, and it reads
/// the clock it was given so a test can freeze time and assert a rate instead of
/// racing one.
struct ChallengeACKBudget {
    /// Challenge ACKs per second. See "The rate" above.
    static let defaultPerSecond = 100

    private let clock: any NetstackClock
    /// The full bucket, and also the per-second rate: the bucket holds exactly
    /// one second's worth, so a burst can never exceed what a second buys.
    private let capacity: Int
    /// How long one token takes to earn.
    private let tokenInterval: TimeAmount
    private var tokens: Int
    /// When `tokens` was last credited. Meaningless while the bucket is full —
    /// `refill` overwrites it before it can be read — which is why it needs no
    /// "not started yet" case.
    private var lastRefill: NIODeadline = .uptimeNanoseconds(0)

    init(clock: any NetstackClock, perSecond: Int = ChallengeACKBudget.defaultPerSecond) {
        let rate = max(1, perSecond)
        self.clock = clock
        self.capacity = rate
        self.tokens = rate
        self.tokenInterval = .nanoseconds(max(1, 1_000_000_000 / Int64(rate)))
    }

    /// Spend one token if there is one. False means this challenge ACK is not
    /// sent at all — RFC 5961 §7 throttles by dropping, not by deferring: a
    /// queued challenge would answer a segment the peer has long since moved
    /// past, and holding one per suppressed segment is the memory the flood was
    /// after in the first place.
    mutating func consume() -> Bool {
        refill()
        guard tokens > 0 else { return false }
        tokens -= 1
        return true
    }

    private mutating func refill() {
        let now = clock.now()
        // A full bucket earns nothing, so there is no partial token to carry and
        // the whole elapsed interval is forfeit. Doing this here rather than
        // leaving `lastRefill` behind is what keeps an idle connection from
        // banking hours of credit against a bucket that was never empty.
        guard tokens < capacity else {
            lastRefill = now
            return
        }
        guard now > lastRefill else { return }
        let earned = (now - lastRefill).nanoseconds / tokenInterval.nanoseconds
        guard earned > 0 else { return }
        // `earned` is a count of tokens and `capacity - tokens` is the room for
        // them; comparing before adding keeps a long idle period from overflowing
        // the `Int` conversion.
        guard earned < Int64(capacity - tokens) else {
            tokens = capacity
            lastRefill = now
            return
        }
        tokens += Int(earned)
        // Advance by exactly what was spent, not to `now`: the remainder is a
        // fraction of a token already earned, and discarding it on every arriving
        // segment would let a peer that keeps the bucket busy hold the refill
        // rate arbitrarily far below what the clock has actually paid for.
        lastRefill = lastRefill + .nanoseconds(earned * tokenInterval.nanoseconds)
    }
}
