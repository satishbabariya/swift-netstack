# Differential harness

This directory drives gVisor's real TCP/IP stack from the same frame-level
vectors the Swift test suite uses, so the pure-Swift TCP implementation in
`Sources/Netstack` can be diffed against an independent implementation —
one nobody on this project wrote — instead of only against tests written by
the same author as the code. That is the whole point: an earlier phase of
this project shipped roughly thirty real defects that its own
author-matched tests did not catch. This harness, plus the Swift-side
vector runner, are meant to exist *before* any Swift TCP code lands, not
bolted on afterward.

## What's here

- `harness/` — a Go binary (`go.mod`, `main.go`, `link.go`) that builds a
  gVisor `stack.Stack`, wires up a link endpoint that speaks ethernet
  (`link.go`), and drives it from a scripted list of frames.

The binary reads a JSON request on stdin — one run, or a batch of
independent runs each played against its own freshly built stack:

```json
{"frames": ["<base64 ethernet frame>", "", ...],
 "advanceMs": [0, 100, ...],
 "actions": ["", "write:1460", "close", ...]}

{"runs": [ {"frames": [...], "advanceMs": [...], "actions": [...]}, ... ]}
```

and writes a JSON response on stdout, always in the batched shape, one entry
per run and one list of frames **per step**:

```json
{"runs": [ [ ["<base64 ethernet frame>", ...], [], ... ], ... ]}
```

At step `i` the harness injects `frames[i]` (empty string for "nothing
arrives"), advances its manual clock by `advanceMs[i]` milliseconds, reads
and discards whatever the connection has received, performs `actions[i]`
(`write:<n>` or `close`, mirroring the Swift vector DSL's application
lines), and collects everything the stack emitted along the way. Each of
those is followed by a `Stack.Pause`/`Stack.Resume` pair, which blocks until
gVisor's TCP processor goroutines have finished.

Per step, not one flat list per run: a flat list cannot tell "retransmitted
after one second" from "retransmitted after eight", because both stacks emit
the same bytes in the same order either way. The step boundary is the only
timing information a frame-level differential has.

`close` is `Shutdown(Write)`, not `Endpoint.Close`. RFC 9293 §3.10.4's CLOSE
— and this stack's `close()` — shuts the SEND direction and goes on
accepting the peer's data; gVisor's socket close is `shutdown(RDWR)` plus
release, and resets everything that arrives afterwards.

The harness always plays the **gateway** side of the fixed address pair
used throughout this project's vectors: `192.168.127.1` /
`5a:94:ef:e4:0c:ee` (gateway) and `192.168.127.2` / `0a:0b:0c:0d:0e:0f`
(guest) — see `Tests/NetstackTests/Support/VectorFrames.swift` on the Swift
side. It does not learn addressing from the request; a script built
against different addresses will not resolve against anything this stack
owns.

## Build against the module cache, not `-mod=vendor`

There is a vendored gVisor tree elsewhere on this machine
(`airlock/netstack/.work`), and it is tempting to point at it instead of
pulling from the network. Don't: it ships only `link/{loopback,nested,sniffer}`
and no `faketime` and no `link/channel`. This harness needs
`pkg/tcpip/faketime` for a clock that advances under explicit control
(`ManualClock`, not the wall clock — a differential run against a wall
clock would be a race against CI), and that package simply is not in the
vendored tree. Build with:

```
cd harness && GOFLAGS= go mod tidy && GOFLAGS= go build -o harness .
```

against `gvisor.dev/gvisor v0.0.0-20260413194555-9680d69bf798`, resolved
from the Go module cache. If that version is ever bumped, re-verify that
`faketime` is still present at the new pin before assuming the vendored
tree can be substituted — it likely still can't.

## Both stacks are pinned to Reno

`tcp.NewProtocol` (used here) already defaults to Reno internally
(`newProtocol(s, ccReno, nil)`); this harness simply never selects CUBIC by
calling `tcp.NewProtocolCUBIC` instead. This is **load-bearing** for the
comparison: Reno and CUBIC differ in their congestion-window growth and
loss response, so if the two stacks ran different congestion control
algorithms, every timing-sensitive divergence in a diff would be
attributable to that mismatch rather than to a real defect in the Swift
implementation. Whichever side of this you're touching next, do not
introduce CUBIC (or any other congestion control) on either stack without
updating this note and re-justifying the comparison.

**Update: the Swift stack now HAS CUBIC** (`CongestionControlAlgorithm.cubic`,
RFC 9438), and it is opt-in with Reno the default precisely so this comparison
keeps working. That is not the whole reason, though, and the rest is worth
stating because it says what it would take to lift this constraint the way the
option constraints were lifted.

gVisor keeps its congestion window in **whole segments**; this stack keeps a
real number of them, because RFC 9438's growth rule adds
`(W_cubic(t + RTT) - cwnd) / cwnd` per acknowledgement, which is a fraction of a
segment on any window worth having and vanishes if rounded away at each step.
Pinning both to CUBIC would therefore diverge on rounding at every
acknowledgement — and the generator's connections, capped at one initial
congestion window of data, never stay in congestion avoidance long enough for
the shape of the curve to outweigh that. The comparison would report arithmetic
units rather than behaviour, which is the same difference this file records for
the advertised window.

Lifting it needs the generator to sustain a transfer for tens of round trips,
and a decision about the units. Until then CUBIC's evidence is `CubicTests`,
which checks the formulas against the RFC's own arithmetic — weaker, and said so
there too.

## Spoofing and promiscuous mode are both on

The harness calls both `SetSpoofing(1, true)` and
`SetPromiscuousMode(1, true)` on its NIC. Upstream `gvisor-tap-vsock` sets
both, and so does the Swift stack (see the constraints and decisions this
task was built against). Running the comparison with only one side
promiscuous makes every frame diverge for reasons that have nothing to do
with TCP — the point of a differential harness is to isolate what's
actually different in the TCP logic, not to also be diffing NIC modes.

## Ethernet, not bare IP

`link.go`'s link endpoint reports `ARPHardwareType() == header.ARPHardwareEther`
and prepends/strips a real ethernet header on every frame (`AddHeader`,
`ParseHeader`), rather than delegating to gVisor's own
`link/ethernet.Endpoint` wrapper or driving the stack at bare IP. The Swift
stack under comparison speaks ethernet; driving gVisor at bare IP would
make the two stacks structurally incomparable, not just differently
configured.

## CI must build this harness

**Update (M4): a `harness` job now builds this directory on every run, but
the SWIFT job does not, so the differential still silently does not run in
CI. See "CI must build the harness for the SWIFT job" at the end of this
file.**

CI **must** build `differential/harness` as part of every run, not just
when someone remembers to. The Swift-side differential tests locate the
built binary and, if it is absent, skip silently rather than failing — a
skip that runs in about a millisecond and still reports the suite as green.
That means a broken build here, or a CI job that simply forgets to build
this directory, makes the entire differential comparison vanish from CI
with nothing in the output saying so. There is no green checkmark that
distinguishes "the differential suite ran and passed" from "the differential
suite did not run at all." Wire the build into CI explicitly and do not
rely on the Swift tests' skip behavior to catch its absence.

## Verified working

Feeding the harness a single ARP request — constructed with the Swift
codec (`VectorFrames.encode(.arpRequest, direction: .inbound)`), not by
hand — produces a correct ARP reply from the gateway address back to the
requester. See `.superpowers/sdd/2026-08-26-swift-netstack-p2-tcp/task-4-report.md`
for the exact bytes and commands.

## What the differential is, after M4

Everything above describes the harness. This section describes the
comparison it now drives, what that comparison found, and — the part the
next person needs most — which differences are expected, so a new one can
be told from an old one.

The Swift side is `Tests/NetstackTests/TCPDifferentialTests.swift` (the
seeded generator and the gate) and
`Tests/NetstackTests/Support/Differential.swift` (the driver). The Go side
is `harness/main.go`.

```
swift test --filter Differential                       # 300 sequences, ~2s
NETSTACK_DIFFERENTIAL_SEQUENCES=10000 swift test --filter Differential
NETSTACK_DIFFERENTIAL_SEED=1 NETSTACK_DIFFERENTIAL_SEQUENCES=3000 swift test --filter Differential
```

A divergence is reproducible from its seed alone: the generator is
SplitMix64 over `base + index`, and the failure message prints the seed, the
whole script in order, both stacks' frames step by step, and the diff.

### The harness plays a listening endpoint, not a forwarder

`tcp.Forwarder`'s handler could only complete the handshake and immediately
close, so gVisor sent a FIN one round trip after every SYN and reset
everything that arrived afterwards — no data transfer, no retransmission and
no teardown was comparable at all. And the forwarder dispatches on a bare
goroutine, so every frame paid a 200 ms wall-clock wait standing in for
scheduling latency.

`main.go` now binds a real listening endpoint and settles each step with
`Stack.Pause` / `Stack.Resume`, which block until every TCP processor
goroutine has drained its endpoint queue (`dispatcher.go`'s
`processor.start`). That is a **positive completion signal, not a timeout**:
there is no sleep anywhere in the binary, and ten thousand sequences take
about fifteen seconds.

That also removes a hazard the earlier design carried. gVisor processes
segments for an ESTABLISHED endpoint on processor goroutines, so the old
unconditional 200 ms wait was load-bearing for far more than the handshake;
gating it on the frame being a SYN — the obvious optimisation — would have
made the Go collector intermittently blind to every ACK a data segment
provoked.

### What is compared, exactly

Per **step**, not as one flat list of frames. A flat list cannot tell
"retransmitted after one second" from "retransmitted after eight": both
stacks emit the same bytes in the same order either way. Frames are compared
by decoded content and by the step they were drained after.

Spec §8.2 permits three divergences. Two of them are handled by
normalisation rather than by masking:

- **Initial sequence numbers are normalised, not discarded.** Each side's
  gateway ISS is learned from the first SYN it emits and every sequence
  number is expressed relative to it. An earlier version of the driver
  masked `seqStart`/`seqEnd` to constants, which also masked "retransmitted
  at the wrong sequence number".
- **Acknowledgement numbers are compared exactly.** They live in the
  *guest's* sequence space, which the generated script fixes identically for
  both stacks, so there is nothing about them a stack may choose. The
  earlier driver masked them to zero, which made `ack 1` and `ack 4381`
  compare equal and the entire receive-side comparison vacuous.
- **Timestamp option values are masked; the option's presence is not.**
- **ACK coalescing is not masked.** Nothing the generator produces creates a
  frame-count difference from coalescing alone. If a run ever does, it will
  be reported as a divergence — the safe direction — and whoever meets it
  can implement the masking against a real example rather than a hypothesis.

Because the two stacks choose different ISNs, the guest cannot acknowledge
one script against both. Both sides therefore **shift** every inbound
acknowledgement number by their own ISS, which preserves deliberate errors
exactly: a step that acknowledges five bytes too many still does, against
whichever ISS the stack under test chose.

### The one difference that is recognised, and why it is asserted

**The SYN-ACK's advertised window: gVisor 29184, this stack 65535.**

It is reported, labelled `syn-ack-initial-window`, matched against an exact
signature (both windows, the flags, and equality of every other field), and
the gate **asserts that exactly one appears per sequence**. It is not
permitted, it is pinned: a SYN-ACK whose windows are 29184/65500, or whose
option list differs as well, is not recognised and fails.

Neither value is wrong — RFC 9293 mandates no initial window — and neither
side can move:

- gVisor caps the window it offers in a SYN-ACK at
  `InitialCwnd * advertisedMSS * 2` = 10 × 1460 × 2 = 29200, rounded down to
  a multiple of its handshake window scale, giving 29184
  (`endpoint.go`'s `initialReceiveWindow`). At a 1500-byte MTU it *cannot*
  offer 65535 under any configuration. Capping its receive buffer at 65535
  yields 29200, not more.
- Lowering this stack to 29184 was measured and is **worse**: gVisor
  advertises 65535 on every frame after the handshake, so the divergence
  would move from one frame per connection to all of them.

### What gVisor is configured to, and why

The harness pins gVisor's tuning to this stack's own documented constants,
so the comparison is about algorithms rather than about two choices of
number. Each constant is already pinned on its own side by unit tests and by
the vector files.

| option | gVisor default | set to | this stack's constant |
|---|---|---|---|
| `TCPMinRTOOption` | 200 ms (Linux) | 1 s | `RTTEstimator.minimumTimeout` (RFC 6298 §2.4) |
| `TCPMaxRTOOption` | 120 s | 60 s | `RTTEstimator.maximumTimeout` |
| `TCPMaxRetriesOption` | 15 | 8 | `TCPEndpoint.maximumFinTransmissions` |
| `TCPModerateReceiveBufferOption` | on | off | no counterpart; auto-tuning is a gVisor heuristic with no RFC behind it |

The harness also **reads and discards** everything an accepted endpoint
receives, at every step. This stack has no receive socket buffer at all —
`TCPEndpoint` hands in-order bytes straight to `onData` and frees the space
in the same pass — so an unread gVisor buffer would make its window fall
while ours stayed put, on every data segment, for a design reason rather
than a defect. And it **closes** an endpoint that reaches a terminal state,
because gVisor keeps a dead endpoint registered until the application closes
it while this stack deletes the block at once; without that, a segment
arriving after a reset reaches gVisor's corpse and is dropped, where here it
falls through to the listener and is answered.

### The ARP boundary: both caches are kept warm, deliberately

`ARPCache` entries live 60 seconds and an RTO backoff ladder crosses that
inside a single sequence, at which point this stack correctly emits an ARP
request and no TCP segment at all — right in production, and
indistinguishable from a TCP divergence in a diff.

Of the two options, this run takes **keep both caches warm** rather than
"treat an ARP exchange as a recognised difference": a recognised difference
on every long sequence is noise, and noise is how a real divergence gets
waved through. The Go side installs a **static** neighbour entry for the
guest (a learned one would expire after `BaseReachableTime` scaled by a
*random* factor, which under a manual clock is a random point at which
gVisor stops answering with TCP); the Swift side re-asserts the guest in
`Stack.arpCache` before every step. Neither stack emits ARP during a
generated sequence, so an ARP frame in a diff is a real divergence.

## What this run found

Three defects, each frozen as a vector before the code was changed, each
with the seed it was found from. All three were found in the first three
hundred sequences.

**1. No PSH, ever** (seed 6840123409045651459). RFC 1122 §4.2.2.2 clause (2),
carried forward by RFC 9293 §3.9.1, makes PSH on the last buffered segment a
**MUST** for a sender whose send call has no push argument — and
`TCPEndpoint.send` has none. gVisor is right and this stack was wrong. Worse,
`tcp-data.vec`'s header had recorded the omission as a design decision
("legal; PSH is advisory"), and six expected lines in three scenarios had
been written to agree with it. Fixed; three new scenarios pin the rule
(MSS split defers the push, window split does not, a retransmission
reproduces it).

**2. RFC 5681 §3.2's duplicate-ACK test read off the wrong variable** (seed
6840123409045651459). Condition (e) compares the window *in the incoming
acknowledgement* against the one in the last incoming acknowledgement;
`Sender` compared `tcb.sndWnd` before and after, which is what RFC 9293
§3.10.7.4's update rule made of it. The rule refuses a window whose segment
does not advance SND.WL1, so **one out-of-order segment freezes SND.WND** and
every later window update then reads as "unchanged". Three bare
acknowledgements with three different windows made this stack halve its
congestion window and retransmit a segment nothing had been lost of — work
the guest can provoke at will. Fixed; SEG.WND is now a required argument.

**3. TIME-WAIT assassination** (seed 6840123409045651495). A reset arriving
in TIME-WAIT deleted the block and freed the four-tuple. That is RFC 9293
§3.10.7.4 as written, and it is the attack RFC 1337 §3 documents: the block
is exactly the state that stops a delayed duplicate being delivered into the
next connection on the same four-tuple. gVisor implements RFC 1337's fix 1
unconditionally and says so; Linux hides it behind `net.ipv4.tcp_rfc1337`,
off by default, on the reasoning that the peer is not usually an adversary.
Here it always is. Fixed.

Note the shape of all three: **two are places this stack was more lenient
than gVisor and one is a place a normative MUST was simply not implemented.**
None was found by the vectors, which were written by the same author as the
code they check.

## Differences that are NOT defects, and which stack is right

These were investigated, ruled on, and then engineered out of the run — by
constraining the generator, not by permitting a divergence. Each is listed
so the next person can tell a new divergence from a known one, and so that
anyone who widens the generator knows what will come back.

| difference | which stack is right | how the run avoids it |
|---|---|---|
| **SND.WND update rule.** gVisor assigns `s.SndWnd = rcvdSeg.window` unconditionally; RFC 9293 §3.10.7.4 updates only when SND.WL1 < SEG.SEQ, or SND.WL1 = SEG.SEQ and SND.WL2 =< SEG.ACK. | **This stack.** The rule is normative and explicit. | Every guest segment carries the current window; it changes only on an update sent from the highest sequence number the guest has reached, where the rule's precondition holds on both sides. |
| **In-window reset off RCV.NXT.** gVisor's `handleReset` accepts any reset the receive window accepts; RFC 5961 §3.2 requires a challenge ACK unless SEG.SEQ = RCV.NXT. | **This stack.** RFC 5961 exists for the blind-reset attack, and the guest here is the attacker by assumption. | Generated resets sit at exactly RCV.NXT. `tcp-handshake.vec`'s `different-iss` and `TCPStateMachineTests` pin the hardening. |
| **Unacceptable segment.** This stack acknowledges it (RFC 9293 §3.10.7.4 step 1); gVisor drops it in silence. | **This stack**, though note it has no RFC 5961 challenge-ACK rate limit — see "known gaps". | The generator never places a zero-length segment behind RCV.NXT. |
| **Congestion window units.** RFC 5681 §3.1 counts cwnd in bytes and this stack does; gVisor and Linux count whole segments, so `(cwnd - outstanding) * MSS` refuses what a byte count would allow. | **Both.** Conformant either way. | One application write per sequence, no larger than one initial congestion window and no larger than the offered window, so the whole write is on the wire in one pass and a second one never has to fit into what is left. |
| **FIN behind unacknowledged data.** This stack forms the FIN and sends it as soon as preceding sends are segmentized (RFC 9293 §3.10.4); gVisor queues it behind the unacknowledged data and lets its congestion window decide, so after an RTO it holds the FIN indefinitely. | **This stack**, on the RFC's text. | `close` only once everything written has been acknowledged. |
| **Handshake RTT sample.** gVisor takes one from the SYN-ACK/ACK round trip; `Sender` models no SYN, so this stack takes none and starts its estimator from the first data sample. RFC 6298 requires *a* sample, not which one. | **Both**, but gVisor's is what every deployed stack does, and this stack's first data RTO is up to 3× longer as a result (a 716 ms sample put its first FIN retransmission at +2.148 s against gVisor's +1.000 s). Worth revisiting in M5. | Every acknowledgement of our data arrives in the next step with **no time advance**, so every sample is zero and both estimators stay pinned to RFC 6298 §2.4's one-second floor. |
| **NewReno `recover`.** gVisor declines fast recovery unless the cumulative acknowledgement is strictly past `FastRecovery.Last`, comparing it against `SEG.ACK - 1`; initialised to the ISS, that suppresses the *first* loss episode of a connection entirely. RFC 6582 §3.2 step 1 asks for "covers more than `recover`", which ISS+1 does. | **Probably this stack**, but it is an M5 question about NewReno and not one this run can settle. | The duplicate-acknowledgement case acknowledges one segment first, which puts the episode past the off-by-one. |

## Timestamps: the third generator constraint lifted

The generated SYN now offers `mss`, `wscale` and `timestamp`. Only `sackOK`
remains withheld, and it stays withheld for the original reason: nothing here
acts on a SACK block, so gVisor would send blocks into a stack that ignores them.

Three things had to change with it, and each was a real finding rather than a
formality.

**Every generated segment carries the option, not just the SYN.** RFC 7323 §3
requires it once negotiated, and a generator that stamped only the SYN would be
modelling a peer that negotiates the option and then stops using it. gVisor
refuses such a connection outright — the third-leg ACK arrives unstamped and the
handshake never completes — which surfaced as `close has no accepted connection
to act on` rather than as anything mentioning timestamps.

**Option order is now normalised in the comparison.** This stack emits
`mss, wscale, timestamp` in a SYN-ACK; gVisor emits `mss, timestamp, wscale`.
RFC 9293 requires no order and no receiver depends on one. Sorting removes
*ordering only*: a missing option, an extra one or a changed value still fails,
because the sorted lists differ the moment their contents do. It is neither a
permitted divergence nor a recogniser — it is putting both sides in the same form
before comparing, as this run already does for sequence numbers.

**The write cap had to shrink, and the reason is a difference that timestamps made
reachable.** The initial congestion window is ten segments, and a timestamped
segment carries twelve fewer bytes. A write sized against 1460-byte segments needs
eleven 1448-byte ones — which this stack's byte-counted window admits and gVisor's
segment-counted window does not, so gVisor withholds the eleventh. That units
difference is recorded below as one the run deliberately stays away from; enabling
timestamps moved the boundary, and the cap had to follow. It appeared only at
10,000 sequences, not at 300.

## Window scaling: what changed when the constraint was lifted

The generator used to offer `mss` alone. It now offers `mss` and `wscale`, and
still not `sackOK`.

That was always the plan. The restriction was scoped as a **generator
constraint** rather than a permitted divergence precisely so that lifting it
would be a task someone has to do, one option at a time, by whoever implements
the option — rather than a hole someone has to remember. `wscale`'s lift belongs
to the window-scaling work; `sackOK`'s belongs to whoever implements SACK,
because nothing here acts on a SACK block and gVisor would send blocks into a
stack that ignores them.

**Two configuration changes were needed on the Go side, and both are about
comparing behaviour rather than configuration.**

`TCPReceiveBufferSizeRangeOption` now sets gVisor's receive buffer to 256 KiB,
the Swift reassembler's capacity. Without it each side derives its shift from its
own buffer — gVisor's 1 MiB default gives `wscale 5` against this stack's
`wscale 3` — and every window afterwards is scaled by a different factor. With
the capacities matched, both stacks independently pick **3**, which is worth
noting: they use the same rule (the smallest shift that fits the capacity into
the 16-bit field) without having been made to.

`TCPModerateReceiveBufferOption(false)` turns off gVisor's receive-buffer
auto-tuning. This stack does not auto-tune — its window is a function of what the
reassembler holds and nothing else — so leaving moderation on compares two
policies and calls the difference a divergence. (Measured: it changed none of the
numbers here, but it removes a reason for them to move later.)

### A second recognised difference, and what it costs

**Window scaling did not create the window difference. It made it visible.**
Before the scale, both stacks' advertised windows were clipped to 65535 by the
header field, so two different receive capacities produced the same number and
the comparison matched by accident. With the scale applied each side expresses
what it actually has: this stack advertises what its reassembler holds, gVisor
charges `SegOverheadSize` per segment against its buffer and advertises roughly
half. Both are honest about their own capacity; they account for overhead
differently, and RFC 9293 mandates no particular window.

So `scaled-advertised-window` joins `syn-ack-initial-window` as a *recognised*
difference — asserted, not permitted. It is bounded by "the window is the **only**
difference", on any frame. The first attempt restricted it to bare ACKs and the
very next sequence produced the same difference on a FIN-ACK, which showed the
restriction was arbitrary rather than principled.

**What that masks:** a defect changing only the advertised window, and nothing
else about the frame, is not caught here. Exact-window coverage lives in
`tcp-data.vec` instead, where the peer is fixed and the numbers are derived by
hand, so it cannot drift with a reference implementation's buffer policy.

Both labels are counted and asserted — the SYN-ACK's exactly once per sequence,
the scaled window at least once — and a third label appearing without anyone
adding one fails the run.

## What the generator deliberately does not vary

Every one of these is a scoped restriction with a reason, not an oversight.

- **The SYN offers `mss` and nothing else.** gVisor mirrors its peer's
  options — it offers `wscale` and `sackOK` exactly when the SYN did, and no
  configuration makes it omit an option the peer offered (capping its
  receive buffer yields `wscale 00`, not no option). This stack negotiates
  neither, so a SYN offering them would put an option-list difference on the
  SYN-ACK of every sequence. The case where a guest *does* offer both is
  pinned by `tcp-handshake.vec`'s `passive-open`. **This constraint
  disappears when window scaling lands in M5.**
- **Every data-bearing segment is at least 628 bytes** — gVisor's
  `tcp.SegOverheadSize` for the pinned version. A smaller in-order delivery
  does not move gVisor's advertised right edge (`rcv.go`'s `toGrow` gate),
  so its window falls while this stack's — which has nothing to hold — stays
  at its ceiling. The first thing after every handshake is a full-MSS
  in-order segment for the same reason.
- **Out-of-order segments land less than 20000 bytes ahead of RCV.NXT.**
  gVisor's real right edge after the first delivery sits far beyond the
  16-bit window it advertises, so it accepts out-of-order data this stack
  correctly refuses as outside the window it promised. The trim itself is
  pinned by `tcp-data.vec`'s `right-edge-trim`.
- **The offered window never goes below 4096.** A closed window puts a
  sender into RFC 9293 §3.8.6.1's persist state. Both stacks probe one; what
  they are not required to agree on is *when*. The probe's timing is a SHOULD
  in both documents that specify it (RFC 9293 SHLD-29, SHLD-30) and the
  interval ceiling is explicitly left open — RFC 1122 §4.2.2.17: "possibly
  with some maximum interval not specified here" — so a divergence there would
  be a report about nothing. See "what this run does NOT cover".
- **No data after the peer's FIN, and the peer's FIN only with nothing
  queued ahead of it.** Both are cases where the two stacks' handling is
  pinned by vectors (`data-past-the-fin`, `fin-ahead-of-rcv-nxt`) and where
  the generator's own model of RCV.NXT would otherwise drift.
- **One application write per sequence**, bounded by the offered window and
  by one initial congestion window. See the congestion-window row above.

## What this run does NOT cover

- **The RTO the Jacobson update produces once it escapes the floor.** Samples
  are now 700 ms rather than zero, so the update itself runs — SRTT and RTTVAR
  both move on every acknowledged write — but at that size the resulting RTO is
  about 788 ms and RFC 6298 §2.4's one-second floor clamps it, so the number
  that reaches the wire is the floor either way.

  **This constraint used to have a different reason, and that reason is dead.**
  It read: this stack takes no RTT sample from the handshake while gVisor does,
  so the two estimators start from different state. Plan 3 added the handshake
  sample, so they now start from the same place — and the constraint survives for
  a new reason, found by removing it.

  Raising the round trip to 2000 ms puts the RTO at about 2250 ms, clear of the
  floor, and **the two stacks then disagree**: a FIN retransmission lands one step
  apart, gVisor at step 12 and this stack at step 13 on the first seed. Both seed
  from the handshake, so the difference is in the update arithmetic or in the
  clock granularity `G`, not in whether a sample is taken. Which stack is right is
  **unresolved**, and it is the most concrete open question this instrument has.

  **To reproduce: change the `advanceMs: 700` in the write follow-up to 2000.**
  One number, one run. `tcp-data.vec`'s `rtt-sample-drives-the-rto` remains the
  only wire-level cover of the estimator on this side. **Do not report the
  estimator as differentially verified.**
- **Window scaling, SACK and timestamps.** Not implemented here; the
  generator does not offer them.
- **Payload bytes.** `VectorFrames` encodes and decodes segment *lengths*,
  not contents, so a stack that retransmitted the right length from the
  wrong offset would be caught by the sequence number and not by the data.
  `TCPSenderTests` and `TCPReassemblerTests` cover content.
- **Two connections at once**, and therefore the backlog, the TIME-WAIT cap
  and the four-tuple demultiplexing. One connection per sequence.
- **The full FIN retransmission budget.** The ladder reaches five rungs
  inside a sequence's virtual time; the eighth-transmission give-up is
  pinned by unit tests.
- **Zero-window probing, in its entirety.** The generator floors the offered
  window at 4096 (see the row above), so no sequence ever reaches the persist
  condition and the harness exercises none of it: not the probe, not its one
  byte, not the backoff ladder, not the absence of a give-up budget. **A green
  differential run says nothing whatever about persist.** It is pinned by
  `tcp-data.vec`'s `a-lost-window-update-is-recovered-by-a-zero-window-probe`
  and `zero-window-probes-back-off-and-do-not-give-up`, and by the persist
  section of `TCPSenderTests` — which is where the thousand-probe check that
  actually falsifies a give-up budget lives, since no vector of a runnable
  length can reach that far up the ladder.
- **The duplicate-acknowledgement window condition (e) itself.** Closing the
  SND.WND-update difference above also removed the traffic that exposed
  defect 2: the differential no longer reaches it. It is pinned by
  `tcp-data.vec`'s `window-updates-are-not-duplicate-acknowledgements` and
  its positive control, which is where that regression protection now lives.

## The RTO disagreement, traced to a cause

Three sightings — a FIN above the floor, persist below it, and the run below —
all had the same shape: a retransmission landing one step apart. It is one cause,
and it is **not** the estimator arithmetic.

**Reproduction:** seed `6840123409045651477`, with the write follow-up's
`advanceMs` at 2000 instead of 700. Both stacks agree on every frame up to the
FIN and disagree only on when it is retransmitted.

**The trace.** The application writes 304 B at t≈821 ms. The RTO is at RFC 6298
§2.4's one-second floor, so it expires at t≈1821 ms and **both stacks retransmit**
— that step is identical. §5.5 then doubles the RTO to 2000 ms on both sides. The
guest's acknowledgement arrives at t≈2821 ms, and Karn's algorithm applies: the
segment was retransmitted, so the acknowledgement is ambiguous and **neither stack
may take a sample from it**. The FIN goes out at t≈3936 ms. gVisor retransmits it
within (4975, 5875]; this stack within (5875, 6775] — roughly 2× later, which is
exactly the doubling.

**So the difference is whether an acknowledgement of new data clears the RTO
backoff when Karn has forbidden a new measurement.**

- **This stack keeps it.** The backoff is discarded only by
  `RTTEstimator.measure`, so the first *unambiguous* sample clears it and an
  ambiguous acknowledgement does not (`Sender.swift`, `retransmitTimerFired`'s
  doc comment). That is RFC 6298 read literally: §5.5 doubles the RTO, and nothing
  in §5 undoes it except recomputation from a measurement Karn has just forbidden.
- **gVisor and Linux clear it** on any acknowledgement of new data
  (Linux zeroes `icsk_backoff` on `FLAG_ACKED`), on the reasoning that a delivered
  segment is evidence the path works, and the backoff exists to respond to loss.

**Neither is an RFC violation, and the practical case favours changing.** Keeping
a doubled RTO after the path has demonstrably delivered means the *next* loss is
detected twice as slowly, for no benefit — and "every deployed stack does it" was
the argument that settled the handshake-sample question earlier in this plan. The
counter-argument is real but weaker: the acknowledgement is ambiguous precisely
because we cannot tell which transmission it answers, and if it answers the
original then the path is slow rather than lossy.

**Tried, and reverted, because the premise was wrong — and measuring is what
showed it.**

The change made `Sender.acknowledged` discard the backoff when SND.UNA advances,
justified as "gVisor and Linux both do this". It moved the FIN retransmission from
one step *late* to one step *early*, which was the first sign something was off:
converging on the reference should close a gap, not cross it.

So the harness was instrumented to report gVisor's own estimator through
`tcpip.TCPInfoOption`, and the answer is unambiguous:

```
step=7  rto=1s  rtt=10ms  rttvar=5ms
step=8  rto=2s  rtt=10ms  rttvar=5ms
step=11 rto=2s  rtt=10ms  rttvar=5ms
step=12 rto=4s  rtt=10ms  rttvar=5ms
```

**gVisor accumulates the doublings across acknowledgements** — 1 s, then 2 s held
across four steps, then 4 s — and its `rtt`/`rttvar` never leave the handshake
sample, so Karn holds there too. It does **not** clear the backoff on an
acknowledgement of new data. That claim was carried over from Linux's
`icsk_backoff` behaviour and never checked against the reference this project
actually compares against.

Reverted. What this stack already had — the backoff surviving until a fresh
unambiguous sample — is both the literal RFC 6298 reading and what gVisor does.

**Linux's behaviour may still be the better engineering.** Keeping a doubled RTO
after the path has demonstrably delivered detects the next loss twice as slowly.
But it would have to be argued on its merits, as a deliberate divergence from the
reference, rather than on "everyone does it" — which turned out to be false.

## The residual disagreement: closed, by RFC 7323 Appendix G

**Closed.** The reproduction above — seed `6840123409045651477` with the write
follow-up at 2000 ms — now agrees on every frame.

The cause was not the backoff and not the arming. It was the **sampling gain**,
and it was found by doing what this section already recommended: instrumenting
both estimators rather than reasoning about them. `NETSTACK_HARNESS_RTO=<path>`
writes gVisor's `TCPInfoOption` per step; the same figures were printed from this
side, and at one instant, on one acknowledgement, gVisor's smoothed round trip
stayed at 10 ms while this one jumped to 259 ms.

**RFC 7323 Appendix G.** RFC 6298's α = 1/8 and β = 1/4 are chosen for one sample
per round trip, which is what Karn's algorithm gives. Timestamps make a usable
sample arrive with *every* acknowledgement, so the estimator tracks as many times
too fast as there are segments in the window. The appendix divides both gains by
`ExpectedSamples = ceil(FlightSize / (2 * SMSS))`.

**The edge is what mattered.** A flight of zero makes that divisor zero — a
division by zero, not a gain of one — so the acknowledgement that retires the
*last* outstanding segment carries no usable sample. gVisor guards it with
`if s.Outstanding == 0 { return }` in `updateRTO`. And that acknowledgement is
exactly the one most likely to be inflated: the one arriving after a
retransmission, echoing a timestamp from a transmission the peer may never have
seen. Taking it once moved the estimate twenty-five-fold on a path whose real
round trip was 10 ms, and every timer derived from it landed a step late for the
rest of the connection.

**The consequence is worth knowing rather than discovering.** A connection that
sends one segment at a time and waits for each acknowledgement never updates its
estimate after the handshake. That is what gVisor does too, which is what settled
it — `theAcknowledgementThatEmptiesTheFlightProducesNoSample` records it as a
property rather than leaving it to be found.

The earlier attempt in this section reasoned from Linux's `icsk_backoff` and
reached a conclusion that did not describe gVisor at all. This one asked.

## Nagle: another configuration difference, and two attempts that failed

RFC 9293 §3.7.4 is implemented. gVisor does not apply it by default, so it sends
the short tail of every write at once where this stack holds it until something is
acknowledged — a configuration difference rather than a disagreement about the
rule.

**Two attempts to turn it on in gVisor, both measured and both ineffective**, so
nobody repeats them:

- `tcpip.TCPDelayEnabled(true)` as a transport protocol option. No change: gVisor
  still sent every tail immediately.
- `ep.SocketOptions().SetDelayOption(true)` on the accepted endpoint, on the
  theory that the protocol option does not reach an endpoint the listener
  produced. Also no change.

Whatever gVisor's Nagle is gated on, neither knob reaches it from here. So the
comparison runs with Nagle off on **this** side instead —
`TCPEndpoint(nagleDisabled:)`, alongside the delayed-acknowledgement timeout,
both stated at the one construction site.

**What that costs:** the run does not compare small-segment buffering at all.
`tcp-data.vec`'s `push-on-the-last-segment-of-a-write` pins it instead, and pins
it better than the differential could — it shows the tail waiting for an
acknowledgement and then going, which is the whole of what Nagle costs and buys
on one write.

**Two bugs the existing tests caught while implementing it**, both interactions
invisible from Nagle alone:

- **A zero-window crawl deadlocked.** A peer offering one byte at a time produces
  a segment that is never full-sized, with something always outstanding — so
  Nagle buffered it, and the peer, waiting on data before opening the window
  further, never sent the acknowledgement that would release it. Fixed by the
  third escape: when the *window* limits the segment rather than the data
  available, send it. Nagle exists to stop an application dribbling into a path
  that could carry more; it has nothing to say about a segment that is small
  because the receiver said so.
- **A zero-window probe counted as outstanding data.** The peer answers a probe by
  reopening its window, and this stack then held everything queued because the
  one byte it had been obliged to send to ask the question was unacknowledged.
  The probe is excluded now: Nagle's "unacknowledged data" means user data this
  sender chose to put on the path, and a probe is not that.

Both were caught by *persist* tests rather than Nagle ones.

## Delayed acknowledgements break the run's alignment, and a recogniser cannot fix it

RFC 9293 §3.8.6.3 is implemented. All 527 unit and vector tests pass, and the
differential passes with the delay turned off for the comparison — the reason it
had to be turned off is structural rather than a missing mask.

**The spec listed ACK coalescing as a permitted divergence from the start**, and
this file recorded that nothing in the run had produced one yet, so whoever met it
should "implement the masking against a real example rather than a hypothesis".
Delaying acknowledgements produced the example. Masking it turned out not to be
possible in the shape that was planned.

**First attempt: recognise a bare acknowledgement gVisor sent that this stack did
not.** One-directional on purpose, reasoned as "coalescing can only ever remove
one of our frames, never add one". That reasoning is **wrong**, and the run said
so on the next comparison: the divergence flipped to *this stack* emitting a bare
acknowledgement gVisor did not, at a later step.

Coalescing does not only remove frames — **it moves them between steps.** A held
acknowledgement is released by its own timer during whichever step advance covers
the deadline, and that is not the step the peer's segment arrived in. So the two
stacks flush on different schedules and their per-step frame lists no longer line
up, in both directions.

A two-directional recogniser would mask a spurious acknowledgement this stack
invented, which is a real defect class and not one worth trading away for a green
run. Withdrawn.

**Resolved by configuration, stated rather than masked.** `TCPEndpoint`'s
`delayedAckTimeout` is injectable and the differential constructs its endpoint
with `.zero`. The stack under comparison therefore acknowledges at once, its
frames align with gVisor's again, and the 10,000-sequence gate is clean.

What that costs, precisely: **the run no longer compares sub-500 ms
acknowledgement timing at all.** It is pinned in `tcp-data.vec` instead, against a
fixed peer whose timing cannot drift with a reference implementation's own
heuristics — which is the better place for it, since gVisor's schedule was never
going to match this one.

Two alternatives were considered and rejected. Advancing past the timeout at every
step would restore alignment too, but every step would then be at least half a
second and the RTO behaviour the run *does* compare would be distorted. Comparing
acknowledgement *coverage* across the run — that none is lost and none invented,
without requiring them in the same step — is strictly better and is the right
thing to build if this ever needs to compare timing again; it is a larger change
to the instrument than to the stack, and it was not needed to get the gate clean.

**Also measured while here, and deliberately NOT implemented:** gVisor answers the
FIRST full-sized segment after a handshake at once, where "every second full-sized
segment" alone would hold it — Linux's quick-ACK mode. RFC 9293 neither requires
nor forbids it, and the argument for it is real: delaying the first
acknowledgement of a connection delays the sender's congestion window opening, and
slow start is when the window most needs to move.

It was tried and reverted once, because it invalidated five expectations that had
just been re-derived for the delay. The reason it stays out is stronger than that
timing accident, though, and worth stating so it is a decision rather than a
backlog item:

**Nothing here can verify it.** The differential now runs with delayed
acknowledgements off, so it does not compare acknowledgement timing at all; the
vectors pin timing against a fixed peer, so they would only reflect whatever rule
was written into them. The benefit is real-world throughput at connection start,
which no instrument in this repository measures. Implementing it would mean
churning the delayed-acknowledgement vectors for a change whose value could only
be asserted, not shown.

That is a poor trade in a project whose whole method is that a property nothing
can falsify is a property nobody should claim. It belongs with the throughput gate
(M7), where a measurement exists to justify it.

## Persist: widened, and withdrawn again with a reason

The generator holds the offered window at or above
`DiffLimits.minimumOfferedWindow`, so no sequence enters RFC 9293 §3.8.6.1's
persist state. That was widened and then withdrawn, and both halves are worth
recording because the attempt found two things.

**First, the widening was silently doing nothing.** A case that closes the window
with data unacknowledged was added at `58..<62` — inside the `52..<62` range of
the case above it. Swift takes the first matching case, so it was dead code, and
`enteredPersist` was exactly 0 across 300 sequences. **Only a coverage floor
caught it**: the run was green and the new path had never once executed. That is
why the `entersPersist` flag and its counter are still here despite the case being
withdrawn — the next attempt should assert the floor *before* trusting a pass.

**Second, once it actually fired, the two stacks disagreed** — and not about
window arithmetic. The same segment is retransmitted on different schedules
(this stack at steps 8 and 10, gVisor at step 9), which is the third place a
retransmission has landed one step apart, after the FIN case in the RTT section
above. The open question is the same one, and this widens its reach: it is not
confined to a FIN, and it appears here even with samples under the RTO floor.

There is also a behavioural question underneath the timing one, unresolved:
**when the window closes with unacknowledged data in flight, which timer owns the
connection?** This stack switches to persist; gVisor appears to go on
retransmitting. Both readings have RFC support and they produce different wire
behaviour, so this needs settling before persist can be compared frame for frame.

**To reproduce:** re-add a case that emits `window: 0` with unacknowledged data,
in a range that does not overlap the one above it, and assert
`coverage.enteredPersist` is non-zero before reading anything else into the result.

## SACK: the last generator constraint, lifted twice

`sackOK` was the last option the generator withheld. It was lifted once when
SACK's receiver half landed, went back, and is now lifted for good. There are no
option constraints left.

**The first lift found four defects in the receiver half** that eleven unit
tests had not:

1. **Data segments overflowed the options area.** Options come out of the
   payload (RFC 6691), and SACK is added at the egress point, after a segment
   has been cut. The payload budget charged the timestamp only, so the header
   passed 40 bytes, the four-bit data offset wrapped, and the frame went out
   unparseable — reported here, in as many words, as "Swift emitted an
   undecodable frame".
2. **The per-segment budget fixed the wrong problem.** A segment is cut once and
   may be retransmitted much later, when more blocks are being reported than
   when it was sized. The budget has to be the connection's worst case, which is
   what gVisor's `endpoint.maxOptionSize` computes too.
3. **Blocks were still reported after close** — and the first fix for that was
   wrong. Dropping the queue on close matched gVisor's silence, but a later
   sequence showed gVisor still acknowledging data it had queued before closing,
   which contradicts the explanation the fix was built on. Reverted; see the
   recogniser below for what gVisor actually does.
4. **Block ordering disagreed from the second out-of-order arrival onward.** RFC
   2018 §4 requires the run containing the newest segment first and asks for the
   rest in the order they were most recently reported. The first version did the
   MUST and skipped the SHOULD.

**Why it went back.** With `sackOK` negotiated, gVisor's *sender* switches to
SACK-based recovery, and on the third duplicate acknowledgement the two stacks
made different choices. That is a behavioural difference in a path this
comparison exists to cover, so the constraint stood until the sender half
existed.

**The second lift found five more**, all in code the sender half touched:

1. **Bare duplicate acknowledgements still entered fast recovery.** RFC 6675 §2
   redefines "duplicate" on a SACK connection: an ACK counts only if it carries
   previously unknown SACK information. gVisor's `isDupAck` opens with exactly
   that test. Without it this stack retransmitted and inflated its window where
   gVisor did neither.
2. **SMSS was the negotiated MSS rather than the payload size.** RFC 5681
   defines SMSS excluding options, so the initial window of ten segments was a
   few hundred bytes wider than ten segments — invisible until a write landed
   just past the boundary and produced one extra short segment on the opening
   burst.
3. **The timestamp option was packed tight instead of aligned.** `NOP NOP TS` is
   twelve bytes and `TS` alone is ten; with SACK beside it the difference moved
   the reserved options area from 40 to 36 and every data segment from 1420
   bytes to 1424.
4. **A short retransmission was charged by its length.** Under a window
   collapsed to one segment by a timeout, a first segment that had been
   window-limited to 1380 bytes left 40 bytes of slack, and a 26-byte
   retransmission went out into it — two packets from a window that RFC 5681
   §3.1 had just collapsed to one. gVisor and Linux count this window in
   segments; this stack now charges a whole segment per retransmission, for the
   reason that what a path carries is packets.
5. **Block ordering ignored duplicate arrivals.** §4's MUST is about "the
   segment which triggered this ACK", and a segment wholly duplicating a held
   run triggered it just as much as a novel one. Recording only novel pieces
   looked equivalent and was not.

**A generator constraint had to widen with them.** The write cap is "one initial
congestion window", computed as ten segments less the options each carries. It
named the timestamp alone, so enabling SACK left it forty bytes per segment too
generous — and the step that acknowledges the whole write then acknowledged data
that had not been sent. RFC 9293 §3.10.7.4 answers that with an ACK and gVisor
stays silent, which is a real difference on an acknowledgement the generator
never meant to produce.

**RACK is off in the harness** (`tcpip.TCPRecovery(0)`), a configuration
difference in the same family as Nagle and delayed ACKs above. With SACK
negotiated gVisor enables RACK-TLP (RFC 8985), whose tail loss probe fires
around 200 ms after the last transmission — so gVisor retransmits a FIN once
before its RTO would have, and this stack waits out the full RTO. gVisor's
behaviour is better; the setting records the gap rather than denying it, and
RACK is the next TCP feature.

**One recognised difference came out of it**, and it is the only one with a
source line rather than an inference behind it. `connect.go`'s `sendRaw`
attaches blocks only while the endpoint is ESTABLISHED, so gVisor stops
reporting after `Shutdown(Write)` and this stack does not. RFC 2018 puts no
state restriction on the option and a receiver in FIN-WAIT-2 is still receiving,
so this stack is right and matching gVisor would mean copying a limitation. See
`Differential.recogniseSackAfterEstablished`, which is also the first recogniser
to compose with another: the frames it appears on carry the window difference
too, and a chain of alternatives cannot see that one frame needs two rules.

## Known gaps in this stack, visible from here

Not comparison nuisances — real limitations, recorded because the
differential is where they became visible.

- **~~There is no receive-side backpressure at all.~~ Closed in M6.** `onData`
  used to be called synchronously with the space freed in the same pass, so the
  advertised window described a buffer that never held anything — honest in the
  narrow sense that the stack really did have all that room, and useless in the
  sense that an application which ignored `onData` had its data acknowledged and
  then dropped. The peer was told the bytes arrived; nobody had them.

  It was an *interface* consequence, so the fix changed the interface rather than
  adding to it. `onData` is a readiness signal now; `read` takes the bytes;
  delivered-but-unread bytes sit on the connection and the receiver subtracts
  them from RCV.WND, so the advertised window finally describes what the
  connection will accept. `TCB.heldBytes` carries the count, which keeps
  `Receiver` the single writer of RCV.WND — the ownership rule two Criticals came
  from breaking.

  Three things fell out of it that the plan did not predict, each caught by a
  test rather than by review:

  - **Reading emitted an acknowledgement per read.** RFC 1122 §4.2.3.3's
    silly-window-syndrome avoidance is required here, and the first attempt at it
    was itself the syndrome: it compared the buffer's capacity against the last
    *advertised* window, which the 16-bit field caps whenever no scale is
    negotiated — so it read "the window opened by 196 KiB" on a connection where
    nothing was ever held, and fired on every read. Measured as bytes *freed*
    instead, which compares like with like.
  - **The update still duplicated the acknowledgement about to be sent.** A read
    inside `onData` is a read the arriving segment caused, and that segment is
    usually acknowledged in the same pass. The update is deferred and rides it.
  - **Segment boundaries stopped surviving above the stack**, and should: two
    segments delivered in one pass are one read, because an application reads a
    byte count and not a segment list.
- **~~After a timeout, only the earliest unacknowledged segment is
  retransmitted, once per timeout.~~ Closed in M5.** RFC 6298 §5.4 asks for no
  more, so this stack was conformant and unusable at the same time: recovering an
  *n*-segment loss burst cost *n* timeouts on a backing-off ladder, about 31
  seconds for five segments against roughly one on any deployed stack.
  The expiry now presumes every outstanding byte lost — the same judgement
  RFC 5681 §3.1 makes one line above when it collapses the window to a single
  segment — which is what leaves room under the collapsed window for anything to
  go out at all. `drainPresumedLost` then retransmits the remaining holes
  oldest-first as acknowledgements arrive, at most once each per episode, and
  `timeout(flightSize:)` is called exactly once so slow start is not quietly
  disabled. Pinned by `tcp-data.vec`'s `a-timeout-keeps-retransmitting`.
- **~~No RFC 5961 challenge-ACK rate limit.~~ Closed in M5.** This stack used to
  acknowledge every unacceptable segment, which is RFC 9293 §3.10.7.4 step 1 and
  is also an amplification the guest controls. There is now a stack-wide token
  bucket (`ChallengeACKBudget`, 100 per second, refilled from the injected
  `NetstackClock`) that **all six** challenge-ACK sites in `TCPStateMachine`
  spend from — RFC 5961 §3.2's blind reset, §4's SYN on a synchronized
  connection, §5's acknowledgement of data never sent, and RFC 9293 §3.10.7.4
  step 1's acknowledge-and-drop in each of its three arms. It is a limit on the
  ACK only: the 2·MSL restart that travels with a TIME-WAIT FIN retransmission is
  unconditional, or a guest could expire a TIME-WAIT block by emptying the budget
  elsewhere. See `TCPEndpointTests`' challenge-ACK section.

  Two adjacent 1:1 emitters are deliberately **not** throttled, and both are worth
  knowing about before someone reports them as the same gap: the SYN-ACK
  reproduced for a retransmitted SYN in SYN-RECEIVED, and the reset `Stack`'s TCP
  handler sends for a port with no endpoint. Neither is a challenge ACK, both are
  what lets a peer make progress, and throttling either turns a flood on one
  connection into a refusal to open another.

  **The generator now does place a zero-length segment behind RCV.NXT**, so the
  acknowledge-and-drop path is exercised — and the divergence predicted here duly
  appeared on the first run: a step where this stack answered and gVisor stayed
  silent, reported as "Swift emitted a frame with no matching Go frame".
  Both stacks are conformant. RFC 5961 §7 mandates no rate, and the two throttle
  differently in both dimensions
  (`transport/tcp/endpoint.go`'s `allowOutOfWindowAck`, called from
  `connect.go`'s handshake and from `snd.go`'s `maybeSendOutOfWindowAck`):

  | | this stack | gVisor at the pinned version |
  |---|---|---|
  | shape | token bucket, 100 tokens, one second to refill | minimum *interval* between two out-of-window ACKs, no bucket |
  | rate | 100 per second, burstable to 100 at once | `defaultTCPInvalidRateLimit` = 500 ms, so 2 per second and never two together |
  | scope | one budget per `Stack` | `lastOutOfWindowAckTime` per **endpoint**; only the interval is a stack option |
  | data-bearing segments | throttled like any other | **exempt** — `maybeSendOutOfWindowAck` always ACKs a segment with a payload |

  That last row is a deliberate disagreement, not an oversight. gVisor's exemption
  is aimed at ACK loops, where a data segment is unlikely to be one; the threat
  here is amplification, and a one-byte payload would turn the exemption into a
  bypass of the whole budget for the price of one byte per segment. Pinned by
  `aFloodOfUnacceptableSegmentsCarryingDataIsBoundedToo`.

  **How the run avoids it, and what that costs.** Each unacceptable segment is
  preceded by 500 ms of quiet, which puts both stacks in the answer-every-one
  regime. What is then compared is RFC 9293 §3.10.7.4 step 1's requirement to
  acknowledge — normative, and now exercised on both sides — rather than the
  throttle rate, which is not mandated by anything.

  A generator constraint again, not a permitted divergence, and for a sharper
  reason than usual: recognising this one would mean recognising *"we emitted a
  frame and gVisor did not"*, which is precisely the class of difference the
  instrument exists to catch. A recogniser that broad would mask a genuinely
  missing frame anywhere else in the run.

  **So the rates themselves remain covered by unit tests alone.** Widening this
  further — to compare what happens when a throttle actually engages — would need
  the two policies reconciled first, and they are not reconcilable: 100 per second
  with bursts against 2 per second with none is a difference in kind.

  That also explains part of a row in the table above: "gVisor drops an
  unacceptable segment in silence" is not only a policy difference, it is this
  limiter, which at 500 ms suppresses everything a generated sequence sends after
  the first. A widened generator would see gVisor answer roughly one challenge and
  this stack answer a hundred, both conformant — RFC 5961 §7 fixes no number and
  offers "no more than 10 in any 5 second window" only as an example.

## CI must build the harness for the SWIFT job

The `harness` job builds `differential/harness` on Linux, which catches a
harness that no longer compiles. It does **not** make the differential run:
the Swift job is a separate macOS runner with no Go step, so
`differentialHarnessPathIfBuilt()` returns nil there and every differential
test returns immediately, in about a millisecond, reporting green.

There is still no green checkmark that distinguishes "the differential ran
and passed" from "the differential did not run". Building the harness in the
Swift job would fix that, and the 300-sequence default takes about two
seconds.
