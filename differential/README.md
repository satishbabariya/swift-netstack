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

The binary reads a JSON request on stdin:

```json
{"frames": ["<base64 ethernet frame>", ...], "advanceMs": [0, 100, ...]}
```

and writes a JSON response on stdout:

```json
{"emitted": ["<base64 ethernet frame>", ...]}
```

`frames[i]` is injected, then the harness's manual clock is advanced by
`advanceMs[i]` milliseconds, and whatever the stack emitted in response
(including anything a fired retransmission timer produced) is collected
before moving to the next frame. `emitted` is every captured frame across
the whole run, in emission order.

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
