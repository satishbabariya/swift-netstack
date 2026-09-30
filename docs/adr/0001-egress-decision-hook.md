# ADR 0001: Where a gateway may refuse egress

- **Status:** Proposed
- **Date:** 2026-09-29
- **Applies to:** `Sources/Netstack` at `fb2070d`. Line numbers below are for that commit.
- **Decides:** the public API of `Gateway.Configuration`, before any code refuses anything.

## Context

This gateway forwards whatever the guest sends. Link-local destinations and the
resource bounds are the only things it refuses. No point in `Sources/Netstack`
asks "may this leave?", so an embedder cannot refuse a DNS name, a dial, a ping
or a TLS server name without forking the package.

sandbox does refuse these things today, but it does not use this package to do
it. It runs gvisor-tap-vsock `fca6da3` plus 12 patches (3,481 lines) under
`sandbox/netstack/patches/`. Each patch adds a refusal to Go code. Replacing
that gateway with this one means each refusal needs a place here. Adding those
places changes `Gateway.Configuration`, and this package's API is 0.x and says
so (CHANGELOG 0.2.0), so the shape is written down before it is built.

The patch series is the requirement. Every row of the table below is a patch,
with the hook that replaces it or the reason none is needed. A hook with no
patch behind it is not proposed.

### What the Go patches actually do on refusal

This was read from the patches, not from their commit messages, because the
refusal is what a guest observes:

| Gate (patch) | Go call site | What the guest sees |
|---|---|---|
| DNS name (0001) | `dnsHandler.addAnswers`, after `addLocalAnswers`, before the upstream lookup, for every qtype | `REFUSED` (rcode 5), no answers, upstream never asked |
| TCP dial (0001) | TCP forwarder, after NAT, before `net.Dial` | `r.Complete(true)`: RST to the SYN, no SYN-ACK |
| UDP flow (0001) | UDP forwarder handler, after NAT, once per new flow | datagram dropped, no ICMP, no endpoint created |
| ICMP echo (0006) | ICMP forwarder, after NAT, `AllowDial("icmp", ip, 0)` | request dropped, no reply of any kind |
| TLS server name (0003) | `inspectAndForward`, after the guest handshake and, since 0012, after the upstream dial | guest connection closed (`guest.Close()`), upstream connection closed with no bytes sent |

## Decision

### One protocol, four decisions, all synchronous

`Gateway.Configuration` gains one property:

```swift
/// nil: forward everything, exactly as today.
public var egressPolicy: (any EgressPolicy)? = nil
```

`EgressPolicy` is a protocol with four requirements. **None of them has a
default implementation.** An embedder who conforms has to write down a verdict
for DNS, for dials (TCP, UDP and ICMP), for DNS answers and for TLS. That is
what patch 0006 is about. Before it, sandbox reported "reaches nothing" while
`ping 1.1.1.1` got an answer, because nobody had written the ICMP gate. A
default of `.allow` would repeat that mistake for every future embedder. A
default of `.refuse` would silently break things the embedder never thought
about. Neither default is a decision, so the compiler asks for one. Adding a
fifth requirement later will break every conformer's build, and it should.

The shape proposed for review (names can change, the call sites and the
results are what this ADR fixes):

```swift
public protocol EgressPolicy: Sendable {
    /// A question the gateway would forward upstream.
    func resolve(_ question: EgressQuestion) -> EgressVerdict
    /// An upstream answer, before it is relayed to the guest.
    func resolved(_ answer: EgressAnswer) -> EgressVerdict
    /// A new TCP connection, a new UDP flow, or an ICMP echo request.
    func dial(_ flow: EgressFlow) -> EgressVerdict
    /// Ports whose first bytes are read for a ClientHello. Read once, at assembly.
    var inspectedTLSPorts: Set<UInt16> { get }
    /// The ClientHello on an inspected port, after the dial has been allowed.
    func clientHello(_ hello: EgressClientHello) -> EgressTLSVerdict
}

public enum EgressVerdict: Sendable { case allow, refuse }

public enum EgressTLSVerdict: Sendable {
    case allow
    case refuse
    /// Hand the guest's connection to the embedder, ClientHello unread.
    case divert(@Sendable (Channel) -> Void)
}
```

What each call is passed:

- **`EgressQuestion`**: the guest's source address, the question name
  (lowercased, trailing dot removed, the way `DNSServer.StaticRecord` already
  normalises), the qtype, the qclass, and the transport it came on (UDP, or
  TCP via `serve`).
- **`EgressAnswer`**: the question, the IPv4 addresses from the reply's answer
  section with their TTLs, and the CNAME chain that led to them. Only records
  reachable from the question name through that chain are included.
- **`EgressFlow`**: the transport (`.tcp`, `.udp`, `.icmpEcho`), the guest's
  source address and port, the destination **as the guest dialled it**, the
  destination **after `nat`**, and the port (`nil` for ICMP). Both
  destinations are passed because they answer different questions. The Go
  patch evaluates after NAT ("the address we are actually about to dial"), and
  that is what parity needs. A policy about `host.containers.internal` needs
  the address before NAT.
- **`EgressClientHello`**: the `EgressFlow` above, plus one of: `.serverName(String)`
  (lowercased, trailing dot removed), `.noServerName` (a valid hello with no
  SNI extension), `.notTLS` (first byte is not a handshake record), or
  `.unreadable` (malformed, over the size bound, or not complete before the
  timeout).

### Why synchronous

Every decision runs on the stack's event loop, inline, and returns a value.
No future, no callback.

- **This package has no locks** (conventions rule 1). Every call site below is
  already synchronous code on the loop, deciding in place. An async verdict
  means holding the request across a suspension, and each transport would hold
  it differently. TCP already holds a `ForwarderRequest` while it dials, so TCP
  could hold one. UDP would need to buffer the datagram, ICMP the echo, and DNS
  a pending entry. Each of those is a new place for a hostile guest to spend
  memory. The only thing that would pay for that is a policy that has to wait:
  one that asks a person, or a service. No patch in the series does. The Go
  engine is an in-memory matcher and a map.
- **The verdict has to be the same one the guest sees.** A synchronous call
  followed by the refusal, on the same tick, leaves nothing that could
  interleave between deciding and acting.

What this asks of the embedder: **a hook must not block**. It runs on the
thread that carries every frame for every guest on this gateway. Writing an
audit record to a file from inside `dial` stalls the network for the whole
`write(2)`. The embedder hands records off the loop, to its own queue, and
bounds that queue (see patch 0010 below). A policy shared by several gateways
on different loops has to be `Sendable` for real, which in practice means a
`Mutex` in the embedder's code. Rule 1 covers `Sources/Netstack`. It does not
cover the embedder's types.

An asynchronous `dial` for TCP only is left open, because `ForwarderRequest` is
already held across an asynchronous connect. It would need its own ADR and a
patch that needs it.

### Where each hook sits

#### `resolve`: before a question leaves the gateway

- **Where:** `DNSServer.handle`, immediately before
  `forward(query, payload:respond:)` (DNSServer.swift:384). So after the
  static records (line 326) and the owned zones (line 342), which is upstream's
  order too: `addAnswers` calls `addLocalAnswers` first, and the Go patch's
  check comes after it. The gateway's own names are not egress. A
  default-deny policy that refused `host.containers.internal` would cut the
  guest off from the host it was configured to reach.
- **Covers:** every qtype, not only A. A `TXT` query for a refused name is
  refused too, which is what the Go patch does, and it is what stops DNS
  tunnelling through a name the guest was never allowed. It also covers both
  transports, because `serve` (TCP) and the UDP socket both end in `handle`.
- **On refusal:** `REFUSED`, rcode 5, built by the existing
  `refuse(_:payload:respond:)` (line 481). Nothing is sent upstream and no
  `pending` slot is taken. Not NXDOMAIN, for the Go patch's reason: the name
  probably exists, and the gateway is declining to look it up. A resolver also
  caches NXDOMAIN as the name not existing.

#### `resolved`: before an answer reaches the guest

- **Where:** `DNSServer.deliverUpstream`, after the reply has been matched to
  its pending question (line 516) and before `entry.respond(outgoing)`
  (line 529).
- **Why it exists:** patch 0001's dial gate refuses an address "our own
  resolver never handed out". That needs a record of what was handed out, and
  the record has to be made from answers the guest actually received. gvproxy
  resolves through the host's resolver and gets typed results. This gateway
  relays upstream's reply whole and never parses its answer section, so this
  hook is where that parse has to be added. The answer section comes from
  upstream, which is not the guest but is not trusted either. The parser gets
  the same treatment as `DNSCodec.parseQuery`: every length checked, and a
  fuzz target before it merges (#180 and #183 are the precedent).
- **On refusal:** `REFUSED`, rcode 5, to the guest, in place of the reply.
  sandbox's patches never refuse an answer. They only record it, so for parity
  this returns `.allow` every time. The refusal exists because an answer is
  where DNS-rebinding protection would go (a public name answering with a
  private address), and deciding the result now costs nothing.
- **The ledger is not the netstack's.** Minimum TTL (5 min), the entry cap
  (8,192), deny-wins across every name sharing an address: all of that is
  sandbox's policy, pinned by `testdata/host-patterns.json` against sandbox's
  Swift matcher. This package reports what was answered. It does not decide
  what an answer permits.

#### `dial`: a new TCP connection

- **Where:** `OutboundTCPForwarder.handle`, after the `locallyServed` match
  (lines 206–239) and before `live += 1` (line 250). The `nat` lookup at
  line 256 moves above the call so that both addresses can be passed.
- **Ordering, and what it means:** the link-local refusal (line 188) and the
  connection limit (line 196) stay in front of the hook. A link-local dial is
  refused whatever the policy says. It is a security default, not a
  preference, and a policy that allowed 169.254.169.254 must not re-open it.
  Under a full connection table a SYN is refused for the limit before the
  policy sees it, so the audit will not record that attempt. Either way
  nothing leaves. The gateway's own services (DNS over TCP at
  `gatewayAddress:53`, the guest API if one is served) are answered before the
  hook and are not gated. They are not egress. See patch 0007 for what that
  means for the guest API.
- **On refusal:** `request.refuse()`, the RFC 9293 §3.10.7.1 reset that
  `TCPForwarder` already sends (TCPForwarder.swift:172): `RST|ACK`, `SEQ=0`,
  `ACK=SEG.SEQ+1`, and no SYN-ACK first. The guest's `connect()` fails with
  `ECONNREFUSED` at once, which is the Go patch's `r.Complete(true)`. No slot
  is taken, and nothing is dialled.

#### `dial`: a new UDP flow

- **Where:** `UDPForwarder.handle`, after `guard !opening.contains(key)`
  (line 148) and before `reclaimIdle()` and the flow limit (lines 149–150). It
  runs once per new four-tuple, not once per datagram: a datagram on a flow
  that is already open goes out at line 140 without a call. That matches the
  Go handler, which gVisor calls only for a datagram with no endpoint.
- **On refusal:** `return true`, meaning the datagram is consumed and dropped.
  No socket, no flow, no ICMP port-unreachable. That is the Go patch's
  behaviour, and sending no ICMP means a scan of refused ports gets nothing
  back to count. Because nothing is remembered, every datagram to a refused
  destination calls the hook again. That costs one call per frame the guest
  sends, which the guest is already paying for, and it is the same shape as
  today's link-local refusal at line 123.
- **Datagrams to the gateway fall through before the hook** (line 117), so
  DHCP and DNS keep working under a policy that refuses everything.

#### `dial`: an ICMP echo request

- **Where:** `ICMPForwarder.handle`, after the three `decline()` checks
  (gateway address, loopback and broadcast, link-local; lines 106–108) and
  before the outstanding limit (line 110). `port` is `nil`. The Go patch uses
  port 0 so that a rule with a port does not grant ping. How a policy reads
  `nil` is the policy's business.
- **On refusal:** `return true`, meaning taken and dropped. The guest's ping
  sees 100% loss, which is what patch 0006 does.
  **It must not be `decline()`.** Declining returns `false`, and
  `IPv4Protocol.handleICMP` then answers the echo itself, from the address that
  was pinged (IPv4Protocol.swift:216–233). A refused ping would get a reply,
  and that is worse than the hole 0006 closed: it tells the guest a destination
  answers when policy says it may not be reached. This is the likeliest way to
  get the implementation wrong, so it gets a test with a control: an allowed
  address is answered by the destination (`forwarded` rises), and a refused one
  gets nothing (`answered` and the local fallback both stay flat).

#### `clientHello`: the server name on a shared address

- **Where:** `OutboundTCPForwarder.splice`, for a flow whose destination port
  is in `inspectedTLSPorts`. A channel handler goes into the guest channel's
  pipeline ahead of `guestGlue` (line 345), before
  `registerAlreadyConfigured0` (line 364). It buffers the guest's first bytes,
  calls the hook once, and then either passes the buffered bytes on as one
  read and removes itself, or refuses. Ports not in the set get no handler and
  are spliced exactly as today.
- **Why here and not earlier:** the ClientHello comes after the TCP handshake,
  and this gateway only answers the SYN after the upstream dial succeeds
  (the "order is the design" comment, OutboundTCPForwarder.swift:13–20). So
  inspection happens on a connection whose upstream is already open. That is
  what patch 0012 fixed in Go, and here it is true by construction. The cost
  is the same as Go's: a connection refused on its server name has already
  made a TCP handshake with the upstream. It sends no bytes, but the handshake
  happened. That is unavoidable, because the name arrives after the only
  moment the dial could have been refused.
- **Reading the hello:** the handshake message is reassembled across TLS
  records until it is complete, up to 16 KiB. A ClientHello split across
  several records is legal, and servers reassemble it. A parser that reads one
  record and treats a partial hello as "no name to check" would let the guest
  choose not to be checked. So a hello that cannot be read is reported as
  `.unreadable`, and that is kept apart from `.noServerName`. The hook decides
  what each one means. A sandbox-shaped policy answers `.noServerName` and
  `.notTLS` with `.allow`, because the dial gate has already allowed the
  address and gvsandbox splices both, and answers `.unreadable` with `.refuse`.
- **Bounds:** 16 KiB buffered per inspected connection, so at most 16 MiB with
  `maximumTCPConnections` at its default of 1,024. The timeout for the hello
  comes from the injected clock (rule 2), defaulting to Go's
  `clientHelloTimeout` of 15 s.
- **On refusal:** the guest's connection is **reset** and the upstream
  channel is closed. The reset needs a new primitive,
  `TCPEndpoint.abort()`: RFC 9293 §3.10.5's ABORT, an `RST` at `SND.NXT`,
  then straight to CLOSED with the queues discarded. `TCPEndpoint` has
  `close()` and `shutdownWrite()` but no abort. That primitive ships first, in
  its own PR, with its own state-machine tests. This differs from Go on
  purpose: Go calls `guest.Close()`, which sends a FIN. A FIN in the middle of
  a handshake reads to a TLS client as a server that answered and hung up. A
  reset says the connection was refused, and the gateway holds no FIN-WAIT
  state for it. Both fail the handshake. The backend-neutral enforcement suite
  should assert that (the handshake fails, no byte reaches the upstream) and
  not which segment caused it.
- **On `.divert`:** the upstream channel netstack dialled is closed, and the
  guest channel, with the buffered hello still to be read, is handed to the
  embedder's closure. The embedder dials for itself, because the credential
  broker verifies the upstream against the name. Patch 0012 does the same
  ("the plain connection is not its to use"). The guest channel keeps its
  `maximumTCPConnections` slot until it closes.

#### `clientHello` as built

Built after the rest, and it differs from the shape above in four places. Each
difference is on purpose:

- **Only a name is asked about.** `EgressClientHello` is the flow and a
  `serverName`, not the four-case enum. A stream that is not TLS and a complete
  hello with no SNI are passed on without a call, because `dial` has already
  allowed the address and sandbox splices both. A hello that cannot be read is
  refused **without** a call and counted in `tlsRefusedUnreadable`. That is the
  precedent `resolved` set, where a reply whose answer section cannot be read is
  refused without a call. It is also patch 0013's rule: a hello that is
  truncated, too slow, too large or malformed has not said which name it wants,
  and the server may still read one from it. A policy that could answer
  `.unreadable` with `.allow` would reopen the hole 0013 closed.
- **Two bounds, not one.** 16 KiB for the handshake message and 32 KiB for the
  records carrying it, as in patch 0013. Each record costs a five-byte header, so
  without the second bound a guest that sends one-byte records would make the
  gateway hold six bytes for each byte of hello.
- **Not TLS is decided on the first byte.** Go reads five bytes first, so a
  protocol that sends one byte and waits would stall until the deadline. A
  stream that ends before sending anything is also passed on, FIN and all:
  there are no bytes to leak. Go refuses that stream.
- **`.divert` is not built.** `EgressTLSVerdict` has `allow` and `refuse`. The
  broker that needs a divert is out of scope, and the case goes into
  `EgressTLSVerdict` when a patch needs it.

A server name that is not printable ASCII (a NUL, a space, anything over 0x7E)
is refused as unreadable. RFC 6066 makes a `host_name` an ASCII DNS name, and a
policy that matches suffixes should not be asked to judge
`"evil\0.allowed.example"`. Go passes those bytes through to its matcher.

The guest-observed check is `ClientHelloTests`. The guest there is the
differential harness in `tls` mode: gVisor's TCP stack running Go's crypto/tls
client, whose hello is re-framed into two records the way patch 0013's test
does it. The upstream is a crypto/tls server on loopback. A refused name gets a
reset, and the upstream reads zero bytes before EOF. An allowed name, and the
same refused name under an allow-all policy, complete their handshakes.

### What the netstack adds around the hooks

- **Counters** (rule 16): `refusedByPolicy` on `OutboundTCPForwarder`,
  `UDPForwarder`, `ICMPForwarder` and `DNSServer`, plus `refusedForServerName`
  and `diverted` on the TCP forwarder, all in `Gateway.Statistics`. As built:
  `refusedForServerName` and `refusedUnreadableClientHello`, reported as
  `tlsRefusedByPolicy` and `tlsRefusedUnreadable`. There is no `diverted`,
  because nothing diverts yet.
- **Events** (rule 9): `tcpRefusedByPolicy`, `udpRefusedByPolicy`,
  `icmpRefusedByPolicy`, `dnsRefusedByPolicy`, `tlsRefusedByPolicy`, and
  `tlsRefusedUnreadable` as built, all
  through the shared `RateLimitedLogger`. The guest decides how many
  refusals there are, and this is the rule patch 0011 had to add to Go by hand.
- **Nothing else.** No matcher, no ledger, no audit file.

### The patch series, row by row

| Patch | What it does | Replaced by | Where in `Sources/Netstack` | On refusal |
|---|---|---|---|---|
| **0001** Default-deny egress policy | Gates DNS names; records the addresses it answered; gates TCP and UDP dials against that record | `resolve`, `resolved`, `dial` (`.tcp`, `.udp`). The matcher and the ledger stay with the embedder | `DNSServer.handle` before `forward` (:384); `DNSServer.deliverUpstream` before `respond` (:529); `OutboundTCPForwarder.handle` before `live += 1` (:250); `UDPForwarder.handle` before the flow limit (:149) | DNS `REFUSED` (rcode 5); TCP `RST\|ACK` to the SYN; UDP dropped, no ICMP |
| **0002** Credential broker | Terminates TLS for bound domains with a per-sandbox CA and substitutes the secret | `clientHello` returning `.divert`. The broker is out of scope | `OutboundTCPForwarder.splice`, the handler ahead of `guestGlue` (:345) | n/a: diverted, not refused |
| **0003** SNI inspection | Re-checks the name a TLS connection asks for on an address the dial gate allowed | `clientHello` | Same handler as 0002 | Guest connection reset via the new `TCPEndpoint.abort()`; upstream closed with no bytes sent |
| **0004** Credential strips a header | Deletes the guest's `x-api-key` before injecting `authorization` | No hook. Internal to the broker | n/a | n/a |
| **0005** DNS refusals in the audit log | Writes a record when a name is refused | No hook. The embedder's `resolve` returns the refusal, so it already knows. The netstack adds `DNSServer.refusedByPolicy` and `dnsRefusedByPolicy` | n/a | n/a |
| **0006** Gate ICMP | Refuses echo to a destination the policy would not dial | `dial` (`.icmpEcho`, `port: nil`) | `ICMPForwarder.handle` after the `decline()` checks (:108), before the limit (:110) | Dropped (`return true`). Never `decline()`, which would make the gateway answer for the refused address |
| **0007** No port-forward API for the guest | Removes gvproxy's guest-facing API at `gatewayIP:80` | No hook. The library serves it only when an embedder calls `ControlPlane.listenForGuests()` (ControlPlane.swift:146), and sandbox would not. A policy hook would be the wrong tool anyway: `locallyServed` destinations are answered before `dial`, because they are the gateway's own services and not egress | n/a | n/a. The `netstack-gateway` executable does call it, unconditionally (main.swift:687), for gvproxy parity. If sandbox ever ran the executable rather than the library, that would need a flag of its own |
| **0008** Brokered request goes to the verified name | Overwrites `Host` with the SNI name | No hook. Internal to the broker | n/a | n/a |
| **0009** Broker will not send a secret to an unverified upstream | A test only; the code already verified | No hook. Internal to the broker | n/a | n/a |
| **0010** Bound the audit log | Rotates the audit file at 32 MiB, one generation kept | No hook. The audit file is the embedder's. What the netstack adds is the constraint that hooks must not block, so audit writes go off-loop, and bounding that queue is the embedder's job | n/a | n/a |
| **0011** Gateway log does not grow per refusal | Moves refusal lines from Info to Debug | No hook. Conventions rule 9 already rate-limits every guest-caused line through `RateLimitedLogger`. The new events go through it | `NetstackLog.swift`, `RateLimitedLogger.record` (:133) | n/a |
| **0012** Dial upstream before answering the guest | Makes the SNI path dial before the guest's handshake, bounded, with RST on failure | No hook. Already the design: `OutboundTCPForwarder` dials before `request.complete()`, bounded by `tcpDialTimeout` (5 s), and refuses with a reset on failure (:290–307). `clientHello` runs inside `splice`, after the dial, so it keeps that order | `OutboundTCPForwarder.handle` / `splice` | Failed dial: `RST\|ACK` to the SYN, `refusedForDial` |

### What a hook costs on the fast path

The fast path is a segment on an established TCP connection or a datagram on
an open UDP flow. **No hook is called on it.** `TCPForwarder.handle` hands an
established four-tuple's segment to its endpoint (TCPForwarder.swift, the
`endpoints[id]` branch) before any new-connection logic runs, and
`UDPForwarder.handle` sends on an open flow at line 140 before the new-flow
code. With a policy installed, per-packet cost is unchanged.

The new-flow path pays:

| Event | Calls with `egressPolicy == nil` | Calls with a policy |
|---|---|---|
| TCP SYN that would dial | one `nil` check | one `dial` |
| New UDP four-tuple | one `nil` check | one `dial` |
| Datagram to a refused UDP destination | n/a | one `dial` per datagram (nothing is remembered) |
| ICMP echo past the `decline()` checks | one `nil` check | one `dial` |
| DNS question not answered locally | one `nil` check | one `resolve` |
| DNS answer from upstream | one `nil` check | one `resolved`, plus parsing the answer section |
| TCP connection on an inspected port | none | one `clientHello`, plus reassembling and parsing up to 16 KiB |

The budget for a hook is **10 µs at p99**, measured on the event loop from call
to return. The reason is scale: every one of those events already costs at
least one host round trip (a `connect`, a `sendto`, an upstream DNS query),
which is milliseconds. A hook within budget is under 1% of the event it gates.
A hook over it is taking time from every other guest on the loop. **No number
here has been measured.** No toolchain was available when this was written, and
this repository has no benchmark to measure with: `scripts/soak.sh` says of
itself that it is "not a benchmark". The `dial` PR therefore adds one. It opens
TCP connections to a loopback listener through the gateway with no policy, with
a policy that always allows, and with a sandbox-shaped policy (a matcher and a
ledger of 8,192 entries), and it reports connections per second and the hook's
own p99 against the parent commit. The `nil` path must not move.

`clientHello` adds **no round trip.** The bytes are held only until the
handshake message is complete, and a server could not have acted on an
incomplete ClientHello either. A hello in one segment is passed on in the same
tick it arrives. A hello in two segments is held for the second, which the
server would also have waited for. The only added time is the parse.

## Consequences

- `Gateway.Configuration` gains `egressPolicy`. `OutboundTCPForwarder`,
  `UDPForwarder`, `ICMPForwarder` and `DNSServer` each gain a `policy:`
  initialiser parameter defaulting to `nil`, so hand-assembled arrangements opt
  in the same way. With `nil`, behaviour is unchanged. The differential gate
  and the interop check are how that stays true, and they run on the
  implementation PRs unchanged.
- The work splits into PRs, in this order: `TCPEndpoint.abort()`; the protocol
  plus `dial` for TCP, UDP and ICMP; `resolve` and `resolved` with the answer
  parser and its fuzz target; `clientHello`. Each gets guest-observed tests with
  controls, not only frame-level ones: `nslookup` gets `REFUSED` for a refused
  name and an address for an allowed one, busybox `nc` gets connection refused
  at once for a refused dial and connects for an allowed one, `ping` gets 100%
  loss for a refused address and replies for an allowed one, and a TLS client
  fails its handshake for a refused name, including a hello split across two
  records.
- The same assertions, written backend-neutral, run against both gvsandbox and
  this gateway. Where the two differ on purpose (a reset rather than a FIN on
  a refused server name), the suite asserts the outcome and not the segment.
- Noticed while reading, and left alone: with `allowsLinkLocal` off, a ping to
  169.254.169.254 goes through `decline()` (ICMPForwarder.swift:108) and gets a
  local reply from the gateway. Nothing leaves, so it is not a leak. It is the
  same false reachability `ICMPForwarder` exists to stop, though, and it is
  tracked separately.

## Limits

What the hooks, as built, do not see:

- **`resolved` reports IPv4 only.** `EgressAnswer.addresses` holds class IN
  `A` records and nothing else. An `AAAA` answer is still passed to `resolved`,
  since every matched reply is, but its addresses are not in it: `addresses`
  is empty. This gateway carries no IPv6, so a guest cannot dial an address it
  learned that way through this gateway. A policy checking answers for DNS
  rebinding still sees nothing of a v6 answer.
- **`resolved` reports `A` records only, and only from the answer section.**
  Addresses carried in any other form are not reported: the `ipv4hint` and
  `ipv6hint` of an `HTTPS` or `SVCB` record, and `A` records in the additional
  section. For a policy that allows a dial only to addresses it was shown,
  that fails closed: a guest dialling an `ipv4hint` address is refused as
  unresolved. For a rebinding check it is a gap: a private address in an
  `ipv4hint` reaches the guest, because the policy is never shown it.
  `A` records owned by a name the question does not reach through its CNAME
  chain are left out on purpose: an upstream can put anything in a reply.
- **`clientHello` runs after a TCP handshake with the upstream.** See "Why
  here and not earlier" above. The upstream sees a connection open and close
  with no bytes, even for a refused name.
- **`clientHello` sees the outer name only** under Encrypted ClientHello. See
  below.

## Out of scope

These stay above the netstack or outside this decision:

- **The credential broker** (0002, 0004, 0008, 0009): the per-sandbox CA, TLS
  termination, header substitution, pinning `Host`, and verifying the upstream.
  They belong to the embedder, reached through `.divert`. This package does not
  hold secrets or terminate TLS.
- **The policy itself:** the pattern language, the conformance vectors in
  `testdata/host-patterns.json`, the resolution ledger, deny-wins across shared
  addresses, the minimum TTL. Those are sandbox's semantics, and sandbox
  already has a Swift matcher that has to agree with them. A reference policy
  in this package could come later, under its own ADR.
- **The audit log** and its bound (0005, 0010).
- **Asynchronous decisions:** asking a person, or a remote service.
- **Inbound traffic:** port forwards from the host into the guest are
  published by the host and are not egress.
- **The gateway's own services:** DHCP, DNS at `gatewayAddress`, and the guest
  API when served. They are not gated. Whether to serve them is the embedder's
  choice.
- **IPv6.** This package does not carry it (README: "Not yet implemented:
  IPv6"). Hooks for it come with it.
- **Encrypted ClientHello.** With ECH, the hook sees the outer SNI, which is
  the client-facing server's public name, and only that. A policy that must
  tell the inner names apart cannot do it at this layer.
- **Per-guest policy on a switched gateway.** The hook is given the guest's
  source address. Whether a source address identifies a guest on a
  `NetworkSwitch` is the switch's question and is not answered here.
- **Flags for `netstack-gateway`.** A policy is given in code, by an embedder.
  Whether the executable should load one from a file is a later decision.
