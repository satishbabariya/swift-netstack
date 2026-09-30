# Changelog

Notable changes. Dates are the release date; the full history is in the commit
log, where each change says what was measured as well as what moved.

## Unreleased

### Added

- **`Gateway.Configuration.egressPolicy`**, the `dial` half of ADR 0001. An
  `EgressPolicy` is asked once per new TCP connection, UDP flow and ICMP echo,
  with the destination as the guest dialled it and after `nat`. A refused SYN
  gets `RST|ACK` and no SYN-ACK; a refused datagram or ping is dropped with no
  reply of any kind. Link-local refusals and the gateway's own services come
  first and are not the policy's to decide. `nil`, the default, changes
  nothing. Counted as `tcp_refused_by_policy`, `udp_refused_by_policy` and
  `icmp_refused_by_policy`.
- **`EgressPolicy.resolve` and `resolved`**, the DNS half of ADR 0001. A
  question of any type for a name the gateway does not own is put to
  `resolve` before it goes upstream; a refusal is `REFUSED` and nothing is
  sent. An upstream reply is put to `resolved`, with its A records and CNAME
  chain reachable from the question, before the guest sees it; a refusal
  replaces it with `REFUSED`, and so does a reply whose answer section cannot
  be read. Both are new requirements with no default, so an existing conformer
  stops compiling until it writes a verdict. Counted as
  `dns_refused_by_policy`. The TLS decision is not in this release.

### Fixed

- **A ping to link-local was answered by the gateway.** With `allowsLinkLocal`
  off, `ICMPForwarder` declined 169.254.0.0/16, and a declined echo is answered
  locally — so `ping 169.254.169.254` got a reply while TCP and UDP to the same
  address were refused. It is now taken and dropped, and counted as
  `icmp_refused_link_local`. This differs from gvproxy v0.8.9, which answers
  every ping locally; the README says why.

## 0.2.0 — 2026-09-07

Feature parity with `gvproxy` v0.8.9 is complete and enforced by CI rather than
asserted in prose. 150 commits since 0.1.0.

**The API is still 0.x and still moving.** `Gateway.Configuration` gained
parameters over this cycle and will gain more; pin an exact version if that
matters. What is stable is the wire behaviour, which is what the differential
harness and the interop check are for.

### Added

- **DNS over TCP**, with RFC 1035 §4.2.2 length-prefixed framing, RFC 7766
  pipelining, and a server-side idle timeout. Upstream serves it and a resolver
  needs it.
- **Truncation.** A reply too large for a datagram comes back with the TC bit
  set, honouring an EDNS0 advertised size when the query carries one.
- **The guest-facing forwarding API**, served at the gateway's own address on
  port 80, as `gvproxy` does — so a container can publish its own port over the
  network it already has, with no socket on the host.
- **`docker.internal`**, the host's DNS search list, and podman's vpnkit UUID
  handling.
- `--services`, the endpoint that serves the same API without `/connect`, so it
  can be handed to something less trusted.
- Six statistics counters that were kept internally and could not be read, plus
  a conventions rule so there is no seventh.
- A real-VM acceptance gate: 28 checks across seven boots against a live guest.
- Mutation guards (`scripts/guards.tsv`, 80 rows), re-proved on every pull
  request by mutating the exact source line each names.

### Fixed

- **A guest could collapse an idle connection's congestion window** with three
  54-byte pure ACKs. RFC 5681 §3.2 condition (a) — "the receiver of the ACK has
  outstanding data" — was implemented but untested, and with nothing in flight
  SND.UNA equals SND.NXT, so the acknowledgements were acceptable, advanced
  nothing, and reached `lossDetected`.
- **A reopened receive window was announced as zero.** `read()` correctly
  decided that a window which had closed must be announced at once rather than
  ride the next acknowledgement, and then sent an acknowledgement carrying the
  closed window — so every connection whose reader fell behind paid a full
  persist interval.
- TCP half-close: a FIN is forwarded as a FIN, and a close no longer discards
  queued writes.
- A banner sent in SYN-RECEIVED was dropped; a SYN was never retransmitted; the
  first UDP datagram to an unresolved next hop was lost.
- A SACK option whose length is not a whole number of blocks is refused rather
  than read as far as it goes — the remainder used to stay in the options area
  and be parsed as the next option.
- The guest's port publishing lands on loopback and nowhere else; a guest can
  withdraw only what guests published; the host's filesystem stays out of the
  guest's listing.

### Changed

- The command line takes a `gvproxy` command line the way its callers write it.
- Link-local (`169.254.0.0/16`) is refused by default in both forwarders, with
  `--ec2-metadata-access` to permit it, matching upstream's default.
- CI jobs have time ceilings, so a hung suite ends red rather than holding a
  runner for six hours in silence.

### Documentation

- `CONTRIBUTING.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`.
- Several source comments now record what was falsified and what *survived*
  falsification, so a future editor knows which checks the tests would not stop
  them removing, and why the redundant ones are there.

## 0.1.0 — 2026-08-30

First tagged version. The stack, the gateway, the wires, and the control API.
