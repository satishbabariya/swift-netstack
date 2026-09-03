# swift-netstack

A userspace TCP/IP stack and VM gateway in pure Swift, built on SwiftNIO.

This is a port of [gvisor-tap-vsock](https://github.com/containers/gvisor-tap-vsock),
which gives a VM guest a network without a TUN device, a bridge, or root: the
guest's only wire is a datagram socket, and a userspace process terminates every
flow on it. Upstream uses gVisor's `tcpip` package, which is Go. This replaces it
with Swift so the gateway can be **linked into a Swift host process** —
`apple/container`, or anything else driving Virtualization.framework — rather
than spawned as a separate Go binary.

## Adding it

```swift
.package(url: "https://github.com/satishbabariya/swift-netstack.git", from: "0.1.0")
```

```swift
.product(name: "Netstack", package: "swift-netstack")
```

**0.x, and the API is not stable yet.** `Gateway.Configuration` gained eight
parameters in a single day of work and will gain more; pin an exact version if
that matters to you. What is stable is the wire behaviour — that is what the
differential harness and the interop check are for.

## Using it

One descriptor in, a working network out:

```swift
import Netstack
import NIOPosix

// The host keeps one end of the pair and hands the other to the VM.
var pair: [Int32] = [0, 0]
socketpair(AF_UNIX, SOCK_DGRAM, 0, &pair)

let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
let gateway = try await Gateway.start(
    adoptingDatagramSocket: pair[0],
    group: group,
    configuration: .init(upstreamResolvers: [try .init(ipAddress: "1.1.1.1", port: 53)])
).get()

// pair[1] goes to VZFileHandleNetworkDeviceAttachment.
```

The guest then boots, asks for an address by DHCP, is told the gateway is its
router and its resolver, and can open TCP connections and send UDP datagrams to
anywhere the host can reach. `host.containers.internal` resolves to a **host
address** inside the subnet — the last usable one, `192.168.127.254` on the
default subnet — which the gateway answers ARP
for and rewrites to `127.0.0.1` when it dials — that translation is what makes
the host's own services reachable, since they are on its loopback rather than on
any address the guest could route to.

**Guests cannot reach 169.254.0.0/16 by default.** 169.254.169.254 is the cloud
instance metadata service, which hands credentials to whatever asks from the
host, and a gateway that dials on a guest's behalf is a way for the guest to
ask. Set `allowsLinkLocal` if you need it; upstream spells the same switch
`Ec2MetadataAccess` and also defaults it off. To publish one of its ports on the host:

```swift
let leased = gateway.leasedAddress(for: guestMAC)!
_ = try await gateway.forward(hostPort: 8080, toGuest: leased, port: 80).get()
```

Or at runtime, over upstream's HTTP API, so a tool written against `gvproxy`
works unchanged:

```swift
let control = ControlPlane(gateway: gateway)
try await control.listen(unixSocketPath: "/tmp/netstack.sock").get()
```

```
POST /services/forwarder/expose   {"local":":8080","remote":"192.168.127.2:80","protocol":"tcp"}
POST /services/forwarder/unexpose {"local":":8080","protocol":"tcp"}
GET  /services/forwarder/all
GET  /stats
GET  /leases
GET  /services/dhcp/leases
GET  /cam
GET  /services/dns/all
POST /services/dns/add      {"name":"svc.test.","records":[{"name":"api","ip":"10.1.2.3"}]}
GET  /tunnel?ip=<guest>&port=<port>
POST /connect
```

The last two take the connection away from HTTP. `/tunnel` answers a bare `OK`
and then carries that connection to a guest's port — a port forward for one
connection, with no listener. `/connect` makes the connection a **port on the
switch**, which is how a guest that can reach only this socket joins the
network.

Field names are matched case-insensitively, because Go's `encoding/json` is and
upstream's types carry no json tags — so its own client sends `Name`/`Local`
where its documentation says `name`/`local`, and both have to work.

`protocol` is `tcp` (the default), `udp`, or `unix` — where `local` is a socket
path rather than a port, and who may reach the guest is decided by filesystem
permissions. A host port is only unique **within** a protocol: `8080/tcp` and
`8080/udp` are two different forwards and both can be published at once.

Every connection has a **request timeout**: a peer that sends half a request
otherwise holds it forever, because the server is waiting for the rest and the
peer is waiting for an answer and neither is wrong.

It listens on a unix socket because anything that can reach it can publish any
guest port on the host, and a unix socket puts that behind the filesystem where
an operator can see and set who may use it. `":8080"` — upstream's spelling with
no host — means loopback rather than `0.0.0.0`, which is the safe reading of a
request that did not say.

One default of upstream's is deliberately not carried: its DHCP reservation of
`192.168.127.2` for the guest's hardware address. Upstream reserves that pair in
its pool, so a guest with any other address starts at `.3`. Here the pool simply
offers the lowest free address, which gives the same result for the one guest a
single wire carries, and `--subnet` is a flag rather than a config key — a
reservation hard-coded to `192.168.127.2` would be off-subnet the moment anyone
used it. The guarantee it buys only differs under several guests at once, which
is `--listen-switch`, where nothing expects `.2` in particular.

**The guest reaches it too**, at the gateway's own address on port 80, and gets
exactly three routes there: `/services/forwarder/all`, `/expose` and
`/unexpose`. That is upstream's mux for the same endpoint. A container publishing
its own port over the network it already has is the point of it; everything else
the API can do is withheld, because `/leases` and `/cam` say who else is on the
network, `/services/dns/add` decides what every guest resolves, and `/connect`
and `/tunnel` hand out a place on the wire.

It is served by the outbound forwarder rather than by a listener bound inside the
stack, because that forwarder is the stack's TCP handler and a second one cannot
be bound without silently displacing it.

Serving it to the guest moves a capability that was the host's alone to something
this package's threat model calls hostile, so three things about it are stricter
than upstream, each measured against this port before it was changed:

- **What a guest publishes is bounded** — `maximumGuestForwards`, sixty-four by
  default. Each forward is a bound listening socket, and two hundred of them cost
  two hundred descriptors: a guest looping on `expose` takes the gateway's
  descriptors until it can accept nothing from anybody.
- **A guest publishes on loopback, over tcp or udp, and nowhere else.** `local`
  carries the interface to bind and the transport to bind it with, and upstream
  takes both from whoever asked — so a guest there publishes itself on `0.0.0.0`,
  which turns "reach my container from this machine" into "reach my container
  from the office", or names a filesystem path and gets a socket wherever the
  gateway can write. Both answered `200` here before they were refused. The
  reading of `":8080"` above is already that an unstated interface means
  loopback; this is the same reading applied to a request that did say, by a
  caller whose say-so this package does not take.
- **A guest withdraws only what guests published, and is not shown the host's
  filesystem.** Upstream serves `unexpose` to the guest with the same handler the
  host gets, so a guest there withdraws a forward the operator published — `200
  OK`, and the forward gone. The listing has the same shape of problem: podman
  publishes `/Users/<name>/.local/share/containers/podman/machine/podman.sock`,
  which tells a guest the operator's name and where their things live, for no use
  a guest has once it can neither publish nor withdraw one. The tcp and udp
  entries stay, because they are port numbers on a host the guest can already
  dial.

The withdrawal rule is *what guests published* rather than *what this guest
published*: several guests share a switch and nothing on the wire distinguishes
them, so one guest can still withdraw another's. What it stops is the host's
being reachable at all.

The host is held to none of the three. It reaches this over a unix socket, which
is behind the filesystem where an operator decides who may use it — the reason
the control API is a unix socket in the first place.

`Gateway` is an assembly of public parts, and unusual arrangements should reach
past it: `WireBootstrap` for the wire, `Stack` for the stack, and
`DHCPServer` / `DNSServer` / `OutboundTCPForwarder` / `UDPForwarder` /
`PortForwarder` for the services. What `Gateway` holds that is not obvious is the
**order**: DHCP and DNS bind their UDP ports before the UDP forwarder installs
its protocol handler, because the forwarder falls through for anything addressed
to the gateway and something has to be bound for those datagrams to reach.

### Wires

Two shapes, and two directions. **Adopting** takes a descriptor the host already
has — Virtualization.framework hands one end of a `socketpair` to the VM and
keeps the other. **Listening** binds a path and waits for the guest to dial it,
which is what `vfkit` and `qemu` do.

| Wire | Use it for |
|---|---|
| `WireBootstrap.adoptingDatagramSocket` | Virtualization.framework. One datagram is one ethernet frame; the kernel keeps the boundaries. |
| `WireBootstrap.listeningDatagramSocket` | vfkit, upstream's `unixgram`. The peer is learned from the first frame. |
| `WireBootstrap.connectingDatagramSocket` | The same, dialled rather than served. |
| `WireBootstrap.adoptingStreamSocket` | A stream descriptor already connected. A four-byte big-endian length in front of each frame. |
| `WireBootstrap.listeningStreamSocket` | qemu's `-netdev socket`. One guest at a time; a second connection is closed, and a guest that goes away releases the wire for the next. |
| `WireBootstrap.switchedStreamSocket` | The same, but every guest that connects gets a port on a `NetworkSwitch`. |
| `WireBootstrap.vpnKitStreamSocket` | hyperkit, over its handshake. Several guests, each on a port of a switch. |
| `WireBootstrap.seqPacketSocket` | bess. Bare frames, one per message, with no length prefix — the socket type carries the boundaries. Linux only. |
| `WireBootstrap.adoptingPipes` | `--listen-stdio`: the wire is a pair of descriptors, ordinarily the process's own. |

Stream wires carry a length prefix, and there are **two incompatible spellings**
of it: qemu's four-byte big-endian (the default here) and hyperkit's two-byte
little-endian (upstream's default for `/connect`, and what this uses there).
Nothing on the wire says which is in use, so a mismatch shows up as a frame
claiming an impossible length rather than as anything naming the problem. Pick
with `framing:`.

### Names

A **zone** is a name this gateway answers and everything under it, and its
record names are **relative** to it: the record `api` in the zone `svc.test`
answers `api.svc.test`. A zone with a `defaultIP` answers every name under it
that no record matches; one without answers those `NXDOMAIN`, because a name
inside a zone this gateway owns and does not have is not a question for a public
resolver — forwarding it would leak the guest's internal names and wait out a
timeout to return the same answer.

Zones from `Configuration.dnsRecords` are **protected**: the control API cannot
replace them, because the guests were told `gateway.containers.internal` is how
they reach the host and an API that could point that name elsewhere is one that
can cut every guest off from it.

Where a name falls in two zones, **the more specific one answers**. Upstream
takes the first suffix match in its list, so the answer depends on which zone was
added first; the more specific zone is the authoritative one, and making that
depend on insertion order turns a DNS question into a configuration accident.

### Several guests

`Gateway.start(switchListeningOnStreamSocketAt:)` serves a whole network rather
than one VM: every guest that connects gets a port on a `NetworkSwitch`, DHCP
gives each its own address, and guests reach each other across the fabric
without the gateway's stack seeing the traffic at all.

The forwarding rules are upstream's. A frame for another guest is forwarded and
not delivered up; a broadcast is both; **an unknown unicast destination is
dropped rather than flooded**. That last one is worth knowing because it is not
what a physical switch does — flooding would let any guest make the switch
replicate a frame to every port by naming an address nobody owns, and on this
network every station announces itself by DHCP before it can use an address.

What is *not* upstream's is the bound. Upstream's CAM is a map that gains an
entry for every source address it sees, and the source address is a field the
guest writes, so a guest emitting random ones grows it without limit. Here the
limit is **per port**, which matters more than that it exists: a global cap
would let one flooding guest fill the table and lock every other guest out of
it, where a per-port cap means a guest can only exhaust its own share.

That holds for *taking* addresses as well as inventing them. An address arriving
on a new port moves — a switch that refused would make a reconnecting guest
unreachable forever — but a move is an acquisition by the destination port and
respects that port's limit like any other. Without that check a guest could
exceed its share by claiming addresses another guest already held, one at a
time and without limit, removing the victim's entries as it went.

### As a program

For hosts that cannot link a Swift library, `netstack-gateway` is upstream's
`gvproxy` in the same shape:

```
netstack-gateway --listen-vfkit /tmp/net.sock --dns 1.1.1.1:53 \
                 --listen /tmp/net-control.sock \
                 --forward 8080:192.168.127.2:80 \
                 --pcap /tmp/net.pcap
```

`--config` takes the same configuration `gvproxy` does, **as JSON rather than
YAML**: the field names, nesting and meanings are upstream's exactly, so a YAML
file converts with any one-line tool, and a YAML parser would be a dependency
every program linking this library carries for a flag only the executable has. A
YAML file is refused *as YAML* rather than as unparseable. The file is also the
only way to reach DNS zones, static leases, NAT, virtual addresses and the TCP
dial timeout (`tcpConnectTimeout`) — no flag says those. Flags win over the
file.

**The flag names are `gvproxy`'s**, so a command line moves across unchanged —
which means `--listen` is the *control* endpoint and the guest wire is
`--listen-vfkit` (datagram) or `--listen-qemu` (length-prefixed stream). An
earlier version of this program had `--listen` as the wire, so a `gvproxy`
command line would have pointed the control API at the VM's socket and the VM at
the control socket, with nothing saying so.

`--listen-bess`, `--listen-stdio`, `--listen-vpnkit` and `--listen-switch` are
wires too, so every wire `gvproxy` has is one this has. That paragraph used to
say the opposite — that the first three were recognised and refused by name,
because bess is `SOCK_SEQPACKET`, stdio is a pipe, and vpnkit needs hyperkit's
handshake. Each of those was true and none of them was a reason.

`--listen-bess` is the exception worth knowing: Darwin has no `SOCK_SEQPACKET`
for `AF_UNIX` at all, so it fails at the `socket` call there and says so. CI's
Linux job is where it runs.

### Every flag

`--help` prints this too, and `scripts/conventions.sh` fails if the program
grows a flag this table does not name — the sort of drift nothing else notices,
because a missing row breaks nothing.

| Flag | What it does |
|---|---|
| `--config <path>` | Configuration file, in gvproxy's shape as JSON. A forwards entry prefixed `udp:` on the host side is a datagram forward, as upstream spells it |
| `--listen <endpoint>` | HTTP control API: `unix://<path>`, `tcp://<host>:<port>`, or a bare path. Repeatable |
| `--services <endpoint>` | The same API without `/connect`, for an endpoint a guest may reach. Repeatable |
| `--listen-vfkit <path>` | Datagram socket the guest dials. One datagram is one frame |
| `--listen-qemu <path>` | Stream socket, four-byte big-endian length per frame. One guest at a time |
| `--listen-vpnkit <path>` | hyperkit's wire: a handshake, then two little-endian length bytes. Several guests |
| `--listen-stdio <ignored>` | The wire is this process's own stdin and stdout. Every message goes to stderr |
| `--listen-bess <path>` | `SOCK_SEQPACKET`, bare frames, one per message. Linux only |
| `--listen-switch <path>` | qemu's framing, carrying every guest that connects on its own port |
| `--gatewayIP <address>` | The gateway's own address. Defaults to the first usable address of the subnet |
| `--hostIP <address>` | The address that means the host. Defaults to the last usable |
| `--subnet <cidr>` | The subnet leased to guests. Default `192.168.127.0/24` |
| `--mtu <bytes>` | Link MTU. Default 1500 |
| `--forward <host:guest:port>` | Publish a guest port on the host at startup. Prefix `udp:` for a datagram forward, as in the config file |
| `--pcap <path>` | Write every frame to a pcap file, capped at 64 MiB. **Replaces** an existing file, unlike `--log-file`, which appends. Buffered: stop with Ctrl-C, not SIGKILL |
| `--notification <path>` | Socket told when the network is ready and when guests come and go |
| `--pid-file <path>` | Write this process's PID there, and remove it on a clean stop |
| `--log-file <path>` | Append log messages there as well as to stderr |
| `--log-level <level>` | `trace`\|`debug`\|`info`\|`notice`\|`warning`\|`error`. Default `notice` |
| `--debug` | Shorthand for `--log-level debug` |
| `--ec2-metadata-access` | Let guests reach 169.254.0.0/16. Off by default |
| `--help`, `-h` | Print the usage |

`--log-level` picks how much it says; the default is `notice`, which is every
refusal and nothing else. It is the only place in the package that bootstraps
`LoggingSystem` — a library that installs a global log handler has decided for
every other library in the process, and only the process is entitled to.

Everything it does is available as an API, and a Swift host process should use
that instead.

## What is implemented

| | |
|---|---|
| **Core** | RFC 1071 checksums, IPv4/MAC/subnet types, `PacketBuffer` with reserved headroom, injected clock |
| **Link** | `LinkEndpoint` protocol, recording + loopback wires, Ethernet II, `NIC` with promiscuous and spoofing modes, ARP cache + responder, and a learning `NetworkSwitch` carrying several guests on one gateway |
| **Wire** | Datagram and length-prefixed transports over real sockets, adopted from a descriptor or dialled to a path |
| **Network** | IPv4 parse/emit, route table with spoof-aware source selection, limited broadcast, egress fragmentation, ingress reassembly with timeout and memory bounds, ICMPv4 |
| **Transport** | Four-tuple demultiplexer with protocol-handler override, UDP, ICMP port-unreachable |
| **TCP** | RFC 9293 state machine with RFC 5961 hardening and a §7 challenge-ACK rate limit, RFC 1982 serial arithmetic, out-of-order reassembly, RFC 6298 RTO with Karn and a handshake sample, RFC 5681 Reno and RFC 9438 CUBIC, RFC 6675 SACK-based loss recovery and RFC 8985 RACK-TLP time-based loss detection and tail loss probing, RFC 2018 SACK reporting, RFC 6528 initial sequence numbers, RFC 7323 window scaling and timestamps with PAWS, RFC 1122 keep-alive, delayed ACK, Nagle, zero-window probing, RFC 1122 §4.2.3.3 receiver-side silly-window-syndrome avoidance, half-closure in both directions, retransmit / persist / TIME-WAIT timers |
| **Bridge** | `NetstackStreamChannel`, `NetstackServerChannel` and `NetstackDatagramChannel` conforming to NIO's `Channel`, with backpressure that reaches the guest's window |
| **Gateway** | ICMP echo forwarding over unprivileged sockets, DHCP server with static leases and search domains, address translation for reaching the host, link-local blocking, host-to-guest forwarding over TCP, UDP and unix sockets, DNS server with zones, wildcards and upstream forwarding, outbound TCP forwarding, UDP flow forwarding, host-to-guest port forwarding, and upstream's HTTP control API for managing forwards at runtime |
| **Observability** | notifications to a supervisor when the network is ready and guests arrive or leave, pcap capture of every frame, bounded so a guest cannot fill the host's disk, `swift-log` logging of every refusal, rate-limited per event kind so a hostile guest cannot flood the host's disk, and `Gateway.statistics()` — monotonic counters read as one consistent snapshot, also served as JSON on `GET /stats` |

**Not yet implemented:** IPv6, and RFC 9293 §3.8.6.2.1's MUST-38 — sender-side
silly-window-syndrome avoidance. The receiver side is there; the sender side is
not, and the table above used to say "SWS avoidance" without saying which. A
peer that reopens its window one byte at a time therefore gets a
one-byte-per-round-trip crawl. That is poor and it is not a wedge, and it is
deliberately preferred to the alternative that was considered: staying in
persist while the window is open, which would stall a receiver that is genuinely
draining slowly.

It is left rather than written because nothing here could check it. The
differential pins the advertised window at its ceiling on the gVisor side — its
auto-tuning is a heuristic with no counterpart here — and the generated
sequences hold the guest's window above zero-window territory by a wide margin,
so the condition MUST-38 governs never arises in either direction, deliberately
and for reasons written down where each choice was made. Implementing it would
rest on unit tests written by the same person who wrote the code, in the one
part of this system that has an independent check precisely because errors there
are hard to see.

RACK itself (RFC 8985's time-based loss detection) is there and opt-in
(`TCPEndpoint.rack`), alongside CUBIC and for the same reason: the differential
harness runs gVisor with its own RACK disabled, so enabling it here would compare
one stack's time-based detection against another stack's absence of it. What is
absent is §6.3's reordering timer — which re-examines the scoreboard once the
window expires with no further acknowledgements — and the tail loss probe that
usually accompanies it. Without them, a segment whose window has not passed when
the last acknowledgement arrives waits for the retransmission timer.

**Reno is the default and CUBIC is opt-in** (`TCPEndpoint.congestionControl`),
and the reason is evidence rather than preference: Reno is compared
frame-for-frame against gVisor by the differential harness and CUBIC is not.
gVisor's CUBIC keeps its window in whole segments where this one keeps a real
number of them, so the two round differently on every acknowledgement, and the
generator's connections never stay in congestion avoidance long enough for the
shape of the curve to outweigh the rounding — the comparison would report
arithmetic units rather than behaviour. What stands behind CUBIC here is unit
tests against the RFC's own formulas.

**Ping goes where it says it does.** An echo request for the gateway's own
address is answered by the gateway — that is the router answering a question
about itself — and everything else is sent for real over an unprivileged ICMP
socket, `nat` applied, with the reply carried back. A guest that pings an
unreachable address gets no reply, which is the answer.

This is upstream's behaviour: it installs its ICMP forwarder unconditionally.
An earlier version of this file claimed the opposite — that answering every ping
locally *matched* upstream's default — and that was wrong. Loopback and
broadcast are never forwarded, matching upstream. If the host will not open an
unprivileged ICMP socket, the gateway answers locally as it did before, because
a ping that works badly beats a network that fails to start.

### What is not here

**SSH forwarding.** gvproxy's `--forward-sock`, `--forward-dest`,
`--forward-user`, `--forward-identity` and `--ssh-port` publish a unix socket on
the host and carry it to the guest over SSH — how podman machine reaches the
guest's podman socket. It is deliberately absent rather than overlooked.

Upstream keeps it in a package that merely *uses* the virtual network as a
dialer, which is the right shape: it sits on top of the stack rather than being
part of it. Porting it is not 425 lines of Swift the way it is 425 lines of Go,
because Go's standard library supplies the parts this would have to add — an SSH
client, a parser for OpenSSH's private key format including its own KDF for
encrypted keys, and the `direct-streamlocal@openssh.com` channel extension. That
is a crypto dependency and a protocol implementation, and neither can be checked
the way everything else here is checked without an SSH server to check against.

Everything else gvproxy has is here. Every wire — `--listen-vfkit`,
`--listen-qemu`, `--listen-vpnkit`, `--listen-stdio`, `--listen-bess`, and
`--listen-switch` for several guests on one socket — and every other flag, and
the control API route for route.

## Design

Every packet, timer, and endpoint state transition runs on a single
`EventLoop`. There are no locks anywhere in `Sources/Netstack` except one, in the
test-only `ManualClock`.

What replaces them is that everything is confined to one loop — which is a
claim about callers as much as about code. The services a gateway hands out
(`dns`, the forwarders, the link) are closed by whoever made the gateway, from
wherever that was, so `close()` hops when the caller is elsewhere and runs
inline when it is not; deferring unconditionally would reorder it against the
caller's own closing work. The synchronous ones — `stopForwarding` and the
`forwarded*` accessors answer a value, so there is nowhere to hop — assert the
loop instead. An embedder who calls those from the wrong thread gets a trap,
which is better than the data race it replaces. `Gateway.close()` had exactly
that race, quietly, and a precondition added elsewhere is what turned it into a
crash and found it.

That used to be a convention checked by reading, and this file used to say so.
Reading missed a second lock that had appeared in `WireBootstrap` — in a package
whose entire concurrency design is that there are none. `scripts/conventions.sh`
checks it now, along with three others that were equally true when written: no
direct clock reads outside `NetstackClock`, nothing in a library writing to the
process's own output, and the TCP state machine staying behind a named surface.
CI runs it. A convention nothing enforces is a convention until somebody is
busy.

The stack is deliberately promiscuous and spoofing: it accepts frames addressed
to any host and transmits from addresses it does not own. That is not a
weakness, it is the point. A gateway terminating a guest's connection to an
arbitrary internet host has to answer as that host.

**A guest that stops reading does not take the gateway with it, and cannot make
it grow.** On a stream wire there is no queue limit above the socket — NIO holds
whatever cannot be written yet — so a guest that asked questions and never read
the answers grew that queue as fast as it could ask: four hundred thousand ARP
requests took the gateway from 8 MiB to 150 MiB. Every multi-guest wire is a
stream wire, so this was the one that mattered most and the one nothing looked
at. The link drops when its queue is full now, which is what a link does; the
same flood costs 1.7 MiB. The same fix had to be made four times: the direct-write path was written for the
*adopted* datagram socket and the **listening** one — `--listen-vfkit`, the
default, and the one vfkit uses — never got it. A guest that paused took the
gateway's network down for good, and worse than down: the socket was gone, so a
replacement guest could not connect either, and nothing said anything. The
dialling wire and bess were missing it too — and the dialling wire turned out
never to have worked at all, since a unix datagram socket that only connects has
no address for the far end to answer. `scripts/conventions.sh` now checks every
datagram wire for it, per call rather than per line, since what made these
invisible is that each is a separate argument list and the missing argument
looks like nothing. A full unix
datagram queue reports `ENOBUFS` on BSD where Linux reports `EAGAIN`; NIO retries
the second and treats the first as fatal, closing the channel — so a paused or
slow VM used to leave this gateway permanently off the network, with nothing
above it noticing. Frames adopted from a descriptor are written through it with a
bounded retry and dropped if the peer still will not take them, which is what a
link does when its queue is full. Upstream has the same failure and the same fix
([gvisor-tap-vsock#367](https://github.com/containers/gvisor-tap-vsock/issues/367)).

**The guest is assumed hostile.** Every guest-reachable resource is bounded, and
each bound is written down where it is enforced: half-open connections,
established connections, UDP flows, DHCP leases, outstanding DNS queries,
reassembly memory, and the length a frame may claim on a stream wire. Several of
those bounds exist because removing one and running the tests found nothing.

**A log line is one of those resources.** Every event this stack reports is one
a guest can cause on purpose, so `RateLimitedLogger` emits the first of each kind
immediately and holds the rest, reporting how many it held. The key is a closed
enum rather than anything off the wire — a limiter keyed on a destination or a
queried name is not a bound at all, it just moves the flood out of the log file
and into the limiter's own table. Guest-chosen text still reaches the log as
metadata, sanitized, because a DNS name containing a newline is how a guest
forges a log entry an operator reads as authentic.

Counters, unlike log lines, have no window: `Gateway.statistics()` counts every
occurrence and is where a monitoring system should read from. They include
`BytesSent`/`BytesReceived` — upstream's spelling, so a tool written against
gvisor-tap-vsock finds them — and the IPv4 layer's own outcomes, which **add
up**: every packet that arrived is counted under exactly one of delivered,
malformed, not-for-this-stack, expired, awaiting-fragments, or
unknown-protocol. Each of those is a place a packet is dropped and nothing is
said, which is the state an operator cannot debug.

`notificationSocketPath` tells a supervisor — the thing that started the VM —
when the gateway is ready and when a guest arrives or leaves, one JSON object
per connection in upstream's shape. The queue is bounded and **drops** when
full rather than blocking: a supervisor that stops reading its socket must not
be able to slow down, and eventually stop, the network.

`captureFile` writes every frame to a pcap Wireshark can open, and is bounded
for the same reason — a capture is the one guest-reachable resource that spends
the **host's disk**. Reaching the limit stops the capture rather than rotating
it: a rotating capture of a flood keeps the flood and discards the beginning,
which is the part that explains it.

## Testing

```
swift test
./scripts/interop.sh
NETSTACK_DIFFERENTIAL_SEQUENCES=10000 swift test --filter Differential
NETSTACK_FUZZ_ITERATIONS=500000 swift test --filter Fuzz
NETSTACK_THROUGHPUT=1 swift test -c release --filter Throughput
```

The third is a **benchmark, not a gate**: it pushes 32 MiB through the whole
gateway to a real loopback listener and prints a rate. It measured **around 560 Mbit/s
in a release build** (96 in debug) on an Apple-silicon laptop, over four runs
varying by less than one percent.

That number was 618 here for a while and did not reproduce. The write path had
grown a branch per frame since, so the branch was the obvious suspect and was
ruled out by removing it — 559, 558, 560, against 557 to 562 with it. Whatever
moved is not in this package, which is the useful thing a re-measurement can
tell you and the reason a figure like this is written down with the day and the
machine attached rather than as a property of the code. Profiling that run
says the socket calls dominate it: `write`, `sendto`, `recvfrom` and `read`
together take around forty times the samples that `TCPHeader.serialize` and
`TCPHeader.parse` do, so the benchmark measures its own harness at least as much
as the stack. It asserts only that every byte arrived — a throughput number from
a run that lost data is a number about something else.

`scripts/frame-smoke.sh` drives the **built executable** with real ethernet
frames over its wire socket, because everything else that watches the program
watches its control plane — and a gateway that has come up believing it is
`0.0.0.0` answers its control socket perfectly well. That exact failure shipped
once. It asks, across four configurations, who owns the gateway address, what
address may I have, what do the two `.containers.internal` names resolve to, and
then exercises the three paths a guest actually uses. It opens a **TCP
connection to the host address** and gets its bytes echoed back by a real
listener on the loopback — the forwarder, the NAT rewrite and the splice in one
question. It **exposes a host port into the guest** and requires bytes sent the
instant the host connects to come back — which is how the silent data loss in
`write0` was found, after 768 library tests had passed over it. It **pings the host** and requires two things: the echo back, and the gateway's
own `icmp_forwarded` count to have moved. Only the second distinguishes a real
ping from this process answering for an address it holds — the gateway falls
back to a local answer when it cannot open an unprivileged ICMP socket, and that
fallback is identical on the wire. It sends **a UDP datagram to the host** and requires the reply to come back to
the port it was sent from — nothing in a datagram says which conversation it
belongs to, so that is the part with somewhere to go wrong. It asks for **a name
the gateway does not own**, which is every name a guest
actually asks for, and requires the answer a fake upstream on the loopback gave
— the forwarding path is the resolver's whole job, and a check that needs the
real internet is a check that fails for reasons of its own. And it drives
the **`--listen-qemu` wire**, where a four-byte big-endian length says where
each frame ends, because a whole entry point nobody drives is a whole entry
point that can be wrong — then disconnects and comes back, the way a rebooting
VM does. It opens **`--listen-vpnkit`**, the one wire whose connection does not begin
with a frame — hyperkit's handshake is 49 bytes echoed, 41 read, 258 written,
and the sizes are exact — then speaks ordinary frames using the address the
handshake handed out. It runs a whole gateway over **`--listen-stdio`**, where the wire is the
process's own pipes — and requires stdout to carry nothing but frames while the
program's messages appear on stderr, because on that wire a printed line lands
in the middle of a frame. That second half is asserted on stderr rather than on
stdout's cleanliness: `print` to a pipe is block-buffered, so a gateway printing
into the wire writes nothing for the first four kilobytes, and a check watching
only stdout passed with the redirection removed. It joins a guest through
**`POST /connect`**, which hands the connection to the
switch and stops being HTTP — with no status line, no body, nothing, because
that silence is upstream's contract and a gateway that answered "200 OK" would
put three bytes at the front of every client's first frame. And it opens
**`--listen-switch`** with two guests, requiring each to be
answered on its own port and one to reach the other directly — the shape
gvisor-tap-vsock actually is, a network rather than a point-to-point link, which
until now the library could do and the program could not.

And it reads back a **`--pcap` capture**, with a parser that knows only what
libpcap's format says, requiring both directions of the exchange to be in it.
Nothing in the gateway reads that file, which makes it the easiest thing here to
get subtly wrong and never notice — and it was: the writer buffers, the program
had no shutdown path at all, and Ctrl-C on a capture left the operator an empty
file.

Each of those fails when the thing it names is broken: removing the NAT entry
turns the SYN into a reset, breaking the return direction of the splice leaves
the handshake intact and loses the echo, switching the stream framing to
hyperkit's two little-endian bytes leaves the wire silent, a forwarder that cannot open its
socket still answers the ping and leaves `icmp_forwarded` at zero, a resolver
that declines to forward answers REFUSED where an address belonged, and a capture
that never flushes is zero bytes where a header belonged.

**A path that is not a socket is left where it is.** Every listener clears its
path before binding, because a socket left by a process that is gone makes the
bind fail with `EADDRINUSE` forever — and it used to clear whatever was there.
`--listen-vfkit /etc/hosts` deleted `/etc/hosts` and bound a socket in its
place, with no sign but a gateway that started normally. A stale socket is still
removed; anything else survives and the bind reports the path.

`scripts/bess-smoke.sh` is the one check that cannot run where this is written.
Darwin has no `SOCK_SEQPACKET` for `AF_UNIX`, so `--listen-bess` was implemented
against a manual page and CI's Linux job is the only place it is ever opened. It
says "skipped" and passes on a Mac rather than passing silently — a check that
quietly succeeds where it cannot run reports "fine" about a wire nobody has
tried.

`scripts/vm-acceptance.sh` is the other one, for the opposite reason: it boots a
real Linux guest through
[`sandbox`](https://github.com/satishbabariya/sandbox) and checks what that
guest actually sees. GitHub's macOS runners are themselves virtual machines, so
Virtualization.framework cannot nest and CI can never run it. It is a local
gate, and it earns the inconvenience -- every other check here drives the
gateway with frames this repository wrote, which cannot tell you what a real TCP
stack does when it meets this one. Three defects came out of that gap and none
were reachable from a test that composes its own segments: an answer discarded
when the guest closed its send side (`busybox nc` with no stdin does it within a
millisecond of the handshake), a banner dropped when the host spoke before the
guest's third leg landed, and NXDOMAIN returned for a name that exists without
the record type asked for -- which a resolver caches as "no such name".

The script is falsified the same way the guards are: reverting the half-close
fix makes its TCP checks fail and leaves the others passing, so it fails at the
thing that broke rather than at everything. Within an afternoon of existing it
found two more, both the same shape and neither reachable from a composed
frame: a port published into the guest never carried a connection, because an
active open's SYN was dropped while ARP was unresolved and nothing retransmitted
it; and the first datagram to a published UDP port was lost every time, because
nothing held it either.

One thing it does **not** cover, despite booting a guest: DHCP. `sandbox`
addresses its guest itself, so no real guest here has ever asked this gateway
for a lease -- `/leases` is empty during these runs and that is correct. The
DHCP server's tests are the frame-level ones in `frame-smoke.sh`.

The Swift examples on this page are **compiled**. They sit in a function nothing
calls in `Tests/NetstackTests/READMEExample.swift`, so the test build type-checks
them, and `scripts/conventions.sh` regenerates that copy from the code blocks
above and refuses if the two disagree — so the page cannot drift from what
compiles, in either direction. Renaming `Gateway.start`'s first label breaks the
build rather than leaving the page quietly wrong.

The differential's base seed stays **fixed**, and that is a different judgement
from the fuzzer's. A crash is a bug at any seed; a frame-for-frame divergence
from gVisor might instead be behaviour neither RFC pins down — this project has
already found one such difference and decided not to follow it. A gate that went
red at a random seed on an unspecified difference would block unrelated work, and
the fix would be to pin the seed again.

The seed is overridable so that "clean at this seed" can be checked against being
an accident of this seed, which is a check nobody had run. **Thirty thousand
fresh sequences across three other base seeds — 1, 424242 and 2⁶⁴−1 — diverge
nowhere.** Repeat it with `NETSTACK_DIFFERENTIAL_SEED`.

The frame fuzzer gets **a different seed on every CI run**, from the run id, and
fifty thousand mutants rather than four. It defaults to a fixed seed so a local
run is reproducible — which meant CI explored the same four thousand frames on
every build since the day it was written: green after the first one by
construction, and unable to find anything new however long it ran. A failure
names its own seed and says to replay with `NETSTACK_FUZZ_SEED`, so a red build
is reproducible on a laptop.

Five million mutated frames across five hand-picked seeds found nothing, which
is worth saying only because the seeds differed.

`scripts/soak.sh` runs one gateway for twenty seconds under mixed traffic — ARP,
DHCP, DNS, TCP dials, UDP flows — and then asks what it is *holding* rather than
what it answers. Every other executable-level check asks one question and stops,
which is right for "does this work" and blind to a descriptor leaked per
connection or memory that climbs.

It measures between the halfway mark and the end, not against the start. The
gateway's pools are bounded, so a run that opens flows climbs to that ceiling and
stops — the first version called 523 descriptors a leak when it was the limit
doing its job. And it bounds absolute growth rather than a multiple: allowing
"no more than double" let a removed flow bound through at 7,081 → 13,908
descriptors, which is a rule loose enough to admit the failure it exists for.

Its second half churns guests instead: half a million connect, speak and leave
over twenty seconds on the switch wire, which is where a port is added per guest
and has to be given back. Descriptors and memory stay flat, and the address table
is empty at the end.

That half also carries a floor — at least half the guests must have been
*answered* — and the floor is what catches the failure it exists for. With port
removal deleted the switch fills to its guest limit and refuses everyone after:
descriptors stay flat, memory stays flat, and it settles beautifully while
serving nobody. An earlier version had no floor, swallowed every connection
error, and reported five hundred thousand guests a second having exercised
nothing at all.

`./scripts/check.sh` runs every gate CI runs, in one command; `--quick` skips
the two slow ones. It exists because the gates were seven scripts across five CI
jobs and running "the ones I remembered" is not running them — CI builds with
`-warnings-as-errors` and nothing local did, so code that compiled clean here
failed there after the push. `scripts/conventions.sh` checks that every script
`ci.yml` invokes is invoked by `check.sh` too, so a gate cannot be added to CI
and quietly stay unrunnable locally.

822 tests, plus a differential harness in `differential/` that drives gVisor's
real TCP stack from the same generated sequences and compares every frame. **CI
runs the full ten thousand**, not the three hundred `swift test` does by
default — the claim below was checked by hand until it wasn't. The
generator withholds nothing: both stacks negotiate window scaling, timestamps and
SACK, and 10,000 randomised sequences agree frame for frame apart from three
documented differences, each with a reason recorded in `differential/README.md`.

It exposes and unexposes over **UDP** as well as TCP, which nothing exercised at
all until that was written — a forward is two halves and only the TCP half of
each had ever been driven.

`scripts/interop.sh` starts a gateway and drives it with **gvisor-tap-vsock's own
client library**, pinned at v0.8.9. Every other comparison with upstream here
rests on having read upstream correctly — and reading is what put `--listen` on
the wrong socket, missed `/services/dhcp/leases`, and did not notice that Go's
JSON decoder matches field names case-insensitively where this one did not, so
upstream's client could list zones from this gateway but not add one. This is the
only check that does not depend on my reading being right.

The fuzzer mutates real frames rather than generating random bytes — uniformly
random input is rejected by the first length check and never reaches anything.
It has **found no bugs**, and what makes that worth saying is that the oracles
are checked: a canary that traps on a 17-byte frame is caught, and removing the
reassembler's table bound is caught. It also asserts how deep the mutants get,
because the first version reached the TCP parser **zero** times — the corpus
segment carried a placeholder checksum — and looked like it was working.

The Swift samples above are compiled as part of the test target
(`READMESamplesTests.swift`), and the concrete values this file states — the
gateway and host addresses, the NAT entry, link-local being off, the two
`containers.internal` names — are asserted there. Both were stale claims waiting
to happen: `Gateway.Configuration` gained eight parameters in a day, each one in
the middle of an initialiser these samples call.

`scripts/falsify.sh --all` deletes each of the thirty-seven guards in
`scripts/guards.tsv` in turn and requires that the named test notices — the
bounds on half-open connections, established connections, UDP flows in both
directions, reassembly entries and fragments, outstanding DNS queries, log
lines, capture bytes, CAM entries per port, and the control plane's request
timeout. `CAUGHT` is the guard being guarded;
`SURVIVED` means it is only described. It keeps the three outcomes apart —
including `NOT-BUILT`, a mutation that does not compile and therefore says
nothing — because a falsification that reports the wrong one is worse than not
running it.

Many of these tests exist because falsification proved an earlier one could not
fail. Three habits came out of that and are worth knowing before adding a test
here:

- an upper bound with no floor is satisfied by doing nothing;
- an assertion whose expected value is computed from the code under test goes
  vacuous exactly when that code breaks;
- arranging for a guard to be *reached* is not the same as arranging for its
  removal to *show* — a test can exercise the exact line and still pass with it
  deleted, if the two paths produce the same number.

All three shipped here, repeatedly, before anyone thought to check by deleting
the thing the test was supposed to guard.

## Requirements

Swift 6.2 toolchain, macOS 14+. CI builds the library with warnings as errors and
runs the differential against gVisor.

One thing is Linux-only rather than macOS-only: `--listen-bess` needs
`SOCK_SEQPACKET` on `AF_UNIX`, which Darwin does not have. It is implemented,
and CI's Linux job is the only place it can be exercised — on a Mac the flag
parses and the bind fails with the reason.

## License

Apache-2.0, matching upstream.
