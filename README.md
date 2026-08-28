# swift-netstack

A userspace TCP/IP stack in pure Swift, built on SwiftNIO.

This is a port of the network stack underneath
[gvisor-tap-vsock](https://github.com/containers/gvisor-tap-vsock), which gives a
VM guest a network without a TUN device, a bridge, or root: the guest's only wire
is a datagram socket, and a userspace process terminates every flow on it.
Upstream uses gVisor's `tcpip` package, which is Go. This replaces it with Swift
so the gateway can be linked into a Swift host process — `apple/container`,
`airlock`, or anything else driving Virtualization.framework — rather than
spawned as a separate Go binary.

## Status

**Plans 2 and 3 of 4 complete.** The stack core and TCP exist and are under test: a
guest can ARP for the gateway and get a ping answered, DNS-shaped traffic
round-trips through a real NIO pipeline, and a TCP connection opens, carries
data, retransmits what is lost, and closes from either side.

| | |
|---|---|
| **Core** | RFC 1071 checksums, IPv4/MAC/subnet types, `PacketBuffer` with reserved headroom, injected clock |
| **Link** | `LinkEndpoint` protocol, recording + loopback wires, Ethernet II, `NIC` with promiscuous and spoofing modes, ARP cache + responder |
| **Network** | IPv4 parse/emit, route table with spoof-aware source selection, egress fragmentation, ingress reassembly with timeout and memory bounds, ICMPv4 |
| **Transport** | Four-tuple demultiplexer with protocol-handler override, UDP, ICMP port-unreachable |
| **TCP** | RFC 9293 state machine with RFC 5961 hardening and a §7 challenge-ACK rate limit, RFC 1982 serial arithmetic, out-of-order reassembly, RFC 6298 RTO with Karn and a handshake sample, RFC 5681 Reno with multi-segment loss recovery, RFC 6528 initial sequence numbers, RFC 7323 window scaling, zero-window probing, retransmit / persist / TIME-WAIT timers, endpoint wired into the stack |
| **Bridge** | `NetstackDatagramChannel` conforming to NIO's `Channel` and `ChannelCore`, `StackBootstrap` |

Not yet implemented: timestamps/PAWS, SACK, delayed ACK, Nagle, keepalives and
CUBIC (parse-only or absent); the
TCP/UDP/ICMP forwarders and receive-side backpressure; any wire a real VM can
attach to; and the DHCP/DNS services.

## Design

Every packet, timer, and endpoint state transition runs on a single
`EventLoop`. There are no locks anywhere in `Sources/Netstack` except one, in the
test-only `ManualClock`. That is a convention rather than a guarantee: nothing
fails if someone adds a lock, and the absence is checked by reading rather than
by a test. It is worth saying plainly, because a claim of structural safety that
is really a discipline is exactly the kind of thing that stops the next reader
checking.

The stack is deliberately promiscuous and spoofing: it accepts frames addressed
to any host and transmits from addresses it does not own. That is not a
weakness, it is the point. A gateway terminating a guest's connection to an
arbitrary internet host has to answer as that host.

Endpoints are exposed as real NIO `Channel`s, so everything built on top is
ordinary NIO code.

## Requirements

Swift 6.2 toolchain, macOS 14+. CI builds the library with warnings as errors.

## Testing

```
swift test
```

513 tests, plus a differential harness in `differential/` that drives gVisor's
real stack from the same frames.

Many of these tests exist because falsification proved an earlier one could not
fail. Two habits came out of that and are worth knowing before adding a test
here: an upper bound with no floor is satisfied by doing nothing, and an
assertion whose expected value is computed from the code under test goes vacuous
exactly when that code breaks. Both shipped here, repeatedly, before anyone
thought to check by deleting the thing the test was supposed to guard.

## License

Apache-2.0, matching upstream.
