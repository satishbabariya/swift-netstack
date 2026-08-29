# swift-netstack

A userspace TCP/IP stack and VM gateway in pure Swift, built on SwiftNIO.

This is a port of [gvisor-tap-vsock](https://github.com/containers/gvisor-tap-vsock),
which gives a VM guest a network without a TUN device, a bridge, or root: the
guest's only wire is a datagram socket, and a userspace process terminates every
flow on it. Upstream uses gVisor's `tcpip` package, which is Go. This replaces it
with Swift so the gateway can be **linked into a Swift host process** —
`apple/container`, or anything else driving Virtualization.framework — rather
than spawned as a separate Go binary.

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
anywhere the host can reach. To publish one of its ports on the host:

```swift
let leased = gateway.leasedAddress(for: guestMAC)!
_ = try await gateway.forward(hostPort: 8080, toGuest: leased, port: 80).get()
```

`Gateway` is an assembly of public parts, and unusual arrangements should reach
past it: `WireBootstrap` for the wire, `Stack` for the stack, and
`DHCPServer` / `DNSServer` / `OutboundTCPForwarder` / `UDPForwarder` /
`PortForwarder` for the services. What `Gateway` holds that is not obvious is the
**order**: DHCP and DNS bind their UDP ports before the UDP forwarder installs
its protocol handler, because the forwarder falls through for anything addressed
to the gateway and something has to be bound for those datagrams to reach.

### Wires

| Wire | Use it for |
|---|---|
| `WireBootstrap.adoptingDatagramSocket` | Virtualization.framework, vfkit, upstream's `unixgram`. One datagram is one ethernet frame; the kernel keeps the boundaries. |
| `WireBootstrap.connectingDatagramSocket` | The same, dialled to a path rather than adopted. |
| `WireBootstrap.adoptingStreamSocket` | qemu's `-netdev socket`, bess, stdio. A four-byte big-endian length in front of each frame. |

## What is implemented

| | |
|---|---|
| **Core** | RFC 1071 checksums, IPv4/MAC/subnet types, `PacketBuffer` with reserved headroom, injected clock |
| **Link** | `LinkEndpoint` protocol, recording + loopback wires, Ethernet II, `NIC` with promiscuous and spoofing modes, ARP cache + responder |
| **Wire** | Datagram and length-prefixed transports over real sockets, adopted from a descriptor or dialled to a path |
| **Network** | IPv4 parse/emit, route table with spoof-aware source selection, limited broadcast, egress fragmentation, ingress reassembly with timeout and memory bounds, ICMPv4 |
| **Transport** | Four-tuple demultiplexer with protocol-handler override, UDP, ICMP port-unreachable |
| **TCP** | RFC 9293 state machine with RFC 5961 hardening and a §7 challenge-ACK rate limit, RFC 1982 serial arithmetic, out-of-order reassembly, RFC 6298 RTO with Karn and a handshake sample, RFC 5681 Reno and RFC 9438 CUBIC, RFC 6675 SACK-based loss recovery, RFC 2018 SACK reporting, RFC 6528 initial sequence numbers, RFC 7323 window scaling and timestamps with PAWS, RFC 1122 keep-alive, delayed ACK, Nagle, zero-window probing, SWS avoidance, retransmit / persist / TIME-WAIT timers |
| **Bridge** | `NetstackStreamChannel`, `NetstackServerChannel` and `NetstackDatagramChannel` conforming to NIO's `Channel`, with backpressure that reaches the guest's window |
| **Gateway** | DHCP server, DNS server with owned zones and upstream forwarding, outbound TCP forwarding, UDP flow forwarding, host-to-guest port forwarding |

**Not yet implemented:** RACK-TLP, IPv6, and the HTTP control plane upstream
exposes for managing forwards at runtime.

**Reno is the default and CUBIC is opt-in** (`TCPEndpoint.congestionControl`),
and the reason is evidence rather than preference: Reno is compared
frame-for-frame against gVisor by the differential harness and CUBIC is not.
gVisor's CUBIC keeps its window in whole segments where this one keeps a real
number of them, so the two round differently on every acknowledgement, and the
generator's connections never stay in congestion avoidance long enough for the
shape of the curve to outweigh the rounding — the comparison would report
arithmetic units rather than behaviour. What stands behind CUBIC here is unit
tests against the RFC's own formulas.

**One behaviour worth knowing before you trust it:** a ping *through* the
gateway is answered *by* the gateway, for any address at all. A guest that pings
8.8.8.8 gets a reply whether or not 8.8.8.8 is reachable, so `ping` is a test of
the guest's own stack rather than of the path. This matches upstream's default —
gVisor's stack does the same — and upstream's alternative is a separate mode
that proxies echo through an unprivileged ICMP socket, which is not implemented
here.

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

**The guest is assumed hostile.** Every guest-reachable resource is bounded, and
each bound is written down where it is enforced: half-open connections,
established connections, UDP flows, DHCP leases, outstanding DNS queries,
reassembly memory, and the length a frame may claim on a stream wire. Several of
those bounds exist because removing one and running the tests found nothing.

## Testing

```
swift test
NETSTACK_DIFFERENTIAL_SEQUENCES=10000 swift test --filter Differential
```

637 tests, plus a differential harness in `differential/` that drives gVisor's
real TCP stack from the same generated sequences and compares every frame. The
generator withholds nothing: both stacks negotiate window scaling, timestamps and
SACK, and 10,000 randomised sequences agree frame for frame apart from three
documented differences, each with a reason recorded in `differential/README.md`.

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

## License

Apache-2.0, matching upstream.
