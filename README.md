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

**Plan 1 of 3 complete.** The stack core exists and is under test: a guest can
ARP for the gateway and get a ping answered, and DNS-shaped traffic round-trips
through a real NIO pipeline.

| | |
|---|---|
| **Core** | RFC 1071 checksums, IPv4/MAC/subnet types, `PacketBuffer` with reserved headroom, injected clock |
| **Link** | `LinkEndpoint` protocol, recording + loopback wires, Ethernet II, `NIC` with promiscuous and spoofing modes, ARP cache + responder |
| **Network** | IPv4 parse/emit, route table with spoof-aware source selection, egress fragmentation, ingress reassembly with timeout and memory bounds, ICMPv4 |
| **Transport** | Four-tuple demultiplexer with protocol-handler override, UDP, ICMP port-unreachable |
| **Bridge** | `NetstackDatagramChannel` conforming to NIO's `Channel` and `ChannelCore`, `StackBootstrap` |

Not yet implemented: TCP, the TCP/UDP/ICMP forwarders, any wire a real VM can
attach to, and the DHCP/DNS services. Those are Plans 2 and 3.

## Design

Every packet, timer, and endpoint state transition runs on a single
`EventLoop`. There are no locks anywhere in `Sources/Netstack` — the absence is
structural, not a discipline anyone has to maintain.

The stack is deliberately promiscuous and spoofing: it accepts frames addressed
to any host and transmits from addresses it does not own. That is not a
weakness, it is the point. A gateway terminating a guest's connection to an
arbitrary internet host has to answer as that host.

Endpoints are exposed as real NIO `Channel`s, so everything built on top is
ordinary NIO code.

## Requirements

Swift 6.2 toolchain, macOS 14+.

## Testing

```
swift test
```

169 tests. Many exist because a review proved an earlier one could not fail.

## License

Apache-2.0, matching upstream.
