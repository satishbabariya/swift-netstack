# Security policy

## What this software is

`swift-netstack` terminates a network in userspace on behalf of a virtual
machine guest. It sits between something untrusted and the host it runs on. Its
threat model is stated plainly in the README and is worth repeating here:

**The guest is assumed hostile.** It writes every byte of every frame the stack
parses. It chooses the sequence numbers, the option lengths, the DNS names, the
addresses, the timing, and how much of all of it to send. Every resource it can
reach is bounded on purpose, and those bounds are what a report about this
project would most usefully be about.

## Reporting a vulnerability

**Please do not open a public issue.**

Report privately through GitHub's
[security advisories](https://github.com/satishbabariya/swift-netstack/security/advisories/new),
which lets us discuss a fix before it is public.

Useful things to include, in rough order of how much they help:

- A frame, a sequence of frames, or an API request that reproduces it. A
  reproduction beats a description.
- What the guest gets that it should not: host reachability, host memory, host
  CPU, another guest's traffic, or the ability to keep the gateway from serving.
- Which version or commit.

You should get an acknowledgement within a few days. This is a small project
without a staffed security team; what it can promise is that a real report will
be taken seriously and credited, not that it will be answered within an hour.

## In scope

- Anything a guest can do with frames on its wire: reaching a host service it
  should not, escaping the subnet's routing, reading another guest's traffic on
  a shared switch, or making the gateway consume memory or CPU without bound.
- Anything reachable through the control API that exceeds what that endpoint is
  meant to allow — in particular the `--services` endpoint, which exists to be
  handed to something less trusted and must not attach guests to the network.
- Link-local reachability. `169.254.0.0/16` is refused by default because
  `169.254.169.254` is the cloud instance metadata service; a guest reaching it
  reads the *host's* credentials. Enabling that is what `--ec2-metadata-access`
  is for, and a way around the default is a vulnerability.
- Anything that lets a guest crash the host process. A trap on guest-supplied
  input is a denial of service against everything sharing that process.

## Out of scope

- Anything requiring control of the host process or its command line. A
  configuration that turns a protection off is not a bypass of it.
- Resource use that is bounded and documented. The stack holds buffers per
  connection and per queue on purpose; a guest driving those to their limits is
  the design working. A guest driving them *past* their limits is not.
- Denial of service against the guest's own connectivity. A guest can always
  stop its own network from working.
- The absence of IPv6 or SSH forwarding. Both are documented as not implemented.

## What is already done about it

Not a promise that there are no bugs — a description of what would have to fail
for one to reach you:

- Every guest-reachable structure is bounded, and the bounds have tests that
  drive them to the limit rather than reasoning about them.
- 80 mutation guards, re-proved on every pull request: CI mutates the exact
  source line each names and requires the named test to fail.
- A differential harness comparing this TCP against gVisor's on generated
  sequences, and an interop check driving this gateway with upstream's own
  client.
- Fuzzers over the frame parsers and the control plane, with oracles stronger
  than "it did not crash": mutated frames must still be answered correctly
  afterwards, and a fuzzed connection's delivered bytes must match the sequence
  numbers they arrived under.
- A real-VM acceptance gate over seven boots.

If you find something these missed, that is exactly the report worth sending.
