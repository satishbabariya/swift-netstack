# Interoperating with upstream's client

`scripts/interop.sh` starts `netstack-gateway` and drives it with
[gvisor-tap-vsock][]'s own `pkg/client`, pinned at
`fca6da3418e8e6bd3b0f4f1a8c8bc1a2e84e2208` -- the commit sandbox actually
enforces egress with, not v0.8.9. The two diverged: v0.8.9 is 146 commits
behind fca6da3 and 24 commits sideways of it on its own backport branch. A
parity claim against v0.8.9 said nothing about the sixteen wire-affecting
commits in that gap, eight of them still uncovered by anything in this
repository -- see issue RED-21's `wire-diff` document.

Everything else that compares this port with upstream does so by *reading*
upstream. That is how three things went wrong:

- `--listen` is the control endpoint in `gvproxy` and was the guest wire here,
  so a command line moved across would have pointed the control API at the VM's
  socket and the VM at the control socket.
- `/services/dhcp/leases` did not exist. Upstream serves leases at two paths and
  its client calls the one this did not have.
- `types.Zone` carries no json tags, so Go emits `Name`, `Records`, `IP`,
  `DefaultIP`, and its decoder matches case-insensitively. This read only
  lowercase, so `pkg/client` could list zones and not add one.

Each was found by reading upstream more carefully, eventually. This check does
not need me to.

## What it does not cover

`Protected` on `types.Zone` landed on upstream's main branch after fca6da3
(commit `901a96a5`, DNS `/add` input validation) and is in neither v0.8.9 nor
the commit now pinned here, so the driver does not read it. This port
implements it because it was ported from main; an older client ignores the
field, which is what a JSON decoder does with one it has no home for.

The wire protocols are not exercised here — this drives the HTTP control API. The
frame-level comparison against gVisor's TCP is `differential/`.

[gvisor-tap-vsock]: https://github.com/containers/gvisor-tap-vsock
