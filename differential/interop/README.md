# Interoperating with upstream's client

`scripts/interop.sh` starts `netstack-gateway` and drives it with
[gvisor-tap-vsock][]'s own `pkg/client`, pinned at v0.8.9.

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

`Protected` on `types.Zone` is on upstream's main branch and not in v0.8.9, the
newest release, so the driver does not read it. This port implements it because
it was ported from main; an older client ignores the field, which is what a JSON
decoder does with one it has no home for.

The wire protocols are not exercised here — this drives the HTTP control API. The
frame-level comparison against gVisor's TCP is `differential/`.

[gvisor-tap-vsock]: https://github.com/containers/gvisor-tap-vsock
