#!/usr/bin/env bash
# Drive this gateway with gvisor-tap-vsock's own client library.
#
# Everything else here compares this port against upstream by READING upstream.
# Reading is what got `--listen` backwards (it is the control endpoint in
# gvproxy and was the guest wire here), missed `/services/dhcp/leases`
# entirely, and did not notice that Go's JSON decoder matches field names
# case-insensitively while this one did not -- so upstream's client could list
# zones from this gateway and not add one.
#
# This runs upstream's actual code against a running gateway. It is the
# narrowest useful definition of being a port and the only check here that does
# not depend on my reading being right.

set -uo pipefail
cd "$(dirname "$0")/.."

WIRE="${TMPDIR:-/tmp}/netstack-interop-wire-$$.sock"
CONTROL="${TMPDIR:-/tmp}/netstack-interop-control-$$.sock"
GATEWAY=""

cleanup() {
    [[ -n "$GATEWAY" ]] && kill "$GATEWAY" 2>/dev/null
    rm -f "$WIRE" "$CONTROL"
}
trap cleanup EXIT INT TERM

echo "building the gateway"
swift build -c release --product netstack-gateway >/dev/null || exit 1
binary="$(swift build -c release --show-bin-path)/netstack-gateway"

echo "building upstream's client"
(cd differential/interop && go build -o interop .) || exit 1

"$binary" --listen-vfkit "$WIRE" --listen "$CONTROL" >/dev/null 2>&1 &
GATEWAY=$!

# Wait for the socket rather than sleeping: on a loaded machine a fixed wait is
# either flaky or slow, and this suite has been bitten by both.
for _ in $(seq 1 120); do
    [[ -S "$CONTROL" ]] && break
    sleep 0.25
done
if [[ ! -S "$CONTROL" ]]; then
    echo "the gateway never bound its control socket" >&2
    exit 1
fi

./differential/interop/interop "$CONTROL"
