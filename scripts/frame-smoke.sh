#!/usr/bin/env bash
# One ethernet frame through the built executable.
#
# Everything else that watches the executable watches its control plane, and a
# gateway that has come up believing it is 0.0.0.0 answers its control socket
# perfectly well. That exact failure shipped: an initialization-order bug fed
# the address resolution zeroed storage, and the gateway ran, bound its wire,
# and answered ARP for nobody -- while every existing check stayed green. The
# narrowest thing that catches the whole class is what a guest does first:
# ask who owns the gateway address, and hear back.

set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

WIRE=""
CONFIG=""
GATEWAY=""
cleanup() {
    [[ -n "$GATEWAY" ]] && kill "$GATEWAY" 2>/dev/null
    rm -f "$WIRE" "$CONFIG"
}
trap cleanup EXIT INT TERM

echo "building the gateway"
swift build -c release --product netstack-gateway >/dev/null || exit 1
binary="$(swift build -c release --show-bin-path)/netstack-gateway"

# One run: start the gateway with the given arguments, ARP for `expected`, and
# require the reply to claim it.
smoke() {
    local expected="$1" guest="$2"
    shift 2
    WIRE="${TMPDIR:-/tmp}/netstack-smoke-$$.sock"
    rm -f "$WIRE"
    "$binary" --listen-vfkit "$WIRE" "$@" >/dev/null 2>&1 &
    GATEWAY=$!

    for _ in $(seq 1 120); do
        [[ -S "$WIRE" ]] && break
        sleep 0.25
    done
    [[ -S "$WIRE" ]] || { echo "FAIL: wire socket never appeared ($*)"; return 1; }

    EXPECTED="$expected" GUEST="$guest" WIRE="$WIRE" ARGS="$*" python3 - <<'PY'
import os, socket, sys

wire = os.environ["WIRE"]
expected = bytes(int(part) for part in os.environ["EXPECTED"].split("."))
guest = bytes(int(part) for part in os.environ["GUEST"].split("."))
described = os.environ.get("ARGS") or "(defaults)"
client_path = wire + ".client"
s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
s.bind(client_path)
try:
    s.connect(wire)
    src = bytes.fromhex("5a94efe4bc00")
    # who-has <the gateway address> tell <a guest on its subnet>
    frame = (
        b"\xff\xff\xff\xff\xff\xff" + src + b"\x08\x06"
        + b"\x00\x01\x08\x00\x06\x04\x00\x01"
        + src + guest
        + b"\x00\x00\x00\x00\x00\x00" + expected
    )
    s.send(frame)
    s.settimeout(5)
    try:
        reply = s.recv(2048)
    except socket.timeout:
        print("FAIL: no ARP reply within 5s for", described)
        sys.exit(1)
    # An ARP reply, from the gateway, claiming the address that was asked for.
    if reply[12:14] != b"\x08\x06" or reply[20:22] != b"\x00\x02":
        print("FAIL: the reply is not an ARP reply:", reply[:22].hex())
        sys.exit(1)
    if reply[28:32] != expected:
        print("FAIL: the reply claims", ".".join(map(str, reply[28:32])),
              "rather than", ".".join(map(str, expected)), "for", described)
        sys.exit(1)
    print("ok:", ".".join(map(str, expected)), "answered for", described)
finally:
    s.close()
    os.unlink(client_path)
PY
    local outcome=$?
    kill "$GATEWAY" 2>/dev/null
    wait "$GATEWAY" 2>/dev/null
    GATEWAY=""
    rm -f "$WIRE"
    return $outcome
}

status=0

# The defaults.
smoke 192.168.127.1 192.168.127.2 || status=1

# An address given as a flag. The gateway must answer for what it was told, not
# for what it would have defaulted to.
smoke 10.7.0.1 10.7.0.2 --gatewayIP 10.7.0.1 --subnet 10.7.0.0/24 || status=1

# The same, from a configuration file. This is the path that broke: the address
# resolution read the file's contents before the file was loaded, so every
# configured value was silently the default -- or worse, zero.
CONFIG="${TMPDIR:-/tmp}/netstack-smoke-$$.json"
cat > "$CONFIG" <<JSON
{"gatewayIP":"10.8.0.1","subnet":"10.8.0.0/24","hostIP":"10.8.0.254"}
JSON
smoke 10.8.0.1 10.8.0.2 --config "$CONFIG" || status=1

exit $status
