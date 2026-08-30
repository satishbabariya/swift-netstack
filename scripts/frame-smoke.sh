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

WIRE="${TMPDIR:-/tmp}/netstack-smoke-$$.sock"
GATEWAY=""
cleanup() {
    [[ -n "$GATEWAY" ]] && kill "$GATEWAY" 2>/dev/null
    rm -f "$WIRE"
}
trap cleanup EXIT INT TERM

echo "building the gateway"
swift build -c release --product netstack-gateway >/dev/null || exit 1
binary="$(swift build -c release --show-bin-path)/netstack-gateway"

"$binary" --listen-vfkit "$WIRE" >/dev/null 2>&1 &
GATEWAY=$!

for _ in $(seq 1 120); do
    [[ -S "$WIRE" ]] && break
    sleep 0.25
done
[[ -S "$WIRE" ]] || { echo "FAIL: wire socket never appeared"; exit 1; }

WIRE="$WIRE" python3 - <<'PY'
import os, socket, sys

wire = os.environ["WIRE"]
client_path = wire + ".client"
s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
s.bind(client_path)
try:
    s.connect(wire)
    src = bytes.fromhex("5a94efe4bc00")
    # who-has 192.168.127.1 (the default gateway address) tell 192.168.127.2
    frame = (
        b"\xff\xff\xff\xff\xff\xff" + src + b"\x08\x06"
        + b"\x00\x01\x08\x00\x06\x04\x00\x01"
        + src + bytes([192, 168, 127, 2])
        + b"\x00\x00\x00\x00\x00\x00" + bytes([192, 168, 127, 1])
    )
    s.send(frame)
    s.settimeout(5)
    try:
        reply = s.recv(2048)
    except socket.timeout:
        print("FAIL: no ARP reply for the gateway address within 5s")
        sys.exit(1)
    # An ARP reply, from the gateway, claiming the address that was asked for.
    if reply[12:14] != b"\x08\x06" or reply[20:22] != b"\x00\x02":
        print("FAIL: the reply is not an ARP reply:", reply[:22].hex())
        sys.exit(1)
    if reply[28:32] != bytes([192, 168, 127, 1]):
        print("FAIL: the reply claims", ".".join(map(str, reply[28:32])),
              "rather than the gateway address")
        sys.exit(1)
    print("ok: the gateway answered ARP for its own address")
finally:
    s.close()
    os.unlink(client_path)
PY
