#!/usr/bin/env bash
# One bare frame through --listen-bess, where the platform has it.
#
# Separate from `frame-smoke.sh` because it cannot run on the machine most of
# this is developed on: Darwin has no `SOCK_SEQPACKET` for `AF_UNIX` at all, so
# the socket call fails before anything else can be wrong. CI's Linux job runs
# this; on macOS it says why it did not.
#
# Skipping is reported, not silent. A check that quietly passes where it cannot
# run is a check that reports "fine" about a wire nobody has ever opened -- and
# this wire was implemented against a manual page, so it is exactly the one that
# needs to be run rather than reasoned about.

set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

export SMOKE_SUPPORT="$PWD/scripts/smoke"

# A missing interpreter is not a platform limitation, and the difference is the
# whole point of this file. The first version conflated them: CI's Linux
# container has no python3, the probe below failed to run at all, and the script
# reported the same "skipped" it reports on a Mac -- passing, in the one place
# the wire can actually be opened. It said nothing, and the wire it exists to
# check went untried for exactly as long as nobody read the log.
if ! command -v python3 >/dev/null 2>&1; then
    echo "FAIL: python3 is not installed, so this check cannot run at all."
    echo "      That is not the same as a platform without SOCK_SEQPACKET, and"
    echo "      passing quietly here would leave --listen-bess untested where it"
    echo "      is the only place it can be tested."
    exit 1
fi

if ! python3 -c "
import socket, sys
try:
    socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET).close()
except OSError as error:
    print('skipped: this platform has no SOCK_SEQPACKET on AF_UNIX --', error.strerror)
    sys.exit(1)
"; then
    exit 0
fi

echo "building the gateway"
swift build -c release --product netstack-gateway >/dev/null || exit 1
binary="$(swift build -c release --show-bin-path)/netstack-gateway"

WIRE="${TMPDIR:-/tmp}/netstack-bess-$$.sock"
GATEWAY=""
cleanup() {
    [[ -n "$GATEWAY" ]] && kill "$GATEWAY" 2>/dev/null
    rm -f "$WIRE"
}
trap cleanup EXIT INT TERM

rm -f "$WIRE"
"$binary" --listen-bess "$WIRE" >/dev/null 2>&1 &
GATEWAY=$!
for _ in $(seq 1 120); do
    [[ -S "$WIRE" ]] && break
    sleep 0.25
done
[[ -S "$WIRE" ]] || { echo "FAIL: the bess wire never appeared"; exit 1; }

WIRE="$WIRE" python3 - <<'PY'
import os, socket, sys

sys.path.insert(0, os.environ["SMOKE_SUPPORT"])
from wire import address, printable

gateway = address("192.168.127.1")
guest = address("192.168.127.2")
mac = bytes.fromhex("5a94efe4bc00")

s = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
s.settimeout(10)
try:
    s.connect(os.environ["WIRE"])
    # No length prefix, and none is needed: the socket type carries the frame
    # boundaries. A gateway that wrote a prefix anyway would put four bytes of
    # length at the front of a frame, and the guest would read a broken one.
    s.send(
        b"\xff\xff\xff\xff\xff\xff" + mac + b"\x08\x06"
        + b"\x00\x01\x08\x00\x06\x04\x00\x01"
        + mac + guest + b"\x00" * 6 + gateway)

    while True:
        try:
            frame = s.recv(2048)
        except socket.timeout:
            print("FAIL: no ARP reply over the seqpacket wire within 10s")
            sys.exit(1)
        if not frame:
            print("FAIL: the seqpacket wire closed")
            sys.exit(1)
        # One message is one frame, so a reply that arrived with anything in
        # front of it is not 42 bytes long and does not parse as ARP here --
        # which is the failure a length prefix would cause.
        if len(frame) != 42 or frame[12:14] != b"\x08\x06":
            continue
        if frame[20:22] != b"\x00\x02" or frame[28:32] != gateway:
            continue
        print("ok: bess  ARP", printable(gateway),
              "answered over a seqpacket wire, one message per frame")
        sys.exit(0)
finally:
    s.close()
PY
outcome=$?
kill "$GATEWAY" 2>/dev/null
wait "$GATEWAY" 2>/dev/null
GATEWAY=""
exit $outcome
