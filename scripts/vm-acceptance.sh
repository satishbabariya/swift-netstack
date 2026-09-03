#!/usr/bin/env bash
# Boot a real Linux guest against this gateway and check what it actually sees.
#
# Every other gate in this repository drives the gateway with frames this
# repository wrote. That is worth a great deal and it has one blind spot: it
# cannot tell you what a real TCP stack does when it meets this one. Two rounds
# of defects came out of closing that gap and none of them were reachable from a
# test that composes its own segments:
#
#   - A guest that FINs its send side got its answer thrown away. `busybox nc`
#     with no stdin does that within a millisecond of the handshake, and the
#     capture showed the gateway answering with `[F.] length 0`.
#   - A host that speaks first had its banner dropped, because the forwarder
#     dials on the guest's SYN and the reply could be queued on a channel whose
#     endpoint was still in SYN-RECEIVED.
#   - A DNS name that exists with no record of the type asked for was answered
#     NXDOMAIN, which a resolver caches as "this name does not exist".
#
# ## Why this is not in CI
#
# It needs Virtualization.framework, and GitHub's macOS runners are themselves
# virtual machines -- nesting is not available. So this is a local gate: run it
# before anything that touches the data path, and read it as the thing that
# tells you whether the gateway works, as opposed to whether it does what its
# tests say.
#
# ## What it needs
#
#   brew install satishbabariya/tap/sandbox     (or however you have it)
#
# ## The shim, and its one dishonesty
#
# `sandbox` passes `-config <file>` to whatever it starts as its gateway. This
# gateway does not take that flag -- the decision not to grow a YAML surface is
# deliberate and documented -- so a shim drops it. That also drops sandbox's
# egress policy, which is why every check below stays inside the virtual
# network or talks to a listener on this machine. Nothing here exercises or
# validates sandbox's enforcement, and this script must not grow a check that
# reaches the internet and reads a pass as one.

set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

if ! command -v sandbox >/dev/null 2>&1; then
    echo "skipped: sandbox is not installed, so there is no guest to boot"
    exit 0
fi

status=0
fail() {
    status=1
    echo "✘ $1"
    [[ $# -gt 1 ]] && printf '    %s\n' "$2"
}
pass() { echo "✔ $1"; }

work="$(mktemp -d)"
pcap="$work/guest.pcap"
trap 'rm -rf "$work"; jobs -p | xargs -r kill 2>/dev/null' EXIT

echo "building the gateway"
if ! swift build -c release --product netstack-gateway >"$work/build.log" 2>&1; then
    tail -20 "$work/build.log"
    echo "✘ the gateway did not build"
    exit 1
fi
gateway="$PWD/.build/arm64-apple-macosx/release/netstack-gateway"
[[ -x "$gateway" ]] || gateway="$PWD/$(swift build -c release --show-bin-path)/netstack-gateway"

cat > "$work/shim" <<SHIM
#!/bin/bash
set -euo pipefail
args=()
skip=0
for argument in "\$@"; do
    if [[ \$skip -eq 1 ]]; then skip=0; continue; fi
    case "\$argument" in
        -config|--config) skip=1 ;;
        *) args+=("\$argument") ;;
    esac
done
exec "$gateway" --pcap "$pcap" "\${args[@]}"
SHIM
chmod +x "$work/shim"

# One boot per check would be honest and unusably slow -- a guest takes several
# seconds to come up. The checks that need no host listener are batched into a
# single boot instead, and the ones that do get their own.
guest() {
    local script="$1" out="$2"
    SANDBOX_GATEWAY="$work/shim" sandbox run alpine -- sh -c "$script" >"$out" 2>&1
}

# --- What the guest is given -------------------------------------------------

echo "booting a guest"
guest 'ip -4 addr show dev eth0; ip route; cat /etc/resolv.conf; ping -c 3 -W 2 192.168.127.1; nslookup gateway.containers.internal 192.168.127.1' "$work/basics.out"

grep -q "192.168.127.2" "$work/basics.out" \
    && pass "the guest gets 192.168.127.2 by DHCP" \
    || fail "the guest did not get 192.168.127.2" "$(head -5 "$work/basics.out")"

grep -qE "default via 192.168.127.1" "$work/basics.out" \
    && pass "the default route is the gateway" \
    || fail "no default route through 192.168.127.1"

grep -q "nameserver 192.168.127.1" "$work/basics.out" \
    && pass "the resolver is the gateway" \
    || fail "resolv.conf does not name the gateway"

grep -qE "3 packets received|3 received" "$work/basics.out" \
    && pass "the gateway answers ICMP echo" \
    || fail "ping lost packets" "$(grep -A 2 'ping statistics' "$work/basics.out" | head -3)"

grep -q "192.168.127.1" "$work/basics.out" && grep -q "gateway.containers.internal" "$work/basics.out" \
    && pass "the gateway's own name resolves" \
    || fail "gateway.containers.internal did not resolve"

# --- The half-close, which is what a real guest found ------------------------

port=24682
printf 'TWENTY-BYTES-EXACTLY\n' | nc -l "$port" >/dev/null 2>&1 &
sleep 1
guest "nc -w 8 192.168.127.254 $port | od -c" "$work/halfclose.out"
grep -q "T   W   E   N   T   Y" "$work/halfclose.out" \
    && pass "a guest that has finished sending still gets the answer" \
    || fail "the half-closed connection got nothing" "$(tail -3 "$work/halfclose.out")"

# --- The same, with enough payload that the FIN has to queue behind it -------

port=24684
python3 - "$port" <<'PY' &
import socket, sys
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", int(sys.argv[1])))
s.listen(1)
c, _ = s.accept()
# Deliberately ignores the client's half-close, which `nc` does not: `nc` quits
# on it, and a truncated transfer would then look like a gateway defect.
c.sendall(b"Z" * 200000)
c.shutdown(socket.SHUT_WR)
c.close()
s.close()
PY
sleep 1
guest "nc -w 20 192.168.127.254 $port | wc -c" "$work/bulk.out"
received="$(grep -oE '^ *[0-9]+' "$work/bulk.out" | tr -d ' ' | tail -1)"
[[ "${received:-0}" == "200000" ]] \
    && pass "200,000 bytes cross a half-closed connection" \
    || fail "the guest received ${received:-0} of 200000 bytes"

# The FIN must sit at the end of the data, not on top of it. This is the check
# that a unit test can state and only a real transfer can put under pressure:
# the window has to actually close for the sender to hold anything back.
if command -v tcpdump >/dev/null 2>&1 && [[ -s "$pcap" ]]; then
    finish="$(tcpdump -r "$pcap" -n 2>/dev/null | grep "$port" | grep -oE 'Flags \[F\.\], seq [0-9]+' | tail -1 | grep -oE '[0-9]+$')"
    [[ "${finish:-0}" == "200001" ]] \
        && pass "the gateway's FIN sits where the data ends" \
        || fail "the FIN is at ${finish:-unknown}, the data ends at 200001"
fi

# --- A host that speaks first ------------------------------------------------

port=24686
printf 'GREETINGS\n' | nc -l "$port" >/dev/null 2>&1 &
sleep 1
guest "nc -w 8 192.168.127.254 $port | head -1" "$work/banner.out"
grep -q "GREETINGS" "$work/banner.out" \
    && pass "a host that speaks first is heard" \
    || fail "the banner never arrived" "$(tail -3 "$work/banner.out")"

echo
if [[ $status -eq 0 ]]; then
    echo "✔ a real guest sees what it should"
else
    echo "✘ a real guest sees something it should not"
fi
exit $status
