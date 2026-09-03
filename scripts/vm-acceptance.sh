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
# The control plane, so a check can publish a guest port the way `gvproxy`'s
# callers do. The path is short on purpose: an AF_UNIX path is capped near 104
# bytes and `mktemp -d` under TMPDIR eats most of that.
api="/tmp/netstack-acceptance-$$.sock"
trap 'rm -rf "$work" "$api"; jobs -p | xargs -r kill 2>/dev/null' EXIT
rm -f "$api"

echo "building the gateway"
if ! swift build -c release --product netstack-gateway >"$work/build.log" 2>&1; then
    tail -20 "$work/build.log"
    echo "✘ the gateway did not build"
    exit 1
fi
gateway="$PWD/.build/arm64-apple-macosx/release/netstack-gateway"
# `--show-bin-path` answers with an absolute path, so prepending $PWD to it
# produced a path that does not exist -- and the shim would have failed inside
# the guest, where the error is much harder to read than it is here.
[[ -x "$gateway" ]] || gateway="$(swift build -c release --show-bin-path)/netstack-gateway"
if [[ ! -x "$gateway" ]]; then
    echo "✘ no netstack-gateway at $gateway"
    exit 1
fi

# Written with a QUOTED heredoc and then substituted, rather than letting the
# outer shell expand it. An unquoted heredoc expands `${args[@]+...}` here,
# where there is no `args` -- which under `set -u` is an error reported against
# this line, for a variable belonging to a script that has not run yet.
cat > "$work/shim" <<'SHIM'
#!/bin/bash
set -uo pipefail
args=()
skip=0
for argument in "$@"; do
    if [[ $skip -eq 1 ]]; then skip=0; continue; fi
    case "$argument" in
        -config|--config) skip=1 ;;
        *) args+=("$argument") ;;
    esac
done
# `${args[@]+...}` rather than a bare expansion: in the bash 3.2 that macOS
# ships an empty array is an unbound variable under `set -u`, and so is
# `${#args[@]}` on one, so counting first does not help. The array can be
# empty, because sandbox may pass nothing but the config this drops.
exec "@GATEWAY@" --pcap "@PCAP@" --listen "unix://@API@" ${args[@]+"${args[@]}"}
SHIM
sed -i '' -e "s|@GATEWAY@|$gateway|" -e "s|@PCAP@|$pcap|" -e "s|@API@|$api|" "$work/shim"
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
# The DNS answers are reduced to a token inside the guest rather than grepped
# out of the transcript here. Grepping the transcript is what this did first,
# and it could not fail: `192.168.127.1` is in `resolv.conf`, and the name being
# asked about is echoed by `nslookup` whether it resolves or not, so the check
# passed on its own inputs.
guest 'ip -4 addr show dev eth0
ip route
cat /etc/resolv.conf
ping -c 3 -W 2 192.168.127.1
resolve() {
    nslookup "$1" 192.168.127.1 2>/dev/null |
        awk "/^Name:/ { seen = 1; next } seen && /^Address/ { print \$NF; exit }"
}
echo "GATEWAY_NAME=$(resolve gateway.containers.internal)"
echo "HOST_NAME=$(resolve host.containers.internal)"
echo "ABSENT_NAME=$(resolve nothing.containers.internal)"' "$work/basics.out"

grep -qE "inet 192\.168\.127\.2(/| )" "$work/basics.out" \
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

grep -q "^GATEWAY_NAME=192.168.127.1$" "$work/basics.out" \
    && pass "gateway.containers.internal resolves to the gateway" \
    || fail "gateway.containers.internal resolved to $(grep '^GATEWAY_NAME=' "$work/basics.out" | cut -d= -f2-)"

grep -q "^HOST_NAME=192.168.127.254$" "$work/basics.out" \
    && pass "host.containers.internal resolves to the host" \
    || fail "host.containers.internal resolved to $(grep '^HOST_NAME=' "$work/basics.out" | cut -d= -f2-)"

# The negative control, without which the two above would pass against a
# resolver that answered everything with the gateway's own address.
grep -q "^ABSENT_NAME=$" "$work/basics.out" \
    && pass "a name that does not exist resolves to nothing" \
    || fail "an absent name resolved to $(grep '^ABSENT_NAME=' "$work/basics.out" | cut -d= -f2-)"

# --- The half-close, which is what a real guest found ------------------------

port=24682
printf 'TWENTY-BYTES-EXACTLY\n' | nc -l "$port" >/dev/null 2>&1 &
sleep 1
guest "nc -w 8 192.168.127.254 $port | od -c" "$work/halfclose.out"
grep -q "T   W   E   N   T   Y" "$work/halfclose.out" \
    && pass "a guest that has finished sending still gets the answer" \
    || fail "the half-closed connection got nothing" "$(tail -3 "$work/halfclose.out")"

# --- The same, with enough payload that the FIN has to queue behind it -------

# `nc` cannot serve this one: it quits when the client half-closes, and a
# truncated transfer would read as a gateway defect. So the listener is Python,
# and its absence is reported rather than skipped past.
if ! command -v python3 >/dev/null 2>&1; then
    fail "python3 is not available, so the bulk half-close check did not run"
fi
port=24684
if command -v python3 >/dev/null 2>&1; then
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
fi

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

# --- A port published into the guest -----------------------------------------
#
# The reason this check exists: it did not work at all, and nothing here noticed
# until a guest was booted and asked. The gateway bound the host port, accepted,
# ARPed for the guest, got its reply -- and never sent a SYN, because an active
# open's SYN was emitted once, dropped while ARP was still unresolved, and never
# retransmitted.

port=24688
guest_out="$work/published.out"
rm -f "$api"
SANDBOX_GATEWAY="$work/shim" sandbox run alpine -- sh -c \
    '(while true; do echo GUEST-LISTENER | nc -l -p 9999; done) & sleep 45' >"$guest_out" 2>&1 &
for _ in $(seq 1 20); do [[ -S "$api" ]] && break; sleep 2; done
sleep 12

if [[ -S "$api" ]] && command -v curl >/dev/null 2>&1; then
    curl -s -X POST --unix-socket "$api" http://x/services/forwarder/expose \
        -d "{\"local\":\"127.0.0.1:$port\",\"remote\":\"192.168.127.2:9999\"}" >/dev/null
    sleep 1
    cat > "$work/reach.py" <<'PY'
import socket, sys
s = socket.socket()
s.settimeout(10)
try:
    s.connect(("127.0.0.1", int(sys.argv[1])))
    # Never closes its own send side: the guest's listener speaks first, so
    # this must not depend on half-closure to get an answer.
    print(s.recv(64).decode(errors="replace").strip())
except Exception as error:
    print("error: %s" % type(error).__name__)
s.close()
PY
    answer="$(python3 "$work/reach.py" "$port")"
    [[ "$answer" == "GUEST-LISTENER" ]] \
        && pass "a port published into the guest carries a connection" \
        || fail "the published port answered '$answer'"
else
    fail "the control plane never appeared at $api, so nothing was published"
fi

# --- A UDP port published into the guest, first datagram and all -------------
#
# The same root cause as the check above, without the thing that hid it. TCP
# retransmits its SYN and so eventually gets through; UDP has nothing to
# retransmit with, so the FIRST datagram to a guest -- the one that has to wait
# for ARP -- was lost every time. Exactly one datagram is sent here on purpose.

udp_port=24690
rm -f "$api"
SANDBOX_GATEWAY="$work/shim" sandbox run alpine -- sh -c \
    '(timeout 40 nc -u -l -p 9998 > /tmp/udp.seen 2>&1) & sleep 34; echo "SEEN=$(cat /tmp/udp.seen 2>/dev/null)"' \
    >"$work/udp.out" 2>&1 &
for _ in $(seq 1 20); do [[ -S "$api" ]] && break; sleep 2; done
sleep 12

if [[ -S "$api" ]] && command -v curl >/dev/null 2>&1; then
    curl -s -X POST --unix-socket "$api" http://x/services/forwarder/expose \
        -d "{\"local\":\"127.0.0.1:$udp_port\",\"remote\":\"192.168.127.2:9998\",\"protocol\":\"udp\"}" >/dev/null
    sleep 1
    cat > "$work/knock.py" <<'PY'
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
# One datagram, deliberately. A second would arrive whatever happens to the
# first, and would turn this into a check that cannot fail.
s.sendto(b"FIRST-DATAGRAM", ("127.0.0.1", int(sys.argv[1])))
s.close()
PY
    python3 "$work/knock.py" "$udp_port"
    for _ in $(seq 1 12); do grep -q "^SEEN=" "$work/udp.out" && break; sleep 5; done
    grep -q "^SEEN=FIRST-DATAGRAM$" "$work/udp.out" \
        && pass "the first datagram to a published UDP port arrives" \
        || fail "the guest saw '$(grep '^SEEN=' "$work/udp.out" | cut -d= -f2-)'"
else
    fail "the control plane never appeared at $api, so no UDP port was published"
fi

echo
if [[ $status -eq 0 ]]; then
    echo "✔ a real guest sees what it should"
else
    echo "✘ a real guest sees something it should not"
fi
exit $status
