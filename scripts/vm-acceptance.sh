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

# NOT "by DHCP", which is what this said first and is not true: the capture
# holds no DHCP exchange at all, because `sandbox` addresses its guest itself.
# What this checks is that the address the guest ends up with is the one this
# gateway expects to be talking to. The DHCP server has frame-level tests of its
# own in `frame-smoke.sh`; no real guest here has ever asked it for anything,
# and this script must not be read as saying otherwise.
grep -qE "inet 192\.168\.127\.2(/| )" "$work/basics.out" \
    && pass "the guest is addressed at 192.168.127.2 on the gateway's subnet" \
    || fail "the guest is not at 192.168.127.2" "$(head -5 "$work/basics.out")"

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

# --- The resolver over TCP ---------------------------------------------------
#
# Upstream serves DNS on both transports and a resolver needs both: an answer
# that will not fit a datagram comes back truncated, and the asker's next move
# is the same question over TCP. Before this the guest could not even connect --
# `nc -z 192.168.127.1 53` returned 1.
#
# The query is built here rather than by a tool, because Alpine has neither
# `dig` nor a `nslookup` that will use TCP. It is `gateway.containers.internal`
# A IN, framed with RFC 1035 §4.2.2's two-byte length prefix.

# Labelled and on one line of its own. The first version collapsed the whole
# transcript with `tr -d`, which swept sandbox's own banner into the answer and
# made the match fail for a reason that had nothing to do with DNS.
# Retried inside the guest rather than asked once. Every other check here runs
# after something that has already waited for the network -- this one is first
# in its own boot, and asking before the interface is up answered nothing at
# all, which read as a refusal.
guest 'i=0
while [ $i -lt 10 ]; do
    answer=$(printf "\x00\x2d\x2b\x2b\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07\x67\x61\x74\x65\x77\x61\x79\x0a\x63\x6f\x6e\x74\x61\x69\x6e\x65\x72\x73\x08\x69\x6e\x74\x65\x72\x6e\x61\x6c\x00\x00\x01\x00\x01" | nc -w 6 192.168.127.1 53 | od -An -tx1 | tr -d " \n")
    case "$answer" in *c0a87f01) break ;; esac
    i=$((i + 1))
    sleep 2
done
echo "TCPANSWER=$answer"' \
    "$work/dnstcp.out"

# The answer's last four bytes are the address: c0 a8 7f 01 is 192.168.127.1.
# Matched rather than "did anything come back", so a truncated or refused reply
# cannot pass.
grep -q "^TCPANSWER=.*c0a87f01$" "$work/dnstcp.out" \
    && pass "the resolver answers over TCP" \
    || fail "the TCP query answered [$(grep '^TCPANSWER=' "$work/dnstcp.out" | cut -d= -f2- | tail -c 40)]"

# And the host alias is NOT the resolver. That address exists so a guest can
# reach the HOST, and a gateway answering port 53 there takes away the one
# thing it is for. An earlier version of the registration above claimed every
# address this gateway answers for, and did exactly that.
#
# Asked as a QUERY rather than as a connection. `nc -z` to this address
# succeeds either way -- the forwarder accepts the guest's SYN before it knows
# whether the host will answer -- so a check on the connection cannot tell "the
# gateway answered" from "the host was asked". The gateway's own record can.
guest 'echo "ALIASANSWER=$(printf "\\x00\\x2d\\x2b\\x2b\\x01\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x07\\x67\\x61\\x74\\x65\\x77\\x61\\x79\\x0a\\x63\\x6f\\x6e\\x74\\x61\\x69\\x6e\\x65\\x72\\x73\\x08\\x69\\x6e\\x74\\x65\\x72\\x6e\\x61\\x6c\\x00\\x00\\x01\\x00\\x01" | nc -w 6 192.168.127.254 53 | od -An -tx1 | tr -d " \\n")"' \
    "$work/aliasdns.out"
if grep -q "^ALIASANSWER=.*c0a87f01" "$work/aliasdns.out"; then
    fail "the gateway answered a query on the host alias, so the host cannot"
else
    pass "port 53 on the host alias belongs to the host, not the gateway"
fi

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
    || fail "the half-closed bulk transfer lost data" \
        "the guest received ${received:-0} of 200000 bytes"
fi

# The FIN must sit at the end of the data, not on top of it. This is the check
# that a unit test can state and only a real transfer can put under pressure:
# the window has to actually close for the sender to hold anything back.
#
# It reads the capture, which is buffered, and it gets away with that only
# because more checks run after it and their traffic flushes what this one
# needs. That is luck rather than design -- see the note further down about a
# check that had none -- so this must stay ahead of at least one other check
# that puts traffic through, and it must not become the last thing here.
if command -v tcpdump >/dev/null 2>&1 && [[ -s "$pcap" ]]; then
    finish="$(tcpdump -r "$pcap" -n 2>/dev/null | grep "$port" | grep -oE 'Flags \[F\.\], seq [0-9]+' | tail -1 | grep -oE '[0-9]+$')"
    [[ "${finish:-0}" == "200001" ]] \
        && pass "the gateway's FIN sits where the data ends" \
        || fail "the FIN is at ${finish:-unknown}, the data ends at 200001"
fi

# --- A megabyte to a guest that stops reading ---------------------------------
#
# The 200,000-byte check above crosses without the peer's window ever closing,
# so nothing is ever held in the channel's own queue. This one holds the reader
# still for fifteen seconds, which fills the send buffer and pushes the rest
# into that queue -- and a close used to discard exactly that.
#
# The failure it guards was silent from both ends: the host's `sendall` returned
# having written every byte, and the guest simply had fewer. Measured before the
# fix, 400,160 of 1,000,000, varying run to run.

port=24750
if command -v python3 >/dev/null 2>&1; then
cat > "$work/megabyte.py" <<'PY'
import socket, sys
PAYLOAD = bytes((i * 31 + 7) % 256 for i in range(1000000))
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", int(sys.argv[1])))
s.listen(1)
c, _ = s.accept()
c.sendall(PAYLOAD)
c.shutdown(socket.SHUT_WR)
c.close()
s.close()
PY
python3 "$work/megabyte.py" "$port" &
sleep 1
# The reader stalls, so the guest's window closes and the gateway has to hold
# what it has accepted rather than drop it.
guest "nc -w 60 192.168.127.254 $port | (sleep 15; wc -c)" "$work/megabyte.out"
carried="$(grep -oE '^ *[0-9]+' "$work/megabyte.out" | tr -d ' ' | tail -1)"
[[ "${carried:-0}" == "1000000" ]] \
    && pass "a megabyte survives a guest that stops reading" \
    || fail "the megabyte to a stalled reader lost data" \
        "the guest received ${carried:-0} of 1000000 bytes"
else
    fail "python3 is not available, so the megabyte check did not run"
fi

# --- The premise under which MUST-38 is left unimplemented --------------------
#
# RFC 9293 §3.8.6.2.1's MUST-38 -- sender-side silly-window-syndrome avoidance
# -- is deliberately not implemented, and the README says why: the condition it
# governs is a peer that reopens its window a few bytes at a time, and nothing
# available could check whether that ever happens.
#
# A real guest can. Linux does its own receiver-side avoidance: under the stall
# above it holds the window at ZERO and then reopens it by tens of kilobytes,
# rather than dribbling. So the crawl MUST-38 prevents has no occasion to
# happen, which is the premise the decision rests on.
#
# This check is that premise, not the RFC. If a guest ever does advertise a
# small non-zero window here, the decision needs revisiting -- and this is what
# would say so.

if command -v tcpdump >/dev/null 2>&1 && [[ -s "$pcap" ]]; then
    # The raw field, because the scale factor is not visible per segment. This
    # guest negotiates wscale 7, so 12 raw is 1536 bytes -- about one segment.
    # Unscaled it would be 12 bytes, which is absurd either way, so the
    # threshold flags a silly window under either reading.
    dribbles="$(tcpdump -r "$pcap" -n 2>/dev/null |
        grep "192.168.127.2\.[0-9]* > 192.168.127.254.$port" |
        grep -oE 'win [0-9]+' | awk '$2 > 0 && $2 < 12' | wc -l | tr -d ' ')"
    [[ "${dribbles:-0}" == "0" ]] \
        && pass "the guest never advertises a silly window, so MUST-38 has no occasion" \
        || fail "the guest advertised $dribbles small non-zero windows; MUST-38 now matters"
fi

# --- A host that resets mid-transfer -----------------------------------------
#
# There is no check here, and the reason is worth writing down.
#
# One was written: it read the capture and required the LAST thing the gateway
# said on the connection to carry a FIN or a RST, so that a stream could not
# simply stop. It failed intermittently, and the intermittency was the check's,
# not the gateway's. The capture is flushed on exit and the gateway exits when
# the guest does, so the very last record written -- which is exactly the FIN --
# is the one most likely to be missing. Waiting and re-reading did not help,
# because it was never going to arrive.
#
# What settled it was tracing the gateway rather than the capture:
#
#     shutdownWrite already=false n=1 unsent=0 state=closeWait
#     emitFin state=lastAck
#
# The FIN was sent. The check's evidence was absent, which is not the same
# thing, and a check that cannot tell those apart does not belong in a gate
# whose whole purpose is to be believed.
#
# The property is covered where it can be observed without a capture:
# `aDeferredCloseEndsWithAFinRatherThanSilence` in the channel tests.


# --- A connection that says nothing for a while and then does -----------------
#
# What an SSH session or a database connection looks like from here. Nothing in
# this gateway should end one: TCP keep-alive does not start probing for two
# hours by default, and neither of the two short timers this gateway does have
# belongs anywhere near an ordinary connection -- the resolver's ten-second read
# idle applies to guests asking it questions, and the lingering close's sixty
# seconds applies to a channel that is already closing.
#
# Ninety seconds, which is past the longer of those two on purpose. The risk
# this guards is real rather than theoretical: destinations this gateway answers
# itself are matched by address and port, and a service registered for the wrong
# one would put the control plane's idle handler on a connection that was only
# passing through.

port=24780
if command -v python3 >/dev/null 2>&1; then
cat > "$work/idle.py" <<'PY'
import socket, sys, time
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", int(sys.argv[1])))
s.listen(1)
c, _ = s.accept()
c.sendall(b"HELLO\n")
time.sleep(90)
try:
    c.sendall(b"STILL-HERE\n")
except Exception:
    pass
c.close()
s.close()
PY
python3 "$work/idle.py" "$port" &
sleep 1
guest "nc -w 130 192.168.127.254 $port" "$work/idle.out"
grep -q "STILL-HERE" "$work/idle.out" \
    && pass "a connection idle for ninety seconds still carries traffic" \
    || fail "the idle connection was gone: $(grep -v '^sandbox:' "$work/idle.out" | tr '\n' ' ')"
else
    fail "python3 is not available, so the idle check did not run"
fi

# --- A host that speaks first ------------------------------------------------

port=24686
printf 'GREETINGS\n' | nc -l "$port" >/dev/null 2>&1 &
sleep 1
guest "nc -w 8 192.168.127.254 $port | head -1" "$work/banner.out"
grep -q "GREETINGS" "$work/banner.out" \
    && pass "a host that speaks first is heard" \
    || fail "the banner never arrived" "$(tail -3 "$work/banner.out")"

# --- A real DHCP client asking this gateway for a lease -----------------------
#
# The gap this script has carried since it was written, and said so: `sandbox`
# addresses its guest itself, so no guest here had ever asked for a lease and
# the DHCP server's only tests were the frame-level ones in `frame-smoke.sh`.
# Upstream's suite has "should return DHCP leases"; this is that, plus the
# exchange behind it.
#
# `udhcpc` is busybox's, so it is already in the image. It reports the whole
# exchange -- discover, select, the lease and its term -- and its own attempts
# to reconfigure the interface fail under sandbox's restrictions, which is why
# the check reads its output rather than its exit status.

lease_out="$work/dhcp.out"
rm -f "$api"
SANDBOX_GATEWAY="$work/shim" sandbox run alpine -- sh -c \
    'sleep 8
     cat > /tmp/opts.sh <<'"'"'SCRIPT'"'"'
#!/bin/sh
echo "OPT_ROUTER=$router"
echo "OPT_DNS=$dns"
echo "OPT_SUBNET=$subnet"
echo "OPT_MTU=$mtu"
echo "OPT_LEASE=$lease"
SCRIPT
     chmod +x /tmp/opts.sh
     udhcpc -i eth0 -n -q -f -s /tmp/opts.sh 2>&1 | grep -E "obtained|discover|select|^OPT_"
     echo DHCPASKED
     sleep 40' \
    >"$lease_out" 2>&1 &
for _ in $(seq 1 20); do [[ -S "$api" ]] && break; sleep 2; done
for _ in $(seq 1 30); do grep -q DHCPASKED "$lease_out" && break; sleep 2; done

grep -q "lease of 192.168.127.2 obtained from 192.168.127.1" "$lease_out" \
    && pass "a real DHCP client gets a lease from this gateway" \
    || fail "no lease was offered to a real DHCP client" \
        "udhcpc said: $(grep -v '^sandbox:' "$lease_out" | tr '\n' ' ' | tail -c 120)"

# And the options it is given, which is the part that decides whether the guest
# can do anything with the address. `udhcpc` hands them to its script as
# environment variables, so this asks for one that prints them.
#
# These replaced two checks that read the guest's own configuration back --
# "the default route is the gateway", "the resolver is the gateway". Those were
# reading what `sandbox` had written, not what this gateway offers, so nothing
# this gateway did could make them fail. What they claimed is now checked at the
# only place it is this gateway's to get right.
#
# Options 3, 6, 1, 26 and 51. Upstream sends the same set, plus 119 when there
# are search domains -- absent here because the host has none, which is why
# there is no assertion for it rather than an assertion that it is empty.
dhcp_option() { grep "^OPT_$1=" "$lease_out" | tail -1 | cut -d= -f2-; }
for expected in "ROUTER=192.168.127.1" "DNS=192.168.127.1" \
    "SUBNET=255.255.255.0" "MTU=1500" "LEASE=3600"; do
    name="${expected%%=*}"
    want="${expected#*=}"
    got="$(dhcp_option "$name")"
    [[ "$got" == "$want" ]] \
        && pass "the lease carries $name=$want" \
        || fail "the lease carried $name=$got, not $want"
done

# And the lease is visible where upstream's own client looks for it. Asked
# while the guest is still up: the gateway goes when the guest does, and an
# empty answer from a socket that is no longer there reads exactly like an
# empty lease table.
if [[ -S "$api" ]] && command -v curl >/dev/null 2>&1; then
    listed="$(curl -s --unix-socket "$api" http://x/services/dhcp/leases)"
    case "$listed" in
        *192.168.127.2*) pass "the lease is listed at /services/dhcp/leases" ;;
        *) fail "the lease table said '$listed'" ;;
    esac
else
    fail "the control plane was gone, so the lease table could not be read"
fi

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

    # The daemon's tunnel, in the same boot rather than another: `POST /tunnel`
    # turns the control-plane connection itself into a byte pipe to an address
    # inside the guest network. Upstream tests it ("reach a http server in the
    # VM using the tunneling of the daemon") and nothing here did.
    #
    # `OK` first, not an HTTP response: the connection stopped being HTTP when
    # the request was hijacked, and a client waits for that byte pair before it
    # sends anything.
    cat > "$work/tunnel.py" <<'PY'
import socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(12)
s.connect(sys.argv[1])
s.sendall(b"POST /tunnel?ip=192.168.127.2&port=9999 HTTP/1.1\r\nHost: x\r\n\r\n")
got = b""
try:
    while len(got) < 64:
        chunk = s.recv(4096)
        if not chunk:
            break
        got += chunk
except Exception:
    pass
print(got.decode(errors="replace").strip())
s.close()
PY
    tunnelled="$(python3 "$work/tunnel.py" "$api")"
    case "$tunnelled" in
        OKGUEST-LISTENER) pass "the daemon's tunnel reaches into the guest" ;;
        *) fail "the tunnel carried '$tunnelled'" ;;
    esac

    # And a unix socket on the host forwarding to a port in the guest, which is
    # upstream's "expose and reach an http service using unix to tcp
    # forwarding". The route accepts `protocol: unix`; nothing here had ever
    # opened one.
    #
    # Short path on purpose, beside `$api` and for the same reason: an AF_UNIX
    # path is capped near 104 bytes and `$work` is under TMPDIR.
    socket_forward="/tmp/netstack-acceptance-fwd-$$.sock"
    rm -f "$socket_forward"
    curl -s -X POST --unix-socket "$api" http://x/services/forwarder/expose \
        -d "{\"local\":\"$socket_forward\",\"remote\":\"192.168.127.2:9999\",\"protocol\":\"unix\"}" \
        >/dev/null
    sleep 1
    cat > "$work/unixfwd.py" <<'PY'
import socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(10)
try:
    s.connect(sys.argv[1])
    print(s.recv(64).decode(errors="replace").strip())
except Exception as error:
    print("error: %s" % type(error).__name__)
s.close()
PY
    carried="$(python3 "$work/unixfwd.py" "$socket_forward")"
    rm -f "$socket_forward"
    [[ "$carried" == "GUEST-LISTENER" ]] \
        && pass "a unix socket on the host forwards into the guest" \
        || fail "the unix forward carried '$carried'"
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
        || fail "the first datagram to a published UDP port was not delivered" \
            "the guest saw '$(grep '^SEEN=' "$work/udp.out" | cut -d= -f2-)'"
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
