#!/usr/bin/env bash
# A gateway under sustained mixed traffic, watched rather than sampled.
#
# Every other executable-level check asks one question and stops. That is the
# right shape for "does this work", and it is blind to everything that only
# appears over time: a descriptor leaked per connection, memory that climbs, a
# table that fills, a race that needs a thousand attempts to lose.
#
# So this runs one gateway for a while and keeps a guest talking to it -- ARP,
# DHCP, DNS, TCP connections opened and closed, UDP flows -- then asks three
# questions the single-shot checks cannot:
#
#   - is it still answering,
#   - did its memory settle rather than climb,
#   - did its descriptors settle rather than climb.
#
# Not a benchmark. The numbers here are bounds a broken gateway crosses, not
# figures to compare between runs, and they are deliberately loose: a check that
# fails when a machine is busy teaches nothing.

set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

export SMOKE_SUPPORT="$PWD/scripts/smoke"
SECONDS_TO_RUN="${NETSTACK_SOAK_SECONDS:-20}"

WIRE=""
CONTROL=""
GATEWAY=""
cleanup() {
    [[ -n "$GATEWAY" ]] && kill "$GATEWAY" 2>/dev/null
    rm -f "$WIRE" "$WIRE.client" "$CONTROL"
}
trap cleanup EXIT INT TERM

echo "building the gateway"
swift build -c release --product netstack-gateway >/dev/null || exit 1
binary="$(swift build -c release --show-bin-path)/netstack-gateway"

WIRE="${TMPDIR:-/tmp}/netstack-soak-$$.sock"
CONTROL="${TMPDIR:-/tmp}/netstack-soak-ctl-$$.sock"
rm -f "$WIRE" "$CONTROL"
"$binary" --listen-vfkit "$WIRE" --listen "unix://$CONTROL" >/dev/null 2>&1 &
GATEWAY=$!
for _ in $(seq 1 120); do
    [[ -S "$WIRE" && -S "$CONTROL" ]] && break
    sleep 0.25
done
[[ -S "$WIRE" && -S "$CONTROL" ]] || { echo "FAIL: the gateway never came up"; exit 1; }

echo "soaking for ${SECONDS_TO_RUN}s"
WIRE="$WIRE" CONTROL="$CONTROL" GATEWAY="$GATEWAY" SECONDS_TO_RUN="$SECONDS_TO_RUN" python3 - <<'PY'
import json, os, socket, struct, subprocess, sys, time

sys.path.insert(0, os.environ["SMOKE_SUPPORT"])
from wire import address, ones_complement, printable

wire = os.environ["WIRE"]
gateway = address("192.168.127.1")
host = address("192.168.127.254")
guest = address("192.168.127.2")
mac = bytes.fromhex("5a94efe4bc00")
GATEWAY_MAC = bytes.fromhex("5a94efe40cee")
run_for = float(os.environ["SECONDS_TO_RUN"])
pid = os.environ["GATEWAY"]

client_path = wire + ".client"
try:
    os.unlink(client_path)
except OSError:
    pass
s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
s.bind(client_path)
s.connect(wire)
s.setblocking(False)


def ipv4(source, destination, protocol, payload):
    header = bytearray(
        b"\x45\x00" + (20 + len(payload)).to_bytes(2, "big")
        + b"\x00\x00\x40\x00\x40" + bytes([protocol]) + b"\x00\x00" + source + destination)
    header[10:12] = ones_complement(bytes(header)).to_bytes(2, "big")
    return GATEWAY_MAC + mac + b"\x08\x00" + bytes(header) + payload


def tcp_syn(sport, dport):
    header = (
        sport.to_bytes(2, "big") + dport.to_bytes(2, "big") + (1000).to_bytes(4, "big")
        + bytes(4) + bytes([5 << 4, 0x02]) + (65535).to_bytes(2, "big") + bytes(4))
    pseudo = guest + host + b"\x00\x06" + len(header).to_bytes(2, "big")
    header = header[:16] + ones_complement(pseudo + header).to_bytes(2, "big") + header[18:]
    return ipv4(guest, host, 6, header)


def udp_to(destination, sport, dport, payload):
    body = (sport.to_bytes(2, "big") + dport.to_bytes(2, "big")
            + (8 + len(payload)).to_bytes(2, "big") + b"\x00\x00" + payload)
    return ipv4(guest, destination, 17, body)


def dns_query(sport, index):
    labels = [b"soak%d" % index, b"example"]
    name = b"".join(bytes([len(part)]) + part for part in labels) + b"\x00"
    return udp_to(gateway, sport, 53,
                  b"\x51\x51" + b"\x01\x00" + b"\x00\x01" + b"\x00" * 6 + name + b"\x00\x01\x00\x01")


def arp():
    return (b"\xff" * 6 + mac + b"\x08\x06" + b"\x00\x01\x08\x00\x06\x04\x00\x01"
            + mac + guest + b"\x00" * 6 + gateway)


def resources():
    """What the gateway is holding: resident kilobytes and open descriptors."""
    rss = subprocess.run(["ps", "-o", "rss=", "-p", pid], capture_output=True, text=True)
    files = subprocess.run(["lsof", "-p", pid], capture_output=True, text=True)
    return (int(rss.stdout.strip() or 0), len(files.stdout.strip().split("\n")))


def statistics():
    answer = subprocess.run(
        ["curl", "--silent", "--fail-with-body", "--max-time", "10",
         "--unix-socket", os.environ["CONTROL"], "http://gateway/stats"],
        capture_output=True, text=True, timeout=20)
    return json.loads(answer.stdout) if answer.returncode == 0 else None


# Measured between two points partway through, not against the start.
#
# The gateway's pools are bounded -- five hundred and twelve UDP flows, a
# thousand TCP connections -- so a run that opens flows climbs to that ceiling
# and stops. Comparing against the first instant cannot tell that apart from
# climbing without one: the first version of this check called five hundred and
# twenty-three descriptors a leak when it was the limit doing its job.
#
# So the question is asked between HALFWAY and the END, by which time anything
# bounded has found its bound and anything unbounded is still going.
s.send(arp())
time.sleep(1.0)
while True:
    try:
        s.recv(4096)
    except OSError:
        break

started = time.time()
midpoint = None
sent = 0
port = 20000
def offer(frame):
    """Send unless the gateway's queue is full, which is the guest's own
    backpressure and not a failure -- a real guest waits too."""
    global sent
    try:
        s.send(frame)
        sent += 1
    except OSError:
        pass


while time.time() - started < run_for:
    for _ in range(25):
        port = 20000 + (port + 1) % 40000
        offer(arp())
        offer(dns_query(port, port))
        offer(tcp_syn(port, 80))
        offer(udp_to(host, port, 9, b"soak"))
    # Drained, because a guest that never reads is a different test and this one
    # would otherwise measure the wire backing up rather than the gateway.
    while True:
        try:
            s.recv(4096)
        except OSError:
            break
    if midpoint is None and time.time() - started >= run_for / 2:
        midpoint = resources()
    time.sleep(0.01)

time.sleep(1.0)
after = resources()
before = midpoint if midpoint is not None else after
stats = statistics()
s.close()
os.unlink(client_path)

print(f"  sent {sent} frames over {run_for:.0f}s")
if stats:
    interesting = [
        "ipv4_delivered", "udp_sockets_opened", "udp_flows", "tcp_established",
        "tcp_dial_failed", "dns_refused_no_upstream", "outbound_frames_backed_up",
    ]
    print("  " + "  ".join(f"{k}={stats.get(k)}" for k in interesting if k in stats))
print(f"  resident: {before[0]} KiB at the halfway mark -> {after[0]} KiB at the end")
print(f"  open files: {before[1]} -> {after[1]}")

if stats is None:
    print("FAIL: the gateway stopped answering its control API")
    sys.exit(1)

# Absolute growth, not a multiple. The first version allowed doubling, which
# sounds generous and is: with the UDP flow bound removed the gateway went from
# 7081 descriptors to 13908 and from 47 to 84 MiB over the second half, and
# doubling let all of it through. A rule loose enough to admit the failure it
# exists for is not a loose rule, it is not a rule.
#
# A settled gateway barely moves -- 523 to 523 descriptors and 32 KiB of memory
# in the run this was written against -- so these are still hundreds of times
# what normal looks like, and a leaking one crosses them by thousands.
if after[1] > before[1] + 256:
    print(f"FAIL: open descriptors went from {before[1]} to {after[1]} over the second",
          "half, so something is not being given back")
    sys.exit(1)
if after[0] > before[0] + 32768:
    print(f"FAIL: resident memory went from {before[0]} to {after[0]} KiB over the",
          "second half, which is growth rather than a working set")
    sys.exit(1)

# And it is still doing its job, not merely alive.
s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
s.bind(client_path)
s.connect(wire)
s.settimeout(10)
s.send(arp())
answered = False
while not answered:
    try:
        frame = s.recv(2048)
    except socket.timeout:
        break
    answered = len(frame) >= 42 and frame[12:14] == b"\x08\x06" and frame[20:22] == b"\x00\x02"
s.close()
os.unlink(client_path)
if not answered:
    print("FAIL: the gateway is running and no longer answers ARP")
    sys.exit(1)

print(f"ok: soak  {sent} frames, still answering, memory and descriptors settled")
PY
outcome=$?
kill "$GATEWAY" 2>/dev/null
wait "$GATEWAY" 2>/dev/null
GATEWAY=""
[[ $outcome -eq 0 ]] || exit $outcome

# The second half: guests that come and go, on the wire that carries several.
#
# The first soak keeps one guest talking. What it cannot see is the port
# lifecycle -- a switch adds a port per guest, learns addresses on it, and has to
# give all of that back when the guest leaves. Every one of those steps was
# written or changed today, and a port that is added and never removed is a leak
# that only appears if somebody leaves.
WIRE="${TMPDIR:-/tmp}/netstack-soak-switch-$$.sock"
CONTROL="${TMPDIR:-/tmp}/netstack-soak-switch-ctl-$$.sock"
rm -f "$WIRE" "$CONTROL"
"$binary" --listen-switch "$WIRE" --listen "unix://$CONTROL" >/dev/null 2>&1 &
GATEWAY=$!
for _ in $(seq 1 120); do
    [[ -S "$WIRE" && -S "$CONTROL" ]] && break
    sleep 0.25
done
[[ -S "$WIRE" && -S "$CONTROL" ]] || { echo "FAIL: the switch gateway never came up"; exit 1; }

echo "churning guests for ${SECONDS_TO_RUN}s"
WIRE="$WIRE" CONTROL="$CONTROL" GATEWAY="$GATEWAY" SECONDS_TO_RUN="$SECONDS_TO_RUN" python3 - <<'PY2'
import json, os, socket, struct, subprocess, sys, time

sys.path.insert(0, os.environ["SMOKE_SUPPORT"])
from wire import address

wire = os.environ["WIRE"]
pid = os.environ["GATEWAY"]
gateway = address("192.168.127.1")
run_for = float(os.environ["SECONDS_TO_RUN"])


def resources():
    rss = subprocess.run(["ps", "-o", "rss=", "-p", pid], capture_output=True, text=True)
    files = subprocess.run(["lsof", "-p", pid], capture_output=True, text=True)
    return (int(rss.stdout.strip() or 0), len(files.stdout.strip().split("\n")))


def cam():
    answer = subprocess.run(
        ["curl", "--silent", "--fail-with-body", "--max-time", "10",
         "--unix-socket", os.environ["CONTROL"], "http://gateway/cam"],
        capture_output=True, text=True, timeout=20)
    return json.loads(answer.stdout) if answer.returncode == 0 else None


def visit(index):
    """One guest: connect, speak, leave, and say whether it was answered.

    The answer matters more than the visit. An earlier version swallowed every
    error, ran five hundred thousand "guests" in twenty seconds -- twenty-seven
    thousand a second, which is not a connection rate -- and settled beautifully
    while exercising nothing. A soak that measures its own failures to connect
    measures nothing at all.
    """
    mac = bytes.fromhex("5a94efe4%04x" % (index % 65536))
    guest = address("192.168.127.%d" % (2 + index % 200))
    frame = (b"\xff" * 6 + mac + b"\x08\x06" + b"\x00\x01\x08\x00\x06\x04\x00\x01"
             + mac + guest + b"\x00" * 6 + gateway)
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(5)
    try:
        s.connect(wire)
        s.sendall(struct.pack(">I", len(frame)) + frame)
        held = b""
        while len(held) < 4:
            chunk = s.recv(4096)
            if not chunk:
                return False
            held += chunk
        length = struct.unpack(">I", held[:4])[0]
        while len(held) < 4 + length:
            chunk = s.recv(4096)
            if not chunk:
                return False
            held += chunk
        reply = held[4:4 + length]
        return len(reply) >= 42 and reply[12:14] == b"\x08\x06" and reply[20:22] == b"\x00\x02"
    except OSError:
        return False
    finally:
        s.close()


started = time.time()
visits = 0
answered = 0
midpoint = None
while time.time() - started < run_for:
    if visit(visits):
        answered += 1
    visits += 1
    if midpoint is None and time.time() - started >= run_for / 2:
        # Let the departures settle before measuring: a guest that has just gone
        # is still going.
        time.sleep(0.5)
        midpoint = resources()

time.sleep(1.0)
after = resources()
table = cam()

print(f"  {visits} guests came and went over {run_for:.0f}s, {answered} of them answered")
print(f"  resident: {midpoint[0]} KiB at the halfway mark -> {after[0]} KiB at the end")
print(f"  open files: {midpoint[1]} -> {after[1]}")
if table is not None:
    print(f"  addresses the switch still remembers: {len(table)}")

if table is None:
    print("FAIL: the switch stopped answering its control API")
    sys.exit(1)
# The floor that stops this measuring nothing. A guest that never connected
# leaks nothing, so a run of failures would settle perfectly.
if answered < visits // 2 or answered < 100:
    print(f"FAIL: only {answered} of {visits} guests were answered, so this measured",
          "failures to connect rather than a switch under churn")
    sys.exit(1)
if after[1] > midpoint[1] + 256:
    print(f"FAIL: open descriptors went from {midpoint[1]} to {after[1]} while guests",
          "were leaving, so a port is not being given back")
    sys.exit(1)
if after[0] > midpoint[0] + 32768:
    print(f"FAIL: resident memory went from {midpoint[0]} to {after[0]} KiB")
    sys.exit(1)
# Every guest has gone. The table is keyed by address and the addresses repeat,
# so this is not a count of visits -- but a switch that never forgot anything
# would hold one entry per address it ever saw.
if len(table) > 200:
    print(f"FAIL: the switch still remembers {len(table)} addresses after every guest left")
    sys.exit(1)
print(f"ok: churn {visits} guests came and went, and the switch gave their ports back")
PY2
outcome=$?
kill "$GATEWAY" 2>/dev/null
wait "$GATEWAY" 2>/dev/null
GATEWAY=""
exit $outcome
