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
LISTENER=""
ECHO_PID=""
cleanup() {
    [[ -n "$GATEWAY" ]] && kill "$GATEWAY" 2>/dev/null
    [[ -n "$ECHO_PID" ]] && kill "$ECHO_PID" 2>/dev/null
    rm -f "$WIRE" "$CONFIG" "$LISTENER" "${LISTENER:-/nonexistent}.port"
}
trap cleanup EXIT INT TERM

echo "building the gateway"
swift build -c release --product netstack-gateway >/dev/null || exit 1
binary="$(swift build -c release --show-bin-path)/netstack-gateway"

# One run: start the gateway with the given arguments, then ask it the two
# questions a guest asks first -- who owns the gateway address, and what address
# may I use -- and require both answers to match what it was configured with.
smoke() {
    local expected="$1" guest="$2" expected_host="$3"
    shift 3
    WIRE="${TMPDIR:-/tmp}/netstack-smoke-$$.sock"
    rm -f "$WIRE"
    "$binary" --listen-vfkit "$WIRE" "$@" >/dev/null 2>&1 &
    GATEWAY=$!

    for _ in $(seq 1 120); do
        [[ -S "$WIRE" ]] && break
        sleep 0.25
    done
    [[ -S "$WIRE" ]] || { echo "FAIL: wire socket never appeared ($*)"; return 1; }

    EXPECTED="$expected" GUEST="$guest" EXPECTED_HOST="$expected_host" \
        WIRE="$WIRE" ARGS="$*" python3 - <<'PY'
import os, socket, sys

wire = os.environ["WIRE"]
expected = bytes(int(part) for part in os.environ["EXPECTED"].split("."))
expected_host = bytes(int(part) for part in os.environ["EXPECTED_HOST"].split("."))
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
    print("ok: ARP  ", ".".join(map(str, expected)), "answered for", described)

    # And a lease. The bug this file exists for produced a gateway that answered
    # its control socket while serving a subnet nobody asked for, so the address
    # it hands a guest has to be checked against the one it was configured with
    # -- not merely that it handed out something.
    transaction = b"\x5a\x5a\x00\x01"
    discover = (
        b"\x01\x01\x06\x00" + transaction + b"\x00\x00\x80\x00"
        + b"\x00" * 16 + src + b"\x00" * 10 + b"\x00" * 192
        + b"\x63\x82\x53\x63" + b"\x35\x01\x01" + b"\xff"
    )
    udp = (
        (68).to_bytes(2, "big") + (67).to_bytes(2, "big")
        + (8 + len(discover)).to_bytes(2, "big") + b"\x00\x00" + discover
    )
    total = 20 + len(udp)
    header = bytearray(
        b"\x45\x00" + total.to_bytes(2, "big") + b"\x00\x00\x00\x00\x40\x11\x00\x00"
        + b"\x00\x00\x00\x00" + b"\xff\xff\xff\xff"
    )
    checksum = 0
    for i in range(0, 20, 2):
        checksum += (header[i] << 8) | header[i + 1]
    checksum = (checksum >> 16) + (checksum & 0xFFFF)
    checksum = (~((checksum >> 16) + (checksum & 0xFFFF))) & 0xFFFF
    header[10:12] = checksum.to_bytes(2, "big")
    s.send(b"\xff" * 6 + src + b"\x08\x00" + bytes(header) + udp)

    s.settimeout(5)
    leased = None
    while leased is None:
        try:
            reply = s.recv(2048)
        except socket.timeout:
            print("FAIL: no DHCP offer within 5s for", described)
            sys.exit(1)
        # ethernet + IPv4 + UDP, from the DHCP server port
        if len(reply) < 42 or reply[12:14] != b"\x08\x00" or reply[23] != 17:
            continue
        if int.from_bytes(reply[34:36], "big") != 67:
            continue
        payload = reply[42:]
        if len(payload) < 240 or payload[4:8] != transaction:
            continue
        leased = payload[16:20]

    if leased[:3] != expected[:3]:
        print("FAIL: leased", ".".join(map(str, leased)),
              "which is not on the subnet of", ".".join(map(str, expected)),
              "for", described)
        sys.exit(1)
    print("ok: lease ", ".".join(map(str, leased)), "offered for", described)

    # And the names. `gateway.containers.internal` says the resolver is bound and
    # knows which address it is on -- the thing that was wrong when this file was
    # written. `host.containers.internal` is the headline feature, "reach the
    # machine you are running on", and it is derived from the subnet rather than
    # configured, so it is the one that silently pointed off-subnet: a gateway on
    # 10.7.0.0/24 answered 192.168.127.254, an address the guest cannot route to,
    # while every other check here stayed green.
    def udp_frame(source, destination, sport, dport, payload):
        udp = (
            sport.to_bytes(2, "big") + dport.to_bytes(2, "big")
            + (8 + len(payload)).to_bytes(2, "big") + b"\x00\x00" + payload
        )
        total = 20 + len(udp)
        header = bytearray(
            b"\x45\x00" + total.to_bytes(2, "big") + b"\x00\x00\x00\x00\x40\x11\x00\x00"
            + source + destination
        )
        checksum = 0
        for i in range(0, 20, 2):
            checksum += (header[i] << 8) | header[i + 1]
        checksum = (checksum >> 16) + (checksum & 0xFFFF)
        checksum = (~((checksum >> 16) + (checksum & 0xFFFF))) & 0xFFFF
        header[10:12] = checksum.to_bytes(2, "big")
        return b"\x5a\x94\xef\xe4\x0c\xee" + src + b"\x08\x00" + bytes(header) + udp

    def resolve(labels, transaction, sport):
        name = b"".join(bytes([len(part)]) + part for part in labels) + b"\x00"
        query = (
            transaction + b"\x01\x00" + b"\x00\x01" + b"\x00" * 6
            + name + b"\x00\x01\x00\x01"
        )
        s.send(udp_frame(leased, expected, sport, 53, query))
        s.settimeout(5)
        printable = ".".join(part.decode() for part in labels)
        while True:
            try:
                reply = s.recv(2048)
            except socket.timeout:
                print("FAIL: no DNS answer for", printable, "within 5s for", described)
                sys.exit(1)
            if len(reply) < 54 or reply[12:14] != b"\x08\x00" or reply[23] != 17:
                continue
            if int.from_bytes(reply[34:36], "big") != 53:
                continue
            if int.from_bytes(reply[36:38], "big") != sport:
                continue
            body = reply[42:]
            if len(body) < 12 or body[0:2] != transaction:
                continue
            if int.from_bytes(body[6:8], "big") < 1:
                print("FAIL: the resolver answered with no records for", printable,
                      "for", described)
                sys.exit(1)
            return body[-4:]

    for labels, wanted, sport in (
        ([b"gateway", b"containers", b"internal"], expected, 40000),
        ([b"host", b"containers", b"internal"], expected_host, 40001),
    ):
        printable = ".".join(part.decode() for part in labels)
        resolved = resolve(labels, sport.to_bytes(2, "big"), sport)
        if resolved != wanted:
            print("FAIL:", printable, "resolved to", ".".join(map(str, resolved)),
                  "rather than", ".".join(map(str, wanted)), "for", described)
            sys.exit(1)
        print("ok: name ", printable, "->", ".".join(map(str, resolved)),
              "for", described)
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

# A TCP connection, opened by the guest, to a real listener on the host.
#
# Everything above is one datagram and an answer. This is the path the gateway
# exists for and the one with the most between the two ends: the guest ARPs for
# the host address, the forwarder accepts a SYN for an address that is not on
# any interface, NAT rewrites it to 127.0.0.1 -- because the host's services are
# on its loopback, not on anything the guest could route to -- a real socket is
# dialled, and the bytes come back. None of it is exercised by the control API,
# which is what the rest of the executable-level checking looks at.
tcp_smoke() {
    local expected="$1" guest="$2" expected_host="$3"
    shift 3
    LISTENER="${TMPDIR:-/tmp}/netstack-smoke-echo-$$.py"
    cat > "$LISTENER" <<'ECHO'
import socket, sys
server = socket.socket()
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("127.0.0.1", 0))
server.listen(1)
print(server.getsockname()[1], flush=True)
connection, _ = server.accept()
while True:
    chunk = connection.recv(4096)
    if not chunk:
        break
    connection.sendall(chunk)
connection.close()
ECHO
    python3 "$LISTENER" > "$LISTENER.port" &
    ECHO_PID=$!
    local port=""
    for _ in $(seq 1 80); do
        port="$(head -1 "$LISTENER.port" 2>/dev/null)"
        [[ -n "$port" ]] && break
        sleep 0.25
    done
    [[ -n "$port" ]] || { echo "FAIL: the echo listener never reported a port"; return 1; }

    WIRE="${TMPDIR:-/tmp}/netstack-smoke-$$.sock"
    rm -f "$WIRE"
    "$binary" --listen-vfkit "$WIRE" "$@" >/dev/null 2>&1 &
    GATEWAY=$!
    for _ in $(seq 1 120); do
        [[ -S "$WIRE" ]] && break
        sleep 0.25
    done
    [[ -S "$WIRE" ]] || { echo "FAIL: wire socket never appeared (tcp)"; return 1; }

    EXPECTED="$expected" GUEST="$guest" EXPECTED_HOST="$expected_host" \
        WIRE="$WIRE" PORT="$port" ARGS="$*" python3 - <<'PY'
import os, socket, sys

wire = os.environ["WIRE"]
gateway = bytes(int(part) for part in os.environ["EXPECTED"].split("."))
guest = bytes(int(part) for part in os.environ["GUEST"].split("."))
host = bytes(int(part) for part in os.environ["EXPECTED_HOST"].split("."))
port = int(os.environ["PORT"])
described = os.environ.get("ARGS") or "(defaults)"

client_path = wire + ".client"
s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
s.bind(client_path)
GUEST_MAC = bytes.fromhex("5a94efe4bc00")
GATEWAY_MAC = bytes.fromhex("5a94efe40cee")


def ones_complement(data):
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    while total >> 16:
        total = (total >> 16) + (total & 0xFFFF)
    return (~total) & 0xFFFF


def tcp_frame(source, destination, sport, dport, seq, ack, flags, payload=b""):
    offset = 5 << 4
    header = (
        sport.to_bytes(2, "big") + dport.to_bytes(2, "big")
        + seq.to_bytes(4, "big") + ack.to_bytes(4, "big")
        + bytes([offset, flags]) + (65535).to_bytes(2, "big")
        + b"\x00\x00" + b"\x00\x00"
    )
    segment = header + payload
    pseudo = source + destination + b"\x00\x06" + len(segment).to_bytes(2, "big")
    checksum = ones_complement(pseudo + segment)
    segment = segment[:16] + checksum.to_bytes(2, "big") + segment[18:]

    total = 20 + len(segment)
    ip = bytearray(
        b"\x45\x00" + total.to_bytes(2, "big") + b"\x00\x00\x40\x00\x40\x06\x00\x00"
        + source + destination
    )
    ip[10:12] = ones_complement(bytes(ip)).to_bytes(2, "big")
    return GATEWAY_MAC + GUEST_MAC + b"\x08\x00" + bytes(ip) + segment


def receive(sport, dport, timeout=10):
    """The next TCP segment of this connection, as (flags, seq, ack, payload)."""
    s.settimeout(timeout)
    while True:
        try:
            frame = s.recv(4096)
        except socket.timeout:
            return None
        if len(frame) < 54 or frame[12:14] != b"\x08\x00":
            continue
        ip = frame[14:]
        length = (ip[0] & 0x0F) * 4
        if ip[9] != 6 or ip[12:16] != host or ip[16:20] != guest:
            continue
        segment = ip[length:int.from_bytes(ip[2:4], "big")]
        if int.from_bytes(segment[0:2], "big") != dport:
            continue
        if int.from_bytes(segment[2:4], "big") != sport:
            continue
        data_offset = (segment[12] >> 4) * 4
        return segment[13], int.from_bytes(segment[4:8], "big"), \
            int.from_bytes(segment[8:12], "big"), segment[data_offset:]


SYN, ACK, PSH, FIN, RST = 0x02, 0x10, 0x08, 0x01, 0x04
sport = 40100
seq = 1000

try:
    s.connect(wire)
    s.send(tcp_frame(guest, host, sport, port, seq, 0, SYN))
    answer = receive(sport, port)
    if answer is None:
        print("FAIL: no answer to the SYN within 10s for", described)
        sys.exit(1)
    flags, their_seq, their_ack, _ = answer
    if flags & RST:
        print("FAIL: the gateway reset the connection rather than dialling for", described)
        sys.exit(1)
    if flags & (SYN | ACK) != (SYN | ACK):
        print("FAIL: expected SYN-ACK, got flags", hex(flags), "for", described)
        sys.exit(1)
    if their_ack != seq + 1:
        print("FAIL: the SYN-ACK acknowledged", their_ack, "rather than", seq + 1,
              "for", described)
        sys.exit(1)
    print("ok: TCP   SYN-ACK from", ".".join(map(str, host)) + ":" + str(port),
          "for", described)

    seq += 1
    s.send(tcp_frame(guest, host, sport, port, seq, their_seq + 1, ACK))

    # The listener echoes. Getting the bytes back means the gateway dialled a
    # real socket on the loopback and spliced both directions, not merely that
    # it answered a handshake in userspace.
    body = b"the guest reached the host"
    s.send(tcp_frame(guest, host, sport, port, seq, their_seq + 1, PSH | ACK, body))

    echoed = b""
    theirs = their_seq + 1
    while len(echoed) < len(body):
        answer = receive(sport, port)
        if answer is None:
            print("FAIL: the echo did not come back within 10s for", described)
            sys.exit(1)
        flags, segment_seq, _, payload = answer
        if flags & RST:
            print("FAIL: reset while waiting for the echo for", described)
            sys.exit(1)
        if payload and segment_seq == theirs:
            echoed += payload
            theirs += len(payload)
            s.send(tcp_frame(guest, host, sport, port,
                             seq + len(body), theirs, ACK))

    if echoed != body:
        print("FAIL: the host echoed", echoed, "rather than", body, "for", described)
        sys.exit(1)
    print("ok: TCP  ", len(echoed), "bytes echoed by a real host listener for", described)
finally:
    s.close()
    os.unlink(client_path)
PY
    local outcome=$?
    kill "$GATEWAY" 2>/dev/null
    wait "$GATEWAY" 2>/dev/null
    GATEWAY=""
    kill "$ECHO_PID" 2>/dev/null
    wait "$ECHO_PID" 2>/dev/null
    ECHO_PID=""
    rm -f "$WIRE" "$LISTENER" "$LISTENER.port"
    return $outcome
}

status=0

# The defaults.
smoke 192.168.127.1 192.168.127.2 192.168.127.254 || status=1

# An address given as a flag. The gateway must answer for what it was told, not
# for what it would have defaulted to.
smoke 10.7.0.1 10.7.0.2 10.7.0.254 --gatewayIP 10.7.0.1 --subnet 10.7.0.0/24 \
    --hostIP 10.7.0.254 || status=1

# A subnet and nothing else. Upstream documents --gatewayIP as "first usable
# address of subnet" and --hostIP as "last usable"; both are derived here, so
# this is the case where a hardcoded default shows up as an address the guest
# cannot reach. A /25 is deliberate: its broadcast is not .255, so a derivation
# that only knows how to subtract from 255 gets the host address wrong.
smoke 10.9.0.1 10.9.0.2 10.9.0.126 --subnet 10.9.0.0/25 || status=1

# The same, from a configuration file. This is the path that broke: the address
# resolution read the file's contents before the file was loaded, so every
# configured value was silently the default -- or worse, zero.
CONFIG="${TMPDIR:-/tmp}/netstack-smoke-$$.json"
cat > "$CONFIG" <<JSON
{"gatewayIP":"10.8.0.1","subnet":"10.8.0.0/24","hostIP":"10.8.0.254"}
JSON
smoke 10.8.0.1 10.8.0.2 10.8.0.254 --config "$CONFIG" || status=1

# The whole path, once, on the defaults: guest -> host address -> NAT ->
# 127.0.0.1 -> a real listener, and the bytes back.
tcp_smoke 192.168.127.1 192.168.127.2 192.168.127.254 || status=1

exit $status
