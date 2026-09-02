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
CONTROL=""
RESOLVER=""
CAPTURE=""
NOTIFY=""
GATEWAY=""
LISTENER=""
ECHO_PID=""
cleanup() {
    [[ -n "$GATEWAY" ]] && kill "$GATEWAY" 2>/dev/null
    [[ -n "$ECHO_PID" ]] && kill "$ECHO_PID" 2>/dev/null
    rm -f "$WIRE" "$CONFIG" "$CONTROL" "$LISTENER" "$RESOLVER" "$CAPTURE" "$NOTIFY" "${LISTENER:-/nonexistent}.port"
}
trap cleanup EXIT INT TERM

# Where the shared helpers live. Exported once; every case inherits it.
export SMOKE_SUPPORT="$PWD/scripts/smoke"

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
sys.path.insert(0, os.environ["SMOKE_SUPPORT"])
from wire import address, ones_complement, printable

wire = os.environ["WIRE"]
expected = address(os.environ["EXPECTED"])
expected_host = address(os.environ["EXPECTED_HOST"])
guest = address(os.environ["GUEST"])
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
        print("FAIL: the reply claims", printable(reply[28:32]),
              "rather than", printable(expected), "for", described)
        sys.exit(1)
    print("ok: ARP  ", printable(expected), "answered for", described)

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
        print("FAIL: leased", printable(leased),
              "which is not on the subnet of", printable(expected),
              "for", described)
        sys.exit(1)
    print("ok: lease ", printable(leased), "offered for", described)

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
        asked = ".".join(part.decode() for part in labels)
        while True:
            try:
                reply = s.recv(2048)
            except socket.timeout:
                print("FAIL: no DNS answer for", asked, "within 5s for", described)
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
                print("FAIL: the resolver answered with no records for", asked,
                      "for", described)
                sys.exit(1)
            return body[-4:]

    for labels, wanted, sport in (
        ([b"gateway", b"containers", b"internal"], expected, 40000),
        ([b"host", b"containers", b"internal"], expected_host, 40001),
    ):
        asked = ".".join(part.decode() for part in labels)
        resolved = resolve(labels, sport.to_bytes(2, "big"), sport)
        if resolved != wanted:
            print("FAIL:", asked, "resolved to", printable(resolved),
                  "rather than", printable(wanted), "for", described)
            sys.exit(1)
        print("ok: name ", asked, "->", printable(resolved),
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
sys.path.insert(0, os.environ["SMOKE_SUPPORT"])
from wire import address, ones_complement, printable

wire = os.environ["WIRE"]
gateway = address(os.environ["EXPECTED"])
guest = address(os.environ["GUEST"])
host = address(os.environ["EXPECTED_HOST"])
port = int(os.environ["PORT"])
described = os.environ.get("ARGS") or "(defaults)"

client_path = wire + ".client"
s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
s.bind(client_path)
GUEST_MAC = bytes.fromhex("5a94efe4bc00")
GATEWAY_MAC = bytes.fromhex("5a94efe40cee")


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
    print("ok: TCP   SYN-ACK from", printable(host) + ":" + str(port),
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

# A host port forwarded into the guest.
#
# The other direction, and the other headline feature: something on the host
# connects to a port the gateway is holding for the guest, and the gateway opens
# the connection inside the network to deliver it. Nothing has ever pushed a
# byte through one. The interop driver calls Expose and checks that the list
# grew, which says the control API accepted the request and nothing at all about
# whether a forward forwards.
#
# The guest side of this is a listener, so the script has to act like one: answer
# the ARP the gateway sends looking for the guest, accept the SYN it dials, and
# echo. The host side is an ordinary socket, on an ordinary thread.
forward_smoke() {
    local expected="$1" guest="$2"
    # tcp publishes on a host port; unix publishes on a host socket path. The
    # guest side of this case does not care which -- the forward arrives as a
    # dial to the guest either way -- so the two share everything but the two
    # lines that differ, rather than the case being copied for the second one.
    FORWARD_KIND="${3:-tcp}"
    shift 2
    [[ $# -gt 0 ]] && shift
    CONTROL="${TMPDIR:-/tmp}/netstack-smoke-control-$$.sock"
    WIRE="${TMPDIR:-/tmp}/netstack-smoke-$$.sock"
    FORWARD_PATH="${TMPDIR:-/tmp}/netstack-smoke-fwd-$$.sock"
    rm -f "$FORWARD_PATH"
    rm -f "$WIRE" "$CONTROL"
    "$binary" --listen-vfkit "$WIRE" --listen "unix://$CONTROL" "$@" >/dev/null 2>&1 &
    GATEWAY=$!
    for _ in $(seq 1 120); do
        [[ -S "$WIRE" && -S "$CONTROL" ]] && break
        sleep 0.25
    done
    [[ -S "$WIRE" && -S "$CONTROL" ]] || {
        echo "FAIL: the wire or the control socket never appeared (forward)"
        return 1
    }

    EXPECTED="$expected" GUEST="$guest" WIRE="$WIRE" CONTROL="$CONTROL" ARGS="$*" \
        FORWARD_KIND="$FORWARD_KIND" FORWARD_PATH="$FORWARD_PATH" python3 - <<'PY'
import json, os, socket, subprocess, sys, threading
sys.path.insert(0, os.environ["SMOKE_SUPPORT"])
from wire import address, ones_complement, printable

wire = os.environ["WIRE"]
control = os.environ["CONTROL"]
gateway = address(os.environ["EXPECTED"])
guest = address(os.environ["GUEST"])
described = os.environ.get("ARGS") or "(defaults)"
guest_text = printable(guest)

GUEST_MAC = bytes.fromhex("5a94efe4bc00")
GATEWAY_MAC = bytes.fromhex("5a94efe40cee")
GUEST_PORT = 8080
SYN, ACK, PSH, FIN, RST = 0x02, 0x10, 0x08, 0x01, 0x04

client_path = wire + ".client"
s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
s.bind(client_path)


def tcp_frame(source, destination, sport, dport, seq, ack, flags, payload=b""):
    header = (
        sport.to_bytes(2, "big") + dport.to_bytes(2, "big")
        + seq.to_bytes(4, "big") + ack.to_bytes(4, "big")
        + bytes([5 << 4, flags]) + (65535).to_bytes(2, "big") + b"\x00\x00\x00\x00"
    )
    segment = header + payload
    pseudo = source + destination + b"\x00\x06" + len(segment).to_bytes(2, "big")
    segment = (segment[:16] + ones_complement(pseudo + segment).to_bytes(2, "big")
               + segment[18:])
    ip = bytearray(
        b"\x45\x00" + (20 + len(segment)).to_bytes(2, "big")
        + b"\x00\x00\x40\x00\x40\x06\x00\x00" + source + destination
    )
    ip[10:12] = ones_complement(bytes(ip)).to_bytes(2, "big")
    return GATEWAY_MAC + GUEST_MAC + b"\x08\x00" + bytes(ip) + segment


def arp_reply(target_mac, target_ip):
    return (
        target_mac + GUEST_MAC + b"\x08\x06"
        + b"\x00\x01\x08\x00\x06\x04\x00\x02"
        + GUEST_MAC + guest + target_mac + target_ip
    )


kind = os.environ.get("FORWARD_KIND", "tcp")
forward_path = os.environ.get("FORWARD_PATH", "")


def expose():
    """Ask for a host endpoint, delivered to the guest.

    For tcp that is a port bound to whatever is free; for unix it is a socket
    path. Upstream spells both through this one route, and this port had never
    driven the unix half of it -- the transport existed, bound its socket and
    listed itself, and nothing had ever asked it to carry a byte.
    """
    local = forward_path if kind == "unix" else "127.0.0.1:0"
    request = json.dumps({
        "local": local, "remote": f"{guest_text}:{GUEST_PORT}", "protocol": kind,
    })
    answer = subprocess.run(
        ["curl", "--silent", "--fail-with-body", "--unix-socket", control,
         "-X", "POST", "--data", request,
         "http://gateway/services/forwarder/expose"],
        capture_output=True, text=True, timeout=20,
    )
    if answer.returncode != 0:
        print("FAIL: expose was refused:", answer.stdout.strip() or answer.stderr.strip(),
              "for", described)
        sys.exit(1)
    body = json.loads(answer.stdout)
    if kind == "unix":
        return body["local"]
    return int(body["local"].rsplit(":", 1)[1])


body = b"the host reached the guest"
received = {}


def host_side(endpoint):
    """An ordinary client, on the host, that knows nothing about any of this."""
    try:
        if kind == "unix":
            connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            connection.settimeout(15)
            connection.connect(endpoint)
        else:
            connection = socket.create_connection(("127.0.0.1", endpoint), timeout=15)
        connection.settimeout(15)
        # Sent at once, before the guest-side handshake can possibly have
        # finished. That is what every HTTP client does, and it is what the
        # forwarder used to lose.
        connection.sendall(body)
        echoed = b""
        while len(echoed) < len(body):
            chunk = connection.recv(4096)
            if not chunk:
                break
            echoed += chunk
        received["echoed"] = echoed
        connection.close()
    except Exception as error:  # reported by the main thread, which owns the verdict
        received["error"] = error


try:
    s.connect(wire)

    # Announce the guest before asking for anything. The switch learns which port
    # an address is on from frames it receives, so until the guest has spoken it
    # is on no port at all and the gateway has nowhere to send the dial -- which
    # looks exactly like a forwarder that does not forward.
    s.send(
        b"\xff\xff\xff\xff\xff\xff" + GUEST_MAC + b"\x08\x06"
        + b"\x00\x01\x08\x00\x06\x04\x00\x01"
        + GUEST_MAC + guest + b"\x00" * 6 + gateway
    )

    port = expose()
    print(f"ok: fwd   expose accepted over {kind},", port, "->",
          f"{guest_text}:{GUEST_PORT}", "for", described)

    client = threading.Thread(target=host_side, args=(port,), daemon=True)
    client.start()

    # Act like a guest with something listening: answer the ARP, accept the SYN,
    # echo what arrives. The gateway chooses its own source address for the dial,
    # so it is read off the SYN rather than assumed.
    s.settimeout(20)
    peer = None
    their_port = None
    seq = 5000
    theirs = 0
    echoed_back = 0
    deadline_missed = "no SYN arrived from the gateway"
    while echoed_back < len(body):
        try:
            frame = s.recv(4096)
        except socket.timeout:
            print("FAIL:", deadline_missed, "for", described)
            sys.exit(1)
        if len(frame) < 42:
            continue

        if frame[12:14] == b"\x08\x06" and frame[38:42] == guest:
            # who-has <the guest> -- the gateway cannot dial until this is answered
            s.send(arp_reply(frame[22:28], frame[28:32]))
            continue

        if frame[12:14] != b"\x08\x00":
            continue
        ip = frame[14:int.from_bytes(frame[16:18], "big") + 14]
        if len(ip) < 20 or ip[9] != 6 or ip[16:20] != guest:
            continue
        segment = ip[(ip[0] & 0x0F) * 4:]
        if int.from_bytes(segment[2:4], "big") != GUEST_PORT:
            continue
        flags = segment[13]
        their_seq = int.from_bytes(segment[4:8], "big")
        payload = segment[(segment[12] >> 4) * 4:]

        if flags & SYN and not flags & ACK:
            peer, their_port = ip[12:16], int.from_bytes(segment[0:2], "big")
            theirs = their_seq + 1
            s.send(tcp_frame(guest, peer, GUEST_PORT, their_port, seq, theirs, SYN | ACK))
            seq += 1
            deadline_missed = "the handshake was answered but no data arrived"
            continue

        if peer is None:
            continue
        if flags & RST:
            print("FAIL: the gateway reset the forwarded connection for", described)
            sys.exit(1)
        if payload and their_seq == theirs:
            theirs += len(payload)
            s.send(tcp_frame(guest, peer, GUEST_PORT, their_port, seq, theirs,
                             PSH | ACK, payload))
            echoed_back += len(payload)
            deadline_missed = "the echo was sent but the host never saw it"

    client.join(20)
    if "error" in received:
        print("FAIL: the host side failed:", received["error"], "for", described)
        sys.exit(1)
    if received.get("echoed") != body:
        print("FAIL: the host read", received.get("echoed"), "rather than", body,
              "for", described)
        sys.exit(1)
    print("ok: fwd  ", len(body), "bytes round-tripped host -> guest -> host for", described)
finally:
    s.close()
    os.unlink(client_path)
PY
    local outcome=$?
    kill "$GATEWAY" 2>/dev/null
    wait "$GATEWAY" 2>/dev/null
    GATEWAY=""
    rm -f "$WIRE" "$CONTROL"
    return $outcome
}

# The other wire.
#
# `--listen-vfkit` is a datagram socket where one datagram is one frame;
# `--listen-qemu` is a stream where a four-byte big-endian length says where each
# frame ends. They are different code paths from the socket up, and a whole
# entry point that nobody drives is a whole entry point that can be wrong -- the
# `--config` ordering bug was exactly that, and every check in the repository
# stayed green through it.
stream_smoke() {
    local expected="$1" guest="$2"
    shift 2
    WIRE="${TMPDIR:-/tmp}/netstack-smoke-stream-$$.sock"
    rm -f "$WIRE"
    "$binary" --listen-qemu "$WIRE" "$@" >/dev/null 2>&1 &
    GATEWAY=$!
    for _ in $(seq 1 120); do
        [[ -S "$WIRE" ]] && break
        sleep 0.25
    done
    [[ -S "$WIRE" ]] || { echo "FAIL: the stream wire never appeared"; return 1; }

    EXPECTED="$expected" GUEST="$guest" WIRE="$WIRE" ARGS="$*" python3 - <<'PY'
import os, socket, struct, sys, time
sys.path.insert(0, os.environ["SMOKE_SUPPORT"])
from wire import address, ones_complement, printable

expected = address(os.environ["EXPECTED"])
guest = address(os.environ["GUEST"])
described = os.environ.get("ARGS") or "(defaults)"
src = bytes.fromhex("5a94efe4bc00")

s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(10)
try:
    s.connect(os.environ["WIRE"])
    frame = (
        b"\xff\xff\xff\xff\xff\xff" + src + b"\x08\x06"
        + b"\x00\x01\x08\x00\x06\x04\x00\x01"
        + src + guest + b"\x00" * 6 + expected
    )
    # Four bytes, big-endian, then the frame. Getting the endianness or the width
    # wrong gives a length that is not a length, and every byte after it is
    # garbage -- which is the failure this exists to notice.
    s.sendall(struct.pack(">I", len(frame)) + frame)

    held = b""

    def next_frame():
        global held
        while True:
            if len(held) >= 4:
                length = struct.unpack(">I", held[:4])[0]
                if length > 65536:
                    print("FAIL: the gateway framed a", length, "byte frame, which is not a",
                          "length -- the prefix is being read the wrong way round for", described)
                    sys.exit(1)
                if len(held) >= 4 + length:
                    body, held = held[4:4 + length], held[4 + length:]
                    return body
            try:
                chunk = s.recv(4096)
            except socket.timeout:
                return None
            if not chunk:
                return None
            held += chunk

    def await_reply(when):
        while True:
            reply = next_frame()
            if reply is None:
                print("FAIL: no ARP reply over the stream wire within 10s", when,
                      "for", described)
                sys.exit(1)
            if len(reply) < 42 or reply[12:14] != b"\x08\x06":
                continue
            if reply[20:22] != b"\x00\x02" or reply[28:32] != expected:
                continue
            return

    await_reply("on the first connection")
    print("ok: qemu  ARP", printable(expected),
          "answered over the length-prefixed wire for", described)

    # And again, on a new connection, the way a rebooted VM comes back. The wire
    # used to be taken once and never released: the second connection was
    # accepted and closed, so a guest could not reboot without the gateway being
    # restarted alongside it.
    #
    # Retried, because the release happens when the gateway notices the close and
    # a guest that reconnects instantly can beat it there. Bounded, because the
    # bug being guarded against never releases at all: no number of attempts
    # helps it.
    s.close()
    reconnected = False
    for _ in range(20):
        held = b""
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(2)
        try:
            s.connect(os.environ["WIRE"])
            s.sendall(struct.pack(">I", len(frame)) + frame)
            if next_frame() is not None:
                reconnected = True
                break
        except OSError:
            pass
        s.close()
        time.sleep(0.25)
    if not reconnected:
        print("FAIL: the wire was never given to the returning guest, after 20 attempts",
              "over five seconds, for", described)
        sys.exit(1)
    print("ok: qemu  the wire was taken over again by a returning guest for", described)
finally:
    s.close()
PY
    local outcome=$?
    kill "$GATEWAY" 2>/dev/null
    wait "$GATEWAY" 2>/dev/null
    GATEWAY=""
    rm -f "$WIRE"
    return $outcome
}

# A name the gateway does not own.
#
# The DNS checks above ask for the two `.containers.internal` names, which the
# gateway answers from its own table without ever opening a socket. Every other
# name a guest asks for -- which is every name a guest actually asks for -- is
# forwarded to an upstream resolver over a real UDP socket and the answer
# carried back. That path is the resolver's whole job and nothing outside the
# library had driven it.
#
# The upstream here is a fake on the loopback rather than whatever the machine's
# resolver is: a check that needs the internet is a check that fails for reasons
# of its own.
dns_forward_smoke() {
    local expected="$1" guest="$2"
    shift 2
    RESOLVER="${TMPDIR:-/tmp}/netstack-smoke-resolver-$$.py"
    cat > "$RESOLVER" <<'FAKE'
import socket, sys
# Answers every A query with the same address, so the check is about carriage
# rather than about what any real resolver happens to say today.
ANSWER = bytes([203, 0, 113, 7])
server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server.bind(("127.0.0.1", 0))
print(server.getsockname()[1], flush=True)
while True:
    query, sender = server.recvfrom(2048)
    if len(query) < 12:
        continue
    end = 12
    while end < len(query) and query[end]:
        end += query[end] + 1
    name = query[12:end + 1]
    reply = (
        query[0:2] + b"\x81\x80" + b"\x00\x01\x00\x01" + b"\x00\x00\x00\x00"
        + name + b"\x00\x01\x00\x01"
        + b"\xc0\x0c" + b"\x00\x01\x00\x01" + b"\x00\x00\x00\x3c"
        + b"\x00\x04" + ANSWER
    )
    server.sendto(reply, sender)
FAKE
    python3 "$RESOLVER" > "$RESOLVER.port" &
    ECHO_PID=$!
    local port=""
    for _ in $(seq 1 80); do
        port="$(head -1 "$RESOLVER.port" 2>/dev/null)"
        [[ -n "$port" ]] && break
        sleep 0.25
    done
    [[ -n "$port" ]] || { echo "FAIL: the fake resolver never reported a port"; return 1; }

    WIRE="${TMPDIR:-/tmp}/netstack-smoke-dns-$$.sock"
    rm -f "$WIRE"
    "$binary" --listen-vfkit "$WIRE" --dns "127.0.0.1:$port" "$@" >/dev/null 2>&1 &
    GATEWAY=$!
    for _ in $(seq 1 120); do
        [[ -S "$WIRE" ]] && break
        sleep 0.25
    done
    [[ -S "$WIRE" ]] || { echo "FAIL: wire socket never appeared (dns)"; return 1; }

    EXPECTED="$expected" GUEST="$guest" WIRE="$WIRE" ARGS="$*" python3 - <<'PY'
import os, socket, sys
sys.path.insert(0, os.environ["SMOKE_SUPPORT"])
from wire import address, ones_complement, printable

wire = os.environ["WIRE"]
gateway = address(os.environ["EXPECTED"])
guest = address(os.environ["GUEST"])
described = os.environ.get("ARGS") or "(defaults)"
src = bytes.fromhex("5a94efe4bc00")

client_path = wire + ".client"
s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
s.bind(client_path)


def udp_frame(source, destination, sport, dport, payload):
    udp = (
        sport.to_bytes(2, "big") + dport.to_bytes(2, "big")
        + (8 + len(payload)).to_bytes(2, "big") + b"\x00\x00" + payload
    )
    ip = bytearray(
        b"\x45\x00" + (20 + len(udp)).to_bytes(2, "big")
        + b"\x00\x00\x00\x00\x40\x11\x00\x00" + source + destination
    )
    ip[10:12] = ones_complement(bytes(ip)).to_bytes(2, "big")
    return bytes.fromhex("5a94efe40cee") + src + b"\x08\x00" + bytes(ip) + udp


try:
    s.connect(wire)
    labels = [b"a-name-the-gateway-does-not-own", b"example"]
    name = b"".join(bytes([len(part)]) + part for part in labels) + b"\x00"
    query = b"\x7a\x1c" + b"\x01\x00" + b"\x00\x01" + b"\x00" * 6 + name + b"\x00\x01\x00\x01"
    s.send(udp_frame(guest, gateway, 40002, 53, query))

    s.settimeout(10)
    while True:
        try:
            reply = s.recv(2048)
        except socket.timeout:
            print("FAIL: the forwarded query went unanswered within 10s for", described)
            sys.exit(1)
        if len(reply) < 54 or reply[12:14] != b"\x08\x00" or reply[23] != 17:
            continue
        if int.from_bytes(reply[34:36], "big") != 53:
            continue
        body = reply[42:]
        if len(body) < 12 or body[0:2] != b"\x7a\x1c":
            continue
        if body[3] & 0x0F:
            print("FAIL: the gateway answered rcode", body[3] & 0x0F,
                  "rather than forwarding, for", described)
            sys.exit(1)
        if int.from_bytes(body[6:8], "big") < 1:
            print("FAIL: the forwarded answer carried no records for", described)
            sys.exit(1)
        resolved = body[-4:]
        if resolved != bytes([203, 0, 113, 7]):
            print("FAIL: the guest was told", printable(resolved),
                  "rather than what the upstream said, for", described)
            sys.exit(1)
        print("ok: dns   a forwarded name resolved to",
              printable(resolved), "for", described)
        break
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
    rm -f "$WIRE" "$RESOLVER" "$RESOLVER.port"
    return $outcome
}

# A UDP datagram the guest sends to the host.
#
# The TCP case above is a connection; this is the other transport, through a
# different forwarder, with no handshake to hide behind. The guest sends to the
# host address, NAT rewrites it to the loopback, a real socket carries it, and
# the reply has to find its way back to the flow it belongs to -- which is the
# part with somewhere to go wrong, since nothing in a datagram says which
# conversation it is part of.
udp_smoke() {
    local expected="$1" guest="$2" expected_host="$3"
    shift 3
    LISTENER="${TMPDIR:-/tmp}/netstack-smoke-udp-$$.py"
    cat > "$LISTENER" <<'ECHO'
import socket
server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server.bind(("127.0.0.1", 0))
print(server.getsockname()[1], flush=True)
while True:
    payload, sender = server.recvfrom(4096)
    server.sendto(payload[::-1], sender)
ECHO
    python3 "$LISTENER" > "$LISTENER.port" &
    ECHO_PID=$!
    local port=""
    for _ in $(seq 1 80); do
        port="$(head -1 "$LISTENER.port" 2>/dev/null)"
        [[ -n "$port" ]] && break
        sleep 0.25
    done
    [[ -n "$port" ]] || { echo "FAIL: the udp echo listener never reported a port"; return 1; }

    WIRE="${TMPDIR:-/tmp}/netstack-smoke-udp-$$.sock"
    rm -f "$WIRE"
    "$binary" --listen-vfkit "$WIRE" "$@" >/dev/null 2>&1 &
    GATEWAY=$!
    for _ in $(seq 1 120); do
        [[ -S "$WIRE" ]] && break
        sleep 0.25
    done
    [[ -S "$WIRE" ]] || { echo "FAIL: wire socket never appeared (udp)"; return 1; }

    EXPECTED="$expected" GUEST="$guest" EXPECTED_HOST="$expected_host" \
        WIRE="$WIRE" PORT="$port" ARGS="$*" python3 - <<'PY'
import os, socket, sys
sys.path.insert(0, os.environ["SMOKE_SUPPORT"])
from wire import address, ones_complement, printable

wire = os.environ["WIRE"]
guest = address(os.environ["GUEST"])
host = address(os.environ["EXPECTED_HOST"])
port = int(os.environ["PORT"])
described = os.environ.get("ARGS") or "(defaults)"
src = bytes.fromhex("5a94efe4bc00")

client_path = wire + ".client"
s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
s.bind(client_path)


def udp_frame(source, destination, sport, dport, payload):
    udp = (
        sport.to_bytes(2, "big") + dport.to_bytes(2, "big")
        + (8 + len(payload)).to_bytes(2, "big") + b"\x00\x00" + payload
    )
    ip = bytearray(
        b"\x45\x00" + (20 + len(udp)).to_bytes(2, "big")
        + b"\x00\x00\x00\x00\x40\x11\x00\x00" + source + destination
    )
    ip[10:12] = ones_complement(bytes(ip)).to_bytes(2, "big")
    return bytes.fromhex("5a94efe40cee") + src + b"\x08\x00" + bytes(ip) + udp


body = b"a datagram the guest sent"
sport = 40010
try:
    s.connect(wire)
    s.send(udp_frame(guest, host, sport, port, body))

    s.settimeout(10)
    while True:
        try:
            reply = s.recv(4096)
        except socket.timeout:
            print("FAIL: the datagram was not answered within 10s for", described)
            sys.exit(1)
        if len(reply) < 42 or reply[12:14] != b"\x08\x00" or reply[23] != 17:
            continue
        ip = reply[14:]
        # Back from the address it was sent to, to the port it was sent from.
        # Either being wrong means the flow was not carried, only the bytes.
        if ip[12:16] != host or ip[16:20] != guest:
            continue
        body_start = (ip[0] & 0x0F) * 4
        udp = ip[body_start:int.from_bytes(ip[2:4], "big")]
        if int.from_bytes(udp[0:2], "big") != port:
            continue
        if int.from_bytes(udp[2:4], "big") != sport:
            print("FAIL: the reply came back to port", int.from_bytes(udp[2:4], "big"),
                  "rather than", sport, "for", described)
            sys.exit(1)
        echoed = udp[8:]
        if echoed != body[::-1]:
            print("FAIL: the host sent back", echoed, "rather than", body[::-1],
                  "for", described)
            sys.exit(1)
        print("ok: udp  ", len(echoed), "bytes there and back through a real socket for",
              described)
        break
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

# The capture file.
#
# `--pcap` is what an operator reaches for when the network is doing something
# they cannot explain, which means it is used exactly when nothing else is
# working and its own correctness is the last thing anyone wants to be debugging.
# A file format is also the easiest thing in this program to get subtly wrong and
# never notice: nothing in the gateway reads it back.
#
# So it is read back here, by a parser that knows only what libpcap's format
# says, and the frames the guest sent have to be in it.
pcap_smoke() {
    local expected="$1" guest="$2"
    shift 2
    CAPTURE="${TMPDIR:-/tmp}/netstack-smoke-$$.pcap"
    WIRE="${TMPDIR:-/tmp}/netstack-smoke-pcap-$$.sock"
    rm -f "$WIRE" "$CAPTURE"
    "$binary" --listen-vfkit "$WIRE" --pcap "$CAPTURE" "$@" >/dev/null 2>&1 &
    GATEWAY=$!
    for _ in $(seq 1 120); do
        [[ -S "$WIRE" ]] && break
        sleep 0.25
    done
    [[ -S "$WIRE" ]] || { echo "FAIL: wire socket never appeared (pcap)"; return 1; }

    EXPECTED="$expected" GUEST="$guest" WIRE="$WIRE" ARGS="$*" python3 - <<'PY'
import os, socket, sys
sys.path.insert(0, os.environ["SMOKE_SUPPORT"])
from wire import address, ones_complement, printable

expected = address(os.environ["EXPECTED"])
guest = address(os.environ["GUEST"])
src = bytes.fromhex("5a94efe4bc00")
wire = os.environ["WIRE"]
client_path = wire + ".client"
s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
s.bind(client_path)
try:
    s.connect(wire)
    s.send(
        b"\xff\xff\xff\xff\xff\xff" + src + b"\x08\x06"
        + b"\x00\x01\x08\x00\x06\x04\x00\x01"
        + src + guest + b"\x00" * 6 + expected
    )
    s.settimeout(10)
    try:
        s.recv(2048)
    except socket.timeout:
        print("FAIL: the gateway did not answer, so there is nothing to have captured")
        sys.exit(1)
finally:
    s.close()
    os.unlink(client_path)
PY
    local outcome=$?
    # Stopped before reading: the writer buffers, and a capture is only a capture
    # once it has been flushed and closed. Reading it while the gateway still
    # holds it would check something the operator never gets.
    kill "$GATEWAY" 2>/dev/null
    wait "$GATEWAY" 2>/dev/null
    GATEWAY=""
    rm -f "$WIRE"
    [[ $outcome -eq 0 ]] || { rm -f "$CAPTURE"; return 1; }

    CAPTURE="$CAPTURE" EXPECTED="$expected" GUEST="$guest" ARGS="$*" python3 - <<'PY'
import os, struct, sys
sys.path.insert(0, os.environ["SMOKE_SUPPORT"])
from wire import address, ones_complement, printable

described = os.environ.get("ARGS") or "(defaults)"
expected = address(os.environ["EXPECTED"])
guest = address(os.environ["GUEST"])
try:
    with open(os.environ["CAPTURE"], "rb") as handle:
        data = handle.read()
except OSError as error:
    print("FAIL: the capture file could not be read:", error, "for", described)
    sys.exit(1)

if len(data) < 24:
    print("FAIL: the capture is", len(data), "bytes, which is not even a header, for",
          described)
    sys.exit(1)

magic = struct.unpack("<I", data[:4])[0]
if magic != 0xA1B2C3D4:
    print("FAIL: the capture begins", hex(magic), "rather than a libpcap magic, for",
          described)
    sys.exit(1)
major, minor, _, _, snaplen, link = struct.unpack("<HHiIII", data[4:24])
if (major, minor) != (2, 4):
    print("FAIL: the capture says version", f"{major}.{minor}", "for", described)
    sys.exit(1)
if link != 1:
    print("FAIL: the capture says link type", link, "rather than 1 (ethernet), for",
          described)
    sys.exit(1)

# Walked record by record. A length that runs off the end is the failure a reader
# actually hits, and it is silent in a file that opens fine.
frames = []
at = 24
while at + 16 <= len(data):
    _, _, captured, original = struct.unpack("<IIII", data[at:at + 16])
    if captured > original or captured > snaplen:
        print("FAIL: a record claims", captured, "captured of", original,
              "original bytes, for", described)
        sys.exit(1)
    if at + 16 + captured > len(data):
        print("FAIL: the last record runs", at + 16 + captured - len(data),
              "bytes past the end of the file, for", described)
        sys.exit(1)
    frames.append(data[at + 16:at + 16 + captured])
    at += 16 + captured
if at != len(data):
    print("FAIL:", len(data) - at, "trailing bytes are not a record, for", described)
    sys.exit(1)
if not frames:
    print("FAIL: the capture has a valid header and no frames, for", described)
    sys.exit(1)

# The exchange that just happened, both halves: a capture that only recorded one
# direction would still parse.
asked = any(f[12:14] == b"\x08\x06" and f[20:22] == b"\x00\x01" and f[38:42] == expected
            for f in frames if len(f) >= 42)
answered = any(f[12:14] == b"\x08\x06" and f[20:22] == b"\x00\x02" and f[28:32] == expected
               for f in frames if len(f) >= 42)
if not asked:
    print("FAIL: the guest's ARP request is not in the capture, for", described)
    sys.exit(1)
if not answered:
    print("FAIL: the gateway's ARP reply is not in the capture -- only one direction",
          "was recorded, for", described)
    sys.exit(1)
print("ok: pcap ", len(frames), "frames, both directions of the exchange, for", described)
PY
    outcome=$?
    rm -f "$CAPTURE"
    return $outcome
}

# Several guests on one wire.
#
# `--listen-switch` is the shape gvisor-tap-vsock actually is: a network, not a
# point-to-point link. Every guest that connects gets its own port, the gateway
# leases each one its own address, and guests reach each other directly -- the
# gateway never sees that traffic, which is the part a check has to be careful
# about, because "the reply arrived" and "the first frame was the reply" are
# different claims. They are different here: a broadcast is flooded to every
# other port, so the first frame a guest reads is usually somebody else's.
switch_smoke() {
    local expected="$1"
    shift 1
    WIRE="${TMPDIR:-/tmp}/netstack-smoke-switch-$$.sock"
    rm -f "$WIRE"
    "$binary" --listen-switch "$WIRE" "$@" >/dev/null 2>&1 &
    GATEWAY=$!
    for _ in $(seq 1 120); do
        [[ -S "$WIRE" ]] && break
        sleep 0.25
    done
    [[ -S "$WIRE" ]] || { echo "FAIL: the switch wire never appeared"; return 1; }

    EXPECTED="$expected" WIRE="$WIRE" ARGS="$*" python3 - <<'PY'
import os, socket, struct, sys
sys.path.insert(0, os.environ["SMOKE_SUPPORT"])
from wire import address, ones_complement, printable

gateway = address(os.environ["EXPECTED"])
described = os.environ.get("ARGS") or "(defaults)"
wire = os.environ["WIRE"]

GUESTS = [
    (bytes.fromhex("5a94efe4bc01"), bytes([gateway[0], gateway[1], gateway[2], 2])),
    (bytes.fromhex("5a94efe4bc02"), bytes([gateway[0], gateway[1], gateway[2], 3])),
]


class Guest:
    def __init__(self, mac, address):
        self.mac, self.address = mac, address
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.socket.settimeout(10)
        self.socket.connect(wire)
        self.held = b""

    def send(self, frame):
        self.socket.sendall(struct.pack(">I", len(frame)) + frame)

    def frames(self, deadline=10):
        """Every frame, not just the first: a broadcast is flooded to every other
        port, so somebody else's traffic arrives interleaved with the answer."""
        self.socket.settimeout(deadline)
        while True:
            if len(self.held) >= 4:
                length = struct.unpack(">I", self.held[:4])[0]
                if len(self.held) >= 4 + length:
                    frame, self.held = self.held[4:4 + length], self.held[4 + length:]
                    yield frame
                    continue
            try:
                chunk = self.socket.recv(8192)
            except socket.timeout:
                return
            if not chunk:
                return
            self.held += chunk

    def request(self, target):
        self.send(
            b"\xff\xff\xff\xff\xff\xff" + self.mac + b"\x08\x06"
            + b"\x00\x01\x08\x00\x06\x04\x00\x01"
            + self.mac + self.address + b"\x00" * 6 + target
        )


def find(guest, predicate, what):
    for frame in guest.frames():
        if len(frame) >= 42 and predicate(frame):
            return frame
    print("FAIL:", what, "for", described)
    sys.exit(1)


guests = [Guest(mac, address) for mac, address in GUESTS]
try:
    # Each guest asks who owns the gateway, and each has to be answered on its
    # own port. Serving only the first is exactly what the single-guest wire
    # does, and it is what this is here to tell apart.
    for index, guest in enumerate(guests):
        guest.request(gateway)
    for index, guest in enumerate(guests):
        find(
            guest,
            lambda f: f[12:14] == b"\x08\x06" and f[20:22] == b"\x00\x02" and f[28:32] == gateway,
            f"guest {index + 1} was never told who owns {'.'.join(map(str, gateway))}")
    print("ok: switch", len(guests), "guests each answered on their own port for", described)

    # And one guest reaches another. The gateway is not involved: the switch
    # carries it, which is the whole difference between a network and a wire.
    guests[0].request(guests[1].address)
    find(
        guests[1],
        lambda f: (f[12:14] == b"\x08\x06" and f[20:22] == b"\x00\x01"
                   and f[28:32] == guests[0].address and f[38:42] == guests[1].address),
        "one guest's request never reached the other")
    print("ok: switch a guest reached another guest directly for", described)
finally:
    for guest in guests:
        guest.socket.close()
PY
    local outcome=$?
    kill "$GATEWAY" 2>/dev/null
    wait "$GATEWAY" 2>/dev/null
    GATEWAY=""
    rm -f "$WIRE"
    return $outcome
}

# A guest's ping, sent for real.
#
# Every reply here looks the same to the guest, which is the difficulty: the
# gateway answers echo requests for its own address itself, and it falls back to
# answering locally when it cannot open an unprivileged ICMP socket. So "a reply
# came back" is true whether the ping left this machine or not, and a check that
# asserted only that would pass with the forwarder removed entirely.
#
# The host address is the one that is genuinely forwarded -- NAT turns it into
# 127.0.0.1 *after* the loopback check, deliberately, so that
# `ping host.containers.internal` is a real ping. The gateway's own statistics
# say which happened, so the check asks for both: the reply, and the count.
icmp_smoke() {
    local expected="$1" guest="$2" expected_host="$3"
    shift 3
    CONTROL="${TMPDIR:-/tmp}/netstack-smoke-icmp-ctl-$$.sock"
    WIRE="${TMPDIR:-/tmp}/netstack-smoke-icmp-$$.sock"
    rm -f "$WIRE" "$CONTROL"
    "$binary" --listen-vfkit "$WIRE" --listen "unix://$CONTROL" "$@" >/dev/null 2>&1 &
    GATEWAY=$!
    for _ in $(seq 1 120); do
        [[ -S "$WIRE" && -S "$CONTROL" ]] && break
        sleep 0.25
    done
    [[ -S "$WIRE" && -S "$CONTROL" ]] || { echo "FAIL: the icmp gateway never came up"; return 1; }

    EXPECTED="$expected" GUEST="$guest" EXPECTED_HOST="$expected_host" \
        WIRE="$WIRE" CONTROL="$CONTROL" ARGS="$*" python3 - <<'PY'
import json, os, socket, struct, subprocess, sys
sys.path.insert(0, os.environ["SMOKE_SUPPORT"])
from wire import address, ones_complement, printable

wire = os.environ["WIRE"]
guest = address(os.environ["GUEST"])
host = address(os.environ["EXPECTED_HOST"])
described = os.environ.get("ARGS") or "(defaults)"
src = bytes.fromhex("5a94efe4bc00")


def echo_frame(destination, identifier, payload):
    icmp = bytearray(b"\x08\x00\x00\x00" + struct.pack(">HH", identifier, 1) + payload)
    icmp[2:4] = ones_complement(bytes(icmp)).to_bytes(2, "big")
    ip = bytearray(
        b"\x45\x00" + (20 + len(icmp)).to_bytes(2, "big")
        + b"\x00\x00\x00\x00\x40\x01\x00\x00" + guest + destination
    )
    ip[10:12] = ones_complement(bytes(ip)).to_bytes(2, "big")
    return bytes.fromhex("5a94efe40cee") + src + b"\x08\x00" + bytes(ip) + bytes(icmp)


def statistics():
    answer = subprocess.run(
        ["curl", "--silent", "--fail-with-body", "--max-time", "10",
         "--unix-socket", os.environ["CONTROL"], "http://gateway/stats"],
        capture_output=True, text=True, timeout=20,
    )
    if answer.returncode != 0:
        print("FAIL: /stats was not answered for", described)
        sys.exit(1)
    return json.loads(answer.stdout)


client_path = wire + ".client"
s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
s.bind(client_path)
identifier = 0x4321
body = b"a guests ping"
try:
    s.connect(wire)
    before = statistics().get("icmp_forwarded", 0)
    s.send(echo_frame(host, identifier, body))

    s.settimeout(10)
    while True:
        try:
            reply = s.recv(2048)
        except socket.timeout:
            print("FAIL: the ping went unanswered within 10s for", described)
            sys.exit(1)
        if len(reply) < 42 or reply[12:14] != b"\x08\x00" or reply[23] != 1:
            continue
        if reply[34] != 0:
            continue
        if struct.unpack(">H", reply[38:40])[0] != identifier:
            continue
        if reply[42:] != body:
            print("FAIL: the echo came back as", reply[42:], "rather than", body,
                  "for", described)
            sys.exit(1)
        break
    print("ok: icmp  the echo came back with its payload for", described)

    # And it was a real ping rather than this process answering for an address it
    # holds. Without this the check passes with the forwarder gone: declining
    # falls back to a local answer, which looks identical on the wire.
    after = statistics().get("icmp_forwarded", 0)
    if after <= before:
        print("FAIL: the gateway answered the ping itself --", "icmp_forwarded stayed at",
              after, "for", described)
        sys.exit(1)
    print("ok: icmp  the gateway forwarded it rather than answering for", described)
finally:
    s.close()
    os.unlink(client_path)
PY
    local outcome=$?
    kill "$GATEWAY" 2>/dev/null
    wait "$GATEWAY" 2>/dev/null
    GATEWAY=""
    rm -f "$WIRE" "$CONTROL"
    return $outcome
}

# A guest that arrives over the control API.
#
# `POST /connect` hands the connection to the switch and the connection stops
# being HTTP -- with no status line, no body, nothing: upstream hijacks and
# writes not a byte, so a client that waited for a response would wait forever.
# That silence is the contract, which makes it the kind of thing a check should
# pin: an implementation that helpfully answered "200 OK" would break every
# client by putting three bytes at the front of the first frame.
#
# The framing on this wire is hyperkit's two little-endian bytes, not qemu's
# four big-endian ones, because that is what upstream's clients speak here.
connect_smoke() {
    local expected="$1" guest="$2"
    shift 2
    CONTROL="${TMPDIR:-/tmp}/netstack-smoke-connect-ctl-$$.sock"
    WIRE="${TMPDIR:-/tmp}/netstack-smoke-connect-$$.sock"
    rm -f "$WIRE" "$CONTROL"
    "$binary" --listen-switch "$WIRE" --listen "unix://$CONTROL" "$@" >/dev/null 2>&1 &
    GATEWAY=$!
    for _ in $(seq 1 120); do
        [[ -S "$WIRE" && -S "$CONTROL" ]] && break
        sleep 0.25
    done
    [[ -S "$WIRE" && -S "$CONTROL" ]] || { echo "FAIL: the connect gateway never came up"; return 1; }

    EXPECTED="$expected" GUEST="$guest" CONTROL="$CONTROL" ARGS="$*" python3 - <<'PY'
import os, socket, struct, sys
sys.path.insert(0, os.environ["SMOKE_SUPPORT"])
from wire import address, ones_complement, printable

gateway = address(os.environ["EXPECTED"])
guest = address(os.environ["GUEST"])
described = os.environ.get("ARGS") or "(defaults)"
mac = bytes.fromhex("5a94efe4bc09")

s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(10)
try:
    s.connect(os.environ["CONTROL"])
    s.sendall(b"POST /connect HTTP/1.1\r\nHost: gateway\r\nContent-Length: 0\r\n\r\n")

    frame = (
        b"\xff\xff\xff\xff\xff\xff" + mac + b"\x08\x06"
        + b"\x00\x01\x08\x00\x06\x04\x00\x01"
        + mac + guest + b"\x00" * 6 + gateway
    )
    s.sendall(struct.pack("<H", len(frame)) + frame)

    held = b""
    while True:
        while len(held) >= 2:
            length = struct.unpack("<H", held[:2])[0]
            # Checked BEFORE waiting for the bytes, which is the whole point: an
            # HTTP status line arrives here as a "frame" whose first two bytes
            # ("HT") read as a length of 21576, and a reader that waits for that
            # many bytes before noticing waits forever -- which is exactly what a
            # real client would do. Written the other way round first, and it
            # hung instead of failing.
            if length > 1600:
                print("FAIL: /connect wrote something before the wire started --",
                      "the first two bytes say a frame of", length, "bytes, and the",
                      "connection is meant to go silent, for", described)
                sys.exit(1)
            if len(held) < 2 + length:
                break
            body, held = held[2:2 + length], held[2 + length:]
            if len(body) >= 42 and body[12:14] == b"\x08\x06" and body[20:22] == b"\x00\x02":
                if body[28:32] != gateway:
                    continue
                print("ok: conn  a guest joined over POST /connect and was answered for",
                      described)
                sys.exit(0)
        try:
            chunk = s.recv(4096)
        except socket.timeout:
            print("FAIL: no answer over /connect within 10s for", described)
            sys.exit(1)
        if not chunk:
            print("FAIL: /connect closed the connection rather than carrying frames for",
                  described)
            sys.exit(1)
        held += chunk
finally:
    s.close()
PY
    local outcome=$?
    kill "$GATEWAY" 2>/dev/null
    wait "$GATEWAY" 2>/dev/null
    GATEWAY=""
    rm -f "$WIRE" "$CONTROL"
    return $outcome
}

# The wire that is this process's own pipes.
#
# `--listen-stdio` has no socket: the hypervisor spawns the gateway and speaks to
# it through the pipes it already has. Upstream documents the framing as
# "HyperKitProtocol without the handshake" -- two little-endian length bytes and
# then the frame.
#
# It has a hazard the socket wires do not, and the hazard is the reason this
# check reads stdout strictly rather than looking for a frame somewhere in it:
# stdout IS the wire, so every line the program would print lands in the middle
# of one. The guest's decoder reads the first two bytes of "netstack-gateway: "
# as a length of 25966 and everything after it is noise.
stdio_smoke() {
    local expected="$1" guest="$2"
    EXPECTED="$expected" GUEST="$guest" BINARY="$binary" python3 - <<'PY'
import os, select, struct, subprocess, sys
sys.path.insert(0, os.environ["SMOKE_SUPPORT"])
from wire import address, ones_complement, printable

gateway = address(os.environ["EXPECTED"])
guest = address(os.environ["GUEST"])
mac = bytes.fromhex("5a94efe4bc00")

process = subprocess.Popen(
    [os.environ["BINARY"], "--listen-stdio", "on"],
    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
try:
    frame = (
        b"\xff\xff\xff\xff\xff\xff" + mac + b"\x08\x06"
        + b"\x00\x01\x08\x00\x06\x04\x00\x01"
        + mac + guest + b"\x00" * 6 + gateway
    )
    process.stdin.write(struct.pack("<H", len(frame)) + frame)
    process.stdin.flush()

    held = b""
    answered = False
    for _ in range(80):
        ready, _, _ = select.select([process.stdout], [], [], 0.25)
        if not ready:
            continue
        chunk = os.read(process.stdout.fileno(), 4096)
        if not chunk:
            break
        held += chunk
        while len(held) >= 2:
            length = struct.unpack("<H", held[:2])[0]
            # Strict, and deliberately so: anything on stdout that is not a frame
            # is the bug this wire invites. A message printed there reads as a
            # length of tens of thousands.
            if length > 1600:
                print("FAIL: stdout carried something that is not a frame --",
                      repr(held[:48]), "-- stdout is the wire on --listen-stdio")
                sys.exit(1)
            if len(held) < 2 + length:
                break
            body, held = held[2:2 + length], held[2 + length:]
            if len(body) >= 42 and body[12:14] == b"\x08\x06" and body[20:22] == b"\x00\x02":
                if body[28:32] != gateway:
                    continue
                answered = True
                break
        if answered:
            break

    if not answered:
        print("FAIL: no ARP reply over stdio within 20s")
        sys.exit(1)
    print("ok: stdio ARP", printable(gateway),
          "answered over this process's own pipes")

    # And the program's own messages went somewhere else.
    #
    # Asserted on stderr rather than only on stdout's cleanliness, because
    # `print` to a pipe is block-buffered: a gateway printing into the wire
    # writes nothing until four kilobytes have piled up, so a check that only
    # watched stdout passed with the redirection removed. It would have
    # corrupted the wire later, on a longer run, which is worse than failing.
    process.terminate()
    _, complaints = process.communicate(timeout=15)
    said = complaints.decode(errors="replace")
    # The line printed BEFORE the wire is adopted, so it has certainly been
    # written by the time a frame has been answered. "running" comes later --
    # after the forwards and the control endpoints -- and terminating on the
    # first reply beats it there.
    if "netstack-gateway: waiting for a guest" not in said:
        print("FAIL: the gateway said nothing on stderr, so its output is going",
              "into the wire:", repr(said[:120]))
        sys.exit(1)
    print("ok: stdio every message went to stderr, leaving stdout to the frames")
    sys.exit(0)
finally:
    process.kill()
    process.wait()
PY
}

# hyperkit's wire.
#
# The one wire whose connection does not begin with a frame: hyperkit sends a
# fixed-size init and a fixed-size command, and is told its MTU and its hardware
# address before anything else happens. The sizes are hyperkit's -- 49, 41, 258
# -- and there is nothing in them to negotiate, so getting one wrong is a wire
# that never carries a frame and never says why.
vpnkit_smoke() {
    local expected="$1" guest="$2"
    shift 2
    WIRE="${TMPDIR:-/tmp}/netstack-smoke-vpnkit-$$.sock"
    rm -f "$WIRE"
    "$binary" --listen-vpnkit "$WIRE" "$@" >/dev/null 2>&1 &
    GATEWAY=$!
    for _ in $(seq 1 120); do
        [[ -S "$WIRE" ]] && break
        sleep 0.25
    done
    [[ -S "$WIRE" ]] || { echo "FAIL: the vpnkit wire never appeared"; return 1; }

    EXPECTED="$expected" GUEST="$guest" WIRE="$WIRE" ARGS="$*" python3 - <<'PY'
import os, socket, struct, sys
sys.path.insert(0, os.environ["SMOKE_SUPPORT"])
from wire import address, ones_complement, printable

gateway = address(os.environ["EXPECTED"])
guest = address(os.environ["GUEST"])
described = os.environ.get("ARGS") or "(defaults)"

s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(10)


def exactly(count):
    collected = b""
    while len(collected) < count:
        chunk = s.recv(count - len(collected))
        if not chunk:
            print("FAIL: the wire closed during the handshake for", described)
            sys.exit(1)
        collected += chunk
    return collected


try:
    s.connect(os.environ["WIRE"])
    initial = b"VMN3T" + bytes(44)
    s.sendall(initial)
    if exactly(49) != initial:
        print("FAIL: the init message was not echoed back verbatim for", described)
        sys.exit(1)

    uuid = b"1e0a4f1a-0000-4000-8000-0123456789ab"
    s.sendall(bytes([1]) + uuid + bytes(4))
    reply = exactly(258)
    mtu = struct.unpack("<H", reply[1:3])[0]
    frame_size = struct.unpack("<H", reply[3:5])[0]
    mac = reply[5:11]
    if reply[0] != 0x01:
        print("FAIL: the reply is tagged", reply[0], "rather than 1, for", described)
        sys.exit(1)
    if frame_size != mtu + 14:
        print("FAIL: the reply says an MTU of", mtu, "and a frame size of", frame_size,
              "-- the frame size is the MTU plus an ethernet header, for", described)
        sys.exit(1)
    if mac[0] & 0x03 != 0x02:
        print("FAIL: the guest was given", mac.hex(":"), "which is not a locally",
              "administered unicast address, for", described)
        sys.exit(1)
    print("ok: vpnkit the handshake gave an MTU of", mtu, "and the address", mac.hex(":"),
          "for", described)

    # And now it is an ordinary hyperkit wire, using the address it was handed.
    frame = (
        b"\xff\xff\xff\xff\xff\xff" + mac + b"\x08\x06"
        + b"\x00\x01\x08\x00\x06\x04\x00\x01"
        + mac + guest + b"\x00" * 6 + gateway
    )
    s.sendall(struct.pack("<H", len(frame)) + frame)
    held = b""
    while True:
        while len(held) >= 2:
            length = struct.unpack("<H", held[:2])[0]
            if length > 1600:
                print("FAIL: the wire carried something that is not a frame:",
                      repr(held[:32]), "for", described)
                sys.exit(1)
            if len(held) < 2 + length:
                break
            body, held = held[2:2 + length], held[2 + length:]
            if len(body) >= 42 and body[12:14] == b"\x08\x06" and body[20:22] == b"\x00\x02":
                if body[28:32] != gateway:
                    continue
                print("ok: vpnkit ARP", printable(gateway),
                      "answered after the handshake for", described)
                sys.exit(0)
        try:
            chunk = s.recv(4096)
        except socket.timeout:
            print("FAIL: no ARP reply after the vpnkit handshake for", described)
            sys.exit(1)
        if not chunk:
            print("FAIL: the wire closed after the handshake for", described)
            sys.exit(1)
        held += chunk
finally:
    s.close()
PY
    local outcome=$?
    kill "$GATEWAY" 2>/dev/null
    wait "$GATEWAY" 2>/dev/null
    GATEWAY=""
    rm -f "$WIRE"
    return $outcome
}

# The socket a supervisor waits on.
#
# `--notification` is how whatever started this gateway learns it is up. Upstream
# dials the socket per message and closes it, and encodes with Go's
# `json.Encoder`, which appends a newline -- so the reader on the other end is
# reading newline-delimited JSON and a message without the newline would leave it
# blocking on a line that never ends.
#
# The listener is opened BEFORE the gateway starts, because that is the order a
# supervisor uses: nothing to connect to means the notification is lost, and a
# check that started them the other way round would be testing its own timing.
notification_smoke() {
    NOTIFY="${TMPDIR:-/tmp}/netstack-smoke-notify-$$.sock"
    WIRE="${TMPDIR:-/tmp}/netstack-smoke-notify-wire-$$.sock"
    rm -f "$NOTIFY" "$WIRE"

    BINARY="$binary" NOTIFY="$NOTIFY" WIRE="$WIRE" python3 - <<'PY'
import json, os, socket, subprocess, sys

notify, wire = os.environ["NOTIFY"], os.environ["WIRE"]
server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
server.bind(notify)
server.listen(8)
server.settimeout(20)

process = subprocess.Popen(
    [os.environ["BINARY"], "--listen-vfkit", wire, "--notification", notify],
    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
try:
    try:
        connection, _ = server.accept()
    except socket.timeout:
        print("FAIL: nothing was said on the notification socket within 20s")
        sys.exit(1)
    connection.settimeout(10)
    said = b""
    while b"\n" not in said:
        try:
            chunk = connection.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        said += chunk
    connection.close()

    if not said.endswith(b"\n"):
        print("FAIL: the notification is not newline-terminated:", repr(said),
              "-- the reader on the other end is reading lines")
        sys.exit(1)
    try:
        message = json.loads(said)
    except ValueError:
        print("FAIL: the notification is not JSON:", repr(said))
        sys.exit(1)
    if message.get("notification_type") != "ready":
        print("FAIL: the gateway announced", message, "rather than ready")
        sys.exit(1)
    print("ok: notify the gateway announced itself ready, as newline-delimited JSON")
finally:
    process.terminate()
    process.wait()
    server.close()
    os.unlink(notify)
PY
    local outcome=$?
    rm -f "$WIRE" "$NOTIFY"
    return $outcome
}

# A host-side client dialled into the guest.
#
# `GET /tunnel?ip=&port=` is the other way for something on the host to reach a
# guest: rather than publishing a port, the caller asks the control API to make
# *this* connection into one. The connection stops being HTTP and the raw bytes
# on it are the guest's.
#
# It is not silent, unlike `/connect`: upstream writes a literal `OK` -- not an
# HTTP response, because the connection stopped being HTTP a moment earlier --
# and a client waits for it before sending. So the two-byte answer is part of the
# contract, and a gateway that spliced without it would leave every caller
# waiting.
tunnel_smoke() {
    local expected="$1" guest="$2"
    shift 2
    CONTROL="${TMPDIR:-/tmp}/netstack-smoke-tunnel-ctl-$$.sock"
    WIRE="${TMPDIR:-/tmp}/netstack-smoke-tunnel-$$.sock"
    rm -f "$WIRE" "$CONTROL"
    "$binary" --listen-vfkit "$WIRE" --listen "unix://$CONTROL" "$@" >/dev/null 2>&1 &
    GATEWAY=$!
    for _ in $(seq 1 120); do
        [[ -S "$WIRE" && -S "$CONTROL" ]] && break
        sleep 0.25
    done
    [[ -S "$WIRE" && -S "$CONTROL" ]] || { echo "FAIL: the tunnel gateway never came up"; return 1; }

    EXPECTED="$expected" GUEST="$guest" WIRE="$WIRE" CONTROL="$CONTROL" ARGS="$*" python3 - <<'PY'
import os, socket, struct, sys, threading

sys.path.insert(0, os.environ["SMOKE_SUPPORT"])
from wire import address, ones_complement, printable

gateway = address(os.environ["EXPECTED"])
guest = address(os.environ["GUEST"])
described = os.environ.get("ARGS") or "(defaults)"
GUEST_MAC = bytes.fromhex("5a94efe4bc00")
GATEWAY_MAC = bytes.fromhex("5a94efe40cee")
GUEST_PORT = 9090
SYN, ACK, PSH, RST = 0x02, 0x10, 0x08, 0x04

wire = os.environ["WIRE"]
client_path = wire + ".client"
s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
s.bind(client_path)

body = b"through the tunnel"
seen = {}


def tcp_frame(source, destination, sport, dport, sequence, ack, flags, payload=b""):
    header = (
        sport.to_bytes(2, "big") + dport.to_bytes(2, "big")
        + sequence.to_bytes(4, "big") + ack.to_bytes(4, "big")
        + bytes([5 << 4, flags]) + (65535).to_bytes(2, "big") + b"\x00\x00\x00\x00"
    )
    segment = header + payload
    pseudo = source + destination + b"\x00\x06" + len(segment).to_bytes(2, "big")
    segment = (segment[:16] + ones_complement(pseudo + segment).to_bytes(2, "big")
               + segment[18:])
    ip = bytearray(
        b"\x45\x00" + (20 + len(segment)).to_bytes(2, "big")
        + b"\x00\x00\x40\x00\x40\x06\x00\x00" + source + destination
    )
    ip[10:12] = ones_complement(bytes(ip)).to_bytes(2, "big")
    return GATEWAY_MAC + GUEST_MAC + b"\x08\x00" + bytes(ip) + segment


def caller():
    """The thing on the host that wants to reach the guest."""
    try:
        control = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        control.settimeout(20)
        control.connect(os.environ["CONTROL"])
        control.sendall(
            ("GET /tunnel?ip=%s&port=%d HTTP/1.1\r\nHost: gateway\r\n\r\n"
             % (printable(guest), GUEST_PORT)).encode())
        # `OK`, then the connection is the guest's.
        hello = b""
        while len(hello) < 2:
            chunk = control.recv(2 - len(hello))
            if not chunk:
                seen["error"] = "the control plane closed before saying OK"
                return
            hello += chunk
        seen["hello"] = hello
        control.sendall(body)
        echoed = b""
        while len(echoed) < len(body):
            chunk = control.recv(4096)
            if not chunk:
                break
            echoed += chunk
        seen["echoed"] = echoed
        control.close()
    except Exception as error:
        seen["error"] = error


try:
    s.connect(wire)
    # The guest announces itself, so the gateway knows where to send the dial.
    s.send(
        b"\xff\xff\xff\xff\xff\xff" + GUEST_MAC + b"\x08\x06"
        + b"\x00\x01\x08\x00\x06\x04\x00\x01"
        + GUEST_MAC + guest + b"\x00" * 6 + gateway)

    thread = threading.Thread(target=caller, daemon=True)
    thread.start()

    s.settimeout(20)
    peer = None
    their_port = None
    sequence = 7000
    theirs = 0
    echoed_back = 0
    missing = "no SYN arrived from the gateway"
    while echoed_back < len(body):
        try:
            frame = s.recv(4096)
        except socket.timeout:
            print("FAIL:", missing, "for", described)
            sys.exit(1)
        if len(frame) < 42 or frame[12:14] != b"\x08\x00":
            continue
        packet = frame[14:int.from_bytes(frame[16:18], "big") + 14]
        if len(packet) < 20 or packet[9] != 6 or packet[16:20] != guest:
            continue
        segment = packet[(packet[0] & 0x0F) * 4:]
        if int.from_bytes(segment[2:4], "big") != GUEST_PORT:
            continue
        flags = segment[13]
        their_sequence = int.from_bytes(segment[4:8], "big")
        payload = segment[(segment[12] >> 4) * 4:]

        if flags & SYN and not flags & ACK:
            peer, their_port = packet[12:16], int.from_bytes(segment[0:2], "big")
            theirs = their_sequence + 1
            s.send(tcp_frame(guest, peer, GUEST_PORT, their_port, sequence, theirs, SYN | ACK))
            sequence += 1
            missing = "the handshake was answered but no data came through the tunnel"
            continue
        if peer is None:
            continue
        if flags & RST:
            print("FAIL: the gateway reset the tunnelled connection for", described)
            sys.exit(1)
        if payload and their_sequence == theirs:
            theirs += len(payload)
            s.send(tcp_frame(guest, peer, GUEST_PORT, their_port, sequence, theirs,
                             PSH | ACK, payload))
            echoed_back += len(payload)
            missing = "the guest echoed but the caller never saw it"

    thread.join(20)
    if "error" in seen:
        print("FAIL: the caller failed:", seen["error"], "for", described)
        sys.exit(1)
    if seen.get("hello") != b"OK":
        print("FAIL: /tunnel said", seen.get("hello"), "rather than OK --",
              "a client waits for that before it sends, for", described)
        sys.exit(1)
    if seen.get("echoed") != body:
        print("FAIL: the caller read", seen.get("echoed"), "rather than", body,
              "for", described)
        sys.exit(1)
    print("ok: tunnel", len(body), "bytes host -> guest -> host through /tunnel for",
          described)
finally:
    s.close()
    os.unlink(client_path)
PY
    local outcome=$?
    kill "$GATEWAY" 2>/dev/null
    wait "$GATEWAY" 2>/dev/null
    GATEWAY=""
    rm -f "$WIRE" "$CONTROL"
    return $outcome
}

# Which MTU the guest is told, when the config file and the command line
# disagree.
#
# The merge decided this by comparing the parsed flag against 1500, which cannot
# tell "the user asked for 1500" from "the user asked for nothing" -- so a
# `--mtu 1500` given precisely to override a config file saying 9000 was
# discarded and the guest was told 9000. That is the failure `parsedAddress` in
# main.swift already carried a comment about, for the addresses, a few lines from
# the line that still had it.
#
# All four combinations, because this is a precedence rule and a precedence rule
# checked in one direction is half a rule: the flag must win when both are given,
# the file must still be read when only it is, and 1500 must survive neither.
mtu_smoke() {
    local directory="${TMPDIR:-/tmp}/netstack-smoke-mtu-$$"
    rm -rf "$directory"
    mkdir -p "$directory" || { echo "FAIL: could not make $directory"; return 1; }
    echo '{"mtu": 9000}' > "$directory/config.json"
    MTU_WIRE="$directory/wire.sock"

    local failures=0
    check_mtu() {
        local want="$1" description="$2"
        shift 2
        rm -f "$MTU_WIRE"
        "$binary" --listen-vpnkit "$MTU_WIRE" "$@" >/dev/null 2>&1 &
        GATEWAY=$!
        local waited=0
        for _ in $(seq 1 120); do
            [[ -S "$MTU_WIRE" ]] && { waited=1; break; }
            sleep 0.25
        done
        if [[ $waited -eq 0 ]]; then
            echo "FAIL: $description -- the gateway never came up"
            failures=1
            return
        fi
        local got
        got="$(MTU_WIRE="$MTU_WIRE" python3 "$SMOKE_SUPPORT/vpnkit_mtu.py")"
        kill "$GATEWAY" 2>/dev/null
        wait "$GATEWAY" 2>/dev/null
        GATEWAY=""
        if [[ "$got" != "$want" ]]; then
            echo "FAIL: $description -- the guest was told ${got:-nothing}, not $want"
            failures=1
        fi
    }

    check_mtu 1500 "an explicit --mtu 1500 against a config file saying 9000" \
        --config "$directory/config.json" --mtu 1500
    check_mtu 9000 "a config file saying 9000 and no flag" \
        --config "$directory/config.json"
    check_mtu 4000 "an explicit --mtu 4000 and no config file" --mtu 4000
    check_mtu 1500 "neither a config file nor a flag"

    rm -rf "$directory"
    [[ $failures -eq 0 ]] || return 1
    echo "ok: mtu   the flag wins over the file, the file over the default"
}

# A number in the config file that is present and wrong.
#
# The range test on `mtu` was a condition of the `if let` that read it, so an
# out-of-range value left the field nil and the gateway started on 1500 -- while
# `--mtu 100` on the command line was refused outright. The same program, the
# same value, two answers, and the silent one is the one an operator cannot see.
# Every structured field in that file already threw on bad content; the scalars
# did not.
#
# Driven through the executable because the parser lives in it and a test target
# cannot import it.
config_value_smoke() {
    local directory="${TMPDIR:-/tmp}/netstack-smoke-cfg-$$"
    rm -rf "$directory"
    mkdir -p "$directory" || { echo "FAIL: could not make $directory"; return 1; }
    local failures=0

    # Refused: the gateway must not start, and must say which field and why.
    #
    # Started in the background and waited for, rather than read through a
    # command substitution. The first version of this was
    #
    #     output="$("$binary" ... 2>&1 | head -1)"
    #
    # which waits for the command to finish -- and the failure it is looking for
    # is a gateway that does not refuse, so it starts and runs forever. Against
    # the very bug this case was written for, it hung instead of reporting it,
    # leaving gateways behind. In CI that is a job timeout rather than a failed
    # assertion, and a check that cannot say what is wrong is most of the way to
    # a check that says nothing.
    refuses() {
        local json="$1" expected="$2"
        echo "$json" > "$directory/config.json"
        rm -f "$directory/wire.sock"
        "$binary" --listen-vpnkit "$directory/wire.sock" \
            --config "$directory/config.json" >"$directory/output.txt" 2>&1 &
        local pid=$!
        local exited=0
        for _ in $(seq 1 120); do
            if ! kill -0 "$pid" 2>/dev/null; then exited=1; break; fi
            [[ -S "$directory/wire.sock" ]] && break
            sleep 0.25
        done
        kill "$pid" 2>/dev/null
        wait "$pid" 2>/dev/null
        if [[ $exited -eq 0 ]]; then
            echo "FAIL: $json started a gateway instead of being refused"
            failures=1
            return
        fi
        local output
        output="$(head -1 "$directory/output.txt")"
        case "$output" in
            *"$expected"*) ;;
            *)
                echo "FAIL: $json was refused with \"$output\", which does not mention $expected"
                failures=1
                ;;
        esac
    }

    # The shapes, not just the numbers. A table written as the one string
    # somebody meant to put in it used to leave the field empty and start a
    # gateway that quietly did none of it -- and a forward that does not happen
    # looks, from the guest, exactly like a network problem.
    refuses '{"nat": "10.0.0.1"}' "not a table of strings"
    refuses '{"forwards": "8080:192.168.127.2:80"}' "not a table of strings"
    refuses '{"dnsSearchDomains": "example.com"}' "not a list of strings"
    refuses '{"gatewayIP": 42}' "not a string"
    refuses '{"dns": {"name": "x"}}' "not a list of zones"
    refuses '{"ec2MetadataAccess": "true"}' "not true or false"

    refuses '{"mtu": 100}' "outside 576...65535"
    refuses '{"mtu": 99999}' "outside 576...65535"
    refuses '{"mtu": "1500"}' "not a whole number"
    refuses '{"tcpMaxInFlight": 0}' "tcpMaxInFlight"
    refuses '{"tcpConnectTimeout": -1}' "tcpConnectTimeout"

    # And the values that are fine are still taken, so this did not simply
    # become a parser that refuses everything. A JSON null is among them: it is
    # how a generated file says "not set", and refusing it would fight the tools
    # that write these.
    echo '{"mtu": 9000, "tcpMaxInFlight": 64, "tcpConnectTimeout": 3, "nat": null}' \
        > "$directory/config.json"
    rm -f "$directory/wire.sock"
    "$binary" --listen-vpnkit "$directory/wire.sock" --config "$directory/config.json" \
        >/dev/null 2>&1 &
    GATEWAY=$!
    for _ in $(seq 1 120); do
        [[ -S "$directory/wire.sock" ]] && break
        sleep 0.25
    done
    local got=""
    if [[ -S "$directory/wire.sock" ]]; then
        got="$(MTU_WIRE="$directory/wire.sock" python3 "$SMOKE_SUPPORT/vpnkit_mtu.py")"
    fi
    kill "$GATEWAY" 2>/dev/null
    wait "$GATEWAY" 2>/dev/null
    GATEWAY=""
    if [[ "$got" != "9000" ]]; then
        echo "FAIL: a config file of values that are all in range was not applied --"
        echo "      the guest was told ${got:-nothing}, not 9000"
        failures=1
    fi

    rm -rf "$directory"
    [[ $failures -eq 0 ]] || return 1
    echo "ok: cfg   a number that is present and wrong is refused, not dropped"
}

# What a supervisor is told when the hypervisor's socket cannot be served.
#
# `ready` is sent by the gateway once it is assembled, so a wire that could not
# bind produced a message on stderr and silence on the socket a supervisor is
# watching -- there was no sender yet to say anything with. gvproxy sends
# `hypervisor_error` on exactly that path, before returning the listen error.
#
# And not on the others: a mistyped flag is not a hypervisor failure, and a
# supervisor told that its hypervisor died because somebody wrote `--mtu 100`
# would act on it.
hypervisor_error_smoke() {
    local directory="${TMPDIR:-/tmp}/netstack-smoke-hyp-$$"
    rm -rf "$directory"
    mkdir -p "$directory" || { echo "FAIL: could not make $directory"; return 1; }
    echo '{"mtu": 100}' > "$directory/bad-config.json"

    BINARY="$binary" DIRECTORY="$directory" python3 - <<'PY'
import json, os, socket, subprocess, sys

binary, directory = os.environ["BINARY"], os.environ["DIRECTORY"]


def heard(arguments, wait_for):
    """Run the gateway with a supervisor listening, and return what it said."""
    notify = os.path.join(directory, "notify.sock")
    if os.path.exists(notify):
        os.unlink(notify)
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(notify)
    server.listen(4)
    server.settimeout(wait_for)
    process = subprocess.Popen(
        [binary] + arguments + ["--notification", notify],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        try:
            connection, _ = server.accept()
        except socket.timeout:
            return None
        connection.settimeout(5)
        said = b""
        while b"\n" not in said:
            chunk = connection.recv(4096)
            if not chunk:
                break
            said += chunk
        connection.close()
        return json.loads(said)
    finally:
        process.terminate()
        process.wait(timeout=10)
        server.close()


unbindable = os.path.join(directory, "no-such-directory", "wire.sock")
message = heard(["--listen-vfkit", unbindable], 20)
if message is None:
    print("FAIL: a wire that could not bind said nothing to the supervisor")
    sys.exit(1)
if message.get("notification_type") != "hypervisor_error":
    print("FAIL: a wire that could not bind announced", message)
    sys.exit(1)

# The other direction, which is the half that can go wrong quietly: this must
# stay silent rather than blaming the hypervisor for a typo. Five seconds,
# because a wrong answer here is a message arriving and there is nothing to
# wait for when the right answer is silence.
for arguments, described in (
    (["--listen-vfkit", os.path.join(directory, "a.sock"), "--mtu", "100"], "a bad --mtu"),
    (["--listen-vfkit", os.path.join(directory, "b.sock"),
      "--config", os.path.join(directory, "bad-config.json")], "a bad config value"),
):
    message = heard(arguments, 5)
    if message is not None:
        print("FAIL:", described, "was reported to the supervisor as", message)
        sys.exit(1)

print("ok: notify a wire that cannot bind says hypervisor_error, a bad flag says nothing")
PY
    local outcome=$?
    rm -rf "$directory"
    return $outcome
}

# The instance metadata service, and the flag that opens it.
#
# A guest that reaches 169.254.169.254 on a cloud host is asking the host's
# metadata service for the host's credentials. It is refused by default, and
# `--ec2-metadata-access` is the deliberate opt-out.
#
# The library has a guard for the policy. What it cannot have is a check that the
# FLAG reaches the policy -- and a flag that does not reach its setting is the
# bug that shipped here once already, when --config was read before it was
# loaded and every configured value was silently the default.
metadata_smoke() {
    local expected="$1" guest="$2"
    METADATA_ARGS="$3"
    CONTROL="${TMPDIR:-/tmp}/netstack-smoke-imds-ctl-$$.sock"
    WIRE="${TMPDIR:-/tmp}/netstack-smoke-imds-$$.sock"
    rm -f "$WIRE" "$CONTROL"
    # shellcheck disable=SC2086
    "$binary" --listen-vfkit "$WIRE" --listen "unix://$CONTROL" $METADATA_ARGS >/dev/null 2>&1 &
    GATEWAY=$!
    for _ in $(seq 1 120); do
        [[ -S "$WIRE" && -S "$CONTROL" ]] && break
        sleep 0.25
    done
    [[ -S "$WIRE" && -S "$CONTROL" ]] || { echo "FAIL: the metadata gateway never came up"; return 1; }

    EXPECTED="$expected" GUEST="$guest" WIRE="$WIRE" CONTROL="$CONTROL" \
        EXPECT_REACHABLE="${4}" ARGS="${METADATA_ARGS:-(defaults)}" python3 - <<'PY'
import json, os, socket, subprocess, sys

sys.path.insert(0, os.environ["SMOKE_SUPPORT"])
from wire import address, ones_complement, printable

gateway = address(os.environ["EXPECTED"])
guest = address(os.environ["GUEST"])
metadata = address("169.254.169.254")


def statistics():
    answer = subprocess.run(
        ["curl", "--silent", "--fail-with-body", "--max-time", "10",
         "--unix-socket", os.environ["CONTROL"], "http://gateway/stats"],
        capture_output=True, text=True, timeout=20)
    if answer.returncode != 0:
        print("FAIL: /stats was not answered")
        sys.exit(1)
    return json.loads(answer.stdout)
reachable = os.environ["EXPECT_REACHABLE"] == "yes"
described = os.environ.get("ARGS") or "(defaults)"
mac = bytes.fromhex("5a94efe4bc00")

wire = os.environ["WIRE"]
client_path = wire + ".client"
s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
s.bind(client_path)

SYN, ACK, RST = 0x02, 0x10, 0x04


def syn_frame(sport):
    header = (
        sport.to_bytes(2, "big") + (80).to_bytes(2, "big")
        + (1000).to_bytes(4, "big") + (0).to_bytes(4, "big")
        + bytes([5 << 4, SYN]) + (65535).to_bytes(2, "big") + b"\x00\x00\x00\x00"
    )
    pseudo = guest + metadata + b"\x00\x06" + len(header).to_bytes(2, "big")
    header = header[:16] + ones_complement(pseudo + header).to_bytes(2, "big") + header[18:]
    ip = bytearray(
        b"\x45\x00" + (20 + len(header)).to_bytes(2, "big")
        + b"\x00\x00\x40\x00\x40\x06\x00\x00" + guest + metadata
    )
    ip[10:12] = ones_complement(bytes(ip)).to_bytes(2, "big")
    return bytes.fromhex("5a94efe40cee") + mac + b"\x08\x00" + bytes(ip) + header


try:
    s.connect(wire)
    s.send(syn_frame(40200))
    s.settimeout(6)
    answer = None
    while answer is None:
        try:
            frame = s.recv(2048)
        except socket.timeout:
            break
        if len(frame) < 54 or frame[12:14] != b"\x08\x00" or frame[23] != 6:
            continue
        if frame[26:30] != metadata:
            continue
        answer = frame[14 + (frame[14] & 0x0F) * 4:][13]

    # The guest sees the same thing either way, and that is the difficulty. A
    # refusal by policy is a reset; a dial to an address nothing answers on ends
    # as a reset too. Written first as "did a reset come back", this check
    # reported a bug that was not there -- it could not tell the two apart,
    # because from the wire they are not different.
    #
    # The gateway's own counter is what separates them, and it exists for the
    # same reason: an operator asking why a guest cannot reach the metadata
    # service has two possible answers that call for opposite actions.
    counters = statistics()
    refused = counters.get("tcp_refused_link_local", 0)
    if reachable:
        # A floor, read before the refusal count means anything. `refused == 0`
        # is what the flag working looks like, and it is equally what a gateway
        # that never received the SYN looks like -- and this branch, unlike the
        # refusal one below, has no second piece of evidence to tell them apart.
        # Run against a stack whose link layer discarded every inbound frame,
        # this case reported ok. `ipv4_delivered` rises before the policy is
        # consulted, so it separates "the flag let the request through" from
        # "there was no request to let through".
        delivered = counters.get("ipv4_delivered", 0)
        if delivered < 1:
            print("FAIL: no IPv4 packet reached the gateway at all, so a refusal",
                  "count of zero says nothing about the flag, for", described)
            sys.exit(1)
        if refused != 0:
            print("FAIL: --ec2-metadata-access was given and the gateway refused",
                  "169.254.169.254 by policy anyway, for", described)
            sys.exit(1)
        print("ok: imds  --ec2-metadata-access let the request through the policy for",
              described)
    else:
        if refused < 1:
            print("FAIL: 169.254.169.254 was not refused by policy --",
                  "tcp_refused_link_local is", refused, "for", described)
            sys.exit(1)
        if answer is None or not answer & RST:
            print("FAIL: the guest was not told --", "flags",
                  hex(answer) if answer is not None else "no answer", "for", described)
            sys.exit(1)
        print("ok: imds  169.254.169.254 refused by policy, and the guest told, for",
              described)
finally:
    s.close()
    os.unlink(client_path)
PY
    local outcome=$?
    kill "$GATEWAY" 2>/dev/null
    wait "$GATEWAY" 2>/dev/null
    GATEWAY=""
    rm -f "$WIRE" "$CONTROL"
    return $outcome
}

# What the gateway says when a guest stops reading.
#
# Two questions an operator asks in that order: is anything being lost, and
# whose end is it. The wire counts them apart -- a frame the queue had no room
# for is backed up, a frame the kernel refused for another reason is rejected --
# and until recently only the second reached `GET /stats`, which is the one that
# almost never happens.
#
# What this pins is that the number is reported at all. The split itself -- full
# queue against hard failure -- is real and is checked by the errno list in
# `WireLinkEndpoint`, which an experiment settled: on an unconnected unix
# datagram socket macOS reports ENOBUFS for a full queue and ECONNREFUSED for a
# peer that has gone. Reading a flood's ECONNREFUSED as "full" is a mistake I
# made and measured my way out of.
backpressure_smoke() {
    CONTROL="${TMPDIR:-/tmp}/netstack-smoke-bp-ctl-$$.sock"
    WIRE="${TMPDIR:-/tmp}/netstack-smoke-bp-$$.sock"
    rm -f "$WIRE" "$CONTROL"
    "$binary" --listen-vfkit "$WIRE" --listen "unix://$CONTROL" >/dev/null 2>&1 &
    GATEWAY=$!
    for _ in $(seq 1 120); do
        [[ -S "$WIRE" && -S "$CONTROL" ]] && break
        sleep 0.25
    done
    [[ -S "$WIRE" && -S "$CONTROL" ]] || { echo "FAIL: the backpressure gateway never came up"; return 1; }

    WIRE="$WIRE" CONTROL="$CONTROL" python3 - <<'PY'
import json, os, socket, subprocess, sys

sys.path.insert(0, os.environ["SMOKE_SUPPORT"])
from wire import address

wire = os.environ["WIRE"]
gateway = address("192.168.127.1")
guest = address("192.168.127.2")
mac = bytes.fromhex("5a94efe4bc00")

client_path = wire + ".client"
s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
s.bind(client_path)
try:
    s.connect(wire)
    frame = (
        b"\xff\xff\xff\xff\xff\xff" + mac + b"\x08\x06"
        + b"\x00\x01\x08\x00\x06\x04\x00\x01"
        + mac + guest + b"\x00" * 6 + gateway
    )
    # Twenty thousand questions, and not one answer read.
    for _ in range(20000):
        try:
            s.send(frame)
        except OSError:
            pass

    answer = subprocess.run(
        ["curl", "--silent", "--fail-with-body", "--max-time", "10",
         "--unix-socket", os.environ["CONTROL"], "http://gateway/stats"],
        capture_output=True, text=True, timeout=20)
    if answer.returncode != 0:
        print("FAIL: /stats was not answered after the flood")
        sys.exit(1)
    stats = json.loads(answer.stdout)
    backed_up = stats.get("outbound_frames_backed_up")
    rejected = stats.get("outbound_frames_rejected")
    if backed_up is None:
        print("FAIL: /stats does not report outbound_frames_backed_up at all,",
              "so an operator cannot tell loss at the guest's end from loss at this one")
        sys.exit(1)
    if backed_up < 1:
        print("FAIL: twenty thousand answers into a queue of about forty and",
              "outbound_frames_backed_up is", backed_up)
        sys.exit(1)
    # No assertion on the ratio to `rejected`. It would express something true --
    # ordinary loss is a full queue and not a hard failure -- and it cannot fail
    # here, because a full queue reports ENOBUFS and ENOBUFS has always been
    # handled. An assertion that holds either way reads as coverage of a rule it
    # cannot see.
    print("ok: stats", backed_up, "frames backed up and", rejected, "rejected:",
          "the loss is reported at the guest's end, where it is")
finally:
    s.close()
    os.unlink(client_path)
PY
    local outcome=$?
    kill "$GATEWAY" 2>/dev/null
    wait "$GATEWAY" 2>/dev/null
    GATEWAY=""
    rm -f "$WIRE" "$CONTROL"
    return $outcome
}

# The pool must not contain an address the gateway answers for.
#
# It contained the host address -- the one `host.containers.internal` resolves
# to, and the one NAT translates to the host's loopback. A guest handed it
# believes it IS the host: the name resolves to itself, and its ARP for that
# address collides with the gateway's own.
#
# On the default /24 that takes two hundred and fifty guests, which is why
# nothing saw it. This asks on a /29, where it is the fifth guest, and it asks
# through the executable because the claim is about what the gateway TELLS its
# DHCP server -- a library test can only check that the pool builder knows the
# rule, which it did all along.
pool_smoke() {
    WIRE="${TMPDIR:-/tmp}/netstack-smoke-pool-$$.sock"
    rm -f "$WIRE"
    "$binary" --listen-vfkit "$WIRE" --subnet 192.168.127.0/29 >/dev/null 2>&1 &
    GATEWAY=$!
    for _ in $(seq 1 120); do
        [[ -S "$WIRE" ]] && break
        sleep 0.25
    done
    [[ -S "$WIRE" ]] || { echo "FAIL: the small-subnet gateway never came up"; return 1; }

    WIRE="$WIRE" python3 - <<'PY'
import os, socket, sys

sys.path.insert(0, os.environ["SMOKE_SUPPORT"])
from wire import address, ones_complement, printable

wire = os.environ["WIRE"]
client_path = wire + ".client"
s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
s.bind(client_path)
s.connect(wire)
s.settimeout(3)

# On a /29 the gateway is .1 and the host is .6, so a guest may have .2 to .5.
gateway = address("192.168.127.1")
host = address("192.168.127.6")


def discover(index):
    mac = bytes.fromhex("5a94efe4bc%02x" % index)
    payload = (
        b"\x01\x01\x06\x00" + bytes([0, 0, 0, index]) + b"\x00" * 2 + b"\x80\x00"
        + b"\x00" * 16 + mac + b"\x00" * 10 + b"\x00" * 64 + b"\x00" * 128
        + b"\x63\x82\x53\x63" + b"\x35\x01\x01" + b"\xff"
    )
    udp = b"\x00\x44\x00\x43" + (8 + len(payload)).to_bytes(2, "big") + b"\x00\x00" + payload
    ip = bytearray(
        b"\x45\x00" + (20 + len(udp)).to_bytes(2, "big")
        + b"\x00\x00\x00\x00\x40\x11\x00\x00" + bytes(4) + b"\xff\xff\xff\xff"
    )
    ip[10:12] = ones_complement(bytes(ip)).to_bytes(2, "big")
    s.send(b"\xff" * 6 + mac + b"\x08\x00" + bytes(ip) + udp)
    try:
        return s.recv(2048)[42 + 16:42 + 20]
    except socket.timeout:
        return None


try:
    leased = []
    for index in range(1, 8):
        offered = discover(index)
        if offered is None:
            break
        leased.append(offered)
        if offered == host:
            print("FAIL: a guest was leased", printable(host), "-- the host's own address,",
                  "which host.containers.internal resolves to")
            sys.exit(1)
        if offered == gateway:
            print("FAIL: a guest was leased the gateway's own address", printable(gateway))
            sys.exit(1)

    # Exhausted rather than merely quiet: if the pool ran out at the first guest
    # this check would pass having proved nothing.
    if len(leased) != 4:
        print("FAIL: a /29 offered", len(leased), "leases where four addresses are free:",
              [printable(one) for one in leased])
        sys.exit(1)
    print("ok: pool ", len(leased), "guests leased .2 to .5, and the pool ran out before",
          printable(host))
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

# A forward's transport, which upstream spells as a prefix.
#
# `{"udp:127.0.0.1:5353": "192.168.127.2:53"}` is upstream's way of asking for a
# datagram forward. The parser here took the last colon-separated component of
# the host side as the port, and `udp:127.0.0.1:5353` ends in one -- so the
# prefix was skipped and every entry became a TCP forward. A DNS forward, which
# is the reason the prefix exists, listened on TCP and never saw a datagram.
#
# Read back through the control API rather than by connecting, because what went
# wrong is the transport and not the port: the wrong forward was listening on
# exactly the right number.
forward_transport_smoke() {
    CONFIG="${TMPDIR:-/tmp}/netstack-smoke-fwd-$$.json"
    CONTROL="${TMPDIR:-/tmp}/netstack-smoke-fwd-ctl-$$.sock"
    WIRE="${TMPDIR:-/tmp}/netstack-smoke-fwd-$$.sock"
    rm -f "$WIRE" "$CONTROL"
    cat > "$CONFIG" <<'JSON'
{"subnet":"192.168.127.0/24",
 "forwards":{"udp:127.0.0.1:0":"192.168.127.2:53","127.0.0.1:0":"192.168.127.2:80"}}
JSON
    # Two from the file and two from the command line, because the prefix has to
    # mean the same thing in both. It did not exist on the command line at all
    # until this was written, so an operator could ask for a datagram forward in
    # a file and not in the invocation beside it.
    "$binary" --listen-vfkit "$WIRE" --listen "unix://$CONTROL" --config "$CONFIG" \
        --forward "udp:0:192.168.127.2:5354" --forward "0:192.168.127.2:81" >/dev/null 2>&1 &
    GATEWAY=$!
    for _ in $(seq 1 120); do
        [[ -S "$CONTROL" ]] && break
        sleep 0.25
    done
    [[ -S "$CONTROL" ]] || { echo "FAIL: the forwarding gateway never came up"; return 1; }

    CONTROL="$CONTROL" python3 - <<'PY'
import json, os, subprocess, sys

answer = subprocess.run(
    ["curl", "--silent", "--fail-with-body", "--max-time", "10",
     "--unix-socket", os.environ["CONTROL"], "http://gateway/services/forwarder/all"],
    capture_output=True, text=True, timeout=20)
if answer.returncode != 0:
    print("FAIL: the forwarder list was not answered")
    sys.exit(1)
forwards = json.loads(answer.stdout)
protocols = sorted(entry.get("protocol", "?") for entry in forwards)
if protocols != ["tcp", "tcp", "udp", "udp"]:
    print("FAIL: two udp forwards and two tcp ones were asked for, one of each from",
          "the config file and one of each from the command line, and the gateway made",
          protocols, "-- the udp: prefix on the host side is what says which")
    sys.exit(1)
print("ok: fwd   the udp: prefix means the same in a config file and on the command line")
PY
    local outcome=$?
    kill "$GATEWAY" 2>/dev/null
    wait "$GATEWAY" 2>/dev/null
    GATEWAY=""
    rm -f "$WIRE" "$CONTROL" "$CONFIG"
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

# And the other direction: a host port held open for the guest.
forward_smoke 192.168.127.1 192.168.127.2 || status=1

# The third transport of the same route. tcp and udp are both driven -- udp
# because writing this check found that nothing drove it -- and unix was the one
# left.
forward_smoke 192.168.127.1 192.168.127.2 unix || status=1

# And the wire nobody drives.
stream_smoke 192.168.127.1 192.168.127.2 || status=1

# And a name the gateway has to ask somebody else about.
dns_forward_smoke 192.168.127.1 192.168.127.2 || status=1

# And the other transport.
udp_smoke 192.168.127.1 192.168.127.2 192.168.127.254 || status=1

# And the file an operator reads when nothing else is working.
pcap_smoke 192.168.127.1 192.168.127.2 || status=1

# And the wire that carries a network rather than a link.
switch_smoke 192.168.127.1 || status=1

# And a ping that actually leaves.
icmp_smoke 192.168.127.1 192.168.127.2 192.168.127.254 || status=1

# And a guest that arrives through the control API rather than over a socket.
connect_smoke 192.168.127.1 192.168.127.9 || status=1

# And the wire that has no socket at all.
stdio_smoke 192.168.127.1 192.168.127.2 || status=1

# And the wire that opens with a handshake.
vpnkit_smoke 192.168.127.1 192.168.127.2 || status=1

# And the socket a supervisor waits on.
notification_smoke || status=1

hypervisor_error_smoke || status=1

# And a host-side client dialled into the guest.
tunnel_smoke 192.168.127.1 192.168.127.2 || status=1

# And the address a guest must not reach by accident.
mtu_smoke || status=1

config_value_smoke || status=1

metadata_smoke 192.168.127.1 192.168.127.2 "" no || status=1
metadata_smoke 192.168.127.1 192.168.127.2 "--ec2-metadata-access" yes || status=1

# And what it says about a guest that has stopped reading.
backpressure_smoke || status=1

# And that the pool keeps back what the gateway answers for.
pool_smoke || status=1

# And that a forward's transport survives the config file.
forward_transport_smoke || status=1

exit $status
