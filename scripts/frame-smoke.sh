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
GATEWAY=""
LISTENER=""
ECHO_PID=""
cleanup() {
    [[ -n "$GATEWAY" ]] && kill "$GATEWAY" 2>/dev/null
    [[ -n "$ECHO_PID" ]] && kill "$ECHO_PID" 2>/dev/null
    rm -f "$WIRE" "$CONFIG" "$CONTROL" "$LISTENER" "$RESOLVER" "$CAPTURE" "${LISTENER:-/nonexistent}.port"
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
    shift 2
    CONTROL="${TMPDIR:-/tmp}/netstack-smoke-control-$$.sock"
    WIRE="${TMPDIR:-/tmp}/netstack-smoke-$$.sock"
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

    EXPECTED="$expected" GUEST="$guest" WIRE="$WIRE" CONTROL="$CONTROL" ARGS="$*" python3 - <<'PY'
import json, os, socket, subprocess, sys, threading

wire = os.environ["WIRE"]
control = os.environ["CONTROL"]
gateway = bytes(int(part) for part in os.environ["EXPECTED"].split("."))
guest = bytes(int(part) for part in os.environ["GUEST"].split("."))
described = os.environ.get("ARGS") or "(defaults)"
guest_text = ".".join(map(str, guest))

GUEST_MAC = bytes.fromhex("5a94efe4bc00")
GATEWAY_MAC = bytes.fromhex("5a94efe40cee")
GUEST_PORT = 8080
SYN, ACK, PSH, FIN, RST = 0x02, 0x10, 0x08, 0x01, 0x04

client_path = wire + ".client"
s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
s.bind(client_path)


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


def expose():
    """Ask for a host port, bound to whatever is free, delivered to the guest."""
    request = json.dumps({
        "local": "127.0.0.1:0", "remote": f"{guest_text}:{GUEST_PORT}", "protocol": "tcp",
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
    return int(body["local"].rsplit(":", 1)[1])


body = b"the host reached the guest"
received = {}


def host_side(port):
    """An ordinary client, on the host, that knows nothing about any of this."""
    try:
        connection = socket.create_connection(("127.0.0.1", port), timeout=15)
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
    print("ok: fwd   host port", port, "->", f"{guest_text}:{GUEST_PORT}", "for", described)

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

expected = bytes(int(part) for part in os.environ["EXPECTED"].split("."))
guest = bytes(int(part) for part in os.environ["GUEST"].split("."))
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
    print("ok: qemu  ARP", ".".join(map(str, expected)),
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

wire = os.environ["WIRE"]
gateway = bytes(int(part) for part in os.environ["EXPECTED"].split("."))
guest = bytes(int(part) for part in os.environ["GUEST"].split("."))
described = os.environ.get("ARGS") or "(defaults)"
src = bytes.fromhex("5a94efe4bc00")

client_path = wire + ".client"
s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
s.bind(client_path)


def ones_complement(data):
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    while total >> 16:
        total = (total >> 16) + (total & 0xFFFF)
    return (~total) & 0xFFFF


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
            print("FAIL: the guest was told", ".".join(map(str, resolved)),
                  "rather than what the upstream said, for", described)
            sys.exit(1)
        print("ok: dns   a forwarded name resolved to",
              ".".join(map(str, resolved)), "for", described)
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

wire = os.environ["WIRE"]
guest = bytes(int(part) for part in os.environ["GUEST"].split("."))
host = bytes(int(part) for part in os.environ["EXPECTED_HOST"].split("."))
port = int(os.environ["PORT"])
described = os.environ.get("ARGS") or "(defaults)"
src = bytes.fromhex("5a94efe4bc00")

client_path = wire + ".client"
s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
s.bind(client_path)


def ones_complement(data):
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    while total >> 16:
        total = (total >> 16) + (total & 0xFFFF)
    return (~total) & 0xFFFF


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

expected = bytes(int(part) for part in os.environ["EXPECTED"].split("."))
guest = bytes(int(part) for part in os.environ["GUEST"].split("."))
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

described = os.environ.get("ARGS") or "(defaults)"
expected = bytes(int(part) for part in os.environ["EXPECTED"].split("."))
guest = bytes(int(part) for part in os.environ["GUEST"].split("."))
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

gateway = bytes(int(part) for part in os.environ["EXPECTED"].split("."))
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

wire = os.environ["WIRE"]
guest = bytes(int(part) for part in os.environ["GUEST"].split("."))
host = bytes(int(part) for part in os.environ["EXPECTED_HOST"].split("."))
described = os.environ.get("ARGS") or "(defaults)"
src = bytes.fromhex("5a94efe4bc00")


def ones_complement(data):
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    while total >> 16:
        total = (total >> 16) + (total & 0xFFFF)
    return (~total) & 0xFFFF


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

gateway = bytes(int(part) for part in os.environ["EXPECTED"].split("."))
guest = bytes(int(part) for part in os.environ["GUEST"].split("."))
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

exit $status
