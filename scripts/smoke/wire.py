"""The few things every frame-smoke case needs, in one place.

Each case in `frame-smoke.sh` is a self-contained Python program, and each one
was growing its own copy of these: five identical checksum routines, and the
same address parsing twenty-seven times. None of the copies had drifted yet.
They would have -- a fix reaching one of five is the ordinary way that happens --
and the failure would be silent, because a case whose checksum is wrong does not
fail, it stops testing anything: every packet it sends is discarded before it
reaches the code the case is about.

Only what is genuinely the same in every case is here. The frame builders are
not: they differ in which way round the addresses go and which side is speaking,
which is per-case wiring rather than shared logic, and unifying them would mean
changing what some of the cases test in order to tidy them.
"""


def address(text):
    """"192.168.127.1" -> the four bytes that go in a header."""
    return bytes(int(part) for part in text.split("."))


def printable(raw):
    """The inverse, for a message a person has to read."""
    return ".".join(map(str, raw))


def ones_complement(data):
    """The internet checksum, as every header here computes it.

    Wrong here means every packet a case sends is dropped before it arrives,
    which does not look like a broken check -- it looks like a gateway that
    ignored the request.
    """
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    while total >> 16:
        total = (total >> 16) + (total & 0xFFFF)
    return (~total) & 0xFFFF


# The frames a booting guest sends, built once here rather than in each case
# that needs them. Rule 8 in `scripts/conventions.sh` is about exactly this: a
# case with its own copy of a checksum does not fail when the copy is wrong, it
# stops testing anything, because every packet it sends is discarded before it
# reaches the code the case is about.


def ipv4(source, destination, protocol, payload, identifier=0):
    """An IPv4 packet, with its header checksum filled in."""
    header = bytearray(
        b"\x45\x00" + (20 + len(payload)).to_bytes(2, "big")
        + identifier.to_bytes(2, "big") + b"\x00\x00\x40" + bytes([protocol])
        + b"\x00\x00" + source + destination
    )
    header[10:12] = ones_complement(bytes(header)).to_bytes(2, "big")
    return bytes(header) + payload


def ethernet(destination_mac, source_mac, kind, payload):
    return destination_mac + source_mac + kind + payload


def udp(source, destination, source_port, destination_port, payload):
    """A UDP datagram inside IPv4. The checksum is left zero, which IPv4 allows
    and every stack accepts, because the point here is the addresses."""
    datagram = (
        source_port.to_bytes(2, "big") + destination_port.to_bytes(2, "big")
        + (8 + len(payload)).to_bytes(2, "big") + b"\x00\x00" + payload
    )
    return ipv4(source, destination, 17, datagram)


def arp_request(sender_mac, sender_ip, target_ip):
    return ethernet(
        b"\xff" * 6, sender_mac, b"\x08\x06",
        b"\x00\x01\x08\x00\x06\x04\x00\x01" + sender_mac + sender_ip + bytes(6) + target_ip)


def dhcp(mac, kind, requested=None, server=None, transaction=b"\x39\x03\x1f\x8b"):
    """A DHCP DISCOVER (kind 1) or REQUEST (kind 3), broadcast as a guest sends
    it: from 0.0.0.0, because the address being asked for is not held yet."""
    options = b"\x35\x01" + bytes([kind])
    if requested is not None:
        options += b"\x32\x04" + requested
    if server is not None:
        options += b"\x36\x04" + server
    options += b"\xff"
    payload = (
        b"\x01\x01\x06\x00" + transaction + bytes(8) + bytes(4) + bytes(4) + bytes(4)
        + mac + bytes(10) + bytes(192) + b"\x63\x82\x53\x63" + options
    )
    return ethernet(
        b"\xff" * 6, mac, b"\x08\x00",
        udp(bytes(4), b"\xff\xff\xff\xff", 68, 67, payload))


def dhcp_options(frame):
    """The options in a DHCP reply, as {code: bytes}, and the address offered."""
    body = frame[14:]
    payload = body[(body[0] & 0x0F) * 4 + 8:]
    offered = payload[16:20]
    options, raw = {}, payload[240:]
    index = 0
    while index < len(raw) and raw[index] != 0xFF:
        code, length = raw[index], raw[index + 1]
        options[code] = raw[index + 2:index + 2 + length]
        index += 2 + length
    return offered, options


def dns_query(name, source, destination, source_port, transaction=b"\x2b\x2b"):
    """An A query for `name`, as a guest's resolver sends it."""
    labels = b"".join(bytes([len(part)]) + part for part in name.encode().split(b".")) + b"\x00"
    question = (
        transaction + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + labels
        + b"\x00\x01\x00\x01"
    )
    return udp(source, destination, source_port, 53, question)


def dns_answer(frame):
    """The first A record in a reply, or None."""
    body = frame[14:]
    payload = body[(body[0] & 0x0F) * 4 + 8:]
    if len(payload) < 12 or int.from_bytes(payload[6:8], "big") < 1:
        return None
    index = 12
    while index < len(payload) and payload[index] != 0:
        index += payload[index] + 1
    index += 5  # the terminating zero, then type and class
    # Name pointer, type, class, ttl, length, then the address.
    return payload[index + 12:index + 16] or None

