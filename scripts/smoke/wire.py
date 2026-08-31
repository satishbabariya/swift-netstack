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
