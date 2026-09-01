"""Print the MTU the vpnkit handshake tells a guest, or nothing if it fails.

Split out of the case that uses it rather than written inline, because the case
runs the handshake four times against four different gateways and the handshake
is fixed-size and unforgiving: 49 bytes echoed, 41 written, 258 read.

Silence on any failure is deliberate. The caller compares the printed value
against what it expected, so a handshake that goes wrong has to produce
something that cannot be mistaken for an MTU.
"""

import os
import socket
import struct
import sys


def told(path):
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    connection.settimeout(10)
    try:
        connection.connect(path)

        def exactly(count):
            collected = b""
            while len(collected) < count:
                chunk = connection.recv(count - len(collected))
                if not chunk:
                    raise OSError("the wire closed during the handshake")
                collected += chunk
            return collected

        initial = b"VMN3T" + bytes(44)
        connection.sendall(initial)
        if exactly(49) != initial:
            raise OSError("the init message was not echoed back verbatim")
        connection.sendall(bytes([1]) + b"1e0a4f1a-0000-4000-8000-0123456789ab" + bytes(4))
        return struct.unpack("<H", exactly(258)[1:3])[0]
    finally:
        connection.close()


try:
    print(told(os.environ["MTU_WIRE"]))
except OSError:
    sys.exit(1)
