# ================================================================================
# =                                     PING                                     =
# ================================================================================

"""
ICMP Echo Request/Reply Packet Structure
-----------------------------------------
Header: 8 bytes
  Type:       1 byte
  Code:       1 byte
  Checksum:   2 bytes
  Identifier: 2 bytes
  Sequence:   2 bytes

Data: 56 bytes (POSIX default)

Total: 64 bytes
"""

import socket
import struct

ICMP_ECHO_REQUEST = 8


def checksum(packet):
    total = 0
    # Sum 16 bit words
    for i in range(0, len(packet), 2):
        word = (packet[i] << 8) + packet[i + 1] if i + 1 < len(packet) else 0
        total += word

    return total


def ping():
    dest = "www.google.com"
    header = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, 0, 0, 1, 1)
    data = b"\x00" * 56
    chksum = checksum(header + data)
    header = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, 0, chksum, 1, 1)

    # sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    # sock.sendto(packet, (dest, 1))


if __name__ == "__main__":
    ping()
