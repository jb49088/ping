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
import sys

ICMP_ECHO_REQUEST = 8


def create_packet() -> bytes:
    """Create an ICMP ping request packet."""
    header = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, 0, 0, 1, 1)
    data = b"\x00" * 56
    chksum = calculate_checksum(header + data)
    header = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, 0, chksum, 1, 1)

    return header + data


def calculate_checksum(packet: bytes) -> int:
    """Calculate the 16-bit one's complement checksum of a packet."""
    total = 0
    # Sum 16 bit words
    for i in range(0, len(packet), 2):
        word = (packet[i] << 8) + (packet[i + 1] if i + 1 < len(packet) else 0)
        total += word

    # Add carry to right side
    total = (total >> 16) + (total & 0xFFFF)

    # Perform one's complement
    total = ~total & 0xFFFF

    return total


def ping() -> None:
    destination = "8.8.8.8"

    try:
        host = socket.gethostbyname(destination)
    except socket.gaierror:
        print("\nAddress resolution failed. Bad hostname.\n")
        sys.exit(1)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except PermissionError:
        print("\nICMP messages can only be sent from processess running as root.\n")
        sys.exit(1)

    packet = create_packet()
    print(f"\nPING {destination} ({host}) {len(packet)} bytes of data.\n")
    sock.sendto(packet, (destination, 1))


if __name__ == "__main__":
    ping()
