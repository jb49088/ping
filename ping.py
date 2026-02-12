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

import random
import select
import socket
import struct
import sys
import time

DATA_LEN = 56

TYPE = 8
IDENTIFIER = random.randint(0, 0xFFFF)


def create_packet() -> bytes:
    """Create an ICMP ping request packet."""
    header = struct.pack("!BBHHH", TYPE, 0, 0, IDENTIFIER, 1)
    data = b"\x00" * DATA_LEN
    chksum = calculate_checksum(header + data)
    header = struct.pack("!BBHHH", TYPE, 0, chksum, IDENTIFIER, 1)

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


def send_packet(sock: socket.socket, packet: bytes, destination: str) -> float:
    time_sent = time.perf_counter()
    sock.sendto(packet, (destination, 1))

    return time_sent


def receive_packet(
    sock: socket.socket, destination: str, time_sent: float, timeout: int
) -> float | None:
    time_left = timeout
    while True:
        ready = select.select([sock], [], [], time_left)

        if not ready[0]:  # Timeout
            return

        time_recieved = time.perf_counter()
        packet, address = sock.recvfrom(1024)

        header = packet[20:28]
        _, _, _, identifier, sequence = struct.unpack("!BBHHH", header)

        # Check if packet belongs to us
        if identifier == IDENTIFIER and address[0] == destination:
            return time_recieved - time_sent

        time_left -= time_recieved

        if time_left <= 0:
            return


def ping() -> None:
    destination = "8.8.8.8"
    timeout = 1

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
    print(f"\nPING {destination} ({host}) {DATA_LEN} bytes of data.\n")
    time_sent = send_packet(sock, packet, destination)
    rtt = receive_packet(sock, destination, time_sent, timeout)
    if rtt is None:
        print("Request timeout for icmp_seq=1")
    else:
        print(
            f"{len(packet)} bytes from {host}: icmp_seq=1 ttl=foobar time={rtt * 1000:.2f} ms"
        )


if __name__ == "__main__":
    ping()
