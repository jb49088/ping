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
import time

DATA_LEN = 56

TYPE = 8
IDENTIFIER = random.randint(0, 0xFFFF)


def create_packet(sequence: int) -> bytes:
    """Create an ICMP ping request packet."""
    header = struct.pack("!BBHHH", TYPE, 0, 0, IDENTIFIER, sequence)
    data = b"\x00" * DATA_LEN
    chksum = calculate_checksum(header + data)
    header = struct.pack("!BBHHH", TYPE, 0, chksum, IDENTIFIER, sequence)

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
    """Send packet to destination."""
    time_sent = time.perf_counter()
    sock.sendto(packet, (destination, 1))

    return time_sent


def receive_packet(
    sock: socket.socket, destination: str, time_sent: float, timeout: int
) -> tuple[float | None, int | None, int | None]:
    """Receive packet from destination, check if packet belongs to us, then calculate round trip time."""
    time_left = timeout
    while True:
        start_select = time.perf_counter()
        ready = select.select([sock], [], [], time_left)
        end_select = time.perf_counter() - start_select
        time_left -= end_select

        if not ready[0]:  # Timeout
            return None, None, None

        time_recieved = time.perf_counter()
        packet, address = sock.recvfrom(1024)

        header = packet[20:28]
        _, _, _, identifier, sequence = struct.unpack("!BBHHH", header)

        # Check if packet belongs to us
        if identifier == IDENTIFIER and address[0] == destination:
            ttl = packet[8]
            return time_recieved - time_sent, ttl, sequence

        if time_left <= 0:
            return None, None, None


def ping() -> None:
    destination = "8.8.8.8"
    timeout = 1

    try:
        host = socket.gethostbyname(destination)
    except socket.gaierror:
        print("\nAddress resolution failed. Bad hostname.\n")
        return
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except PermissionError:
        print("\nICMP messages can only be sent from processess running as root.\n")
        return

    print(f"\nPinging {destination} ({host}) with {DATA_LEN} bytes of data:\n")
    try:
        loop_sequence = 1
        while True:
            packet = create_packet(loop_sequence)
            time_sent = send_packet(sock, packet, destination)
            rtt, ttl, sequence = receive_packet(sock, destination, time_sent, timeout)
            if rtt is None:
                print(f"Request timeout for icmp_seq={sequence}")
            else:
                print(
                    f"{len(packet)} bytes from {host}: icmp_seq={sequence} ttl={ttl} time={rtt * 1000:.2f} ms"
                )
            loop_sequence += 1
    except KeyboardInterrupt:
        print(f"\nPing statistics for {host}:\n")
        sock.close()
        return


if __name__ == "__main__":
    ping()
