# ================================================================================
# =                                     PING                                     =
# ================================================================================

"""
ICMP Echo Request/Reply Packet Structure
----------------------------------------
Header: 8 bytes
  Type:       1 byte
  Code:       1 byte
  Checksum:   2 bytes
  Identifier: 2 bytes
  Sequence:   2 bytes

Data: 56 bytes (POSIX default)

Total: 64 bytes
"""

import argparse
import random
import select
import socket
import struct
import time

DATA_LEN = 56

TYPE = 8
IDENTIFIER = random.randint(0, 0xFFFF)


def parse_args():
    parser = argparse.ArgumentParser()

    parser.add_argument("host", help="Host to ping.")
    parser.add_argument(
        "-i", "--interval", type=float, default=1.0, help="Interval between pings."
    )

    args = parser.parse_args()

    return args


def create_packet(sequence: int) -> bytes:
    """Create an ICMP ping request packet."""
    header = struct.pack("!BBHHH", TYPE, 0, 0, IDENTIFIER, sequence)
    data = b"\x00" * DATA_LEN
    checksum = calculate_checksum(header + data)
    header = struct.pack("!BBHHH", TYPE, 0, checksum, IDENTIFIER, sequence)

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
    sock: socket.socket, time_sent: float, timeout: int
) -> tuple[float | None, int | None, int | None]:
    """Receive packet from destination."""
    time_left = timeout
    while True:
        start_select = time.perf_counter()
        ready = select.select([sock], [], [], time_left)
        end_select = time.perf_counter() - start_select
        time_left -= end_select

        if not ready[0]:  # Timeout
            return None, None, None

        time_recieved = time.perf_counter()
        packet, _ = sock.recvfrom(1024)

        header = packet[20:28]
        _, _, _, identifier, sequence = struct.unpack("!BBHHH", header)

        # Check if packet belongs to us
        if identifier == IDENTIFIER:
            ttl = packet[8]
            return time_recieved - time_sent, ttl, sequence

        if time_left <= 0:
            return None, None, None


def ping() -> None:
    args = parse_args()
    hostname = args.host
    interval = args.interval

    try:
        address = socket.gethostbyname(hostname)
    except socket.gaierror:
        print("\nAddress resolution failed.\n")
        return
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except PermissionError:
        print("\nICMP messages can only be sent from processess running as root.\n")
        return

    destination = address if address == hostname else f"{hostname} ({address})"

    print(f"\nPinging {destination} with {DATA_LEN} bytes of data:\n")

    loop_sequence = 1
    sent = 0
    received = 0
    rtts = []

    try:
        while True:
            packet = create_packet(loop_sequence)
            time_sent = send_packet(sock, packet, address)
            sent += 1
            rtt, ttl, sequence = receive_packet(sock, time_sent, 1)
            if rtt is None:
                print(f"Request timeout for icmp_seq={loop_sequence}")
            else:
                print(
                    f"{len(packet)} bytes from {destination}: icmp_seq={sequence} ttl={ttl} time={rtt * 1000:.2f} ms"
                )
                rtts.append(rtt)
                received += 1
            loop_sequence += 1
            time.sleep(interval)
    except KeyboardInterrupt:
        print(f"\nPing statistics for {destination}:")
        loss_pct = ((sent - received) / sent) * 100 if sent > 0 else 0
        print(
            f"\nPackets: Sent = {sent}, Received = {received}, Lost = {sent - received} ({loss_pct:.2f}% lost)"
        )
        min_rtt = min(rtts) * 1000
        max_rtt = max(rtts) * 1000
        avg_rtt = (sum(rtts) / len(rtts)) * 1000
        print(
            f"Round trip times: Min: {min_rtt:.2f} ms Max: {max_rtt:.2f} ms Avg: {avg_rtt:.2f} ms\n"
        )
        sock.close()
        return


if __name__ == "__main__":
    ping()
