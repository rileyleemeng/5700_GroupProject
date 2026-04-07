import random
import socket
import struct
from typing import Optional, Tuple


IP_HEADER_LEN = 20
UDP_HEADER_LEN = 8


def internet_checksum(data: bytes) -> int:
    """Standard Internet checksum used for IPv4 header checksum."""
    if len(data) % 2 == 1:
        data += b'\x00'

    total = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i + 1]
        total += word
        total = (total & 0xFFFF) + (total >> 16)

    return (~total) & 0xFFFF


def build_ip_header(src_ip: str, dst_ip: str, udp_payload_len: int, identification: Optional[int] = None) -> bytes:
    version = 4
    ihl = 5
    version_ihl = (version << 4) + ihl
    tos = 0
    total_length = IP_HEADER_LEN + UDP_HEADER_LEN + udp_payload_len
    identification = random.randint(0, 65535) if identification is None else identification
    flags_fragment_offset = 0
    ttl = 64
    protocol = socket.IPPROTO_UDP
    header_checksum = 0
    src_bytes = socket.inet_aton(src_ip)
    dst_bytes = socket.inet_aton(dst_ip)

    header_wo_checksum = struct.pack(
        '!BBHHHBBH4s4s',
        version_ihl,
        tos,
        total_length,
        identification,
        flags_fragment_offset,
        ttl,
        protocol,
        header_checksum,
        src_bytes,
        dst_bytes,
    )

    header_checksum = internet_checksum(header_wo_checksum)

    return struct.pack(
        '!BBHHHBBH4s4s',
        version_ihl,
        tos,
        total_length,
        identification,
        flags_fragment_offset,
        ttl,
        protocol,
        header_checksum,
        src_bytes,
        dst_bytes,
    )


def build_udp_header(src_port: int, dst_port: int, payload: bytes) -> bytes:
    length = UDP_HEADER_LEN + len(payload)
    checksum = 0  # acceptable here for this project phase; SRFT carries its own checksum
    return struct.pack('!HHHH', src_port, dst_port, length, checksum)


def build_ipv4_udp_packet(src_ip: str, dst_ip: str, src_port: int, dst_port: int, payload: bytes) -> bytes:
    udp_header = build_udp_header(src_port, dst_port, payload)
    ip_header = build_ip_header(src_ip, dst_ip, len(payload))
    return ip_header + udp_header + payload


def parse_ipv4_udp_packet(raw_data: bytes) -> Optional[Tuple[str, str, int, int, bytes]]:
    if len(raw_data) < IP_HEADER_LEN + UDP_HEADER_LEN:
        return None

    first_byte = raw_data[0]
    version = first_byte >> 4
    ihl = first_byte & 0x0F
    if version != 4:
        return None

    ip_header_len = ihl * 4
    if len(raw_data) < ip_header_len + UDP_HEADER_LEN:
        return None

    ip_header = raw_data[:ip_header_len]
    iph = struct.unpack('!BBHHHBBH4s4s', ip_header[:20])
    protocol = iph[6]
    if protocol != socket.IPPROTO_UDP:
        return None

    src_ip = socket.inet_ntoa(iph[8])
    dst_ip = socket.inet_ntoa(iph[9])

    udp_start = ip_header_len
    udp_header = raw_data[udp_start:udp_start + UDP_HEADER_LEN]
    src_port, dst_port, udp_len, _ = struct.unpack('!HHHH', udp_header)

    payload_start = udp_start + UDP_HEADER_LEN
    payload_end = udp_start + udp_len
    if payload_end > len(raw_data):
        return None

    payload = raw_data[payload_start:payload_end]
    return src_ip, dst_ip, src_port, dst_port, payload
