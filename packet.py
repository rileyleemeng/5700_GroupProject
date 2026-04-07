import struct
from constants import HEADER_LEN


class Packet:
    """
    SRFT application packet format:
    pkt_type: 1 byte
    seq: 4 bytes
    ack: 4 bytes
    length: 2 bytes
    checksum: 2 bytes
    payload: variable length
    """

    def __init__(self, pkt_type, seq, ack, payload=b''):
        self.pkt_type = pkt_type
        self.seq = seq
        self.ack = ack
        self.payload = payload
        self.length = len(payload)
        self.checksum = 0


def compute_checksum(data: bytes) -> int:
    """16-bit one's-complement checksum for the SRFT packet body/header."""
    if len(data) % 2 == 1:
        data += b'\x00'

    total = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i + 1]
        total += word
        total = (total & 0xFFFF) + (total >> 16)

    return (~total) & 0xFFFF


def encode(packet: Packet) -> bytes:
    """Convert a Packet object into bytes for sending."""
    header_without_checksum = struct.pack(
        '!BIIH',
        packet.pkt_type,
        packet.seq,
        packet.ack,
        packet.length,
    )

    temp = header_without_checksum + packet.payload
    packet.checksum = compute_checksum(temp)

    return struct.pack(
        '!BIIHH',
        packet.pkt_type,
        packet.seq,
        packet.ack,
        packet.length,
        packet.checksum,
    ) + packet.payload


def decode(data: bytes):
    """Convert bytes back into a Packet object for receiving."""
    if len(data) < HEADER_LEN:
        return None

    header = data[:HEADER_LEN]
    pkt_type, seq, ack, length, checksum = struct.unpack('!BIIHH', header)

    if len(data) != HEADER_LEN + length:
        return None

    payload = data[HEADER_LEN:HEADER_LEN + length]
    temp = struct.pack('!BIIH', pkt_type, seq, ack, length) + payload
    computed = compute_checksum(temp)

    if computed != checksum:
        return None

    pkt = Packet(pkt_type, seq, ack, payload)
    pkt.checksum = checksum
    return pkt
