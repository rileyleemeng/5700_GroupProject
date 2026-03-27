import struct
from constants import DATA, HEADER_LEN

class Packet:
    '''
    Packet format:
    pkt_type: 1 byte
    seq: 4 bytes
    ack: 4 bytes
    length: 2 bytes
    checksum: 2 bytes
    payload: variable length
    '''

    def __init__(self, pkt_type, seq, ack, payload=b''):
        self.pkt_type = pkt_type
        self.seq = seq
        self.ack = ack
        self.payload = payload
        self.length = len(payload)
        self.checksum = 0


def compute_checksum(data):
    '''
    Compute checksum and keep it within 2 bytes (0 to 65535).
    '''
    return sum(data) % 65536


def encode(packet):
    '''
    Convert a Packet object into bytes for sending.
    '''

    # Build header without checksum first
    header = struct.pack(
        '!BIIH',
        packet.pkt_type,
        packet.seq,
        packet.ack,
        packet.length
    )

    # Compute checksum over header + payload
    temp = header + packet.payload
    checksum = compute_checksum(temp)
    packet.checksum = checksum

    # Build final packet with checksum
    final_packet = struct.pack(
        '!BIIHH',
        packet.pkt_type,
        packet.seq,
        packet.ack,
        packet.length,
        checksum
    ) + packet.payload

    return final_packet


def decode(data):
    '''
    Convert bytes back into a Packet object for receiving.
    '''

    # Check whether the data is long enough for a full header
    if len(data) < HEADER_LEN:
        return None

    # Extract header
    header = data[:HEADER_LEN]
    pkt_type, seq, ack, length, checksum = struct.unpack('!BIIHH', header)

    # Check whether the payload is complete
    if len(data) != HEADER_LEN + length:
        return None

    # Extract payload
    payload = data[HEADER_LEN:HEADER_LEN + length]

    # Recompute checksum
    temp = struct.pack('!BIIH', pkt_type, seq, ack, length) + payload
    computed = compute_checksum(temp)

    # Validate checksum
    if computed != checksum:
        return None

    # Rebuild Packet object
    pkt = Packet(pkt_type, seq, ack, payload)
    pkt.checksum = checksum
    return pkt
