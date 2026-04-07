import argparse
import hashlib
import json
import os
import socket
import sys
from typing import Optional, Tuple

from constants import (
    ACK,
    DATA,
    DEFAULT_CLIENT_PORT,
    DEFAULT_SERVER_PORT,
    END,
    ERROR,
    MAX_IDLE_TIMEOUTS,
    RAW_RECV_BUFFER,
    REQUEST,
    TIMEOUT,
)
from packet import Packet, decode, encode
from raw_utils import build_ipv4_udp_packet, parse_ipv4_udp_packet


DEFAULT_SERVER_IP = '127.0.0.1'
DEFAULT_CLIENT_IP = '127.0.0.1'


class SRFTUDPClient:
    def __init__(
        self,
        server_ip: str,
        server_port: int,
        client_ip: str,
        client_port: int,
        timeout: float = TIMEOUT,
        max_idle_timeouts: int = MAX_IDLE_TIMEOUTS,
    ):
        self.server_ip = server_ip
        self.server_port = server_port
        self.client_ip = client_ip
        self.client_port = client_port
        self.timeout = timeout
        self.max_idle_timeouts = max(1, max_idle_timeouts)

        self.send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        self.send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        self.recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        self.recv_sock.settimeout(self.timeout)

        self.expected_seq = 0
        self.buffer = {}
        self.last_ack_sent = -1

        # new: request retransmission support
        self.requested_filename: Optional[str] = None
        self.transfer_started = False

    def _send_srft_packet(self, packet: Packet) -> None:
        raw_packet = build_ipv4_udp_packet(
            src_ip=self.client_ip,
            dst_ip=self.server_ip,
            src_port=self.client_port,
            dst_port=self.server_port,
            payload=encode(packet),
        )
        self.send_sock.sendto(raw_packet, (self.server_ip, 0))

    def _recv_srft_packet(self) -> Tuple[Optional[Packet], Optional[Tuple[str, int]]]:
        while True:
            raw_data, _ = self.recv_sock.recvfrom(RAW_RECV_BUFFER)
            parsed = parse_ipv4_udp_packet(raw_data)
            if parsed is None:
                continue

            src_ip, dst_ip, src_port, dst_port, payload = parsed
            if src_ip != self.server_ip or dst_ip != self.client_ip:
                continue
            if src_port != self.server_port or dst_port != self.client_port:
                continue

            return decode(payload), (src_ip, src_port)

    def request_file(self, filename: str, retransmit: bool = False) -> None:
        self.requested_filename = filename
        pkt = Packet(REQUEST, seq=0, ack=0, payload=filename.encode())
        self._send_srft_packet(pkt)

        if retransmit:
            print(f'[CLIENT] Retransmitted REQUEST for file: {filename}')
        else:
            print(f'[CLIENT] Requested file: {filename}')

    def send_ack(self, force: bool = False) -> None:
        if not force and self.last_ack_sent == self.expected_seq:
            return

        ack_pkt = Packet(ACK, seq=0, ack=self.expected_seq, payload=b'')
        self._send_srft_packet(ack_pkt)
        self.last_ack_sent = self.expected_seq
        print(f'[CLIENT] Sent cumulative ACK={self.expected_seq}')

    def receive_file(self, output_filename: str) -> bool:
        file_data = bytearray()
        idle_timeouts = 0
        sender_md5 = None
        sender_size = None
        sender_name = None

        while True:
            try:
                pkt, _ = self._recv_srft_packet()
                idle_timeouts = 0

                if pkt is None:
                    print('[CLIENT] Corrupted packet ignored')
                    if self.transfer_started:
                        self.send_ack(force=True)
                    else:
                        if self.requested_filename:
                            self.request_file(self.requested_filename, retransmit=True)
                    continue

                if pkt.pkt_type == DATA:
                    self.transfer_started = True
                    print(f'[CLIENT] Received DATA seq={pkt.seq}, len={pkt.length}')
                    advanced = False

                    if pkt.seq == self.expected_seq:
                        file_data.extend(pkt.payload)
                        self.expected_seq += 1
                        advanced = True

                        while self.expected_seq in self.buffer:
                            file_data.extend(self.buffer.pop(self.expected_seq))
                            self.expected_seq += 1

                    elif pkt.seq > self.expected_seq:
                        if pkt.seq not in self.buffer:
                            self.buffer[pkt.seq] = pkt.payload
                            print(f'[CLIENT] Buffered out-of-order seq={pkt.seq}')

                    else:
                        print(f'[CLIENT] Duplicate seq={pkt.seq} ignored')

                    self.send_ack(force=not advanced)

                elif pkt.pkt_type == END:
                    self.transfer_started = True
                    print('[CLIENT] Received END')
                    try:
                        metadata = json.loads(pkt.payload.decode('utf-8')) if pkt.payload else {}
                    except json.JSONDecodeError:
                        metadata = {}

                    sender_md5 = metadata.get('md5')
                    sender_size = metadata.get('size')
                    sender_name = metadata.get('name')

                    with open(output_filename, 'wb') as f:
                        f.write(file_data)

                    local_md5 = hashlib.md5(file_data).hexdigest()
                    local_size = len(file_data)
                    md5_match = sender_md5 == local_md5 if sender_md5 else False

                    print(f'[CLIENT] File saved as: {output_filename}')
                    print(f'[CLIENT] Sender file name: {sender_name}')
                    print(f'[CLIENT] Sender size: {sender_size}, local size: {local_size}')
                    print(f'[CLIENT] Sender MD5: {sender_md5}')
                    print(f'[CLIENT] Local  MD5: {local_md5}')
                    print(f'[CLIENT] MD5 match: {md5_match}')

                    with open('client_report.txt', 'w') as f:
                        f.write(
                            f'- Output file: {output_filename}\n'
                            f'- Sender file name: {sender_name}\n'
                            f'- Sender size: {sender_size}\n'
                            f'- Local size: {local_size}\n'
                            f'- Sender MD5: {sender_md5}\n'
                            f'- Local MD5: {local_md5}\n'
                            f'- MD5 match: {md5_match}\n'
                        )

                    self.send_ack(force=True)
                    return md5_match and (sender_size == local_size if sender_size is not None else True)

                elif pkt.pkt_type == ERROR:
                    self.transfer_started = True
                    try:
                        message = pkt.payload.decode('utf-8', errors='replace')
                    except Exception:
                        message = 'server returned ERROR'
                    print(f'[CLIENT] Server error: {message}')
                    return False

                else:
                    print(f'[CLIENT] Unknown packet type={pkt.pkt_type}')

            except socket.timeout:
                idle_timeouts += 1
                print(f'[CLIENT] Timeout waiting for server ({idle_timeouts}/{self.max_idle_timeouts})')

                if not self.transfer_started:
                    if self.requested_filename:
                        self.request_file(self.requested_filename, retransmit=True)
                else:
                    self.send_ack(force=True)

                if idle_timeouts >= self.max_idle_timeouts:
                    print('[CLIENT] Transfer failed: too many timeouts')
                    return False

    def close(self) -> None:
        self.send_sock.close()
        self.recv_sock.close()


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description='SRFT raw-socket UDP client')
    parser.add_argument('filename')
    parser.add_argument('server_ip', nargs='?', default=DEFAULT_SERVER_IP)
    parser.add_argument('client_ip', nargs='?', default=DEFAULT_CLIENT_IP)
    parser.add_argument('--server-port', type=int, default=DEFAULT_SERVER_PORT)
    parser.add_argument('--client-port', type=int, default=DEFAULT_CLIENT_PORT)
    parser.add_argument('--timeout', type=float, default=TIMEOUT)
    parser.add_argument('--max-idle-timeouts', type=int, default=MAX_IDLE_TIMEOUTS)
    parser.add_argument('--output', default=None, help='output file path; default is downloaded_<filename>')
    return parser


def main() -> None:
    args = build_arg_parser().parse_args()
    output_filename = args.output or ('downloaded_' + os.path.basename(args.filename))

    client = SRFTUDPClient(
        server_ip=args.server_ip,
        server_port=args.server_port,
        client_ip=args.client_ip,
        client_port=args.client_port,
        timeout=args.timeout,
        max_idle_timeouts=args.max_idle_timeouts,
    )

    try:
        client.request_file(args.filename)
        ok = client.receive_file(output_filename)
        if not ok:
            sys.exit(2)
    finally:
        client.close()


if __name__ == '__main__':
    main()