import argparse
import hashlib
import json
import os
import socket
import threading
import time
from typing import Dict, List, Optional, Tuple

from constants import (
    ACK,
    ACK_POLL_INTERVAL,
    DATA,
    DEFAULT_SERVER_PORT,
    END,
    END_RETRIES,
    ERROR,
    MAX_PAYLOAD,
    MAX_RETRIES,
    RAW_RECV_BUFFER,
    REQUEST,
    TIMEOUT,
    WINDOW_SIZE,
)
from packet import Packet, decode, encode
from raw_utils import build_ipv4_udp_packet, parse_ipv4_udp_packet


DEFAULT_SERVER_IP = '0.0.0.0'


class SRFTServer:
    def __init__(
        self,
        server_ip: str,
        server_port: int,
        timeout: float = TIMEOUT,
        window_size: int = WINDOW_SIZE,
        max_retries: int = MAX_RETRIES,
        simulate_drop_once: Optional[int] = None,
    ):
        self.server_ip = server_ip
        self.server_port = server_port
        self.timeout = timeout
        self.window_size = max(1, window_size)
        self.max_retries = max(1, max_retries)
        self.simulate_drop_once = simulate_drop_once
        self.drop_done = False

        self.send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        self.send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        self.recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        self.recv_sock.settimeout(None)

        self.packets_sent = 0
        self.packets_retransmitted = 0
        self.packets_received = 0
        self.start_time = None

        self._ack_lock = threading.Lock()
        self._highest_ack = 0
        self._ack_stop = threading.Event()
        self._ack_thread: Optional[threading.Thread] = None
        self._ack_last_seen = time.time()

    def _send_srft_packet(self, packet: Packet, client_ip: str, client_port: int) -> None:
        if (
            self.simulate_drop_once is not None
            and packet.pkt_type == DATA
            and packet.seq == self.simulate_drop_once
            and not self.drop_done
        ):
            print(f'[DEBUG] simulate FIRST drop seq={packet.seq}')
            self.drop_done = True
            return

        raw_packet = build_ipv4_udp_packet(
            src_ip=self.server_ip if self.server_ip != '0.0.0.0' else client_ip,
            dst_ip=client_ip,
            src_port=self.server_port,
            dst_port=client_port,
            payload=encode(packet),
        )
        self.send_sock.sendto(raw_packet, (client_ip, 0))
        self.packets_sent += 1

    def _recv_srft_packet(self, expected_client: Optional[Tuple[str, int]] = None):
        while True:
            raw_data, _ = self.recv_sock.recvfrom(RAW_RECV_BUFFER)
            parsed = parse_ipv4_udp_packet(raw_data)
            if parsed is None:
                continue

            src_ip, dst_ip, src_port, dst_port, payload = parsed

            if dst_port != self.server_port:
                continue
            if self.server_ip != '0.0.0.0' and dst_ip != self.server_ip:
                continue
            if expected_client is not None and (src_ip, src_port) != expected_client:
                continue

            self.packets_received += 1
            pkt = decode(payload)
            return pkt, (src_ip, src_port), dst_ip

    def wait_for_request(self):
        print('[Server] Waiting for client request...')
        while True:
            pkt, client_addr, local_dst_ip = self._recv_srft_packet()
            if pkt is None:
                print('[Server] Corrupted packet ignored')
                continue

            if pkt.pkt_type == REQUEST:
                filename = pkt.payload.decode('utf-8', errors='replace')
                if self.server_ip == '0.0.0.0':
                    self.server_ip = local_dst_ip
                print(f"[Server] Got REQUEST for '{filename}' from {client_addr}")
                return filename, client_addr

            print(f'[Server] Expected REQUEST, got type={pkt.pkt_type}, ignoring')

    def read_file_chunks(self, filepath: str) -> List[Tuple[int, bytes]]:
        chunks = []
        seq = 0
        with open(filepath, 'rb') as f:
            while True:
                chunk = f.read(MAX_PAYLOAD)
                if not chunk:
                    break
                chunks.append((seq, chunk))
                seq += 1
        return chunks

    def _ack_receiver_loop(self, client_addr: Tuple[str, int]) -> None:
        self.recv_sock.settimeout(0.2)
        try:
            while not self._ack_stop.is_set():
                try:
                    pkt, _, _ = self._recv_srft_packet(expected_client=client_addr)
                except socket.timeout:
                    continue

                if pkt is None:
                    continue

                if pkt.pkt_type == ACK:
                    with self._ack_lock:
                        if pkt.ack > self._highest_ack:
                            self._highest_ack = pkt.ack
                        self._ack_last_seen = time.time()
                    print(f'[DEBUG] ACK received: cumulative ack={pkt.ack}')
        finally:
            self.recv_sock.settimeout(None)

    def _start_ack_thread(self, client_addr: Tuple[str, int]) -> None:
        self._highest_ack = 0
        self._ack_last_seen = time.time()
        self._ack_stop.clear()
        self._ack_thread = threading.Thread(
            target=self._ack_receiver_loop,
            args=(client_addr,),
            daemon=True,
            name='ack-receiver',
        )
        self._ack_thread.start()

    def _stop_ack_thread(self) -> None:
        self._ack_stop.set()
        if self._ack_thread is not None:
            self._ack_thread.join(timeout=1.0)
            self._ack_thread = None

    def _send_error(self, client_addr: Tuple[str, int], message: str) -> None:
        pkt = Packet(ERROR, seq=0, ack=0, payload=message.encode())
        self._send_srft_packet(pkt, client_addr[0], client_addr[1])

    def _send_end(self, client_addr: Tuple[str, int], total_chunks: int, filename: str, file_md5: str, filesize: int) -> None:
        payload = json.dumps(
            {
                'name': os.path.basename(filename),
                'size': filesize,
                'md5': file_md5,
                'chunks': total_chunks,
            }
        ).encode()
        pkt = Packet(END, seq=total_chunks, ack=0, payload=payload)

        retries = 0
        while retries < END_RETRIES:
            self._send_srft_packet(pkt, client_addr[0], client_addr[1])
            if retries > 0:
                self.packets_retransmitted += 1

            deadline = time.time() + self.timeout
            while time.time() < deadline:
                with self._ack_lock:
                    current_ack = self._highest_ack
                if current_ack >= total_chunks:
                    print('[Server] END acknowledged')
                    return
                time.sleep(ACK_POLL_INTERVAL)

            retries += 1
            print(f'[Server] END timeout, retry #{retries}')

        print('[Server] Warning: END not acknowledged')

    def send_file(self, filepath: str, client_addr: Tuple[str, int], file_md5: str, filesize: int) -> bool:
        chunks = self.read_file_chunks(filepath)
        total = len(chunks)
        print(f'[Server] File split into {total} chunks')
        self.start_time = time.time()

        outstanding: Dict[int, float] = {}
        base = 0
        next_seq_to_send = 0
        retries_by_seq: Dict[int, int] = {}

        self._start_ack_thread(client_addr)
        try:
            while base < total:
                # Fill the sending window.
                while next_seq_to_send < total and next_seq_to_send < base + self.window_size:
                    seq_num, chunk_data = chunks[next_seq_to_send]
                    pkt = Packet(DATA, seq=seq_num, ack=0, payload=chunk_data)
                    self._send_srft_packet(pkt, client_addr[0], client_addr[1])
                    outstanding[seq_num] = time.time()
                    retries_by_seq.setdefault(seq_num, 0)
                    next_seq_to_send += 1

                with self._ack_lock:
                    highest_acked = self._highest_ack
                if highest_acked > base:
                    for seq in range(base, min(highest_acked, total)):
                        outstanding.pop(seq, None)
                    base = highest_acked
                    if base > 0 and (base % 100 == 0 or base == total):
                        print(f'[Server] Progress: {base}/{total}')
                    continue

                if not outstanding:
                    time.sleep(ACK_POLL_INTERVAL)
                    continue

                oldest_outstanding_seq = min(outstanding)
                sent_at = outstanding[oldest_outstanding_seq]
                if time.time() - sent_at < self.timeout:
                    time.sleep(ACK_POLL_INTERVAL)
                    continue

                # Timeout: retransmit all currently outstanding packets (Go-Back-N behavior).
                for seq in sorted(outstanding):
                    retries_by_seq[seq] += 1
                    if retries_by_seq[seq] > self.max_retries:
                        print(f'[Server] FAILED: max retries for seq={seq}')
                        return False

                    chunk_data = chunks[seq][1]
                    pkt = Packet(DATA, seq=seq, ack=0, payload=chunk_data)
                    self._send_srft_packet(pkt, client_addr[0], client_addr[1])
                    outstanding[seq] = time.time()
                    self.packets_retransmitted += 1
                    print(f'[Server] Timeout seq={seq}, retry #{retries_by_seq[seq]}')

            self._send_end(client_addr, total, filepath, file_md5, filesize)
            return True
        finally:
            self._stop_ack_thread()

    def generate_report(self, filename: str, filesize: int, file_md5: str) -> None:
        elapsed = 0 if self.start_time is None else time.time() - self.start_time
        h = int(elapsed // 3600)
        m = int((elapsed % 3600) // 60)
        s = int(elapsed % 60)

        report = (
            f'- Name of the transferred file: {filename}\n'
            f'- Size of the transferred file: {filesize} bytes\n'
            f'- The number of packets sent from the server: {self.packets_sent}\n'
            f'- The number of retransmitted packets from the server: {self.packets_retransmitted}\n'
            f'- The number of packets received from the client: {self.packets_received}\n'
            f'- The time duration of the file transfer: {h:02d}:{m:02d}:{s:02d}\n'
            f'- Sender MD5: {file_md5}\n'
            f'- Sliding window size: {self.window_size}\n'
            f'- ACK receiver thread enabled: Yes\n'
        )

        print('\n========== Transfer Report ==========')
        print(report)
        with open('server_report.txt', 'w') as f:
            f.write(report)
        print('[Server] Report saved to server_report.txt')

    def run(self) -> None:
        print(f'[Server] Starting raw UDP server on {self.server_ip}:{self.server_port}')
        print(f'[Server] Window size={self.window_size}, timeout={self.timeout}s')
        filename, client_addr = self.wait_for_request()

        if not os.path.exists(filename):
            print(f"[Server] File '{filename}' not found")
            self._send_error(client_addr, f"File '{filename}' not found")
            return

        with open(filename, 'rb') as f:
            file_bytes = f.read()
        filesize = len(file_bytes)
        md5 = hashlib.md5(file_bytes).hexdigest()
        print(f'[Server] File: {filename}, Size: {filesize}, MD5: {md5}')

        success = self.send_file(filename, client_addr, md5, filesize)
        self.generate_report(filename, filesize, md5)

        if success:
            print('[Server] Transfer complete!')
        else:
            print('[Server] Transfer failed.')

    def close(self) -> None:
        self.send_sock.close()
        self.recv_sock.close()


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description='SRFT raw-socket UDP server')
    parser.add_argument('server_ip', nargs='?', default=DEFAULT_SERVER_IP)
    parser.add_argument('--port', type=int, default=DEFAULT_SERVER_PORT)
    parser.add_argument('--timeout', type=float, default=TIMEOUT)
    parser.add_argument('--window-size', type=int, default=WINDOW_SIZE)
    parser.add_argument('--max-retries', type=int, default=MAX_RETRIES)
    parser.add_argument(
        '--simulate-drop-once',
        type=int,
        default=None,
        help='drop one DATA packet with this seq number once; useful for local retransmission tests',
    )
    return parser


def main() -> None:
    args = build_arg_parser().parse_args()
    server = SRFTServer(
        server_ip=args.server_ip,
        server_port=args.port,
        timeout=args.timeout,
        window_size=args.window_size,
        max_retries=args.max_retries,
        simulate_drop_once=args.simulate_drop_once,
    )
    try:
        server.run()
    finally:
        server.close()


if __name__ == '__main__':
    main()
