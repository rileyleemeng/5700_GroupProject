"""
SRFT UDP Client – Phase 2  (Secure Reliable File Transfer)
  • PSK handshake  (ClientHello → ServerHello → HKDF key derivation)
  • AES-GCM AEAD encryption on every packet
  • Cumulative ACK with out-of-order buffering
  • Streaming writes (never loads entire file into memory)
  • Full client report matching sample format
"""
 
import argparse
import hashlib
import os
import socket
import sys
import time
from typing import Optional, Tuple
 
from constants import (
    ACK,
    CLIENT_HELLO,
    DATA,
    DEFAULT_CLIENT_PORT,
    DEFAULT_SERVER_PORT,
    DIGEST,
    END,
    ERROR,
    MAX_IDLE_TIMEOUTS,
    RAW_RECV_BUFFER,
    REQUEST,
    RESULT,
    SERVER_HELLO,
    TIMEOUT,
    CLIENT_NONCE_LEN,
    SERVER_NONCE_LEN,
    SESSION_ID_LEN,
    PSK,
    VERSION,
)
from packet import Packet, decode, encode, build_aad
from raw_utils import build_ipv4_udp_packet, parse_ipv4_udp_packet
from security import (
    decrypt_aead,
    derive_session_keys,
    encrypt_aead,
    generate_nonce,
    build_gcm_nonce,
    make_hmac,
    sha256_bytes,
    verify_hmac,
)
 
DEFAULT_SERVER_IP = '127.0.0.1'
DEFAULT_CLIENT_IP = '127.0.0.1'
 
 
class SRFTUDPClient:
    """Secure Reliable File Transfer – raw-socket UDP client."""
 
    def __init__(
        self,
        server_ip: str,
        server_port: int,
        client_ip: str,
        client_port: int,
        timeout: float = TIMEOUT,
        max_idle_timeouts: int = MAX_IDLE_TIMEOUTS,
        psk: bytes = PSK,
    ):
        self.server_ip = server_ip
        self.server_port = server_port
        self.client_ip = client_ip
        self.client_port = client_port
        self.timeout = timeout
        self.max_idle_timeouts = max(1, max_idle_timeouts)
        self.psk = psk
 
        # ── Raw sockets ──
        self.send_sock = socket.socket(
            socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW
        )
        self.send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
 
        self.recv_sock = socket.socket(
            socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP
        )
        self.recv_sock.settimeout(self.timeout)
        self.recv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
 
        # ── Reliability state ──
        self.expected_seq = 0
        self.buffer = {}
        self.last_ack_sent = -1
 
        # ── Request / transfer state ──
        self.requested_filename: Optional[str] = None
        self.transfer_started = False
 
        # ── Phase 2 session state ──
        self.client_nonce: Optional[bytes] = None
        self.server_nonce: Optional[bytes] = None
        self.session_id: Optional[bytes] = None
        self.keys = None
        self.handshake_success = False
 
        # ── Statistics (matches sample report format) ──
        self.packets_received = 0
        self.duplicate_packets = 0
        self.out_of_order_packets = 0
        self.checksum_errors = 0
        self.aead_failures = 0
        self.replay_drops = 0
        self.received_digest: Optional[bytes] = None
        self.start_time: Optional[float] = None
 
        # ── Progress tracking ──
        self._last_progress = -1
 
    # ================================================================
    #  Raw socket send / recv
    # ================================================================
 
    def _send_srft_packet(self, packet: Packet) -> None:
        raw_packet = build_ipv4_udp_packet(
            src_ip=self.client_ip,
            dst_ip=self.server_ip,
            src_port=self.client_port,
            dst_port=self.server_port,
            payload=encode(packet),
        )
        for _retry in range(10):
            try:
                self.send_sock.sendto(raw_packet, (self.server_ip, 0))
                break
            except OSError:
                time.sleep(0.005)
 
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
 
            self.packets_received += 1
 
            pkt = decode(payload)
            if pkt is None:
                self.checksum_errors += 1
                return None, (src_ip, src_port)
 
            return pkt, (src_ip, src_port)
 
    # ================================================================
    #  Phase 2 – Handshake
    # ================================================================
 
    def do_handshake(self) -> bool:
        self.client_nonce = generate_nonce(CLIENT_NONCE_LEN)
 
        hello_body = bytes([VERSION]) + self.client_nonce
        hello_mac = make_hmac(self.psk, hello_body)
 
        pkt = Packet(CLIENT_HELLO, seq=0, ack=0, payload=hello_body + hello_mac)
        self._send_srft_packet(pkt)
        print('[CLIENT] Sent CLIENT_HELLO')
 
        idle_timeouts = 0
        while idle_timeouts < self.max_idle_timeouts:
            try:
                resp, _ = self._recv_srft_packet()
 
                if resp is None or resp.pkt_type != SERVER_HELLO:
                    continue
 
                payload = resp.payload
                min_len = 1 + SERVER_NONCE_LEN + SESSION_ID_LEN + 32
                if len(payload) < min_len:
                    print('[CLIENT] Invalid SERVER_HELLO length')
                    return False
 
                version = payload[0]
                self.server_nonce = payload[1 : 1 + SERVER_NONCE_LEN]
                self.session_id = payload[1 + SERVER_NONCE_LEN : 1 + SERVER_NONCE_LEN + SESSION_ID_LEN]
                recv_mac = payload[1 + SERVER_NONCE_LEN + SESSION_ID_LEN :]
 
                signed_part = bytes([version]) + self.server_nonce + self.session_id
 
                if not verify_hmac(self.psk, signed_part, recv_mac):
                    print('[CLIENT] SERVER_HELLO HMAC verification failed')
                    return False
 
                self.keys = derive_session_keys(self.psk, self.client_nonce, self.server_nonce)
                self.handshake_success = True
                print('[CLIENT] Handshake success')
                return True
 
            except socket.timeout:
                idle_timeouts += 1
                print(f'[CLIENT] Handshake timeout ({idle_timeouts}/{self.max_idle_timeouts})')
 
        print('[CLIENT] Handshake failed: too many timeouts')
        return False
 
    # ================================================================
    #  Secure packet helpers
    # ================================================================
 
    def _send_secure_packet(self, pkt_type: int, seq: int, ack: int, plaintext: bytes) -> None:
        if not self.handshake_success or self.session_id is None or self.keys is None:
            raise RuntimeError('secure session not established')
 
        aad = build_aad(self.session_id, pkt_type, seq, ack)
        nonce = build_gcm_nonce(self.keys['c2s_nonce_prefix'], seq)
        ciphertext = encrypt_aead(self.keys['c2s_key'], nonce, aad, plaintext)
 
        pkt = Packet(pkt_type, seq=seq, ack=ack, payload=ciphertext)
        self._send_srft_packet(pkt)
 
    def _decrypt_server_packet(self, pkt: Packet) -> Optional[bytes]:
        if not self.handshake_success or self.session_id is None or self.keys is None:
            return None
 
        aad = build_aad(self.session_id, pkt.pkt_type, pkt.seq, pkt.ack)
        nonce = build_gcm_nonce(self.keys['s2c_nonce_prefix'], pkt.seq)
 
        try:
            return decrypt_aead(self.keys['s2c_key'], nonce, aad, pkt.payload)
        except Exception:
            self.aead_failures += 1
            return None
 
    # ================================================================
    #  Secure REQUEST / ACK
    # ================================================================
 
    def request_file(self, filename: str, retransmit: bool = False) -> None:
        self.requested_filename = filename
        self._send_secure_packet(
            pkt_type=REQUEST, seq=0, ack=0,
            plaintext=filename.encode('utf-8'),
        )
        tag = 'Retransmitted' if retransmit else 'Sent'
        print(f'[CLIENT] {tag} secure REQUEST for file: {filename}')
 
    def send_ack(self, force: bool = False) -> None:
        if not force and self.last_ack_sent == self.expected_seq:
            return
 
        self._send_secure_packet(
            pkt_type=ACK,
            seq=self.expected_seq,
            ack=self.expected_seq,
            plaintext=b'ACK',
        )
        self.last_ack_sent = self.expected_seq
 
    # ================================================================
    #  Streaming file helpers
    # ================================================================
 
    def _compute_file_sha256(self, filepath: str) -> bytes:
        h = hashlib.sha256()
        with open(filepath, 'rb') as f:
            while True:
                block = f.read(65536)
                if not block:
                    break
                h.update(block)
        return h.digest()
 
    def _compute_file_md5(self, filepath: str) -> str:
        h = hashlib.md5()
        with open(filepath, 'rb') as f:
            while True:
                block = f.read(65536)
                if not block:
                    break
                h.update(block)
        return h.hexdigest()
 
    # ================================================================
    #  Secure receive loop  (streaming – writes to disk, not memory)
    # ================================================================
 
    def receive_file(self, output_filename: str) -> bool:
        idle_timeouts = 0
        self.start_time = time.time()
        total_bytes_written = 0
 
        # Open file for streaming writes
        out_f = open(output_filename, 'wb')
 
        try:
            while True:
                try:
                    pkt, _ = self._recv_srft_packet()
                    idle_timeouts = 0
 
                    if pkt is None:
                        if self.transfer_started:
                            self.send_ack(force=True)
                        else:
                            if self.requested_filename:
                                self.request_file(self.requested_filename, retransmit=True)
                        continue
 
                    if pkt.pkt_type in (DATA, DIGEST, END):
                        plaintext = self._decrypt_server_packet(pkt)
                        if plaintext is None:
                            continue
 
                        # ── DATA packet ──
                        if pkt.pkt_type == DATA:
                            self.transfer_started = True
 
                            if pkt.seq == self.expected_seq:
                                # Write directly to disk
                                out_f.write(plaintext)
                                total_bytes_written += len(plaintext)
                                self.expected_seq += 1
 
                                # Flush buffered out-of-order packets
                                while self.expected_seq in self.buffer:
                                    buffered = self.buffer.pop(self.expected_seq)
                                    out_f.write(buffered)
                                    total_bytes_written += len(buffered)
                                    self.expected_seq += 1
 
                                self.send_ack()
 
                                # Progress (print every 5000 chunks)
                                if self.expected_seq % 5000 == 0:
                                    elapsed = time.time() - self.start_time
                                    print(f'[CLIENT] Received {self.expected_seq} chunks, elapsed={elapsed:.0f}s')
 
                            elif pkt.seq > self.expected_seq:
                                if pkt.seq not in self.buffer:
                                    self.buffer[pkt.seq] = plaintext
                                    self.out_of_order_packets += 1
                                else:
                                    self.duplicate_packets += 1
                                self.send_ack(force=True)
 
                            else:
                                self.duplicate_packets += 1
                                self.send_ack(force=True)
 
                        # ── DIGEST packet ──
                        elif pkt.pkt_type == DIGEST:
                            self.transfer_started = True
                            self.received_digest = plaintext
                            print('[CLIENT] Received secure DIGEST')
 
                        # ── END packet ──
                        elif pkt.pkt_type == END:
                            self.transfer_started = True
                            print('[CLIENT] Received secure END')
 
                            # Close the file before computing hashes
                            out_f.close()
                            out_f = None
 
                            # Compute hashes from disk (streaming, no full load)
                            local_digest = self._compute_file_sha256(output_filename)
                            sha_match = (self.received_digest == local_digest)
 
                            received_md5 = self._compute_file_md5(output_filename)
                            file_size = os.path.getsize(output_filename)
 
                            result_payload = b'OK' if sha_match else b'FAIL'
                            self._send_secure_packet(
                                pkt_type=RESULT,
                                seq=self.expected_seq + 100000,
                                ack=self.expected_seq,
                                plaintext=result_payload,
                            )
 
                            elapsed = time.time() - self.start_time
                            h = int(elapsed // 3600)
                            m = int((elapsed % 3600) // 60)
                            s = int(elapsed % 60)
 
                            print(f'[CLIENT] File saved as: {output_filename}')
                            print(f'[CLIENT] SHA-256 match: {sha_match}')
                            print(f'[CLIENT] AEAD failures: {self.aead_failures}')
                            print(f'[CLIENT] Replay/duplicate drops: {self.duplicate_packets}')
 
                            report_lines = [
                                f'Security enabled (PSK + AEAD): Yes',
                                f'Handshake status: {"True" if self.handshake_success else "False"}',
                                f'Size of the transferred file: {file_size} bytes',
                                f'Number of packets received from server: {self.packets_received}',
                                f'Number of duplicate packets: {self.duplicate_packets}',
                                f'Number of out of order packets: {self.out_of_order_packets}',
                                f'Number of packets with checksum errors: {self.checksum_errors}',
                                f'Time duration of the file transfer: {h:02d}:{m:02d}:{s:02d}',
                                f'Received file MD5: {received_md5}',
                                f'AEAD authentication failures: {self.aead_failures}',
                                f'SHA-256 match: {"Yes" if sha_match else "No"}',
                            ]
                            report = '\n'.join(report_lines) + '\n'
 
                            print('\n' + '=' * 50)
                            print('CLIENT REPORT')
                            print('=' * 50)
                            print(report)
                            print('=' * 50)
 
                            with open('client_report.txt', 'w') as f:
                                f.write(report)
                            print('[CLIENT] Report saved to client_report.txt')
 
                            return sha_match
 
                    elif pkt.pkt_type == ERROR:
                        self.transfer_started = True
                        try:
                            message = pkt.payload.decode('utf-8', errors='replace')
                        except Exception:
                            message = 'server returned ERROR'
                        print(f'[CLIENT] Server error: {message}')
                        return False
 
                except socket.timeout:
                    idle_timeouts += 1
                    if not self.transfer_started:
                        if self.requested_filename:
                            self.request_file(self.requested_filename, retransmit=True)
                    else:
                        self.send_ack(force=True)
 
                    if idle_timeouts >= self.max_idle_timeouts:
                        print('[CLIENT] Transfer failed: too many timeouts')
                        return False
 
        finally:
            if out_f is not None:
                out_f.close()
 
    def close(self) -> None:
        self.send_sock.close()
        self.recv_sock.close()
 
 
# ====================================================================
#  CLI
# ====================================================================
 
def load_psk(path: Optional[str]) -> bytes:
    if path is None:
        return PSK
    with open(path, 'rb') as f:
        key = f.read().strip()
    if len(key) < 16:
        print(f'[WARNING] PSK from {path} is shorter than 16 bytes')
    return key
 
 
def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description='SRFT raw-socket UDP client (Phase 2)')
    p.add_argument('filename')
    p.add_argument('server_ip', nargs='?', default=DEFAULT_SERVER_IP)
    p.add_argument('client_ip', nargs='?', default=DEFAULT_CLIENT_IP)
    p.add_argument('--server-port', type=int, default=DEFAULT_SERVER_PORT)
    p.add_argument('--client-port', type=int, default=DEFAULT_CLIENT_PORT)
    p.add_argument('--timeout', type=float, default=TIMEOUT)
    p.add_argument('--max-idle-timeouts', type=int, default=MAX_IDLE_TIMEOUTS)
    p.add_argument('--output', default=None, help='output file path')
    p.add_argument('--psk-file', default=None, help='Path to PSK file')
    return p
 
 
def main() -> None:
    args = build_arg_parser().parse_args()
    output_filename = args.output or ('downloaded_' + os.path.basename(args.filename))
    psk = load_psk(args.psk_file)
 
    client = SRFTUDPClient(
        server_ip=args.server_ip,
        server_port=args.server_port,
        client_ip=args.client_ip,
        client_port=args.client_port,
        timeout=args.timeout,
        max_idle_timeouts=args.max_idle_timeouts,
        psk=psk,
    )
 
    try:
        if not client.do_handshake():
            print('[CLIENT] Handshake failed')
            sys.exit(2)
 
        client.request_file(args.filename)
        ok = client.receive_file(output_filename)
 
        if not ok:
            sys.exit(2)
 
    finally:
        client.close()
 
 
if __name__ == '__main__':
    main()
 