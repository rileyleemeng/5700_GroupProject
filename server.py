"""
SRFT UDP Server – Phase 2  (Secure Reliable File Transfer)
  • Sliding-window with a dedicated ACK-listener thread
  • Streaming file reads (never loads entire file into memory)
  • AES-GCM AEAD encryption on every DATA / ACK / control packet
  • PSK handshake  (ClientHello ↔ ServerHello → HKDF key derivation)
  • DIGEST + END retransmission until RESULT received
  • Built-in attack modes for security testing  (--attack tamper|replay|inject)
"""
 
import argparse
import hashlib
import os
import socket
import sys
import threading
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
    MAX_PAYLOAD,
    MAX_RETRIES,
    RAW_RECV_BUFFER,
    REQUEST,
    RESULT,
    SERVER_HELLO,
    TIMEOUT,
    WINDOW_SIZE,
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
 
RETRANSMIT_BATCH = 4
POLL_INTERVAL = 0.01
SEND_PACE = 0.0005          # small delay between packets to avoid buffer overflow
 
 
class SRFTUDPServer:
    """Secure Reliable File Transfer – raw-socket UDP server."""
 
    def __init__(
        self,
        server_ip: str,
        server_port: int,
        client_ip: str,
        client_port: int,
        timeout: float = TIMEOUT,
        max_idle_timeouts: int = MAX_IDLE_TIMEOUTS,
        attack_mode: Optional[str] = None,
        psk: bytes = PSK,
    ):
        self.server_ip = server_ip
        self.server_port = server_port
        self.client_ip = client_ip
        self.client_port = client_port
        self.timeout = timeout
        self.max_idle_timeouts = max(1, max_idle_timeouts)
        self.attack_mode = attack_mode
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
 
        # ── Phase 2 session state ──
        self.client_nonce: Optional[bytes] = None
        self.server_nonce: Optional[bytes] = None
        self.session_id: Optional[bytes] = None
        self.keys = None
        self.handshake_success = False
 
        # ── Statistics ──
        self.packets_sent = 0
        self.packets_retransmitted = 0
        self.packets_received = 0
        self.aead_failures = 0
        self.replay_drops = 0
        self.sha256_match = False
        self.start_time: Optional[float] = None
 
        # ── Thread-safety lock ──
        self._lock = threading.Lock()
 
    # ================================================================
    #  Raw socket send / recv
    # ================================================================
 
    def _send_srft_packet(self, packet: Packet) -> None:
        """Wrap an SRFT Packet inside IP+UDP headers and send via raw socket."""
        raw = build_ipv4_udp_packet(
            src_ip=self.server_ip,
            dst_ip=self.client_ip,
            src_port=self.server_port,
            dst_port=self.client_port,
            payload=encode(packet),
        )
        for _retry in range(10):
            try:
                self.send_sock.sendto(raw, (self.client_ip, 0))
                break
            except OSError:
                time.sleep(0.005)
        with self._lock:
            self.packets_sent += 1
 
    def _recv_srft_packet(self) -> Tuple[Optional[Packet], Optional[Tuple[str, int]]]:
        """Block until an SRFT packet arrives from the expected client."""
        while True:
            raw_data, _ = self.recv_sock.recvfrom(RAW_RECV_BUFFER)
            parsed = parse_ipv4_udp_packet(raw_data)
            if parsed is None:
                continue
 
            src_ip, dst_ip, src_port, dst_port, payload = parsed
 
            if src_ip != self.client_ip or dst_ip != self.server_ip:
                continue
            if src_port != self.client_port or dst_port != self.server_port:
                continue
 
            with self._lock:
                self.packets_received += 1
            return decode(payload), (src_ip, src_port)
 
    # ================================================================
    #  Phase 2 – Handshake
    # ================================================================
 
    def do_handshake(self) -> bool:
        print('[SERVER] Waiting for CLIENT_HELLO...')
 
        idle_timeouts = 0
        while idle_timeouts < self.max_idle_timeouts:
            try:
                pkt, _ = self._recv_srft_packet()
 
                if pkt is None or pkt.pkt_type != CLIENT_HELLO:
                    continue
 
                payload = pkt.payload
                min_len = 1 + CLIENT_NONCE_LEN + 32
                if len(payload) < min_len:
                    print('[SERVER] Invalid CLIENT_HELLO length')
                    return False
 
                version = payload[0]
                self.client_nonce = payload[1 : 1 + CLIENT_NONCE_LEN]
                recv_mac = payload[1 + CLIENT_NONCE_LEN :]
 
                if not verify_hmac(self.psk, bytes([version]) + self.client_nonce, recv_mac):
                    print('[SERVER] CLIENT_HELLO HMAC verification failed')
                    return False
 
                self.server_nonce = generate_nonce(SERVER_NONCE_LEN)
                self.session_id = generate_nonce(SESSION_ID_LEN)
 
                reply_body = bytes([VERSION]) + self.server_nonce + self.session_id
                reply_mac = make_hmac(self.psk, reply_body)
                resp = Packet(SERVER_HELLO, seq=0, ack=0, payload=reply_body + reply_mac)
                self._send_srft_packet(resp)
 
                self.keys = derive_session_keys(self.psk, self.client_nonce, self.server_nonce)
                self.handshake_success = True
                print('[SERVER] Handshake success')
                return True
 
            except socket.timeout:
                idle_timeouts += 1
                print(f'[SERVER] Handshake timeout ({idle_timeouts}/{self.max_idle_timeouts})')
 
        print('[SERVER] Handshake failed: too many timeouts')
        return False
 
    # ================================================================
    #  Secure packet helpers
    # ================================================================
 
    def _send_secure_packet(self, pkt_type: int, seq: int, ack: int, plaintext: bytes) -> None:
        if not self.handshake_success or self.keys is None:
            raise RuntimeError('secure session not established')
 
        aad = build_aad(self.session_id, pkt_type, seq, ack)
        nonce = build_gcm_nonce(self.keys['s2c_nonce_prefix'], seq)
        ciphertext = encrypt_aead(self.keys['s2c_key'], nonce, aad, plaintext)
 
        self._send_srft_packet(Packet(pkt_type, seq=seq, ack=ack, payload=ciphertext))
 
    def _decrypt_client_packet(self, pkt: Packet) -> Optional[bytes]:
        if not self.handshake_success or self.keys is None:
            return None
 
        aad = build_aad(self.session_id, pkt.pkt_type, pkt.seq, pkt.ack)
        nonce = build_gcm_nonce(self.keys['c2s_nonce_prefix'], pkt.seq)
 
        try:
            return decrypt_aead(self.keys['c2s_key'], nonce, aad, pkt.payload)
        except Exception:
            with self._lock:
                self.aead_failures += 1
            return None
 
    # ================================================================
    #  REQUEST phase
    # ================================================================
 
    def wait_for_request(self) -> Optional[str]:
        print('[SERVER] Waiting for secure REQUEST...')
 
        idle_timeouts = 0
        while idle_timeouts < self.max_idle_timeouts:
            try:
                pkt, _ = self._recv_srft_packet()
                if pkt is None or pkt.pkt_type != REQUEST:
                    continue
 
                plaintext = self._decrypt_client_packet(pkt)
                if plaintext is None:
                    print('[SERVER] REQUEST AEAD failed')
                    continue
 
                filename = plaintext.decode('utf-8', errors='replace')
                print(f'[SERVER] Received secure REQUEST for: {filename}')
                return filename
 
            except socket.timeout:
                idle_timeouts += 1
                print(f'[SERVER] REQUEST timeout ({idle_timeouts}/{self.max_idle_timeouts})')
 
        return None
 
    # ================================================================
    #  Streaming file helpers (never loads entire file into memory)
    # ================================================================
 
    def count_chunks(self, filepath: str) -> int:
        """Count total chunks without loading the file."""
        size = os.path.getsize(filepath)
        return (size + MAX_PAYLOAD - 1) // MAX_PAYLOAD
 
    def read_chunk(self, filepath: str, seq: int) -> bytes:
        """Read a single chunk from disk by sequence number."""
        with open(filepath, 'rb') as f:
            f.seek(seq * MAX_PAYLOAD)
            return f.read(MAX_PAYLOAD)
 
    def compute_file_sha256(self, filepath: str) -> bytes:
        """Compute SHA-256 in streaming fashion (no full load)."""
        h = hashlib.sha256()
        with open(filepath, 'rb') as f:
            while True:
                block = f.read(65536)
                if not block:
                    break
                h.update(block)
        return h.digest()
 
    def compute_file_md5(self, filepath: str) -> str:
        """Compute MD5 in streaming fashion (no full load)."""
        h = hashlib.md5()
        with open(filepath, 'rb') as f:
            while True:
                block = f.read(65536)
                if not block:
                    break
                h.update(block)
        return h.hexdigest()
 
    # ================================================================
    #  Sliding-window file transfer  (multithreaded, streaming)
    # ================================================================
 
    def send_file(self, filepath: str) -> bool:
        """
        Send a file using a sliding window with streaming reads.
        A background thread listens for ACKs and advances *base*.
        The main thread keeps the window full and retransmits on timeout.
        """
        total = self.count_chunks(filepath)
        print(f'[SERVER] File split into {total} chunk(s)')
 
        if total == 0:
            self.start_time = time.time()
            return self._send_digest_and_end(filepath, total)
 
        self.start_time = time.time()
 
        base = 0
        base_lock = threading.Lock()
        stop_event = threading.Event()
 
        # Attack bookkeeping
        attack_done = False
        stored_replay_pkt: Optional[Tuple[int, bytes]] = None
 
        # Progress tracking – print ~20 updates total
        progress_interval = max(1, total // 20)
        last_progress = -1
 
        # ── ACK listener thread ──
        def ack_listener():
            nonlocal base
            while not stop_event.is_set():
                try:
                    pkt, _ = self._recv_srft_packet()
                    if pkt is None or pkt.pkt_type != ACK:
                        continue
                    plaintext = self._decrypt_client_packet(pkt)
                    if plaintext is None or plaintext != b'ACK':
                        continue
                    with base_lock:
                        if pkt.ack > base:
                            base = pkt.ack
                except socket.timeout:
                    continue
 
        listener = threading.Thread(target=ack_listener, daemon=True)
        listener.start()
 
        next_seq = 0
 
        try:
            while True:
                with base_lock:
                    current_base = base
 
                if current_base >= total:
                    break
 
                # Print progress (only ~20 lines for entire transfer)
                pct = 100 * current_base // total
                if pct // 5 > last_progress:
                    last_progress = pct // 5
                    elapsed = time.time() - self.start_time
                    print(f'[SERVER] Progress: {current_base}/{total} ({pct}%) elapsed={elapsed:.0f}s')
 
                # Fill the window
                window_end = min(current_base + WINDOW_SIZE, total)
                while next_seq < window_end:
                    data = self.read_chunk(filepath, next_seq)
 
                    # Attack: tamper
                    if (self.attack_mode == 'tamper'
                            and not attack_done and next_seq == 5 and total > 6):
                        self._attack_tamper(next_seq, data)
                        attack_done = True
                    else:
                        self._send_secure_packet(DATA, next_seq, 0, data)
 
                    # Attack: replay – store
                    if (self.attack_mode == 'replay'
                            and not attack_done and next_seq == 2 and total > 6):
                        stored_replay_pkt = (next_seq, data)
 
                    # Attack: replay – resend
                    if (self.attack_mode == 'replay'
                            and stored_replay_pkt is not None
                            and not attack_done and next_seq == 5):
                        rseq, rdata = stored_replay_pkt
                        self._send_secure_packet(DATA, rseq, 0, rdata)
                        print(f'[ATTACK] Replayed DATA seq={rseq}')
                        attack_done = True
 
                    # Attack: inject
                    if (self.attack_mode == 'inject'
                            and not attack_done and next_seq == 3 and total > 4):
                        self._attack_inject(next_seq)
                        attack_done = True
 
                    time.sleep(SEND_PACE)
                    next_seq += 1
 
                # Wait for ACK progress or timeout
                deadline = time.time() + self.timeout
                made_progress = False
 
                while time.time() < deadline:
                    with base_lock:
                        if base > current_base or base >= total:
                            made_progress = True
                            break
                    time.sleep(POLL_INTERVAL)
 
                if not made_progress:
                    with base_lock:
                        rb = base
                    batch_end = min(rb + RETRANSMIT_BATCH, next_seq, total)
                    for i in range(rb, batch_end):
                        rdata = self.read_chunk(filepath, i)
                        self._send_secure_packet(DATA, i, 0, rdata)
                        with self._lock:
                            self.packets_retransmitted += 1
                    if rb < total:
                        print(f'[SERVER] Timeout retransmit seq {rb}..{batch_end - 1}')
 
        finally:
            stop_event.set()
            listener.join(timeout=2)
 
        print(f'[SERVER] All {total} chunks ACKed')
        return self._send_digest_and_end(filepath, total)
 
    # ================================================================
    #  DIGEST / END / RESULT  (with retransmission)
    # ================================================================
 
    def _send_digest_and_end(self, filepath: str, total_chunks: int) -> bool:
        digest = self.compute_file_sha256(filepath)
 
        for attempt in range(MAX_RETRIES):
            self._send_secure_packet(DIGEST, total_chunks, 0, digest)
            print('[SERVER] Sent secure DIGEST')
 
            self._send_secure_packet(END, total_chunks + 1, 0, b'END')
            print('[SERVER] Sent secure END')
 
            wait_rounds = 0
            while wait_rounds < 3:
                try:
                    pkt, _ = self._recv_srft_packet()
                    if pkt is None or pkt.pkt_type != RESULT:
                        continue
 
                    plaintext = self._decrypt_client_packet(pkt)
                    if plaintext is None:
                        continue
 
                    self.sha256_match = (plaintext == b'OK')
                    status = 'match' if self.sha256_match else 'mismatch'
                    print(f'[SERVER] Client reported SHA-256 {status}')
                    return True
 
                except socket.timeout:
                    wait_rounds += 1
 
            if attempt < MAX_RETRIES - 1:
                with self._lock:
                    self.packets_retransmitted += 2
                print(f'[SERVER] No RESULT, resending DIGEST+END (retry {attempt + 1})')
 
        print('[SERVER] Failed to receive RESULT after max retries')
        self.sha256_match = False
        return False
 
    # ================================================================
    #  Attack-mode helpers
    # ================================================================
 
    def _attack_tamper(self, seq: int, plaintext: bytes) -> None:
        aad = build_aad(self.session_id, DATA, seq, 0)
        nonce = build_gcm_nonce(self.keys['s2c_nonce_prefix'], seq)
        ciphertext = encrypt_aead(self.keys['s2c_key'], nonce, aad, plaintext)
 
        tampered = bytearray(ciphertext)
        if len(tampered) > 2:
            tampered[0] ^= 0x01
            tampered[1] ^= 0x02
 
        pkt = Packet(DATA, seq=seq, ack=0, payload=bytes(tampered))
        self._send_srft_packet(pkt)
        print(f'[ATTACK] Sent tampered DATA seq={seq} (2 bits flipped)')
 
    def _attack_inject(self, near_seq: int) -> None:
        forged = os.urandom(64)
        pkt = Packet(DATA, seq=near_seq + 999, ack=0, payload=forged)
        self._send_srft_packet(pkt)
        print(f'[ATTACK] Injected forged DATA seq={near_seq + 999}')
 
    # ================================================================
    #  Error helper
    # ================================================================
 
    def send_error(self, message: str) -> None:
        pkt = Packet(ERROR, seq=0, ack=0, payload=message.encode('utf-8'))
        self._send_srft_packet(pkt)
 
    # ================================================================
    #  Transfer report
    # ================================================================
 
    def generate_report(self, filename: str, filesize: int) -> None:
        elapsed = 0.0 if self.start_time is None else (time.time() - self.start_time)
        h = int(elapsed // 3600)
        m = int((elapsed % 3600) // 60)
        s = int(elapsed % 60)
 
        file_md5 = ''
        if filesize > 0 and os.path.exists(filename):
            file_md5 = self.compute_file_md5(filename)
 
        report_lines = [
            f'Name of the transferred file: {filename}',
            f'Size of the transferred file: {filesize} bytes',
            f'Number of packets sent from the server: {self.packets_sent}',
            f'Number of retransmitted packets from the server: {self.packets_retransmitted}',
            f'Number of packets received from the client: {self.packets_received}',
            f'Time duration of the file transfer (hh:min:ss): {h:02d}:{m:02d}:{s:02d}',
            f'Original file MD5: {file_md5}',
            f'Security enabled (PSK + AEAD): Yes',
            f'Handshake status: {"Success" if self.handshake_success else "Fail"}',
            f'AEAD authentication failures (invalid packets dropped): {self.aead_failures}',
            f'Replay drops (duplicate/out-of-window packets): {self.replay_drops}',
            f'SHA-256 match: {"Yes" if self.sha256_match else "No"}',
        ]
 
        report = '\n'.join(report_lines) + '\n'
 
        print('\n' + '=' * 50)
        print('SERVER REPORT')
        print('=' * 50)
        print(report)
        print('=' * 50)
 
        with open('server_report.txt', 'w') as f:
            f.write(report)
        print('[SERVER] Report saved to server_report.txt')
 
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
    p = argparse.ArgumentParser(description='SRFT raw-socket UDP server (Phase 2)')
    p.add_argument('--server-ip',   default=DEFAULT_SERVER_IP)
    p.add_argument('--client-ip',   default=DEFAULT_CLIENT_IP)
    p.add_argument('--server-port', type=int, default=DEFAULT_SERVER_PORT)
    p.add_argument('--client-port', type=int, default=DEFAULT_CLIENT_PORT)
    p.add_argument('--timeout',     type=float, default=TIMEOUT)
    p.add_argument('--max-idle-timeouts', type=int, default=MAX_IDLE_TIMEOUTS)
    p.add_argument('--psk-file',    default=None, help='Path to PSK file')
    p.add_argument(
        '--attack',
        choices=['tamper', 'replay', 'inject'],
        default=None,
        help='Security test mode (Test 3/4/5)',
    )
    return p
 
 
def main() -> None:
    args = build_arg_parser().parse_args()
    psk = load_psk(args.psk_file)
 
    server = SRFTUDPServer(
        server_ip=args.server_ip,
        server_port=args.server_port,
        client_ip=args.client_ip,
        client_port=args.client_port,
        timeout=args.timeout,
        max_idle_timeouts=args.max_idle_timeouts,
        attack_mode=args.attack,
        psk=psk,
    )
 
    if args.attack:
        print(f'[SERVER] *** ATTACK MODE: {args.attack} ***')
 
    try:
        if not server.do_handshake():
            print('[SERVER] Handshake failed – aborting')
            server.generate_report(filename='N/A', filesize=0)
            sys.exit(2)
 
        filename = server.wait_for_request()
        if not filename:
            print('[SERVER] No valid REQUEST received')
            server.generate_report(filename='N/A', filesize=0)
            sys.exit(2)
 
        if not os.path.exists(filename):
            print(f'[SERVER] File not found: {filename}')
            server.send_error(f'File not found: {filename}')
            server.generate_report(filename=filename, filesize=0)
            sys.exit(2)
 
        filesize = os.path.getsize(filename)
        print(f'[SERVER] File: {filename}, Size: {filesize} bytes')
 
        ok = server.send_file(filename)
        server.generate_report(filename=filename, filesize=filesize)
 
        if not ok:
            sys.exit(2)
 
    finally:
        server.close()
 
 
if __name__ == '__main__':
    main()
 