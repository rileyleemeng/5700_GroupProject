import argparse
import os
import socket
import sys
import threading
import time
from collections import deque
from typing import Deque, Dict, Optional, Tuple

from constants import (
    ACK,
    ACK_POLL_INTERVAL,
    CLIENT_HELLO,
    CLIENT_NONCE_LEN,
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
    SERVER_NONCE_LEN,
    SESSION_ID_LEN,
    TIMEOUT,
    VERSION,
    WINDOW_SIZE,
)
from packet import Packet, build_aad, decode, encode
from raw_utils import build_ipv4_udp_packet, parse_ipv4_udp_packet
from security import (
    build_gcm_nonce,
    decrypt_aead,
    derive_session_keys,
    encrypt_aead,
    generate_nonce,
    load_psk,
    make_hmac,
    sha256_bytes,
    verify_hmac,
)

DEFAULT_SERVER_IP = '127.0.0.1'
DEFAULT_CLIENT_IP = '127.0.0.1'


class SRFTUDPServer:
    def __init__(
        self,
        server_ip: str,
        server_port: int,
        client_ip: str,
        client_port: int,
        timeout: float = TIMEOUT,
        max_idle_timeouts: int = MAX_IDLE_TIMEOUTS,
        window_size: int = WINDOW_SIZE,
        psk: Optional[bytes] = None,
        attack: str = 'none',
        attack_seq: int = 0,
    ):
        self.server_ip = server_ip
        self.server_port = server_port
        self.client_ip = client_ip
        self.client_port = client_port
        self.timeout = timeout
        self.max_idle_timeouts = max(1, max_idle_timeouts)
        self.window_size = max(1, window_size)
        self.psk = psk or load_psk(None)
        self.attack = attack
        self.attack_seq = max(0, attack_seq)

        self.send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        self.send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        self.recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        self.recv_sock.settimeout(self.timeout)

        self.client_nonce: Optional[bytes] = None
        self.server_nonce: Optional[bytes] = None
        self.session_id: Optional[bytes] = None
        self.keys = None
        self.handshake_success = False

        self.packets_sent = 0
        self.packets_retransmitted = 0
        self.packets_received = 0
        self.aead_failures = 0
        self.replay_drops = 0
        self.sha256_match = False
        self.last_ack_seen = -1
        self.start_time: Optional[float] = None

        self.ack_lock = threading.Lock()
        self.highest_cumulative_ack = 0
        self.ack_receiver_running = False
        self.ack_thread: Optional[threading.Thread] = None

        # 把 ACK 线程误收到的非 ACK 包先存起来，避免 RESULT 被吞掉
        self.pending_packets: Deque[Tuple[Packet, Optional[Tuple[str, int]]]] = deque()
        self.pending_lock = threading.Lock()

        # 为了在最后阶段 timeout 时可重发
        self.last_digest_packet: Optional[Packet] = None
        self.last_end_packet: Optional[Packet] = None

        self.attack_done = False
        self.saved_replay_raw_packet: Optional[bytes] = None
        self.saved_replay_dst: Optional[Tuple[str, int]] = None

    def _send_raw_encoded(self, encoded_srft: bytes) -> None:
        raw_packet = build_ipv4_udp_packet(
            src_ip=self.server_ip,
            dst_ip=self.client_ip,
            src_port=self.server_port,
            dst_port=self.client_port,
            payload=encoded_srft,
        )
        self.send_sock.sendto(raw_packet, (self.client_ip, 0))
        self.packets_sent += 1

    def _send_srft_packet(self, packet: Packet) -> None:
        self._send_raw_encoded(encode(packet))

    def _recv_srft_packet(self) -> Tuple[Optional[Packet], Optional[Tuple[str, int]]]:
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

            self.packets_received += 1
            return decode(payload), (src_ip, src_port)

    def _push_pending_packet(self, pkt: Packet, addr: Optional[Tuple[str, int]]) -> None:
        with self.pending_lock:
            self.pending_packets.append((pkt, addr))

    def _pop_pending_packet(
        self, wanted_type: Optional[int] = None
    ) -> Tuple[Optional[Packet], Optional[Tuple[str, int]]]:
        with self.pending_lock:
            if not self.pending_packets:
                return None, None

            if wanted_type is None:
                return self.pending_packets.popleft()

            for i, item in enumerate(self.pending_packets):
                pkt, addr = item
                if pkt is not None and pkt.pkt_type == wanted_type:
                    del self.pending_packets[i]
                    return pkt, addr

        return None, None

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
                self.client_nonce = payload[1:1 + CLIENT_NONCE_LEN]
                recv_mac = payload[1 + CLIENT_NONCE_LEN:]
                signed_part = bytes([version]) + self.client_nonce

                if not verify_hmac(self.psk, signed_part, recv_mac):
                    print('[SERVER] CLIENT_HELLO HMAC verification failed')
                    return False

                self.server_nonce = generate_nonce(SERVER_NONCE_LEN)
                self.session_id = generate_nonce(SESSION_ID_LEN)

                reply_body = bytes([VERSION]) + self.server_nonce + self.session_id
                reply_mac = make_hmac(self.psk, reply_body)

                self._send_srft_packet(
                    Packet(SERVER_HELLO, seq=0, ack=0, payload=reply_body + reply_mac)
                )
                self.keys = derive_session_keys(self.psk, self.client_nonce, self.server_nonce)
                self.handshake_success = True
                print('[SERVER] Handshake success')
                return True

            except socket.timeout:
                idle_timeouts += 1
                print(f'[SERVER] Handshake timeout ({idle_timeouts}/{self.max_idle_timeouts})')

        print('[SERVER] Handshake failed: too many timeouts')
        return False

    def _build_secure_packet(self, pkt_type: int, seq: int, ack: int, plaintext: bytes) -> Packet:
        if not self.handshake_success or self.session_id is None or self.keys is None:
            raise RuntimeError('secure session is not established')

        aad = build_aad(self.session_id, pkt_type, seq, ack)
        nonce = build_gcm_nonce(self.keys['s2c_nonce_prefix'], seq)
        ciphertext = encrypt_aead(self.keys['s2c_key'], nonce, aad, plaintext)
        return Packet(pkt_type, seq=seq, ack=ack, payload=ciphertext)

    def _send_secure_packet(self, pkt_type: int, seq: int, ack: int, plaintext: bytes) -> None:
        self._send_srft_packet(self._build_secure_packet(pkt_type, seq, ack, plaintext))

    def _decrypt_client_packet(self, pkt: Packet) -> Optional[bytes]:
        if not self.handshake_success or self.session_id is None or self.keys is None:
            return None

        aad = build_aad(self.session_id, pkt.pkt_type, pkt.seq, pkt.ack)
        nonce = build_gcm_nonce(self.keys['c2s_nonce_prefix'], pkt.seq)
        try:
            return decrypt_aead(self.keys['c2s_key'], nonce, aad, pkt.payload)
        except Exception:
            self.aead_failures += 1
            return None

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
                    print('[SERVER] REQUEST AEAD authentication failed')
                    continue

                filename = plaintext.decode('utf-8', errors='replace')
                print(f'[SERVER] Received secure REQUEST for file: {filename}')
                return filename

            except socket.timeout:
                idle_timeouts += 1
                print(f'[SERVER] Waiting REQUEST timeout ({idle_timeouts}/{self.max_idle_timeouts})')

        return None

    def _ack_receiver_loop(self) -> None:
        idle = 0
        while self.ack_receiver_running and idle < self.max_idle_timeouts * 4:
            try:
                pkt, addr = self._recv_srft_packet()
                idle = 0

                if pkt is None:
                    continue

                # 非 ACK 包不要吞掉，留给主线程
                if pkt.pkt_type != ACK:
                    self._push_pending_packet(pkt, addr)
                    continue

                plaintext = self._decrypt_client_packet(pkt)
                if plaintext != b'ACK':
                    continue

                if pkt.ack <= self.last_ack_seen:
                    self.replay_drops += 1
                    print(f'[SERVER] Duplicate/old ACK={pkt.ack} dropped')
                    continue

                self.last_ack_seen = pkt.ack
                with self.ack_lock:
                    if pkt.ack > self.highest_cumulative_ack:
                        self.highest_cumulative_ack = pkt.ack

                print(f'[SERVER] Received secure cumulative ACK={pkt.ack}')

            except socket.timeout:
                idle += 1
                continue
            except OSError:
                break

    def _start_ack_receiver(self) -> None:
        self.ack_receiver_running = True
        self.ack_thread = threading.Thread(target=self._ack_receiver_loop, daemon=True)
        self.ack_thread.start()

    def _stop_ack_receiver(self) -> None:
        self.ack_receiver_running = False
        if self.ack_thread is not None:
            self.ack_thread.join(timeout=1.0)

    def _maybe_attack_send(self, seq: int, encoded_srft: bytes) -> None:
        if self.attack == 'none' or self.attack_done or seq != self.attack_seq:
            return

        pkt = decode(encoded_srft)
        if pkt is None:
            return

        if self.attack == 'tamper':
            if len(pkt.payload) >= 2:
                tampered = bytearray(pkt.payload)
                tampered[0] ^= 0x03
                tampered[1] ^= 0x0C
                pkt.payload = bytes(tampered)
                pkt.length = len(pkt.payload)
                self._send_srft_packet(pkt)
                self.attack_done = True
                print(f'[ATTACK] Tampered secure DATA seq={seq}')

        elif self.attack == 'inject':
            forged = Packet(DATA, seq=seq + 50000, ack=0, payload=os.urandom(48))
            self._send_srft_packet(forged)
            self.attack_done = True
            print(f'[ATTACK] Injected forged DATA after seq={seq}')

        elif self.attack == 'replay':
            self.saved_replay_raw_packet = build_ipv4_udp_packet(
                src_ip=self.server_ip,
                dst_ip=self.client_ip,
                src_port=self.server_port,
                dst_port=self.client_port,
                payload=encoded_srft,
            )
            self.saved_replay_dst = (self.client_ip, 0)
            print(f'[ATTACK] Stored packet for replay seq={seq}')

    def _maybe_replay_after_progress(self, base: int) -> None:
        if self.attack != 'replay' or self.attack_done:
            return
        if self.saved_replay_raw_packet is None or self.saved_replay_dst is None:
            return
        if base <= self.attack_seq + 1:
            return

        self.send_sock.sendto(self.saved_replay_raw_packet, self.saved_replay_dst)
        self.packets_sent += 1
        self.attack_done = True
        print(f'[ATTACK] Replayed saved DATA seq={self.attack_seq}')

    def read_file_chunks(self, filepath: str):
        chunks = []
        seq = 0
        with open(filepath, 'rb') as f:
            while True:
                data = f.read(MAX_PAYLOAD)
                if not data:
                    break
                chunks.append((seq, data))
                seq += 1
        return chunks

    def send_error(self, message: str) -> None:
        if self.handshake_success:
            self._send_secure_packet(ERROR, seq=0, ack=0, plaintext=message.encode('utf-8'))
        else:
            self._send_srft_packet(Packet(ERROR, seq=0, ack=0, payload=message.encode('utf-8')))

    def send_file(self, filepath: str) -> bool:
        chunks = self.read_file_chunks(filepath)
        total_chunks = len(chunks)
        print(f'[SERVER] File split into {total_chunks} chunk(s)')
        self.start_time = time.time()

        self._start_ack_receiver()
        try:
            base = 0
            next_to_send = 0
            in_flight: Dict[int, Dict[str, object]] = {}
            retries: Dict[int, int] = {}

            while base < total_chunks:
                while next_to_send < total_chunks and next_to_send < base + self.window_size:
                    seq, chunk_data = chunks[next_to_send]
                    pkt = self._build_secure_packet(DATA, seq=seq, ack=0, plaintext=chunk_data)
                    encoded = encode(pkt)
                    self._send_raw_encoded(encoded)

                    in_flight[seq] = {
                        'encoded': encoded,
                        'sent_at': time.time(),
                    }
                    retries.setdefault(seq, 0)

                    print(f'[SERVER] Sent secure DATA seq={seq}, len={len(chunk_data)}')
                    self._maybe_attack_send(seq, encoded)
                    next_to_send += 1

                time.sleep(ACK_POLL_INTERVAL)
                with self.ack_lock:
                    current_ack = self.highest_cumulative_ack

                while base < current_ack and base in in_flight:
                    del in_flight[base]
                    base += 1

                self._maybe_replay_after_progress(base)

                now = time.time()
                for seq in list(in_flight.keys()):
                    if current_ack > seq:
                        continue

                    info = in_flight[seq]
                    sent_at = float(info['sent_at'])
                    if now - sent_at < self.timeout:
                        continue

                    retries[seq] += 1
                    if retries[seq] > MAX_RETRIES:
                        print(f'[SERVER] Failed: max retries exceeded for seq={seq}')
                        return False

                    raw_pkt = build_ipv4_udp_packet(
                        src_ip=self.server_ip,
                        dst_ip=self.client_ip,
                        src_port=self.server_port,
                        dst_port=self.client_port,
                        payload=info['encoded'],
                    )
                    self.send_sock.sendto(raw_pkt, (self.client_ip, 0))
                    self.packets_sent += 1
                    self.packets_retransmitted += 1
                    info['sent_at'] = now
                    print(f'[SERVER] Retransmitted DATA seq={seq}, retry #{retries[seq]}')

            with open(filepath, 'rb') as f:
                digest = sha256_bytes(f.read())

            self.last_digest_packet = self._build_secure_packet(
                DIGEST, seq=total_chunks, ack=base, plaintext=digest
            )
            self._send_srft_packet(self.last_digest_packet)
            print('[SERVER] Sent secure DIGEST')

            self.last_end_packet = self._build_secure_packet(
                END, seq=total_chunks + 1, ack=base, plaintext=b'END'
            )
            self._send_srft_packet(self.last_end_packet)
            print('[SERVER] Sent secure END')
            return True
        finally:
            self._stop_ack_receiver()

    def wait_for_result(self) -> bool:
        print('[SERVER] Waiting for secure RESULT...')
        idle_timeouts = 0

        while idle_timeouts < self.max_idle_timeouts:
            pending_pkt, _ = self._pop_pending_packet(RESULT)
            if pending_pkt is not None:
                plaintext = self._decrypt_client_packet(pending_pkt)
                if plaintext is None:
                    print('[SERVER] RESULT AEAD authentication failed')
                else:
                    self.sha256_match = plaintext == b'OK'
                    print('[SERVER] Client reported SHA-256 ' + ('match' if self.sha256_match else 'mismatch'))
                    return self.sha256_match

            try:
                pkt, _ = self._recv_srft_packet()
                if pkt is None:
                    continue

                if pkt.pkt_type != RESULT:
                    self._push_pending_packet(pkt, None)
                    continue

                plaintext = self._decrypt_client_packet(pkt)
                if plaintext is None:
                    print('[SERVER] RESULT AEAD authentication failed')
                    continue

                self.sha256_match = plaintext == b'OK'
                print('[SERVER] Client reported SHA-256 ' + ('match' if self.sha256_match else 'mismatch'))
                return self.sha256_match

            except socket.timeout:
                idle_timeouts += 1
                print(f'[SERVER] Waiting RESULT timeout ({idle_timeouts}/{self.max_idle_timeouts})')

                if self.last_end_packet is not None:
                    self._send_srft_packet(self.last_end_packet)
                    self.packets_retransmitted += 1
                    print('[SERVER] Retransmitted secure END while waiting for RESULT')

                if idle_timeouts % 3 == 0 and self.last_digest_packet is not None:
                    self._send_srft_packet(self.last_digest_packet)
                    self.packets_retransmitted += 1
                    print('[SERVER] Retransmitted secure DIGEST while waiting for RESULT')

        self.sha256_match = False
        return False

    def generate_report(self, filename: str, filesize: int) -> None:
        elapsed = 0.0 if self.start_time is None else (time.time() - self.start_time)
        h = int(elapsed // 3600)
        m = int((elapsed % 3600) // 60)
        s = int(elapsed % 60)

        report = (
            f'Name of the transferred file: {filename}\n'
            f'Size of the transferred file: {filesize}\n'
            f'The number of packets sent from the server: {self.packets_sent}\n'
            f'The number of retransmitted packets from the server: {self.packets_retransmitted}\n'
            f'The number of packets received from the client: {self.packets_received}\n'
            f'The time duration of the file transfer (hh:min:ss): {h:02d}:{m:02d}:{s:02d}\n'
            f'Security enabled (PSK + AEAD): Yes\n'
            f'Handshake status: {"Success" if self.handshake_success else "Fail"}\n'
            f'AEAD authentication failures (invalid packets dropped): {self.aead_failures}\n'
            f'Replay drops (duplicate/out-of-window packets): {self.replay_drops}\n'
            f'SHA-256 match: {"Yes" if self.sha256_match else "No"}\n'
        )

        print('\n========== Transfer Report ==========')
        print(report)
        with open('server_report.txt', 'w') as f:
            f.write(report)

    def close(self) -> None:
        self._stop_ack_receiver()
        self.send_sock.close()
        self.recv_sock.close()


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description='SRFT raw-socket UDP server (Phase 1+2)')
    parser.add_argument('--server-ip', default=DEFAULT_SERVER_IP)
    parser.add_argument('--client-ip', default=DEFAULT_CLIENT_IP)
    parser.add_argument('--server-port', type=int, default=DEFAULT_SERVER_PORT)
    parser.add_argument('--client-port', type=int, default=DEFAULT_CLIENT_PORT)
    parser.add_argument('--timeout', type=float, default=TIMEOUT)
    parser.add_argument('--max-idle-timeouts', type=int, default=MAX_IDLE_TIMEOUTS)
    parser.add_argument('--window-size', type=int, default=WINDOW_SIZE)
    parser.add_argument('--psk-file', default=None)
    parser.add_argument('--attack', choices=['none', 'tamper', 'replay', 'inject'], default='none')
    parser.add_argument('--attack-seq', type=int, default=0)
    return parser


def main() -> None:
    args = build_arg_parser().parse_args()
    server = SRFTUDPServer(
        server_ip=args.server_ip,
        server_port=args.server_port,
        client_ip=args.client_ip,
        client_port=args.client_port,
        timeout=args.timeout,
        max_idle_timeouts=args.max_idle_timeouts,
        window_size=args.window_size,
        psk=load_psk(args.psk_file),
        attack=args.attack,
        attack_seq=args.attack_seq,
    )

    try:
        if not server.do_handshake():
            print('[SERVER] Handshake failed')
            server.generate_report(filename='N/A', filesize=0)
            sys.exit(2)

        filename = server.wait_for_request()
        if not filename:
            print('[SERVER] Failed to receive valid secure REQUEST')
            server.generate_report(filename='N/A', filesize=0)
            sys.exit(2)

        if not os.path.exists(filename):
            print(f"[SERVER] File not found: {filename}")
            server.send_error(f'File not found: {filename}')
            server.generate_report(filename=filename, filesize=0)
            sys.exit(2)

        filesize = os.path.getsize(filename)
        ok = server.send_file(filename)
        if ok:
            server.wait_for_result()

        server.generate_report(filename=filename, filesize=filesize)
        if not ok:
            sys.exit(2)

    finally:
        server.close()


if __name__ == '__main__':
    main()