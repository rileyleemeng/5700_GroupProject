import argparse
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
    MAX_PAYLOAD,
    MAX_RETRIES,
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


class SRFTUDPServer:
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

        # Phase 2 session state
        self.client_nonce: Optional[bytes] = None
        self.server_nonce: Optional[bytes] = None
        self.session_id: Optional[bytes] = None
        self.keys = None
        self.handshake_success = False

        # Stats
        self.packets_sent = 0
        self.packets_retransmitted = 0
        self.packets_received = 0
        self.aead_failures = 0
        self.replay_drops = 0
        self.sha256_match = False

        self.last_ack_seen = -1
        self.start_time: Optional[float] = None

    def _send_srft_packet(self, packet: Packet) -> None:
        raw_packet = build_ipv4_udp_packet(
            src_ip=self.server_ip,
            dst_ip=self.client_ip,
            src_port=self.server_port,
            dst_port=self.client_port,
            payload=encode(packet),
        )
        self.send_sock.sendto(raw_packet, (self.client_ip, 0))
        self.packets_sent += 1

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

    # ----------------------------
    # Handshake
    # ----------------------------
    def do_handshake(self) -> bool:
        print('[SERVER] Waiting for CLIENT_HELLO...')

        idle_timeouts = 0
        while idle_timeouts < self.max_idle_timeouts:
            try:
                pkt, _ = self._recv_srft_packet()

                if pkt is None:
                    print('[SERVER] Corrupted CLIENT_HELLO ignored')
                    continue

                if pkt.pkt_type != CLIENT_HELLO:
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

                if not verify_hmac(PSK, signed_part, recv_mac):
                    print('[SERVER] CLIENT_HELLO HMAC verification failed')
                    return False

                self.server_nonce = generate_nonce(SERVER_NONCE_LEN)
                self.session_id = generate_nonce(SESSION_ID_LEN)

                reply_body = bytes([VERSION]) + self.server_nonce + self.session_id
                reply_mac = make_hmac(PSK, reply_body)

                resp = Packet(SERVER_HELLO, seq=0, ack=0, payload=reply_body + reply_mac)
                self._send_srft_packet(resp)

                self.keys = derive_session_keys(PSK, self.client_nonce, self.server_nonce)
                self.handshake_success = True
                print('[SERVER] Handshake success')
                return True

            except socket.timeout:
                idle_timeouts += 1
                print(f'[SERVER] Handshake timeout ({idle_timeouts}/{self.max_idle_timeouts})')

        print('[SERVER] Handshake failed: too many timeouts')
        return False

    # ----------------------------
    # Secure helpers
    # ----------------------------
    def _send_secure_packet(self, pkt_type: int, seq: int, ack: int, plaintext: bytes) -> None:
        if not self.handshake_success or self.session_id is None or self.keys is None:
            raise RuntimeError('secure session is not established')

        aad = build_aad(self.session_id, pkt_type, seq, ack)

        # Scheme B: use packet seq directly as AES-GCM nonce counter
        nonce = build_gcm_nonce(self.keys['s2c_nonce_prefix'], seq)

        ciphertext = encrypt_aead(self.keys['s2c_key'], nonce, aad, plaintext)

        pkt = Packet(pkt_type, seq=seq, ack=ack, payload=ciphertext)
        self._send_srft_packet(pkt)

    def _decrypt_client_packet(self, pkt: Packet) -> Optional[bytes]:
        if not self.handshake_success or self.session_id is None or self.keys is None:
            return None

        aad = build_aad(self.session_id, pkt.pkt_type, pkt.seq, pkt.ack)

        # client -> server also uses seq directly as AES-GCM nonce counter
        nonce = build_gcm_nonce(self.keys['c2s_nonce_prefix'], pkt.seq)

        try:
            plaintext = decrypt_aead(
                self.keys['c2s_key'],
                nonce,
                aad,
                pkt.payload,
            )
            return plaintext
        except Exception:
            self.aead_failures += 1
            return None

    # ----------------------------
    # Request / ACK / RESULT
    # ----------------------------
    def wait_for_request(self) -> Optional[str]:
        print('[SERVER] Waiting for secure REQUEST...')

        idle_timeouts = 0
        while idle_timeouts < self.max_idle_timeouts:
            try:
                pkt, _ = self._recv_srft_packet()

                if pkt is None:
                    print('[SERVER] Corrupted REQUEST ignored')
                    continue

                if pkt.pkt_type != REQUEST:
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

    def wait_for_ack(self, current_seq: int) -> bool:
        idle_timeouts = 0

        while idle_timeouts < self.max_idle_timeouts:
            try:
                pkt, _ = self._recv_srft_packet()

                if pkt is None:
                    print('[SERVER] Corrupted ACK ignored')
                    continue

                if pkt.pkt_type != ACK:
                    # Ignore unrelated packets while waiting for ACK
                    continue

                plaintext = self._decrypt_client_packet(pkt)
                if plaintext is None:
                    print('[SERVER] ACK AEAD authentication failed')
                    continue

                if plaintext != b'ACK':
                    print('[SERVER] Invalid ACK payload ignored')
                    continue

                # Replay / duplicate ACK protection
                if pkt.ack <= self.last_ack_seen:
                    self.replay_drops += 1
                    print(f'[SERVER] Duplicate/old ACK={pkt.ack} dropped')
                    continue

                self.last_ack_seen = pkt.ack
                print(f'[SERVER] Received secure ACK={pkt.ack}')

                if pkt.ack >= current_seq + 1:
                    return True

            except socket.timeout:
                idle_timeouts += 1
                return False

        return False

    def wait_for_result(self) -> bool:
        print('[SERVER] Waiting for secure RESULT...')

        idle_timeouts = 0
        while idle_timeouts < self.max_idle_timeouts:
            try:
                pkt, _ = self._recv_srft_packet()

                if pkt is None:
                    print('[SERVER] Corrupted RESULT ignored')
                    continue

                if pkt.pkt_type != RESULT:
                    continue

                plaintext = self._decrypt_client_packet(pkt)
                if plaintext is None:
                    print('[SERVER] RESULT AEAD authentication failed')
                    continue

                if plaintext == b'OK':
                    self.sha256_match = True
                    print('[SERVER] Client reported SHA-256 match')
                    return True
                else:
                    self.sha256_match = False
                    print('[SERVER] Client reported SHA-256 mismatch')
                    return False

            except socket.timeout:
                idle_timeouts += 1
                print(f'[SERVER] Waiting RESULT timeout ({idle_timeouts}/{self.max_idle_timeouts})')

        self.sha256_match = False
        return False

    # ----------------------------
    # File transfer
    # ----------------------------
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
        pkt = Packet(ERROR, seq=0, ack=0, payload=message.encode('utf-8'))
        self._send_srft_packet(pkt)

    def send_file(self, filepath: str) -> bool:
        chunks = self.read_file_chunks(filepath)
        total_chunks = len(chunks)
        print(f'[SERVER] File split into {total_chunks} chunk(s)')

        self.start_time = time.time()

        for seq, chunk_data in chunks:
            acked = False
            retries = 0

            while not acked and retries < MAX_RETRIES:
                self._send_secure_packet(
                    pkt_type=DATA,
                    seq=seq,
                    ack=0,
                    plaintext=chunk_data,
                )
                print(f'[SERVER] Sent secure DATA seq={seq}, len={len(chunk_data)}')

                if retries > 0:
                    self.packets_retransmitted += 1

                acked = self.wait_for_ack(seq)
                if not acked:
                    retries += 1
                    print(f'[SERVER] Timeout / no valid ACK for seq={seq}, retry #{retries}')

            if not acked:
                print(f'[SERVER] Failed: max retries exceeded for seq={seq}')
                return False

        # Send final SHA-256 digest
        full_data = open(filepath, 'rb').read()
        digest = sha256_bytes(full_data)

        self._send_secure_packet(
            pkt_type=DIGEST,
            seq=total_chunks,
            ack=0,
            plaintext=digest,
        )
        print('[SERVER] Sent secure DIGEST')

        self._send_secure_packet(
            pkt_type=END,
            seq=total_chunks + 1,
            ack=0,
            plaintext=b'END',
        )
        print('[SERVER] Sent secure END')

        return True

    # ----------------------------
    # Reporting
    # ----------------------------
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
        self.send_sock.close()
        self.recv_sock.close()


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description='SRFT raw-socket UDP server (Phase 2 secure)')
    parser.add_argument('--server-ip', default=DEFAULT_SERVER_IP)
    parser.add_argument('--client-ip', default=DEFAULT_CLIENT_IP)
    parser.add_argument('--server-port', type=int, default=DEFAULT_SERVER_PORT)
    parser.add_argument('--client-port', type=int, default=DEFAULT_CLIENT_PORT)
    parser.add_argument('--timeout', type=float, default=TIMEOUT)
    parser.add_argument('--max-idle-timeouts', type=int, default=MAX_IDLE_TIMEOUTS)
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