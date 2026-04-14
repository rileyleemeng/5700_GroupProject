import argparse
import os
import socket
import sys
import time
from typing import Optional, Tuple

from constants import (
    ACK,
    ACK_EVERY,
    CLIENT_HELLO,
    CLIENT_NONCE_LEN,
    DATA,
    DEFAULT_CLIENT_PORT,
    DEFAULT_SERVER_PORT,
    DIGEST,
    END,
    ERROR,
    MAX_IDLE_TIMEOUTS,
    RAW_RECV_BUFFER,
    RECEIVER_WINDOW,
    REQUEST,
    RESULT,
    SERVER_HELLO,
    SERVER_NONCE_LEN,
    SESSION_ID_LEN,
    TIMEOUT,
    VERSION,
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


class SRFTUDPClient:
    def __init__(
        self,
        server_ip: str,
        server_port: int,
        client_ip: str,
        client_port: int,
        timeout: float = TIMEOUT,
        max_idle_timeouts: int = MAX_IDLE_TIMEOUTS,
        receiver_window: int = RECEIVER_WINDOW,
        ack_every: int = ACK_EVERY,
        psk: Optional[bytes] = None,
    ):
        self.server_ip = server_ip
        self.server_port = server_port
        self.client_ip = client_ip
        self.client_port = client_port
        self.timeout = timeout
        self.max_idle_timeouts = max(1, max_idle_timeouts)
        self.receiver_window = max(1, receiver_window)
        self.ack_every = max(1, ack_every)
        self.psk = psk or load_psk(None)

        self.send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        self.send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        self.recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        self.recv_sock.settimeout(self.timeout)

        self.expected_seq = 0
        self.buffer = {}
        self.last_ack_sent = 0
        self.requested_filename: Optional[str] = None
        self.transfer_started = False

        self.client_nonce: Optional[bytes] = None
        self.server_nonce: Optional[bytes] = None
        self.session_id: Optional[bytes] = None
        self.keys = None
        self.handshake_success = False

        self.aead_failures = 0
        self.replay_drops = 0
        self.received_digest: Optional[bytes] = None

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

    def do_handshake(self) -> bool:
        self.client_nonce = generate_nonce(CLIENT_NONCE_LEN)
        hello_body = bytes([VERSION]) + self.client_nonce
        hello_mac = make_hmac(self.psk, hello_body)
        self._send_srft_packet(Packet(CLIENT_HELLO, seq=0, ack=0, payload=hello_body + hello_mac))
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
                self.server_nonce = payload[1:1 + SERVER_NONCE_LEN]
                self.session_id = payload[1 + SERVER_NONCE_LEN:1 + SERVER_NONCE_LEN + SESSION_ID_LEN]
                recv_mac = payload[1 + SERVER_NONCE_LEN + SESSION_ID_LEN:]
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

    def _send_secure_packet(self, pkt_type: int, seq: int, ack: int, plaintext: bytes) -> None:
        if not self.handshake_success or self.session_id is None or self.keys is None:
            raise RuntimeError('secure session is not established')

        aad = build_aad(self.session_id, pkt_type, seq, ack)
        nonce = build_gcm_nonce(self.keys['c2s_nonce_prefix'], seq)
        ciphertext = encrypt_aead(self.keys['c2s_key'], nonce, aad, plaintext)
        self._send_srft_packet(Packet(pkt_type, seq=seq, ack=ack, payload=ciphertext))

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

    def request_file(self, filename: str, retransmit: bool = False) -> None:
        self.requested_filename = filename
        self._send_secure_packet(REQUEST, seq=0, ack=0, plaintext=filename.encode('utf-8'))
        print(f"[CLIENT] {'Retransmitted' if retransmit else 'Sent'} secure REQUEST for file: {filename}")

    def send_ack(self, force: bool = False) -> None:
        should_send = force or (self.expected_seq - self.last_ack_sent >= self.ack_every)
        if not should_send and self.expected_seq == self.last_ack_sent:
            return

        self._send_secure_packet(ACK, seq=self.expected_seq, ack=self.expected_seq, plaintext=b'ACK')
        self.last_ack_sent = self.expected_seq
        print(f'[CLIENT] Sent secure cumulative ACK={self.expected_seq}')

    def send_result_reliably(self, sha_match: bool) -> None:
        payload = b'OK' if sha_match else b'FAIL'
        base_seq = self.expected_seq + 100000

        for i in range(5):
            self._send_secure_packet(
                RESULT,
                seq=base_seq + i,
                ack=self.expected_seq,
                plaintext=payload,
            )
            print(f'[CLIENT] Sent secure RESULT attempt #{i + 1}')
            try:
                self.send_ack(force=True)
            except Exception:
                pass
            time.sleep(0.1)

    def _handle_secure_error(self, message_bytes: bytes) -> bool:
        message = message_bytes.decode('utf-8', errors='replace')
        print(f'[CLIENT] Server error: {message}')
        return False

    def receive_file(self, output_filename: str) -> bool:
        file_data = bytearray()
        idle_timeouts = 0

        while True:
            try:
                pkt, _ = self._recv_srft_packet()
                idle_timeouts = 0

                if pkt is None:
                    print('[CLIENT] Corrupted outer packet ignored')
                    if self.transfer_started:
                        self.send_ack(force=True)
                    elif self.requested_filename:
                        self.request_file(self.requested_filename, retransmit=True)
                    continue

                if pkt.pkt_type in (DATA, DIGEST, END, ERROR):
                    plaintext = self._decrypt_server_packet(pkt)
                    if plaintext is None:
                        print('[CLIENT] AEAD authentication failed, packet dropped')
                        continue

                    if pkt.pkt_type == DATA:
                        self.transfer_started = True
                        print(f'[CLIENT] Received secure DATA seq={pkt.seq}, plain_len={len(plaintext)}')
                        advanced = False

                        if pkt.seq < self.expected_seq:
                            self.replay_drops += 1
                            print(f'[CLIENT] Replay/duplicate seq={pkt.seq} dropped')
                            self.send_ack(force=True)
                            continue

                        if pkt.seq >= self.expected_seq + self.receiver_window:
                            self.replay_drops += 1
                            print(f'[CLIENT] Out-of-window seq={pkt.seq} dropped')
                            self.send_ack(force=True)
                            continue

                        if pkt.seq == self.expected_seq:
                            file_data.extend(plaintext)
                            self.expected_seq += 1
                            advanced = True

                            while self.expected_seq in self.buffer:
                                file_data.extend(self.buffer.pop(self.expected_seq))
                                self.expected_seq += 1
                        else:
                            if pkt.seq not in self.buffer:
                                self.buffer[pkt.seq] = plaintext
                                print(f'[CLIENT] Buffered out-of-order seq={pkt.seq}')
                            else:
                                self.replay_drops += 1
                                print(f'[CLIENT] Duplicate buffered seq={pkt.seq} dropped')

                        self.send_ack(force=not advanced)

                    elif pkt.pkt_type == DIGEST:
                        self.transfer_started = True
                        self.received_digest = plaintext
                        print('[CLIENT] Received secure DIGEST')
                        self.send_ack(force=True)

                    elif pkt.pkt_type == END:
                        self.transfer_started = True
                        print('[CLIENT] Received secure END')

                        with open(output_filename, 'wb') as f:
                            f.write(file_data)

                        local_digest = sha256_bytes(bytes(file_data))
                        sha_match = self.received_digest == local_digest

                        self.send_result_reliably(sha_match)

                        print(f'[CLIENT] File saved as: {output_filename}')
                        print(f'[CLIENT] SHA-256 match: {sha_match}')
                        print(f'[CLIENT] AEAD failures: {self.aead_failures}')
                        print(f'[CLIENT] Replay drops: {self.replay_drops}')

                        with open('client_report.txt', 'w') as f:
                            f.write(
                                f'Security enabled (PSK + AEAD): Yes\n'
                                f'Handshake status: {"Success" if self.handshake_success else "Fail"}\n'
                                f'Output file: {output_filename}\n'
                                f'Local size: {len(file_data)}\n'
                                f'AEAD authentication failures: {self.aead_failures}\n'
                                f'Replay drops: {self.replay_drops}\n'
                                f'SHA-256 match: {sha_match}\n'
                            )
                        return sha_match

                    elif pkt.pkt_type == ERROR:
                        return self._handle_secure_error(plaintext)

                else:
                    print(f'[CLIENT] Unexpected packet type={pkt.pkt_type}')

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
    parser = argparse.ArgumentParser(description='SRFT raw-socket UDP client (Phase 1+2)')
    parser.add_argument('filename')
    parser.add_argument('server_ip', nargs='?', default=DEFAULT_SERVER_IP)
    parser.add_argument('client_ip', nargs='?', default=DEFAULT_CLIENT_IP)
    parser.add_argument('--server-port', type=int, default=DEFAULT_SERVER_PORT)
    parser.add_argument('--client-port', type=int, default=DEFAULT_CLIENT_PORT)
    parser.add_argument('--timeout', type=float, default=TIMEOUT)
    parser.add_argument('--max-idle-timeouts', type=int, default=MAX_IDLE_TIMEOUTS)
    parser.add_argument('--receiver-window', type=int, default=RECEIVER_WINDOW)
    parser.add_argument('--ack-every', type=int, default=ACK_EVERY)
    parser.add_argument('--psk-file', default=None)
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
            receiver_window=args.receiver_window,
            ack_every=args.ack_every,
            psk=load_psk(args.psk_file),
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