import argparse
import os
import socket
import sys
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

        # Reliability state
        self.expected_seq = 0
        self.buffer = {}
        self.last_ack_sent = -1

        # Request / transfer state
        self.requested_filename: Optional[str] = None
        self.transfer_started = False

        # Phase 2 session state
        self.client_nonce: Optional[bytes] = None
        self.server_nonce: Optional[bytes] = None
        self.session_id: Optional[bytes] = None
        self.keys = None
        self.handshake_success = False

        # Phase 2 stats
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

    # ----------------------------
    # Phase 2 handshake
    # ----------------------------
    def do_handshake(self) -> bool:
        self.client_nonce = generate_nonce(CLIENT_NONCE_LEN)

        hello_body = bytes([VERSION]) + self.client_nonce
        hello_mac = make_hmac(PSK, hello_body)

        pkt = Packet(CLIENT_HELLO, seq=0, ack=0, payload=hello_body + hello_mac)
        self._send_srft_packet(pkt)
        print('[CLIENT] Sent CLIENT_HELLO')

        idle_timeouts = 0
        while idle_timeouts < self.max_idle_timeouts:
            try:
                resp, _ = self._recv_srft_packet()

                if resp is None:
                    print('[CLIENT] Corrupted SERVER_HELLO ignored')
                    continue

                if resp.pkt_type != SERVER_HELLO:
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

                if not verify_hmac(PSK, signed_part, recv_mac):
                    print('[CLIENT] SERVER_HELLO HMAC verification failed')
                    return False

                self.keys = derive_session_keys(PSK, self.client_nonce, self.server_nonce)
                self.handshake_success = True
                print('[CLIENT] Handshake success')
                return True

            except socket.timeout:
                idle_timeouts += 1
                print(f'[CLIENT] Handshake timeout ({idle_timeouts}/{self.max_idle_timeouts})')

        print('[CLIENT] Handshake failed: too many timeouts')
        return False

    # ----------------------------
    # Secure helpers
    # ----------------------------
    def _send_secure_packet(self, pkt_type: int, seq: int, ack: int, plaintext: bytes) -> None:
        if not self.handshake_success or self.session_id is None or self.keys is None:
            raise RuntimeError('secure session is not established')

        aad = build_aad(self.session_id, pkt_type, seq, ack)

        # Scheme B: use packet seq directly as AES-GCM nonce counter
        nonce = build_gcm_nonce(self.keys['c2s_nonce_prefix'], seq)

        ciphertext = encrypt_aead(self.keys['c2s_key'], nonce, aad, plaintext)

        pkt = Packet(pkt_type, seq=seq, ack=ack, payload=ciphertext)
        self._send_srft_packet(pkt)

    def _decrypt_server_packet(self, pkt: Packet) -> Optional[bytes]:
        if not self.handshake_success or self.session_id is None or self.keys is None:
            return None

        aad = build_aad(self.session_id, pkt.pkt_type, pkt.seq, pkt.ack)

        # server -> client also uses seq directly as AES-GCM nonce counter
        nonce = build_gcm_nonce(self.keys['s2c_nonce_prefix'], pkt.seq)

        try:
            plaintext = decrypt_aead(
                self.keys['s2c_key'],
                nonce,
                aad,
                pkt.payload,
            )
            return plaintext
        except Exception:
            self.aead_failures += 1
            return None

    # ----------------------------
    # Secure REQUEST / ACK
    # ----------------------------
    def request_file(self, filename: str, retransmit: bool = False) -> None:
        self.requested_filename = filename

        # REQUEST uses seq=0, which is also the nonce counter
        self._send_secure_packet(
            pkt_type=REQUEST,
            seq=0,
            ack=0,
            plaintext=filename.encode('utf-8'),
        )

        if retransmit:
            print(f'[CLIENT] Retransmitted secure REQUEST for file: {filename}')
        else:
            print(f'[CLIENT] Sent secure REQUEST for file: {filename}')

    def send_ack(self, force: bool = False) -> None:
        if not force and self.last_ack_sent == self.expected_seq:
            return

        # ACK.seq = ACK.ack = expected_seq
        self._send_secure_packet(
            pkt_type=ACK,
            seq=self.expected_seq,
            ack=self.expected_seq,
            plaintext=b'ACK',
        )

        self.last_ack_sent = self.expected_seq
        print(f'[CLIENT] Sent secure cumulative ACK={self.expected_seq}')

    # ----------------------------
    # Secure receive loop
    # ----------------------------
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
                    else:
                        if self.requested_filename:
                            self.request_file(self.requested_filename, retransmit=True)
                    continue

                if pkt.pkt_type in (DATA, DIGEST, END):
                    plaintext = self._decrypt_server_packet(pkt)
                    if plaintext is None:
                        print('[CLIENT] AEAD authentication failed, packet dropped')
                        continue

                    if pkt.pkt_type == DATA:
                        self.transfer_started = True
                        print(f'[CLIENT] Received secure DATA seq={pkt.seq}, plain_len={len(plaintext)}')
                        advanced = False

                        if pkt.seq == self.expected_seq:
                            file_data.extend(plaintext)
                            self.expected_seq += 1
                            advanced = True

                            while self.expected_seq in self.buffer:
                                file_data.extend(self.buffer.pop(self.expected_seq))
                                self.expected_seq += 1

                        elif pkt.seq > self.expected_seq:
                            if pkt.seq not in self.buffer:
                                self.buffer[pkt.seq] = plaintext
                                print(f'[CLIENT] Buffered out-of-order seq={pkt.seq}')
                            else:
                                self.replay_drops += 1
                                print(f'[CLIENT] Duplicate buffered seq={pkt.seq} dropped')

                        else:
                            self.replay_drops += 1
                            print(f'[CLIENT] Replay/duplicate seq={pkt.seq} dropped')

                        self.send_ack(force=not advanced)

                    elif pkt.pkt_type == DIGEST:
                        self.transfer_started = True
                        self.received_digest = plaintext
                        print('[CLIENT] Received secure DIGEST')

                    elif pkt.pkt_type == END:
                        self.transfer_started = True
                        print('[CLIENT] Received secure END')

                        with open(output_filename, 'wb') as f:
                            f.write(file_data)

                        local_digest = sha256_bytes(bytes(file_data))
                        sha_match = (self.received_digest == local_digest)

                        result_payload = b'OK' if sha_match else b'FAIL'
                        self._send_secure_packet(
                            pkt_type=RESULT,
                            seq=self.expected_seq + 100000,
                            ack=self.expected_seq,
                            plaintext=result_payload,
                        )

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
                    self.transfer_started = True
                    try:
                        message = pkt.payload.decode('utf-8', errors='replace')
                    except Exception:
                        message = 'server returned ERROR'
                    print(f'[CLIENT] Server error: {message}')
                    return False

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
    parser = argparse.ArgumentParser(description='SRFT raw-socket UDP client (Phase 2 secure)')
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