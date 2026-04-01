import socket
import sys
import os
import time
import hashlib

from packet import Packet, encode, decode
from constants import REQUEST, DATA, ACK, END, MAX_PAYLOAD, TIMEOUT, HEADER_LEN

SERVER_IP = "0.0.0.0"
SERVER_PORT = 12000
BUFFER_SIZE = 2048
MAX_RETRIES = 10


class SRFTServer:
    def __init__(self, host=SERVER_IP, port=SERVER_PORT):
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((self.host, self.port))

        self.packets_sent = 0
        self.packets_retransmitted = 0
        self.packets_received = 0
        self.start_time = None

    def wait_for_request(self):
        print("[Server] Waiting for client request...")
        while True:
            raw_data, client_addr = self.sock.recvfrom(BUFFER_SIZE)
            self.packets_received += 1

            pkt = decode(raw_data)
            if pkt is None:
                print("[Server] Corrupted packet, ignoring")
                continue

            if pkt.pkt_type == REQUEST:
                filename = pkt.payload.decode("utf-8")
                print(f"[Server] Got REQUEST for '{filename}' from {client_addr}")
                return filename, client_addr
            else:
                print(f"[Server] Expected REQUEST, got type={pkt.pkt_type}, ignoring")

    def read_file_chunks(self, filepath):
        chunks = []
        seq = 0
        with open(filepath, "rb") as f:
            while True:
                chunk = f.read(MAX_PAYLOAD)
                if not chunk:
                    break
                chunks.append((seq, chunk))
                seq += 1
        return chunks

    def send_file(self, filepath, client_addr):
        chunks = self.read_file_chunks(filepath)
        total = len(chunks)
        print(f"[Server] File split into {total} chunks")

        self.start_time = time.time()

        for seq_num, chunk_data in chunks:
            pkt = Packet(DATA, seq=seq_num, ack=0, payload=chunk_data)
            pkt_bytes = encode(pkt)

            acked = False
            retries = 0

            while not acked and retries < MAX_RETRIES:
                self.sock.sendto(pkt_bytes, client_addr)
                self.packets_sent += 1
                if retries > 0:
                    self.packets_retransmitted += 1

                acked = self._wait_for_ack(seq_num, client_addr)

                if not acked:
                    retries += 1
                    print(f"[Server] Timeout seq={seq_num}, retry #{retries}")

            if not acked:
                print(f"[Server] FAILED: max retries for seq={seq_num}")
                return False

            if (seq_num + 1) % 100 == 0 or seq_num == total - 1:
                print(f"[Server] Progress: {seq_num + 1}/{total}")

        self._send_end(client_addr)
        return True

    def _wait_for_ack(self, sent_seq, client_addr):
        self.sock.settimeout(TIMEOUT)
        try:
            raw_data, addr = self.sock.recvfrom(BUFFER_SIZE)
            self.packets_received += 1

            pkt = decode(raw_data)
            if pkt is None:
                return False

            if pkt.pkt_type == ACK and pkt.ack >= sent_seq + 1:
                return True

            return False

        except socket.timeout:
            return False
        finally:
            self.sock.settimeout(None)

    def _send_end(self, client_addr):
        pkt = Packet(END, seq=0, ack=0)
        pkt_bytes = encode(pkt)
        retries = 0

        while retries < MAX_RETRIES:
            self.sock.sendto(pkt_bytes, client_addr)
            self.packets_sent += 1
            if retries > 0:
                self.packets_retransmitted += 1

            self.sock.settimeout(TIMEOUT)
            try:
                raw_data, addr = self.sock.recvfrom(BUFFER_SIZE)
                self.packets_received += 1
                pkt_resp = decode(raw_data)
                if pkt_resp and pkt_resp.pkt_type == ACK:
                    print("[Server] END acknowledged")
                    self.sock.settimeout(None)
                    return
            except socket.timeout:
                retries += 1
                print(f"[Server] END timeout, retry #{retries}")

        self.sock.settimeout(None)
        print("[Server] Warning: END not acknowledged")

    def generate_report(self, filename, filesize):
        elapsed = time.time() - self.start_time
        h = int(elapsed // 3600)
        m = int((elapsed % 3600) // 60)
        s = int(elapsed % 60)

        report = (
            f"- Name of the transferred file: {filename}\n"
            f"- Size of the transferred file: {filesize} bytes\n"
            f"- The number of packets sent from the server: {self.packets_sent}\n"
            f"- The number of retransmitted packets from the server: {self.packets_retransmitted}\n"
            f"- The number of packets received from the client: {self.packets_received}\n"
            f"- The time duration of the file transfer: {h:02d}:{m:02d}:{s:02d}\n"
        )

        print("\n========== Transfer Report ==========")
        print(report)

        with open("server_report.txt", "w") as f:
            f.write(report)
        print("[Server] Report saved to server_report.txt")

    def run(self):
        print(f"[Server] Starting on {self.host}:{self.port}")

        filename, client_addr = self.wait_for_request()

        if not os.path.exists(filename):
            print(f"[Server] File '{filename}' not found!")
            return

        filesize = os.path.getsize(filename)
        md5 = hashlib.md5(open(filename, "rb").read()).hexdigest()
        print(f"[Server] File: {filename}, Size: {filesize}, MD5: {md5}")

        success = self.send_file(filename, client_addr)

        self.generate_report(filename, filesize)

        if success:
            print("[Server] Transfer complete!")
        else:
            print("[Server] Transfer failed.")


if __name__ == "__main__":
    server = SRFTServer()
    server.run()