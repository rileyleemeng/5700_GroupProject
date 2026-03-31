import socket
import sys
import os

from packet import Packet, encode, decode
from constants import REQUEST, DATA, ACK, END, MAX_PAYLOAD, TIMEOUT

SERVER_IP = "127.0.0.1"
SERVER_PORT = 12000
BUFFER_SIZE = 2048    # big enough to receive the whole packet

class SRFT_UDPClient:
    def __init__(self, server_ip, server_port):
        self.server_addr = (server_ip, server_port)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(TIMEOUT)
        self.expected_seq  = 0   # expected_seq = received_seq + 1
        self.buffer = {}    # temporarily save the wrong order packets
        
    def request_file(self, filename):
        pkt = Packet(REQUEST, seq = 0, ack = 0, payload = filename.encode())
        self.sock.sendto(encode(pkt), self.server_addr)
        print(f'[CLIENT] Requested File: {filename}')
        
    def send_ack(self):
        ack_pkt = Packet(ACK, seq=0, ack = self.expected_seq, payload=b'')
        self.sock.sendto(encode(ack_pkt), self.server_addr)
        print(f'[CLIENT] Sent ACK = {self.expected_seq}')
        
    def receive_file(self, output_filename):
        file_data = bytearray()
        
        while True:
            try:
                raw_data, addr = self.sock.recvfrom(BUFFER_SIZE)
                pkt = decode(raw_data)
                
                # corrupted packet
                if pkt is None:
                    print('[CLIENT] Corrupted packet, ignored')
                    continue
                # data packet
                if pkt.pkt_type == DATA:
                    print(f'[CLIENT] Received DATA seq={pkt.seq}, len={pkt.length}')
                    # if the seq = expected seq
                    if pkt.seq == self.expected_seq:
                        file_data.extend(pkt.payload)
                        self.expected_seq += 1
                        #if the following seq packets are in the buffer, continue retrive them in order
                        while self.expected_seq in self.buffer:
                            file_data.extend(self.buffer[self.expected_seq])
                            del self.buffer[self.expected_seq]
                            self.expected_seq += 1
                            
                    # if the seq > expected seq (out of order arrival, buffer it first)
                    elif pkt.seq > self.expected_seq:
                        if pkt.seq not in self.buffer:
                            self.buffer[pkt.seq] = pkt.payload
                            print(f'[CLIENT] Buffered out of order packet seq={pkt.seq}')
                    
                    # if the seq < expected seq (duplicate packet, ignore)
                    else:
                        print(f'[CLIENT] Duplicate packet seq={pkt.seq}, ignored ')
                    
                    # whenever receive a packet, client should send new cumulative ACK
                    self.send_ack()
                
                # END packet
                elif pkt.pkt_type == END:
                    print('[CLIENT] Received END packet')
                    self.send_ack() 
                    with open(output_filename, 'wb') as f:
                        f.write(file_data)
                        
                    print(f'[CLIENT] File saved as: {output_filename}')
                    break
                
                # unknown packet
                else:
                    print(f'[CLIENT] Unknown packet type: {pkt.pkt_type}')
            
            except socket.timeout:
                print('[CLIENT] Timeout waiting for server')
                break
    
    def close(self):
        self.sock.close()
def main():
    if len(sys.argv) != 2:
        print('Usage: python client.py <filename>')
        sys.exit(1)

    filename = sys.argv[1]
    output_filename = 'downloaded_' + os.path.basename(filename)

    client = SRFT_UDPClient(SERVER_IP, SERVER_PORT)

    try:
        client.request_file(filename)
        client.receive_file(output_filename)
    finally:
        client.close()


if __name__ == '__main__':
    main()
        
        