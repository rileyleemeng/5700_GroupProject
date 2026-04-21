# SRFT – Secure Reliable File Transfer

A Python-based secure and reliable file transfer protocol built on raw UDP sockets (`SOCK_RAW`). The system manually constructs IPv4/UDP headers and implements reliability, security, and integrity verification from scratch.

## Features

### Phase 1 – Reliable Transfer
- Manual IPv4 + UDP header construction with `SOCK_RAW`
- Checksum validation at the SRFT layer
- Sequence numbers with client-side reordering buffer
- Cumulative acknowledgements (ACK)
- Timeout-based retransmission
- Multithreaded ACK handling on the server
- Sliding-window transfer for high throughput
- End-to-end MD5 verification

### Phase 2 – Security Layer
- Pre-shared key (PSK) authentication
- Secure handshake: ClientHello / ServerHello with nonce exchange
- HMAC-based handshake verification
- HKDF-SHA256 session key derivation
- AES-256-GCM (AEAD) encryption on all DATA, ACK, and control packets
- Replay protection (duplicate/out-of-window packet detection)
- SHA-256 end-to-end file integrity verification
- Built-in attack modes for security testing (`--attack tamper|replay|inject`)

## Files

| File | Description |
|------|-------------|
| `server.py` | Raw-socket server with sliding window, AEAD encryption, and attack modes |
| `client.py` | Raw-socket client with cumulative ACK, streaming writes, and AEAD decryption |
| `constants.py` | Protocol constants, timeouts, window size, PSK, and security parameters |
| `packet.py` | SRFT packet encode/decode/checksum and AAD construction |
| `raw_utils.py` | Manual IPv4/UDP header building and parsing |
| `security.py` | AES-GCM encryption/decryption, HMAC, HKDF key derivation, nonce generation |

## Requirements

- Python 3.8+
- Linux (raw sockets require root privileges)
- `cryptography` library: `pip install cryptography`

## How to Run

Both server and client require `sudo` for raw socket access.

### Basic Transfer

Terminal 1 (Server):
```bash
sudo python3 server.py --server-ip <SERVER_IP> --client-ip <CLIENT_IP> --server-port 9090 --client-port 9091
```

Terminal 2 (Client):
```bash
sudo python3 client.py <filename> <SERVER_IP> <CLIENT_IP> --server-port 9090 --client-port 9091
```

### Example (same machine):
```bash
# Terminal 1
sudo python3 server.py --server-ip 172.31.43.79 --client-ip 172.31.43.79 --server-port 9090 --client-port 9091

# Terminal 2
sudo python3 client.py test_10mb 172.31.43.79 172.31.43.79 --server-port 9090 --client-port 9091
```

### Example (two EC2 instances):
```bash
# Server EC2 (IP: 172.31.45.124)
sudo python3 server.py --server-ip 172.31.45.124 --client-ip 172.31.38.90 --server-port 9090 --client-port 9091

# Client EC2 (IP: 172.31.38.90)
sudo python3 client.py test_100mb 172.31.45.124 172.31.38.90 --server-port 9090 --client-port 9091
```

## Security Testing

### Test 1 – Baseline Secure Transfer
Normal transfer with security enabled. Expected: Handshake success, SHA-256 match, 0 AEAD failures.

### Test 2 – Wrong PSK
```bash
echo -n "this-is-a-wrong-psk-key-12345678" > wrong_psk.txt
# Server runs with default PSK, client uses wrong PSK:
sudo python3 client.py test.txt <SERVER_IP> <CLIENT_IP> --server-port 9090 --client-port 9091 --psk-file wrong_psk.txt
```
Expected: Handshake fails, connection refused.

### Test 3 – Tamper Detection
```bash
sudo python3 server.py --server-ip <IP> --client-ip <IP> --server-port 9090 --client-port 9091 --attack tamper
```
Expected: Client detects AEAD failure (failures > 0), drops tampered packet, retransmission recovers, SHA-256 match.

### Test 4 – Replay Protection
```bash
sudo python3 server.py --server-ip <IP> --client-ip <IP> --server-port 9090 --client-port 9091 --attack replay
```
Expected: Client detects duplicate packet (replay drops > 0), SHA-256 match.

### Test 5 – Forged Injection
```bash
sudo python3 server.py --server-ip <IP> --client-ip <IP> --server-port 9090 --client-port 9091 --attack inject
```
Expected: Client detects AEAD failure on forged packet, drops it, SHA-256 match.

## Packet Loss Testing

Apply simulated packet loss using `tc`:
```bash
# Add 2% loss
sudo tc qdisc add dev ens5 root netem loss 2%

# Run transfer, then remove loss
sudo tc qdisc del dev ens5 root

# Add 4% loss
sudo tc qdisc add dev ens5 root netem loss 4%

# Run transfer, then remove loss
sudo tc qdisc del dev ens5 root
```

## How Security Works

1. Client sends `ClientHello` with a random nonce and HMAC signature
2. Server verifies HMAC, responds with `ServerHello` containing server nonce and session ID
3. Both sides derive encryption keys using HKDF-SHA256 from PSK + both nonces
4. All subsequent packets (DATA, ACK, DIGEST, END) are encrypted with AES-256-GCM
5. AAD (Additional Authenticated Data) includes session ID, packet type, sequence number, and ACK number
6. After transfer, server sends SHA-256 digest; client verifies against locally computed hash

## Generated Reports

After each transfer, both server and client generate report files:
- `server_report.txt`: file name, size, packets sent/retransmitted/received, transfer time, MD5, security status, SHA-256 match
- `client_report.txt`: file size, packets received, duplicates, out-of-order, transfer time, MD5, AEAD failures, replay drops, SHA-256 match

## Notes

- Raw sockets require root privileges and are most reliable on Linux/AWS
- The client uses streaming writes to disk, enabling transfers of files larger than available RAM
- The server uses streaming reads, never loading the entire file into memory
- AWS Free Tier EC2 (t3.micro) with swap space is sufficient for testing up to 1GB files
