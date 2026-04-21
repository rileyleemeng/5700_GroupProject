# SRFT – Secure Reliable File Transfer

A Python-based secure and reliable file transfer protocol built on raw UDP sockets (`SOCK_RAW`). The system manually constructs IPv4/UDP headers and implements reliability, security, and integrity verification from scratch.

## Features

### Phase 1 – Reliable Transfer
- Manual IPv4 + UDP header construction with `SOCK_RAW` (no kernel IP stack dependency)
- 16-bit one's-complement checksum validation at the SRFT layer
- Sequence numbers (32-bit) with cumulative ACK mechanism
- Client-side reordering buffer (capacity: 64 packets) to handle out-of-order delivery
- Cumulative acknowledgements (ACK) – acknowledges "all data up to seq N"
- Timeout-based retransmission (default 0.5s timeout, adaptive for large files)
- Multithreaded ACK listener on server for non-blocking progress tracking
- Sliding-window transfer (default window size: 8 packets, configurable to 16)
- Performance optimization with streaming I/O (never loads entire file into memory)

### Phase 2 – Security Layer
- **Handshake Protocol**: PSK-based authentication with ClientHello/ServerHello exchange
  - Client sends random nonce + HMAC-SHA256 signature of (version || nonce)
  - Server responds with server nonce, session ID, and verifies client's HMAC
  - Both sides derive session keys from PSK using HKDF-SHA256 (8 salt, PRF=SHA256)
- **Encryption**: AES-256-GCM (AEAD) on all DATA, ACK, DIGEST, END, RESULT packets
  - 256-bit keys from HKDF key derivation
  - 12-byte nonces (4-byte prefix + 8-byte counter per packet)
  - Additional Authenticated Data (AAD) includes: session_id || pkt_type || seq || ack
- **Integrity & Authenticity**: Automatic via GCM tag verification (detect tamper/forgery)
- **Replay Protection**: Sequence number windowing (duplicate/out-of-window packets dropped)
- **End-to-End Verification**: SHA-256 digest computed and transmitted by server, verified by client
- **Attack Modes for Testing**:
  - `--attack tamper`: Flip 2 random bits in a DATA packet → GCM failure
  - `--attack replay`: Resend an earlier DATA packet → Replay dropped
  - `--attack inject`: Insert forged random payload → AEAD failure

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
- Linux with raw socket support (requires `sudo` privilege)
- `cryptography` library: `pip install cryptography`

## Configuration

Key parameters defined in `constants.py`:
- `MAX_PAYLOAD`: 900 bytes (application payload per packet, safe for AWS VPC MTU)
- `WINDOW_SIZE`: 8 packets (sliding window size, configurable to 16 for better throughput)
- `TIMEOUT`: 1.0 second (adjusted for reliable large-file transfers)
- `MAX_IDLE_TIMEOUTS`: 100 (max idle wait cycles)
- `DEFAULT_SERVER_PORT`: 12000
- `DEFAULT_CLIENT_PORT`: 12001
- `PSK`: 32-byte pre-shared key (hardcoded, can be overridden with `--psk-file`)

## How to Run

Both server and client require `sudo` for raw socket access. Default ports are 12000 (server) and 12001 (client).

### Minimal Usage

Terminal 1 (Server):
```bash
sudo python3 server.py --server-ip <SERVER_IP> --client-ip <CLIENT_IP>
```

Terminal 2 (Client):
```bash
sudo python3 client.py <filename> <SERVER_IP> <CLIENT_IP>
```

### With Custom Ports

Terminal 1 (Server):
```bash
sudo python3 server.py --server-ip <SERVER_IP> --client-ip <CLIENT_IP> --server-port 12000 --client-port 12001
```

Terminal 2 (Client):
```bash
sudo python3 client.py <filename> <SERVER_IP> <CLIENT_IP> --server-port 12000 --client-port 12001
```

### Example (same machine with loopback):
```bash
# Terminal 1
sudo python3 server.py --server-ip 127.0.0.1 --client-ip 127.0.0.1

# Terminal 2
sudo python3 client.py test.txt 127.0.0.1 127.0.0.1
```

### Example (two AWS EC2 instances):
```bash
# Server EC2 (Private IP: 172.31.13.69, Client Private IP: 172.31.13.49)
ssh -i srft-key.pem ec2-user@<SERVER_PUBLIC_IP>
cd ~/5700_GroupProject
sudo python3 server.py --server-ip 172.31.13.69 --client-ip 172.31.13.49

# Client EC2 (in another terminal)
ssh -i srft-key.pem ec2-user@<CLIENT_PUBLIC_IP>
cd ~/5700_GroupProject
sudo python3 client.py test_800mb.bin 172.31.13.69 172.31.13.49
```

## Security Testing (Phase 2 Attack Modes)

### Test 1 – Baseline Secure Transfer
Normal transfer with security enabled. Expected: Handshake success, SHA-256 match, 0 AEAD failures.

```bash
# Terminal 1
sudo python3 server.py --server-ip 127.0.0.1 --client-ip 127.0.0.1

# Terminal 2
sudo python3 client.py test.txt 127.0.0.1 127.0.0.1
```

Expected output: `SHA-256 match: Yes, AEAD failures: 0`

### Test 2 – Wrong PSK (Handshake Failure)
Create a wrong PSK file and run client with it. Expected: Handshake fails, connection refused.

```bash
echo -n "this-is-a-wrong-psk-key-12345678" > wrong_psk.txt

# Terminal 1
sudo python3 server.py --server-ip 127.0.0.1 --client-ip 127.0.0.1

# Terminal 2
sudo python3 client.py test.txt 127.0.0.1 127.0.0.1 --psk-file wrong_psk.txt
```

Expected output: `[CLIENT] Handshake failed`

### Test 3 – Tamper Detection
Server flips 2 bits in a DATA packet mid-transfer. Expected: Client detects AEAD failure, retransmits, completes successfully.

```bash
# Terminal 1
sudo python3 server.py --server-ip 127.0.0.1 --client-ip 127.0.0.1 --attack tamper

# Terminal 2
sudo python3 client.py test.txt 127.0.0.1 127.0.0.1
```

Expected output: `AEAD authentication failures: 1, SHA-256 match: Yes`

### Test 4 – Replay Protection
Server resends an earlier DATA packet. Expected: Client drops duplicate, completes with SHA-256 match.

```bash
# Terminal 1
sudo python3 server.py --server-ip 127.0.0.1 --client-ip 127.0.0.1 --attack replay

# Terminal 2
sudo python3 client.py test.txt 127.0.0.1 127.0.0.1
```

Expected output: `Replay/duplicate drops: 1, SHA-256 match: Yes`

### Test 5 – Injection Attack
Server injects a forged random DATA packet. Expected: Client detects AEAD failure, drops forged packet, completes successfully.

```bash
# Terminal 1
sudo python3 server.py --server-ip 127.0.0.1 --client-ip 127.0.0.1 --attack inject

# Terminal 2
sudo python3 client.py test.txt 127.0.0.1 127.0.0.1
```

Expected output: `AEAD authentication failures: 1, SHA-256 match: Yes`

## Phase 1 Testing – Packet Loss & Retransmission

Apply simulated packet loss using Linux `tc` (traffic control) on the client side:

```bash
# On client EC2 instance, add 2% loss to outgoing packets
sudo tc qdisc add dev eth0 root netem loss 2%

# Run transfer
sudo python3 client.py <filename> <SERVER_IP> <CLIENT_IP>

# Remove loss after transfer
sudo tc qdisc del dev eth0 root

# Add 4% loss and test again  
sudo tc qdisc add dev eth0 root netem loss 4%
sudo python3 client.py <filename> <SERVER_IP> <CLIENT_IP>
sudo tc qdisc del dev eth0 root
```

Expected behavior with packet loss:
- `packets_retransmitted > 0` (SERVER detects timeouts and retransmits)
- `SHA-256 match: Yes` (despite losses, file integrity maintained)
- Transfer time increases proportionally to loss rate
- With 3-4% loss on 800MB files, expect 20-50 retransmitted packets

## How Phase 2 Security Works (In Detail)

### 1. Handshake (Packets: ClientHello ↔ ServerHello)
- Client generates 16-byte random nonce
- Client sends: HMAC-SHA256(PSK, version || client_nonce)
- Server verifies HMAC, generates 16-byte server nonce + 8-byte session_id
- Server responds: HMAC-SHA256(PSK, version || server_nonce || session_id)
- Client verifies response HMAC
- Both sides now have agreed-upon session_id and nonces

### 2. Key Derivation (HKDF-SHA256)
- Both client and server independently compute:
  ```
  session_keys = HKDF(
    hash=SHA256,
    length=128,     // 4 keys × 32 bytes each
    ikm=PSK,
    salt=min(client_nonce, server_nonce),
    info=max(client_nonce, server_nonce)
  )
  ```
- Extract 4 keys: `c2s_key`, `s2c_key`, `c2s_nonce_prefix`, `s2c_nonce_prefix`

### 3. Packet Encryption (AES-256-GCM)
- Every DATA, ACK, DIGEST, END, RESULT packet is encrypted:
  ```
  AAD = session_id || pkt_type || seq || ack
  nonce = nonce_prefix || counter
  ciphertext = AES-GCM-Encrypt(key, nonce, AAD, plaintext)
  ```
- GCM provides both confidentiality and authentication

### 4. Replay Protection
- Receiver maintains a sliding window (receiver_window ≥ 0)
- Incoming packet seq must satisfy: `base_seq ≤ pkt.seq < base_seq + window_size`
- Packets outside this range are dropped (detected as duplicate or replay)

### 5. End-to-End File Integrity
- After all DATA packets received, server computes SHA-256 digest
- Server sends DIGEST packet (encrypted)
- Client computes local SHA-256, compares with received digest
- Client sends RESULT (OK/FAIL) back to server
- Report indicates `SHA-256 match: Yes/No`

## Generated Reports

After each transfer, both server and client generate detailed report files:

### server_report.txt
- File name and size transferred
- Packets sent, retransmitted, and received
- Transfer duration (hh:min:ss format)
- Original file MD5 hash
- Security status (PSK + AEAD enabled/disabled)
- Handshake success/failure
- AEAD authentication failures (invalid ciphertext packets)
- Replay drops (duplicate/out-of-window packets)
- SHA-256 match result (Yes/No) – indicates if client received complete file

### client_report.txt
- File size received
- Packets received from server
- Duplicate packets detected
- Out-of-order packets buffered
- Transfer duration (hh:min:ss format)
- Received file MD5 hash
- AEAD authentication failures (GCM tag verification failures)
- SHA-256 match result (Yes/No) – confirms file integrity

## Implementation Notes

### Memory Efficiency
- **Streaming I/O**: Both server and client never load entire file into memory
  - Server: reads file in 900-byte chunks on-demand
  - Client: writes file directly to disk in sequence, using a reorder buffer (65KB max)
  - Result: Can transfer files larger than available RAM

### Reliability (Phase 1)
- **Sliding Window**: Default window size 8 (can be tuned to 16 for higher throughput)
- **ACK Mechanism**: Client sends cumulative ACK (all data up to seq N received)
- **Retransmission**: Server retransmits on timeout (1.0 second) in batches of 4 packets
- **Heartbeat ACKs**: Client sends ACK even on out-of-order packets to signal liveness

### Security (Phase 2)
- **Handshake**: Cannot proceed without matching PSK
- **Key Derivation**: Fresh keys for each session (includes random server nonce)
- **Encryption**: Every application packet is encrypted—no plaintext protocol traffic
- **AEAD Tags**: GCM provides both encryption and authentication (one-step verification)
- **Session Isolation**: Each transfer is independent (new nonces, new keys, new session_id)

### Network Compatibility
- **Raw Sockets**: Direct packet injection at IP layer (requires root)
- **MTU Planning**: MAX_PAYLOAD=900 bytes leaves room for headers and AEAD tag (~50 bytes total overhead), safe for AWS VPC (1500 MTU)
- **AWS Recommendations**: Test on t3.micro with /swap space for large files (800MB+)
- **Timeout Tuning**: TIMEOUT=1.0s handles network latency up to ~500ms RTT

### Known Limitations
- Requires root privilege (raw socket operations)
- Limited to single-file transfers (no bulk directory transfer)
- PSK is hardcoded (can override with `--psk-file` argument)
- No IPv6 support (IPv4 only)

## SRFT Packet Format Reference

All SRFT packets share a common 13-byte header:

```
+---------+---------+---------+---------+---------+---------+---------+
|  Type   |     Sequence Number (4 bytes)     |  ACK Number (4 bytes) |
| (1 byte)|                                   |                       |
+---------+---------+---------+---------+---------+-------+-----------+
|  Length (2 bytes) |  Checksum (2 bytes) |      Payload (variable)     |
+---------+---------+---------+---------+---------+-----+------+-----+
```

### Packet Types

| Type | Name | Direction | Encrypted | Used In |
|------|------|-----------|-----------|---------|
| 0 | REQUEST | Client→Server | ✅ Phase 2 | File transfer request (filename) |
| 1 | DATA | Server→Client | ✅ Phase 2 | File payload (max 900 bytes) |
| 2 | ACK | Client→Server | ✅ Phase 2 | Cumulative acknowledgement |
| 3 | END | Server→Client | ✅ Phase 2 | Signals end of file transfer |
| 4 | ERROR | Either | ❌ | Error message |
| 5 | CLIENT_HELLO | Client→Server | ❌ | Handshake: client nonce + HMAC |
| 6 | SERVER_HELLO | Server→Client | ❌ | Handshake: server nonce + session_id + HMAC |
| 7 | DIGEST | Server→Client | ✅ Phase 2 | SHA-256 file hash (32 bytes) |
| 8 | RESULT | Client→Server | ✅ Phase 2 | OK/FAIL (hash verification result) |

### Checksum (Phase 1)
- 16-bit one's-complement checksum (RFC 791 style)
- Computed over header + payload
- Zeros filled during computation; complements filled in final result

---

**Last Updated**: April 2026  
**Course**: CS5700 – Computer Networks  
**Project**: SRFT – Secure Reliable File Transfer Protocol
