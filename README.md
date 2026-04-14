# SRFT over Raw UDP — Phase 1 + Phase 2

This project implements a secure reliable file transfer protocol on top of raw UDP sockets.
Both the client and the server use `SOCK_RAW`, and the code manually builds the IPv4 and UDP headers.

## What is implemented

### Phase 1 reliability
- manual IPv4 + UDP header construction with `SOCK_RAW`
- SRFT packet format with checksum validation
- sequence numbers
- cumulative ACK numbers
- sliding-window sending on the server
- retransmission on timeout
- client-side reordering buffer
- receiver window check for out-of-window packets

### Phase 2 security
- pre-shared key (PSK) authentication
- handshake with `CLIENT_HELLO` / `SERVER_HELLO`
- per-session key derivation using HKDF-SHA256
- AES-GCM AEAD protection for DATA, ACK, DIGEST, END, ERROR, RESULT
- authenticated metadata using AAD: `session_id`, `pkt_type`, `seq`, `ack`
- replay / duplicate drop counters
- final SHA-256 end-to-end verification

### Testing helpers
- `packet_loss_test.py` for packet-loss testing with `tc netem`
- built-in server attack modes:
  - `--attack tamper`
  - `--attack replay`
  - `--attack inject`
- configurable PSK loading with `--psk-file`

## Files
- `server.py`: raw-socket secure server with sliding window and ACK receiver thread
- `client.py`: raw-socket secure client with reorder buffer and cumulative ACKs
- `packet.py`: SRFT packet encode/decode/checksum
- `raw_utils.py`: manual IPv4/UDP header building and parsing
- `security.py`: PSK loading, HMAC, HKDF, AES-GCM, SHA-256 helpers
- `packet_loss_test.py`: automated loss / attack test runner

## Basic run

Linux / AWS only, usually with sudo:

```bash
sudo python3 server.py --server-ip 127.0.0.1 --client-ip 127.0.0.1
sudo python3 client.py big.txt 127.0.0.1 127.0.0.1 --output downloaded_big.txt
```

## Useful options

### Server

```bash
sudo python3 server.py \
  --server-ip 172.31.0.10 \
  --client-ip 172.31.0.11 \
  --window-size 8 \
  --timeout 0.5 \
  --psk-file psk.bin
```

Security test examples:

```bash
sudo python3 server.py --server-ip 127.0.0.1 --client-ip 127.0.0.1 --attack tamper --attack-seq 1
sudo python3 server.py --server-ip 127.0.0.1 --client-ip 127.0.0.1 --attack replay --attack-seq 1
sudo python3 server.py --server-ip 127.0.0.1 --client-ip 127.0.0.1 --attack inject --attack-seq 1
```

### Client

```bash
sudo python3 client.py big.txt 172.31.0.10 172.31.0.11 \
  --server-port 12000 \
  --client-port 12001 \
  --receiver-window 64 \
  --ack-every 2 \
  --psk-file psk.bin \
  --output downloaded_big.txt
```

## PSK setup

Create a file once and reuse it on both client and server:

```bash
python3 - <<'PY'
import os
open('psk.bin', 'wb').write(os.urandom(32))
print('wrote psk.bin')
PY
```

Wrong-PSK test: run the server with one PSK file and the client with a different PSK file.
Expected result: handshake fails and no valid file is produced.

## Packet-loss / security test script

### Phase 1 baseline under loss

```bash
python3 packet_loss_test.py \
  --filename big.txt \
  --server-ip 127.0.0.1 \
  --client-ip 127.0.0.1 \
  --interface lo \
  --loss 3% \
  --delay 40ms
```

### Tamper test

```bash
python3 packet_loss_test.py --filename big.txt --skip-tc --attack tamper --attack-seq 1
```

### Replay test

```bash
python3 packet_loss_test.py --filename big.txt --skip-tc --attack replay --attack-seq 1
```

### Forged injection test

```bash
python3 packet_loss_test.py --filename big.txt --skip-tc --attack inject --attack-seq 1
```

## Notes
- Raw sockets require root privileges and are most reliable on Linux / AWS EC2.
- The transfer is successful only when the client reconstructs the file and the final SHA-256 matches.
- The automated test script also compares MD5 so you can satisfy the Phase 1 grading expectation.
