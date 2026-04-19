# Packet types
REQUEST = 0
DATA = 1
ACK = 2
END = 3
ERROR = 4

# Phase 2 secure control packets
CLIENT_HELLO = 5
SERVER_HELLO = 6
DIGEST = 7
RESULT = 8

# Header length (bytes)
HEADER_LEN = 13

# Application payload size (SRFT payload inside UDP payload)
# Leave room for AES-GCM overhead
MAX_PAYLOAD = 900
RAW_RECV_BUFFER = 65535

# Reliability defaults
TIMEOUT = 1.0  # Increased from 0.5s → 1.0s (large file needs patience)
MAX_RETRIES = 15
WINDOW_SIZE = 16  # Increased from 8 → 16 (more aggressive pipelining)
ACK_POLL_INTERVAL = 0.01
END_RETRIES = 10
MAX_IDLE_TIMEOUTS = 100  # Keep this: 100 * 1.0s = 100 seconds max wait 

# Default ports
DEFAULT_SERVER_PORT = 12000
DEFAULT_CLIENT_PORT = 12001

# ----------------------------
# Phase 2 security constants
# ----------------------------
VERSION = 1

CLIENT_NONCE_LEN = 16
SERVER_NONCE_LEN = 16
SESSION_ID_LEN = 8
HMAC_LEN = 32

AES_KEY_LEN = 32          # AES-256
NONCE_PREFIX_LEN = 4      # 4-byte prefix
AES_GCM_NONCE_LEN = 12    # 4-byte prefix + 8-byte counter

# Pre-shared key
PSK = b"replace-with-32+bytes-random-key!!!"