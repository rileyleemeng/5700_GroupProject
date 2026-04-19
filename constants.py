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
MAX_PAYLOAD = 1200
RAW_RECV_BUFFER = 65535

# Reliability defaults
TIMEOUT = 0.5
MAX_RETRIES = 15
WINDOW_SIZE = 8
ACK_POLL_INTERVAL = 0.01
END_RETRIES = 10
MAX_IDLE_TIMEOUTS = 20

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
# 先写死，后面也可以改成从配置文件读取
PSK = b"replace-with-32+bytes-random-key!!!"