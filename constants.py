# Packet types
REQUEST = 0
DATA = 1
ACK = 2
END = 3
ERROR = 4

# Header length (bytes)
HEADER_LEN = 13

# Application payload size (SRFT payload inside UDP payload)
MAX_PAYLOAD = 1024
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
