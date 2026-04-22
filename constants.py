PIPING_SERVERS = [
    'ppng.io',
    'piping.nwtgck.org',
    'piping.onrender.com',
    'piping.glitch.me',
]

STUN_HOSTS = [
    {'host': 'stun.l.google.com',      'port': 19302},
    {'host': 'stun1.l.google.com',     'port': 19302},
    {'host': 'stun2.l.google.com',     'port': 19302},
    {'host': 'stun.cloudflare.com',    'port': 3478},
    {'host': 'stun.stunprotocol.org',  'port': 3478},
    {'host': 'global.stun.twilio.com', 'port': 3478},
    {'host': 'stun.ekiga.net',         'port': 3478},
]

F_RELAY_ANN = 0x20
F_RELAY_REQ = 0x21
F_RELAY_FWD = 0x22

F_PEX        = 0x30
PEX_MAX      = 20
PEX_INTERVAL = 60_000

HARDCODED_SEEDS = []

HARDCODED_HTTP_BOOTSTRAP = [
    'https://bootstrap-4eft.onrender.com',
    'https://bootsrtap.firestarp.workers.dev',
]

PEER_CACHE_EMIT_MS = 30_000

RELAY_NAT_OPEN = {'full_cone', 'open'}
RELAY_MAX      = 20
RELAY_ANN_MS   = 30_000
RELAY_BAN_MS   = 5 * 60_000

BOOTSTRAP_TIMEOUT = 15_000

MAX_PEERS      = 100
MAX_ADDRS_PEER = 4
PEER_TIMEOUT   = 60_000
ANNOUNCE_MS    = 18_000
HEARTBEAT_MS   = 1_000
PUNCH_TRIES    = 8
PUNCH_INTERVAL = 300

GOSSIP_MAX = 200_000
GOSSIP_TTL = 30_000

D_DEFAULT = 6
D_MIN     = 4
D_MAX     = 16
D_LOW     = 4
D_HIGH    = 16
D_GOSSIP  = 6
IHAVE_MAX = 200

BATCH_MTU      = 1400
BATCH_INTERVAL = 2

QUEUE_CTRL = 256
QUEUE_DATA = 2048

BLOOM_BITS   = 64 * 1024 * 1024
BLOOM_HASHES = 5
BLOOM_ROTATE = 5 * 60 * 1000

SYNC_CACHE_MAX  = 10_000
SYNC_CHUNK_SIZE = 900
SYNC_TIMEOUT    = 30_000
HAVE_BATCH      = 64

MAX_PAYLOAD   = 1200
FRAG_HDR      = 12
FRAG_DATA_MAX = MAX_PAYLOAD - FRAG_HDR
FRAG_TIMEOUT  = 10_000

CWND_INIT  = 16
CWND_MAX   = 512
CWND_DECAY = 0.75

RATE_PER_SEC = 128
RATE_BURST   = 256

RTT_ALPHA = 0.125
RTT_INIT  = 100

DRAIN_TIMEOUT     = 2000
STUN_FAST_TIMEOUT = 1500

TAG_LEN   = 16
NONCE_LEN = 12

F_DATA      = 0x01
F_PING      = 0x03
F_PONG      = 0x04
F_FRAG      = 0x0B
F_GOAWAY    = 0x0A
F_HAVE      = 0x10
F_WANT      = 0x11
F_CHUNK     = 0x12
F_BATCH     = 0x13
F_CHUNK_ACK = 0x14

MCAST_ADDR = '239.0.0.1'
MCAST_PORT = 45678
F_LAN      = 0x09

