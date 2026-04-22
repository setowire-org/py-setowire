# Setowire - Python

A lightweight P2P networking library built on UDP. No central servers, no brokers — peers find each other and communicate directly.

Built to be simple enough that the protocol fits in your head.

---

## Why

Most P2P libraries are either too heavy or too tied to a specific runtime. Setowire is small, auditable, and designed to be reimplemented in any language. The wire protocol is documented and intentionally minimal.

---

## Requirements

- Python 3.11+
- `cryptography` package (X25519 + ChaCha20-Poly1305)

## Install

```bash
pip install py-setowire
```

```bash
# Termux (Android)
pkg install python
pip install py-setowire

# Debian / Ubuntu
sudo apt install python3 python3-pip
pip install py-setowire

# Arch
sudo pacman -S python python-pip
pip install py-setowire

# macOS (Homebrew)
brew install python
pip install py-setowire
```

---

## How it works

Peers discover each other through multiple strategies running in parallel — whichever works first wins:

- **DHT** — decentralized peer discovery by topic
- **Piping servers** — HTTPS rendezvous for peers behind strict NATs
- **LAN multicast** — instant discovery on local networks
- **HTTP bootstrap nodes** — fallback seed servers
- **Peer cache** — remembers peers from previous sessions

Once connected, all traffic is encrypted end-to-end with X25519 + ChaCha20-Poly1305. Peers that detect they have a full-cone NAT automatically become relays for others.

---

## File structure

```
constants.py   — all tuneable parameters and frame type definitions
crypto.py      — X25519 key exchange, ChaCha20-Poly1305 encrypt/decrypt
structs.py     — BloomFilter, LRU, RingBuffer, PayloadCache
framing.py     — packet fragmentation, jitter buffer, batch UDP sender
dht_lib.py     — minimal DHT for decentralized topic-based discovery
peer.py        — per-peer state: queues, congestion control, multipath
swarm.py       — main class: discovery, mesh, relay, sync, gossip
setowire/      — package entry point
  __init__.py
chat.py        — example terminal chat app
```

---

## Quick start

```python
import asyncio
import hashlib
from setowire import Swarm

async def main():
    swarm = Swarm()
    topic = hashlib.sha256(b'my-topic').digest()

    await swarm.join(topic, announce=True, lookup=True)

    swarm.on('connection', lambda peer: peer.write(b'hello'))
    swarm.on('data', lambda data, peer: print('got:', data))

    await asyncio.sleep(3600)

asyncio.run(main())
```

---

## API

### `Swarm(opts?)`

| option | default | description |
|---|---|---|
| `seed` | random | hex string — deterministic identity |
| `max_peers` | 100 | max simultaneous connections |
| `relay` | False | force relay mode regardless of NAT |
| `bootstrap` | [] | `["host:port"]` bootstrap nodes |
| `seeds` | [] | additional hardcoded seed peers |
| `storage` | None | pluggable storage backend (see [Persistent storage](#persistent-storage)) |
| `store_cache_max` | 10000 | max entries kept in the in-memory cache |
| `on_save_peers` | None | `(peers) -> None` called when the peer cache is updated |
| `on_load_peers` | None | `() -> peers` called on startup to restore known peers |

### `await swarm.join(topic, announce=True, lookup=True)`

Start announcing and/or looking up peers on a topic. `topic` is a `bytes` object (usually a hash).

### `swarm.broadcast(data)`

Send data to all connected peers. Returns number of peers reached.

### `swarm.store(key, value)`

Store a value in the local cache, persist it to the storage backend if one is set, and announce to the mesh that you have it.

### `await swarm.fetch(key, timeout?)`

Fetch a value. Lookup order:

1. In-memory cache
2. Storage backend (if set)
3. Network — sends a WANT to the mesh and waits up to `timeout` ms (default 30s)

Returns `bytes`.

### `await swarm.destroy()`

Graceful shutdown. Notifies peers and closes the socket.

### Events

| event | args | description |
|---|---|---|
| `connection` | `peer` | new peer connected |
| `data` | `data, peer` | message received |
| `disconnect` | `peer_id` | peer dropped |
| `sync` | `key, value` | value received from network |
| `nat` | — | public address discovered |

---

## Persistent storage

By default, `store()` and `fetch()` only use an in-memory LRU cache — data is lost when the process exits.

To persist data across restarts, pass a `storage` object with async `get` and `set` methods:

```python
swarm = Swarm({'storage': my_backend})
```

The backend must implement:

```python
async def get(self, key: str) -> bytes | None: ...
async def set(self, key: str, value: bytes) -> None: ...
```

Any async key-value store works. Examples:

**aiosqlite**
```python
import aiosqlite

class SQLiteStorage:
    def __init__(self, path):
        self._path = path
        self._db   = None

    async def open(self):
        self._db = await aiosqlite.connect(self._path)
        await self._db.execute('CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v BLOB)')
        await self._db.commit()

    async def get(self, key):
        async with self._db.execute('SELECT v FROM kv WHERE k = ?', (key,)) as cur:
            row = await cur.fetchone()
            return row[0] if row else None

    async def set(self, key, value):
        await self._db.execute('INSERT OR REPLACE INTO kv (k, v) VALUES (?, ?)', (key, value))
        await self._db.commit()

storage = SQLiteStorage('data.db')
await storage.open()
swarm = Swarm({'storage': storage})
```

**aiofiles (plain JSON file — simple, not for large data)**
```python
import aiofiles
import json

class JSONStorage:
    def __init__(self, path):
        self._path = path

    async def get(self, key):
        try:
            async with aiofiles.open(self._path, 'r') as f:
                data = json.loads(await f.read())
            v = data.get(key)
            return bytes.fromhex(v) if v else None
        except Exception:
            return None

    async def set(self, key, value):
        try:
            async with aiofiles.open(self._path, 'r') as f:
                data = json.loads(await f.read())
        except Exception:
            data = {}
        data[key] = value.hex()
        async with aiofiles.open(self._path, 'w') as f:
            await f.write(json.dumps(data))

swarm = Swarm({'storage': JSONStorage('store.json')})
```

If no `storage` is provided, the library works fine — values that aren't in memory will be fetched from the network instead.

---

## Protocol

The wire protocol is plain UDP. Each packet starts with a 1-byte frame type:

| byte | type | description |
|---|---|---|
| `0x01` | DATA | encrypted application data |
| `0x03` | PING | keepalive + RTT measurement |
| `0x04` | PONG | keepalive reply |
| `0x0A` | GOAWAY | graceful disconnect |
| `0x0B` | FRAG | fragment of a large message |
| `0x13` | BATCH | multiple frames in one datagram |
| `0x14` | CHUNK_ACK | acknowledgement for reliable multi-chunk transfers |
| `0x20` | RELAY_ANN | peer announcing itself as relay |
| `0x21` | RELAY_REQ | request introduction via relay |
| `0x22` | RELAY_FWD | relay forwarding an introduction |
| `0x30` | PEX | peer exchange |

Handshake is two frames: `0xA1` (hello) and `0xA2` (hello ack). Each carries the sender's ID and raw X25519 public key. After that, all data is encrypted.

The session key derivation label is `p2p-v12-session`. The peer with the lexicographically lower ID uses the first 32 bytes as send key; the other peer flips them.
For cross-runtime compatibility, that ordering uses the on-wire ID prefix (first 8 bytes / 16 hex chars). If two peers ever collide on that prefix, Python falls back to lexicographic ordering of full X25519 public keys.

### Reliable chunk transfer

When a value larger than 900 bytes is requested via `fetch()`, the sender uses a sliding window protocol instead of fire-and-forget:

1. Sender splits the value into 900-byte chunks and sends the first 8 in parallel (window size = 8)
2. Receiver sends a `CHUNK_ACK` frame for each chunk it receives
3. Sender retransmits any chunk that isn't acknowledged within 1.5 seconds (RTO)
4. As each ACK arrives, the sender advances the window and sends the next unacknowledged chunk
5. Transfer completes when all chunks are acknowledged; a 60-second safety timeout cleans up any stale state

Small values (≤ 900 bytes) are still fire-and-forget — no ACK needed.

This is what makes large transfers like video files reliable over UDP.

---

## Porting to another language

The minimum you need to implement:

1. X25519 key exchange + HKDF-SHA256 to derive send/recv keys
2. ChaCha20-Poly1305 encrypt/decrypt with a 12-byte nonce (4-byte session ID + 8-byte counter)
3. The handshake frames (`0xA1` / `0xA2`)
4. DATA frame (`0x01`) with the encrypted payload
5. PING/PONG for keepalive

Everything else (DHT, relay, gossip, PEX, reliable chunks) is optional and can be added incrementally.

---

## Chat example

```bash
# From a cloned repo
python -m chat <nick> [room]
python -m chat alice myroom
```

Commands: `/peers`, `/nat`, `/quit`

---

## License

MIT

