import asyncio
import hashlib
import json
import os
import socket
import struct
import time
import urllib.request
import urllib.error
import threading
import concurrent.futures

from constants import (
    PIPING_SERVERS, STUN_HOSTS,
    F_RELAY_ANN, F_RELAY_REQ, F_RELAY_FWD,
    F_PEX, PEX_MAX, PEX_INTERVAL,
    HARDCODED_SEEDS, HARDCODED_HTTP_BOOTSTRAP,
    PEER_CACHE_EMIT_MS,
    RELAY_NAT_OPEN, RELAY_MAX, RELAY_ANN_MS, RELAY_BAN_MS,
    BOOTSTRAP_TIMEOUT,
    MAX_PEERS, PEER_TIMEOUT, ANNOUNCE_MS,
    HEARTBEAT_MS, PUNCH_TRIES, PUNCH_INTERVAL,
    GOSSIP_MAX, GOSSIP_TTL,
    D_DEFAULT, D_MIN, D_MAX, D_LOW, D_HIGH, D_GOSSIP, IHAVE_MAX,
    BLOOM_BITS, BLOOM_HASHES,
    SYNC_CACHE_MAX, SYNC_CHUNK_SIZE, SYNC_TIMEOUT, HAVE_BATCH,
    FRAG_HDR,
    DRAIN_TIMEOUT,
    F_DATA, F_PING, F_PONG, F_FRAG, F_GOAWAY,
    F_HAVE, F_WANT, F_CHUNK, F_BATCH, F_CHUNK_ACK,
    MCAST_ADDR, MCAST_PORT, F_LAN,
    RTT_ALPHA,
)
from structs import BloomFilter, LRU, PayloadCache
from crypto import generate_x25519, derive_session, decrypt
from framing import xor_hash, BatchSender, fragment_payload
from peer import Peer
from dht_lib import SimpleDHT

def _now_ms():
    return time.monotonic() * 1000

def _is_local_id_lower(local_id_hex: str, remote_id_hex: str, local_pub_raw: bytes, remote_pub_raw: bytes) -> bool:
    local_short = (local_id_hex or '')[:16]
    remote_short = (remote_id_hex or '')[:16]
    if local_short != remote_short:
        return local_short < remote_short
    if not isinstance(local_pub_raw, (bytes, bytearray)) or len(local_pub_raw) != 32:
        raise ValueError('local_pub_raw must be 32-byte bytes')
    if not isinstance(remote_pub_raw, (bytes, bytearray)) or len(remote_pub_raw) != 32:
        raise ValueError('remote_pub_raw must be 32-byte bytes')
    return bytes(local_pub_raw) < bytes(remote_pub_raw)

def _local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return '127.0.0.1'

class _SwarmProtocol(asyncio.DatagramProtocol):
    def __init__(self, swarm):
        self._swarm = swarm

    def connection_made(self, transport):
        self._swarm._transport = transport
        self._swarm._ready_event.set()

    def datagram_received(self, data, addr):
        self._swarm._recv(data, addr)

    def error_received(self, exc):
        pass

class Swarm:
    def __init__(self, opts=None):
        opts = opts or {}

        self._transport     = None
        self._mcast_sock    = None
        self._batch         = None
        self._lip           = _local_ip()
        self._lport         = None
        self._peers         = {}
        self._addr_to_id    = {}
        self._dialing       = set()
        self._destroyed     = False
        self._announcers    = []
        self._max_peers     = opts.get('max_peers', MAX_PEERS)
        self._ready_event   = asyncio.Event()
        self._listeners     = {}

        self._relays      = {}
        self._is_relay    = opts.get('relay', False)
        self._relay_bans  = {}
        self._relay_idx   = 0

        piping = opts.get('piping_servers', [])
        if piping:
            if opts.get('exclusive_piping'):
                self._piping_servers = list(set(piping))
            else:
                self._piping_servers = list(set(piping + PIPING_SERVERS))
        else:
            self._piping_servers = list(PIPING_SERVERS)

        self._bootstrap_nodes = opts.get('bootstrap', [])
        self._bootstrap_http  = opts.get('bootstrap_http', []) + HARDCODED_HTTP_BOOTSTRAP
        self._peer_cache      = {}
        self._on_save_peers   = opts.get('on_save_peers', None)
        self._on_load_peers   = opts.get('on_load_peers', None)
        self._load_peer_cache()

        self._hardcoded_seeds = opts.get('seeds', []) + list(HARDCODED_SEEDS)
        self._relay_list      = self._piping_servers

        self._my_x25519 = generate_x25519(opts.get('seed', None))
        self._id        = hashlib.sha256(self._my_x25519['pub_raw']).digest()[:20].hex()

        self.nat_type      = 'unknown'
        self.public_address = None

        self._bloom         = BloomFilter(BLOOM_BITS, BLOOM_HASHES)
        self._gossip_seen   = LRU(GOSSIP_MAX, GOSSIP_TTL)
        self._mesh_d        = D_DEFAULT
        self._last_mesh_adapt = 0
        self._ihave_buf     = []
        self._payload_cache = PayloadCache(8192)
        self._store         = LRU(opts.get('store_cache_max', SYNC_CACHE_MAX))
        self._storage       = opts.get('storage', None)
        self._want_pending  = {}
        self._chunk_assembly = {}
        self._reliable_tx   = {}
        self._topic_hash    = None
        self._dht           = None
        self._hb_handle     = None
        self._stun_pending  = {}

        self._loop = asyncio.get_event_loop()
        self._init_task = self._loop.create_task(self._init())

    @property
    def peers(self):
        return list(self._peers.values())

    @property
    def size(self):
        return len(self._peers)

    @property
    def mesh_peers(self):
        return [p for p in self.peers if p.in_mesh]

    def on(self, event, cb):
        self._listeners.setdefault(event, []).append(cb)

    def once(self, event, cb):
        def _wrapper(*args):
            self._listeners[event].remove(_wrapper)
            cb(*args)
        self._listeners.setdefault(event, []).append(_wrapper)

    def off(self, event, cb):
        cbs = self._listeners.get(event, [])
        if cb in cbs:
            cbs.remove(cb)

    def _emit(self, event, *args):
        for cb in list(self._listeners.get(event, [])):
            cb(*args)

    def store(self, key, value: bytes):
        k = key if isinstance(key, str) else key.hex()
        v = value if isinstance(value, bytes) else value.encode()
        self._store.add(k, v)
        if self._storage:
            self._loop.create_task(self._storage_set(k, v))
        self._announce_have([k])

    async def _storage_set(self, k: str, v: bytes):
        try:
            await self._storage.set(k, v)
        except Exception:
            pass

    async def fetch(self, key, timeout=SYNC_TIMEOUT):
        k = key if isinstance(key, str) else key.hex()
        local = self._store.get(k)
        if local:
            return local
        if self._storage:
            try:
                disk = await self._storage.get(k)
                if disk:
                    self._store.add(k, disk)
                    return disk
            except Exception:
                pass
        fut = self._loop.create_future()

        def _timeout():
            if not fut.done():
                fut.set_exception(asyncio.TimeoutError(f'fetch timeout: {k}'))
            self._want_pending.pop(k, None)

        handle = self._loop.call_later(timeout / 1000, _timeout)
        self._want_pending[k] = {'future': fut, 'handle': handle}
        self._send_want(k)
        return await fut

    async def join(self, topic_buf: bytes, announce=True, lookup=True):
        await self._ready_event.wait()

        topic_hex  = topic_buf.hex() if isinstance(topic_buf, bytes) else topic_buf
        topic_hash = hashlib.sha1(topic_hex.encode()).hexdigest()[:12]
        self._topic_hash = topic_hash

        ANNOUNCE_PATH = f'/p2p-{topic_hash}-announce'
        inbox         = f'/p2p-{topic_hash}-{self._id}'
        timers        = []

        def _http_post_sync(url, body):
            try:
                data = json.dumps(body).encode()
                req  = urllib.request.Request(
                    url, data=data,
                    headers={'Content-Type': 'application/json'}
                )
                urllib.request.urlopen(req, timeout=8)
            except Exception:
                pass

        async def piping_post(host, path, body):
            url = f'https://{host}{path}'
            await self._loop.run_in_executor(None, _http_post_sync, url, body)

        def _http_get_sync(url, timeout=120):
            try:
                req  = urllib.request.Request(url)
                resp = urllib.request.urlopen(req, timeout=timeout)
                return resp.read().decode()
            except Exception:
                return None

        async def piping_get(host, path, cb):
            url = f'https://{host}{path}'
            while not self._destroyed:
                text = await self._loop.run_in_executor(None, _http_get_sync, url, 120)
                if text:
                    try:
                        d = json.loads(text.strip())
                        if d:
                            cb(d)
                    except Exception:
                        pass
                if not self._destroyed:
                    await asyncio.sleep(0.1)

        def post_all(path, body):
            for host in self._piping_servers:
                self._loop.create_task(piping_post(host, path, body))

        def dial_bootstrap_node(hostport):
            c = hostport.rfind(':')
            if c == -1:
                return
            host = hostport[:c]
            port = int(hostport[c+1:]) or 49737
            self._loop.create_task(self._resolve_and_dial(host, port))

        async def schedule_bootstrap_fallback():
            if not self._bootstrap_nodes:
                return
            await asyncio.sleep(BOOTSTRAP_TIMEOUT / 1000)
            if len(self._peers) == 0 and not self._destroyed:
                for n in self._bootstrap_nodes:
                    dial_bootstrap_node(n)

        async def start_dht():
            self._dht = SimpleDHT({'port': 0})
            await self._dht.start()

            if self._bootstrap_nodes:
                nodes = []
                for hp in self._bootstrap_nodes:
                    c = hp.rfind(':')
                    if c == -1:
                        continue
                    nodes.append({'ip': hp[:c], 'port': int(hp[c+1:]) or 49737})
                try:
                    await self._dht.bootstrap(nodes)
                except Exception:
                    pass

            if announce:
                def do_announce():
                    if self._destroyed:
                        return
                    self._dht.put(f'topic:{topic_hash}:{self._id}', json.dumps(self._me()))

                do_announce()
                handle = self._loop.call_later(ANNOUNCE_MS / 1000, do_announce)
                timers.append(handle)
                self._announcers.append(handle)

            if lookup:
                def do_lookup():
                    if self._destroyed:
                        return
                    for key, raw in self._dht.storage.items():
                        try:
                            info = json.loads(raw)
                        except Exception:
                            continue
                        if not info.get('id') or info['id'] == self._id:
                            continue
                        if key.startswith('relay:') and info['id'] not in self._relays:
                            self._register_relay(info['id'], info['ip'], info['port'])
                        existing = self._peers.get(info['id'])
                        if existing and existing._open and existing._session:
                            continue
                        if info.get('ip') and info.get('port'):
                            self._meet(info)

                self._loop.call_later(1.5, do_lookup)
                h = self._loop.call_later(ANNOUNCE_MS / 1000, do_lookup)
                timers.append(h)

        def start_relay():
            self._loop.create_task(start_dht())
            self._dial_peer_cache()
            self._dial_hardcoded_seeds()
            self._loop.create_task(self._query_bootstrap_http())

            if announce:
                post_all(ANNOUNCE_PATH, self._me())
                self._loop.call_later(2, lambda: post_all(ANNOUNCE_PATH, self._me()) if not self._destroyed else None)
                self._loop.call_later(5, lambda: post_all(ANNOUNCE_PATH, self._me()) if not self._destroyed else None)

                def _repeat_announce():
                    if self._destroyed:
                        return
                    post_all(ANNOUNCE_PATH, self._me())
                    h = self._loop.call_later(ANNOUNCE_MS / 1000, _repeat_announce)
                    timers.append(h)
                    self._announcers.append(h)

                h = self._loop.call_later(ANNOUNCE_MS / 1000, _repeat_announce)
                timers.append(h)
                self._announcers.append(h)

            if lookup:
                for host in self._piping_servers:
                    self._loop.create_task(piping_get(host, ANNOUNCE_PATH, lambda info: (
                        (post_all(f'/p2p-{topic_hash}-{info["id"]}', self._me()) if announce else None) or
                        (self._meet(info) if info.get('id') and info['id'] != self._id and info.get('ip') and info.get('port') else None)
                    )))
                    self._loop.create_task(piping_get(host, inbox, lambda info: (
                        self._meet(info) if info.get('id') and info['id'] != self._id and info.get('ip') and info.get('port') else None
                    )))

            self._loop.create_task(schedule_bootstrap_fallback())

        await self._ready_event.wait()
        if self.public_address:
            start_relay()
        else:
            called = False

            def on_nat():
                nonlocal called
                if not called:
                    called = True
                    start_relay()

            self.once('nat', on_nat)
            self._loop.call_later(5.0, lambda: (start_relay() if not called else None))

        return self

    def broadcast(self, data: bytes) -> int:
        sent = 0
        for peer in self.peers:
            if peer._session and peer._open:
                peer.write(data)
                sent += 1
        return sent

    async def destroy(self):
        if self._destroyed:
            return
        self._destroyed = True
        for h in self._announcers:
            try:
                h.cancel()
            except Exception:
                pass
        if self._hb_handle:
            self._hb_handle.cancel()
        goaway = bytes([F_GOAWAY])
        for peer in self.peers:
            try:
                peer._send_raw_now(goaway)
            except Exception:
                pass
        await asyncio.sleep(DRAIN_TIMEOUT / 1000)
        self._emit_peer_cache()
        if self._batch:
            self._batch.destroy()
        if self._transport:
            self._transport.close()
        if self._dht:
            self._dht.destroy()
        for p in self.peers:
            p.destroy()
        self._peers.clear()
        self._emit('close')

    async def _init(self):
        self._transport, _ = await self._loop.create_datagram_endpoint(
            lambda: _SwarmProtocol(self),
            local_addr=('0.0.0.0', 0),
        )
        self._lport = self._transport.get_extra_info('sockname')[1]
        self._batch = BatchSender(self._transport)
        self._heartbeat()
        self._stun_lazy()
        self._init_lan()
        self._init_pex()
        self._init_peer_cache_emit()
        self._loop.call_later(0.5, lambda: self._loop.create_task(self._query_bootstrap_http()))

    def _stun_lazy(self):
        async def attempt():
            if self._destroyed:
                return
            tasks = [self._loop.create_task(self._stun_probe(s, 3.0)) for s in STUN_HOSTS]
            first = None
            pending = set(tasks)
            while pending and first is None:
                done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
                for t in done:
                    try:
                        result = t.result()
                        if result and first is None:
                            first = result
                    except Exception:
                        pass
            for t in pending:
                t.cancel()
            if first:
                self._ext           = first
                self.public_address = f'{first["ip"]}:{first["port"]}'
                self.nat_type       = 'unknown'
                self._emit('nat')
                self._loop.create_task(self._query_bootstrap_http())
                self._start_bootstrap_announce()
            else:
                self._loop.call_later(3, lambda: self._loop.create_task(attempt()))

        self._loop.create_task(attempt())

    async def _stun_probe(self, server, timeout):
        fut    = self._loop.create_future()
        req    = bytearray(20)
        struct.pack_into('>H', req, 0, 0x0001)
        struct.pack_into('>I', req, 4, 0x2112A442)
        txn_id = os.urandom(12)
        req[8:20] = txn_id

        def handler(data):
            if len(data) < 20 or struct.unpack_from('>H', data, 0)[0] != 0x0101:
                return False
            if data[8:20] != txn_id:
                return False
            length = struct.unpack_from('>H', data, 2)[0]
            off = 20
            while off + 4 <= 20 + length:
                attr_type = struct.unpack_from('>H', data, off)[0]
                attr_len  = struct.unpack_from('>H', data, off + 2)[0]
                off += 4
                if off + attr_len > len(data):
                    break
                if attr_type in (0x0001, 0x0020):
                    try:
                        if attr_type == 0x0001:
                            port = struct.unpack_from('>H', data, off + 2)[0]
                            ip   = f'{data[off+4]}.{data[off+5]}.{data[off+6]}.{data[off+7]}'
                        else:
                            port = struct.unpack_from('>H', data, off + 2)[0] ^ 0x2112
                            ip   = f'{data[off+4]^0x21}.{data[off+5]^0x12}.{data[off+6]^0xA4}.{data[off+7]^0x42}'
                        if not fut.done():
                            fut.set_result({'ip': ip, 'port': port})
                    except Exception:
                        pass
                    return True
                off += attr_len + (4 - attr_len % 4 if attr_len % 4 else 0)
            return False

        txn_key = bytes(txn_id)
        self._stun_pending[txn_key] = handler

        try:
            self._transport.sendto(bytes(req), (server['host'], server['port']))
        except Exception:
            self._stun_pending.pop(txn_key, None)
            return None

        try:
            return await asyncio.wait_for(asyncio.shield(fut), timeout=timeout)
        except Exception:
            return None
        finally:
            self._stun_pending.pop(txn_key, None)

    def _init_lan(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(('', MCAST_PORT))
            mreq = struct.pack('4sL', socket.inet_aton(MCAST_ADDR), socket.INADDR_ANY)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            sock.setblocking(False)
            self._mcast_sock = sock

            def _read_mcast():
                try:
                    while True:
                        data, addr = sock.recvfrom(1500)
                        if data and data[0] == F_LAN:
                            src = data[1:].decode(errors='ignore')
                            parts = src.split(':')
                            if len(parts) >= 3:
                                pid, ip, port_s = parts[0], parts[1], parts[2]
                                t_hash = parts[3] if len(parts) > 3 else ''
                                if pid == self._id:
                                    continue
                                if t_hash and self._topic_hash and t_hash != self._topic_hash:
                                    continue
                                if pid not in self._peers and pid not in self._dialing:
                                    self._dial(ip, int(port_s), pid, None, None)
                except BlockingIOError:
                    pass

            def _send_mcast():
                if self._destroyed:
                    return
                t_hash = self._topic_hash or ''
                msg = bytes([F_LAN]) + f'{self._id}:{self._lip}:{self._lport}:{t_hash}'.encode()
                try:
                    sock.sendto(msg, (MCAST_ADDR, MCAST_PORT))
                except Exception:
                    pass
                self._loop.call_later(5, _send_mcast)

            self._loop.add_reader(sock.fileno(), _read_mcast)
            self._loop.call_later(5, _send_mcast)
        except Exception:
            pass

    def _recv(self, buf: bytes, addr: tuple):
        if len(buf) < 2:
            return
        if len(buf) >= 20 and struct.unpack_from('>H', buf, 0)[0] == 0x0101 and self._stun_pending:
            txn_key = bytes(buf[8:20])
            handler = self._stun_pending.get(txn_key)
            if handler and handler(buf):
                return
        src  = f'{addr[0]}:{addr[1]}'
        t    = buf[0]

        if t == 0xA1:        self._on_hello(buf, src)
        elif t == 0xA2:      self._on_hello_ack(buf, src)
        elif t == F_DATA:    self._on_data(buf, src)
        elif t == F_PING:    self._on_ping(buf, src)
        elif t == F_PONG:    self._on_pong(buf, src)
        elif t == F_FRAG:    self._on_frag(buf, src)
        elif t == F_GOAWAY:  self._on_goaway(src)
        elif t == F_BATCH:   self._on_batch(buf, addr)
        elif t == F_HAVE:    self._on_have(buf, src)
        elif t == F_WANT:    self._on_want(buf, src)
        elif t == F_CHUNK:   self._on_chunk(buf, src)
        elif t == F_CHUNK_ACK: self._on_chunk_ack(buf, src)
        elif t == F_RELAY_ANN: self._on_relay_ann(buf, src)
        elif t == F_RELAY_REQ: self._on_relay_req(buf, src)
        elif t == F_RELAY_FWD: self._on_relay_fwd(buf, src)
        elif t == F_PEX:     self._on_pex(buf, src)

    def _on_batch(self, buf: bytes, addr: tuple):
        if len(buf) < 3:
            return
        count = buf[1]
        off   = 2
        for _ in range(count):
            if off + 2 > len(buf):
                break
            length = struct.unpack_from('>H', buf, off)[0]
            off += 2
            if off + length > len(buf):
                break
            self._recv(buf[off:off + length], addr)
            off += length

    def _send_hello(self, ip, port):
        id_buf = bytes.fromhex(self._id)
        frame  = bytes([0xA1]) + id_buf[:8] + self._my_x25519['pub_raw']
        try:
            self._transport.sendto(frame, (ip, int(port)))
        except Exception:
            pass

    def _send_hello_ack(self, ip, port):
        id_buf = bytes.fromhex(self._id)
        frame  = bytes([0xA2]) + id_buf[:8] + self._my_x25519['pub_raw']
        try:
            self._transport.sendto(frame, (ip, int(port)))
        except Exception:
            pass

    def _on_hello(self, buf: bytes, src: str):
        if len(buf) < 41:
            return
        pid       = buf[1:9].hex()
        their_pub = buf[9:41]
        if pid == self._id:
            return
        ip, port = src.rsplit(':', 1)
        self._send_hello_ack(ip, int(port))
        is_new = self._register_peer(pid, src, their_pub)
        if is_new:
            peer = self._peers[pid]
            self._add_to_mesh(peer)
            self._gossip_peer(ip, int(port), pid)
            self._send_have_summary(peer)
            self._peer_cache[src] = {'id': pid, 'ip': ip, 'port': int(port), 'last_seen': _now_ms()}
            self._emit('connection', peer)
            peer.emit('open')
        else:
            peer = self._peers.get(pid)
            if peer:
                peer._touch(src)

    def _on_hello_ack(self, buf: bytes, src: str):
        if len(buf) < 41:
            return
        pid       = buf[1:9].hex()
        their_pub = buf[9:41]
        if pid == self._id:
            return
        is_new = self._register_peer(pid, src, their_pub)
        if is_new:
            peer = self._peers[pid]
            ip, port = src.rsplit(':', 1)
            self._add_to_mesh(peer)
            self._gossip_peer(ip, int(port), pid)
            self._send_have_summary(peer)
            self._peer_cache[src] = {'id': pid, 'ip': ip, 'port': int(port), 'last_seen': _now_ms()}
            self._emit('connection', peer)
            peer.emit('open')
        else:
            peer = self._peers.get(pid)
            if peer:
                peer._touch(src)

    def _register_peer(self, pid: str, src: str, their_pub_raw: bytes) -> bool:
        if pid in self._peers:
            return False
        if len(self._peers) >= self._max_peers:
            return False
        peer              = Peer(self, pid, src)
        peer._their_pub_raw = their_pub_raw
        raw               = derive_session(self._my_x25519['private_key'], their_pub_raw)
        i_am_lo           = _is_local_id_lower(self._id, pid, self._my_x25519['pub_raw'], their_pub_raw)
        peer._session     = {
            'send_key':   raw['send_key']  if i_am_lo else raw['recv_key'],
            'recv_key':   raw['recv_key']  if i_am_lo else raw['send_key'],
            'session_id': raw['session_id'],
            'send_ctr':   0,
        }
        self._peers[pid]        = peer
        self._addr_to_id[src]   = pid
        self._dialing.discard(pid)
        return True

    def _on_data(self, buf: bytes, src: str):
        if len(buf) < 2:
            return
        pid  = self._addr_to_id.get(src)
        peer = self._peers.get(pid) if pid else None
        if not peer or not peer._session:
            return
        plain = decrypt(peer._session, buf[1:])
        if plain is None:
            return
        peer._touch(src)
        peer._on_ack()
        peer._score_up()
        msg_key = xor_hash(plain)
        self._payload_cache.set(msg_key, buf)
        self._ihave_buf.append(bytes.fromhex(msg_key))

        if plain and plain[0] == 0x7B:
            try:
                obj = json.loads(plain)
                if obj.get('_gossip'):
                    self._meet(obj)
                    return
            except Exception:
                pass

        if len(plain) >= 4:
            seq  = struct.unpack_from('>I', plain, 0)[0]
            data = plain[4:]
            peer._jitter.push(seq, data)
        else:
            if self._bloom.seen(msg_key):
                return
            peer.emit('data', plain)
            self._emit('data', plain, peer)
            self._flood_mesh(plain, pid)

    def _on_frag(self, buf: bytes, src: str):
        if len(buf) < 1 + FRAG_HDR:
            return
        pid  = self._addr_to_id.get(src)
        peer = self._peers.get(pid) if pid else None
        if not peer:
            return
        payload   = buf[1:]
        frag_id   = payload[0:8]
        frag_idx  = struct.unpack_from('>H', payload, 8)[0]
        frag_total = struct.unpack_from('>H', payload, 10)[0]
        data      = payload[FRAG_HDR:]
        assembled = peer._fragger.add(frag_id, frag_idx, frag_total, data)
        if assembled:
            msg_key = xor_hash(assembled)
            if self._bloom.seen(msg_key):
                return
            peer.emit('data', assembled)
            self._emit('data', assembled, peer)
            self._flood_mesh(assembled, peer.id)

    def _on_ping(self, buf: bytes, src: str):
        pid = self._addr_to_id.get(src)
        if not pid and len(buf) >= 17:
            sender_id = buf[9:17].hex()
            if sender_id in self._peers:
                pid = sender_id
        peer = self._peers.get(pid) if pid else None
        if peer:
            peer._touch(src)
        id_buf = bytes.fromhex(self._id)
        pong   = bytes([F_PONG]) + id_buf
        try:
            ip, port = src.rsplit(':', 1)
            self._transport.sendto(pong, (ip, int(port)))
        except Exception:
            pass

    def _on_pong(self, buf: bytes, src: str):
        pid = self._addr_to_id.get(src)
        if not pid and len(buf) >= 9:
            sender_id = buf[1:9].hex()
            if sender_id in self._peers:
                pid = sender_id
        peer = self._peers.get(pid) if pid else None
        if not peer:
            return
        if src not in self._addr_to_id:
            self._addr_to_id[src] = peer.id
        rtt = (_now_ms() - peer._last_ping_sent) if peer._last_ping_sent else peer.rtt
        peer._touch(src, rtt)
        peer._on_ack()
        peer.rtt = peer.rtt + RTT_ALPHA * (rtt - peer.rtt)

    def _on_goaway(self, src: str):
        pid = self._addr_to_id.get(src)
        if pid:
            self._drop(pid)
            self._emit('disconnect', pid)

    def _send_have_summary(self, peer):
        keys = list(self._store.keys())[:HAVE_BATCH]
        if not keys:
            return
        self._send_have_keys(peer, keys)

    def _announce_have(self, keys):
        for peer in self.mesh_peers:
            if peer._session and peer._open:
                self._send_have_keys(peer, keys)

    def _send_have_keys(self, peer, keys):
        parts = [bytes([F_HAVE, len(keys)])]
        for k in keys:
            kb = k.encode() if isinstance(k, str) else k
            parts.append(bytes([len(kb)]) + kb)
        peer.write_ctrl(b''.join(parts))

    def _send_want(self, key: str):
        kb  = key.encode() if isinstance(key, str) else key
        msg = bytes([F_WANT, len(kb)]) + kb
        for peer in self.mesh_peers:
            if peer._session and peer._open:
                peer.write_ctrl(msg)

    def _on_have(self, buf: bytes, src: str):
        if len(buf) < 3:
            return
        pid  = self._addr_to_id.get(src)
        peer = self._peers.get(pid) if pid else None
        if not peer:
            return
        count = buf[1]
        off   = 2
        for _ in range(count):
            if off >= len(buf):
                break
            klen = buf[off]; off += 1
            if off + klen > len(buf):
                break
            key = buf[off:off + klen].decode(); off += klen
            if key in self._want_pending:
                kb  = key.encode()
                msg = bytes([F_WANT, len(kb)]) + kb
                peer.write_ctrl(msg)

    def _on_want(self, buf: bytes, src: str):
        if len(buf) < 3:
            return
        pid  = self._addr_to_id.get(src)
        peer = self._peers.get(pid) if pid else None
        if not peer:
            return
        klen = buf[1]
        if len(buf) < 2 + klen:
            return
        key   = buf[2:2 + klen].decode()
        value = self._store.get(key)
        if not value:
            return
        kb = key.encode()

        # Small value — fire and forget
        if len(value) <= SYNC_CHUNK_SIZE:
            msg = bytes([F_CHUNK, len(kb)]) + kb + struct.pack('>H', len(value)) + value
            peer.write_ctrl(msg)
            return

        # Large value — reliable sliding window with ACK
        total   = -(-len(value) // SYNC_CHUNK_SIZE)
        tx_key  = f'{key}:{pid}'
        if tx_key in self._reliable_tx:
            return

        WINDOW = 8
        RTO_S  = 1.5

        acked  = [False] * total
        timers = [None]  * total
        tx     = {'acked': acked, 'timers': timers, 'done': False}
        self._reliable_tx[tx_key] = tx

        def cleanup():
            tx['done'] = True
            for t in tx['timers']:
                if t:
                    t.cancel()
            self._reliable_tx.pop(tx_key, None)

        # Safety timeout — 60s
        safety = self._loop.call_later(60, cleanup)

        ip, port_s = peer._best.rsplit(':', 1)

        def send_frame(i):
            if tx['done'] or tx['acked'][i]:
                return
            chunk = value[i * SYNC_CHUNK_SIZE: (i + 1) * SYNC_CHUNK_SIZE]
            msg   = bytes([F_CHUNK, len(kb)]) + kb + struct.pack('>HHH', 0xFFFF, i, total) + chunk
            # Send directly — chunk frames are too large for batching (> MTU)
            try:
                self._batch.send_now(ip, int(port_s), msg)
            except Exception:
                pass
            if tx['timers'][i]:
                tx['timers'][i].cancel()
            tx['timers'][i] = self._loop.call_later(RTO_S, lambda _i=i: send_frame(_i))

        def on_ack(idx):
            if tx['done']:
                return
            tx['acked'][idx] = True
            if tx['timers'][idx]:
                tx['timers'][idx].cancel()
                tx['timers'][idx] = None
            if all(tx['acked'][i] for i in range(total)):
                safety.cancel()
                cleanup()
                return
            # Send next unsent frame to keep the window full
            for i in range(total):
                if not tx['acked'][i] and not tx['timers'][i]:
                    send_frame(i)
                    break

        tx['on_ack'] = on_ack

        # Send initial window
        for i in range(min(WINDOW, total)):
            send_frame(i)

    def _on_chunk(self, buf: bytes, src: str):
        if len(buf) < 4:
            return
        o    = 1
        klen = buf[o]; o += 1
        if o + klen > len(buf):
            return
        key  = buf[o:o + klen].decode(); o += klen
        if o + 2 > len(buf):
            return
        vlen = struct.unpack_from('>H', buf, o)[0]; o += 2

        if vlen != 0xFFFF:
            if o + vlen > len(buf):
                return
            value = buf[o:o + vlen]
            self._store.add(key, value)
            if self._storage:
                self._loop.create_task(self._storage_set(key, value))
            pending = self._want_pending.get(key)
            if pending:
                pending['handle'].cancel()
                self._want_pending.pop(key, None)
                if not pending['future'].done():
                    pending['future'].set_result(value)
            self._emit('sync', key, value)
        else:
            if o + 4 > len(buf):
                return
            idx   = struct.unpack_from('>H', buf, o)[0]; o += 2
            total = struct.unpack_from('>H', buf, o)[0]; o += 2
            data  = buf[o:]
            if key not in self._chunk_assembly:
                def _cleanup(k=key):
                    self._chunk_assembly.pop(k, None)
                handle = self._loop.call_later(SYNC_TIMEOUT / 1000, _cleanup)
                self._chunk_assembly[key] = {'total': total, 'pieces': {}, 'handle': handle}
            asm = self._chunk_assembly[key]

            # Only store if not already received (duplicate protection)
            if idx not in asm['pieces']:
                asm['pieces'][idx] = bytes(data)

            # Send ACK after storing — confirms we actually have this piece
            pid2  = self._addr_to_id.get(src)
            peer2 = self._peers.get(pid2) if pid2 else None
            if peer2:
                kb2 = key.encode()
                ack = bytes([F_CHUNK_ACK, len(kb2)]) + kb2 + struct.pack('>H', idx)
                ip2, port2 = peer2._best.rsplit(':', 1)
                try:
                    self._batch.send_now(ip2, int(port2), ack)
                except Exception:
                    pass
            if len(asm['pieces']) == asm['total']:
                asm['handle'].cancel()
                self._chunk_assembly.pop(key, None)
                # Build value in order, skip any missing index gracefully
                parts = [bytes(asm['pieces'][i]) for i in range(asm['total']) if i in asm['pieces']]
                if len(parts) != asm['total']:
                    return  # missing pieces — wait for retransmit
                value = b''.join(parts)
                self._store.add(key, value)
                if self._storage:
                    self._loop.create_task(self._storage_set(key, value))
                pending = self._want_pending.get(key)
                if pending:
                    pending['handle'].cancel()
                    self._want_pending.pop(key, None)
                    if not pending['future'].done():
                        pending['future'].set_result(value)
                self._emit('sync', key, value)

    def _on_chunk_ack(self, buf: bytes, src: str):
        if len(buf) < 5:
            return
        o    = 1
        klen = buf[o]; o += 1
        if o + klen + 2 > len(buf):
            return
        key = buf[o:o + klen].decode(); o += klen
        idx = struct.unpack_from('>H', buf, o)[0]
        pid = self._addr_to_id.get(src)
        if not pid:
            return
        tx = self._reliable_tx.get(f'{key}:{pid}')
        if not tx or tx['done']:
            return
        tx['on_ack'](idx)

    def _check_become_relay(self):
        if self._is_relay:
            return
        if not (self.nat_type in RELAY_NAT_OPEN or self.nat_type == 'full_cone'):
            return
        if not hasattr(self, '_ext'):
            return
        self._is_relay = True
        self._announce_relay()
        self._announce_relay_dht()

        def _repeat():
            self._announce_relay()
            self._announce_relay_dht()
            h = self._loop.call_later(RELAY_ANN_MS / 1000, _repeat)
            self._announcers.append(h)

        h = self._loop.call_later(RELAY_ANN_MS / 1000, _repeat)
        self._announcers.append(h)

    def _announce_relay_dht(self):
        if not self._dht or not hasattr(self, '_ext') or not self._topic_hash:
            return
        self._dht.put(
            f'relay:{self._topic_hash}:{self._id}',
            json.dumps({'id': self._id, 'ip': self._ext['ip'], 'port': self._ext['port']})
        )

    def _announce_relay(self):
        if not self._is_relay or not hasattr(self, '_ext'):
            return
        id_buf = bytes.fromhex(self._id)
        ip_buf = self._ext['ip'].encode()
        frame  = bytes([F_RELAY_ANN]) + id_buf[:8] + bytes([len(ip_buf)]) + ip_buf + struct.pack('>H', self._ext['port'])
        for peer in self.peers:
            if peer._open:
                peer.write_ctrl(frame)

    def _register_relay(self, rid, ip, port):
        if len(self._relays) >= RELAY_MAX:
            oldest = min(self._relays.items(), key=lambda x: x[1]['last_seen'])
            self._relays.pop(oldest[0], None)
        self._relays[rid] = {'id': rid, 'ip': ip, 'port': port, 'last_seen': _now_ms(), 'fails': 0}

    def _on_relay_ann(self, buf: bytes, src: str):
        if len(buf) < 12:
            return
        o    = 1
        rid  = buf[o:o + 8].hex(); o += 8
        if rid == self._id:
            return
        ip_len = buf[o]; o += 1
        if o + ip_len + 2 > len(buf):
            return
        ip   = buf[o:o + ip_len].decode(); o += ip_len
        port = struct.unpack_from('>H', buf, o)[0]
        ban  = self._relay_bans.get(rid)
        if ban and _now_ms() - ban < RELAY_BAN_MS:
            return
        self._register_relay(rid, ip, port)

    def _request_via_relay(self, target_id: str) -> bool:
        now   = _now_ms()
        valid = [r for r in self._relays.values()
                 if not self._relay_bans.get(r['id']) or now - self._relay_bans[r['id']] >= RELAY_BAN_MS]
        if not valid:
            return False
        relay  = max(valid, key=lambda r: r['last_seen'])
        my_id  = bytes.fromhex(self._id)
        tgt_id = bytes.fromhex(target_id)
        my_ip  = (self._ext['ip'] if hasattr(self, '_ext') else self._lip).encode()
        frame  = bytes([F_RELAY_REQ]) + my_id[:8] + tgt_id[:8] + bytes([len(my_ip)]) + my_ip + struct.pack('>H', self._lport)
        try:
            self._transport.sendto(frame, (relay['ip'], relay['port']))
        except Exception:
            pass
        return True

    def _on_relay_req(self, buf: bytes, src: str):
        if not self._is_relay or len(buf) < 18:
            return
        o       = 1
        from_id = buf[o:o + 8].hex(); o += 8
        to_id   = buf[o:o + 8].hex(); o += 8
        ip_len  = buf[o]; o += 1
        if o + ip_len + 2 > len(buf):
            return
        from_ip   = buf[o:o + ip_len].decode(); o += ip_len
        from_port = struct.unpack_from('>H', buf, o)[0]
        fwd_ip    = from_ip.encode()
        fwd       = bytes([F_RELAY_FWD]) + bytes.fromhex(from_id)[:8] + bytes([len(fwd_ip)]) + fwd_ip + struct.pack('>H', from_port)
        to_peer   = self._peers.get(to_id)
        if to_peer and to_peer._open:
            to_peer.write_ctrl(fwd)

    def _on_relay_fwd(self, buf: bytes, src: str):
        if len(buf) < 12:
            return
        o      = 1
        rid    = buf[o:o + 8].hex(); o += 8
        ip_len = buf[o]; o += 1
        if o + ip_len + 2 > len(buf):
            return
        ip   = buf[o:o + ip_len].decode(); o += ip_len
        port = struct.unpack_from('>H', buf, o)[0]
        if rid == self._id:
            return
        if rid not in self._peers:
            self._dial(ip, port, rid, None, None)

    def _init_pex(self):
        def _pex_tick():
            if self._destroyed:
                return
            for peer in self.peers:
                if peer._open and peer._session:
                    self._send_pex(peer)
            self._loop.call_later(PEX_INTERVAL / 1000, _pex_tick)

        self._loop.call_later(PEX_INTERVAL / 1000, _pex_tick)

    def _send_pex(self, peer):
        known = [p for p in self.peers if p.id != peer.id and p._open and p._best][:PEX_MAX]
        if not known:
            return
        parts = [bytes([F_PEX, len(known)])]
        for p in known:
            ip, port_s = p._best.rsplit(':', 1)
            id_buf = bytes.fromhex(p.id)[:8]
            ip_buf = ip.encode()
            parts.append(bytes([len(id_buf)]) + id_buf + bytes([len(ip_buf)]) + ip_buf + struct.pack('>H', int(port_s)))
        peer.write_ctrl(b''.join(parts))

    def _on_pex(self, buf: bytes, src: str):
        if len(buf) < 3:
            return
        count = buf[1]
        o     = 2
        for _ in range(count):
            if o >= len(buf):
                break
            id_len = buf[o]; o += 1
            if o + id_len > len(buf):
                break
            pid = buf[o:o + id_len].hex(); o += id_len
            if o >= len(buf):
                break
            ip_len = buf[o]; o += 1
            if o + ip_len + 2 > len(buf):
                break
            ip   = buf[o:o + ip_len].decode(); o += ip_len
            port = struct.unpack_from('>H', buf, o)[0]; o += 2
            if pid == self._id or pid in self._peers:
                continue
            addr = f'{ip}:{port}'
            self._peer_cache[addr] = {'id': pid, 'ip': ip, 'port': port, 'last_seen': _now_ms()}
            self._dial(ip, port, pid, None, None)

    def _load_peer_cache(self):
        if not self._on_load_peers:
            return
        try:
            lst = self._on_load_peers()
            if not isinstance(lst, list):
                return
            for entry in lst:
                if entry.get('ip') and entry.get('port'):
                    self._peer_cache[f'{entry["ip"]}:{entry["port"]}'] = entry
        except Exception:
            pass

    def _emit_peer_cache(self):
        lst = sorted(self._peer_cache.values(), key=lambda e: e.get('last_seen', 0), reverse=True)[:200]
        self._emit('peers', lst)
        if self._on_save_peers:
            try:
                self._on_save_peers(lst)
            except Exception:
                pass

    def _init_peer_cache_emit(self):
        def _tick():
            if self._destroyed:
                return
            self._emit_peer_cache()
            self._loop.call_later(PEER_CACHE_EMIT_MS / 1000, _tick)

        self._loop.call_later(PEER_CACHE_EMIT_MS / 1000, _tick)

    def _dial_peer_cache(self):
        entries = sorted(self._peer_cache.values(), key=lambda e: e.get('last_seen', 0), reverse=True)[:30]
        for e in entries:
            if e.get('id') and e['id'] in self._peers:
                continue
            self._dial(e['ip'], e['port'], e.get('id'), None, None)

    def _dial_hardcoded_seeds(self):
        for hp in self._hardcoded_seeds:
            c = hp.rfind(':')
            if c == -1:
                continue
            host = hp[:c]
            port = int(hp[c+1:]) or 49737
            self._loop.create_task(self._resolve_and_dial(host, port))

    async def _resolve_and_dial(self, host, port):
        try:
            infos = await self._loop.getaddrinfo(host, port, type=socket.SOCK_DGRAM)
            for info in infos:
                ip = info[4][0]
                self._dial(ip, port, None, None, None)
        except Exception:
            self._dial(host, port, None, None, None)

    async def _query_bootstrap_http(self):
        if not self._bootstrap_http:
            return
        ext           = getattr(self, '_ext', None)
        announce_ip   = ext['ip']   if ext else self._lip
        announce_port = ext['port'] if ext else self._lport

        def _post_announce(base):
            if not (announce_ip and announce_port):
                return
            try:
                data = json.dumps({'id': self._id, 'ip': announce_ip, 'port': announce_port}).encode()
                req  = urllib.request.Request(
                    f'{base}/announce', data=data,
                    headers={'Content-Type': 'application/json'}
                )
                urllib.request.urlopen(req, timeout=8)
            except Exception:
                pass

        def _get_peers(base):
            try:
                resp = urllib.request.urlopen(f'{base}/peers', timeout=8)
                return json.loads(resp.read().decode())
            except Exception:
                return None

        for url in self._bootstrap_http:
            base = url.rstrip('/')
            await self._loop.run_in_executor(None, _post_announce, base)
            lst = await self._loop.run_in_executor(None, _get_peers, base)
            if isinstance(lst, list):
                for p in lst:
                    if not p.get('ip') or not p.get('port'):
                        continue
                    addr = f'{p["ip"]}:{p["port"]}'
                    self._peer_cache[addr] = {**p, 'last_seen': _now_ms()}
                    if p.get('id') and p['id'] in self._peers:
                        continue
                    self._dial(p['ip'], p['port'], p.get('id'), None, None)

    def _start_bootstrap_announce(self):
        async def _do():
            await self._query_bootstrap_http()

        if hasattr(self, '_ext'):
            self._loop.create_task(_do())
        else:
            self.once('nat', lambda: self._loop.create_task(_do()))

        def _repeat():
            if self._destroyed:
                return
            self._loop.create_task(_do())
            self._loop.call_later(3 * 60, _repeat)

        self._loop.call_later(3 * 60, _repeat)

    def _heartbeat(self):
        def _tick():
            if self._destroyed:
                return
            now  = _now_ms()
            dead = []
            for pid, peer in list(self._peers.items()):
                if now - peer._seen > PEER_TIMEOUT:
                    dead.append(pid)
                elif now - peer._last_pong > 5000 and not peer._loss_signaled:
                    peer._loss_signaled = True
                    peer._on_loss()
            for pid in dead:
                self._drop(pid)
                self._emit('disconnect', pid)

            self._maintain_mesh()
            self._adapt_mesh_degree()
            self._emit_ihave()

            id_buf = bytes.fromhex(self._id)
            for peer in self.peers:
                now2 = _now_ms()
                ping = bytes([F_PING]) + struct.pack('>Q', int(now2)) + id_buf
                peer._last_ping_sent = now2
                ip, port = peer._best.rsplit(':', 1)
                try:
                    self._transport.sendto(ping, (ip, int(port)))
                except Exception:
                    pass

            self._hb_handle = self._loop.call_later(HEARTBEAT_MS / 1000, _tick)

        self._hb_handle = self._loop.call_later(HEARTBEAT_MS / 1000, _tick)

    def _add_to_mesh(self, peer):
        if len(self.mesh_peers) < self._mesh_d:
            peer.in_mesh    = True
            peer._mesh_time = _now_ms()

    def _flood_mesh(self, plain: bytes, exclude_pid: str):
        for peer in self.mesh_peers:
            if peer.id != exclude_pid and peer._session and peer._open:
                peer._enqueue(plain)

    def _maintain_mesh(self):
        mesh     = self.mesh_peers
        non_mesh = [p for p in self.peers if not p.in_mesh and p._session]
        if len(mesh) > D_HIGH:
            for p in sorted(mesh, key=lambda p: p.score)[:len(mesh) - self._mesh_d]:
                p.in_mesh = False
        if len(mesh) < D_LOW and non_mesh:
            for p in sorted(non_mesh, key=lambda p: p.score, reverse=True)[:self._mesh_d - len(mesh)]:
                p.in_mesh    = True
                p._mesh_time = _now_ms()

    def _adapt_mesh_degree(self):
        now = _now_ms()
        if now - self._last_mesh_adapt < 5000:
            return
        self._last_mesh_adapt = now
        ps = [p for p in self.peers if p._session]
        if not ps:
            return
        avg_rtt = sum(p.rtt for p in ps) / len(ps)
        if avg_rtt > 200 and self._mesh_d > D_MIN:
            self._mesh_d -= 1
        elif avg_rtt < 50 and self._mesh_d < D_MAX and len(ps) > self._mesh_d + 2:
            self._mesh_d += 1
        for p in sorted([p for p in ps if not p.in_mesh and p.bandwidth > 50_000], key=lambda p: p.bandwidth, reverse=True)[:2]:
            p.in_mesh    = True
            p._mesh_time = _now_ms()

    def _emit_ihave(self):
        if not self._ihave_buf:
            return
        ids     = self._ihave_buf[-IHAVE_MAX:]
        self._ihave_buf = self._ihave_buf[:-IHAVE_MAX]
        targets = [p for p in self.peers if not p.in_mesh and p._session][:D_GOSSIP]
        if not targets:
            return
        inner   = b''.join(ids)
        payload = bytes([0x07]) + inner
        for p in targets:
            p.write_ctrl(payload)

    def _dial(self, ip, port, pid, lip, lport):
        key = pid or f'{ip}:{port}'
        if key in self._dialing:
            return
        if pid and pid in self._peers:
            return
        self._dialing.add(key)
        for i in range(PUNCH_TRIES):
            self._loop.call_later(i * PUNCH_INTERVAL / 1000, lambda _ip=ip, _port=port: self._send_hello(_ip, _port))
        if lip and lport:
            for i in range(PUNCH_TRIES):
                self._loop.call_later(i * PUNCH_INTERVAL / 1000, lambda _ip=lip, _port=lport: self._send_hello(_ip, _port))

        def _cleanup(_pid=pid, _key=key):
            if _pid is None or _pid not in self._peers:
                self._dialing.discard(_key)

        self._loop.call_later((PUNCH_TRIES * PUNCH_INTERVAL + 3000) / 1000, _cleanup)

    def _meet(self, info: dict):
        if not info.get('id') or info['id'] == self._id:
            return
        if not info.get('ip') or not info.get('port'):
            return
        self._dial(info['ip'], info['port'], info['id'], info.get('lip'), info.get('lport'))

    def _gossip_peer(self, ip, port, new_id: str):
        if self._gossip_seen.seen(new_id):
            return
        info    = {'id': new_id, 'ip': ip, 'port': port}
        payload = json.dumps({'_gossip': True, **info}).encode()
        for pid, peer in self._peers.items():
            if pid != new_id and peer._session and peer._open:
                peer._enqueue(payload)

    def _drop(self, pid: str):
        peer = self._peers.pop(pid, None)
        if peer:
            peer.destroy()
        self._dialing.discard(pid)

    def _me(self) -> dict:
        ext = getattr(self, '_ext', None)
        return {
            'id':    self._id,
            'ip':    ext['ip']   if ext else None,
            'port':  ext['port'] if ext else None,
            'lip':   self._lip,
            'lport': self._lport,
            'nat':   self.nat_type,
            }

