"""Local chat bridge with persistent identity, history, and reconnecting relay transport."""
import argparse
import asyncio
from contextlib import suppress
import fcntl
import hashlib
import json
import logging
import math
import os
from pathlib import Path
import random
import re
import secrets
import time
from urllib.parse import urlsplit
import uuid

from aiohttp import web, ClientSession, ClientError
from cryptography.fernet import Fernet, InvalidToken
import websockets
from client_store import Store
from media import MAX_FILE_BYTES, validate_file, validate_metadata
from relay_config import PolicyError

log = logging.getLogger('mesh.client')


def peer_id(value):
    if not isinstance(value, str) or not re.fullmatch(r'usr_[0-9a-f]{16}', value):
        raise ValueError('Invalid contact ID')
    return value


def coordinates(lat, lon):
    # Zero is valid; booleans, infinities, NaN, and out-of-range values are not.
    if isinstance(lat, bool) or isinstance(lon, bool):
        raise ValueError('Invalid location')
    lat, lon = float(lat), float(lon)
    if not math.isfinite(lat) or not math.isfinite(lon) or not -90 <= lat <= 90 or not -180 <= lon <= 180:
        raise ValueError('Invalid location')
    return lat, lon


def distance_bearing(origin, target):
    lat1, lon1, lat2, lon2 = map(math.radians, (*origin, *target))
    dlat, dlon = lat2 - lat1, lon2 - lon1
    a = math.sin(dlat / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2) ** 2
    # Clamp rounding error near antipodal points before taking square roots.
    a = min(1.0, max(0.0, a))
    distance = 3958.8 * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    bearing = math.degrees(math.atan2(math.sin(dlon) * math.cos(lat2),
                                    math.cos(lat1) * math.sin(lat2) - math.sin(lat1) * math.cos(lat2) * math.cos(dlon))) % 360
    return distance, bearing


class Client:
    def __init__(self, store, relay, token, port):
        self.store, self.relay, self.invite, self.port = store, relay, token, port
        # Persist registration inputs before network I/O, including across process crashes.
        if not store.setting('user_id'):
            if token:
                store.setting('registration_invite', token)
            if not store.setting('registration_secret'):
                store.setting('registration_secret', secrets.token_urlsafe(32))
            self.invite = store.setting('registration_invite')
        self.websocket = None
        self.uis = set()
        self.status = 'Connecting to relay'
        self.session = secrets.token_urlsafe(32)
        self.cookie_name = 'mesh_session_' + str(port)
        self.origins = {f'http://127.0.0.1:{port}', f'http://localhost:{port}'}
        self.waiting = {}
        self.key_requests = set()
        self.sent = set()
        self.wakeup = asyncio.Event()
        self.sharing = {}  # Explicit recipient -> expiry, independent of selected tab.
        self.location = None
        self.bot_tasks = set()
        self.download_waiting = {}

    async def notify(self, payload):
        # A closed browser must never stop relay reception or lose a delivery.
        for socket in tuple(self.uis):
            try:
                await socket.send_json(payload)
            except (ConnectionError, RuntimeError):
                self.uis.discard(socket)

    async def snapshot(self):
        await self.notify(self.store.snapshot())

    async def set_status(self, status):
        self.status = status
        log.info('%s', status)
        await self.notify({'type': 'connection', 'text': status})

    async def send(self, payload):
        if not self.websocket:
            return False
        await self.websocket.send(json.dumps(payload))
        return True

    async def request_key(self, peer):
        if peer not in self.key_requests and self.websocket:
            self.key_requests.add(peer)
            await self.send({'type': 'get_key', 'recipient_id': peer})

    def envelope(self, peer, message_id, body, kind='chat'):
        # Bind routing metadata inside the authenticated ciphertext to prevent relabeling.
        inner = {**body, 'sender_id': self.store.setting('user_id'), 'recipient_id': peer,
                 'envelope_id': message_id}
        result = {'type': kind, 'recipient_id': peer, 'message_id': message_id,
                  'text': self.store.cipher(peer).encrypt(json.dumps(inner, ensure_ascii=False).encode()).decode()}
        if body.get('type') == 'attachment':
            result['attachment_id'] = body['attachment']['id']
        return result

    def media_url(self, file_id):
        relay = urlsplit(self.relay)
        return ('https://' if relay.scheme == 'wss' else 'http://') + relay.netloc + '/attachments/' + file_id

    def media_headers(self):
        return {'Authorization': 'Bearer ' + self.store.setting('auth_token'), 'X-User-ID': self.store.setting('user_id')}

    async def upload_file(self, row, body):
        descriptor = body['attachment']
        cached = self.store.conn.execute('SELECT ciphertext FROM local_files WHERE id=?', (descriptor['id'],)).fetchone()
        if not cached or not cached[0]:
            raise PolicyError('local_file_missing', 'Local attachment data is missing; restore a profile backup.')
        async with ClientSession() as session:
            async with session.put(self.media_url(descriptor['id']), params={'recipient_id': row['peer']},
                                   data=cached[0], headers=self.media_headers(), timeout=45, allow_redirects=False) as response:
                if response.status != 200:
                    try:
                        detail = (await response.json()).get('detail', {})
                    except (ClientError, ValueError):
                        detail = {}
                    if not isinstance(detail, dict):
                        detail = {}
                    raise PolicyError(detail.get('code', 'upload_failed'), detail.get('text', f'Attachment upload failed (HTTP {response.status}).'),
                                      retryable=detail.get('retryable', response.status >= 500 or response.status in (408, 429)))

    async def download_file(self, descriptor):
        async with ClientSession() as session:
            async with session.get(self.media_url(descriptor['id']), headers=self.media_headers(),
                                   timeout=45, allow_redirects=False) as response:
                response.raise_for_status()
                encrypted = bytearray()
                async for chunk in response.content.iter_chunked(65536):
                    if len(encrypted) + len(chunk) > 8 * 1024 * 1024:
                        raise ValueError('Encrypted attachment exceeds protocol ceiling')
                    encrypted.extend(chunk)
        if hashlib.sha256(encrypted).hexdigest() != descriptor['sha256']:
            raise ValueError('Attachment digest mismatch')
        raw = Fernet(descriptor['key'].encode()).decrypt(bytes(encrypted))
        if len(raw) != descriptor['size']:
            raise ValueError('Attachment size mismatch')
        validate_file(raw, descriptor['mime'])
        return raw

    async def retry_downloads(self):
        # A transient HTTP failure must not strand a durable message until a restart.
        while True:
            await asyncio.sleep(5)
            for key, envelope in list(self.download_waiting.items())[:10]:
                self.download_waiting.pop(key, None)
                try:
                    await self.receive_envelope(envelope)
                except (ValueError, TypeError, KeyError, AttributeError, InvalidToken):
                    await self.notify({'type': 'error', 'text': 'Attachment authentication failed; it was not acknowledged.'})

    async def event(self, peer, body):
        if self.websocket and self.store.cipher(peer):
            await self.send(self.envelope(peer, str(uuid.uuid4()), {**body, 'timestamp': time.time()}, 'event'))

    async def pump(self):
        while True:
            self.wakeup.clear()
            rows = self.store.conn.execute("SELECT * FROM outbox WHERE state!='blocked' AND retry_at<=? ORDER BY rowid", (time.time(),)).fetchall()
            for row in rows:
                if row['id'] in self.sent:
                    continue
                if not self.store.cipher(row['peer']):
                    await self.request_key(row['peer'])
                    continue
                body = json.loads(row['body'])
                if body.get('type') == 'attachment':
                    try:
                        await self.upload_file(row, body)
                    except PolicyError as exc:
                        self.store.reject(row['id'], exc.text, exc.retryable)
                        await self.snapshot()
                        continue
                    except (ClientError, asyncio.TimeoutError, OSError):
                        self.store.reject(row['id'], 'Upload interrupted; retrying in 30 seconds.', True)
                        await self.snapshot()
                        continue
                envelope = self.envelope(row['peer'], row['id'], body)
                # Catch the protocol ceiling before a transport-level close can hide
                # which message failed (the server may enforce a smaller limit too).
                if len(envelope['text'].encode('utf-8')) > 48000:
                    self.store.reject(row['id'], 'Encrypted message exceeds the 48000-byte protocol ceiling.')
                    await self.snapshot()
                    continue
                self.sent.add(row['id'])
                await self.send(envelope)
                await asyncio.sleep(0.03)  # Bound reconnect bursts below the relay's rate limit.
            with suppress(asyncio.TimeoutError):
                await asyncio.wait_for(self.wakeup.wait(), 2)

    async def receive_envelope(self, data):
        peer = peer_id(data.get('sender_id'))
        message_id = str(uuid.UUID(data.get('message_id', '')))
        self.store.add_peer(peer)
        cipher = self.store.cipher(peer)
        if not cipher:
            # The relay retains unacknowledged ciphertext if this temporary buffer is lost.
            self.waiting[(peer, message_id)] = data
            await self.request_key(peer)
            return
        body = json.loads(cipher.decrypt(data['text'].encode()).decode())
        if not isinstance(body, dict) or (body.get('sender_id'), body.get('recipient_id'), body.get('envelope_id')) != (peer, self.store.setting('user_id'), message_id):
            raise ValueError('Message identity mismatch')
        kind = body.get('type')
        if data['type'] == 'event':
            # Typing and GPS events expire and are never queued for offline delivery.
            timestamp = float(body.get('timestamp', 0))
            if not math.isfinite(timestamp) or not -5 <= time.time() - timestamp <= 15:
                return
            if kind in ('typing_start', 'typing_stop', 'location_stop'):
                await self.notify({'type': kind, 'sender_id': peer})
            elif kind == 'gps':
                target = coordinates(body.get('lat'), body.get('lon'))
                expires = float(body.get('expires', 0))
                if not math.isfinite(expires) or expires <= time.time():
                    return
                if self.location:
                    distance, bearing = distance_bearing(self.location, target)
                    await self.notify({'type': 'distance_update', 'sender_id': peer, 'distance': distance,
                                       'bearing': bearing, 'updated': timestamp, 'expires': expires})
            return
        if kind == 'attachment':
            descriptor = validate_metadata(body.get('attachment'))
            if descriptor['id'] != data.get('attachment_id'):
                raise ValueError('Attachment routing mismatch')
            # Duplicate messages have already been cached and may no longer exist on the relay.
            seen = self.store.conn.execute('SELECT 1 FROM inbox WHERE sender=? AND id=?', (peer, message_id)).fetchone()
            if not seen:
                try:
                    body['_file_bytes'] = await self.download_file(descriptor)
                except (ClientError, asyncio.TimeoutError, OSError):
                    self.download_waiting[(peer, message_id)] = data
                    await self.notify({'type': 'error', 'text': 'Attachment download interrupted; retrying. Delivery is not yet acknowledged.'})
                    return
        elif kind == 'text':
            if not isinstance(body.get('content'), str) or len(body['content']) > 8000:
                raise ValueError('Invalid message text')
        elif kind == 'receipt':
            uuid.UUID(body.get('message_id', ''))
            if body.get('status') not in ('delivered', 'read'):
                raise ValueError('Invalid receipt')
        else:
            raise ValueError('Unsupported persistent message')
        changed = self.store.receive(peer, message_id, body)
        # ACK only after the local history/dedup/receipt transaction commits.
        await self.send({'type': 'queue_ack', 'sender_id': peer, 'message_id': message_id})
        self.wakeup.set()
        if changed:
            await self.snapshot()

    async def receive(self):
        async for raw in self.websocket:
            try:
                data = json.loads(raw)
                kind = data.get('type')
                if kind == 'peer_key':
                    peer = peer_id(data['user_id'])
                    self.store.pin(peer, data['public_key'])
                    self.key_requests.discard(peer)
                    for key, envelope in list(self.waiting.items()):
                        if key[0] == peer:
                            del self.waiting[key]
                            # One bad queued envelope must not strand the rest of this peer's backlog.
                            try:
                                await self.receive_envelope(envelope)
                            except (ValueError, TypeError, KeyError, AttributeError, InvalidToken):
                                log.warning('Rejected invalid buffered message')
                                await self.notify({'type': 'error', 'text': 'An invalid queued message was skipped and not acknowledged.'})
                    self.wakeup.set()
                    await self.snapshot()
                elif kind in ('chat', 'event'):
                    await self.receive_envelope(data)
                elif kind == 'accepted':
                    self.store.accepted(data['message_id'])
                    self.sent.discard(data['message_id'])
                    await self.snapshot()
                elif kind == 'presence':
                    await self.notify(data)
                elif kind == 'error':
                    # Queue-full errors remain pending with a durable retry deadline;
                    # permanent rejections stay visible and need an explicit retry.
                    message_id = data.get('message_id')
                    if message_id:
                        self.store.reject(message_id, data['text'], data.get('retryable', False), data.get('retry_after') or 30)
                        self.sent.discard(message_id)
                    elif data.get('code') == 'recipient_unavailable' and data.get('recipient_id'):
                        peer = data['recipient_id']
                        self.key_requests.discard(peer)
                        for row in self.store.conn.execute('SELECT id FROM outbox WHERE peer=?', (peer,)).fetchall():
                            self.store.reject(row[0], data['text'])
                            self.sent.discard(row[0])
                    await self.snapshot()
                    await self.notify(data)
            except (ValueError, TypeError, KeyError, AttributeError, InvalidToken):
                # One malformed or undecryptable envelope cannot kill the receive loop.
                log.warning('Rejected invalid or untrusted incoming message')
                await self.notify({'type': 'error', 'text': 'Message or identity could not be verified; delivery was not acknowledged.'})

    async def connect_forever(self):
        delay = 1
        while True:
            started = time.monotonic()
            tasks = []
            try:
                async with websockets.connect(self.relay, max_size=65536, open_timeout=10) as socket:
                    credentials = {'public_key': self.store.public_key}
                    if self.store.setting('user_id'):
                        credentials.update(type='authenticate', user_id=self.store.setting('user_id'),
                                           auth_token=self.store.setting('auth_token'))
                    else:
                        credentials.update(type='register', invite_token=self.invite,
                                           recovery_secret=self.store.setting('registration_secret'))
                    await socket.send(json.dumps(credentials))
                    result = json.loads(await asyncio.wait_for(socket.recv(), 10))
                    if result.get('type') == 'error':
                        # A rejected invite/capacity limit requires user action, not
                        # endless attempts to register with the same rejected token.
                        await self.set_status('Registration rejected: ' + result.get('text', 'Contact the administrator'))
                        return
                    if result.get('type') not in ('registered', 'authenticated'):
                        raise ValueError('Unexpected authentication response')
                    if result['type'] == 'registered':
                        # Persist the issued credentials together before processing any traffic.
                        with self.store.conn:
                            self.store.conn.executemany('INSERT OR REPLACE INTO settings VALUES (?, ?)',
                                                        [('user_id', result['user_id']), ('auth_token', result['auth_token'])])
                            self.store.conn.execute("DELETE FROM settings WHERE key IN ('registration_invite', 'registration_secret')")
                        self.invite = None
                    self.websocket = socket
                    self.sent.clear()
                    self.key_requests.clear()
                    self.waiting.clear()
                    self.download_waiting.clear()
                    await self.set_status('Connected')
                    await self.snapshot()
                    log.info('Your user ID: %s', self.store.setting('user_id'))
                    # Receiver and outbox run independently so key lookups cannot deadlock delivery.
                    tasks = [asyncio.create_task(self.receive()), asyncio.create_task(self.pump()), asyncio.create_task(self.retry_downloads())]
                    done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                    for task in done:
                        task.result()
            except websockets.exceptions.ConnectionClosed as exc:
                if exc.rcvd and exc.rcvd.code in (4003, 4009, 1008):
                    await self.set_status('Connection rejected: ' + (exc.rcvd.reason or 'Contact the administrator'))
                    return
            except (OSError, asyncio.TimeoutError, websockets.exceptions.WebSocketException, ValueError):
                pass
            finally:
                self.websocket = None
                for task in tasks:
                    task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
            if time.monotonic() - started > 30:
                delay = 1
            await self.set_status(f'Relay offline; retrying in about {delay}s. Messages saved locally.')
            await asyncio.sleep(delay + random.uniform(0, delay * 0.2))
            delay = min(30, delay * 2)

    async def index(self, request):
        # Exact Host allowlisting blocks DNS-rebinding access to the local bridge.
        if 'http://' + request.host not in self.origins:
            raise web.HTTPForbidden()
        response = web.Response(text=Path(__file__).with_name('index.html').read_text(), content_type='text/html')
        response.set_cookie(self.cookie_name, self.session, httponly=True, samesite='Strict')
        response.headers['Cache-Control'] = 'no-store'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        return response

    async def ui(self, request):
        # Loopback alone is insufficient: require both the expected browser Origin and session.
        if ('http://' + request.host not in self.origins or request.headers.get('Origin') not in self.origins
                or not secrets.compare_digest(request.cookies.get(self.cookie_name, ''), self.session)):
            raise web.HTTPForbidden()
        socket = web.WebSocketResponse(max_msg_size=32768)
        await socket.prepare(request)
        self.uis.add(socket)
        await socket.send_json(self.store.snapshot())
        await socket.send_json({'type': 'connection', 'text': self.status})
        try:
            async for frame in socket:
                if frame.type != web.WSMsgType.TEXT:
                    continue
                try:
                    data = json.loads(frame.data)
                    if not isinstance(data, dict):
                        raise ValueError('Expected an object')
                    await self.ui_command(data)
                except (ValueError, TypeError, KeyError, AttributeError):
                    await socket.send_json({'type': 'error', 'text': 'Invalid command, contact, or message'})
                except (websockets.exceptions.ConnectionClosed, OSError):
                    await socket.send_json({'type': 'error', 'text': 'Relay disconnected. Saved messages will retry.'})
        finally:
            self.uis.discard(socket)
        return socket

    def check_local_request(self, request, *, mutation=False):
        # Downloads use same-origin cookies; writes additionally require an Origin check.
        if ('http://' + request.host not in self.origins
                or not secrets.compare_digest(request.cookies.get(self.cookie_name, ''), self.session)
                or (mutation and request.headers.get('Origin') not in self.origins)):
            raise web.HTTPForbidden()

    async def local_upload(self, request):
        self.check_local_request(request, mutation=True)
        try:
            peer = peer_id(request.query.get('recipient_id'))
            # aiohttp's app limit bounds this read, independent of a claimed Content-Length.
            raw = await request.read()
            message_id = self.store.send_attachment(peer, raw, request.content_type, request.query.get('name', 'attachment'))
        except (ValueError, TypeError):
            raise web.HTTPBadRequest(text='Unsupported file, invalid recipient, or file exceeds 5 MiB') from None
        self.wakeup.set()
        await self.snapshot()
        return web.json_response({'message_id': message_id, 'status': 'pending'})

    async def local_file(self, request):
        self.check_local_request(request)
        try:
            file_id = str(uuid.UUID(request.match_info['file_id']))
        except ValueError:
            raise web.HTTPNotFound() from None
        row = self.store.conn.execute('SELECT plaintext FROM local_files WHERE id=?', (file_id,)).fetchone()
        # Metadata is validated before caching. Inline content is limited to known image/audio formats.
        messages = self.store.conn.execute('SELECT media FROM messages WHERE media IS NOT NULL').fetchall()
        metadata = next((json.loads(m[0]) for m in messages if json.loads(m[0])['id'] == file_id), None)
        if not row or not metadata:
            raise web.HTTPNotFound()
        return web.Response(body=row[0], content_type=metadata['mime'],
                            headers={'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff',
                                     'Content-Security-Policy': "default-src 'none'; sandbox"})

    async def ui_command(self, data):
        peer = peer_id(data.get('recipient_id'))
        kind = data.get('type')
        if kind == 'add_target':
            self.store.add_peer(peer)
            await self.request_key(peer)
        elif kind == 'chat':
            text = data.get('text')
            if not isinstance(text, str) or not text.strip() or len(text) > 8000:
                raise ValueError('Message must contain 1–8000 characters')
            message_id = str(uuid.UUID(data.get('msg_id', '')))
            self.store.send_text(peer, text, message_id)
            self.wakeup.set()
            if '@bot' in text.lower():
                task = asyncio.create_task(self.bot(peer, re.split('@bot', text, maxsplit=1, flags=re.I)[1].strip()))
                self.bot_tasks.add(task)
                task.add_done_callback(self.bot_tasks.discard)
        elif kind == 'read':
            self.store.mark_read(peer)
            self.wakeup.set()
        elif kind == 'retry':
            message_id = str(uuid.UUID(data.get('msg_id', '')))
            self.store.retry(peer, message_id)
            self.sent.discard(message_id)
            self.key_requests.discard(peer)
            self.wakeup.set()
        elif kind == 'alias':
            alias = data.get('alias', '')
            if not isinstance(alias, str) or len(alias) > 80:
                raise ValueError('Invalid alias')
            with self.store.conn:
                self.store.conn.execute('UPDATE peers SET alias=? WHERE user_id=?', (alias.strip(), peer))
        elif kind == 'verify':
            # A verification click is accepted only for the fingerprint actually displayed.
            from client_store import fingerprint
            row = self.store.conn.execute('SELECT public_key FROM peers WHERE user_id=?', (peer,)).fetchone()
            if not row or not row[0] or fingerprint(row[0]) != data.get('fingerprint'):
                raise ValueError('Fingerprint mismatch')
            with self.store.conn:
                self.store.conn.execute('UPDATE peers SET verified=1 WHERE user_id=?', (peer,))
        elif kind == 'presence':
            await self.send({'type': 'presence', 'recipient_id': peer})
        elif kind in ('typing_start', 'typing_stop'):
            await self.event(peer, {'type': kind})
        elif kind == 'location_start':
            # Sharing is always temporary and explicitly bound to a chosen recipient.
            self.sharing[peer] = time.time() + 15 * 60
        elif kind == 'location_stop':
            self.sharing.pop(peer, None)
            await self.event(peer, {'type': 'location_stop'})
        elif kind == 'location_update':
            if self.sharing.get(peer, 0) <= time.time():
                raise ValueError('Location sharing expired')
            self.location = coordinates(data.get('lat'), data.get('lon'))
            await self.event(peer, {'type': 'gps', 'lat': self.location[0], 'lon': self.location[1],
                                    'expires': self.sharing[peer]})
        else:
            raise ValueError('Unknown command')
        if kind in ('add_target', 'chat', 'read', 'alias', 'verify', 'retry'):
            await self.snapshot()

    async def bot(self, peer, prompt):
        # Bot replies use the same durable message path and keep the original prompt casing.
        try:
            async with ClientSession() as session:
                async with session.post('http://127.0.0.1:11434/api/generate',
                                        json={'model': 'llama3.2:1b', 'prompt': prompt, 'stream': False},
                                        timeout=120) as response:
                    response.raise_for_status()
                    result = await response.json()
            text = '🤖 BOT: ' + str(result.get('response', ''))[:7900]
            self.store.send_text(peer, text, str(uuid.uuid4()))
            self.wakeup.set()
            await self.snapshot()
        except (ClientError, asyncio.TimeoutError, ValueError):
            await self.notify({'type': 'error', 'text': 'Local Ollama could not generate a reply.'})


async def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile', default='default', help='Separate local identity/history directory name')
    parser.add_argument('--token', help='Invitation for first registration only')
    # A private prompt keeps shared invitation links out of shell history/process arguments.
    parser.add_argument('--invite', nargs='?', const=True, help='Invitation link; omit its value to paste privately')
    parser.add_argument('--user', help='Optional check against the ID saved in this profile')
    parser.add_argument('--port', type=int, default=8081)
    parser.add_argument('--relay', help='Relay URL; invitation links supply this automatically')
    args = parser.parse_args()
    if not re.fullmatch(r'[a-zA-Z0-9_-]+', args.profile):
        parser.error('Profile names can contain letters, numbers, underscores, and hyphens')
    from invitation import parse_invite, relay_url
    try:
        if args.invite:
            import getpass
            link = getpass.getpass('Paste invitation link: ') if args.invite is True else args.invite
            invited_relay, invited_token = parse_invite(link)
            if args.token or (args.relay and args.relay != invited_relay):
                parser.error('Use the invitation link alone, without conflicting token or relay arguments')
            args.relay, args.token = invited_relay, invited_token
        if args.relay:
            relay_url(args.relay)
    except ValueError as exc:
        parser.error(str(exc))
    os.umask(0o077)
    directory = Path(__file__).parent / '.mesh' / args.profile
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    # Two processes must not concurrently use one profile and fight over its identity/outbox.
    lock = (directory / 'profile.lock').open('w')
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        parser.error('This profile is already running')
    store = Store(directory)
    if args.user and args.user != store.setting('user_id'):
        parser.error('--user must match this profile; IDs alone cannot authenticate')
    if not store.setting('user_id') and not args.token and not store.setting('registration_invite'):
        parser.error('A new profile needs --token INVITE_TOKEN')
    existing_relay = store.setting('relay')
    # Restarting a saved profile reuses its relay; no repeated URL argument is needed.
    args.relay = args.relay or existing_relay or 'ws://127.0.0.1:8000/ws'
    if existing_relay and existing_relay != args.relay:
        parser.error('This profile belongs to a different relay; use a separate profile')
    store.setting('relay', args.relay)
    client = Client(store, args.relay, args.token, args.port)
    app = web.Application(client_max_size=MAX_FILE_BYTES + 1)
    app.router.add_get('/', client.index)
    # Serve only this known script; never expose profile files through a directory route.
    app.router.add_get('/app.js', lambda request: web.FileResponse(Path(__file__).with_name('app.js')))
    app.router.add_get('/ws', client.ui)
    app.router.add_post('/upload', client.local_upload)
    app.router.add_get('/files/{file_id}', client.local_file)
    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    await web.TCPSite(runner, '127.0.0.1', args.port).start()
    print(f'Open http://127.0.0.1:{args.port} in your browser', flush=True)
    task = asyncio.create_task(client.connect_forever())
    try:
        await asyncio.Event().wait()
    finally:
        task.cancel()
        for bot_task in client.bot_tasks:
            bot_task.cancel()
        await asyncio.gather(task, *client.bot_tasks, return_exceptions=True)
        await runner.cleanup()
        store.conn.close()
        lock.close()


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
    with suppress(KeyboardInterrupt):
        asyncio.run(main())
