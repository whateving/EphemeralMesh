"""Authenticated WebSocket relay with an administrator-only membership API."""
import asyncio
from contextlib import asynccontextmanager, suppress
import json
import logging
import os
import secrets
import time
import uuid
from anyio import CancelScope, ClosedResourceError, BrokenResourceError
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, Response, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, ConfigDict, Field
import db
from relay_config import Limits, PolicyError

log = logging.getLogger('mesh.relay')
active = {}
delivery_locks = {}
inflight = {}  # Per-connection sent IDs; persisted ACKs remain the source of truth.
limits = Limits()
membership_lock = asyncio.Lock()
upload_slots = asyncio.Semaphore(4)
SOCKET_ERRORS = (WebSocketDisconnect, RuntimeError, OSError, ClosedResourceError, BrokenResourceError)


def valid_public_key(pem):
    # Reject unsupported curves and oversized key material before storing it.
    if not isinstance(pem, str) or len(pem) > 2048:
        raise ValueError('Invalid public key')
    key = serialization.load_pem_public_key(pem.encode())
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP384R1):
        raise ValueError('Expected a P-384 public key')
    return pem


@asynccontextmanager
async def lifespan(app):
    global limits, membership_lock, upload_slots
    # Invalid configuration stops startup rather than quietly weakening policy.
    secret = os.getenv('ADMIN_SECRET', '')
    if len(secret) < 32 or secret == 'my_local_dev_secret':
        raise RuntimeError('Set ADMIN_SECRET to a random secret of at least 32 characters')
    limits = Limits.from_env()
    membership_lock = asyncio.Lock()
    upload_slots = asyncio.Semaphore(4)
    await db.init_db()
    await db.purge_orphan_attachments()
    async def cleanup_uploads():
        while True:
            await asyncio.sleep(60)
            await db.purge_orphan_attachments()
    cleanup_task = asyncio.create_task(cleanup_uploads())
    try:
        yield
    finally:
        cleanup_task.cancel()
        await asyncio.gather(cleanup_task, return_exceptions=True)


app = FastAPI(title='Ephemeral Mesh Relay', lifespan=lifespan)


@app.get('/healthz')
async def health():
    # Exercise the database without exposing membership or operational secrets publicly.
    try:
        await db.account('health-probe')
    except Exception:
        raise HTTPException(503, 'Database unavailable') from None
    return {'status': 'ok'}


async def authenticate_http(request: Request):
    if request.headers.get('origin'):
        raise HTTPException(403, 'Use the local client for attachments')
    token = request.headers.get('authorization', '')
    user_id = request.headers.get('x-user-id', '')
    record = await db.account(user_id)
    if (not token.startswith('Bearer ') or not record or record['revoked_at'] is not None
            or not secrets.compare_digest(record['auth_hash'], db.token_hash(token[7:]))):
        raise HTTPException(401, 'Invalid member credentials')
    return user_id


@app.put('/attachments/{attachment_id}')
async def upload_attachment(attachment_id: uuid.UUID, request: Request, recipient_id: str,
                            user_id: str = Depends(authenticate_http)):
    # Authenticate before reading bytes and reject excess simultaneous uploads instead
    # of accumulating unbounded waiting bodies in memory. Slow uploads also time out.
    if upload_slots.locked():
        raise HTTPException(429, detail={'code': 'uploads_busy', 'text': 'Uploads busy; retry shortly.', 'retryable': True})
    async with upload_slots:
        body = bytearray()
        try:
            async with asyncio.timeout(30):
                async for chunk in request.stream():
                    if len(body) + len(chunk) > limits.max_attachment_bytes:
                        raise HTTPException(413, detail={'code': 'attachment_too_large', 'text': 'Upload exceeds the encrypted file limit.', 'retryable': False})
                    body.extend(chunk)
        except asyncio.TimeoutError:
            raise HTTPException(408, 'Upload timed out') from None
        if not body:
            raise HTTPException(400, 'Empty attachment')
        try:
            async with membership_lock:
                await db.put_attachment(str(attachment_id), user_id, recipient_id, bytes(body), limits)
        except PolicyError as exc:
            raise HTTPException(exc.status, detail=exc.detail()) from exc
    return {'attachment_id': str(attachment_id), 'bytes': len(body)}


@app.get('/attachments/{attachment_id}')
async def download_attachment(attachment_id: uuid.UUID, user_id: str = Depends(authenticate_http)):
    async with membership_lock:
        member = await db.account(user_id)
        if not member or member['revoked_at'] is not None:
            raise HTTPException(401, 'Membership revoked')
        body = await db.get_attachment(str(attachment_id), user_id)
    if body is None:
        raise HTTPException(404, 'Attachment unavailable')
    # The relay serves only opaque encrypted bytes, never user-supplied active content.
    return Response(body, media_type='application/octet-stream', headers={'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff'})


def require_admin(x_admin_token: str | None = Header(default=None)):
    # Every admin endpoint shares the same constant-time credential check.
    if not secrets.compare_digest((x_admin_token or '').encode(), os.environ['ADMIN_SECRET'].encode()):
        raise HTTPException(401, detail={'code': 'unauthorized', 'text': 'Administrator credentials required.'})


class InviteRequest(BaseModel):
    # Single-use is fixed by the protocol; labels are admin-only, not proof of identity.
    model_config = ConfigDict(extra='forbid', strict=True)
    label: str = Field(default='', max_length=80)
    expires_in: int = Field(default=86400, ge=60, le=604800)


@app.post('/admin/invite', dependencies=[Depends(require_admin)], include_in_schema=False)
@app.post('/admin/invites', dependencies=[Depends(require_admin)])
async def invite(body: InviteRequest | None = None):
    body = body or InviteRequest()
    try:
        return await db.create_invitation(body.label.strip(), body.expires_in, limits)
    except PolicyError as exc:
        raise HTTPException(exc.status, detail=exc.detail()) from exc


@app.get('/admin/invites', dependencies=[Depends(require_admin)])
async def invitations(limit: int = Query(100, ge=1, le=200), offset: int = Query(0, ge=0)):
    # Paginate audit history and never return invitation/authentication hashes.
    return {'invites': await db.list_invites(limit, offset), 'limit': limit, 'offset': offset}


@app.delete('/admin/invites/{invite_id}', dependencies=[Depends(require_admin)])
async def revoke_invitation(invite_id: uuid.UUID):
    try:
        return await db.revoke_invite(str(invite_id))
    except PolicyError as exc:
        raise HTTPException(exc.status, detail=exc.detail()) from exc


@app.get('/admin/members', dependencies=[Depends(require_admin)])
async def members(limit: int = Query(100, ge=1, le=200), offset: int = Query(0, ge=0)):
    rows = await db.list_members(limit, offset)
    for row in rows:
        row['online'] = row['revoked_at'] is None and row['user_id'] in active
    return {'members': rows, 'limit': limit, 'offset': offset}


@app.delete('/admin/members/{user_id}', dependencies=[Depends(require_admin)])
async def revoke_member(user_id: str):
    try:
        # Serialize admission/routing with revocation so a login in progress cannot
        # reattach itself after the admin has removed that member's access.
        async with membership_lock:
            result = await db.revoke_member(user_id)
            socket = active.pop(user_id, None)
            inflight.pop(user_id, None)
        if socket:
            # Access is already revoked even if closing an unresponsive transport times out.
            with suppress(*SOCKET_ERRORS, asyncio.TimeoutError):
                await asyncio.wait_for(socket.close(code=4003, reason='Access revoked by administrator'), 5)
        log.info('Administrator revoked member %s', user_id)
        return result
    except PolicyError as exc:
        raise HTTPException(exc.status, detail=exc.detail()) from exc


@app.get('/admin/limits', dependencies=[Depends(require_admin)])
async def server_limits():
    # This is a read-only view; operators configure limits through startup environment variables.
    return {'limits': limits.public(), 'usage': await db.usage()}


async def send_pending(user_id):
    async with delivery_locks.setdefault(user_id, asyncio.Lock()):
        websocket = active.get(user_id)
        if not websocket:
            return
        try:
            for payload in await db.pending(user_id):
                async with membership_lock:
                    session = inflight.get(user_id)
                    if not session or session[0] is not websocket:
                        break
                    key = (payload['sender_id'], payload['message_id'])
                    if key in session[1]:
                        continue
                    # A flush snapshot may predate revocation of the sender. Check
                    # membership again before forwarding each buffered envelope.
                    sender = await db.account(payload['sender_id'])
                    if not sender or sender['revoked_at'] is not None:
                        continue
                    await websocket.send_json(payload)
                    session[1].add(key)
                await asyncio.sleep(.03)
        except SOCKET_ERRORS:
            pass  # Persisted ciphertext survives any transport failure.


async def route_message(websocket, user_id, data):
    """Authorize one frame and return an optional recipient whose queue needs a flush."""
    async with membership_lock:
        if active.get(user_id) is not websocket:
            raise PolicyError('access_revoked', 'This session is no longer active.', status=403)
        kind = data.get('type')
        if kind == 'queue_ack':
            if not all(isinstance(data.get(k), str) for k in ('sender_id', 'message_id')):
                raise ValueError('Invalid acknowledgment')
            await db.acknowledge(user_id, data['sender_id'], data['message_id'])
            return
        recipient = data.get('recipient_id')
        record = await db.account(recipient) if isinstance(recipient, str) else None
        if not record or record['revoked_at'] is not None:
            raise PolicyError('recipient_unavailable', 'Recipient does not exist or access has been revoked.', status=404)
        if kind == 'get_key':
            await websocket.send_json({'type': 'peer_key', 'user_id': recipient, 'public_key': record['public_key']})
        elif kind == 'presence':
            await websocket.send_json({'type': 'presence', 'user_id': recipient,
                                       'online': recipient in active, 'last_seen': record['last_seen']})
        elif kind in ('chat', 'event'):
            message_id = str(uuid.UUID(data.get('message_id', '')))
            ciphertext = data.get('text')
            if not isinstance(ciphertext, str) or not ciphertext:
                raise ValueError('Invalid ciphertext')
            # Count UTF-8 bytes rather than characters; limits apply to encrypted bodies.
            if len(ciphertext.encode('utf-8')) > limits.max_message_bytes:
                raise PolicyError('message_too_large', f'Encrypted message exceeds {limits.max_message_bytes} bytes.')
            envelope = {'type': kind, 'sender_id': user_id, 'recipient_id': recipient,
                        'message_id': message_id, 'text': ciphertext}
            if data.get('attachment_id'):
                envelope['attachment_id'] = str(uuid.UUID(data['attachment_id']))
            if kind == 'chat':
                await db.enqueue(user_id, message_id, recipient, envelope, limits)
                await websocket.send_json({'type': 'accepted', 'message_id': message_id})
                return recipient
            elif recipient in active:
                with suppress(*SOCKET_ERRORS):
                    await active[recipient].send_json(envelope)
        else:
            raise ValueError('Unknown message type')


@app.websocket('/ws')
async def websocket_endpoint(websocket: WebSocket):
    if websocket.headers.get('origin'):
        await websocket.close(code=1008)
        return
    await websocket.accept()
    user_id, initial_delivery = None, None
    try:
        # Credentials belong in a bounded first frame, never in logged query strings.
        raw = await asyncio.wait_for(websocket.receive_text(), 10)
        if len(raw.encode('utf-8')) > 4096:
            raise ValueError('Authentication frame too large')
        credentials = json.loads(raw)
        if not isinstance(credentials, dict):
            raise ValueError('Expected authentication object')
        public_key = valid_public_key(credentials.get('public_key'))
        async with membership_lock:
            if credentials.get('type') == 'register':
                token = credentials.get('invite_token')
                if not isinstance(token, str):
                    raise ValueError('Invitation required')
                user_id, auth_token = await db.register(token, public_key, limits, credentials.get('recovery_secret'))
                await websocket.send_json({'type': 'registered', 'user_id': user_id, 'auth_token': auth_token})
            elif credentials.get('type') == 'authenticate':
                claimed_id, auth_token = credentials.get('user_id'), credentials.get('auth_token')
                record = await db.account(claimed_id) if isinstance(claimed_id, str) else None
                if (not record or record['revoked_at'] is not None or not isinstance(auth_token, str)
                        or not secrets.compare_digest(record['auth_hash'], db.token_hash(auth_token))
                        or record['public_key'] != public_key):
                    await websocket.close(code=4003, reason='Invalid credentials, revoked membership, or identity key')
                    return
                user_id = claimed_id
                await websocket.send_json({'type': 'authenticated', 'user_id': user_id})
            else:
                raise ValueError('Authentication required')
            previous = active.get(user_id)
            active[user_id] = websocket
            inflight[user_id] = (websocket, set())
        if previous:
            with suppress(*SOCKET_ERRORS):
                await previous.close(code=4009, reason='Account connected elsewhere')
        initial_delivery = asyncio.create_task(send_pending(user_id))
        window_start, count = time.monotonic(), 0
        while True:
            raw = await websocket.receive_text()
            if active.get(user_id) is not websocket:
                break
            if time.monotonic() - window_start >= 1:
                window_start, count = time.monotonic(), 0
            count += 1
            if count > limits.max_frames_per_second or len(raw.encode('utf-8')) > 65536:
                await websocket.send_json({'type': 'error', 'code': 'frame_limit_exceeded',
                                           'text': 'Connection frame size or rate limit exceeded.', 'retryable': False})
                await websocket.close(code=1008, reason='Frame/rate limit exceeded')
                break
            data = {}
            try:
                data = json.loads(raw)
                if not isinstance(data, dict):
                    raise ValueError('Expected object')
                recipient = await route_message(websocket, user_id, data)
                if recipient:
                    await send_pending(recipient)
            except (ValueError, TypeError, AttributeError) as exc:
                detail = exc.detail() if isinstance(exc, PolicyError) else {
                    'code': 'invalid_request', 'text': 'Invalid request fields or message type.', 'retryable': False}
                # Correlate failures with the durable outbox; a rejection is never an ACK.
                correlation = {k: data[k] for k in ('message_id', 'recipient_id')
                               if isinstance(data, dict) and isinstance(data.get(k), str)}
                await websocket.send_json({'type': 'error', **detail, **correlation,
                                           'retry_after': 30 if detail['retryable'] else None})
    except PolicyError as exc:
        await websocket.send_json({'type': 'error', **exc.detail()})
        await websocket.close(code=4003, reason=exc.code)
    except (*SOCKET_ERRORS, asyncio.TimeoutError, ValueError, TypeError):
        log.info('Connection ended for %s', user_id or 'unauthenticated client')
    finally:
        # Detach before awaiting cleanup so cancellation cannot leave a dead session.
        was_current = user_id and active.get(user_id) is websocket
        if was_current:
            active.pop(user_id, None)
            inflight.pop(user_id, None)
        with CancelScope(shield=True):
            if initial_delivery:
                await asyncio.gather(initial_delivery, return_exceptions=True)
            if was_current:
                await db.touch(user_id)
        with suppress(*SOCKET_ERRORS):
            await websocket.close()
