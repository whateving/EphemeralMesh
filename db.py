"""Relay storage: membership, invitation audit records, and encrypted delivery envelopes."""
import hashlib
import hmac
import json
import os
import secrets
import time
import uuid
import aiosqlite
from relay_config import Limits, PolicyError

DB_PATH = os.getenv('MESH_DB', 'ephemeral_mesh.db')


def token_hash(token):
    # Store random bearer credentials as hashes, never as reusable tokens.
    return hashlib.sha256(token.encode()).hexdigest()


async def init_db():
    async with aiosqlite.connect(DB_PATH) as conn:
        await conn.executescript('''
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS accounts (
                user_id TEXT PRIMARY KEY, auth_hash TEXT NOT NULL,
                public_key TEXT NOT NULL, last_seen INTEGER
            );
            CREATE TABLE IF NOT EXISTS invites (
                token_hash TEXT PRIMARY KEY, expires_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS deliveries (
                sender_id TEXT NOT NULL, message_id TEXT NOT NULL,
                recipient_id TEXT NOT NULL, payload TEXT, created_at INTEGER NOT NULL,
                PRIMARY KEY (sender_id, message_id)
            );
            CREATE INDEX IF NOT EXISTS delivery_recipient ON deliveries(recipient_id);
            CREATE TABLE IF NOT EXISTS attachments (
                attachment_id TEXT PRIMARY KEY, sender_id TEXT NOT NULL,
                recipient_id TEXT NOT NULL, ciphertext BLOB,
                digest TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER,
                message_id TEXT
            );
        ''')
        # Additive, repeatable migrations preserve existing identities, tokens, and queues.
        # Unknown historical creation dates stay null instead of inventing timestamps.
        for table, additions in {
            'accounts': {'created_at': 'INTEGER', 'revoked_at': 'INTEGER', 'registration_hash': 'TEXT'},
            'deliveries': {'attachment_id': 'TEXT'},
            'invites': {'invite_id': 'TEXT', 'label': "TEXT NOT NULL DEFAULT ''",
                        'created_at': 'INTEGER', 'used_at': 'INTEGER',
                        'used_by': 'TEXT', 'revoked_at': 'INTEGER'},
        }.items():
            columns = {row[1] for row in await (await conn.execute(f'PRAGMA table_info({table})')).fetchall()}
            for name, definition in additions.items():
                if name not in columns:
                    await conn.execute(f'ALTER TABLE {table} ADD COLUMN {name} {definition}')
        rows = await (await conn.execute('SELECT token_hash FROM invites WHERE invite_id IS NULL')).fetchall()
        for row in rows:
            await conn.execute('UPDATE invites SET invite_id=? WHERE token_hash=?', (str(uuid.uuid4()), row[0]))
        await conn.execute('CREATE UNIQUE INDEX IF NOT EXISTS invite_id_unique ON invites(invite_id)')
        # The separate legacy queued_messages table remains untouched.
        await conn.commit()


def invite_view(row):
    item = dict(row)
    item['status'] = ('used' if item['used_at'] is not None else
                      'revoked' if item['revoked_at'] is not None else
                      'expired' if item['expires_at'] <= int(time.time()) else 'pending')
    return item


INVITE_COLUMNS = 'invite_id, label, created_at, expires_at, used_at, used_by, revoked_at'


async def create_invitation(label='', expires_in=86400, limits=Limits()):
    token, invite_id, now = secrets.token_urlsafe(32), str(uuid.uuid4()), int(time.time())
    async with aiosqlite.connect(DB_PATH) as conn:
        # Audit records have a separate ceiling, including used/revoked invitations.
        await conn.execute('BEGIN IMMEDIATE')
        count = (await (await conn.execute('SELECT count(*) FROM invites')).fetchone())[0]
        if count >= limits.max_invite_records:
            raise PolicyError('invite_storage_full', 'Invitation record limit reached. Contact the administrator.')
        await conn.execute('''INSERT INTO invites
            (token_hash, expires_at, invite_id, label, created_at) VALUES (?, ?, ?, ?, ?)''',
            (token_hash(token), now + expires_in, invite_id, label, now))
        await conn.commit()
    # The raw invitation is disclosed once at creation, never by list endpoints.
    return {'invite_token': token, 'invite_id': invite_id, 'label': label, 'created_at': now,
            'expires_at': now + expires_in, 'expires_in': expires_in, 'status': 'pending'}


async def create_invite():
    # Retain the existing helper used by development/integration fixtures.
    return (await create_invitation())['invite_token']


async def list_invites(limit=100, offset=0):
    async with aiosqlite.connect(DB_PATH) as conn:
        conn.row_factory = aiosqlite.Row
        rows = await (await conn.execute(
            f'SELECT {INVITE_COLUMNS} FROM invites ORDER BY rowid DESC LIMIT ? OFFSET ?', (limit, offset))).fetchall()
        return [invite_view(row) for row in rows]


async def revoke_invite(invite_id):
    async with aiosqlite.connect(DB_PATH) as conn:
        conn.row_factory = aiosqlite.Row
        await conn.execute('BEGIN IMMEDIATE')
        row = await (await conn.execute(f'SELECT {INVITE_COLUMNS} FROM invites WHERE invite_id=?', (invite_id,))).fetchone()
        if not row:
            raise PolicyError('invite_not_found', 'Invitation not found.', status=404)
        if row['used_at'] is not None:
            raise PolicyError('invite_already_used', 'Invitation already used; revoke the member to remove access.')
        await conn.execute('UPDATE invites SET revoked_at=COALESCE(revoked_at, ?) WHERE invite_id=?',
                           (int(time.time()), invite_id))
        row = await (await conn.execute(f'SELECT {INVITE_COLUMNS} FROM invites WHERE invite_id=?', (invite_id,))).fetchone()
        await conn.commit()
        return invite_view(row)


async def register(token, public_key, limits=Limits(), recovery_secret=None):
    # Capacity checks and single-use redemption share one write transaction: two
    # simultaneous registrations cannot consume one invite or oversubscribe capacity.
    async with aiosqlite.connect(DB_PATH) as conn:
        await conn.execute('BEGIN IMMEDIATE')
        # A client saves this independent random secret before its first attempt.
        # A lost registration response can then be replayed without storing a raw
        # auth token on the relay or making the consumed invitation reusable by others.
        if recovery_secret is not None:
            if not isinstance(recovery_secret, str) or not 43 <= len(recovery_secret) <= 128:
                raise PolicyError('invalid_registration_secret', 'Invalid registration recovery secret.', status=403)
            recovered = await (await conn.execute('''SELECT a.user_id, a.registration_hash, a.public_key, a.revoked_at
                FROM invites i JOIN accounts a ON a.user_id=i.used_by WHERE i.token_hash=?''', (token_hash(token),))).fetchone()
            if recovered:
                if (recovered[3] is None and recovered[2] == public_key and recovered[1]
                        and secrets.compare_digest(recovered[1], token_hash(recovery_secret))):
                    return recovered[0], registration_auth(recovery_secret)
                raise PolicyError('invalid_invite', 'This invitation cannot recover that identity.', status=403)
        invite = await (await conn.execute('''SELECT 1 FROM invites WHERE token_hash=? AND expires_at>?
            AND used_at IS NULL AND revoked_at IS NULL''', (token_hash(token), int(time.time())))).fetchone()
        if not invite:
            raise PolicyError('invalid_invite', 'Invitation is invalid, expired, revoked, or already used.', status=403)
        count = (await (await conn.execute('SELECT count(*) FROM accounts WHERE revoked_at IS NULL')).fetchone())[0]
        if count >= limits.max_members:
            raise PolicyError('member_capacity_reached', 'Server member capacity reached. The invitation has not been consumed.')
        user_id, auth_token, now = 'usr_' + secrets.token_hex(8), secrets.token_urlsafe(32), int(time.time())
        if recovery_secret:
            auth_token = registration_auth(recovery_secret)
        await conn.execute('''INSERT INTO accounts
            (user_id, auth_hash, public_key, last_seen, created_at, registration_hash) VALUES (?, ?, ?, ?, ?, ?)''',
            (user_id, token_hash(auth_token), public_key, now, now, token_hash(recovery_secret) if recovery_secret else None))
        await conn.execute('UPDATE invites SET used_at=?, used_by=? WHERE token_hash=?', (now, user_id, token_hash(token)))
        await conn.commit()
        return user_id, auth_token


def registration_auth(secret):
    # Domain-separated derivation allows the same issued credential to be recovered.
    return hmac.new(secret.encode(), b'ephemeral-mesh-registration-v1', hashlib.sha256).hexdigest()


async def account(user_id):
    async with aiosqlite.connect(DB_PATH) as conn:
        conn.row_factory = aiosqlite.Row
        row = await (await conn.execute('SELECT * FROM accounts WHERE user_id=?', (user_id,))).fetchone()
        return dict(row) if row else None


async def list_members(limit=100, offset=0):
    async with aiosqlite.connect(DB_PATH) as conn:
        conn.row_factory = aiosqlite.Row
        # Explicit columns keep bearer hashes and key material out of admin responses.
        rows = await (await conn.execute('''SELECT user_id, created_at, last_seen, revoked_at,
            CASE WHEN revoked_at IS NULL THEN 'active' ELSE 'revoked' END AS status
            FROM accounts ORDER BY rowid DESC LIMIT ? OFFSET ?''', (limit, offset))).fetchall()
        return [dict(row) for row in rows]


async def revoke_member(user_id):
    async with aiosqlite.connect(DB_PATH) as conn:
        await conn.execute('BEGIN IMMEDIATE')
        row = await (await conn.execute('SELECT revoked_at FROM accounts WHERE user_id=?', (user_id,))).fetchone()
        if not row:
            raise PolicyError('member_not_found', 'Member not found.', status=404)
        revoked_at = row[0] if row[0] is not None else int(time.time())
        await conn.execute('UPDATE accounts SET revoked_at=? WHERE user_id=?', (revoked_at, user_id))
        # Explicit access revocation cancels undelivered traffic in both directions.
        # Keep ID tombstones; local copies already delivered cannot be remotely erased.
        cursor = await conn.execute('''UPDATE deliveries SET payload=NULL
            WHERE (sender_id=? OR recipient_id=?) AND payload IS NOT NULL''', (user_id, user_id))
        await conn.execute('UPDATE attachments SET ciphertext=NULL WHERE sender_id=? OR recipient_id=?', (user_id, user_id))
        await conn.commit()
        return {'user_id': user_id, 'status': 'revoked', 'revoked_at': revoked_at,
                'cancelled_deliveries': cursor.rowcount}


async def touch(user_id):
    async with aiosqlite.connect(DB_PATH) as conn:
        await conn.execute('UPDATE accounts SET last_seen=? WHERE user_id=?', (int(time.time()), user_id))
        await conn.commit()


async def enqueue(sender_id, message_id, recipient_id, payload, limits=Limits()):
    payload_str = json.dumps(payload, ensure_ascii=False)
    size = len(payload_str.encode('utf-8'))
    async with aiosqlite.connect(DB_PATH) as conn:
        await conn.execute('BEGIN IMMEDIATE')
        # Membership is checked inside the write transaction as well as at the router,
        # so revocation cannot race a concurrent insert into persistent storage.
        for member in (sender_id, recipient_id):
            row = await (await conn.execute('SELECT 1 FROM accounts WHERE user_id=? AND revoked_at IS NULL', (member,))).fetchone()
            if not row:
                raise PolicyError('recipient_unavailable', 'Sender or recipient is no longer an active member.', status=403)
        row = await (await conn.execute('SELECT recipient_id, payload FROM deliveries WHERE sender_id=? AND message_id=?',
                                       (sender_id, message_id))).fetchone()
        if row:
            if row[0] != recipient_id:
                raise PolicyError('message_id_conflict', 'This message ID already belongs to another recipient.')
            # Existing IDs succeed even when full: retries consume no additional quota.
            return json.loads(row[1]) if row[1] else None
        totals = await (await conn.execute('''SELECT count(*), count(payload),
            COALESCE(sum(length(CAST(payload AS BLOB))), 0) FROM deliveries''')).fetchone()
        recipient_count = (await (await conn.execute('''SELECT count(*) FROM deliveries
            WHERE recipient_id=? AND payload IS NOT NULL''', (recipient_id,))).fetchone())[0]
        if totals[0] >= limits.max_delivery_records:
            raise PolicyError('delivery_storage_full', 'Delivery record limit reached. Contact the administrator.')
        if recipient_count >= limits.max_queued_per_recipient:
            raise PolicyError('recipient_queue_full', 'Recipient queue is full. Message remains saved locally.', retryable=True)
        if totals[1] >= limits.max_queued_messages or totals[2] + size > limits.max_queued_bytes:
            raise PolicyError('server_queue_full', 'Server queue storage is full. Message remains saved locally.', retryable=True)
        attachment_id = payload.get('attachment_id')
        if attachment_id:
            blob = await (await conn.execute('''SELECT 1 FROM attachments WHERE attachment_id=?
                AND sender_id=? AND recipient_id=? AND ciphertext IS NOT NULL
                AND (expires_at IS NULL OR expires_at>?) AND (message_id IS NULL OR message_id=?)''',
                (attachment_id, sender_id, recipient_id, int(time.time()), message_id))).fetchone()
            if not blob:
                raise PolicyError('attachment_unavailable', 'Upload the attachment before sending this message.')
            # Referenced uploads do not expire while a recipient remains offline.
            await conn.execute('UPDATE attachments SET expires_at=NULL, message_id=? WHERE attachment_id=?', (message_id, attachment_id))
        await conn.execute('''INSERT INTO deliveries
            (sender_id, message_id, recipient_id, payload, created_at, attachment_id) VALUES (?, ?, ?, ?, ?, ?)''',
            (sender_id, message_id, recipient_id, payload_str, int(time.time()), attachment_id))
        await conn.commit()
        return payload


async def pending(user_id):
    async with aiosqlite.connect(DB_PATH) as conn:
        rows = await (await conn.execute('''SELECT payload FROM deliveries
            WHERE recipient_id=? AND payload IS NOT NULL ORDER BY created_at, rowid''', (user_id,))).fetchall()
        return [json.loads(row[0]) for row in rows]


async def acknowledge(user_id, sender_id, message_id):
    # The authenticated recipient frees payload quota, but keeps the deduplication ID.
    async with aiosqlite.connect(DB_PATH) as conn:
        # The client sends this ACK only after caching and authenticating file contents.
        await conn.execute('''UPDATE attachments SET ciphertext=NULL WHERE attachment_id IN
            (SELECT attachment_id FROM deliveries WHERE recipient_id=? AND sender_id=? AND message_id=?)''',
            (user_id, sender_id, message_id))
        await conn.execute('UPDATE deliveries SET payload=NULL WHERE recipient_id=? AND sender_id=? AND message_id=?',
                           (user_id, sender_id, message_id))
        await conn.commit()


async def usage():
    async with aiosqlite.connect(DB_PATH) as conn:
        totals = await (await conn.execute('''SELECT count(*), count(payload),
            COALESCE(sum(length(CAST(payload AS BLOB))), 0) FROM deliveries''')).fetchone()
        members = (await (await conn.execute('SELECT count(*) FROM accounts WHERE revoked_at IS NULL')).fetchone())[0]
        invites = (await (await conn.execute('SELECT count(*) FROM invites')).fetchone())[0]
        blobs = await (await conn.execute('SELECT count(*), COALESCE(sum(length(ciphertext)),0) FROM attachments')).fetchone()
        return {'active_members': members, 'invite_records': invites, 'delivery_records': totals[0],
                'queued_messages': totals[1], 'queued_bytes': totals[2],
                'attachment_records': blobs[0], 'attachment_bytes': blobs[1]}


async def purge_orphan_attachments():
    # Uploaded-but-never-sent blobs expire after 24h. Keep small ID/hash tombstones
    # to prevent retries overwriting a previously used attachment identity.
    async with aiosqlite.connect(DB_PATH) as conn:
        await conn.execute('UPDATE attachments SET ciphertext=NULL WHERE expires_at IS NOT NULL AND expires_at<=?', (int(time.time()),))
        await conn.commit()


async def put_attachment(attachment_id, sender, recipient, ciphertext, limits=Limits()):
    digest = hashlib.sha256(ciphertext).hexdigest()
    async with aiosqlite.connect(DB_PATH) as conn:
        await conn.execute('BEGIN IMMEDIATE')
        for user in (sender, recipient):
            if not await (await conn.execute('SELECT 1 FROM accounts WHERE user_id=? AND revoked_at IS NULL', (user,))).fetchone():
                raise PolicyError('recipient_unavailable', 'Attachment participants must be active members.', status=403)
        old = await (await conn.execute('SELECT sender_id, recipient_id, digest, ciphertext IS NOT NULL, message_id FROM attachments WHERE attachment_id=?', (attachment_id,))).fetchone()
        if old:
            if old[:3] != (sender, recipient, digest):
                raise PolicyError('attachment_conflict', 'Attachment ID already used for different content or participants.')
            if old[3] or old[4]:
                return  # Idempotent retry, including after delivery released ciphertext.
            # An expired orphan may be reuploaded only by the same sender, with identical bytes.
        totals = await (await conn.execute('SELECT count(*), COALESCE(sum(length(ciphertext)),0) FROM attachments')).fetchone()
        count = (await (await conn.execute('SELECT count(*) FROM attachments WHERE sender_id=? AND ciphertext IS NOT NULL', (sender,))).fetchone())[0]
        if len(ciphertext) > limits.max_attachment_bytes:
            raise PolicyError('attachment_too_large', 'Encrypted attachment exceeds the server size limit.', status=413)
        if not old and totals[0] >= limits.max_attachment_records:
            raise PolicyError('attachment_records_full', 'Attachment record limit reached.')
        if totals[1] + len(ciphertext) > limits.max_attachment_total_bytes or count >= limits.max_attachments_per_sender:
            raise PolicyError('attachment_storage_full', 'Attachment storage is full; retry after recipients receive pending files.', retryable=True)
        if old:
            await conn.execute('UPDATE attachments SET ciphertext=?, expires_at=? WHERE attachment_id=?', (ciphertext, int(time.time()) + 86400, attachment_id))
        else:
            await conn.execute('INSERT INTO attachments VALUES (?, ?, ?, ?, ?, ?, ?, NULL)',
                               (attachment_id, sender, recipient, ciphertext, digest, int(time.time()), int(time.time()) + 86400))
        await conn.commit()


async def get_attachment(attachment_id, user_id):
    async with aiosqlite.connect(DB_PATH) as conn:
        row = await (await conn.execute('''SELECT ciphertext FROM attachments WHERE attachment_id=?
            AND (sender_id=? OR recipient_id=?) AND ciphertext IS NOT NULL
            AND (expires_at IS NULL OR expires_at>?)''', (attachment_id, user_id, user_id, int(time.time())))).fetchone()
        return row[0] if row else None
