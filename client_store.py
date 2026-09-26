"""Private, per-profile client state. Plaintext history never enters the relay DB."""
import base64
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import time
import uuid
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def fingerprint(pem):
    # Hash canonical DER, so PEM whitespace cannot change the displayed identity.
    key = serialization.load_pem_public_key(pem.encode())
    raw = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(raw).hexdigest()


class Store:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.directory, 0o700)
        key_path = self.directory / 'identity.pem'
        if not key_path.exists():
            # Exclusive creation prevents accidentally replacing an existing identity.
            key = ec.generate_private_key(ec.SECP384R1())
            raw = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption())
            fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
        self.private_key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        # Tighten permissions on identities created by an older client version, too.
        os.chmod(key_path, 0o600)
        self.public_key = self.private_key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        self.conn = sqlite3.connect(self.directory / 'client.db')
        os.chmod(self.directory / 'client.db', 0o600)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript('''
            PRAGMA journal_mode=WAL;
            PRAGMA synchronous=FULL;
            CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS peers (
                user_id TEXT PRIMARY KEY, public_key TEXT, alias TEXT NOT NULL DEFAULT '',
                verified INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS messages (
                id TEXT NOT NULL, peer TEXT NOT NULL, direction TEXT NOT NULL,
                text TEXT NOT NULL, status TEXT NOT NULL, created REAL NOT NULL,
                PRIMARY KEY (peer, direction, id)
            );
            CREATE TABLE IF NOT EXISTS outbox (
                id TEXT PRIMARY KEY, peer TEXT NOT NULL, body TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS inbox (
                sender TEXT NOT NULL, id TEXT NOT NULL, PRIMARY KEY(sender, id)
            );
            CREATE TABLE IF NOT EXISTS local_files (
                id TEXT PRIMARY KEY, plaintext BLOB NOT NULL, ciphertext BLOB
            );
        ''')
        # Persist rejected sends and retry deadlines so limits never silently lose
        # an outbox item or cause an immediate retry loop after a client restart.
        for table, additions in {
            'outbox': {'state': "TEXT NOT NULL DEFAULT 'pending'", 'retry_at': 'REAL NOT NULL DEFAULT 0'},
            'messages': {'error': 'TEXT', 'media': 'TEXT'},
        }.items():
            columns = {row[1] for row in self.conn.execute(f'PRAGMA table_info({table})')}
            for name, definition in additions.items():
                if name not in columns:
                    self.conn.execute(f'ALTER TABLE {table} ADD COLUMN {name} {definition}')
        self.conn.commit()
        self.ciphers = {}

    def setting(self, key, value=None):
        if value is not None:
            with self.conn:
                self.conn.execute('INSERT OR REPLACE INTO settings VALUES (?, ?)', (key, value))
        row = self.conn.execute('SELECT value FROM settings WHERE key=?', (key,)).fetchone()
        return row[0] if row else None

    def add_peer(self, peer):
        with self.conn:
            self.conn.execute('INSERT OR IGNORE INTO peers(user_id) VALUES (?)', (peer,))

    def pin(self, peer, pem):
        self.add_peer(peer)
        old = self.conn.execute('SELECT public_key FROM peers WHERE user_id=?', (peer,)).fetchone()[0]
        # Trust on first use; changed identities are rejected instead of silently accepted.
        if old and fingerprint(old) != fingerprint(pem):
            raise ValueError('IDENTITY KEY CHANGED for ' + peer + '. Contact your friend through another channel.')
        key = serialization.load_pem_public_key(pem.encode())
        if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP384R1):
            raise ValueError('Unsupported peer key')
        with self.conn:
            self.conn.execute('UPDATE peers SET public_key=? WHERE user_id=?', (pem, peer))
        self.ciphers.pop(peer, None)

    def cipher(self, peer):
        if peer not in self.ciphers:
            row = self.conn.execute('SELECT public_key FROM peers WHERE user_id=?', (peer,)).fetchone()
            if not row or not row[0]:
                return None
            key = serialization.load_pem_public_key(row[0].encode())
            shared = self.private_key.exchange(ec.ECDH(), key)
            # Domain separation keeps this key specific to this protocol version.
            derived = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                           info=b'ephemeral-mesh-v2').derive(shared)
            self.ciphers[peer] = Fernet(base64.urlsafe_b64encode(derived))
        return self.ciphers[peer]

    def queue(self, peer, body, message_id=None):
        message_id = message_id or str(uuid.uuid4())
        self.conn.execute('INSERT OR IGNORE INTO outbox(id, peer, body) VALUES (?, ?, ?)',
                          (message_id, peer, json.dumps(body)))
        return message_id

    def send_text(self, peer, text, message_id):
        # Save the visible message and pending send atomically before notifying the UI.
        self.add_peer(peer)
        with self.conn:
            cursor = self.conn.execute('INSERT OR IGNORE INTO messages(id, peer, direction, text, status, created) VALUES (?, ?, ?, ?, ?, ?)',
                                       (message_id, peer, 'sent', text, 'pending', time.time()))
            if cursor.rowcount:
                self.queue(peer, {'type': 'text', 'content': text}, message_id)

    def receive(self, peer, message_id, body):
        # Deduplication, history, and the outgoing receipt commit before queue ACK.
        with self.conn:
            cursor = self.conn.execute('INSERT OR IGNORE INTO inbox VALUES (?, ?)', (peer, message_id))
            if not cursor.rowcount:
                return False
            if body['type'] in ('text', 'attachment'):
                attachment = body.get('attachment')
                self.conn.execute('INSERT INTO messages(id, peer, direction, text, status, created, media) VALUES (?, ?, ?, ?, ?, ?, ?)',
                                  (message_id, peer, 'received', body.get('content', attachment['name'] if attachment else ''),
                                   'delivered', time.time(), json.dumps(attachment) if attachment else None))
                if attachment:
                    # File, history, dedup, and receipt commit before relay acknowledgment.
                    self.conn.execute('INSERT OR IGNORE INTO local_files VALUES (?, ?, NULL)', (attachment['id'], body['_file_bytes']))
                self.queue(peer, {'type': 'receipt', 'message_id': message_id, 'status': 'delivered'})
            elif body['type'] == 'receipt':
                # Receipts are scoped to the peer and may never downgrade a read status.
                self.conn.execute('''UPDATE messages SET status=?, error=NULL WHERE peer=? AND direction='sent'
                    AND id=? AND status!='read' ''', (body['status'], peer, body['message_id']))
        return True

    def send_attachment(self, peer, raw, mime, name):
        from media import validate_file, safe_name
        mime = validate_file(raw, mime)
        file_id, message_id = str(uuid.uuid4()), str(uuid.uuid4())
        key = Fernet.generate_key()
        encrypted = Fernet(key).encrypt(raw)
        descriptor = {'id': file_id, 'key': key.decode(), 'sha256': hashlib.sha256(encrypted).hexdigest(),
                      'mime': mime, 'name': safe_name(name), 'size': len(raw)}
        self.add_peer(peer)
        # Preserve exact ciphertext and ID across retries, making uploads idempotent.
        with self.conn:
            self.conn.execute('INSERT INTO local_files VALUES (?, ?, ?)', (file_id, raw, encrypted))
            self.conn.execute('''INSERT INTO messages(id, peer, direction, text, status, created, media)
                VALUES (?, ?, 'sent', ?, 'pending', ?, ?)''', (message_id, peer, descriptor['name'], time.time(), json.dumps(descriptor)))
            self.queue(peer, {'type': 'attachment', 'attachment': descriptor}, message_id)
        return message_id

    def accepted(self, message_id):
        with self.conn:
            self.conn.execute('DELETE FROM outbox WHERE id=?', (message_id,))
            self.conn.execute("UPDATE messages SET status='sent', error=NULL WHERE id=? AND direction='sent' AND status='pending'", (message_id,))

    def reject(self, message_id, reason, retryable=False, retry_after=30):
        # Failure changes status, not message ownership: plaintext and outbox stay local.
        with self.conn:
            row = self.conn.execute('SELECT peer FROM outbox WHERE id=?', (message_id,)).fetchone()
            if not row:
                return
            self.conn.execute('UPDATE outbox SET state=?, retry_at=? WHERE id=?',
                              ('pending' if retryable else 'blocked', time.time() + retry_after, message_id))
            self.conn.execute("""UPDATE messages SET status=?, error=?
                WHERE id=? AND peer=? AND direction='sent' AND status IN ('pending', 'failed')""",
                ('pending' if retryable else 'failed', reason, message_id, row[0]))

    def retry(self, peer, message_id):
        # Explicit retries use the original ID, preserving relay-side deduplication.
        with self.conn:
            cursor = self.conn.execute("UPDATE outbox SET state='pending', retry_at=0 WHERE id=? AND peer=?", (message_id, peer))
            if cursor.rowcount:
                self.conn.execute("UPDATE messages SET status='pending', error=NULL WHERE id=? AND peer=? AND direction='sent' AND status='failed'", (message_id, peer))

    def mark_read(self, peer):
        with self.conn:
            rows = self.conn.execute("SELECT id FROM messages WHERE peer=? AND direction='received' AND status!='read'", (peer,)).fetchall()
            for row in rows:
                self.queue(peer, {'type': 'receipt', 'message_id': row[0], 'status': 'read'})
            self.conn.execute("UPDATE messages SET status='read' WHERE peer=? AND direction='received'", (peer,))

    def snapshot(self):
        peers = [dict(row) for row in self.conn.execute('SELECT * FROM peers ORDER BY rowid')]
        for peer in peers:
            pem = peer.pop('public_key')
            peer['fingerprint'] = fingerprint(pem) if pem else None
        messages = [dict(row) for row in self.conn.execute('SELECT * FROM messages ORDER BY created, rowid')]
        for message in messages:
            if message['media']:
                descriptor = json.loads(message['media'])
                # Only display metadata reaches the browser, never the file's encryption key.
                message['media'] = {k: descriptor[k] for k in ('id', 'name', 'mime', 'size')}
        return {'type': 'snapshot', 'user_id': self.setting('user_id'),
                'fingerprint': fingerprint(self.public_key), 'peers': peers,
                'messages': messages}
