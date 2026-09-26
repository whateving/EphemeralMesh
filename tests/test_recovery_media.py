"""Recovery and attachments: confidentiality boundaries, access control, and retries."""
import asyncio
import base64
from dataclasses import replace
import fcntl
import json
from pathlib import Path
import secrets
import tempfile
import unittest
import uuid
from unittest.mock import patch

from cryptography.fernet import Fernet
import db
import main
from client_store import Store
from media import validate_file, safe_name
from profile_backup import export_profile, restore_profile
from relay_config import Limits, PolicyError
from test_admin import AdminFixture

PNG = base64.b64decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+jB9sAAAAASUVORK5CYII=')


class RecoveryTests(unittest.IsolatedAsyncioTestCase):
    async def test_redeemed_invite_recovers_only_original_secret_and_identity(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(db, 'DB_PATH', str(Path(directory) / 'relay.db')):
            await db.init_db()
            token, secret = await db.create_invite(), secrets.token_urlsafe(32)
            first = await db.register(token, 'key-a', recovery_secret=secret)
            second = await db.register(token, 'key-a', recovery_secret=secret)
            self.assertEqual(first, second)
            self.assertEqual((await db.usage())['active_members'], 1)
            self.assertNotIn(secret, json.dumps(await db.account(first[0])))
            for key, recovery in [('key-a', secrets.token_urlsafe(32)), ('key-b', secret), ('key-a', None)]:
                with self.assertRaises(PolicyError):
                    await db.register(token, key, recovery_secret=recovery)
            await db.revoke_member(first[0])
            with self.assertRaises(PolicyError):
                await db.register(token, 'key-a', recovery_secret=secret)


class BackupTests(unittest.TestCase):
    def test_encrypted_round_trip_includes_history_outbox_files_and_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = Store(root / 'source')
            store.setting('auth_token', 'secret-auth-token')
            message_id = store.send_attachment('peer', PNG, 'image/png', '../photo.png')
            public = store.public_key
            backup = root / 'profile.meshbackup'
            export_profile(store.directory, backup, 'correct horse battery staple')
            self.assertNotIn(b'secret-auth-token', backup.read_bytes())
            self.assertNotIn(b'PRIVATE KEY', backup.read_bytes())
            store.conn.close()
            restore_profile(backup, root / 'restored', 'correct horse battery staple')
            restored = Store(root / 'restored')
            try:
                self.assertEqual(restored.public_key, public)
                self.assertEqual(restored.setting('auth_token'), 'secret-auth-token')
                self.assertEqual(restored.snapshot()['messages'][0]['id'], message_id)
                self.assertEqual(restored.snapshot()['messages'][0]['media']['name'], 'photo.png')
                self.assertEqual(restored.conn.execute('SELECT plaintext FROM local_files').fetchone()[0], PNG)
                self.assertEqual(restored.conn.execute('SELECT count(*) FROM outbox').fetchone()[0], 1)
                with self.assertRaises(ValueError):
                    restore_profile(backup, root / 'restored', 'correct horse battery staple')
            finally:
                restored.conn.close()

    def test_wrong_password_tampering_and_running_profile_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = Store(root / 'source')
            store.conn.close()
            backup = root / 'profile.meshbackup'
            with (root / 'source' / 'profile.lock').open('a') as lock:
                fcntl.flock(lock, fcntl.LOCK_EX)
                with self.assertRaises(ValueError):
                    export_profile(root / 'source', backup, 'correct horse battery staple')
            export_profile(root / 'source', backup, 'correct horse battery staple')
            with self.assertRaises(ValueError):
                restore_profile(backup, root / 'wrong', 'wrong password')
            self.assertFalse((root / 'wrong').exists())
            damaged = bytearray(backup.read_bytes()); damaged[-1] ^= 1
            backup.write_bytes(damaged)
            with self.assertRaises(ValueError):
                restore_profile(backup, root / 'tampered', 'correct horse battery staple')
            self.assertFalse((root / 'tampered').exists())


class AttachmentApiTests(AdminFixture):
    def auth_headers(self, user):
        return {'X-User-ID': user['user_id'], 'Authorization': 'Bearer ' + user['auth_token']}

    def test_only_sender_and_recipient_can_access_immutable_blob(self):
        a, b, other = self.register(), self.register(), self.register()
        file_id = str(uuid.uuid4())
        path = '/attachments/' + file_id
        data = Fernet(Fernet.generate_key()).encrypt(PNG)
        self.assertEqual(self.client.put(path, params={'recipient_id': b['user_id']}, content=data).status_code, 401)
        for _ in range(2):
            self.assertEqual(self.client.put(path, params={'recipient_id': b['user_id']}, content=data, headers=self.auth_headers(a)).status_code, 200)
        self.assertEqual(self.client.put(path, params={'recipient_id': b['user_id']}, content=b'different', headers=self.auth_headers(a)).status_code, 409)
        for user in (a, b):
            response = self.client.get(path, headers=self.auth_headers(user))
            self.assertEqual(response.content, data)
            self.assertNotIn(PNG, response.content)
        self.assertEqual(self.client.get(path, headers=self.auth_headers(other)).status_code, 404)
        self.client.delete('/admin/members/' + b['user_id'], headers=self.headers)
        self.assertEqual(self.client.get(path, headers=self.auth_headers(b)).status_code, 401)
        self.assertEqual(self.client.get(path, headers=self.auth_headers(a)).status_code, 404)

    def test_byte_quota_and_sender_quota_enforced_without_partial_blob(self):
        a, b = self.register(), self.register()
        with patch.object(main, 'limits', replace(Limits(), max_attachment_bytes=8, max_attachment_total_bytes=8, max_attachments_per_sender=1)):
            def upload(data):
                return self.client.put('/attachments/' + str(uuid.uuid4()), params={'recipient_id': b['user_id']},
                                       content=data, headers=self.auth_headers(a))
            self.assertEqual(upload(b'123456789').status_code, 413)
            self.assertEqual(upload(b'12345678').status_code, 200)
            self.assertEqual(upload(b'x').json()['detail']['code'], 'attachment_storage_full')
            self.assertEqual(self.client.get('/admin/limits', headers=self.headers).json()['usage']['attachment_bytes'], 8)

    def test_attachment_reference_must_belong_to_authenticated_participants(self):
        a, b, other = self.register(), self.register(), self.register()
        file_id = str(uuid.uuid4())
        self.client.put('/attachments/' + file_id, params={'recipient_id': b['user_id']}, content=b'encrypted', headers=self.auth_headers(a))
        with self.client.websocket_connect('/ws') as socket:
            self.authenticate(socket, other)
            socket.send_json({'type': 'chat', 'recipient_id': b['user_id'], 'message_id': str(uuid.uuid4()),
                              'text': 'encrypted descriptor', 'attachment_id': file_id})
            self.assertEqual(socket.receive_json()['code'], 'attachment_unavailable')

    def test_only_orphan_uploads_expire_and_recipient_ack_releases_file(self):
        a, b = self.register(), self.register()
        file_id, message_id = str(uuid.uuid4()), str(uuid.uuid4())
        self.client.put('/attachments/' + file_id, params={'recipient_id': b['user_id']}, content=b'encrypted', headers=self.auth_headers(a))
        with self.client.websocket_connect('/ws') as socket:
            self.authenticate(socket, a)
            socket.send_json({'type': 'chat', 'recipient_id': b['user_id'], 'message_id': message_id,
                              'text': 'descriptor', 'attachment_id': file_id})
            self.assertEqual(socket.receive_json()['type'], 'accepted')
        async def check():
            with patch('db.time.time', return_value=9999999999):
                await db.purge_orphan_attachments()
                self.assertEqual(await db.get_attachment(file_id, b['user_id']), b'encrypted')
            await db.acknowledge(a['user_id'], a['user_id'], message_id)
            self.assertIsNotNone(await db.get_attachment(file_id, b['user_id']))
            await db.acknowledge(b['user_id'], a['user_id'], message_id)
            self.assertIsNone(await db.get_attachment(file_id, b['user_id']))
        asyncio.run(check())

    def test_html_and_svg_are_never_treated_as_images(self):
        self.assertEqual(validate_file(PNG, 'image/png'), 'image/png')
        self.assertEqual(safe_name('../../image.png'), 'image.png')
        for mime in ('image/png', 'image/svg+xml', 'text/html'):
            with self.assertRaises(ValueError):
                validate_file(b'<svg onload="alert(1)"></svg>', mime)
