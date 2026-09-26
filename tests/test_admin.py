"""Admin authorization, additive migrations, revocation, and atomic quota regressions."""
import asyncio
from dataclasses import replace
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
import uuid
from unittest.mock import patch

from fastapi.testclient import TestClient
import db
import main
from client_store import Store
from relay_config import Limits, PolicyError


class AdminFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db_patch = patch.object(db, 'DB_PATH', str(Path(self.temp.name) / 'relay.db'))
        self.env_patch = patch.dict(os.environ, {
            'ADMIN_SECRET': 'admin-test-secret-' * 3,
            **{'MESH_' + key.upper(): str(value) for key, value in Limits().public().items()},
        })
        self.db_patch.start(); self.env_patch.start()
        self.store = Store(Path(self.temp.name) / 'client')
        self.client = TestClient(main.app)
        self.client.__enter__()
        self.headers = {'X-Admin-Token': os.environ['ADMIN_SECRET']}

    def tearDown(self):
        self.client.__exit__(None, None, None)
        self.store.conn.close()
        self.db_patch.stop(); self.env_patch.stop()
        main.active.clear(); main.inflight.clear(); main.delivery_locks.clear()
        self.temp.cleanup()

    def invitation(self, **body):
        response = self.client.post('/admin/invites', headers=self.headers, json=body)
        self.assertEqual(response.status_code, 200)
        return response.json()

    def register(self, invitation=None):
        invitation = invitation or self.invitation()
        with self.client.websocket_connect('/ws') as socket:
            socket.send_json({'type': 'register', 'invite_token': invitation['invite_token'], 'public_key': self.store.public_key})
            return socket.receive_json()

    def authenticate(self, socket, credentials):
        socket.send_json({'type': 'authenticate', 'user_id': credentials['user_id'],
                          'auth_token': credentials['auth_token'], 'public_key': self.store.public_key})
        return socket.receive_json()

class AdminTests(AdminFixture):
    def test_every_admin_endpoint_requires_admin_secret(self):
        # Possessing ordinary member credentials grants no administrative permissions.
        user = self.register()
        routes = [('GET', '/admin/invites'), ('POST', '/admin/invites'), ('POST', '/admin/invite'),
                  ('DELETE', '/admin/invites/' + str(uuid.uuid4())), ('GET', '/admin/members'),
                  ('DELETE', '/admin/members/' + user['user_id']), ('GET', '/admin/limits')]
        for method, url in routes:
            for headers in ({}, {'X-Admin-Token': user['auth_token']}):
                with self.subTest(method=method, url=url):
                    self.assertEqual(self.client.request(method, url, headers=headers).status_code, 401)

    def test_invitation_lifecycle_and_secret_redaction(self):
        invite = self.invitation(label='For Alex', expires_in=120)
        self.assertEqual(invite['expires_at'] - invite['created_at'], 120)
        rows = self.client.get('/admin/invites', headers=self.headers).json()['invites']
        self.assertEqual(rows[0]['status'], 'pending')
        user = self.register(invite)
        rows = self.client.get('/admin/invites', headers=self.headers).json()['invites']
        self.assertEqual((rows[0]['status'], rows[0]['used_by']), ('used', user['user_id']))
        self.assertEqual(self.register(invite)['code'], 'invalid_invite')
        self.assertEqual(self.client.delete('/admin/invites/' + invite['invite_id'], headers=self.headers).status_code, 409)
        members = self.client.get('/admin/members', headers=self.headers).json()['members']
        serialized = json.dumps(rows + members)
        for secret in (invite['invite_token'], user['auth_token'], db.token_hash(invite['invite_token']),
                       db.token_hash(user['auth_token']), self.store.public_key):
            self.assertNotIn(secret, serialized)

    def test_revoked_and_expired_invites_cannot_register(self):
        invite = self.invitation()
        for _ in range(2):
            response = self.client.delete('/admin/invites/' + invite['invite_id'], headers=self.headers)
            self.assertEqual(response.json()['status'], 'revoked')
        self.assertEqual(self.register(invite)['code'], 'invalid_invite')
        expired = self.invitation()
        with sqlite3.connect(db.DB_PATH) as conn:
            conn.execute('UPDATE invites SET expires_at=0 WHERE invite_id=?', (expired['invite_id'],))
        # sqlite3's context manager commits but does not close the connection.
        conn.close()
        self.assertEqual(self.register(expired)['code'], 'invalid_invite')
        statuses = {row['invite_id']: row['status'] for row in self.client.get('/admin/invites', headers=self.headers).json()['invites']}
        self.assertEqual(statuses[expired['invite_id']], 'expired')

    def test_input_validation_pagination_and_invite_record_limit(self):
        for body in ({'expires_in': 0}, {'expires_in': 604801}, {'expires_in': True},
                     {'label': 'x' * 81}, {'extra': 'forbidden'}):
            self.assertEqual(self.client.post('/admin/invites', headers=self.headers, json=body).status_code, 422)
        self.invitation(label='first'); self.invitation(label='second')
        rows = self.client.get('/admin/invites?limit=1&offset=1', headers=self.headers).json()['invites']
        self.assertEqual(rows[0]['label'], 'first')
        self.assertEqual(self.client.get('/admin/members?limit=9999', headers=self.headers).status_code, 422)
        self.assertEqual(self.client.delete('/admin/invites/' + str(uuid.uuid4()), headers=self.headers).status_code, 404)
        with patch.object(main, 'limits', replace(Limits(), max_invite_records=2)):
            result = self.client.post('/admin/invites', headers=self.headers).json()
            self.assertEqual(result['detail']['code'], 'invite_storage_full')

    def test_member_revocation_disconnects_and_survives_restart(self):
        user = self.register()
        with self.client.websocket_connect('/ws') as socket:
            self.authenticate(socket, user)
            self.assertTrue(self.client.get('/admin/members', headers=self.headers).json()['members'][0]['online'])
            result = self.client.delete('/admin/members/' + user['user_id'], headers=self.headers)
            self.assertEqual(result.json()['status'], 'revoked')
            self.assertEqual(socket.receive()['code'], 4003)
        # Recreate lifespan: revoked credentials stay rejected after relay restart.
        self.client.__exit__(None, None, None)
        self.client = TestClient(main.app)
        self.client.__enter__()
        with self.client.websocket_connect('/ws') as socket:
            socket.send_json({'type': 'authenticate', 'user_id': user['user_id'], 'auth_token': user['auth_token'],
                              'public_key': self.store.public_key})
            self.assertEqual(socket.receive()['code'], 4003)
        row = self.client.get('/admin/members', headers=self.headers).json()['members'][0]
        self.assertEqual(row['status'], 'revoked')
        self.assertFalse(row['online'])
        self.assertEqual(self.client.delete('/admin/members/' + user['user_id'], headers=self.headers).json()['cancelled_deliveries'], 0)
        self.assertEqual(self.client.delete('/admin/members/usr_missing', headers=self.headers).status_code, 404)

    def test_capacity_does_not_consume_invite_and_revocation_frees_slot(self):
        with patch.object(main, 'limits', replace(Limits(), max_members=1)):
            first = self.register()
            invite = self.invitation()
            self.assertEqual(self.register(invite)['code'], 'member_capacity_reached')
            self.client.delete('/admin/members/' + first['user_id'], headers=self.headers)
            self.assertEqual(self.register(invite)['type'], 'registered')

    def test_rejections_include_message_id_and_leave_session_usable(self):
        a, b = self.register(), self.register()
        with self.client.websocket_connect('/ws') as socket:
            self.authenticate(socket, a)
            with patch.object(main, 'limits', replace(Limits(), max_queued_per_recipient=1, max_message_bytes=8)):
                def send(text):
                    message_id = str(uuid.uuid4())
                    socket.send_json({'type': 'chat', 'recipient_id': b['user_id'], 'message_id': message_id, 'text': text})
                    return message_id, socket.receive_json()
                # UTF-8 bytes, not Unicode character count, determine the size limit.
                oversized, result = send('é' * 5)
                self.assertEqual((result['code'], result['message_id']), ('message_too_large', oversized))
                self.assertEqual(send('12345678')[1]['type'], 'accepted')
                queued, result = send('next')
                self.assertEqual((result['code'], result['message_id']), ('recipient_queue_full', queued))
                self.assertTrue(result['retryable'])
                self.assertEqual(result['retry_after'], 30)
                self.client.delete('/admin/members/' + b['user_id'], headers=self.headers)
                unavailable, result = send('last')
                self.assertEqual((result['code'], result['message_id']), ('recipient_unavailable', unavailable))
                socket.send_json({'type': 'presence', 'recipient_id': a['user_id']})
                self.assertEqual(socket.receive_json()['type'], 'presence')

    def test_frame_rate_limit_is_configurable(self):
        user = self.register()
        with patch.object(main, 'limits', replace(Limits(), max_frames_per_second=1)):
            with self.client.websocket_connect('/ws') as socket:
                self.authenticate(socket, user)
                for _ in range(2):
                    socket.send_json({'type': 'presence', 'recipient_id': user['user_id']})
                    response = socket.receive_json()
                self.assertEqual(response['code'], 'frame_limit_exceeded')
                self.assertEqual(socket.receive()['code'], 1008)


class DatabasePolicyTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db_patch = patch.object(db, 'DB_PATH', str(Path(self.temp.name) / 'relay.db'))
        self.db_patch.start()
        await db.init_db()
        self.a = (await db.register(await db.create_invite(), 'public-a'))[0]
        self.b = (await db.register(await db.create_invite(), 'public-b'))[0]

    async def asyncTearDown(self):
        self.db_patch.stop()
        self.temp.cleanup()

    def envelope(self, recipient=None):
        return {'type': 'chat', 'sender_id': self.a, 'recipient_id': recipient or self.b,
                'message_id': str(uuid.uuid4()), 'text': 'é'}

    async def save(self, payload, limits=Limits()):
        return await db.enqueue(self.a, payload['message_id'], payload['recipient_id'], payload, limits)

    async def test_concurrent_registrations_obey_capacity_and_single_use(self):
        invite = await db.create_invite()
        results = await asyncio.gather(db.register(invite, 'first'), db.register(invite, 'second'), return_exceptions=True)
        self.assertEqual(sum(isinstance(result, tuple) for result in results), 1)
        limits = replace(Limits(), max_members=4)
        one, two = await db.create_invite(), await db.create_invite()
        results = await asyncio.gather(db.register(one, 'first', limits), db.register(two, 'second', limits), return_exceptions=True)
        self.assertEqual(sum(isinstance(result, tuple) for result in results), 1)
        self.assertEqual((await db.usage())['active_members'], 4)

    async def test_concurrent_enqueues_cannot_exceed_global_capacity(self):
        limits = replace(Limits(), max_queued_messages=1)
        results = await asyncio.gather(self.save(self.envelope(), limits), self.save(self.envelope(self.a), limits), return_exceptions=True)
        self.assertEqual(sum(isinstance(result, dict) for result in results), 1)
        self.assertEqual((await db.usage())['queued_messages'], 1)

    async def test_exact_byte_limit_ack_frees_space_and_retry_uses_no_quota(self):
        payload = self.envelope()
        size = len(json.dumps(payload, ensure_ascii=False).encode())
        with self.assertRaises(PolicyError) as error:
            await self.save(payload, replace(Limits(), max_queued_bytes=size - 1))
        self.assertEqual(error.exception.code, 'server_queue_full')
        limits = replace(Limits(), max_queued_bytes=size, max_delivery_records=1)
        await self.save(payload, limits)
        await self.save(payload, limits)
        self.assertEqual((await db.usage())['queued_bytes'], size)
        await db.acknowledge(self.a, self.a, payload['message_id'])
        self.assertEqual((await db.usage())['queued_bytes'], size)
        await db.acknowledge(self.b, self.a, payload['message_id'])
        self.assertEqual((await db.usage())['queued_bytes'], 0)
        self.assertIsNone(await self.save(payload, limits))
        with self.assertRaises(PolicyError) as error:
            await self.save(self.envelope(), limits)
        self.assertEqual(error.exception.code, 'delivery_storage_full')
        # Raising only the record cap permits another payload after ACK released its bytes.
        await self.save(self.envelope(), replace(limits, max_delivery_records=2))

    async def test_revocation_cancels_both_directions_and_preserves_other_queues(self):
        payload = self.envelope()
        await self.save(payload)
        other = (await db.register(await db.create_invite(), 'public-c'))[0]
        back = {**self.envelope(self.a), 'sender_id': self.b}
        await db.enqueue(self.b, back['message_id'], self.a, back)
        await self.save(self.envelope(other))
        self.assertEqual((await db.revoke_member(self.b))['cancelled_deliveries'], 2)
        self.assertEqual(len(await db.pending(other)), 1)
        self.assertEqual(len(await db.pending(self.a)), 0)
        with self.assertRaises(PolicyError):
            await self.save(payload)


class MigrationAndConfigurationTests(unittest.TestCase):
    def test_existing_schema_upgrades_without_losing_tokens_or_ciphertext(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / 'legacy.db')
            conn = sqlite3.connect(path)
            conn.executescript('''
                CREATE TABLE accounts(user_id TEXT PRIMARY KEY, auth_hash TEXT NOT NULL, public_key TEXT NOT NULL, last_seen INTEGER);
                CREATE TABLE invites(token_hash TEXT PRIMARY KEY, expires_at INTEGER NOT NULL);
                CREATE TABLE deliveries(sender_id TEXT NOT NULL, message_id TEXT NOT NULL, recipient_id TEXT NOT NULL, payload TEXT, created_at INTEGER NOT NULL, PRIMARY KEY(sender_id,message_id));
                CREATE TABLE queued_messages(payload TEXT);
                INSERT INTO accounts VALUES('old', 'hash', 'key', 1);
                INSERT INTO invites VALUES('invite-hash', 4102444800);
                INSERT INTO deliveries VALUES('old', 'message', 'old', '{"text":"ciphertext"}', 1);
                INSERT INTO queued_messages VALUES('legacy-ciphertext');
            ''')
            conn.close()
            with patch.object(db, 'DB_PATH', path):
                asyncio.run(db.init_db()); asyncio.run(db.init_db())
                self.assertEqual(asyncio.run(db.account('old'))['auth_hash'], 'hash')
                self.assertEqual(asyncio.run(db.list_invites())[0]['status'], 'pending')
                self.assertEqual(asyncio.run(db.pending('old'))[0]['text'], 'ciphertext')
                conn = sqlite3.connect(path)
                self.assertEqual(conn.execute('SELECT payload FROM queued_messages').fetchone()[0], 'legacy-ciphertext')
                conn.close()

    def test_bad_environment_values_fail_closed(self):
        for value in ('0', '-1', 'nope', '999999999999999'):
            with patch.dict(os.environ, MESH_MAX_MEMBERS=value):
                with self.assertRaises(ValueError):
                    Limits.from_env()
        with patch.dict(os.environ, MESH_MAX_MESSAGE_BYTES='48001'):
            with self.assertRaises(ValueError):
                Limits.from_env()

    def test_blocked_outbox_and_retry_survive_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(directory)
            message_id = str(uuid.uuid4())
            store.send_text('peer', 'Keep me', message_id)
            store.reject(message_id, 'Message too large')
            store.conn.close()
            store = Store(directory)
            self.assertEqual(store.snapshot()['messages'][0]['status'], 'failed')
            self.assertEqual(store.conn.execute('SELECT state FROM outbox').fetchone()[0], 'blocked')
            store.retry('another-peer', message_id)
            self.assertEqual(store.snapshot()['messages'][0]['status'], 'failed')
            store.retry('peer', message_id)
            self.assertEqual(store.conn.execute('SELECT id, state FROM outbox').fetchone()[:], (message_id, 'pending'))
            store.reject(message_id, 'Queue full', retryable=True)
            self.assertEqual(store.snapshot()['messages'][0]['status'], 'pending')
            self.assertGreater(store.conn.execute('SELECT retry_at FROM outbox').fetchone()[0], 0)
            store.conn.close()
