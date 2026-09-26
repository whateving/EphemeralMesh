"""Regression tests for identity, queue ownership, delivery, and local bridge isolation."""
import asyncio
from dataclasses import replace
import json
import os
from pathlib import Path
import socket
import tempfile
import unittest
import uuid
import secrets
import sys
import websockets
from unittest.mock import patch

from aiohttp import ClientSession, CookieJar, web
from fastapi.testclient import TestClient
import uvicorn

import db
import main
from chat_client import Client, coordinates, distance_bearing
from client_store import Store, fingerprint


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.a = Store(Path(self.temp.name) / 'a')
        self.b = Store(Path(self.temp.name) / 'b')
        self.addCleanup(self.temp.cleanup)
        self.addCleanup(self.a.conn.close)
        self.addCleanup(self.b.conn.close)

    def test_identity_persistence_and_pinning(self):
        reopened = Store(Path(self.temp.name) / 'a')
        self.addCleanup(reopened.conn.close)
        self.assertEqual(fingerprint(self.a.public_key), fingerprint(reopened.public_key))
        self.a.pin('b', self.b.public_key)
        with self.assertRaises(ValueError):
            self.a.pin('b', self.a.public_key)
        self.b.pin('a', self.a.public_key)
        self.assertEqual(self.b.cipher('a').decrypt(self.a.cipher('b').encrypt(b'hello')), b'hello')

    def test_dedup_and_receipt_are_durable(self):
        message_id = str(uuid.uuid4())
        self.a.receive('b', message_id, {'type': 'text', 'content': 'hello'})
        self.assertFalse(self.a.receive('b', message_id, {'type': 'text', 'content': 'hello'}))
        self.assertEqual(self.a.conn.execute('SELECT count(*) FROM messages').fetchone()[0], 1)
        self.assertEqual(self.a.conn.execute('SELECT count(*) FROM outbox').fetchone()[0], 1)

    def test_status_cannot_downgrade_or_cross_contacts(self):
        message_id = str(uuid.uuid4())
        self.a.send_text('b', 'hello', message_id)
        self.a.receive('c', str(uuid.uuid4()), {'type': 'receipt', 'message_id': message_id, 'status': 'read'})
        self.assertEqual(self.a.snapshot()['messages'][0]['status'], 'pending')
        self.a.receive('b', str(uuid.uuid4()), {'type': 'receipt', 'message_id': message_id, 'status': 'read'})
        self.a.receive('b', str(uuid.uuid4()), {'type': 'receipt', 'message_id': message_id, 'status': 'delivered'})
        self.a.accepted(message_id)
        self.assertEqual(self.a.snapshot()['messages'][0]['status'], 'read')

    def test_coordinate_edges(self):
        self.assertEqual(coordinates(0, 0), (0, 0))
        for location in ((float('nan'), 0), (91, 0), (0, 181), (True, 0)):
            with self.assertRaises(ValueError):
                coordinates(*location)
        self.assertAlmostEqual(distance_bearing((0, 0), (0, 0))[0], 0)
        self.assertTrue(distance_bearing((0, 0), (0, 180))[0] > 12000)
        self.assertAlmostEqual(distance_bearing((0, 0), (0, 1))[1], 90)


class RelayTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.patch_db = patch.object(db, 'DB_PATH', str(Path(self.temp.name) / 'relay.db'))
        self.patch_env = patch.dict(os.environ, ADMIN_SECRET='test-secret-' * 4)
        self.patch_db.start(); self.patch_env.start()
        self.store = Store(Path(self.temp.name) / 'client')
        self.client = TestClient(main.app)
        self.client.__enter__()

    def tearDown(self):
        self.client.__exit__(None, None, None)
        self.store.conn.close()
        self.patch_db.stop(); self.patch_env.stop()
        main.active.clear(); main.delivery_locks.clear()
        self.temp.cleanup()

    def register(self):
        token = self.client.post('/admin/invite', headers={'x-admin-token': os.environ['ADMIN_SECRET']}).json()['invite_token']
        with self.client.websocket_connect('/ws') as ws:
            ws.send_json({'type': 'register', 'invite_token': token, 'public_key': self.store.public_key})
            credentials = ws.receive_json()
        return credentials

    def auth(self, credentials):
        return {'type': 'authenticate', 'user_id': credentials['user_id'],
                'auth_token': credentials['auth_token'], 'public_key': self.store.public_key}

    def test_id_alone_is_rejected(self):
        credentials = self.register()
        with self.client.websocket_connect('/ws') as ws:
            ws.send_json({**self.auth(credentials), 'auth_token': ''})
            self.assertEqual(ws.receive()['code'], 4003)

    def test_queue_survives_send_and_recipient_owns_ack(self):
        a, b = self.register(), self.register()
        message_id = str(uuid.uuid4())
        with self.client.websocket_connect('/ws') as sender:
            sender.send_json(self.auth(a)); sender.receive_json()
            sender.send_json({'type': 'chat', 'recipient_id': b['user_id'], 'message_id': message_id, 'text': 'ciphertext'})
            self.assertEqual(sender.receive_json()['type'], 'accepted')
            sender.send_json({'type': 'queue_ack', 'sender_id': a['user_id'], 'message_id': message_id})
            # A recipient disconnecting without ACK must see the same envelope again.
            for _ in range(2):
                with self.client.websocket_connect('/ws') as recipient:
                    recipient.send_json(self.auth(b)); recipient.receive_json()
                    self.assertEqual(recipient.receive_json()['message_id'], message_id)
            with self.client.websocket_connect('/ws') as recipient:
                recipient.send_json(self.auth(b)); recipient.receive_json()
                recipient.receive_json()
                recipient.send_json({'type': 'queue_ack', 'sender_id': a['user_id'], 'message_id': message_id})
                recipient.send_json({'type': 'presence', 'recipient_id': a['user_id']})
                self.assertEqual(recipient.receive_json()['type'], 'presence')
            # Retrying an acknowledged ID must not resurrect it.
            sender.send_json({'type': 'chat', 'recipient_id': b['user_id'], 'message_id': message_id, 'text': 'ciphertext'})
            sender.receive_json()
            with self.client.websocket_connect('/ws') as recipient:
                recipient.send_json(self.auth(b)); recipient.receive_json()
                recipient.send_json({'type': 'presence', 'recipient_id': a['user_id']})
                self.assertEqual(recipient.receive_json()['type'], 'presence')

    def test_invalid_frame_does_not_kill_session(self):
        credentials = self.register()
        with self.client.websocket_connect('/ws') as ws:
            ws.send_json(self.auth(credentials)); ws.receive_json()
            ws.send_json([])
            self.assertEqual(ws.receive_json()['type'], 'error')
            ws.send_json({'type': 'presence', 'recipient_id': credentials['user_id']})
            self.assertEqual(ws.receive_json()['type'], 'presence')

    def test_replaced_socket_cannot_remove_new_session(self):
        credentials = self.register()
        with self.client.websocket_connect('/ws') as old:
            old.send_json(self.auth(credentials)); old.receive_json()
            with self.client.websocket_connect('/ws') as new:
                new.send_json(self.auth(credentials)); new.receive_json()
                self.assertEqual(old.receive()['code'], 4009)
                new.send_json({'type': 'presence', 'recipient_id': credentials['user_id']})
                self.assertTrue(new.receive_json()['online'])


class EndToEndTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.patch_db = patch.object(db, 'DB_PATH', str(Path(self.temp.name) / 'relay.db'))
        self.patch_env = patch.dict(os.environ, ADMIN_SECRET='test-secret-' * 4)
        self.patch_db.start(); self.patch_env.start()
        self.listener = socket.socket()
        self.listener.bind(('127.0.0.1', 0))
        self.port = self.listener.getsockname()[1]
        self.server = uvicorn.Server(uvicorn.Config(main.app, log_level='error', lifespan='on'))
        self.server_task = asyncio.create_task(self.server.serve(sockets=[self.listener]))
        await self.until(lambda: self.server.started)
        self.stores = [Store(Path(self.temp.name) / name) for name in ('alice', 'bob')]
        self.clients = [Client(store, f'ws://127.0.0.1:{self.port}/ws', await db.create_invite(), 8081 + i)
                        for i, store in enumerate(self.stores)]
        self.tasks = [asyncio.create_task(client.connect_forever()) for client in self.clients]
        await self.until(lambda: all(c.websocket for c in self.clients))

    async def asyncTearDown(self):
        for task in self.tasks:
            task.cancel()
        await asyncio.gather(*self.tasks, return_exceptions=True)
        self.server.should_exit = True
        await self.server_task
        for store in self.stores:
            store.conn.close()
        main.active.clear(); main.delivery_locks.clear()
        self.patch_db.stop(); self.patch_env.stop()
        self.temp.cleanup()

    async def until(self, condition):
        async with asyncio.timeout(12):
            while not condition():
                await asyncio.sleep(.03)

    async def test_admin_smoke_preserves_existing_members(self):
        # Exercise the operator tool on a real disposable listener with two unrelated
        # connected accounts. Its cleanup must leave both accounts and sessions intact.
        process = await asyncio.create_subprocess_exec(
            sys.executable, str(Path(__file__).resolve().parents[1] / 'admin_smoke.py'),
            '--port', str(self.port), stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        stdout, stderr = await asyncio.wait_for(process.communicate(), 40)
        self.assertEqual(process.returncode, 0, stdout.decode() + stderr.decode())
        self.assertIn(b'RESULT PASS', stdout)
        for store in self.stores:
            record = await db.account(store.setting('user_id'))
            self.assertIsNone(record['revoked_at'])
            self.assertIn(store.setting('user_id'), main.active)
            self.assertNotIn(store.setting('auth_token').encode(), stdout)
        self.assertEqual((await db.usage())['active_members'], 2)

    async def test_admin_smoke_cleans_up_after_failure(self):
        import contextlib
        import io
        from admin_smoke import AdminSmoke, CheckFailed
        suite = AdminSmoke(self.port)
        output = io.StringIO()
        # Fail after registration to ensure the finally block removes test access,
        # even when the actual checks do not reach their normal revocation step.
        with patch.object(suite, 'auth_checks', side_effect=CheckFailed('Injected failure')):
            with contextlib.redirect_stdout(output):
                result = await asyncio.to_thread(suite.execute)
        self.assertEqual(result, 1)
        self.assertIn('CLEANUP test members/invites revoked', output.getvalue())
        self.assertEqual((await db.usage())['active_members'], 2)
        for store in self.stores:
            self.assertIsNone((await db.account(store.setting('user_id')))['revoked_at'])
        self.assertTrue(suite.members)
        for member in suite.members:
            self.assertIsNotNone((await db.account(member))['revoked_at'])

    async def test_offline_delivery_restart_history_and_reconnect(self):
        alice, bob = self.clients
        a, b = self.stores
        bob_id = b.setting('user_id')
        self.tasks[1].cancel()
        await asyncio.gather(self.tasks[1], return_exceptions=True)
        await self.until(lambda: bob_id not in main.active)
        message_id = str(uuid.uuid4())
        await alice.ui_command({'type': 'chat', 'recipient_id': bob_id, 'msg_id': message_id, 'text': 'Offline hello'})
        await self.until(lambda: a.snapshot()['messages'][0]['status'] == 'sent')
        self.assertEqual(len(await db.pending(bob_id)), 1)
        self.tasks[1] = asyncio.create_task(bob.connect_forever())
        await self.until(lambda: len(b.snapshot()['messages']) == 1)
        await self.until(lambda: a.snapshot()['messages'][0]['status'] == 'delivered')
        await bob.ui_command({'type': 'read', 'recipient_id': a.setting('user_id')})
        await self.until(lambda: a.snapshot()['messages'][0]['status'] == 'read')
        # Closing the transport exercises automatic reconnect with saved credentials.
        await alice.websocket.close()
        await self.until(lambda: alice.websocket is None)
        await self.until(lambda: alice.websocket is not None)
        self.assertEqual(len(b.snapshot()['messages']), 1)
        reopened = Store(b.directory)
        try:
            self.assertEqual(reopened.snapshot()['messages'][0]['text'], 'Offline hello')
            self.assertEqual(reopened.public_key, b.public_key)
        finally:
            reopened.conn.close()

    async def test_bridge_requires_origin_and_session(self):
        client = self.clients[0]
        app = web.Application()
        app.router.add_get('/', client.index)
        app.router.add_get('/ws', client.ui)
        app.router.add_post('/upload', client.local_upload)
        app.router.add_get('/files/{file_id}', client.local_file)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, '127.0.0.1', 0)
        await site.start()
        port = site._server.sockets[0].getsockname()[1]
        origin = f'http://127.0.0.1:{port}'
        client.origins = {origin}
        try:
            async with ClientSession(cookie_jar=CookieJar(unsafe=True)) as session:
                response = await session.get(origin + '/ws', headers={'Origin': origin})
                self.assertEqual(response.status, 403)
                missing = '/files/' + str(uuid.uuid4())
                response = await session.get(origin + missing)
                self.assertEqual(response.status, 403)
                await session.get(origin + '/')
                response = await session.post(origin + '/upload', data=b'bad', headers={'Origin': 'https://evil.example'})
                self.assertEqual(response.status, 403)
                response = await session.get(origin + missing)
                self.assertEqual(response.status, 404)
                response = await session.get(origin + '/ws', headers={'Origin': 'https://evil.example'})
                self.assertEqual(response.status, 403)
                async with session.ws_connect(origin + '/ws', origin=origin) as ws:
                    self.assertEqual((await ws.receive_json())['type'], 'snapshot')
        finally:
            await runner.cleanup()

    async def test_relay_restart_restores_accounts_and_pending_sends(self):
        alice, bob = self.clients
        alice_id = self.stores[0].setting('user_id')
        bob_id = self.stores[1].setting('user_id')
        # Restart the actual listener and ASGI lifespan with the same on-disk database.
        self.server.should_exit = True
        await self.server_task
        await self.until(lambda: not alice.websocket and not bob.websocket)
        await alice.ui_command({'type': 'chat', 'recipient_id': bob_id,
                                'msg_id': str(uuid.uuid4()), 'text': 'Saved during relay outage'})
        self.assertEqual(self.stores[0].snapshot()['messages'][0]['status'], 'pending')
        self.listener = socket.socket()
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(('127.0.0.1', self.port))
        self.server = uvicorn.Server(uvicorn.Config(main.app, log_level='error', lifespan='on'))
        self.server_task = asyncio.create_task(self.server.serve(sockets=[self.listener]))
        await self.until(lambda: len(self.stores[1].snapshot()['messages']) == 1)
        self.assertEqual(self.stores[0].setting('user_id'), alice_id)
        self.assertEqual(self.stores[1].snapshot()['messages'][0]['text'], 'Saved during relay outage')

    async def test_tampered_envelope_does_not_ack_or_stop_receiver(self):
        alice, bob = self.clients
        a, b = self.stores
        bob_id = b.setting('user_id')
        # Queue the entire backlog while offline so a failed first decrypt cannot
        # be accidentally rescued by duplicate deliveries from a live send.
        self.tasks[1].cancel()
        await asyncio.gather(self.tasks[1], return_exceptions=True)
        await self.until(lambda: bob_id not in main.active)
        bad_id = str(uuid.uuid4())
        await alice.send({'type': 'chat', 'recipient_id': bob_id, 'message_id': bad_id, 'text': 'not-fernet'})
        await alice.ui_command({'type': 'chat', 'recipient_id': bob_id,
                                'msg_id': str(uuid.uuid4()), 'text': 'Valid after malformed ciphertext'})
        await self.until(lambda: a.snapshot()['messages'][0]['status'] == 'sent')
        self.tasks[1] = asyncio.create_task(bob.connect_forever())
        await self.until(lambda: len(b.snapshot()['messages']) == 1)
        self.assertEqual(b.snapshot()['messages'][0]['text'], 'Valid after malformed ciphertext')
        self.assertTrue(any(row['message_id'] == bad_id for row in await db.pending(bob_id)))

    async def test_large_offline_backlog_does_not_trigger_rate_disconnect(self):
        alice, bob = self.clients
        a, b = self.stores
        bob_id = b.setting('user_id')
        self.tasks[1].cancel()
        await asyncio.gather(self.tasks[1], return_exceptions=True)
        await self.until(lambda: bob_id not in main.active)
        # Exceed a one-second frame allowance to test paced replay and concurrent ACKs.
        for index in range(120):
            a.send_text(bob_id, f'Backlog {index}', str(uuid.uuid4()))
        alice.wakeup.set()
        await self.until(lambda: all(m['status'] == 'sent' for m in a.snapshot()['messages']))
        self.tasks[1] = asyncio.create_task(bob.connect_forever())
        await self.until(lambda: len(b.snapshot()['messages']) == 120)
        await self.until(lambda: all(m['status'] == 'delivered' for m in a.snapshot()['messages']))
        self.assertTrue(bob.websocket)

    async def test_queue_rejection_stays_local_and_retries_after_space_is_freed(self):
        alice, bob = self.clients
        a, b = self.stores
        bob_id = b.setting('user_id')
        self.tasks[1].cancel()
        await asyncio.gather(self.tasks[1], return_exceptions=True)
        await self.until(lambda: bob_id not in main.active)
        with patch.object(main, 'limits', replace(main.limits, max_queued_per_recipient=1)):
            await alice.ui_command({'type': 'chat', 'recipient_id': bob_id,
                                    'msg_id': str(uuid.uuid4()), 'text': 'First message'})
            await self.until(lambda: a.snapshot()['messages'][0]['status'] == 'sent')
            second_id = str(uuid.uuid4())
            await alice.ui_command({'type': 'chat', 'recipient_id': bob_id,
                                    'msg_id': second_id, 'text': 'Wait for space'})
            await self.until(lambda: bool(a.snapshot()['messages'][1]['error']))
            self.assertEqual(a.snapshot()['messages'][1]['status'], 'pending')
            self.assertEqual(a.conn.execute('SELECT state FROM outbox WHERE id=?', (second_id,)).fetchone()[0], 'pending')
            self.tasks[1] = asyncio.create_task(bob.connect_forever())
            await self.until(lambda: a.snapshot()['messages'][0]['status'] == 'delivered')
            # Make the already-verified persistent deadline due without spending 30s
            # in the test; the real pump still performs the retry and server acceptance.
            with a.conn:
                a.conn.execute('UPDATE outbox SET retry_at=0 WHERE id=?', (second_id,))
            alice.wakeup.set()
            await self.until(lambda: a.snapshot()['messages'][1]['status'] == 'delivered')
            self.assertEqual(len(b.snapshot()['messages']), 2)
            self.assertIsNone(a.snapshot()['messages'][1]['error'])

    async def test_member_revocation_stops_real_client_without_reconnect_loop(self):
        alice = self.clients[0]
        user_id = self.stores[0].setting('user_id')
        async with ClientSession() as session:
            response = await session.delete(f'http://127.0.0.1:{self.port}/admin/members/{user_id}',
                                            headers={'X-Admin-Token': os.environ['ADMIN_SECRET']})
            self.assertEqual(response.status, 200)
        await self.until(lambda: self.tasks[0].done())
        self.assertIsNone(alice.websocket)
        self.assertIn('revoked', alice.status)

    async def test_message_size_rejection_is_visible_and_manual_retry_keeps_id(self):
        alice = self.clients[0]
        a, b = self.stores
        message_id = str(uuid.uuid4())
        with patch.object(main, 'limits', replace(main.limits, max_message_bytes=8)):
            await alice.ui_command({'type': 'chat', 'recipient_id': b.setting('user_id'),
                                    'msg_id': message_id, 'text': 'Saved even when rejected'})
            await self.until(lambda: a.snapshot()['messages'][0]['status'] == 'failed')
            self.assertEqual(len(b.snapshot()['messages']), 0)
        await alice.ui_command({'type': 'retry', 'recipient_id': b.setting('user_id'), 'msg_id': message_id})
        await self.until(lambda: a.snapshot()['messages'][0]['status'] == 'delivered')
        self.assertEqual(b.snapshot()['messages'][0]['id'], message_id)

    async def test_lost_registration_response_recovers_on_client_restart(self):
        directory = Path(self.temp.name) / 'recover'
        store = Store(directory)
        token, secret = await db.create_invite(), secrets.token_urlsafe(32)
        store.setting('registration_invite', token)
        store.setting('registration_secret', secret)
        async with websockets.connect(self.clients[0].relay) as socket:
            await socket.send(json.dumps({'type': 'register', 'invite_token': token,
                                          'recovery_secret': secret, 'public_key': store.public_key}))
            issued = json.loads(await socket.recv())
            # Deliberately lose the response without persisting its auth credentials.
        store.conn.close()
        recovered = Store(directory)
        client = Client(recovered, self.clients[0].relay, None, 8083)
        task = asyncio.create_task(client.connect_forever())
        try:
            await self.until(lambda: client.websocket is not None)
            self.assertEqual(recovered.setting('user_id'), issued['user_id'])
            self.assertEqual(recovered.setting('auth_token'), issued['auth_token'])
            self.assertIsNone(recovered.setting('registration_secret'))
        finally:
            task.cancel(); await asyncio.gather(task, return_exceptions=True)
            recovered.conn.close()

    async def test_encrypted_image_offline_delivery_cache_and_receipt(self):
        from test_recovery_media import PNG
        alice, bob = self.clients
        a, b = self.stores
        bob_id = b.setting('user_id')
        self.tasks[1].cancel(); await asyncio.gather(self.tasks[1], return_exceptions=True)
        await self.until(lambda: bob_id not in main.active)
        message_id = a.send_attachment(bob_id, PNG, 'image/png', 'test.png')
        alice.wakeup.set()
        await self.until(lambda: a.snapshot()['messages'][0]['status'] == 'sent')
        descriptor = a.snapshot()['messages'][0]['media']
        self.assertNotIn('key', descriptor)
        encrypted = await db.get_attachment(descriptor['id'], bob_id)
        self.assertIsNotNone(encrypted)
        self.assertNotIn(PNG, encrypted)
        self.tasks[1] = asyncio.create_task(bob.connect_forever())
        await self.until(lambda: a.snapshot()['messages'][0]['status'] == 'delivered')
        self.assertEqual(b.conn.execute('SELECT plaintext FROM local_files').fetchone()[0], PNG)
        self.assertEqual(b.snapshot()['messages'][0]['id'], message_id)
        self.assertIsNone(await db.get_attachment(descriptor['id'], bob_id))


if __name__ == '__main__':
    unittest.main()
