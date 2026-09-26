"""Run bounded admin checks against the local relay; only revoke this run's test records."""
import argparse
import json
import os
import secrets
import sys
import time
import uuid

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from websockets.exceptions import ConnectionClosed
from websockets.sync.client import connect


class CheckFailed(Exception):
    pass


def check(condition, description):
    # Never include a response body, request headers or credentials in failure output.
    if not condition:
        raise CheckFailed(description)


class AdminSmoke:
    def __init__(self, port, expiry=False):
        secret = os.environ.get('ADMIN_SECRET', '')
        check(len(secret) >= 32, 'ADMIN_SECRET is missing; run inside the relay container')
        # Fixed loopback host and disabled redirects/proxies keep admin credentials local.
        self.http = httpx.Client(base_url=f'http://127.0.0.1:{port}', timeout=10,
                                 follow_redirects=False, trust_env=False)
        self.ws_url = f'ws://127.0.0.1:{port}/ws'
        self.admin = {'X-Admin-Token': secret}
        self.label = 'admin-smoke-' + uuid.uuid4().hex
        self.invites = []
        self.members = set()
        self.expiry = expiry
        self.passed = 0
        self.pem = ec.generate_private_key(ec.SECP384R1()).public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()

    def passed_check(self, description):
        self.passed += 1
        print('PASS ' + description, flush=True)

    def request(self, method, path, status=200, headers=None, **kwargs):
        response = self.http.request(method, path, headers=self.admin if headers is None else headers, **kwargs)
        check(response.status_code == status, f'{method} {path}: expected HTTP {status}, got {response.status_code}')
        return response.json()

    def rows(self, resource):
        # Read all pages so cleanup does not assume the test records are still first.
        results = []
        for offset in range(0, 100000, 200):
            rows = self.request('GET', f'/admin/{resource}?limit=200&offset={offset}')[resource]
            results.extend(rows)
            if len(rows) < 200:
                return results
        raise CheckFailed('Audit listing exceeds the smoke-test pagination bound')

    def create_invite(self, expires_in=300):
        result = self.request('POST', '/admin/invites', json={'label': self.label, 'expires_in': expires_in})
        self.invites.append(result)
        return result

    def first_frame(self, frame):
        with connect(self.ws_url, open_timeout=10, close_timeout=3, max_size=65536, proxy=None) as socket:
            socket.send(json.dumps(frame))
            return json.loads(socket.recv(timeout=10))

    def registration(self, invite):
        return {'type': 'register', 'invite_token': invite['invite_token'], 'public_key': self.pem}

    def forbidden_invite(self, invite):
        result = self.first_frame(self.registration(invite))
        check(result.get('code') == 'invalid_invite', 'Invalid invitation allowed registration')

    def auth_checks(self, token, member_id):
        routes = [('GET', '/admin/invites'), ('POST', '/admin/invites'), ('POST', '/admin/invite'),
                  ('DELETE', '/admin/invites/' + self.invites[0]['invite_id']),
                  ('GET', '/admin/members'), ('DELETE', '/admin/members/' + member_id),
                  ('GET', '/admin/limits')]
        # Even if authorization is broken, DELETE targets only this run's resources.
        for headers in ({}, {'X-Admin-Token': token}):
            for method, path in routes:
                kwargs = {'json': {'label': self.label, 'expires_in': 60}} if method == 'POST' else {}
                self.request(method, path, status=401, headers=headers, **kwargs)
        self.passed_check('all admin routes reject missing and member credentials')

    def run_checks(self):
        policy = self.request('GET', '/admin/limits')
        check(policy['usage']['active_members'] < policy['limits']['max_members'],
              'Need one free member slot; no existing member was removed')
        needed = 3 if self.expiry else 2
        check(policy['usage']['invite_records'] + needed <= policy['limits']['max_invite_records'],
              'Not enough invitation-record capacity')
        self.passed_check('administrator authentication and capacity preflight')
        expiring = self.create_invite(60) if self.expiry else None
        expiry_deadline = time.monotonic() + 62 if expiring else None
        invitation = self.create_invite()
        listed = next(r for r in self.rows('invites') if r['invite_id'] == invitation['invite_id'])
        check(listed['status'] == 'pending' and listed['label'] == self.label, 'Invitation listing mismatch')
        check(invitation['expires_at'] - invitation['created_at'] == 300, 'Invitation lifetime mismatch')
        self.passed_check('invitation creation, lifetime and listing')

        user = self.first_frame(self.registration(invitation))
        check(user.get('type') == 'registered', 'Disposable member registration failed')
        self.members.add(user['user_id'])
        auth = {'type': 'authenticate', 'user_id': user['user_id'], 'auth_token': user['auth_token'], 'public_key': self.pem}
        self.forbidden_invite(invitation)
        self.request('DELETE', '/admin/invites/' + invitation['invite_id'], status=409)
        listed = next(r for r in self.rows('invites') if r['invite_id'] == invitation['invite_id'])
        check(listed['status'] == 'used' and listed['used_by'] == user['user_id'], 'Used-invitation audit mismatch')
        self.passed_check('single-use registration and used-invitation protection')
        self.auth_checks(user['auth_token'], user['user_id'])

        listings = self.rows('invites') + self.rows('members')
        forbidden = {'invite_token', 'auth_token', 'token_hash', 'auth_hash', 'registration_hash', 'public_key', 'private_key'}
        check(all(not forbidden.intersection(row) for row in listings), 'Secret field exposed in admin listings')
        serialized = json.dumps(listings)
        check(user['auth_token'] not in serialized and invitation['invite_token'] not in serialized,
              'Credential value exposed in admin listings')
        self.passed_check('admin listings redact credentials and key material')

        for body in ({'expires_in': 0}, {'expires_in': True}, {'label': 'x' * 81}, {'extra': True}):
            self.request('POST', '/admin/invites', status=422, json=body)
        self.request('GET', '/admin/members?limit=9999', status=422)
        self.request('DELETE', '/admin/invites/' + str(uuid.uuid4()), status=404)
        self.passed_check('invalid admin input and unknown invite rejection')

        revoked = self.create_invite()
        for _ in range(2):
            result = self.request('DELETE', '/admin/invites/' + revoked['invite_id'])
            check(result['status'] == 'revoked', 'Invitation revocation failed')
        self.forbidden_invite(revoked)
        self.passed_check('invitation revocation is idempotent and blocks registration')

        with connect(self.ws_url, open_timeout=10, close_timeout=3, proxy=None) as socket:
            socket.send(json.dumps(auth))
            check(json.loads(socket.recv(timeout=10)).get('type') == 'authenticated', 'Reconnect authentication failed')
            member = next(r for r in self.rows('members') if r['user_id'] == user['user_id'])
            check(member['online'], 'Connected member missing online status')
            result = self.request('DELETE', '/admin/members/' + user['user_id'])
            check(result['status'] == 'revoked', 'Member revocation failed')
            try:
                socket.recv(timeout=10)
                raise CheckFailed('Revoked session remained open')
            except ConnectionClosed as exc:
                check(exc.rcvd is not None and exc.rcvd.code == 4003, 'Wrong revocation close code')
        try:
            self.first_frame(auth)
            raise CheckFailed('Revoked member was able to reconnect')
        except ConnectionClosed as exc:
            check(exc.rcvd is not None and exc.rcvd.code == 4003, 'Wrong rejected-login close code')
        result = self.request('DELETE', '/admin/members/' + user['user_id'])
        check(result['cancelled_deliveries'] == 0, 'Repeated revocation changed pending deliveries')
        member = next(r for r in self.rows('members') if r['user_id'] == user['user_id'])
        check(member['status'] == 'revoked' and not member['online'], 'Revoked member listing mismatch')
        self.passed_check('member revocation disconnects, blocks reconnect and is idempotent')

        if expiring:
            wait = max(0, expiry_deadline - time.monotonic())
            print(f'WAIT real invitation expiry (up to {wait:.0f}s)', flush=True)
            # Test actual server expiry; never edit the live database clock or rows.
            time.sleep(wait)
            self.forbidden_invite(expiring)
            listed = next(r for r in self.rows('invites') if r['invite_id'] == expiring['invite_id'])
            check(listed['status'] == 'expired', 'Expired invitation listing mismatch')
            self.passed_check('real 60-second invitation expiration')

    def cleanup(self):
        # Recover created records by a unique per-run label, including registrations
        # whose response was lost. Never select an unrelated account for revocation.
        own = [r for r in self.rows('invites') if r['label'] == self.label]
        self.members.update(r['used_by'] for r in own if r.get('used_by'))
        for member_id in self.members:
            self.request('DELETE', '/admin/members/' + member_id)
        for invite in own:
            if not invite.get('used_by'):
                self.request('DELETE', '/admin/invites/' + invite['invite_id'])
        print('CLEANUP test members/invites revoked; audit records retained', flush=True)

    def execute(self):
        ok = True
        try:
            self.run_checks()
        except (Exception, KeyboardInterrupt) as exc:
            # Third-party exception strings can contain URLs/headers, so redact by default.
            print('FAIL ' + (str(exc) if isinstance(exc, CheckFailed) else type(exc).__name__), flush=True)
            ok = False
        finally:
            try:
                self.cleanup()
            except (Exception, KeyboardInterrupt):
                print('CLEANUP FAILED: rerun cleanup manually for invitation label ' + self.label, flush=True)
                ok = False
            self.http.close()
        print(f'RESULT {"PASS" if ok else "FAIL"}: {self.passed} check groups passed', flush=True)
        return 0 if ok else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int, default=8000, help='Local relay port; host is always 127.0.0.1')
    parser.add_argument('--expiry', action='store_true', help='Also wait for and test real 60-second invite expiry')
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error('Port must be between 1 and 65535')
    try:
        suite = AdminSmoke(args.port, args.expiry)
    except CheckFailed as exc:
        print('FAIL ' + str(exc))
        return 1
    return suite.execute()


if __name__ == '__main__':
    sys.exit(main())
