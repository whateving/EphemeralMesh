"""Exercise disposable relay/Caddy containers; never reuse an operator's volumes."""
import argparse
import json
import os
from pathlib import Path
import secrets
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import uuid


def docker(*args, **kwargs):
    return subprocess.check_output(['docker', *args], text=True, **kwargs).strip()


def request(base, path, token=None, method='GET'):
    headers = {'X-Admin-Token': token} if token else {}
    try:
        with urllib.request.urlopen(urllib.request.Request(base + path, headers=headers, method=method), timeout=3) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def ready(base):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            if request(base, '/healthz')[0] == 200:
                return
        except OSError:
            pass
        time.sleep(.2)
    raise AssertionError('Relay did not become healthy')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', default='ephemeral-mesh:local-test')
    parser.add_argument('--caddy-image', default='caddy:2.11.4-alpine')
    args = parser.parse_args()
    suffix = uuid.uuid4().hex[:12]
    network, volume = 'mesh-smoke-net-' + suffix, 'mesh-smoke-data-' + suffix
    relay, proxy = 'mesh-smoke-relay-' + suffix, 'mesh-smoke-proxy-' + suffix
    secret = secrets.token_urlsafe(32)
    # Pass the temporary secret through the environment, never the command line or logs.
    env = {**os.environ, 'ADMIN_SECRET': secret}
    created_network = created_volume = False
    try:
        docker('network', 'create', network); created_network = True
        docker('volume', 'create', volume); created_volume = True
        docker('run', '-d', '--name', relay, '--network', network, '--network-alias', 'relay',
               '-e', 'ADMIN_SECRET', '-v', volume + ':/data', '-p', '127.0.0.1::8000',
               '--read-only', '--tmpfs', '/tmp:size=16m', '--cap-drop', 'ALL',
               '--security-opt', 'no-new-privileges:true', '--memory', '512m', args.image, env=env)
        base = 'http://' + docker('port', relay, '8000/tcp')
        ready(base)
        assert request(base, '/admin/invites')[0] == 401
        status, body = request(base, '/admin/invites', secret, 'POST')
        assert status == 200, (status, body)
        invitation = json.loads(body)['invite_id']
        docker('restart', relay)
        # Docker may allocate a different ephemeral host port on restart.
        base = 'http://' + docker('port', relay, '8000/tcp')
        ready(base)
        status, body = request(base, '/admin/invites', secret)
        assert status == 200 and invitation in body.decode(), 'Volume did not preserve invitation'
        assert docker('exec', relay, 'id', '-u') == '10001'
        # The packaged admin helper creates a fragment-only link without exporting its secret.
        link = docker('exec', relay, 'python', 'invite.py', '--relay', 'wss://chat.example.com/ws', '--label', 'Smoke test')
        assert link.startswith('https://chat.example.com/#invite=') and len(link.split('invite=')[1]) >= 32
        with tempfile.TemporaryDirectory() as scratch:
            # Validate the actual TLS template, then test its routing on disposable HTTP ports.
            config = Path(scratch) / 'Caddyfile'
            source = Path(__file__).resolve().parents[1] / 'deploy' / 'Caddyfile'
            config.write_text(source.read_text().replace('{$MESH_DOMAIN}', 'localhost'))
            docker('run', '--rm', '-v', str(config) + ':/etc/caddy/Caddyfile:ro', args.caddy_image,
                   'caddy', 'validate', '--config', '/etc/caddy/Caddyfile')
            config.write_text(source.read_text().replace('{$MESH_DOMAIN}', ':8080'))
            docker('run', '-d', '--name', proxy, '--network', network,
                   '-v', str(config) + ':/etc/caddy/Caddyfile:ro', '-p', '127.0.0.1::8080', args.caddy_image)
            public = 'http://' + docker('port', proxy, '8080/tcp')
            deadline = time.monotonic() + 20
            while True:
                try:
                    assert request(public, '/admin/invites', secret)[0] == 404
                    break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise
                    time.sleep(.2)
            assert request(public, '/')[0] == 200
            assert request(public, '/healthz')[0] == 404
            assert request(public, '/attachments/' + str(uuid.uuid4()))[0] == 401
            # A WebSocket upgrade reaches the relay through Caddy; an invalid invite is rejected.
            from websockets.sync.client import connect
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric import ec
            pem = ec.generate_private_key(ec.SECP384R1()).public_key().public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
            with connect(public.replace('http:', 'ws:') + '/ws') as socket:
                socket.send(json.dumps({'type': 'register', 'invite_token': 'invalid', 'public_key': pem}))
                assert json.loads(socket.recv())['type'] == 'error'
        print('PASS: non-root relay, durable restart, admin authentication, Caddy configuration, private admin/health routes, attachment routing and WebSocket proxy.')
    except Exception:
        # Startup diagnostics contain no access logs or bearer credentials.
        for container in (relay, proxy):
            subprocess.run(['docker', 'logs', '--tail', '30', container], check=False)
        raise
    finally:
        # Only names generated by this invocation are removed, including on failed assertions.
        for container in (proxy, relay):
            subprocess.run(['docker', 'rm', '-f', container], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if created_volume:
            docker('volume', 'rm', volume)
        if created_network:
            docker('network', 'rm', network)


if __name__ == '__main__':
    main()
