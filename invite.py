"""Administrator CLI: create one invitation through the loopback-only admin API."""
import argparse
import json
import os
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from invitation import make_invite, relay_url


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--relay', required=True, help='Public wss://DOMAIN/ws, or loopback ws:// for testing')
    parser.add_argument('--label', default='')
    parser.add_argument('--expires-in', type=int, default=86400)
    args = parser.parse_args()
    try:
        relay_url(args.relay)
    except ValueError as exc:
        parser.error(str(exc))
    secret = os.getenv('ADMIN_SECRET', '')
    if len(secret) < 32:
        parser.error('Set ADMIN_SECRET to the relay administrator secret')
    # Fixed loopback endpoint prevents accidentally forwarding the admin secret to a public relay.
    request = Request('http://127.0.0.1:8000/admin/invites', method='POST',
                      headers={'X-Admin-Token': secret, 'Content-Type': 'application/json'},
                      data=json.dumps({'label': args.label, 'expires_in': args.expires_in}).encode())
    try:
        with urlopen(request, timeout=10) as response:
            result = json.load(response)
        print(make_invite(args.relay, result['invite_token']))
    except HTTPError as exc:
        parser.error(f'Administrator request rejected (HTTP {exc.code}); check credentials, label and expiry')
    except URLError:
        parser.error('Cannot reach the relay on loopback port 8000; run on the server or use an SSH tunnel')


if __name__ == '__main__':
    main()
