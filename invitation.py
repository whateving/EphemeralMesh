"""Create and parse invitation links without putting tokens in HTTP paths or queries."""
import re
from urllib.parse import parse_qs, urlsplit, urlunsplit


def relay_url(value):
    parts = urlsplit(value)
    if (parts.scheme not in ('ws', 'wss') or not parts.hostname or parts.username or parts.password
            or parts.path != '/ws' or parts.query or parts.fragment):
        raise ValueError('Use a relay URL such as wss://chat.example.com/ws')
    if parts.scheme == 'ws' and parts.hostname not in ('localhost', '127.0.0.1', '::1'):
        raise ValueError('Remote relays require wss://')
    # Force port validation now, before saving a profile against a malformed address.
    parts.port
    return value


def make_invite(relay, token):
    parts = urlsplit(relay_url(relay))
    if not isinstance(token, str) or not re.fullmatch(r'[A-Za-z0-9_-]{32,256}', token):
        raise ValueError('Invalid invitation token')
    # URL fragments are not sent in HTTP requests, unlike query-string credentials.
    return urlunsplit(('https' if parts.scheme == 'wss' else 'http', parts.netloc, '/', '', 'invite=' + token))


def parse_invite(value):
    if not isinstance(value, str) or len(value) > 2048:
        raise ValueError('Invalid invitation link')
    parts = urlsplit(value.strip())
    if parts.scheme not in ('http', 'https') or parts.path not in ('', '/') or parts.query:
        raise ValueError('Invalid invitation link')
    fields = parse_qs(parts.fragment, strict_parsing=True)
    if set(fields) != {'invite'} or len(fields['invite']) != 1:
        raise ValueError('Invalid invitation link')
    relay = urlunsplit(('wss' if parts.scheme == 'https' else 'ws', parts.netloc, '/ws', '', ''))
    token = fields['invite'][0]
    make_invite(relay, token)
    return relay, token
