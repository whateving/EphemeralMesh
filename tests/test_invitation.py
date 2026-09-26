"""Invitation parsing must not silently downgrade TLS or accept embedded credentials."""
import unittest
from invitation import make_invite, parse_invite, relay_url


class InvitationTests(unittest.TestCase):
    def test_round_trip_and_fragment_only_token(self):
        token = 'a' * 43
        for relay in ('wss://chat.example.com/ws', 'ws://127.0.0.1:8000/ws', 'wss://[::1]:9443/ws'):
            link = make_invite(relay, token)
            self.assertEqual(parse_invite(link), (relay, token))
            self.assertNotIn(token, link.split('#')[0])

    def test_unsafe_or_ambiguous_links_rejected(self):
        for link in ('http://remote.example/#invite=' + 'a' * 43,
                     'https://user:pass@chat.example/#invite=' + 'a' * 43,
                     'https://chat.example/#invite=short',
                     'https://chat.example/?invite=' + 'a' * 43,
                     'https://chat.example/#invite=' + 'a' * 43 + '&invite=' + 'b' * 43,
                     'https://chat.example/other#invite=' + 'a' * 43,
                     'https://chat.example:bad/#invite=' + 'a' * 43):
            with self.subTest(link=link), self.assertRaises(ValueError):
                parse_invite(link)
        with self.assertRaises(ValueError):
            relay_url('wss://example.com/ws?auth=anything')
