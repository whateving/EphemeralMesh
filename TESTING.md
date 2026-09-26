# Run and test Ephemeral Mesh

## What changed

- `main.py` is the relay. It now persists accounts, hashes authentication tokens, validates frames, and queues ciphertext before delivery. It clears queued ciphertext when its authenticated recipient acknowledges it or an administrator revokes a member involved in the delivery; delivery IDs remain as deduplication tombstones.
- The admin API manages invitations and members and exposes configurable limits/usage. See [ADMIN_API.md](ADMIN_API.md) for commands, defaults, revocation behavior, and tests.
- `relay_config.py` validates startup limits; `.env.example` documents them.
- `db.py` contains relay persistence. Legacy `queued_messages` data is preserved, but the new protocol does not replay it.
- `chat_client.py` serves the local UI and reconnects to the relay. It binds only to loopback and checks Host, Origin, and an HttpOnly session cookie. Remote relay addresses require WSS.
- `client_store.py` saves identity keys, credentials, aliases, pinned peer keys, plaintext history, received IDs, and an outbox in `.mesh/PROFILE/`. History and delivery receipts commit together before a relay acknowledgment.
- `index.html` and `app.js` restore client history and show connection/delivery states, aliases, verification, presence, typing, and temporary location sharing. Message text is never inserted as HTML. Location sharing stops when switching contacts and expires after 15 minutes. Radar now uses actual geographic bearing.
- `bc.py` now forwards to the supported client instead of maintaining an incompatible terminal-only cryptographic implementation. `test_client.py` runs isolated tests instead of consuming a real invite and printing credentials.
- `deploy/` contains deployment examples, not a running public deployment.

Comments beside changed behavior explain the reasons and mechanics.

## Important migration notes

The original ID-only client protocol is incompatible. Register fresh profiles with new invitations: old user IDs alone cannot establish ownership. Existing encrypted messages may be unrecoverable because the old client discarded its private key on exit. No old database rows are deleted by this migration.

The newer admin/limits upgrade preserves profiles from the persistent-identity version; simply restart relay and clients. No additional registration is needed for that upgrade.

Open the URL printed by the Python client. Do not double-click `index.html`, run a separate static file server, or use the old `?port=` URL. The client serves the UI and `/ws` on the same port.

The commands below assume macOS/Linux and this project directory. The existing `venv` works; on a new machine create a virtual environment and install `requirements.txt` first.

## 1. Start the relay (terminal 1)

```sh
cd /path/to/ephemeral-mesh
export ADMIN_SECRET="$(./venv/bin/python -c 'import secrets; print(secrets.token_urlsafe(32))')"
./venv/bin/uvicorn main:app --host 127.0.0.1 --port 8000 --workers 1 --ws-max-size 65536
```

Keep the secret for your admin terminal. The relay intentionally refuses to start with a missing/short secret. Stop and restart the relay with Ctrl+C and the same command; the accounts and queue remain on disk. Only one worker is supported.

## 2. Create two invitations (terminal 2)

Set `ADMIN_SECRET` in this terminal to the same value used by the relay: `export ADMIN_SECRET='YOUR_RELAY_ADMIN_SECRET'`. To obtain the generated value, stop the relay briefly in terminal 1, run `printenv ADMIN_SECRET`, copy it locally, then restart the relay. Do not post that secret in a chat or commit it.

Run the following twice; each response has a separate single-use `invite_token`:

```sh
curl --fail -X POST http://127.0.0.1:8000/admin/invites \
  -H "X-Admin-Token: $ADMIN_SECRET"
```

Invitations default to a 24-hour expiration. The relay defaults to at most 10 active accounts; both invitation expiration and server capacity are configurable. See [ADMIN_API.md](ADMIN_API.md).

## 3. Start Alice and Bob (two more terminals)

Replace `ALICE_INVITE` and `BOB_INVITE` with the returned tokens:

```sh
./venv/bin/python chat_client.py --profile alice --port 8081 --token ALICE_INVITE
```

```sh
./venv/bin/python chat_client.py --profile bob --port 8082 --token BOB_INVITE
```

Open <http://127.0.0.1:8081> and <http://127.0.0.1:8082>. Each UI displays its own user ID and fingerprint. On Alice's page, click **+ TARGET** and paste Bob's ID; do the reverse on Bob's page.

On later launches, omit the token:

```sh
./venv/bin/python chat_client.py --profile alice --port 8081
./venv/bin/python chat_client.py --profile bob --port 8082
```

Use a separate terminal for each process. A profile can only run in one process at a time. Preserve `.mesh/` across restarts; deleting a profile discards its credentials, keys, and local history.

## 4. Manual acceptance checks

| Test | Steps | Expected result |
| --- | --- | --- |
| Basic chat | Send a message, then focus the receiving page. | Sender progresses through Pending, Saved by relay, Delivered, Read. Fast transitions may be invisible. |
| Safe rendering | Send `<img src=x onerror=alert('oops')>` and `<b>hello</b>`. | Literal text appears; no alert or rendered tag. |
| Browser refresh | Refresh either page. | Identity, contacts, names, history, and statuses return. |
| Browser closed | Close Bob's page but leave his Python client running; send a message; reopen the page. | Delivered while closed; visible when reopened. |
| Recipient offline | Stop Bob's Python client; send several messages; restart Bob without `--token`. | Each message appears once, then receives a delivery receipt. |
| Relay outage | Stop the relay; send messages; restart the relay. | Client shows offline/pending, reconnects with jittered 1–30 second backoff, then delivers messages. |
| Client restart | Stop Alice's client; restart the same profile. | Same ID and fingerprint, same history, pending outbox resumes. |
| Aliases | Select a contact, click NAME, rename, refresh. | Name persists locally; your friend's naming is unaffected. |
| Key verification | Compare each page's own fingerprint with the other's VERIFY KEYS dialog through a trusted channel. | Matching fingerprints can be marked verified; tabs show a check. |
| Typing/presence | Type without sending; stop typing; stop the other client. | Typing expires within five seconds; presence updates on selection or within about ten seconds. |
| Location | On both pages select each other, enable RADAR, grant browser permission. | Distance, bearing, and last update appear. Switching contacts stops sharing. No new updates appear after stopping; stale information expires after 30 seconds. |
| Coordinate edges | Use browser geolocation overrides at latitude/longitude zero and near opposite sides of Earth. | Zero coordinates work; distance calculation does not crash. |
| Bot | Run local Ollama with `llama3.2:1b`, then send `@bot Say hello`. | Reply follows the durable message path; unavailable Ollama shows an error. |
| Mobile layout | Use browser responsive mode at 320px and 390px widths. | Composer remains usable; long messages wrap. |

Presence refers to the Python client's relay connection, not whether a browser tab is open. Presence and last-seen are visible to authenticated members who know a user ID; per-contact visibility controls are not implemented.

## 5. Automated checks

```sh
./venv/bin/python -m unittest discover -s tests -v
node --check app.js
node --test tests/test_ui.cjs
```

The suite also covers admin authorization, invitation lifecycle, member revocation, additive migrations, concurrent capacity/quota enforcement, and client behavior after rejected sends.

The suite uses temporary directories and random local ports, not your actual profiles or relay database. It covers ID-only authentication rejection, recipient-only queue acknowledgment, redelivery/deduplication, stable keys, pinning, status ownership, zero/invalid coordinates, browser socket isolation, encrypted offline delivery, reconnection, relay restart, malformed ciphertext, connection replacement, and a 120-message offline backlog. The Node tests exercise safe UI rendering, draft preservation, browser reconnect scheduling, and retrying a rejected message with a minimal DOM. Browser visual layout and real geolocation still need the manual checks above.

## Deployment and remaining limits

`deploy/Caddyfile.example` and `deploy/mesh-relay.service.example` are templates for a Linux server. Edit domain, account, and paths before use. Point DNS to the server, make ports 80/443 reachable, run the relay on loopback, and let Caddy expose `/ws`, `/attachments/*` and the joining-instructions root page. Create invitations through SSH on the server. Start remote clients with `--relay wss://YOUR_DOMAIN/ws` from their first registration; profiles are tied to their original relay URL. For the tested Docker package and a step-by-step server runbook, see [DEPLOYMENT.md](DEPLOYMENT.md). See RELEASE_CHECKS.md for the recorded local checks and maintainer-reported VPS testing; each new deployment still needs this rehearsal.

Caddy automatically manages HTTPS for qualifying domain configurations and supports WebSocket upgrades: [automatic HTTPS](https://caddyserver.com/docs/automatic-https), [reverse proxy](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy).

This remains a small single-device-per-account prototype, not an audited secure messenger:

- Keys and local history have restrictive filesystem permissions but are not encrypted at rest. Use device encryption; do not share `.mesh/`. Use the password-encrypted profile backup CLI described in [RECOVERY.md](RECOVERY.md).
- Static ECDH has no forward secrecy or automatic key rotation; recovery restores the existing identity from a backup. First-use keys are trusted until you verify fingerprints independently; the relay is not a substitute for that comparison.
- Updated clients can recover an interrupted first registration using their persisted recovery secret and identity. Losing the whole profile still requires a backup or a new invitation.
- Pending ciphertext has no automatic expiry in this version, avoiding silent delivery loss. Queue quotas and account revocation are implemented. Automatic retention/expiry and tombstone pruning remain future work; logical queue-byte limits are not physical filesystem quotas.
- Presence/typing are metadata. Location is encrypted in transit through the relay, sent only live, and not added to conversation history.
- The UI stays on the computer running the Python client. Mobile layout can be tested in responsive mode; direct phone/LAN access is intentionally blocked by the loopback bridge.

## Recovery, media and invitation links

[RECOVERY.md](RECOVERY.md) covers encrypted backup/restore and manual picture/GIF/voice tests. [DEPLOYMENT.md](DEPLOYMENT.md) covers creating invitation links and joining with `--invite`. Restarts now reuse the relay stored in the profile. All existing clients should be updated before exchanging attachments.
