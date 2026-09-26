# Real-server test runbook

Use a Linux server with Docker Engine and the Compose plugin, a domain you control, and DNS A/AAAA records pointing to that server. Remove an incorrect AAAA record if the server has no working IPv6. Allow inbound TCP 80/443 (UDP 443 is optional for HTTP/3) and your SSH port. Keep 8000 private. This package runs one relay worker for a small group; it is not a production scale/performance certification.

## Configure and start

Copy the project source to its own directory on the server, excluding `.mesh/`, `.env`, local databases, backups and `venv/`. From that directory, create a new secret file without overwriting an existing one:

```sh
python3 - <<'PY'
import os, secrets
from pathlib import Path
text = Path('.env.example').read_text().replace('ADMIN_SECRET=REPLACE_ME', 'ADMIN_SECRET=' + secrets.token_urlsafe(32))
fd = os.open('.env', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, 'w') as stream:
    stream.write(text)
PY
```

Edit `.env` and replace `MESH_DOMAIN=chat.example.com` with your actual hostname. Keep the generated administrator secret private. Compose reads this file; you do not need to print/export the secret. `MESH_DB` is overridden to `/data/relay.db` inside the container. Review the membership and storage limits before increasing them.

```sh
docker compose --profile public config --quiet
docker compose --profile public up -d --build
docker compose ps
docker compose logs --tail 50 relay caddy
curl --fail http://127.0.0.1:8000/healthz
```

The relay should be healthy. Caddy obtains a certificate for the configured domain; DNS and externally reachable ports are required. Its configuration exposes `/`, `/ws` and `/attachments/*`. The root page only gives joining instructions. Admin endpoints, API docs and health checks are not exposed by Caddy. See [Caddy automatic HTTPS](https://caddyserver.com/docs/automatic-https) and [release notes for the configured Caddy version](https://github.com/caddyserver/caddy/releases/tag/v2.11.4).

From a different computer, verify:

```sh
curl -I https://YOUR_DOMAIN/
curl -i https://YOUR_DOMAIN/admin/members
curl -i https://YOUR_DOMAIN/healthz
```

Expect valid HTTPS and HTTP 200 for `/`; expect HTTP 404 for the other two paths. Do not bypass certificate validation with `-k`. The local admin API itself must return 401 without the admin header. If certificate issuance fails, inspect Caddy logs and DNS/firewall before inviting anyone.

For loopback-only container testing without a domain, use `docker compose up -d --build relay` and `ws://127.0.0.1:8000/ws` instead. Do not change the host binding to `0.0.0.0` to make the admin API public.

## Invite friends

On the relay server:

```sh
docker compose exec relay python invite.py --relay wss://YOUR_DOMAIN/ws --label Alex --expires-in 86400
```

This prints one single-use invitation link; share it privately with the intended friend. The token is in the URL fragment, which browsers do not send to the relay. A link is still a bearer invitation: anyone who obtains it before use can join. A host-generated link is not a cryptographic proof of the sender's real-world identity.

Your friend installs the project and Python dependencies on their own macOS/Linux computer, then runs:

```sh
./venv/bin/python chat_client.py --profile me --invite
```

They paste the full link at the hidden prompt and open the printed local browser URL. Later they run the same command without `--invite`. You each share your displayed user ID, add the other as a contact, and compare fingerprints through a trusted channel. Do not expose the local Python UI to the Internet. This release is not a browser-only/phone client or an installed custom-URL-handler application.

For other admin operations, see [ADMIN_API.md](ADMIN_API.md). Run those commands on the server or through an SSH tunnel; administrator credentials must not be sent to the public relay URL.

## Acceptance test before regular use

Use two disposable profiles on different computers/networks:

1. Register through two distinct links. Reusing a link from a new profile must fail. Restart clients and confirm stable IDs/fingerprints.
2. Exchange text, a picture/GIF and a voice note. Check microphone preview/cancel, rendered media, Delivered/Read status, and refresh persistence.
3. Stop one Python client, send several messages plus an image, then restart it. Check one copy of each arrives.
4. Run `docker compose restart relay` while a send is pending. Confirm automatic reconnection and eventual delivery without creating new accounts.
5. Revoke a disposable member. Confirm the active connection closes and restart cannot authenticate. Confirm other members still communicate.
6. Export a stopped client's backup, restore into a new profile, then run only that copy. Check ID, history and media. See [RECOVERY.md](RECOVERY.md).
7. Confirm public admin/health paths remain 404, check disk usage and `/admin/limits`, and save relevant logs without credentials or message content.

Actual Internet TLS, mobile-browser microphone behavior and your server's performance must be verified here. The local automated tests cannot certify those properties.

## Persistence, backup and upgrades

`relay-data` contains account credentials (hashed), invitations, encrypted queues/files and tombstones. `caddy-data` preserves certificates. Never run `docker compose down -v` on a server whose state you want to retain. Losing relay account data requires users to register again even if they retain local profiles.

Create a consistent backup by stopping only the relay briefly, copying the **whole** data directory (including any SQLite sidecars), and restarting it:

```sh
umask 077
backup_dir="backups/relay-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$backup_dir"
docker compose stop relay
docker compose cp relay:/data/. "$backup_dir/"
docker compose start relay
```

Keep `.env` in a separate secure backup. Store backups off the server on encrypted storage, and verify restoration into a disposable deployment. For restoration, stop the destination relay, preserve its current data first, copy the complete saved data directory back into `/data`, and restore ownership to UID/GID `10001:10001` before starting. Do not merge database files from different snapshots. Restoring old server state can resurrect old pending ciphertext or revert a revocation; recheck membership afterward. Relay backups cannot decrypt or recreate recipients' local chat history.

Before an upgrade, back up state, record the current image ID (`docker compose images`), and run the regression suite on the candidate source. Then:

```sh
docker compose --profile public build --pull relay
docker compose --profile public pull caddy
docker compose --profile public up -d
docker compose ps
```

Check health and run a two-client send/reconnect smoke test. Rollback requires the old image/source and, if schemas are incompatible, its corresponding data backup; do not assume arbitrary schema downgrades work. Migrations in this update are additive, but old clients do not support new media frames, so update clients together.

## Operating limits

Inspect `docker compose stats`, bounded container logs, filesystem space and `/admin/limits`. Logical attachment/queue quotas do not cap SQLite physical pages/WAL/backup size. Unreferenced files expire after 24 hours; linked offline files remain until acknowledgment/revocation. Tombstones have explicit record caps and no automatic pruning. Reaching those caps requires operator intervention; deleting deduplication rows manually can reintroduce duplicates.

The Compose relay has a 512 MiB memory cap, one CPU and 128 processes. These are starting resource bounds, not measured capacity promises. Container restart policies restart exited processes; an `unhealthy` status alone does not restart a process. Investigate persistent unhealthy status and disk exhaustion. Keep dependencies/base images patched. See [SECURITY.md](SECURITY.md) for the remaining security limits.
