# START HERE — Hostinger VPS, Debian 12

This handoff runs the relay on a Debian 12 VPS with 1–2 CPU cores and 4 GB RAM. That is a reasonable starting size for a small-group test; actual capacity still needs testing. Docker runs the packaged Python version, so you do not need to replace Debian's system Python. Use one relay worker.

The archive contains application source, Docker/Caddy configuration, tests and documentation. It contains no existing client profiles, keys, databases, invitations or administrator secret. Generate a new server secret below. The included `.env.example` is only a template.

The VPS hosts the relay, not the private chat UI. Each participant runs the Python client on their own computer. The public root page gives joining instructions; it is not the chat window.

## 1. Before starting

- Have SSH/root or sudo access to the VPS and access to Hostinger's firewall controls.
- Choose a hostname, for example `chat.example.com`, and point its DNS A record at the VPS public IPv4 address. A free DNS subdomain can also work. Only publish an AAAA record if IPv6 is configured correctly.
- This guide assumes a fresh VPS and free ports 80/443. If another website/proxy already owns them, integrate the supplied Caddy routes with that proxy instead of stopping an unrelated service.
- In Hostinger's managed firewall, allow your actual SSH TCP port (normally 22), TCP 80 and TCP 443. UDP 443 is optional. Preserve SSH access before applying rules. Keep TCP 8000, 8081 and 8082 closed to the public. Apply equivalent rules to any existing OS firewall. Docker-published ports can bypass UFW rules; keep the Compose loopback binding unchanged.

Provider reference: [Hostinger managed firewall](https://www.hostinger.com/support/8172641-how-to-use-a-managed-vps-firewall-at-hostinger/).

## 2. Copy the ZIP to the VPS

From a committed local Git checkout, create a source-only ZIP (Git ignores private local files):

```sh
mkdir -p dist
git archive --format=zip --prefix=ephemeral-mesh/ --output=dist/ephemeral-mesh-source.zip HEAD
```

Run the following from that `dist` folder; substitute the actual SSH account and address:

```sh
scp ephemeral-mesh-source.zip YOUR_SSH_USER@VPS_IP:/tmp/
ssh YOUR_SSH_USER@VPS_IP
```

For a nonstandard SSH port use `scp -P PORT` and `ssh -p PORT`.

The remaining SERVER commands assume a root shell. If logged in as a sudo user, enter `sudo -i` first. Do not run these installation commands on your personal Mac.

## 3. Install Docker Engine and extract the project

If `docker version` and `docker compose version` already work, skip Docker installation and just install `unzip`, `python3`, `curl` and `nano` if needed. For a fresh Debian 12 installation:

```sh
apt-get update
apt-get install -y ca-certificates curl unzip python3 nano
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc

# Use Docker's Debian 12 repository; do not change the system Python.
cat > /etc/apt/sources.list.d/docker.sources <<EOF_DOCKER
Types: deb
URIs: https://download.docker.com/linux/debian
Suites: bookworm
Components: stable
Architectures: $(dpkg --print-architecture)
Signed-By: /etc/apt/keyrings/docker.asc
EOF_DOCKER

apt-get update
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
systemctl enable --now docker
docker version
docker compose version
```

If existing Docker/container packages conflict, follow the [official Docker Debian installation guide](https://docs.docker.com/engine/install/debian/) before replacing them; the commands above target a fresh server.

For the first installation only, extract into a new `/opt/ephemeral-mesh` directory:

```sh
unzip -n /tmp/ephemeral-mesh-source.zip -d /opt
cd /opt/ephemeral-mesh
```

Do not use this first-install procedure to merge files into an existing deployment; follow the backup/upgrade instructions in `DEPLOYMENT.md` instead.

## 4. Create the server's configuration

Run from `/opt/ephemeral-mesh`:

```sh
python3 - <<'PY'
import os
import secrets
from pathlib import Path
# Create a fresh secret on this server; refuse to overwrite an existing configuration.
text = Path('.env.example').read_text().replace(
    'ADMIN_SECRET=REPLACE_ME', 'ADMIN_SECRET=' + secrets.token_urlsafe(32))
fd = os.open('.env', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, 'w') as stream:
    stream.write(text)
PY
nano .env
```

Change **only** `MESH_DOMAIN=chat.example.com` to your actual DNS hostname initially. Use a hostname without `https://`, a path or a port. Keep the generated `ADMIN_SECRET` private and keep the default resource limits for the first test. Compose uses `/data/relay.db` in a persistent Docker volume regardless of the template's `MESH_DB` line.

No private keys or credentials from either participant should be copied onto the VPS.

## 5. Start and check the relay

```sh
cd /opt/ephemeral-mesh
docker compose --profile public config --quiet
docker compose --profile public up -d --build
docker compose ps
docker compose logs --tail 50 relay caddy
curl --fail http://127.0.0.1:8000/healthz
```

The first build downloads images/packages and can take several minutes. The relay should become `healthy`; the health endpoint should return `{"status":"ok"}`. Caddy obtains the HTTPS certificate once DNS and port access work. No Docker Hub account is normally needed to pull these public images.

From a DIFFERENT computer, replace `YOUR_DOMAIN` below:

```sh
curl -I https://YOUR_DOMAIN/
curl -i https://YOUR_DOMAIN/admin/members
curl -i https://YOUR_DOMAIN/healthz
```

Expected results: valid TLS and HTTP 200 at `/`, HTTP 404 for both other paths. Do not disable TLS certificate verification. Public port 8000 should not accept connections. On the VPS, `curl -i http://127.0.0.1:8000/admin/members` should return 401 without an administrator header.

## 6. The host creates two invitations

Run on the VPS, replacing `YOUR_DOMAIN`:

```sh
docker compose exec relay python invite.py --relay wss://YOUR_DOMAIN/ws --label Friend-A --expires-in 86400
docker compose exec relay python invite.py --relay wss://YOUR_DOMAIN/ws --label Friend-B --expires-in 86400
```

Each command prints a different single-use link valid for 24 hours. Send each privately to its intended participant. Share the links, never `.env` or the admin secret. The host needs their own invitation and local client if they also want to chat.

To inspect usage without printing/exporting the secret, run on the VPS:

```sh
docker compose exec -T relay python - <<'PY'
import json, os, urllib.request
request = urllib.request.Request('http://127.0.0.1:8000/admin/limits',
    headers={'X-Admin-Token': os.environ['ADMIN_SECRET']})
with urllib.request.urlopen(request, timeout=10) as response:
    print(json.dumps(json.load(response), indent=2))
PY
```

Other membership/admin commands are documented in `ADMIN_API.md`.

## 7. Each person starts a LOCAL client

On your own macOS/Linux computer, extract this same ZIP into a folder you control. Install Python 3.14 if not already available. The client uses Unix profile locks; native Windows is not supported by this release.

From the extracted `ephemeral-mesh` folder:

```sh
python3.14 -m venv venv
./venv/bin/python -m pip install -r requirements.txt
./venv/bin/python chat_client.py --profile cloud-test --port 8081 --invite
```

If your Python 3.14 installation is named `python3` instead, use that executable after checking `python3 --version`. Paste the entire invitation link at the hidden prompt (pasted characters do not appear), press Enter, then open `http://127.0.0.1:8081`.

If you already have a working local virtual environment, keep using it. Use a NEW profile name for this VPS: existing localhost profiles belong to their original relay and cannot be reused with the new server.

Exchange the displayed user IDs, click **+ TARGET**, and add each other. Compare the fingerprints through another trusted channel before marking them verified. A hosted invitation grants membership; it does not prove the other person's identity.

On later launches:

```sh
./venv/bin/python chat_client.py --profile cloud-test --port 8081
```

No new invitation or relay URL is needed. If two clients run on the SAME computer, choose distinct profile names and ports such as 8081/8082. On different computers both can use 8081. Do not double-click `index.html` or forward these local UI ports publicly.

## 8. Test together

- Send text in both directions; confirm Delivered and Read status.
- Send PNG/JPEG, a GIF and a voice note (raw files up to 5 MiB). Record, preview, cancel and record again; check audio playback on the other computer.
- Refresh both browser pages; verify contacts, history, images and audio remain available. Turn on radar and ensure contacts/radar stay visible while scrolling a long chat.
- Stop one person's Python client, send text and a photo, then restart that same profile. Expect one copy of each queued message.
- On the VPS run `docker compose restart relay`. Both clients should reconnect automatically with their saved identities. Test a send while it restarts.
- Restart both local clients without invitations. Confirm the same IDs/fingerprints and history.
- Check profile backup/restore with disposable profiles using `RECOVERY.md`. Test member revocation on an extra disposable account using `ADMIN_API.md`.

Record the action, expected result, actual result and approximate time for any failure. Share redacted logs/screenshots, not invitation tokens, auth headers, `.env`, `.mesh/`, or packet captures containing credentials.

## 9. Stop, restart and preserve data

Run from `/opt/ephemeral-mesh`:

```sh
# Stop both services for a break; persistent volumes remain.
docker compose --profile public stop
# Start the same services again.
docker compose --profile public up -d
# Inspect bounded logs and resource use.
docker compose logs --tail 100 relay caddy
docker compose stats --no-stream
```

Never use `docker compose down -v` or delete Docker volumes if you want to retain accounts/queues/certificates. Keep using the same project directory/name so Compose selects the same volumes. See `DEPLOYMENT.md` for a consistent server backup and update procedure. Back up the newly generated `.env` separately and securely.

The relay is capped at one CPU and 512 MiB RAM in Compose; Caddy at 256 MiB. These are runtime limits, not bounds on Docker build memory or the whole VPS. Disk/WAL growth still needs monitoring. Hosting charges are governed by your Hostinger plan; application quotas do not cap provider billing.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| Certificate/HTTPS fails | DNS A/AAAA, TCP 80/443, Caddy logs, and whether another service owns those ports. Allow time for DNS propagation. |
| `Address already in use` | Inspect `ss -lntp`; resolve the existing service conflict rather than exposing the relay admin port. |
| Relay unhealthy | Inspect relay logs, disk space (`df -h`), and the secret in `.env` locally. Do not paste the secret into a support chat. |
| Hostname says Not found at `/admin/...` | Expected from the Internet. Administration is local/SSH only. |
| Browser opens instructions, not chat | Expected at the public domain. Run the local Python client and open its printed localhost URL. |
| Profile belongs to a different relay | Pick a fresh profile name for the new VPS. Do not delete your old history. |
| Invitation expired/used | Host issues a new link for a fresh profile. Restart a successfully registered profile without a link. |
| Voice recording unavailable | Check browser microphone permissions and use the locally served UI; see `RECOVERY.md`. |

Creating a source archive does not deploy anything to Hostinger or certify the remote network. `SECURITY.md` describes the remaining application limitations. Start with disposable test data.
