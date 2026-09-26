# Automated administrator tests on the VPS

Run these as the VPS operator from `/opt/ephemeral-mesh`. The live smoke test uses existing container dependencies and its `ADMIN_SECRET` environment variable. No secret is pasted into the terminal or printed. It always connects to loopback and never follows HTTP redirects.

## Install the test tool (no server restart required)

Copy `admin_smoke.py` into `/opt/ephemeral-mesh` on the VPS. If transferring the small test-kit ZIP instead, extract its two files there. Neither file contains credentials. You do not need to rebuild the image: Python reads the script over standard input.

```sh
cd /opt/ephemeral-mesh
docker compose exec -T relay python - --expiry < admin_smoke.py
```

Allow about 65 seconds. The expiry check deliberately waits for a real 60-second invitation to expire; it never edits the server clock/database. Omit `--expiry` for a faster run. Run only one copy at a time.

Expected output: a series of `PASS` lines, then `CLEANUP ...`, and `RESULT PASS`. The command exits with status 0 on success and nonzero on failure. For a saved report:

```sh
set -o pipefail
docker compose exec -T relay python - --expiry < admin_smoke.py | tee admin-smoke-report.txt
```

`pipefail` keeps a failed test from being hidden by a successful `tee` in Bash. The script prints check names, not credentials or HTTP bodies.

## What is tested

- Valid administrator authentication and sufficient remaining resource capacity.
- Invitation creation, expiry timestamp and paginated listing.
- Registration through one invitation; reuse is rejected.
- Used invitations cannot be revoked as unused invitations.
- Every admin route rejects both missing credentials and ordinary member tokens.
- Member/invitation listings do not expose credential fields or public/private keys.
- Invalid expiry, labels, extra fields and pagination are rejected.
- Unknown invitation IDs return 404.
- Revoking an invitation is idempotent and prevents registration.
- A test account can reconnect, appears online, and is disconnected with code 4003 when revoked.
- Revoked credentials cannot reconnect; repeated revocation is safe.
- With `--expiry`, an actual expired invitation cannot register and is listed as expired.

## Effects on the running relay

This is a live integration test. It needs one free member slot and two invitation-record slots (three with expiry). It creates one disposable account and uniquely labeled invitations. It does not send chat traffic or change server limits. Existing member IDs are never used as revocation targets.

Cleanup runs after success, failures and ordinary Ctrl+C interruption. It revokes this run's account and unused invitations. Audit records are intentionally retained, so test entries remain visible and consume invitation-record capacity. Run it for release checks, not every minute as a health check.

If the server becomes unavailable, the process is forcibly killed, or an API response is lost, cleanup may not complete. When possible, the tool prints `CLEANUP FAILED` and its unique `admin-smoke-...` invitation label. Use `/admin/invites` to find only that exact label; revoke any unused invitations and the `used_by` member of any used invitation. Never delete database rows manually. Do not revoke your real chat accounts to free a slot for testing.

An authorization bug may be discovered after a mutation request; the test uses its own IDs and labels to contain that case. A complete independent security audit is still outside this tool's scope.

## Isolated quota, migration and concurrency checks

The source package already contains `tests/test_admin.py`, which checks capacity, queue quotas, concurrent registration/writes, migrations and persistence across application restarts. Run it in a separate container without the live data volume or live administrator secret:

```sh
cd /opt/ephemeral-mesh
docker run --rm --network none --read-only \
  --tmpfs /tmp:rw,size=128m \
  --cap-drop ALL --security-opt no-new-privileges:true \
  -v "$PWD:/checks:ro" -w /checks \
  "$(docker compose images -q relay)" \
  python -m unittest discover -s tests -p test_admin.py -v
```

The tests create temporary databases and dummy secrets. They do not change the running relay or mount its `/data` volume. Expect 15 passing tests. The image must already have been built; the command uses the current deployment's image. Do not run quota tests by lowering the real server's limits or filling real users' queues.

## Checks this does not replace

The live command intentionally does not restart the VPS/relay, exhaust live quotas, or revoke existing users. It also does not verify public Caddy/TLS/firewall boundaries. Check those from another computer:

```sh
curl -i https://YOUR_DOMAIN/admin/members
curl -i https://YOUR_DOMAIN/healthz
```

Both should return 404. The separate container tests simulate app restarts but do not prove the production volume survives an actual VPS restart. Keep the manual restart/backup tests in `DEPLOYMENT.md` as part of the server rehearsal.
