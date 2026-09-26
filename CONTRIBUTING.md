# Contributing

Use Python 3.14 on macOS or Linux and Node.js 24 for UI checks. Docker Engine/Desktop with Compose is needed for the deployment smoke test. Native Windows profile locking is not supported.

```sh
python3.14 -m venv venv
./venv/bin/python -m pip install -r requirements.txt
./venv/bin/python -m unittest discover -s tests -v
node --check app.js
node --test tests/test_ui.cjs
```

For relay or deployment changes:

```sh
docker build -t ephemeral-mesh:local-test .
./venv/bin/python tests/docker_smoke.py
```

Tests create temporary profiles/databases. The Docker test creates and removes its own randomly named network, volume and containers. Never point tests at your live relay database. The live administrator smoke test is separate: read `ADMIN_TESTING.md` before using it on a deployed instance.

Keep changes focused, explain why behavior changes in nearby comments, and add regression coverage for actual bugs or new behavior. Document protocol/schema changes and how an existing deployment upgrades. Retain one-worker operation unless connection routing is redesigned. Security-sensitive changes include account authentication, identity pinning, invite recovery, acknowledgment ordering, file permissions, CORS/Origin handling and cryptographic envelopes.

Before committing:

```sh
git diff --cached
python3 scripts/check_public_files.py
```

The publication guard inspects Git's staged blobs for private artifact paths and common credential markers; it is not a complete secret scanner. Never submit `.env`, `.mesh/`, database files, private keys, profile backups or packet captures. Use synthetic examples and redact logs/screenshots. If a credential was ever committed, removing the current file does not remove it from history: revoke/rotate it and clean the history before publishing.

A pull request should explain the problem, resulting behavior, checks performed, and any migration or compatibility effects. For suspected vulnerabilities, follow `SECURITY.md` rather than posting exploit details or live credentials in public issues.
