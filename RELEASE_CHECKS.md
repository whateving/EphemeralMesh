# Release checks — 2026-09-26

Verified locally on macOS with Python 3.14 and Docker Desktop (Linux ARM64 containers):

| Check | Result |
| --- | --- |
| Python regression suite | 45 passed, including live localhost relay/client tests and admin-smoke cleanup on success and failure |
| JavaScript UI tests and syntax | 6 passed; rendering safety, draft/retry behavior, media preview construction and late microphone callback isolation; syntax check passed |
| Docker image build | Passed with Python 3.14.7 slim base |
| Disposable relay/Caddy smoke test | Passed: non-root runtime, durable restart, admin authentication, Caddy configuration, private admin/health paths, attachment routing and WebSocket upgrade |
| Publication guard | Source publication checks passed; disposable fixtures confirmed private-artifact detection, staged-content inspection and redacted output |
| Python dependency advisories | pip-audit 2.10.1 reported no known vulnerabilities for requirements.txt and its resolved dependencies |

Additional checks previously completed during this release preparation:

- Compose configuration validated using a temporary secret file.
- Isolated container admin regression suite: 15 tests passed.
- Admin acceptance script with real invitation expiry: all nine groups passed against a disposable local relay.
- Browser layout with 100 messages at four viewport sizes: contacts and radar remained accessible.

Tests used temporary profiles/databases and randomly named Docker resources. The Docker test removed its own containers/network/volume. Existing personal profiles, relay databases, public DNS, certificates and the VPS deployment were not modified by these local checks. A local test image remains available as `ephemeral-mesh:local-test`.

FastAPI's TestClient emits an httpx deprecation warning, and Caddy reports a configuration-formatting warning; both test suites pass. Dependency auditing is not an application penetration test or a container operating-system scan.

## VPS acceptance

The maintainer reports that their VPS acceptance tests passed, including messages, pictures and voice notes. This is a manual report, not an independently recorded remote test run. It does not establish load capacity, support for every browser, certificate renewal over time, or recovery from every failure mode.

Each new deployment should follow [DEPLOYMENT.md](DEPLOYMENT.md), [TESTING.md](TESTING.md) and [ADMIN_TESTING.md](ADMIN_TESTING.md). Rehearse backups/restores and check firewall boundaries, TLS, separate-network clients, microphone/geolocation permissions and restart behavior for that environment.

## Publication

The project includes an MIT license, a Git-index publication guard and GitHub Actions configuration. Run `python3 scripts/check_public_files.py` after staging and review `git diff --cached` before committing. The guard checks common private file types and credential markers; it is not an exhaustive secret scanner or a Git-history audit.

GitHub Actions has not run for this unpublished repository. Check its first run after following [PUBLISHING.md](PUBLISHING.md).
