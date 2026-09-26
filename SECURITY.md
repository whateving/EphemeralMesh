# Security model and limits

This is a small-group portfolio application, not an audited replacement for an established secure messenger.

## What is protected

- Remote clients require TLS and retain a stable P-384 identity. Account IDs are public identifiers; high-entropy bearer credentials authenticate reconnects.
- Invitations are single-use and expire. Registration recovery additionally requires the original recovery secret and public key. Administrator access is separate and kept behind loopback/SSH.
- Message content and file descriptors are Fernet-encrypted under an ECDH/HKDF-derived peer key. Routing identities and message IDs are bound inside authenticated ciphertext. Each file receives its own random Fernet key, sent inside that envelope.
- Received content is authenticated and saved locally before acknowledgment. Server-side queues/attachments enforce transactional quotas and recipient ownership.
- The local UI checks Host, an HttpOnly SameSite cookie, and Origin for mutations/WebSockets. It renders text as text, serves a fixed file allowlist, and exposes neither keys nor bearer tokens in UI snapshots.
- Docker copies an explicit source allowlist, uses an unprivileged relay user/read-only root filesystem, and publishes the administration port only on loopback.

## What is not protected

- Compromised endpoints, malicious browser extensions, or access to the local OS account can expose keys and plaintext. Use device encryption and protect backups. Running profiles are not password-encrypted at rest.
- Static ECDH lacks forward secrecy and post-compromise security. A future compromise of an identity key can expose previously recorded traffic. There is no multi-device synchronization or automatic identity rotation.
- First-use peer keys are trusted until fingerprints are compared through another trusted channel. A malicious relay can substitute keys before that verification; invitations and domain names do not prove a friend's personal identity.
- Relay administrators can observe membership, peer public keys, routing, presence, approximate content sizes and timing, and can drop or delay traffic. They cannot recover properly encrypted message content without keys. Local bot prompts are sent to the user's configured local Ollama service.
- Metadata/storage record caps and upload/frame bounds help constrain abuse, but there is no comprehensive Internet-scale DDoS defense, per-IP connection admission policy, spam moderation or external penetration test.
- Revocation prevents future relay access and clears pending payloads. It cannot erase local copies, traffic already in flight, physical SQLite pages or backups. Sender histories can retain “Saved by relay” for deliveries later cancelled by revocation; cancellation receipts are not implemented.
- Bad ciphertext is not acknowledged. Deliberately invalid queued messages can occupy quota until member revocation; no quarantine admin UI exists.
- Dependency auditing checks published advisories for resolved Python packages. A clean result is not proof the application or container OS is vulnerability-free. Rebuild, patch and rerun checks regularly.

## Before sharing source

Exclude secrets, profiles, databases, backups and local runtime directories. `.gitignore` and `.dockerignore` help, but review the files you actually stage and run `python3 scripts/check_public_files.py`. This limited guard checks Git's index; it cannot guarantee the absence of secrets or inspect prior commits. The project is released under the MIT License.

## Reporting vulnerabilities

Use the repository's Security → Report a vulnerability option if the owner has enabled private vulnerability reporting. If no private channel is available, open an issue requesting a private contact channel without including exploit details, credentials or personal data. Do not submit live keys, profiles, backups or packet captures in public issues.
