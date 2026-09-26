# Profile recovery and media testing

## Interrupted registration

Before its first connection, the client saves the invite and a separate random recovery secret beside its persistent identity. If the server creates the account but its reply is lost, restarting the **same profile** recovers the same account and credential. A used invite alone cannot recover the account. The server stores only a hash of the recovery secret, and the client removes the bootstrap secrets after saving the account credential.

Do not delete a pending profile to fix a network failure. This recovery mechanism applies to registrations initiated by the updated client/server. Losing an older profile or all copies of a profile still requires a new invitation and identity.

## Encrypted backups

Stop the Python client first. From the project directory:

```sh
./venv/bin/python profile_backup.py export --profile alice --file alice.embackup
./venv/bin/python profile_backup.py restore --profile alice-restored --file alice.embackup
./venv/bin/python chat_client.py --profile alice-restored --port 8083
```

Use a strong, unique password of at least 12 characters when prompted; keep it separately. Backups include the private identity, account credential, contacts, verification state, plaintext history, cached media and pending outbox. Export snapshots SQLite consistently, derives a key with salted scrypt, and encrypts/authenticates the result with AES-GCM. Export refuses an existing output file; restore refuses an existing profile directory. The snapshot limit is 128 MiB. Larger local histories require a stopped-client filesystem backup kept on encrypted storage.

Run only one copy of the restored identity. Starting both the original and restored profile causes their relay sessions to replace each other. A stale backup cannot recover messages already acknowledged and removed from the relay after that backup. Restoring also cannot reverse administrator revocation. Neither the relay operator nor this application can recover a forgotten backup password.

Test with disposable profiles: wrong password and modified backup should fail without creating a profile; correct restore should show the same ID, fingerprint and history. Keep the old profile until the restored copy is verified.

## Pictures, GIFs, and voice notes

1. Select a contact and choose **PICTURE / GIF**. Send PNG, JPEG, GIF or WebP up to 5 MiB. The local progress indicator measures saving to the Python client; message status tracks subsequent encrypted relay delivery.
2. Stop the recipient's Python client, send a picture, then restart it. Check the image appears once and sender status becomes Delivered. Refresh/restart both clients to verify cached media persists.
3. Choose **VOICE**, allow the microphone, speak, and choose **STOP**. Preview, then **SEND**, or **CANCEL**. Recording stops after two minutes or at the size limit. The recipient is captured when recording starts and displayed beside the draft.
4. Deny microphone access, cancel a recording, and try again. Check the browser's microphone indicator turns off. Real microphone/browser compatibility needs manual testing; automated tests cover cancellation-state races.
5. Stop the relay while sending. The file stays locally pending and retries after reconnect. A failed local save retains a voice preview for retry.
6. Try a file over 5 MiB or renamed HTML/SVG. Expect rejection. Content signatures and MIME allowlists reduce unsafe embedding; they are not a malware scanner or full decoder validation.

Voice formats depend on browser support (WebM/Opus, Ogg/Opus or MP4). GIFs are uploaded files, not a third-party GIF-search integration. Uploads retry as whole bounded files; chunked resumable transfer is not implemented. Cached files and local history currently have no automatic retention policy.

The relay stores encrypted bytes and participant/size/timing metadata. Unreferenced uploads expire after 24 hours and a cleanup loop releases their ciphertext. Once linked to a pending message, a file stays available for offline delivery until recipient acknowledgment or member revocation. Those actions logically clear the blob; SQLite pages, WAL and backups may still contain old ciphertext. Delivery and attachment tombstones remain for idempotency and count toward record limits.
