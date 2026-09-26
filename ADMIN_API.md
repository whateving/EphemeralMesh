# Admin API and server limits

This stage adds administrator control to the existing Python-client relay. There is no browser admin dashboard; `invite.py` creates invitation links for the Python client (see [DEPLOYMENT.md](DEPLOYMENT.md)). Run one relay worker; membership and active WebSocket routing are coordinated in that process.

## Authentication and migration

All endpoints below require `X-Admin-Token: $ADMIN_SECRET`. Member auth tokens do not grant administrator access. Keep the admin API on loopback, accessed locally or through SSH; the Caddy examples expose only the joining page and member messaging/attachment routes.

Restart the relay **and local clients** after updating. Schema upgrades run automatically and preserve existing account credentials, unused invitation tokens, message queues, and client history. Unlike the earlier ID-only-protocol migration, this stage does **not** require new registration. Existing creation timestamps that were never recorded are shown as `null`. Invitations used by the older server were deleted, so their historical use cannot be reconstructed.

The examples assume the relay is running at `http://127.0.0.1:8000` and this terminal has the same `ADMIN_SECRET` environment variable as the relay. See [TESTING.md](TESTING.md) for startup instructions.

## Create and inspect invitations

Create a labeled, single-use invitation valid for one hour:

```sh
curl --fail-with-body -X POST http://127.0.0.1:8000/admin/invites \
  -H "X-Admin-Token: $ADMIN_SECRET" \
  -H 'Content-Type: application/json' \
  -d '{"label":"For Alex","expires_in":3600}'
```

The response includes `invite_token`, `invite_id`, `label`, `created_at`, `expires_at`, `expires_in`, and `status`. Copy the token now: it is returned **only at creation**. List responses contain neither raw tokens nor token hashes.

The optional label is at most 80 characters and visible only to the admin. It does not prove who redeems the invitation. Expiration must be an integer between 60 seconds and 604800 seconds (seven days). Omitting the body creates an unlabeled invitation valid for 24 hours. The older `POST /admin/invite` endpoint remains an alias.

```sh
curl --fail-with-body 'http://127.0.0.1:8000/admin/invites?limit=100&offset=0' \
  -H "X-Admin-Token: $ADMIN_SECRET"
```

Each invitation has one of four statuses:

| Status | Meaning |
| --- | --- |
| `pending` | May be redeemed before expiration if member capacity allows |
| `used` | Redeemed once; `used_at` and `used_by` identify the registration |
| `expired` | No longer valid because its deadline passed |
| `revoked` | Disabled by the administrator before use |

Rows are returned newest first. Pagination supports `limit=1..200` and `offset>=0`. Times are Unix seconds.

Replace `INVITE_ID` with the ID from creation/listing to revoke an unused invitation:

```sh
curl --fail-with-body -X DELETE http://127.0.0.1:8000/admin/invites/INVITE_ID \
  -H "X-Admin-Token: $ADMIN_SECRET"
```

Repeating revocation returns the same revoked record. Revoking a used invitation returns HTTP 409: remove the member instead. Unknown IDs return 404; malformed IDs return 422. Records are retained for audit rather than deleted.

## Inspect and revoke members

```sh
curl --fail-with-body 'http://127.0.0.1:8000/admin/members?limit=100&offset=0' \
  -H "X-Admin-Token: $ADMIN_SECRET"
```

Members include `user_id`, `created_at`, `last_seen`, `revoked_at`, `status` (`active` or `revoked`), and `online`. Credentials and public/private key material are not included. The same pagination bounds apply.

Replace `USER_ID` with a **disposable test member** when trying revocation:

```sh
curl --fail-with-body -X DELETE http://127.0.0.1:8000/admin/members/USER_ID \
  -H "X-Admin-Token: $ADMIN_SECRET"
```

Revocation:

- Persists across relay restarts and prevents future authentication.
- Detaches the active connection immediately and closes it with code 4003. The client shows the reason and stops reconnecting.
- Cancels pending deliveries **to and from** that account, clearing ciphertext while retaining delivery-ID tombstones. The response reports `cancelled_deliveries`.
- Also clears encrypted attachment blobs to/from that account while retaining their ID metadata.
- Frees an active-member slot. The member record stays in the admin list.
- Cannot erase messages already received locally. Frames sent before revocation may already be in transit.

Repeated revocation is safe and returns zero newly cancelled deliveries. There is no restore endpoint in this stage; rejoining requires a new invitation and a new client profile. Other senders' previously accepted messages cancelled by revocation can remain marked "Saved by relay" in their local histories; cancellation receipts are not implemented yet.

## Inspect usage and configure limits

```sh
curl --fail-with-body http://127.0.0.1:8000/admin/limits \
  -H "X-Admin-Token: $ADMIN_SECRET"
```

The response contains the effective `limits` and current `usage` (active members, invitation records, delivery records, queued messages, queued bytes, attachment records, and encrypted attachment bytes).

Set environment variables **before starting the relay**, or use the service's `EnvironmentFile`. `.env.example` documents the variables; the Python program does not automatically load `.env` files. Changes require a relay restart.

| Environment variable | Default | What is limited |
| --- | ---: | --- |
| `MESH_MAX_MEMBERS` | 10 | Active, non-revoked accounts; not connections |
| `MESH_MAX_MESSAGE_BYTES` | 48000 | UTF-8 bytes of the encrypted message body; maximum allowed is 48000 |
| `MESH_MAX_QUEUED_PER_RECIPIENT` | 1000 | Unacknowledged durable envelopes for one recipient |
| `MESH_MAX_QUEUED_MESSAGES` | 10000 | Unacknowledged durable envelopes across the relay |
| `MESH_MAX_QUEUED_BYTES` | 67108864 | Serialized UTF-8 envelope bytes across pending deliveries (64 MiB) |
| `MESH_MAX_DELIVERY_RECORDS` | 100000 | Pending deliveries plus acknowledged/cancelled ID tombstones |
| `MESH_MAX_INVITE_RECORDS` | 10000 | All invitation records, including used/revoked/expired records |
| `MESH_MAX_ATTACHMENT_BYTES` | 8388608 | Encrypted file size; protocol ceiling 8 MiB, raw client file limit 5 MiB |
| `MESH_MAX_ATTACHMENT_TOTAL_BYTES` | 134217728 | Pending encrypted files across the relay (128 MiB) |
| `MESH_MAX_ATTACHMENT_RECORDS` | 10000 | All file IDs, including tombstones |
| `MESH_MAX_ATTACHMENTS_PER_SENDER` | 32 | Files with retained ciphertext per sender |
| `MESH_MAX_FRAMES_PER_SECOND` | 100 | Frames received per authenticated connection in a one-second window |

All values must be positive integers; invalid configuration stops startup. The transport/frame ceiling remains 65536 bytes and the initial authentication frame ceiling is 4096 bytes. Use the documented `--ws-max-size 65536` Uvicorn option to enforce the transport bound before application parsing.

**Quota semantics:**

- Registration checks capacity and consumes the invitation atomically. A capacity rejection leaves the invitation usable.
- Queue checks and insertion are one transaction. Simultaneous senders cannot oversubscribe the configured quota.
- Existing message IDs do not consume additional space when retried, even when the queue is full.
- Recipient ACKs release pending payload count/bytes. They do not remove the ID tombstone.
- Encrypted delivery/read receipts also count toward queue limits. Typing/location events are live-only and do not consume durable queue space.
- Reducing a limit below current usage does not delete old messages. New insertions are rejected until usage falls or the operator raises the limit.
- Byte usage is logical queued data, not the physical SQLite file size. SQLite overhead, WAL files, historical database pages, accounts, and audit metadata are not included. Filesystem/disk monitoring is still needed.
- Record ceilings do not automatically prune history. When reached, the admin must increase the ceiling and restart, or wait for a future supported retention/maintenance flow; manually deleting tombstones can break deduplication.

## Client errors and retries

Policy errors carry a stable `code`, readable `text`, and `retryable` flag. WebSocket send failures include the affected `message_id` and `recipient_id`; temporary queue limits also include `retry_after: 30`. HTTP policy failures return these fields inside `detail`.

| Code | Expected action |
| --- | --- |
| `invalid_invite` | Obtain a new valid invitation |
| `member_capacity_reached` | Admin frees a slot or raises capacity; existing invitation remains usable |
| `recipient_unavailable` | Check the user ID or membership; send is not automatically retried |
| `message_too_large` | Shorten the message or ask the admin about the configured limit |
| `recipient_queue_full` / `server_queue_full` | Client saves the message locally and automatically retries after 30 seconds |
| `delivery_storage_full` / `invite_storage_full` | Operator intervention is required |
| `message_id_conflict` | Protocol/client error: one ID must not be reused for another recipient |
| `frame_limit_exceeded` | Connection closes; reduce traffic before restarting |

The UI displays the reason beside the affected message. Permanent send failures show **Not sent** and a **Retry** button. Retrying keeps the original message ID. The failed message and outbox entry survive local-client restart. Temporary rejections stay **Pending** and preserve their retry deadline across restarts.

## Manual checks for this stage

1. Create a labeled invite, list it, revoke it, and try using its token with a fresh client profile. Expect rejection.
2. Create another invite and register a disposable client. List invites: it should be `used`, with that member's ID. Reuse the token with a different fresh profile: expect rejection.
3. Revoke the disposable member while connected. Expect an immediate disconnect and no reconnect loop. Restart the relay and client: authentication remains rejected.
4. Set `MESH_MAX_MEMBERS=1` on a separate test relay database, register one member, then attempt a second registration. Expect a capacity error without consuming the second invite. Revoke the first member and redeem the second invite successfully.
5. Set `MESH_MAX_QUEUED_PER_RECIPIENT=1`, restart the relay, and stop Bob's Python client. Alice sends two messages: the first is saved by the relay; the second stays pending with a queue-full reason. Restart Bob; the second should follow on the next retry, without duplicates. Restore the normal limit afterward.
6. Set `MESH_MAX_MESSAGE_BYTES=256`, restart the relay, and send a message. Encrypted envelopes include metadata and overhead, so even a short plaintext message can exceed this test limit. Expect **Not sent**, not a false "sent" tick. Restore the default, restart the relay, click **Retry**, and check delivery.
7. Call any admin endpoint without the admin header, or with a member's auth token. Expect 401 and no data or mutation.

Automated checks (temporary databases/profiles, no real user data):

```sh
./venv/bin/python -m unittest discover -s tests -v
node --check app.js
node --test tests/test_ui.cjs
```

For a live VPS smoke test with disposable records and automatic cleanup, see [ADMIN_TESTING.md](ADMIN_TESTING.md). It also documents isolated quota/concurrency checks.
