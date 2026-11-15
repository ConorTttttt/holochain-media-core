# Design note: asynchronous private delivery for Music and Media Core

**Status:** research / proposed future work, **not implemented**, **not an RC1 gate**, and **not approved for production**. Recorded 15 November 2026. Proposed planning identifier: **CORE-009** (not yet a scheduled commitment).

## Motivation and reference implementations

Holochain Music currently sends private access requests and grants via Holochain `call_remote`, authenticated using the recipient conductor's verified call provenance, and stores them as private source-chain entries. A local retrying outbox handles transient failures, but sender and recipient must overlap online for delivery. Do not describe that existing behavior as offline delivery.

The following open-source work is useful *as a design reference*, not as a drop-in dependency:

- [Lightning Rod Labs Files](https://github.com/lightningrodlabs/files): private/public file workflows, inbound notices with accept/decline, outbound distribution status, recovery of missing chunks, activity tracking and file-to-HRL attachments.
- [Delivery Zome](https://github.com/ddd-mtl/delivery-zome): `NORMAL` (direct message first, encrypted DHT fallback), `DM_ONLY`, `DHT_ONLY`; `PendingItem` encrypted envelopes, recipient-addressed inbox links, notice/reply/receipt states and `pull_inbox`.
- Relevant implementations: [send_item.rs](https://github.com/ddd-mtl/delivery-zome/blob/master/crates/delivery_coordinator/src/send_item.rs), [commit_pending_item.rs](https://github.com/ddd-mtl/delivery-zome/blob/master/crates/delivery_coordinator/src/functions/commit_pending_item.rs), [pull_inbox.rs](https://github.com/ddd-mtl/delivery-zome/blob/master/crates/delivery_coordinator/src/functions/pull_inbox.rs), [state types](https://github.com/ddd-mtl/delivery-zome/blob/master/crates/delivery_types/src/delivery.rs), [Files HRL attachments](https://github.com/lightningrodlabs/files/blob/main/dna/zomes/files/src/attach_to_hrl.rs).

The Files and Delivery Zome sources use older Holochain HDK/HDI versions and CAL-1.0 licensing. **Do not import or copy those zomes directly into Holochain 0.7.0 or assume their trust model is safe without review.** Any source-code reuse requires a separate licensing decision; architectural inspiration does not confer permission to copy code.

## Proposed system boundary

```text
Music / Video app (sender)
  -> local durable outbox (retain existing retries)
      -> authenticated direct call_remote attempt (existing behavior)
      -> on eligible failure, encrypt and publish a *small* mailbox envelope
             to a recipient-specific Holochain DHT inbox
Recipient app, later online
  -> discover inbox envelopes -> decrypt -> authenticate sender, recipient,
     intent and freshness -> deduplicate -> persist privately
  -> signed recipient acknowledgement / refusal, when appropriate
  -> optional delivery-state update to sender
```

This is a **control plane only**. Access requests, grants, acknowledgements and future notification references may be mailbox messages. **No WAV/MP3/video bytes, media chunks, plaintext content keys, or bulk encrypted-media objects may be stored on the DHT.** Verified ciphertext remains in Media Core's disk-backed CAS; authenticated large-object retrieval remains on certificate-pinned MoQ/QUIC. A mailbox message or receipt never authorizes playback: CORE-005 entitlement verification, key unwrap and AES-GCM checks remain compulsory.

The current Holochain identity, DNA pinning, and (where enabled) S2 v2/v2.1 key-binding and lifecycle policies must be the source of authentication. A sender field inside a remote-call body or encrypted envelope is **not** independent proof of sender identity. Authenticated provenance must come from a verified Holochain action/chain or other explicit cryptographically verified binding.

## Initial scope and message semantics

Start with **`AccessRequest`** and **`AccessGrant`** only; keep the current grant bytes and rights semantics until a separately reviewed versioned protocol explicitly changes them. The mailbox is not a substitute for completing `access-grant/v2`.

Proposed envelope requirements (contract to be specified before implementation):

- Explicit version, domain separation, DNA/network scope, unique random message ID, sender and recipient identities, recipient encryption-key generation or pin, bounded creation/expiry metadata and authenticated ciphertext.
- Encrypt authenticated payload to a Holochain-verified recipient key, use fresh randomness per message, and bind associated data to the exact recipient, network, envelope version and intent. Avoid disclosing track ID, grant rights, personal identifiers or wrapped content keys in public plaintext metadata.
- Verify the sender using a separately authenticated key or Holochain author provenance, not a self-asserted body field; reject cross-recipient, cross-DNA, replayed, malformed, unknown-version or oversized envelopes.
- Limit each envelope to a small, explicitly reviewed maximum; apply per-sender and global processing limits, bounded persistence and back-pressure before offering DHT fallback.
- Receiver-side idempotency is keyed to an authenticated message ID and prevents duplicated request, grant or acknowledgement actions, including after restarts.
- Distinguish: **queued locally**, **DHT publication observed**, **recipient acknowledged**, **request accepted/refused**, **grant processed**. DHT publication is *not* delivery or acceptance; a transport receipt is *not* a valid licence or proof of decryptability.
- Expires/ignores stale messages by policy but does not claim that published DHT ciphertext, links or metadata can be deleted from other peers. Retained mailboxes must not be treated as deletion-capable private storage.

A second, optional design topic is generic **attachments to authenticated Holochain resource references** (inspired by Files HRL attachment links). A track, album or profile may reference a signed Media Core manifest for artwork, lyrics or documents, **not** embed the asset bytes on the DHT. This is independent of mailbox delivery and not included in the first prototype.

## Risks and decisions requiring review

| Area | Requirement / unresolved question |
|---|---|
| Metadata privacy | Recipient-indexed public inbox links expose routing relationships; posting times, frequency, envelope sizes, and possible sender identity can be observable. Compare this with Music's current private-source-chain action metadata before approval. |
| Confidentiality and authenticity | Authenticated recipient-key binding, sender authorship/provenance, AEAD protection, domain separation, robust key custody and explicit handling of rotated/revoked keys; no trust-on-first-use from the envelope alone. |
| Sender abuse / DoS | Quotas, bounded DHT object sizes and inbox scans, duplicate suppression, refusal of unsolicited messages and resistant handling of large floods/Sybil agents; rate limits alone do not defeat Sybil attacks. |
| Reliability | DHT publication and eventual availability are not guaranteed. Define retries, acknowledgement timeouts, offline window, missing/expired-message behavior, conflict handling, and how storage/network partition is distinguished from refusal. |
| Immutability | DHT data may persist despite application-level expiry. Evaluate retention/privacy implications; never promise remote deletion or cryptographic erasure of previously received plaintext. |
| Key lifecycle | Pin to the recipient's authenticated active key generation at send time; document behavior when a recipient rotates before retrieval, or a sender key is revoked before acknowledgement. Do not silently downgrade from v2.1 to legacy. |
| Protocol ownership | Decide which DNA/network hosts the mailbox, whether multiple apps share one inbox, and whether cross-DNA references or app-specific validation are needed. Avoid an unreviewed shared capability surface. |
| Licensing / compatibility | Files and Delivery Zome use CAL-1.0 and older HDK; evaluate legal and API compatibility before considering code reuse. Independent reimplementation is preferred. |

## Acceptance criteria before any production switch

1. A three-real-conductor (artist, listener, attacker) run proves **both** access-request and grant delivery with **no simultaneous artist/listener online interval**, including restart and durable local processing.
2. Both direct-online and DHT-fallback paths work, with no duplicate grant/request effects under retries, multiple devices, reboots and delayed acknowledgements.
3. Forged author, wrong recipient/key, cross-DNA, mismatched manifest, revoked/rotated keys, replayed ID, stale, malformed, over-limit and unknown-version messages are rejected at named boundaries.
4. Delivery-state UI separates publication, receipt, approval and processing; it never labels DHT publication as completed delivery.
5. Offline mailbox unavailable, DHT slow/partitioned, quota exhausted and flood scenarios report explicit recoverable failures without weakening access checks.
6. Complete privacy/threat and third-party licence reviews; physical two-device testing; Windows and Linux CI; end-to-end regression of the existing v1 private `call_remote` path.
7. No production change to signing, entitlement, MoQ transport, encrypted storage or existing user data until owner sign-off, migration and rollback plans exist.

## Release decision

- **Music RC1:** retain the existing private `call_remote` delivery plus durable retrying outbox. No DHT mailbox, no new sender trust or grant semantics.
- **After RC1:** prototype small encrypted offline mailboxes behind explicit opt-in and fail-closed policy, without media bytes on DHT.
- **Future cross-app adoption:** generalize only after Music security and reliability tests pass. Video publication authorization, public access, rentals, subscriptions and payments are out of scope.

This note records an opportunity for follow-up design and testing. It is **not** evidence that asynchronous delivery is implemented, secure, reliable or ready for release.
