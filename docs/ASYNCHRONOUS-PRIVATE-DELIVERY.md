# Design note: asynchronous private delivery for Music and Media Core

**Status:** research / proposed future work, **not implemented**, **not an RC1 gate**, and **not approved for production**. Recorded 15 November 2026. Proposed planning identifier: **CORE-009** (not yet a scheduled commitment).

Media Core's main branch began with the CORE-001 workspace. References below to Media Core storage, retrieval and entitlement verification describe their intended roles in later milestones. Music v1 currently supplies its own verified storage and pinned transport.

## Motivation and reference implementations

Holochain Music currently sends private access requests and grants via Holochain `call_remote`, authenticated using the recipient conductor's verified call provenance, and stores them as private source-chain entries. A local retrying outbox handles transient failures, but sender and recipient must overlap online for delivery. Do not describe that existing behavior as offline delivery.

The following open-source work is useful *as a design reference*, not as a drop-in dependency:

- [Lightning Rod Labs Files](https://github.com/lightningrodlabs/files): private/public file workflows, inbound notices with accept/decline, outbound distribution status, recovery of missing chunks, activity tracking and file-to-HRL attachments.
- [Delivery Zome](https://github.com/ddd-mtl/delivery-zome): `NORMAL` (direct message first, encrypted DHT fallback), `DM_ONLY`, `DHT_ONLY`; `PendingItem` encrypted envelopes, recipient-addressed inbox links, notice/reply/receipt states and `pull_inbox`.
- Relevant implementations: [send_item.rs](https://github.com/ddd-mtl/delivery-zome/blob/master/crates/delivery_coordinator/src/send_item.rs), [commit_pending_item.rs](https://github.com/ddd-mtl/delivery-zome/blob/master/crates/delivery_coordinator/src/functions/commit_pending_item.rs), [pull_inbox.rs](https://github.com/ddd-mtl/delivery-zome/blob/master/crates/delivery_coordinator/src/functions/pull_inbox.rs), [state types](https://github.com/ddd-mtl/delivery-zome/blob/master/crates/delivery_types/src/delivery.rs), [Files HRL attachments](https://github.com/lightningrodlabs/files/blob/main/dna/zomes/files/src/attach_to_hrl.rs).

The Files and Delivery Zome sources use older Holochain HDK/HDI versions and CAL-1.0 licensing. **Do not import or copy those zomes directly into Holochain 0.7.0 or assume their trust model is safe without review.** Any source-code reuse requires a separate licensing decision; architectural inspiration does not confer permission to copy code.

> **Security-policy conflict requiring approval:** the current Media Core `docs/architecture.md` and `docs/threat-model.md` say not to put *encrypted private grants* on the public DHT. A future mailbox carrying an encrypted grant is an intentional exception to that rule, **not** an already-permitted deployment. Any production proposal must explicitly amend and approve those policies; RC1 does not change them.

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


## Agent 10 review addendum — concrete security contract (17 November 2026)

**Disposition:** conditionally suitable for a *throwaway, opt-in research prototype only*. This is a threat-model and test proposal, not a protocol approval, production implementation, migration, or RC1 requirement. It refines the open questions above; where an item is labelled **must decide**, no developer should silently pick a default.

### Trust assumptions and adversaries

| Boundary / actor | Assumption and required evidence | Not guaranteed |
|---|---|---|
| Direct receive | The recipient conductor verifies the signed \`call_remote\` parameters; \`call_info().provenance\` is the sender for the zome call, and only a successful authenticated receive function confirms private-inbox admission. | A successful network send alone does not mean the request was accepted or a grant is valid. |
| Public-DHT mailbox | Fetch a **validated create-action record by action hash**, check its cryptographic Holochain author and the same author's inbox link; require \`action.author == envelope.sender_agent\`. Independently authenticate the recipient key binding. | A sender field, a link tag, a copied encrypted entry, the publisher's self-report, or an arbitrary \`get\` result is not sender provenance. A relay and DHT authorities are not trusted for delivery or confidentiality. |
| Media/rights | Reuse the app's existing manifest, lifecycle, grant signature, recipient, rights, term and key-unwrapping verifiers. For v2, additionally verify the issuer's grant anchor **when that protocol is implemented**. | Neither transport, receipt nor mailbox decryption authorises playback. Paid settlement and publication authority are outside scope. |
| Recipient key store | Honest recipients protect all retained X25519 private keys; each binding is agent-authored, scoped to DNA and a specific generation/action. | OS-account compromise, stolen keys, agent-key compromise, malicious local conductors and user clock tampering are outside this protection. |
| Holochain DHT | Honest validation/replication is eventually available often enough for the prototype; an attacker can run Sybil agents, author links, flood entries, replay old ciphertext, withhold data, observe traffic and manipulate its own clock. | Bounded latency, permanent availability, deletion, guaranteed ingestion, sender anonymity or recipient privacy. |

**Stronger metadata warning:** Unlike the current private-source-chain inbox actions, a public link keyed by the recipient agent plus a sender-authored encrypted entry can reveal **both endpoints of a communication edge**, including the sender, recipient, approximate timing, frequency and size. Encrypting only the payload does not hide this. A hash of the recipient agent is generally still a stable, guessable index, not anonymity. Neither padding nor pseudonymous mailboxes may be claimed to solve this until measured. Run a privacy approval specifically for artist/listener relationship leakage.

**Important S2 dependency:** S2 v2.1 currently handles Ed25519 \`owner-manifest\` and \`host-receipt\` lifecycle keys. Music's listener X25519 key is currently authenticated in a *direct request* through call provenance; **S2 does not yet have a recipient/mailbox-X25519 binding, possession proof, or rotation policy**. Do not reuse an existing media-key purpose as though it covered mailbox encryption. A new versioned, DNA-scoped, agent-authored binding and a reviewed method for proving/confirming X25519 secret-key control are prerequisites for production. For the isolated prototype only, use pre-enrolled test identities and pinned test encryption-key binding action hashes; mark the assurance \`PrototypePinned\`, **never** \`KeyLifecycleV21\`. A later binding schema must specify inception, generation, rotation, recovery, compromised revocation, anti-equivocation and reader resolution in the S2 style (no first/latest-record selection or legacy fallback). Do not mutate the existing released/v1 DNA to experiment.

**Sender-authority distinction:** A validated Holochain create action proves the action's *agent* authorised publishing that ciphertext; it does **not** prove the agent is a legitimate grant issuer. For \`AccessGrant\`, the inner signed grant must independently satisfy the selected CORE-005 / \`access-grant/v2\` policy. \`AccessRequest\` takes its requestor agent **only** from the validated outer action and must match any inner requestor field. If a link points to a create action by a different agent, or the retrieved entry cannot be paired with its validating action, reject it. Do not treat encryption or \`PendingItem.author\` as a signature.

### Proposed mailbox envelope v1 (research wire contract, not frozen)

Only \`AccessRequest\` and \`AccessGrant\` are application message kinds. An optional future receipt is a **separate, signed status event**, not a grant, licence or third application message type. Canonicalise with a deterministic, length-prefixed binary encoding or an explicitly specified canonical JSON profile with duplicate-key rejection and byte-for-byte Python/Rust vectors; **do not silently accept arbitrary JSON encodings**.

| Outer, publicly exposed header field | Validation rule |
|---|---|
| \`schema\`, \`suite\` | Exact \`holochain-music/mailbox-envelope/v1\` and one explicitly supported reviewed X25519/HKDF/AEAD suite; unknown versions/suites fail closed. Select/test the final suite before coding (prefer a vetted HPKE profile). |
| \`network_dna_hash\`, \`mailbox_dna_hash\` | Pin expected Music network and mailbox DNA; reject cross-DNA, cross-environment and cross-app replay. |
| \`sender_agent\`, \`recipient_agent\` | Recipient is the local expected agent; sender **must equal** the validated create action author. These fields and public recipient-indexed links are observable even when ciphertext is secure. |
| \`recipient_binding_action\`, \`recipient_key_generation\` | Name the exact, authenticated encryption-key binding and generation. Resolve from independently validated records; reject stale, absent, forked, recovered-without-approved-assurance or compromised/revoked bindings under the selected policy. |
| \`message_id\`, \`created_at\`, \`expires_at\` | Cryptographically random 256-bit ID unique per logical delivery, reused across transport retries; bounded TTL (prototype: <= 7 days) and clock-skew policy (prototype: <= 5 min future skew). Timestamps are untrusted claims, not global chain ordering or cryptographic proof of key freshness. |
| \`encapsulated_key\`, \`nonce\`, \`ciphertext\` | Fresh ephemeral sender secret and fresh nonce per independently encrypted message; authenticate the complete canonical header as AEAD associated data with a distinct \`holochain-music/async-mailbox/v1\\0\` domain; reject all-zero X25519 shared secret and authentication failure. |
| \`author_action\` (link target, not self-declared envelope evidence) | The inbox link targets the specific validated *create action* rather than an entry hash with ambiguous authorship. The link's author must match the entry create-action author; recipient reads the action and entry together. |

The *encrypted payload* is an exact, versioned structure containing \`kind=AccessRequest|AccessGrant\`, its normal signed/verified Music control message, any reply correlation token, and an inner copy of IDs that must equal the outer authenticated context. Keeping \`kind\`, track ID, manifest ID, requested rights, grant terms, entitlement reference and wrapped content key **inside** AEAD limits public metadata. The message's **sender action** authenticates the envelope to its agent; the inner grant's independent Ed25519 signature and lifecycle/anchor check authenticates grant authority. Do not use an unsigned envelope body claim as an identity.

Bound the **entire published entry** to <= 8 KiB for the prototype, ciphertext to <= 6 KiB, and reject before parsing, decryption or expensive signature verification when caps fail. These are research limits to be validated with worst-case real grants (especially a future v2 grant); do not silently truncate a grant. A separate content-key wrap already inside an otherwise valid grant is allowed as a *small encrypted control payload*, but a plaintext content key or bulk encrypted media is never allowed.

**Cross-chain ordering limitation:** Holochain does not provide a trusted total order comparing a sender's envelope action with a recipient's key-lifecycle actions. A sender-reported \`created_at\` cannot prove that a key was active at a particular historical instant. For prototype simplicity resolve the recipient binding as **currently active at send and again at processing**. If it rotated or was revoked in between, do not quietly use the old generation: quarantine the old message and request fresh encryption under the new binding. This may sacrifice availability but avoids guessing. Historical grace periods, if ever desired, require a separately reviewed signed retention policy and compromise model; keeping an old decryption key cannot make a stolen key safe.

### Deterministic receiver sequence and fail-closed responses

1. Query only the expected inbox anchor and cap pagination, record count, total bytes and per-poll work **before** downloads. Treat links as untrusted adversarial pointers.
2. Fetch each target by create **action hash** and require a valid Holochain action, matching entry hash, expected schema, same author on link and entry, and exact recipient/DNA.
3. Enforce size, version, suite, unique ID, TTL, supported binding generation and replay limits before decrypting; never accept unknown-field variants through a permissive parser.
4. Resolve and verify recipient binding from independent trusted S2-style records / pinned prototype fixtures. Missing data is \`Unavailable/RetryLater\`, not \`Denied\`; invalid or compromised binding is \`Rejected/Quarantined\`, not legacy fallback.
5. Authenticate AEAD using the **exact** canonical outer header. Decrypt inside the trusted local recipient process, never the public DHT or a relay.
6. Verify the inner kind and all outer/inner bindings. For requests, use action author as requester; for grants, call the pre-existing signed grant, owner/issuer, file, manifest, recipient, permissions, term and key-unwrap validators. Unsupported grant versions and unavailable grant anchors cannot be accepted as valid.
7. Persist a durable \`(network DNA, authenticated sender agent, message ID)\` dedup record and the private inbox result atomically or with an idempotent recovery journal **before** reporting processed. Use the same logical ID for direct-first and DHT fallback in the future *versioned* transport adapter; the legacy RC1 direct path stays unchanged.
8. On duplicate copies, replays, restarts, repeated links or source-chain re-gossip, return the prior outcome without re-issuing a request or granting any additional rights. Detect a reused message ID with *different* ciphertext and quarantine it as a conflict.
9. Surface clear, typed errors: \`InvalidAuth\`, \`WrongRecipient\`, \`UnsupportedVersion\`, \`Expired\`, \`ReplayOrConflict\`, \`QuotaExceeded\`, \`KeyUnavailable\`, \`DhtUnavailable\`, \`EntitlementInvalid\`; network unavailability and lack of a message must never be reported as refusal.
10. Stop work on quotas or malformed data, including before decryption. Never assume a delete-link removes a published action, entry, original link, cached copy, or adversary-held ciphertext.

Prototype budgets (not Sybil protection): process at most 100 links and 1 MiB downloaded per polling pass, and use the existing local inbox's 20-per-sender/day and 500-global/hour ceilings as upper bounds where meaningful. Cap pending outbox items at 200, enforce per-recipient backoff and bounded retries, and reject unsolicited bulk writes. DHT validation can enforce static entry size/schema/author-link rules; it **cannot** securely enforce global dynamic per-sender/time quotas from mutable DHT reads. A Sybil swarm can still fill storage, monopolise scans, reveal social connections and prevent delivery. In production require a separate admission/allowlist, abuse-cost or anti-Sybil decision with realistic adversarial load tests; test limits alone are not a defence.

### Two independent state dimensions (never conflate them)

**Transport observation**: \`CreatedLocal -> QueuedLocal -> DirectAttempted -> [DirectInboxAccepted | DhtPublishObserved | Unavailable]\`, followed independently by \`RecipientReceiptVerified\` *only* upon an authenticated recipient-authored receipt. \`DhtPublishObserved\` means the sender observed a publish operation; it does not mean replication to a retrievable shard, recipient discovery, decryptability or receipt. \`Expired\` and \`Abandoned\` are local terminal reporting outcomes, not DHT deletions. Network ambiguity remains \`Unknown\`, not a negative response. Avoid a catch-all \`Delivered\` state.

**Application/authority outcome**: \`NotSeen -> EnvelopeAuthenticated -> PrivateInboxPersisted -> [AccessRequestPending/Accepted/Refused | GrantVerified/Rejected]\`. A *verified grant* may subsequently yield \`LicenceUsable\` only after the **existing** entitlement, key-unwrapping, storage-integrity and playback checks. A request's recipient acknowledgment is not the artist's acceptance; a grant receipt is not payment evidence. Do not map a transport receipt onto a licence state.

The smallest prototype **does not implement recipient-issued public DHT receipts**: it can inspect the recipient's authenticated private outcome in the test harness while the sender's UI remains \`DhtPublishObserved / unconfirmed\`. A future separately versioned, signed acknowledgement contract may update transport observations, with its own freshness, replay and spam requirements. Do not claim "recipient acknowledged" from inbox link deletion, DHT disappearance or sender self-report.

### Three-real-conductor acceptance contract (no artist/listener overlap)

Use **Artist A, Listener L, Attacker/continuously online DHT peer M** (distinct real Holochain 0.7 conductors, identities, source chains, processes and persistent stores; no mocked in-memory mailbox). All devices/cells may be installed with pinned test identities first, but during the delivery runs A and L must **never be simultaneously online**, including initial publication. Establish a working DHT/gossip topology and demonstrate that M actually holds or makes available the relevant mailbox records after each publisher disconnects; a successful local publish without remote replication is not a pass.

| Phase | Online | Required evidence |
|---|---|---|
| T0 key setup | A + M, then stop A; L + M, then stop L (never A+L) | Both recipient encryption-key bindings and their authenticating action hashes are independently resolvable in the test DNA. |
| T1 request | L + M, A offline | L's authenticated \`AccessRequest\` mailbox envelope is published, observed from M, and outbox remains *unconfirmed*; then stop L completely. |
| T2 intake and grant | A + M, L offline | A pulls, validates and privately persists exactly one request; issues an independently verifiable, recipient-encrypted \`AccessGrant\`; M independently observes its mailbox entry; then stop A completely. |
| T3 receipt and recovery | L + M, A offline | L pulls, decrypts, authenticates and imports exactly one valid grant; reboot L and re-pull, showing zero duplicate effects. The grant verifier and key unwrap pass; **no claim of playback authorisation from mailbox receipt alone**. |
| T4 adversarial runs | M operates as adversary, with A or L alternately online | Forged sender/link author, substitute/rotated/compromised key, wrong recipient, wrong DNA, old and future versions, wrong grant/manifest, invalid AEAD/signature, replay ID, same-ID altered bytes, expired/future clock, oversized and high-volume links all fail closed at named boundaries. |
| T5 failure/recovery | A or L online, M delays or withholds, never A+L | Partition, missing DHT data, offline key lookup, recipient crash between processing and persist, duplicate direct/fallback delivery and outbox restart produce \`Unknown/RetryLater\` or a verified prior result, never fabricated refusal/acceptance. A retry after the network heals processes at most once. |

Test the role-reversed order and a second consecutive request/grant pair. Use separate durable stores and inspect real source-chain records; capture process start/stop timestamps proving **zero online overlap**, exact public metadata visible to M, envelope size/scan budgets, key-generation choices and negative-case verdicts. If the three-node DHT topology does not replicate reliably, that is an **acceptance failure**, not permission to substitute a mock or start A and L together. Windows/Linux and physical-device runs are a later release gate; no RC1 test suite needs to change.

### Proposed implementation order and release gate

1. **CORE-009a (design only, current):** owner review of this threat model, public-DHT encrypted-grant exception, actor/recipient metadata disclosure, exact key-binding assurance, schema canonicalisation and licensing. Keep #7 and Music #48 draft; no code.
2. **CORE-009b (after Music RC1, disposable environment):** byte-exact envelope/parser and AEAD vectors, wrong-domain/author/recipient/ID attacks, independent test key-binding fixtures. Develop an **isolated throwaway test DNA** rather than editing Music's v1, v2 or v2.1 production DNA. No adoption by Music playback paths.
3. **CORE-009c:** opt-in direct-first/DHT fallback for only \`AccessRequest\` and \`AccessGrant\`, bounded local queue and common logical dedup ID, using the test DNA. Integrate with the *existing* grant verifier; no new grant rights or content-key issuance rules.
4. **CORE-009d:** three-conductor offline / malicious-peer and restart tests above, metadata measurement, quotas/DoS and key-rollover failure tests; publish evidence and a rollback plan. A separate recipient-key lifecycle design may need its **own milestone** before production.
5. **Production security gate (no date committed):** independent crypto/protocol review; explicit S2 encryption-key lifecycle approval including X25519 control, rotation/compromise and agent recovery; \`access-grant/v2\` issuance/anchor verification decision; DHT metadata/privacy assessment; admission and Sybil policy; legal/licensing review (Files and Delivery Zome are CAL-1.0; **no copied code**); real-conductor tests and physical Windows/Linux network tests; back-compat migration/rollback; owner sign-off. Without **all** approvals, ship **no** DHT mailbox.

**Owner decision required:** is the extra public sender–recipient relationship graph and retained grant ciphertext acceptable in exchange for non-overlapping-online delivery? If not, do not use recipient-indexed public-DHT mailboxes; evaluate a different store-and-forward architecture. This design cannot promise DHT deletion or anonymous private communication.
