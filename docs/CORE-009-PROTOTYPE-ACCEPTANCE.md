# CORE-009 — Asynchronous private-delivery prototype acceptance specification

**Status: proposed research test contract, 17 November 2026. NOT IMPLEMENTED. NOT AN RC1 GATE.**
**Priority:** P3, post-Music RC1. **Owner decisions unresolved.**
**Companion:** [Architecture and threat model](ASYNCHRONOUS-PRIVATE-DELIVERY.md), including its 17 November Agent 10 addendum.
**Review bases:** Media Core PR #7 at 978441420948a7c4aa538b285a809b7ae245cb03 (stacked on feat/grant-anchor-v21 at a74a8aec32da03962788ad92810c413103b2ffd3); Music PR #48 at 0b2afb759401fa872a3aadf00dd4c62ca82a1338 (Music main bd7aabc3e9ea1fef1e8e8f674301e1b5ffecb637). These are documentation baselines, not merged releases.

## 1. Contract and no-go boundaries

A prototype passes **only** when a listener and artist exchange one small AccessRequest and one independently authorised AccessGrant through a verified DHT mailbox while their conductors never have overlapping online intervals. It must prove that a continuously online, independently controlled third conductor stores or serves the relevant DHT data after the sender has stopped. A local successful publish is insufficient.

All prototype code belongs to a **separate disposable test DNA** with unique network seed, pinned test agent identities and ephemeral test encryption-key bindings. Do not edit or silently switch the released Music v1 DNA, the opt-in v2/v2.1 storage DNA, S2 lifecycle, RC1 call_remote flow, grant format, signed manifest, key unwrap, encrypted CAS or MoQ. No production deployment, source-chain migration or cryptographic trust-policy amendment is authorised.

Only application messages AccessRequest and AccessGrant are supported. No media ciphertext, audio/video files or chunks, plaintext content keys, bulk media objects, secret keys, track/manifest identifiers or licence terms are published as public cleartext. The only possible DHT secret-bearing record is a **small recipient-encrypted control message**, which could carry an already-encrypted grant key-wrap *inside* its AEAD ciphertext. This is a proposed **exception** to the current Media Core public-DHT ban on encrypted private grants: it needs explicit security/product owner approval before any production implementation.

The prototype **does not claim private communication metadata**. Public inbox anchors/links, author actions, timestamps, sizes and DHT gossip can reveal sender–recipient relationships. DHT operations cannot guarantee availability, delivery, receipt, deletion, privacy from traffic analysis, anti-Sybil protection, acceptance of a request or the validity of a grant.

## 2. Preconditions and frozen test fixtures

Before writing executable code, freeze and review:
1. Exact envelope schema, canonical binary encoding or strict canonical JSON, duplicate-field rejection, byte order, length representation, domain separator, cryptographic suite and version. Prefer a reviewed HPKE profile if compatible with actual Holochain 0.7/target WASM; do not implement an improvised KDF/AEAD construction.
2. One recipient mailbox-X25519 binding schema (separate from S2 v2.1 Ed25519 owner-manifest/host-receipt purposes), a proof/control-of-private-key assurance mechanism, lifecycle/recovery/revocation rules, and authenticated read semantics. For a **throwaway-only** test permit pinned, pre-enrolled, agent-authored binding-action hashes with explicit assurance PrototypePinned. Never label that KeyLifecycleV21 or deploy it as a real identity binding.
3. Random 256-bit logical message ID created **before** transport choice, reused verbatim for direct retry and DHT fallback. Current Music RC1 outbox IDs are local 64-bit retry IDs created after a failed remote call; they are **not** an interoperable logical delivery ID and MUST NOT be retroactively interpreted as such.
4. Public entry <= 8 KiB and ciphertext <= 6 KiB; deterministic rejection before expensive work. Include at least one full-size legitimate v1 grant and a future-v2 candidate as a measurement-only fixture; if either exceeds limits, reject without truncation and reopen budget review.
5. TTL <= 7 days, future timestamp tolerance <= 5 minutes, explicitly injected verifier clock, receiver policy for key binding **active at send and again at process** (not sender-provided timestamp as lifecycle evidence). Prototype quarantine on rotation/revocation; no historical grace.
6. Local bounded outbox <= 200; <= 100 links and <= 1 MiB retrieved per poll; upper processing ceilings 20 items/author/24 h and 500 total/hour where applicable. These are local admission/resource controls **not** enforceable global DHT quotas or Sybil defence.
7. Same signed grant and entitlement verifier used by the chosen test integration, including issuer/owner/manifest/recipient/rights/term/key-wrap checks. The AccessGrant payload is never promoted to trusted merely by envelope authentication or DHT presence.

Test harness must create **three independent Holochain 0.7.x conductor processes and persistent stores** (artist A, listener L, malicious peer M), each with a distinct agent key and installed disposable DNA. M must participate in a real network as a replicating DHT peer and later act maliciously. No mocked mailboxes, synthetic one-process pretend conductors or fallback internet store are acceptable substitutes. Exact runtime/binaries, DNA hash, network seed, key-binding action hashes and starting code SHAs must be recorded.

## 3. Security contract — deterministic receiver algorithm

The receiver follows this order. For each failure, return a typed *non-authorising* verdict, do not persist a valid request/grant, do not emit positive receipt or grant a licence, and do not retry as though the artist refused.

| Gate | Evidence | Fail closed when |
|---|---|---|
| R0 poll budget | Expected DNA/inbox anchor; capped pages, bytes and work; stable dedup/cursor strategy | Missing DHT data -> Unknown/RetryLater; work cap -> QuotaExceeded; untrusted links cannot force unlimited scan |
| R1 authenticated action | Fetch target by **create action hash**; validated action, entry match, validated inbox link | Entry-hash-only ambiguous author, missing action/entry, wrong link target/base/recipient or link author differs from entry action author |
| R2 sender binding | Validated create-action author == public sender_agent; inbox-link author == same action author | Spoofed PendingItem.author, injected sender field, copied entry, forged link or sender not allowed by chosen recipient policy |
| R3 structure/context | Known schema/suite, exact field set, canonical bytes, caps, both pinned DNA hashes, intended local recipient | Unknown version/suite/field, malformed, wrong DNA/recipient, noncanonical or over-limit |
| R4 recipient key | Exact validated agent-authored binding action, accepted generation and possession assurance, revocation and successor checks | Unbound/foreign/ambiguous/stale/compromised key, changed active generation, unverifiable current state -> KeyUnavailable/Quarantined |
| R5 cryptography | AEAD authenticates all outer header fields as associated data; fresh ephemeral key and nonce, correct domain | Decrypt/authentication failure, all-zero X25519 secret, tampered associated data, bad suite/domain |
| R6 freshness and idempotency | Random logical ID and sender/recipient/DNA domain; TTL, skew; durable record of digest and outcome | Expired/future/replayed-conflicting ID; identical duplicate returns stored outcome with zero additional effects |
| R7 payload and authority | Inner kind is exactly AccessRequest or AccessGrant; inner IDs/context match; requestor equals R2 author; grant issuer verifies independently | Mismatched requestor, signature, manifest, issuer authority/anchor as required, recipient, rights, term or wrapped key |
| R8 durable apply | Atomic (or crash-recoverably idempotent) private inbox write + dedup record + outcome | Crash or partial write cannot create duplicate grant/request effects or emit premature acknowledgement |
| R9 authorisation separation | Existing entitlement gate, key unwrap, AES-GCM and verified storage checks | A valid envelope alone never produces LicenceUsable or playable media |

**Important nuance:** Holochain authenticates the **agent that authored the public create action**, not a party named in the ciphertext. Action authorship is distinct from grant-issuer authority. A genuine author may send an unauthorised or fraudulent AccessGrant; it must fail R7. Links are adversary-controlled discovery hints, never identity evidence on their own. The reference Delivery Zome passes its self-described PendingItem.author into receive handlers, so copying that usage would be an authentication bug.

A message ID is scoped to exact sender agent, intended recipient agent, both DNA hashes and kind. Persist message ID, authenticated envelope digest, private-effect identifier, outcome, and retry status. Identical redelivery returns the prior outcome; a different envelope with the same scoped ID is **ReplayOrConflict** and neither overwrites the first nor produces a second private effect. The durability/atomicity mechanism is deliberately not assumed; prove crash recovery before approval.

## 4. Delivery-state observability contract

Expose **two independent dimensions**, with stable event codes rather than an ambiguous "delivered" flag:

| Transport observation | Valid proof | What it MUST NOT imply |
|---|---|---|
| CreatedLocal / QueuedLocal | Saved bounded local state | Other conductors know anything |
| DirectAttempted | Outbound authenticated call attempted | Recipient stored it |
| DirectInboxAccepted | Explicit successful authenticated recipient receive result (or independently inspected recipient private record) | Recipient approved the request or grant is valid |
| DhtPublishObserved | Sender-side successful DHT publish result | Replication, recipient retrieval or receipt |
| Unavailable / Unknown / RetryLater | Timeout, missing authority or partition; uncertainty retained | Refusal, expiration or recipient denial |
| RecipientReceiptVerified (future optional) | Separately authenticated, fresh recipient-authored acknowledgement with bound message ID | Request approved, grant valid, payment verified or playback authorised |
| Expired / Abandoned | Local terminal display and retry policy | Deletion of DHT action, link or ciphertext |

Application state: NotSeen -> EnvelopeAuthenticated -> PrivateInboxPersisted -> (AccessRequestPending/Accepted/Refused or GrantVerified/Rejected). LicenceUsable is a **separate** existing policy/crypto/storage outcome.

The initial three-conductor prototype **does not require a public receipt protocol**. It proves recipient intake by independently querying recipient private records through the harness; sender state remains DhtPublishObserved/unconfirmed. Do not infer an acknowledgement from link deletion or DHT absence.

## 5. Test runner and strict offline schedule

Have a fourth **harness process** outside the DHT record an append-only event log with UTC wall time *and* monotonic ticks for PROCESS_START, NETWORK_READY, STOP_REQUEST, PROCESS_EXIT, REMOTE_DHT_READ, PRIVATE_INBOX_COMMIT, CRASH and ASSERT. The harness must fail immediately if A and L are simultaneously PROCESS_START..PROCESS_EXIT, including installation, key discovery, network preparation and attempted direct delivery. M may remain online throughout. A recipient shutdown is complete only after conductor process exit and network resources are closed; "app UI offline" is not sufficient. Stop A and L processes one at a time, not merely their UI.

| Phase | Online | Action | Independently verified evidence |
|---|---|---|---|
| T0a | A + M; L fully stopped | A authors its authenticated test identity/manifest/key commitments. M fetches action hashes. Stop A. | M can independently fetch and validate A's create action, not just sender's return value |
| T0b | L + M; A fully stopped | L authors test recipient key binding; M fetches. Stop L. | M can independently fetch L binding; no A/L overlap |
| T1 | L + M; A stopped | L creates AccessRequest logical ID, authenticates/encrypts for A's pinned mailbox binding and publishes fallback; stop L. | M independently gets matching request action hash and bytes; L outbox shows published/unconfirmed |
| T2 | A + M; L stopped | A polls, runs R0-R8 and persists **one** request; A signs a separately valid AccessGrant for L, encrypts to L's pinned binding and publishes; stop A. | One private request, verified independent grant authority, M retrieves grant action and header; A outbox unconfirmed |
| T3 | L + M; A stopped | L fetches, validates and privately persists one grant; terminates/restarts L, repolls twice. | One private grant/effect, dedup outcome stable after restart; existing grant verifier/key unwrap pass; no purported mailbox-only playback permission |
| T4 | A or L + M, never both A and L | Run all negative cases in §6 with attacker M injecting author-controlled data and withholding/replaying bytes. | Explicit rejected/unknown verdict at specific numbered R-gate, no extra private effects |
| T5 | A or L + M, never both A and L | Delay/partition replica, crash receiver before/after durable persist, restart sender outbox, inject direct-success/response-lost and DHT duplicate using the **prototype** receive contract. | Unknown/RetryLater when uncertain; eventual exactly-one private effect after recovery; no fabricated acceptance or refusal |
| T6 | L + M then A + M, separately | New independent request/grant pair; reverse direction lifecycle/rotation experiments. | Exactly-one effects for both pairs and no overlapping online intervals |

**DHT replication pass condition:** sender exits; M's separate conductor demonstrably has/retrieves the validated action and entry while sender is offline; intended receiver later gets the same action/entry with sender still offline. If the test network lacks enough DHT authorities or gossip for this to happen, **fail** and document topology rather than replacing M with a mock or starting A and L concurrently.

## 6. Executable negative-case matrix (not yet run)

Every negative case requires an adversarial fixture, explicit expected gate/verdict, count of private effects before and after, and elapsed work/bytes. Matrix IDs should become stable test names when implemented.

| ID | Injection / transition | Expected observation |
|---|---|---|
| N01 | M authors action whose header claims A; M writes recipient-indexed link | R2 rejects; no spoofed sender |
| N02 | M links to A's valid entry using M's action or to an entry-hash-only target | R1/R2 reject; no authored-identity confusion |
| N03 | M changes publicly visible sender, recipient, schema, DNS/DNA/network scope or key-generation binding | R2-R5 reject before effects; cross-DNA isolation |
| N04 | Correct key but tampered ciphertext, encapsulation, nonce, header AAD or all-zero X25519 point | R5 rejects; no decrypted payload |
| N05 | Wrong recipient agent, key from another binding, forked or missing binding, rotated/revoked recipient key | R3/R4 reject or quarantine; no fallback to legacy/stale or self-asserted binding |
| N06 | Authored by correct sender but inner requestor differs, inner IDs/kind mismatch | R7 rejects; inner claim cannot replace action author |
| N07 | Authored valid envelope, forged or forwarded grant, wrong issuer/manifest/anchor, rights, term, recipient or wrapped key | R7/R9 reject; no usable entitlement |
| N08 | Same authenticated message twice via DHT, retry, local restart, concurrent poll or dual direct/DHT | One effect; identical ID + digest returns existing outcome |
| N09 | Same logical ID with different authenticated bytes from same sender | ReplayOrConflict, no second effect or silent overwrite |
| N10 | Expired, more than 5 minutes in future, unsupported version/suite, duplicate JSON keys, noncanonical bytes | R3/R6 reject; no parser disagreement |
| N11 | 8193-byte entry, >6144-byte ciphertext, 101 links or >1 MiB poll work, 201 local queued items | Explicit size/QuotaExceeded/pressure, bounded processing; no crash |
| N12 | 20/24h sender pressure, 500/hour aggregate, many Sybil identities and tombstoned links | Local bounded work with no claim of network-wide anti-Sybil guarantee; measure legitimate-message starvation |
| N13 | M withholds records, partitions gossip, DHT key binding temporarily unavailable | Unknown/RetryLater, never "recipient refused", "delivered" or "grant denied" |
| N14 | Receiver crashes between decryption, persisted private effect and dedup mark | After restart either safely retry with one effect or return previous authenticated result; no double grants |
| N15 | Recipient rotates before pulling; sender key or grant authority revoked before processing | Fail closed/quarantine under active-key policy; new independently authorised resend needed; no historical timestamp shortcut |
| N16 | Old ciphertext after declared expiry or inbox-link deletion | No accepted stale message; verify that remote DHT copies **may remain** (never claim erasure) |
| N17 | Replay across app/network seed, different DNA, environment or recipient | R3/R5 reject even if syntactically valid |
| N18 | High-cost invalid link flood with cursor starvation and repeated polling | Enforced time/byte/link bound and explicit unavailability; no unbounded scanning or denial masked as empty inbox |

**Expectations for N15:** If a key genuinely changed, retain old ciphertext only in quarantine (if local retention policy permits) and notify a sender to perform a fresh independently authorised encryption against a newly authenticated binding. Never "re-encrypt in place" DHT ciphertext, silently accept revoked keys, or invent cross-agent chain ordering from user-controlled timestamps. Agent-key compromise has no proven automatic recovery; fail closed.

## 7. Privacy measurements and attack evidence

M is the observer as well as malicious participant. Record what it can actually see without a decryption key: public action author; recipient-indexed inbox anchor/link and link author; timestamp at authoring/gossip observation; ciphertext and full-envelope lengths; poll frequency; sender and recipient relationship; whether size padding changes leakage. Record whether manifest IDs, file IDs, rights, notes, grant terms, content keys or audio bytes ever appear in **public plaintext** (they must not). Add both a known-recipient enumeration attempt and a dictionary-hashed-recipient test to demonstrate that hashing a stable agent ID is not anonymity.

Capture scale/availability limits: per-poll bound, heavy malicious flood, honest message delayed behind spam, gossip lag, data loss on network partition, restart recovery and DHT copy persistence after local expiry. The threat report must separately state confidentiality, metadata exposure, integrity, availability, replay and revocation outcomes. No privacy or availability claim may be inferred from a passed two-node unit test.

## 8. Evidence bundle, verdicts and review gates

Expected future evidence directory is an **uncommitted test artifact**, not proof it exists today. For each run save:
- HEAD commit SHAs of both repos and test DNA, exact conductor/HDK versions, OS, test seed (without private keys), configuration, three distinct agent IDs and host identities.
- Machine-verifiable event log proving no A/L process overlap, exit codes and process states, persistent data directories per conductor and the independent M replication/retrieval observations.
- Valid action hash, link action hash, envelope digest, message ID, recipient binding-action and generation; redact private keys, plaintext key-wrap intermediates and decrypted private notes.
- Before/after private-inbox counts and authenticated grant verification result; full negative matrix gate/verdict/failure counts; resource ceilings, DHT payload-size histograms and privacy exposure.
- Explicit PASS / FAIL / SKIPPED / BLOCKED / NOT RUN for every test ID, with exact command line and CI/job link. The harness MUST NOT mark a case PASS unless its target condition was observed.

**Current result on 17 November 2026: ALL CORE-009 executable tests NOT RUN.** This document is a specification, not evidence of an implemented mailbox. Existing Music PR #48 CI and Media Core PR #7 CI concern other code and do not validate CORE-009.

Hard **NO-GO** if any malformed, spoofed, stale or duplicate message leads to an authorised private effect; if artist/listener overlap; if M cannot independently demonstrate persistence; if local quota work is unbounded; if a DHT publication is represented as recipient receipt; or if a public metadata exposure is hidden from the product/security decision.

## 9. Proposed milestone and blocking decisions

- **CORE-009a (now):** design and threat acceptance, source-code reference/license review, public-DHT encrypted-grant policy exception and sender–recipient graph approval. Documentation only.
- **CORE-009b (post-RC1):** independently testable canonical envelope, cryptographic vectors, exact sender-action checks and isolated PrototypePinned recipient key fixtures. Negative parser/crypto tests run first.
- **CORE-009c:** bounded opt-in local queue, direct-first then encrypted DHT fallback, shared logical ID and receiver idempotency; only AccessRequest and AccessGrant; no changes to Music RC1.
- **CORE-009d:** three-real-conductor no-overlap suite T0-T6 and matrix N01-N18, peer observation/DoS measurements and interruption recovery.
- **Production decision (separate approval, not a committed date):** independently review recipient encryption-key lifecycle, publication-policy exception, Sybil admission, privacy harm of relationship graph, copyright/commercial grants, legal CAL-1.0 questions, physical Windows/Linux tests, migration and rollback. Only then consider an explicitly versioned production DNA or app adapter. Default decision until then: **do not ship**.

## 10. Historical reference and compatibility notes (no code import)

- [Lightning Rod Labs Files](https://github.com/lightningrodlabs/files) README describes private/public file delivery, accept/decline, notices, activity and missing-parcel recovery. Its large-file/chunk behaviour is **not** a model for this bounded control mailbox.
- [ddd-mtl Delivery Zome](https://github.com/ddd-mtl/delivery-zome) master README and code expose NORMAL (direct then DHT), DM_ONLY and DHT_ONLY. In the examined master source, commit_pending_item.rs links a PendingItem under a recipient-derived DHT inbox; send_item.rs reports OK_PENDING after publishing; pull_inbox.rs passes PendingItem.author to receive paths. Neither successful publication nor this author field constitutes trustworthy verified sender delivery proof.
- The examined Delivery Zome master Cargo.toml pins HDK **0.2.1** and HDI **0.3.1**, not the Holochain 0.7 stack used by Music; Files references the Delivery API via the older hdk-2.6 branch. API and validation differences require redesign, not a drop-in port. Both upstream projects publish **CAL-1.0** licence notices/files. Using concepts is not copying source; do not import code until counsel/security have reviewed exact CAL obligations, dependency tree and distribution model.

**References:** Music docs/security-model.md §3, §8; Music holochain_music/outbox.py; Music dna/coordinator/src/lib.rs; Media Core docs/architecture.md and docs/threat-model.md (existing ban on DHT encrypted grants); Media Core docs/S2-KEY-LIFECYCLE-V21.md and docs/ACCESS-GRANT-V2.md. The independent test spec must be reviewed against these actual implementations as they evolve.
