# `access-grant/v2`: issuer authority independent of the manifest key

Status: **proposal for review; reviewer decisions of 14 Nov 2026 recorded in
§12. Grant protocol bytes are not implemented; the grant-anchor entry (§3.5,
§4) is being implemented on `feat/grant-anchor-v21` for review.** This
document is the specification and plan; the canonical test vectors (Part 1
of §11) are the first deliverable after review. Builds on S2 v2.1
(`feat/s2-v21-key-lifecycle`, holochain-media-core#4, holochain-music#44).

## 1. Root cause

Two independent places hard-wire *grant issuer = manifest signer*:

| Where | Code | Effect |
|---|---|---|
| Music issuance | `content_grants.issue_content_grant` / `issue_personal_licence` call `_manifest(signed_manifest, public_key_bytes(owner_signer))`, i.e. they re-verify the manifest with **the issuing key** | only the key that signed the manifest can issue for it |
| Music verification | `unwrap_content_grant`: `signer != trusted_artist → "grant not signed by registered artist"`, with `trusted_artist` = the key that verifies the manifest (`library.meta["artist_key_hex"]`) | the grant signer must be the manifest signer |
| Media Core CORE-005 | `verify_stream` / `verify_licence`: `authenticate(&envelope, content.manifest().signer())` | the same rule in Rust |

S1 manifests are immutable and their digest is the content identity (file
commitments, receipts, grants and licences all bind `manifest_sha256`). So
once the artist rotates (S2 v2.1), the only way to issue a new grant for an
old track is to sign it with the rotated key. v2.1 correctly refuses that
(`ArtistService._grant_signer`).

The defect is the *format*: it conflates two different claims.

* **Content authenticity:** "this manifest is the owner's content". This is
  a historical fact, established by the manifest key that was valid when the
  owner committed the manifest.
* **Grant authority:** "the owner authorises *this* listener *now*". This is
  a fresh operation that needs the owner's *current* authority.

`access-grant/v2` makes these separate, independently verified claims.

## 2. Design summary

* The grant is signed by the owner's **active `owner-manifest` lifecycle key
  at issuance**, which may differ from the manifest's key. It names that
  key's generation and transition action.
* Every v2 grant is **anchored on the issuer's own source chain** by a public
  `grant-anchor/v2` record. The anchor commits to the complete signed grant (a domain-separated commitment), so
  verifiers can apply the existing v2.1 chain-ordered policy:
  * a key that was rotated or revoked *before* the anchor cannot have issued
    it;
  * a compromise revocation leaves valid only grants anchored before it.
* The **content** half is the existing v2.1 check
  (`verify_owned_manifest_lifecycle`, anchored at the owner's commitment), so
  historical manifests stay valid and unchanged.
* **Content keys are never re-encrypted.** Grants wrap the existing S1 AES
  key to the listener's X25519 key, as v1 does, under a v2-only HKDF/AAD
  domain.
* **v1 grants and licences stay valid** under exactly their v1 rules and are
  never promoted. v2 is a new schema with a different envelope shape, a
  domain-separated signature and its own verifier.

### Why anchoring is required, not optional

A grant carries only an issuer-claimed `issued_at`. Without a chain anchor a
verifier cannot distinguish:

* a genuine pre-rotation grant from a fresh grant made later with an
  obsolete key (threat 3); or
* a pre-compromise licence from one forged with the stolen key (threat 17).

The alternatives both fail a requirement:

* "issuer must be active at verification time" would void every perpetual
  licence on each routine rotation;
* "accept any historical issuer key" admits threats 3 and 17.

Anchoring gives the same deterministic, timestamp-free ordering already used
for manifests and receipts.

## 3. Records

### 3.1 Grant body `holochain-music/access-grant/v2`

A JSON object. Every value is a string, except the integers `issued_at`,
`not_before` and `expires_at`, and the array `rights`. Exactly these fields
are allowed:

| Field | Rule |
|---|---|
| `schema` | `holochain-music/access-grant/v2` |
| `grant_id` | 32 lowercase hex, random (128 bit), unique per issuer (enforced by the anchor's DNA rule, §4) |
| `dna_hash` | the storage DNA (`uhC0k…`) whose lifecycle and anchor authorise the grant |
| `owner_agent` | content owner (from the commitment); in v2.0 must equal `issuer_agent` |
| `issuer_agent` | Holochain agent authorising the grant |
| `issuer_purpose` | `owner-manifest` (the only purpose v2.0 accepts; a future `grant-issuer` purpose is a new schema) |
| `issuer_key_hex` | issuer's Ed25519 public key (64 lowercase hex) |
| `issuer_key_generation` | canonical decimal, as in v2.1 |
| `issuer_key_action` | action hash of the transition that introduced `issuer_key_hex` |
| `file_id` | S1 package id (64 hex) |
| `manifest_sha256` | SHA-256 of the exact signed S1 manifest (the historical one, unchanged) |
| `manifest_key_hex` | the key that signed that manifest (explicit; checked against the manifest) |
| `listener_agent` | recipient Holochain agent |
| `recipient_key_hex` | recipient X25519 public key (64 hex) |
| `rights` | sorted, duplicate-free, non-empty subset of `["export", "managed-offline", "stream"]` (CORE-005 `Right`) |
| `term` | `perpetual` or `window` |
| `issued_at` | integer Unix seconds (issuer claim, display and skew checks only; never ordering) |
| `not_before` | integer; `perpetual` requires `= issued_at` |
| `expires_at` | integer; `perpetual` requires `0`; `window` requires `not_before < expires_at` and `expires_at - not_before ≤ max_window(rights)` |
| `basis` | `owner-decision` (the only value in v2.0; payment-backed bases are reserved for a later version) |
| `entitlement_ref` | `""`, or 64 hex: opaque reference to an *external* entitlement or purchase record. Not evidence of payment |
| `key_wrap` | `x25519-hkdf-sha256-aes256gcm/v2` |
| `ephemeral_key_hex`, `salt_b64` (16 B), `nonce_b64` (12 B), `wrapped_key_b64` (48 B) | the key wrap, as in v1 |

`max_window` in v2.0:

* rights = `{stream}`: at most 86 400 s, the same as v1 streaming grants;
* any other combination with `window`: **unsupported in v2.0** (rentals and
  subscriptions are representable but refused by the v2.0 policy until
  defined, §7).

`export` requires `term = perpetual`, matching the existing app gate.

### 3.2 Envelope

```json
{"body": { … }, "signature_hex": "<128 lowercase hex>"}
```

There is deliberately **no `signer` field**: the key is `body.issuer_key_hex`
and is authorised only through the lifecycle. Because the shape differs from
v1 (`{body, signer, signature}`), no parser can accept one as the other.

### 3.3 Canonical signature

```text
message   = "holochain-music/access-grant/v2\0" || canonical(body)
signature = Ed25519(issuer key, message)
grant_digest = SHA-256(message)
```

`canonical` is Music's existing canonical JSON: sorted keys, `(",", ":")`
separators, UTF-8, `ensure_ascii=False`, no NaN. It is already ported
byte-for-byte to Rust (`compat::canonical_json`) and tested with and without
`serde_json/preserve_order`.

The NUL-terminated domain prefix means a v2 grant signature can never verify
as any of:

* an S1 manifest or receipt, or a v1 grant or licence (all of which sign bare
  canonical JSON);
* a v2.1 lifecycle proof or a v2 receipt (other domains);
* any other Music signature.

The reverse also holds.

### 3.4 Key wrap

The key wrap is identical to v1 (X25519 ECDH → HKDF-SHA256 → AES-256-GCM)
with:

```text
info = aad = "holochain-music/access-grant/hkdf-aad/v2\0" || canonical(scope)
scope = body minus {ephemeral_key_hex, salt_b64, nonce_b64, wrapped_key_b64}
```

The wrapped key is therefore bound to every authorisation field: issuer key,
generation, rights, term, recipient, package and grant id. Changing any of
them fails AES-GCM even if a signature check were skipped. The content key
itself is the existing S1 key, so there is **no re-encryption**.

### 3.5 Grant anchor `holochain-storage/grant-anchor/v2` (public DHT entry)

The anchor is deliberately minimal. It carries **no** recipient identity, no
track or manifest identifier, no rights, terms, prices or licence details, no
key material, and no transaction data. Exactly these string fields:

| Field | Rule |
|---|---|
| `schema` | `holochain-storage/grant-anchor/v2` |
| `dna_hash` | this DNA (`dna_info().hash`); binds the anchor to one network |
| `grant_id` | 32 lowercase hex: the grant's random 128-bit id (uniqueness scope: per issuer agent, per DNA) |
| `grant_commitment` | 64 lowercase hex: `SHA-256("holochain-storage/grant-anchor-commitment/v2\0" ‖ grant_message)`, where `grant_message` is the exact signed message of §3.3 |
| `issuer_key_action` | action hash of the issuer's `owner-manifest` lifecycle transition whose key signs the grant |

The **issuer is the action author**: there is no agent field to forge or to
disagree with. The key and generation are not repeated, because they follow
from `issuer_key_action` through the author's validated lifecycle.

The commitment is domain-separated and covers the complete signed grant
(including its random `grant_id`, ephemeral key and wrapped key), so it
cannot be inverted or brute-forced to recover the listener, track or rights.
It binds the anchor to exactly one grant, and through `grant_id` the grant
names its anchor's uniqueness slot.

**What remains visible (documented, accepted):** that the issuer authorised
*some* grant, at which position on their chain (and so roughly when), and
with which key generation. Grant issuance **frequency and timing** per artist
are therefore public. This was already true for the public actions of
private inbox entries.

### 3.6 Delivery wrapper (unsigned transport)

```json
{"grant": <envelope>, "anchor_action": "uhCkk…"}
```

This is carried in the existing private inbox `InboxGrant.grant_json`
(≤ 8 KiB; a worst-case v2 grant is 1.54 KiB canonical, 1.63 KiB with the wrapper). `InboxGrant.kind` stays
`stream` or `perpetual-personal`, both already allowed by the shared v1 rule,
and derives from `term` and `rights`. Rentals and subscriptions would need a
new inbox kind, which is a DNA change for a later version.

## 4. DNA rules (conductor-enforced)

**Decision (14 Nov 2026): option A.** `GrantAnchorV2` is added to the
existing `dna-v21` integrity zome before v2.1 is released. The v2.1 DNA hash
changes once, before any deployment; v1 and v2 are untouched. The entry and
link types are appended after the v2.1 types, so earlier type positions do
not move.

Integrity rules for a `GrantAnchorV2` create, deterministic, using the v2.1
chain walk (`must_get_agent_activity` from `prev_action` to genesis,
`must_get_valid_record` for lifecycle and anchor actions only):

1. Exact fields; schema; lowercase-hex lengths for `grant_id` (32) and
   `grant_commitment` (64); `issuer_key_action` non-empty and ≤ 160 B.
2. `dna_hash` == `dna_info().hash`.
3. At this chain position, `issuer_key_action` is the author's **current**
   `owner-manifest` transition (the last one before this action) and that
   transition has **no revocation** before this action. A transition of
   another purpose, of another agent, a superseded one or a revoked one is
   refused.
4. No earlier `GrantAnchorV2` on the author's chain has the same `grant_id`
   (uniqueness scope: author × DNA).
5. Updates and deletes are forbidden (existing rule).

The author is the issuer by construction (rule: the action author). A
`publish_grant_anchor_v2` coordinator function creates the entry and an
`AgentToGrantAnchorV2` link from the author; readers verify by action hash
with `get_grant_anchor_v2`, which also returns the chain position.

**Conductor-enforced** (true of every anchor an honest conductor stores):

* only the content owner's agent (as the author) can anchor a grant under
  their lifecycle; possession of a media key alone cannot;
* the signing generation was current and unrevoked at the anchor's position,
  so a rotated or revoked key cannot anchor a new grant after its authority
  ended;
* grant ids are unique per author and DNA;
* the anchor names this network.

**Not enforceable by the DNA; verifiers (Music and Media Core) must check:**

* that the grant body matches the anchor (`grant_commitment`, `grant_id`,
  `issuer_key_action`), because the grant is private and never on the DHT;
* that the grant signature verifies with the generation's key;
* that the author is the content owner of *this* manifest (the anchor names
  no content);
* the recovery policy (§5 B7): a recovered generation is a legitimate,
  agent-authorised state, so the DNA accepts its anchors and the verifier
  rejects them by default;
* lifecycle completeness and freshness of the reader's view (§5).

Verifiers re-derive rule 3 from the lifecycle in any case (§5 B6), so a
modified conductor that skips validation gains nothing against an honest
reader.

## 5. Verification

Inputs from trusted sources only:

* the reader's own validating conductor: the owner lifecycle records (with
  chain positions), the owner's commitment (with position) and the anchor
  record (with position);
* the subject (listener agent and X25519 key) from the application's own
  context;
* an injected clock.

The issuer, the owner and both keys are taken from **Holochain records**,
never from the grant alone.

### A. Content authenticity (unchanged v2.1 API)

`owned = verify_owned_manifest_lifecycle(manifest, owner_lifecycle,
commitment)`. The manifest's signer must be a generation of the owner's
lifecycle that is valid at the commitment's chain position:

* a rotation does not invalidate it (`HistoricalOnly`);
* a commitment made after its key ended is refused;
* a `compromised` revocation leaves it valid only if the commitment is
  anchored before the key ended.

### B. Grant authority

All of the following must hold, in this order. Each failure is a distinct
typed error.

1. **Parse:** size ≤ 4 KiB canonical; exact v2 envelope and field set; types;
   canonical encodings; `schema` = v2. A v1 document is
   `Unsupported::WrongVersion`, never re-parsed.
2. **Scope against Holochain:**
   * `owner_agent` == `owned.owner_agent()` == `issuer_agent` ==
     `owner_lifecycle.agent()`;
   * the lifecycle purpose is `owner-manifest`;
   * `dna_hash` == the lifecycle DNA;
   * `file_id` and `manifest_sha256` == `owned`;
   * `manifest_key_hex` == the manifest signer;
   * `listener_agent` and `recipient_key_hex` == the subject.
3. **Issuer generation:** `(issuer_key_action, generation, key)` names exactly
   one generation of `owner_lifecycle` (`generation_at`).
4. **Signature:** Ed25519 strict over §3.3 by `issuer_key_hex`.
5. **Anchor:**
   * the anchor record is authored by `issuer_agent`;
   * it has a chain position;
   * `grant_id`, `issuer_key_action` and `dna_hash` match the grant, and
     `grant_commitment` equals the commitment recomputed from the grant
     message (§3.5).
6. **Issuer validity:** `owner_lifecycle.classify(key, Historical { anchor })`
   ∈ {`Active`, `HistoricalOnly`}. An anchor after the key's end yields
   `Rotated` or `Revoked`, and the grant is refused. Unanchored use is never
   evaluated for v2.
7. **Recovery policy:** if the issuer generation's assurance is
   `KeyLifecycleRecoveredV21`, the verifier's explicit
   `RecoveredIssuerPolicy` decides:
   * `Reject` is the default (fail closed);
   * `Accept` returns the decision labelled `issuer_continuity =
     RecoveredWithoutContinuity`.
8. **Terms:**
   * the `term`, `window` and `rights` rules (§3.1);
   * `issued_at ≤ now + 120 s`;
   * for `window`: `not_before ≤ now < expires_at`;
   * the v2.0 policy table (§7).
9. **Key-wrap fields** are well formed (decrypting is the application's job,
   as in CORE-005 today).

The result is a `VerifiedEntitlement` (CORE-005 type) with:

* `scheme = MusicAccessGrantV2`;
* the issuer agent, key, generation, continuity and assurance;
* `grant_id` and the anchor sequence;
* `rights`, the term and the wrapped key;
* `owner_assurance` from `owned`.

`authorize(Right)` is the existing CORE-005 method.

### Authoritative lifecycle state and partial DHT information

The authoritative state is the **reader's own validated conductor view** of
the owner's `get_key_lifecycle_v21` records plus the anchor record. Holochain
guarantees that what it returns has passed validation. It does not guarantee
completeness.

| Reader's view | Outcome |
|---|---|
| anchor not returned | `Unavailable::AnchorNotFound`: retry, never accept |
| lifecycle gap (successor or revocation target missing) | `LifecycleIncomplete`: retry, never accept |
| forked lifecycle | `Ambiguous`: refuse |
| complete, but a later revocation not yet received (stale) | accepted on the current view. This is the documented freshness bound; it applies equally to v1, v2 and v2.1 |
| no network (offline playback) | use the verdict and lifecycle snapshot cached when the grant was accepted online; `window` grants stop at `expires_at` (device clock) |

To shorten the stale window, re-verify online grants at each playback when
connected, and treat any change from `Active`/`HistoricalOnly` to
`Revoked`/`Rotated` as loss of access from that point on.

## 6. Rights model and layers

| Layer | What it is | Where |
|---|---|---|
| Payment or purchase evidence | out of scope; never in the grant | future (CORE-006+); referenced only by the opaque `entitlement_ref` |
| Entitlement | the owner's decision that a listener may have rights R over content C for term T | expressed **by** the signed grant's authorisation fields |
| Cryptographic access grant | the signed, anchored document plus the content key wrapped to the listener | this format |
| Permitted operation | stream, managed offline, export | the app gate via CORE-005 `authorize(Right)` |

The rights vocabulary is exactly CORE-005's `Right` (`stream`,
`managed-offline`, `export`); there is no new rights model. How the existing
grants and future products map onto it:

| Product | v1 today | v2 encoding | v2.0 policy |
|---|---|---|---|
| Artist-issued private stream | `content-grant/v1` (≤ 24 h) | `window`, `{stream}`, ≤ 24 h | supported |
| Permanent personal licence / purchase | `personal-licence/v1` | `perpetual`, `{export, managed-offline, stream}` | supported |
| Perpetual streaming only | — | `perpetual`, `{stream}` | supported |
| Rental (time-limited, possibly offline) | — | `window` with `managed-offline` | **refused** until a rental policy is specified |
| Subscription period | — | `window` per period | **refused** until specified |
| WAV export | licence only | requires `perpetual` and `export` | supported |

**Offline revocation limits.** This is not DRM.

* A wrapped content key already delivered to a device, once unwrapped, gives
  the plaintext; an exported WAV is plaintext. Neither can be recalled.
* Expiry of a `window` grant offline depends on the device clock and an
  honest client.
* Revoking the issuer key stops **new** acceptance of grants anchored after
  the revocation, and (for `compromised`) of unanchored or late artifacts. It
  does not reach content or keys already delivered.
* There is no per-grant revocation in v2.0. A future `grant-revocation` entry
  can reference the anchor.

## 7. Legacy compatibility and downgrade protection

* **Unchanged:** S1 manifests, chunks, receipts and media identifiers; v1
  grants and licences; offline libraries; content keys. No re-signing and no
  re-encryption.
* **v1 grants** verify only through the existing v1 rules (signer == manifest
  signer, both Music and CORE-005). They are labelled
  `EntitlementScheme::MusicContentGrantV1` / `MusicPersonalLicenceV1` and
  never gain v2 issuer authority, so a v1 grant signed by a rotated key stays
  exactly as valid as before. Applications that require v2 for new purchases
  must state so as an explicit policy (`require_scheme`), not by inference.
* **Format negotiation** is by exact `schema` plus envelope shape:
  * the v2 verifier refuses v1 documents (`WrongVersion`);
  * the v1 verifiers refuse v2 documents (the `UnknownSchema` they already
    return);
  * `check_content_access` (v1 API) refuses `access-grant/v2` with
    `Unsupported::RequiresLifecycle` rather than verifying it without issuer
    evidence.
* **Library storage:** one grant per file, as today. The existing "never
  downgrade a perpetual licence" rule still holds:
  * a v2 `perpetual` grant may replace a v1 stream grant;
  * a v1 licence is never replaced by a narrower v2 grant;
  * equal-rights replacements keep the existing entry.
* **Network:** v2 grants require a v2.1 (or v2.2) storage cell. Content
  published on v1 is usable after the owner's v2.1 inception and a
  republished commitment, with the same manifest digest (the S2 v2.1 §9
  migration).

## 8. Threat matrix

C means conductor-enforced; V means verifier-enforced. Every rejection must be
an explicit typed error asserted by tests, never a timeout.

| # | Threat | Stopped by | Expected error |
|---|---|---|---|
| 1 | Forged grant issuer (Mallory's key) | V3: key not in the owner lifecycle | `Unauthenticated::IssuerNotInLifecycle` |
| 2 | Wrong Holochain agent (`issuer_agent` ≠ owner, or anchor by another author) | V2/V5; C (author = issuer) | `Denied::OwnerMismatch` / `Unauthenticated::AnchorMismatch` |
| 3 | Obsolete (rotated) key issues a new grant | C3 (anchor refused); V6 (anchor after end) | integrity "issuer key is not the author's current owner-manifest key"; `KeyRotated` |
| 4 | Revoked key issues a new grant | C3; V6 | integrity refusal; `KeyRevoked` |
| 5 | Wrong signing generation (key/generation/action mismatch) | V3; C3 | `Unauthenticated::IssuerGenerationMismatch` |
| 6 | Wrong media manifest | V2 (digest, `manifest_key_hex`); key-wrap AAD | `Denied::ManifestMismatch` |
| 7 | Modified rights or term | V4 signature; AAD | `Unauthenticated::InvalidSignature` |
| 8 | Wrong recipient | V2 | `Denied::ListenerMismatch` / `RecipientKeyMismatch` |
| 9 | Cross-DNA or cross-network replay | V2 (`dna_hash`); C (anchor `dna_hash`); lifecycle DNA | `Denied::NetworkMismatch` |
| 10 | Grant id reuse, malicious replay | C4 (unique per issuer and DNA); V5 (anchor commitment == recomputed grant commitment); same grant to the same listener is idempotent | integrity refusal; `Unauthenticated::AnchorMismatch` |
| 11 | Forged lineage (fake rotation, predecessor) | v2.1 DNA and reader lifecycle rules | `Ambiguous` / `Invalid` / `LifecycleIncomplete` |
| 12 | Unauthorised recovered key | V7 default `Reject` | `Unauthenticated::RecoveredIssuerRefused` |
| 13 | Signature for another purpose (host key, receipt, lifecycle proof, v1 grant) | domain prefix; `issuer_purpose`; lifecycle purpose | `InvalidSignature` / `IssuerNotInLifecycle` |
| 14 | Grant for another encrypted package | V2 `file_id`; AAD | `Denied::FileMismatch` |
| 15 | Expired, not-yet-valid or unsupported terms | V8 | `Validity::Expired` / `NotYetValid` / `Unsupported::Terms` |
| 16 | Conflicting or ambiguous lifecycle history | reader lifecycle | `Ambiguous` (never first- or latest-match) |
| 17 | Issuance after a compromise without authorisation | C3 (a revoked key cannot anchor); V6 | integrity refusal; `KeyRevoked` |
| 18 | Legacy rules used to bypass v2 | exact schema and shape dispatch; no promotion | `Unsupported::WrongVersion` / `RequiresLifecycle` |
| + | **Legitimate:** Alice rotates g1→g2, issues a v2 grant for a g1 track | A (`HistoricalOnly` manifest) + B (`Active` issuer, anchored) | `Ok`, scheme v2, issuer generation 2 |

## 9. Changes required, by interface

**Music**

* `music_catalogue/content_grants.py`:
  * add `issue_access_grant_v2` and `unwrap_access_grant_v2`, which separate
    `trusted_manifest_key` from the issuer verified through the lifecycle;
  * v1 functions unchanged;
  * `grant_kind` recognises v2.
* `holochain_storage/key_lifecycle.py`: `make_grant_anchor`.
* `dna-v21` (option A) integrity/coordinator: the `GrantAnchorV2` type,
  validation, `publish_grant_anchor_v2` and `get_grant_anchor_v2`.
* `holochain_music/artist.py`: under v2.1, `grant()` issues v2 with the active
  key and an anchor; refuses when no key is active; never uses a rotated key.
* `holochain_music/app.py`: `sync_grants`, playback, `offline_readiness` and
  `export_wav` dispatch by scheme. For v2 they verify A and B through
  CORE-005-equivalent Python checks, then unwrap. Without v2.1, v2 grants are
  refused.
* `holochain_music/library.py`: grant-kind ordering covers v2; the v2.1
  lifecycle snapshot is stored for offline re-verification.
* `music-e2e` bridge routes for the anchor.

**Media Core**

* `entitlements.rs`:
  * `EntitlementScheme::MusicAccessGrantV2`;
  * `verify_access_grant_v2(...)` and `check_content_access_v2(...)`;
  * new typed errors; `RecoveredIssuerPolicy`;
  * issuer fields on `VerifiedEntitlement`.
* `lifecycle.rs`: public `generation_at`.
* `content-retrieval` `MetadataSource::grant_anchor(action)`.
* `content-holochain`: `get_grant_anchor_v2` in `READ_FUNCTIONS_V21`.
* `scripts/generate_music_access_grant_v2_vectors.py` and testdata.

## 10. Real-agent acceptance design

`integration/core-e2e/tests/access_grant_v2.rs`: disposable conductors on the
anchor-enabled DNA, Music's real MoQ host, and Music's Python for every
grant, anchor and decryption.

| Step | Assertion | Kind |
|---|---|---|
| 1 | Alice incepts g1, publishes encrypted track T (manifest by g1), commits it | conductor |
| 2 | Alice issues Bob a v2 grant with g1 and anchors it; Bob verifies A + B and decrypts | verifier |
| 3 | Alice rotates to g2 | conductor |
| 4 | T's manifest bytes and digest are unchanged; Carol's A check gives `HistoricalOnly` | verifier |
| 5 | Alice issues **Carol** a v2 grant for T with g2 and anchors it | conductor accepts the anchor |
| 6 | Carol verifies A (g1, historical) and B (g2, `Active`) independently | verifier |
| 7 | Carol retrieves authenticated ciphertext over MoQ into VerifiedCas | real MoQ |
| 8 | Carol unwraps and decrypts with Music; plaintext SHA-256 matches; CORE-005 `authorize(Stream)` | Music + CORE-005 |
| 9 | Mallory: forged issuer, relabelled agent, replay to another listener, cross-DNA, modified rights, foreign anchor, reused grant id | each a named typed error or integrity refusal |
| 10 | g1 signs a fresh grant after rotation: its anchor is refused by integrity; an unanchored delivery is refused by the verifier | conductor + verifier |
| 11 | Alice revokes g2 (`compromised`); g2 anchor attempts are refused; Carol's pre-revocation grant: per policy (anchored before → still valid) | conductor + verifier |
| 12 | Bob's step-2 grant (g1, anchored before rotation) stays valid with exactly its rights; `export` refused for a stream-only grant | verifier |
| R | Alice loses g2 and recovers to g3: g3 grants are refused under `Reject` and accepted, labelled, under `Accept` | verifier policy |
| D | Bob's conductor cannot see the anchor yet: `AnchorNotFound` (never accept); after settle, accepted | partial DHT |
| L | A v1 licence for T stays valid under v1 rules; it is not accepted by the v2 verifier and not promoted | legacy |

Fails closed: every critical rejection is asserted by its exact error or
integrity message, never by a timeout or a broken connection. The suite runs
alone, never concurrently with other conductor suites.

## 11. Implementation plan

All work happens on new branches stacked on `feat/s2-v21-key-lifecycle`, so
the reviewed v2.1 PRs are untouched. No grant bytes change until Part 1 is
approved.

| Part | Repo / branch | Scope | Depends on | Tests and acceptance | Main risks |
|---|---|---|---|---|---|
| 1. Spec and vectors | Media Core `feat/access-grant-v2-spec` (this doc) + Music `feat/access-grant-v2-reference` | finalise §3–§8; Music reference `issue_access_grant_v2`/`make_grant_anchor` (Python only, behind no app path); generator producing grants, anchors, AAD and digests plus Music's verdict for every §8 case | review of this doc | byte-exact messages; ≥ 1 vector per threat; deterministic parts reproducible in CI | ambiguity in canonical JSON for integers and arrays; mitigated by explicit vectors |
| 2. Anchor in the DNA | Music + Media Core `feat/grant-anchor-v21` | `GrantAnchorV2` in `dna-v21` (option A, decided); integrity rules 1–5 of §4; coordinator routes; Python and Rust anchor verifiers; anchor conductor tests | 1 (anchor fields only) | integrity unit tests; v1/v2 hashes unchanged; new hash recorded | DNA hash change; re-run the v2.1 suite |
| 3. Media Core verifier | Media Core `feat/access-grant-v2-verify` | `verify_access_grant_v2`, typed errors, `RecoveredIssuerPolicy`; v1 paths untouched | 1 | vectors: Rust verdict = Music verdict for every case; mutation sweep; `preserve_order` | treating any v1 field as v2 authority; mitigated by exact-shape dispatch |
| 4. Interop and CORE-005 | Media Core, same branch | `check_content_access_v2`; retrieval anchor lookup; resolver read set | 2, 3 | CI regenerates the vectors from the pinned Music commit; parity 100 % | pinned commit must be reachable (push Music first) |
| 5. Real-agent acceptance | Media Core `feat/access-grant-v2-e2e` | §10 suite | 2–4 | all steps pass twice, no concurrent suites | flakiness; only explicit errors count |
| 6. App integration (opt-in) | Music `feat/access-grant-v2-app` | `ArtistService.grant` v2 under v2.1; app dispatch by scheme; library ordering; offline snapshot | 2, 3 | full unittest; v1 behaviour byte-identical with v2.1 disabled; export/offline gates | accidental downgrade of a v1 licence; tested |
| 7. Migration and rollout | both, docs plus flags | default stays v1; v2 grants only with `key_binding="v2.1"`; rollback = issue v1 grants (still valid for content whose manifest key is active) | 1–6 | rehearsal on disposable conductors | users on mixed versions: v1 clients refuse v2 grants explicitly |

Release gates:

* external review of §3–§5;
* Windows CI and hosted Media Core CI (currently blocked by billing);
* a two-device run;
* **no default switch** until the gates pass.

## 12. Reviewer decisions (14 Nov 2026)

1. **Option A:** `grant-anchor/v2` goes into the existing `dna-v21` before
   release; no `dna-v22`.
2. **Recovered issuers:** new grants signed by a
   `RecoveredWithoutContinuity` generation are **rejected by default**
   (`RecoveredIssuerPolicy::Reject`); `Accept` is an explicit, labelled
   opt-in.
3. **Rentals and subscriptions:** policy implementation is deferred. The
   format (`term = window`, `rights`, `basis`, `entitlement_ref`) stays
   compatible with a future hybrid model of purchases, rentals and
   subscriptions, which will be a reviewed policy version, not a format
   change.
4. **Public anchors:** allowed, with minimised metadata (§3.5): no recipient
   identity, plaintext licence details, content keys or unnecessary
   transaction data. Issuance frequency and timing remain visible and are
   documented as such.
