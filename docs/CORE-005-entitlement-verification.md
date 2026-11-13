# CORE-005 — Shared entitlement verification

Status: **technical milestone, pre-release, not production.** Built on CORE-004
(`ccr-53e220c1-45x2cc` @ 4989ee4). Music reference: `bd7aabc` (the
`content_grants.py` at Music's CORE-004 integration branch 5d37b76 is
identical).

CORE-005 adds `holochain_content_core::entitlements`: a pure-Rust,
I/O-free verifier for Holochain Music's existing signed grants and licences,
callable by any application that has a CORE-004 `OwnedManifest`. It does not
issue grants, unwrap keys, decrypt, or change Music behaviour.

## 1. What `Authorized` means

```text
Holochain identity ─► OwnedManifest (CORE-004: owner key binding + commitment + S1 signature)
                              │
signed grant bytes ──────────►│  CORE-005 check_content_access     ◄── AuthenticatedSubject
                              │  (schema, issuer signature, owner,      (local conductor agent +
                              │   file, manifest, listener, X25519       own X25519 public key)
                              │   recipient key, time, terms, right)  ◄── now: SystemTime
                              ▼
                     AccessDecision (policy level)
                              │
          application unwrap: X25519 + HKDF-SHA256 + AES-256-GCM  (needs private key)
                              │
          per-chunk SHA-256 (VerifiedCas) + AES-GCM chunk decrypt
                              ▼
                     authorised plaintext playback / export
```

`Ok(AccessDecision)` certifies: a supported schema; Ed25519 (`verify_strict`)
signature over Music's canonical body by the **owner's Holochain-bound
`owner-manifest` key**; `owner_agent`, `file_id` and `manifest_sha256` equal
to the authenticated content; `listener_agent` and `recipient_key_hex` equal
to the authenticated subject; validity at `now`; licence terms understood;
the requested right conferred; and well-formed wrapped-key fields.

It does **not** certify that the wrapped key decrypts (only the recipient's
private key can show that — an owner-signed grant with a corrupted wrapped key
or low-order ephemeral key is `Authorized` here and rejected by Music's
AES-GCM unwrap; both cases are in the vectors), nor payment, nor current
availability of the ciphertext from any host. `VerifiedCas` is unchanged and
never sees a key.

## 2. API

```rust
use holochain_content_core::entitlements::*;

let subject = AuthenticatedSubject::from_trusted_context(my_agent, my_x25519_public)?;
let decision = check_content_access(&owned, &subject, grant_bytes, Right::Export, SystemTime::now())?;
let wrapped = decision.entitlement().wrapped_content_key(); // ephemeral, salt, nonce, wrapped, context
// application unwraps with its X25519 private key, then decrypts verified ciphertext
```

| Item | Purpose |
|---|---|
| `check_content_access(content, subject, bytes, right, now)` | Full decision for one right. |
| `verify_entitlement(content, subject, bytes, now)` → `VerifiedEntitlement` | Same checks without a right; `.rights()`, `.authorize(right)`. |
| `AuthenticatedSubject::from_trusted_context(agent, x25519_public)` | Listener from the app's own conductor + own key. Never from the grant. |
| `EntitlementScheme` (`#[non_exhaustive]`) | `MusicContentGrantV1`, `MusicPersonalLicenceV1`; `.rights()`, `.expires()`, `from_schema`. |
| `VerifiedEntitlement` | scheme, owner/listener agent, package, manifest digest, `issued_at`, `expires_at` (`None` = non-expiring), `licence_id`, `WrappedContentKey`. Only constructible by the verifier. |
| `WrappedContentKey::context()` | Music's HKDF `info` / AES-GCM AAD, byte-identical to Python `_context` / `_licence_context` (tested). |
| `AccessError` | typed, see §6. |

The owner key is **only** `OwnedManifest::manifest().signer()` (the key
CORE-004 authenticated from the owner's Holochain `owner-manifest` binding);
the grant's `signer` field is merely compared with it. There is no API that
accepts an issuer key from the caller or from the grant.

CLI (`holochain-media-core check-access`) and Music adapter
(`media_core_adapter.check_access`) expose the same check; see §8.

## 3. Supported schemas

| Schema | Status |
|---|---|
| `holochain-music/content-grant/v1` | Verified (exact 12-field body). |
| `holochain-music/personal-licence/v1`, terms `perpetual-personal-use` | Verified (exact 13-field body). Other terms → `Unsupported(LicenceTerms)`. |
| `holochain-music/personal-perpetual-grant/v1` | **Recognised and rejected** as `Unsupported(LegacyPerpetualGrant)`. |
| anything else | `Unsupported(UnknownSchema)`; missing schema → `Malformed(Structure)`. |

**Legacy `personal-perpetual-grant/v1`** (`holochain_storage/grant.py`) is used
only by the S1 storage prototype (`holochain_storage/demo.py`, the package
`__init__` re-export, `tests/test_encrypted_storage.py`,
`tests/test_storage_validation.py`, `docs/storage-prototype-quickstart.md`).
The Music app never issues, stores or accepts it (`unwrap_content_grant`
rejects it). It binds only a buyer X25519 key — no owner agent, no listener
agent, an ISO-8601 `granted_at`, a different HKDF construction — so treating it
as equivalent to `personal-licence/v1` would grant rights without a Holochain
listener binding. It belongs in a separate, explicitly scoped compatibility
increment if any real user data in that format is ever found.

## 4. Permission mapping (Music app gates at bd7aabc)

| Scheme | `Stream` | `ManagedOffline` | `Export` | Music source |
|---|---|---|---|---|
| `content-grant/v1` | ✔ | ✘ | ✘ | `_session_for` accepts any verified grant; `download()`, `_offline_readiness_impl`, `_export_wav_impl` require `grant_kind == "perpetual-personal"` |
| `personal-licence/v1` | ✔ | ✔ | ✔ | same gates; licensed offline playback and WAV export |

New offerings (rentals, subscriptions, public, commercial terms) must be new
`EntitlementScheme` variants with their own rights; existing variants never
change meaning.

## 5. Time semantics (identical to Music)

`now` is injected (`SystemTime`), floored to whole seconds like
`int(time.time())`; a pre-epoch clock is `Unavailable(Clock)`.

* Streaming grant: `issued_at` and `expires_at` must be JSON integers in
  `i64` range (bool/string/null → `InvalidTimestamp`, floats →
  `Malformed(NonCanonicalNumber)`); `issued_at > now + 120` → `NotYetValid`;
  `expires_at <= now` → `Expired` (no grace after expiry, as in Music);
  `expires_at − issued_at ∉ 1..=86400` → `InvalidPeriod`.
* Personal licence: **no expiry**; only `issued_at > now + 120` →
  `NotYetValid`. Any past integer is accepted (Music accepts `issued_at = 0`;
  vector `licence_epoch_issued_at_parity`).

## 6. Error classification

| Category | Reasons | Meaning |
|---|---|---|
| `malformed` | `TooLarge`, `Json`, `Structure`, `NonCanonicalNumber`, `RecipientKey`, `EphemeralKey`, `LicenceId`, `KeyEnvelope` | not a well-formed document (incl. unknown/duplicate/missing fields) |
| `unauthenticated` | `WrongIssuer`, `MalformedIssuerKey`, `MalformedSignature`, `InvalidSignature` | not issued by the authenticated owner |
| `unsupported` | `UnknownSchema`, `LegacyPerpetualGrant`, `LicenceTerms` | not understood; never access |
| `denied` | `OwnerMismatch`, `FileMismatch`, `ManifestMismatch`, `ListenerMismatch`, `RecipientKeyMismatch`, `RightNotGranted` | authentic but not for this request |
| `validity` | `NotYetValid`, `Expired`, `InvalidPeriod`, `InvalidTimestamp` | authentic but outside its period |
| `unavailable` | `Clock`, `OwnerKey` | authoritative input unusable |

The evaluator performs no I/O, so a timeout or missing host can never appear
as a denial or expiry; CORE-004 transport errors remain `Unavailable` in
`content-retrieval`.

Check order: raw size (16 KiB, Music `Library.grant()` limit) → JSON →
schema → strict fields → canonical envelope ≤ 4096 B → signer/signature →
owner → file → manifest → listener → recipient key → ephemeral key → time →
licence terms/ID → wrapped-key encodings → right.

## 7. Python compatibility

`scripts/generate_music_entitlement_vectors.py` imports Music at the pinned
commit and produces every grant with Music's own `issue_content_grant`,
`issue_personal_licence`, `create_perpetual_grant` or (for owner-signed
invalid bodies) `_sign`; Music's verdict for every case comes from its own
`json.loads` + `unwrap_content_grant` (+ the `app.py` gate) at the case clock.
Only `time.time` is patched. A run is committed as
`crates/content-core/testdata/music-entitlement-vectors.json` (synthetic keys
only) so `cargo test` covers it on every platform; CI regenerates fresh
vectors and reruns the tests (`MUSIC_ENTITLEMENT_VECTORS`), with and without
`serde_json/preserve_order`.

81 cases: 13 authorised by both, 62 rejected by both (each for the expected
reason), and 6 **documented divergences**, each asserted by the tests:

| Divergence | Cases | Why |
|---|---|---|
| `key-unwrap-boundary` | corrupted wrapped key; low-order ephemeral key (owner-signed) | Rust authorises the policy; Music's unwrap rejects. Intended boundary (§1). |
| `rust-rejects-duplicate-json-keys` | duplicate body key (signed value last); duplicate envelope key | Python `json.loads` keeps the last value; Rust refuses ambiguous JSON. Music never writes duplicates. |
| `rust-caps-raw-input-at-music-library-read-limit` | 16 KiB+ whitespace-padded valid grant | Music's `Library.grant()` refuses > 16 KiB too; `unwrap_content_grant` alone does not. |
| `python-accepts-out-of-range-licence-issued-at` | licence with `issued_at = -10^19` | serde_json reads it as a float; Rust refuses non-canonical numbers. Only an owner could sign it; Music's issuer cannot produce it from a real clock. |

All rejected-by-both cases are also rejected for the expected reason. Base64
matches Python `b64decode(validate=True)` (non-zero trailing bits accepted,
padding required, no whitespace) — vector `signer_field_noncanonical_base64_parity`.

Existing Music grants and licences remain valid: the verifier accepts exactly
what Music's issuer produces and no Music file is changed.

## 8. Integration surfaces

* **Rust**: `check_content_access` after `content-retrieval::authenticate_content`
  (or `binding::verify_owned_manifest`); no MoQ connection needed.
* **CLI**: `holochain-media-core check-access --bridge-json F --manifest F
  --owner-agent A --grant F --listener-agent A --recipient-x25519-hex H
  --right stream|managed-offline|export [--now SECS]`. Exit 0 `authorized`;
  2 with `boundary: "entitlement"` + `category`/`reason` (or `s2-binding`);
  1 usage/I/O. No option takes a private key.
* **Music** (branch `claude/core-005-entitlements-i7zm0e`, based on its
  CORE-004 branch): `holochain_storage/media_core_adapter.check_access`, disabled
  unless `HOLOCHAIN_MEDIA_CORE_BIN` is set; `tests/test_media_core_entitlements.py`
  compares both implementations on Music-issued material. Music's issuance,
  unwrap, playback and export paths are unchanged.
* **Real services**: `integration/core-e2e/tests/core004_acceptance.rs` now
  runs the Rust check on Holochain-resolved content (real conductors, real
  agents) for Music-issued grants before Music's unwrap/decrypt (`[core005]`
  log line): licence → stream/offline/export; stream → stream only; Mallory
  with Bob's licence, Bob with Mallory's licence, wrong X25519 key, forged
  issuer, expired grant (injected clock).

## 9. Trust assumptions and limitations

* **Owner identity** is as strong as CORE-004's S2 binding. Bindings are not
  proof of possession (CORE-004 finding 2): Mallory can bind Alice's public
  key and claim Alice's package. CORE-005 limits the damage — Alice's grants
  name `owner_agent = Alice`, so under Mallory's attribution they are
  `Denied(OwnerMismatch)`, and Mallory cannot sign any (test
  `unproven_key_binding_cannot_turn_alices_grants_into_mallorys`). Fixing the
  binding needs a versioned S2 v2 with signed proof of possession; no DNA
  migration was made here.
  **Update (S2 v2):** on the v2 storage DNA the owner key is bound with proof
  of possession; `VerifiedEntitlement::owner_assurance()` reports it and
  `check_content_access_requiring(.., BindingAssurance::ProofOfPossessionV2)`
  refuses legacy owners (docs/S2-KEY-BINDING-V2.md).
* **Listener identity** is supplied by the application. The library cannot
  prove a string came from the local conductor; `from_trusted_context` is the
  documented contract (as for `ConductorRecord`).
* **Recipient key binding**: Music has no Holochain binding of a listener's
  X25519 key; the owner must authenticate it out of band before issuing. The
  verifier checks the grant is addressed to the key the subject holds.
* Music uses one Ed25519 key for manifests and grants (`owner-manifest`
  purpose); there is no separate grant-issuer purpose or key rotation.
* No revocation: a valid licence is permanent and a streaming grant lasts
  until expiry; offline expiry depends on the device clock.
* Ephemeral keys are not checked as curve points (unwrap does).
* Grants are wrapped-key material for one recipient; they are passed to the
  local CLI but never to Holochain, MoQ or storage.

## 10. Not implemented (explicitly)

Public content (needs an authenticated publication/access policy — never
inferred from a missing grant; CORE-006), rentals, subscriptions, payment
settlement, commercial terms, revocation, key rotation, grant issuance in
Rust, key unwrap in Rust, the legacy perpetual-grant format, and any switch of
a Music production path.

## 11. Evidence (this session, 13 Nov 2026)

Exact commands and before/after counts: `docs/current-state.md`. Summary:
root workspace 54 tests pass with and without `serde_json/preserve_order`
(core interop 54 with fresh Python vectors); real five-conductor acceptance
passes with the CORE-005 checks; Music full regression 428 OK / 34 skipped
with the adapter enabled. Windows CI not run.

### Reproduce

```bash
python -m venv .venv && .venv/bin/pip install 'cryptography==46.0.4'
.venv/bin/python scripts/generate_music_entitlement_vectors.py \
  --music-repo ../holochain-music --output target/music-entitlement-vectors.json   # Music @ bd7aabc
MUSIC_ENTITLEMENT_VECTORS=target/music-entitlement-vectors.json \
  cargo test -p holochain-content-core --all-targets
MUSIC_ENTITLEMENT_VECTORS=target/music-entitlement-vectors.json \
  cargo test -p holochain-content-core --all-targets --features serde_json/preserve_order

# Music comparison (Music branch claude/core-005-entitlements-i7zm0e)
cargo build --release -p holochain-content-cli
HOLOCHAIN_MEDIA_CORE_BIN=$PWD/target/release/holochain-media-core \
  python -m unittest -v tests.test_media_core_entitlements      # run inside holochain-music
```
