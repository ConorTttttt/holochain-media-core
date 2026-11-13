# S2 key-binding v2 — proof of possession

Status: **implemented for a separate, opt-in v2 storage DNA; pre-release; not
deployed; no user data migrated.** Built on CORE-005 (`5f7adf5`).

| Repository | Branch | Contents |
|---|---|---|
| holochain-music | `feat/s2-key-binding-v2` (from `claude/core-005-entitlements-i7zm0e`) | `dna-v2/` (v2 DNA), Python v2 functions, opt-in artist registration, bridge routes, tests |
| holochain-media-core | `feat/s2-key-binding-v2` (from `claude/core-005-entitlements-i7zm0e`) | v2 verification, assurance levels, retrieval policy, CORE-005 assurance, real-conductor suites |

## 1. The original vulnerability

Music's v1 entry `holochain-storage/key-binding/v1` is
`{schema, agent, purpose, signing_key_hex}`. Its integrity rule checks that
`agent` is the action author and that the fields are well-formed. It never
checks that the author controls the private key behind `signing_key_hex`, so
any agent can bind *someone else's* public key (CORE-004 finding 2):

* Mallory binds Alice's artist key and commits Alice's package as hers:
  readers authenticate Alice's ciphertext under Mallory's attribution.
* Mallory binds Carol's host key and claims Carol's receipt: she appears as an
  authenticated host for content she never stored.

Ciphertext integrity was never affected (every object is hash-verified
against the owner-signed manifest), and decryption still needs the owner's
grant. CORE-005 already showed Alice's grants cannot be re-attributed. The
damage is to **identity assurance**: attribution, discovery and host
accounting.

## 2. Threat model

Attacker: any agent on the DHT (Mallory) who can author entries and call any
coordinator function, or bypass the coordinator and craft entries directly;
who can copy any public record, including other agents' proofs; and who
controls her own signing keys only. Out of scope: compromise of a victim's
private key, Holochain/Lair implementation flaws, and the v1 network (which
keeps its documented weakness).

Goal: a stored binding `(agent, purpose, key)` on the v2 network implies the
agent authored it **and** the holder of `key` signed this exact
`(DNA, agent, purpose, key, generation)` statement.

## 3. v2 schema

`holochain-storage/key-binding/v2` (all fields strings, exact field set):

| Field | Rule |
|---|---|
| `schema` | `holochain-storage/key-binding/v2` |
| `dna_hash` | the `uhC0k…` hash of the DNA validating it (`dna_info()`), ≤ 160 B |
| `agent` | equals the action author's `AgentPubKey` string |
| `purpose` | `owner-manifest` or `host-receipt` |
| `signing_key_hex` | 64 lowercase hex (Ed25519 public key) |
| `generation` | `"1"` (reserved for rotation; nothing else accepted in v2.0) |
| `proof_signature_hex` | 128 lowercase hex: Ed25519 signature by `signing_key_hex` over §4 |

Entry type `SigningKeyBindingV2` and link type `AgentToKeyV2` are appended
after the v1 types. Coordinator: `key_binding_v2_context` (returns the DNA
hash and agent the client must sign for), `register_signing_key_v2`
(deliberately check-free; validation decides), `get_signing_keys_v2`.

## 4. Proof-of-possession message and canonical encoding

```text
"holochain-storage/key-binding-pop/v2\0"
|| u32be(len(schema))          || schema
|| u32be(len(dna_hash))        || dna_hash
|| u32be(len(agent))           || agent
|| u32be(len(purpose))         || purpose
|| u32be(len(signing_key_hex)) || signing_key_hex
|| u32be(len(generation))      || generation
```

Fixed field order, UTF-8 bytes, 4-byte big-endian length prefixes: injective
(no two field tuples give the same bytes), no JSON escaping or key-order
questions, trivially identical in Rust (`binding::key_binding_v2_message`),
the integrity zome (`v2.rs`) and Python (`holochain_identity.key_binding_v2_message`).
Byte equality is tested against Music's Python output (`message_hex` vector).

## 5. Domain separation

The NUL-terminated prefix `holochain-storage/key-binding-pop/v2` is used for
nothing else. Music's other Ed25519 uses sign canonical JSON objects (S1
manifests, receipts, S10 grants/licences — bytes starting with `{`), and
grant HKDF contexts use `holochain-music/…` prefixes. A binding proof can
therefore never be a valid manifest, receipt or grant signature, nor the
reverse. Each field in the message prevents one substitution:

| Bound | Attack prevented | Test |
|---|---|---|
| agent | Mallory reuses Alice's proof for her own agent | C |
| purpose | owner-manifest proof used as host-receipt | D |
| key | key swapped after signing | F |
| DNA hash | proof made for another network/app replayed here | E |
| schema + generation | cross-version / future-rotation replay | G |

## 6. Holochain validation

`dna-v2/integrity` validates every `SigningKeyBindingV2` create
deterministically: author == `agent`; exact fields (serde
`deny_unknown_fields`; missing/extra fields cannot be decoded at all);
schema; `dna_hash == dna_info().hash` and ≤ 160 B; purpose; generation;
lowercase-hex key and signature lengths; then `verify_signature_raw` (HDI →
Holochain host → Lair `verify_detached`, libsodium) over §4. No network reads,
no clock. A host error is treated as invalid. v1 `SigningKeyBinding` creates
are rejected on this DNA. Updates/deletes stay forbidden (append-only), and
`AgentToKeyV2` links obey the existing agent-link rule. All other v1 rules are
byte-identical (guarded by the `v1_rules_unchanged` test).

## 7. DNA compatibility

The v1 DNA (`holochain-music/dna/`) is **untouched**. Measured with
Holochain 0.7.0 `hc-dna` and Rust 1.97 / wasm32:

| DNA | Integrity wasm SHA-256 | DNA hash |
|---|---|---|
| v1 `music_storage` (unchanged; rebuilt and compared) | `cf75c4bda7100b62…` | `uhC0kkLUOg2uytGWLz_sTeVtfJBqa0criBmAYAPwAIUhoDp_9G4RV` |
| v2 `music_storage_v2` | `22e74d3d6a53ba8a…` | `uhC0k_-f-D4bF9w53gD2jXkA4RqYQ_bf0dRdF8rMkJG_tS8WGRamb` |

Finding during implementation: even *declaring* a cargo feature on the v1
crates (or shifting source lines, which `wasm_error!` embeds) changes the v1
wasm and DNA hash. v2 is therefore a separate workspace (`dna-v2/`) with its
own crates, a copied `Cargo.lock` (identical dependency versions) and the
unchanged v1 coordinator source compiled via `#[path]`.

v2 is a **different network**. Records on v1 never appear on v2; nothing is
migrated automatically. S1 packages, S1 receipts, file commitments and
grants/licences are not DNA entries of the binding and are unchanged.

## 8. Key purposes

`owner-manifest` (signs S1 manifests and, in Music, S10 grants/licences) and
`host-receipt` (signs S1 replica receipts). A proof is valid for exactly one
purpose. New purposes (for example a separate grant-issuer key) need a new,
versioned schema, not a new string in v2.

## 9. Assurance levels (Media Core API)

```rust
pub enum BindingAssurance { LegacyAuthoredV1, ProofOfPossessionV2 }   // ordered
pub enum KeyBindingPolicy { LegacyV1, ProofOfPossessionV2 { dna_hash } }
pub struct VerifiedKeyBinding { /* private; only verifiers construct it */ }
verify_key_binding_v1(record, agent, purpose)             -> VerifiedKeyBinding (legacy)
verify_key_binding_v2(record, agent, purpose, dna_hash)   -> VerifiedKeyBinding (PoP)
resolve_signing_key(records, agent, purpose, &policy)     -> VerifiedKeyBinding
require_proof_of_possession(&binding)                     -> Ok | InsufficientAssurance
verify_owned_manifest_with_key / verify_replica_claim_with_key
OwnedManifest::owner_assurance(), AuthenticatedReplica::node_assurance()
content_retrieval::resolve_content_with(.., &policy)
entitlements::check_content_access_requiring(.., BindingAssurance::ProofOfPossessionV2)
VerifiedEntitlement::owner_assurance()
```

Existing APIs (`key_for_agent`, `verify_owned_manifest`, `resolve_content`,
`check_content_access`) keep their behaviour and report
`LegacyAuthoredV1`. Assurance flows only from verification; there is no
setter, and an `OwnedManifest` built from a v1 binding can never satisfy
`check_content_access_requiring(.., ProofOfPossessionV2)`
(`Unauthenticated::InsufficientOwnerAssurance`).

Resolution policy (Media Core and Music's `resolve_signing_key`):
* a policy reads exactly one schema; v2 never consults v1, so a missing or
  broken v2 binding can never downgrade;
* every record of that schema for the agent/purpose must verify — an invalid
  one is an error, not skipped;
* identical keys (duplicate registrations) resolve to that key; different keys
  are `Ambiguous`; none is `MissingRecord`;
* no timestamp, first-match or latest-match rule.

The conductor resolver gains an explicit `key_binding_v2` mode with its own
least-privilege read set (`READ_FUNCTIONS_V2`) and exposes the cell's DNA
hash for the policy.

## 10. Legacy compatibility

* v1 network: unchanged DNA, unchanged behaviour, still vulnerable as before;
  readable through `KeyBindingPolicy::LegacyV1` and labelled legacy.
* v2 network: v1 bindings refused by integrity.
* Music app default is still v1 (`ArtistService(key_binding="v1")`); v2 is an
  explicit opt-in and Music's catalogue resolution path still reads v1 (its
  v2 switch is CORE-007 work).
* S1 manifests, receipts and CORE-005 grants/licences verify unchanged; the
  v2 acceptance run verifies the same Music-made packages, grants and
  licences end-to-end.

## 11. Rotation and revocation — **implemented in v2.1 (docs/S2-KEY-LIFECYCLE-V21.md); the proposal below is kept as the original design record**

Implemented: only generation `"1"`; one key per agent and purpose; conflicts
are `Ambiguous`, so a second key makes the agent unresolvable rather than
silently switching. That is the safe default until rotation exists.

Proposed `key-binding/v2.1` (separate review):
1. Rotation entry `{agent, purpose, generation n+1, new key, predecessor
   action hash, proof by new key, continuity signature by the predecessor
   key}` over a distinct domain.
2. Integrity uses `must_get_agent_activity` on the author's own chain (a
   deterministic, validated read) to require that the predecessor is the
   author's current binding for that purpose and that no other successor
   exists (no forks).
3. Lost key: a successor without a continuity signature is accepted only as a
   new assurance level (`RecoveredWithoutContinuity`); readers decide.
4. Revocation entry signed by the agent (and, when available, the key):
   readers stop accepting the key for *new* operations; historical
   manifests, receipts and licences remain verifiable against the key that
   was current when they were made; exported plaintext cannot be recalled.
5. "Current key" is defined by chain order from validated agent activity,
   never by wall-clock timestamps.

## 12. Host receipt attribution — **implemented in v2.1 as `replica-receipt/v2` (docs/S2-KEY-LIFECYCLE-V21.md)**

S1 receipts (`replica-receipt/v1`) still do not name the host agent. With v2,
a host key is now provably the host agent's, so Mallory can no longer bind
Carol's key and replay Carol's receipt (refused at registration). A receipt
still does not by itself say *which* agent's custody it attests, and it is not
proof of ongoing storage. Proposed `replica-receipt/v2` (separate schema,
separate tests): `{schema, dna_hash, host_agent, host_key_hex, file_id,
manifest_sha256, chunk_count, received_at}` signed by the v2-bound host key;
`replica-receipt/v1` stays readable and is labelled weaker.

## 13. Migration and rollback (design only; nothing executed)

* **Existing artist** (v1 binding, published S1 manifests): install the v2
  DNA as an additional cell; register a v2 binding for the *same* Ed25519
  key (proof signed locally from the existing key store); republish file
  commitments (and tracks) on v2 pointing at the same manifest digests. S1
  manifests are not re-signed; their signatures verify against the same key,
  now at v2 assurance.
* **Existing host**: same for the host key (`host-receipt`); republish
  replica claims and endpoints on v2 for the same S1 receipts (receipt
  attribution per §12 remains a separate upgrade).
* **Existing listener with a perpetual licence**: nothing to re-issue. The
  licence is bound to owner agent, file and manifest digest, all unchanged;
  once the owner's v2 binding exists, CORE-005 reports the owner identity at
  `ProofOfPossessionV2`. Offline playback never depended on the DHT.
* **Lost signing key**: a v2 binding cannot be created for it (that is the
  point). The artist may bind a *new* key on v2 and must re-sign/re-publish
  packages and re-issue grants with it; old manifests stay verifiable only at
  legacy assurance; existing licences still unwrap with the listener's key
  (they do not depend on the artist's signing key being available).
* **Conflicting records**: `Ambiguous` — the reader refuses until resolved.
  On v2 the only way to have two keys is for the agent itself to have
  registered both (each with proof); resolving it needs rotation (§11).
* **Rollback**: v1 and v2 are separate networks; uninstalling or ignoring the
  v2 cell returns the app to v1 with both histories intact on their own
  DHTs. Nothing written on v1 is altered.

## 14. Tests and how to run them

```bash
# Music (branch feat/s2-key-binding-v2)
(cd dna-v2 && cargo test -p music_storage_integrity_v2 \
   && cargo build --release --target wasm32-unknown-unknown && hc-dna pack workdir)
python -m unittest tests.test_s2_key_binding_v2 tests.test_holochain_identity

# Media Core
.venv/bin/python scripts/generate_music_key_binding_vectors.py \
  --music-repo ../holochain-music --output target/kb.json    # Music @ f091d5a
MUSIC_KEY_BINDING_VECTORS=target/kb.json cargo test -p holochain-content-core
cargo test --workspace --all-targets [--features serde_json/preserve_order]

# Real conductors (same prerequisites as CORE-004, plus the v2 DNA)
export HOLOCHAIN_MUSIC_REPO=../holochain-music CORE004_ALLOW_UNPINNED_MUSIC=1
export MUSIC_STORAGE_DNA=../holochain-music/dna/workdir/music_storage.dna
export MUSIC_STORAGE_V2_DNA=../holochain-music/dna-v2/workdir/music_storage_v2.dna
cargo test --manifest-path integration/Cargo.toml -p holochain-content-core-e2e \
  --test s2_key_binding_v2 -- --nocapture
CORE_S2_KEY_BINDING=v2 MUSIC_STORAGE_DNA=$MUSIC_STORAGE_V2_DNA \
  cargo test --manifest-path integration/Cargo.toml -p holochain-content-core-e2e \
  --test core004_acceptance -- --nocapture
```

Coverage map (A–K): `s2_key_binding_v2.rs` (real conductors: A, B, C, D, E,
F, G, H, I, J, K), `binding_v2_tests.rs` (26 Music-generated vectors + policy
and CORE-005 tests), `content-retrieval` v2 tests, Music
`tests/test_s2_key_binding_v2.py`, integrity `v2_tests`. Results:
`docs/current-state.md`.

## 15. Security limitations

* Only the v2 network has the property; v1 keeps the weakness.
* Proof of possession shows key control, not legal identity, copyright or
  payment.
* v2 prevents binding a key one does not hold; it does not prevent misuse of
  a *stolen* key — a thief can prove possession and bind it to their own
  agent. Containing that needs revocation (§11).
* No rotation/revocation; one key per agent and purpose.
* Receipts not host-attributed (§12).
* DNA-level uniqueness of bindings is not enforced; readers' policy is.
* Integrity relies on Holochain 0.7 `verify_signature_raw` / Lair; Media Core
  uses ed25519-dalek `verify_strict`. Both reject non-canonical signatures;
  a signature only one accepts would surface as a reader-side rejection
  (fail closed).
* Python and the app bridge route the v2 functions, but Music's production
  app is not switched to the v2 DNA.

## 16. Future identity work

Rotation/revocation (`v2.1`), `replica-receipt/v2`, a dedicated grant-issuer
key purpose, DNA-enforced single active binding via validated agent
activity, switching Music's catalogue resolution and app bundle to the v2
DNA (CORE-007), and an external review of the proof format.
