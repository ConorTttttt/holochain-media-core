# S2 key lifecycle v2.1: rotation, revocation and host-attributed receipts

Status: **implemented for a separate, opt-in v2.1 storage DNA. Pre-release:
not deployed, nothing migrated, not pushed.** Built on S2 key-binding v2
(Media Core `d42b20f`, Music `17a6276`).

| Repository | Branch | Base |
|---|---|---|
| holochain-music | `feat/s2-v21-key-lifecycle` | `feat/s2-key-binding-v2` @ `17a6276` |
| holochain-media-core | `feat/s2-v21-key-lifecycle` | `feat/s2-key-binding-v2` @ `d42b20f` |

Results and exact counts: §14. Open items: §15.

## 1. What changes and what does not

* **New, opt-in network:** `music_storage_v21` (Music `dna-v21/`, its own
  cargo workspace). The v1 DNA (`dna/`) and the v2 DNA (`dna-v2/`) are
  untouched and rebuild to their recorded hashes (§9).
* **New records:** `holochain-storage/key-lifecycle/v2.1` (inception,
  rotation, recovery) and `holochain-storage/key-revocation/v2.1`.
* **New receipt:** `holochain-storage/replica-receipt/v2` (host-attributed).
  The S1 `replica-receipt/v1` schema is unchanged and stays readable.
* **Media Core:** `lifecycle` and `receipt_v2` modules, the
  `KeyBindingPolicy::KeyLifecycleV21` policy, lifecycle-aware manifest,
  receipt and CORE-005 verification. Every existing API keeps its behaviour.
* **Music:** `holochain_storage/key_lifecycle.py`, the
  `ArtistService(key_binding="v2.1")` opt-in and v2.1 bridge routes. The
  default identity path stays v1.

## 2. Threat model

| Actor | Has | Must not be able to |
|---|---|---|
| Mallory (any DHT agent) | her own agent and keys; can author anything on her chain, call any coordinator function or craft entries directly; can copy every public record | rotate, revoke or extend anyone else's lifecycle; make readers accept her key for another agent; make a receipt count as another host's |
| Thief of a media key | Alice's Ed25519 **media** signing key, not her Holochain agent key | authorise any lifecycle step for Alice; get anything signed by that key accepted after Alice revokes it as compromised, except what Alice anchored before |
| Network | can delay, withhold or reorder DHT data | make a reader pick a wrong key by timing or order (it can only cause staleness or "not found", §12) |

Out of scope, documented in §11: compromise of the Holochain agent key itself,
Lair/Holochain implementation bugs, and plaintext that was already exported.

## 3. Authority model: what each signature proves

| Evidence | Who produces it | What it proves |
|---|---|---|
| The Holochain **action** (author = `agent`) | Alice's agent key, via Lair | Alice's agent authorised this exact transition or revocation. It is the **only** lifecycle authority. |
| `proof_signature_hex` (role `successor-possession`) | the **new** key | The registrant controls the new key, for this exact transition |
| `continuity_signature_hex` (role `predecessor-continuity`) | the **predecessor** key | The holder of the old key agreed to this exact successor (rotation only) |

Possessing an Ed25519 media key never authorises a lifecycle step, because
every step must also be **authored** by the agent. A thief holding Alice's
media key can only write to the thief's own chain, where the transition
either names the thief as agent or is refused by the authorship rule.

### What a successful rotation authorises

From the rotation's position on Alice's chain onward, the new key is the only
key acceptable for **new operations** of that one purpose:

* `owner-manifest`: signing new S1 manifests, and S10 grants or licences for
  content signed by that same generation;
* `host-receipt`: signing new replica receipts.

The predecessor stops being acceptable for new operations. Its earlier
signatures stay verifiable under the historical policy (§6). A rotation does
**not** re-attribute existing manifests, and it does **not** make the new key
an issuer for content signed by an earlier generation: S10 binds the grant
issuer to the manifest signer (§15).

## 4. Records and canonical signing format

### 4.1 Transition `holochain-storage/key-lifecycle/v2.1` (all strings, exact field set)

| Field | Rule |
|---|---|
| `schema` | exact |
| `dna_hash` | the validating DNA's `uhC0k…` hash (`dna_info()`), ≤ 160 B |
| `agent` | equals the action author |
| `purpose` | `owner-manifest` or `host-receipt` |
| `generation` | canonical decimal `1..=1000000`; `"1"` only for an inception |
| `kind` | `inception`, `rotation` or `recovery` |
| `signing_key_hex` | new Ed25519 public key, 64 lowercase hex |
| `predecessor_action` | action hash of the predecessor transition; empty for inception |
| `predecessor_key_hex` | predecessor's public key; empty for inception |
| `proof_signature_hex` | 128 lowercase hex, new key, role `successor-possession` |
| `continuity_signature_hex` | rotation: 128 hex, predecessor key, role `predecessor-continuity`; inception and recovery: empty |

Signed bytes (both roles):

```text
"holochain-storage/key-lifecycle/v2.1\0"
|| for f in [role, schema, dna_hash, agent, purpose, generation, kind,
             signing_key_hex, predecessor_action, predecessor_key_hex]:
       u32be(len(f)) || utf8(f)
```

The format is length-prefixed, uses a fixed field order and has no JSON
canonicalisation step. The role is the first field, so a proof can never
serve as a continuity signature or the reverse. The domain differs from v2's
`key-binding-pop/v2`, from S1/S10 canonical JSON (which starts with `{`) and
from the `holochain-music/…` HKDF contexts. Rust
(`lifecycle::key_transition_v21_message`), the integrity zome
(`v21::key_transition_v21_message`) and Python
(`key_lifecycle.transition_message`) produce byte-identical output; the
`signed_messages_match_music_byte_for_byte` test checks this.

### 4.2 Revocation `holochain-storage/key-revocation/v2.1`

Fields: `schema, dna_hash, agent, purpose, generation, signing_key_hex,
target_action, authority, scope`, all strings.

* `authority` must be `holochain-agent`: the agent, through authorship, is
  the revocation authority. No key signs a revocation.
* `scope` is one of:
  * `new-operations` (the key is retired; history stays verifiable);
  * `compromised` (history only when anchored before the key ended, §6).
* `target_action`, `generation` and `signing_key_hex` must name one exact
  transition of the same agent and purpose.

Revocations are append-only. A scope may be recorded once,
`new-operations → compromised` escalation is allowed, and `compromised` is
terminal.

## 5. DNA validation (Music `dna-v21/integrity/src/v21.rs`)

All rules are deterministic. They use only `dna_info`,
`must_get_agent_activity` over the author's hash-linked chain from
`prev_action` to genesis, `must_get_valid_record` for lifecycle actions only,
and `verify_signature_raw`. Validation makes no other network reads and never
consults a clock. An `UnresolvedDependencies` result from `must_get_*` is
propagated so the host retries; it is never mapped to valid. The "current"
generation is the last transition **on the author's chain** for that purpose.

| Rule | Prevents |
|---|---|
| author == `agent` | Mallory rotating or revoking for Alice (3, 4, 12) |
| `dna_hash` == this DNA; both signatures bind it | cross-network replay (6) |
| a purpose's history is filtered by purpose, and the predecessor must be the current transition **of that purpose** | cross-purpose rotation (5) |
| inception only when the purpose has no lifecycle yet | a second lineage (DNA-level fork) |
| `predecessor_action` == current transition | competing successors, replays, stale predecessors (7, 8, 9) |
| generation == current + 1 | skipped generations (no skipping exists, even for recovery) |
| `predecessor_key_hex` == current key; new key never used before in this purpose | silent reactivation |
| rotation needs a valid continuity signature by the predecessor key; recovery must have none | treating a recovery as a normal rotation |
| rotation may not follow a revoked key; only recovery may | continuity "signed" by a revoked key |
| revocation target is a transition on the author's chain with the same purpose, generation and key; no duplicate scope; nothing after `compromised` | revoking someone else's key, replayed revocations |
| `key-binding/v1` and `key-binding/v2` creates refused | parallel, unchained bindings on v2.1 |
| updates and deletes refused (unchanged v1 rule) | rewriting history |

The coordinator's publish functions are deliberately check-free. Every accept
or reject decision is the integrity zome's, and the real-conductor suite
checks each rejection by that rule's own message.

## 6. Reader resolution and validity (Media Core `lifecycle.rs` = Music `key_lifecycle.py`)

Readers receive records with their chain positions (`get_key_lifecycle_v21`)
and verify every record themselves (fields, DNA, both signatures). They then
rebuild the lineage **by predecessor references** and fail closed:

* An invalid record is an error. It is never skipped, and never a reason to
  try v1 or v2.
* More than one inception, or more than one successor of one generation, is
  `Ambiguous`. Neither first-match nor latest-match applies, and timestamps
  are never consulted.
* A successor or revocation target that was not returned is
  `LifecycleIncomplete`. Retrieval reports it as "not found" (propagation),
  not as a denial.
* Generations must increase by one and appear at increasing chain positions.
  Keys are never reused. A rotation may not follow a revoked key.

`KeyValidity` (the same spelling in Python):

| Verdict | Meaning |
|---|---|
| `Active` | the tip generation and not revoked |
| `Rotated` | superseded; not acceptable for this use |
| `Revoked` | revoked; not acceptable for this use |
| `HistoricalOnly` | not acceptable for new operations, acceptable for this historical use |
| `Ambiguous` | the lifecycle forks |
| `Invalid` | invalid, incomplete or unrelated records, or an unknown key |

### Use policy (`KeyUse`)

`end(g)` is the chain position of generation g's successor or of its first
revocation, whichever comes first.

| Use | Accepted when |
|---|---|
| `NewOperation` (new manifest, grant, receipt) | g is the tip and not revoked (`Active`) |
| `Historical { anchor }`, where the anchor is an agent-authored record (the owner's file commitment, the host's replica claim) at chain position `a` | `a ≤ end(g)` → `Active` or `HistoricalOnly`. If `a > end(g)` the artifact was published after its key ended: a **new operation with a stale key** → `Rotated` or `Revoked`. An anchor by another agent → `Invalid`. |
| `Historical { anchor: None }` | Rotated or `new-operations`-revoked → `HistoricalOnly`; `compromised` → `Revoked` |

Revocation and rotation therefore never invalidate all historical content.
Content anchored while its key was valid stays verifiable, even after a
compromise. Unanchored artifacts (S10 grants and licences carry no chain
anchor) survive rotation and retirement, but not a compromise, because after
a compromise they cannot be told apart from forgeries made with the stolen
key.

### Assurance (ordered)

`LegacyAuthoredV1 < ProofOfPossessionV2 < KeyLifecycleRecoveredV21 <
KeyLifecycleV21`.

Any generation reached through a recovery, and every later generation, is
`KeyLifecycleRecoveredV21` with `KeyContinuity::RecoveredWithoutContinuity`.
So `require ≥ KeyLifecycleV21` rejects recovered keys, and
`require_proof_of_possession` accepts all three proof-of-possession levels.

## 7. Compromised and lost keys

| Case | Procedure | Result |
|---|---|---|
| **Normal rotation** (both keys held) | `rotation`: new key proves possession, old key signs continuity, agent authors | `KeyLifecycleV21`, continuity `Rotation`; old key `Rotated` / `HistoricalOnly` |
| **Compromised media key** (thief holds it, not the agent key) | revoke it with `compromised`; then a `recovery` to a new key (a rotation is refused after a revocation) | the thief can neither rotate nor revoke (authorship). Anchored history verifies; unanchored grants and licences by that key are refused (`IssuerKeyRevoked`); every new operation with it is refused |
| **Lost media key** | `recovery` (agent-authorised, no continuity); optionally revoke the lost key | new key is `KeyLifecycleRecoveredV21`, labelled `RecoveredWithoutContinuity`. This is **not** presented as equivalent to a rotation, and readers may require continuity |
| **Compromised Holochain agent key** | **none that v2.1 can enforce.** Whoever holds the agent key **is** the agent: they can recover to their own key and revoke the owner's keys. Readers can only notice a recovery (assurance level) or a chain fork (`Ambiguous`) | needs an out-of-band identity and a new agent (a new lifecycle on a new agent); the old agent's content keeps whatever historical validity its anchors give it. Agent-key rotation (DPKI) is outside this milestone |

No recovery guarantee is claimed beyond the table above.

## 8. Host-attributed receipts: `holochain-storage/replica-receipt/v2`

JSON object with exactly these fields, all strings:

`schema, dna_hash, host_agent, host_key_hex, host_key_generation,
host_key_action, owner_agent, file_id, manifest_sha256, chunk_count,
received_at, context, signature_hex`

* `context` is `replica-acceptance`.
* `chunk_count` is canonical decimal.
* `received_at` is `YYYY-MM-DDTHH:MM:SSZ` (a valid UTC date; a host claim,
  not a trusted time).

Signature: `"holochain-storage/replica-receipt/v2\0" || u32be(len(f)) || f`
over the 12 fields above, in that order, by the key of the **exact** host
lifecycle generation named by `host_key_action`/`host_key_generation`. The
receipt digest is SHA-256 of that signed message, and the host's v2.1 replica
claim commits to it as `receipt_sha256`.

Verification (`receipt_v2::verify_replica_claim_v2`) requires all of:

* the claim is authored by the host;
* the receipt names that host and the owner of the authenticated manifest;
* it names this DNA, the exact manifest digest and the chunk count;
* the named generation exists in the host's verified lifecycle and is
  acceptable as **historical use anchored at the claim's chain position**;
* the claim's `receipt_sha256` equals the digest.

A valid receipt proves that host agent's acceptance of that exact manifest at
some point. It does **not** prove continuing storage or current availability.

Legacy S1 receipts verify only through the existing path and are labelled
`ReceiptAttribution::LegacyUnattributedV1`. They can never satisfy
`require_host_attribution`, and the v2.1 retrieval policy refuses them.

## 9. DNA strategy, hashes and network transition

Changing integrity code changes the DNA hash, and v2 proofs bind the v2 DNA
hash, so v2.1 must be a **new network**. It is a third workspace
(`dna-v21/`): its own crates, a copy of `dna-v2/Cargo.lock` with identical
dependency versions, the unchanged v1 coordinator compiled via `#[path]`, and
the v2 entry definition compiled from `dna-v2`'s own source. The
`v1_rules_unchanged` test guards the shared rules.

Measured (Holochain 0.7.0 `hc-dna`, Rust 1.97, wasm32):

| DNA | Integrity wasm SHA-256 | DNA hash |
|---|---|---|
| v1 `music_storage` (rebuilt, unchanged) | `cf75c4bda7100b62…` | `uhC0kkLUOg2uytGWLz_sTeVtfJBqa0criBmAYAPwAIUhoDp_9G4RV` |
| v2 `music_storage_v2` (rebuilt, unchanged) | `22e74d3d6a53ba8a…` | `uhC0k_-f-D4bF9w53gD2jXkA4RqYQ_bf0dRdF8rMkJG_tS8WGRamb` |
| v2.1 `music_storage_v21` (Music `cfd4807`; **superseded** by the grant-anchor revision, §16) | `a88f871a2d0296cc…` | `uhC0kiNH8oLxWdMyNxpTP-cxCnB6M04rVfcdPkcFmY2cUbVm8Brti` |

**Records do not move between networks.** Nothing on v1 or v2 appears on
v2.1.

### Moving an identity to v2.1 (procedure; nothing was executed)

1. Install `music_storage_v21` as an **additional** cell. v1 and v2 cells
   keep running.
2. Publish a v2.1 **inception** for the same Ed25519 key, with the proof
   re-signed for the v2.1 DNA hash. (A v2 proof cannot be reused: it binds
   the v2 DNA and another domain.)
3. Republish on v2.1 what readers need there:
   * the owner's file commitments, which point at the same manifest digests;
   * the host's inception, replica claims and endpoints. For host
     attribution, a host signs a **new** `replica-receipt/v2` for content it
     still holds, and the claim commits to that receipt's digest. A legacy S1
     receipt cannot be upgraded.
4. Nothing is re-signed for content: S1 manifests verify against the same
   key at generation 1, and existing S10 licences remain valid (§6).

### Which records must be republished

| Record | Republish on v2.1? |
|---|---|
| owner key binding | yes, as an inception |
| file commitments | yes |
| host key binding | yes, as an inception |
| replica claims | yes, with v2 receipt digests |
| MoQ endpoints | yes |
| tracks and catalogue entries (catalogue DNA) | no |
| S1 manifests, ciphertext, content keys | no |
| S10 grants and licences | no |

### Rollback

v1, v2 and v2.1 are separate networks. Ignoring or uninstalling the v2.1
cell returns the app to its previous network with all histories intact. No
v1 or v2 record is altered, and `ArtistService` defaults to v1. Keys created
for generations ≥ 2 live in separate key-store files (`artist.gN.ed25519`,
`host.gN.ed25519`) and are not used by the v1 or v2 paths.

## 10. APIs

```rust
// content-core::lifecycle
resolve_key_lifecycle(records, agent, purpose, dna_hash) -> Result<KeyLifecycle, BindingError>
evaluate_key(records, agent, purpose, dna_hash, &key, &KeyUse) -> KeyValidity   // total
KeyLifecycle::{active, tip_binding, classify, authorize, generations, …}
KeyValidity { Active, Rotated, Revoked, HistoricalOnly, Ambiguous, Invalid }
KeyContinuity { Inception, Rotation, RecoveredWithoutContinuity }
KeyUse { NewOperation, Historical { anchor: Option<ChainAnchor> } }
ChainAnchor::from_record(&ConductorRecord)          // needs the conductor's action_seq
// content-core::receipt_v2
verify_replica_receipt_v2(json, &OwnedManifest, &host: KeyLifecycle, &KeyUse)
verify_replica_claim_v2(json, &OwnedManifest, &host: KeyLifecycle, &claim) -> AuthenticatedReplica
require_host_attribution(&AuthenticatedReplica)
// content-core::binding (additive)
ConductorRecord::from_validated_conductor_at(author, action, action_seq, body)
KeyBindingPolicy::KeyLifecycleV21 { dna_hash }      // resolve_signing_key → active key only
verify_owned_manifest_lifecycle(json, &owner: KeyLifecycle, &commitment)
OwnedManifest::{owner_key_generation, owner_key_validity}
AuthenticatedReplica::{attribution, receipt_v2}
BindingAssurance::{KeyLifecycleRecoveredV21, KeyLifecycleV21}
BindingError::{LifecycleIncomplete, KeyRotated, KeyRevoked, ReceiptHostMismatch,
               InsufficientReceiptAttribution}
// content-core::entitlements
check_content_access_with_lifecycle(…, &owner: KeyLifecycle)
Unauthenticated::{IssuerKeyRevoked, IssuerNotInLifecycle}
// content-retrieval
MetadataSource::{key_lifecycle_v21, with_chain_position}   // default: unavailable
ResolvedContent::owner_lifecycle, HostPins::host_lifecycle
// integration/content-holochain
ConductorTarget::key_lifecycle_v21, READ_FUNCTIONS_V21, read_functions_for
```

Verified types still have no public constructor. Assurance and validity come
only from verification, and no error path downgrades: the v2.1 policy never
reads v1 or v2 records.

## 11. Security guarantees and exclusions

Guaranteed on the v2.1 network (DNA-enforced, then re-checked by readers):

* one lineage per agent and purpose;
* agent-authorised transitions only, with proof of possession of every key;
* continuity for every rotation;
* no skipped generations, forks or key reuse;
* purpose and DNA scoping;
* deterministic, timestamp-free resolution;
* revoked keys refused for new operations;
* host-attributed receipts bound to an exact host key generation.

Not guaranteed:

* **Agent-key compromise** (§7).
* **Freshness.** A reader only knows what its conductor has received. A
  withheld rotation or revocation leaves the reader on the older state until
  it propagates. Revocation propagation is eventually consistent, not
  instant.
* **Recall of plaintext.** Revocation cannot recall exported plaintext or
  content keys already unwrapped.
* **Issuance time of grants and licences.** Verifiers cannot tell when an
  S10 grant was issued; the issuer (Music) signs only with the active key.
* **Ongoing storage.** Receipts are not proof of continuing storage.
* **The v1 and v2 networks** keep their documented properties and
  weaknesses.

## 12. Real-conductor acceptance (`integration/core-e2e/tests/s2_key_lifecycle_v21.rs`)

Four Sweettest conductors on `music_storage_v21`: Alice, Bob, Carol and
Mallory. The flow uses real Music MoQ/QUIC hosts, Music's Python for every
entry, receipt and licence, Bob's least-privilege v2.1 resolver, and
VerifiedCas. Coverage of the 16 required cases:

| # | Case | Where checked |
|---|---|---|
| 1 | Alice rotates owner key | DNA accepts; Bob resolves gen 2 `Active`, continuity `Rotation` |
| 2 | Carol rotates host key | DNA accepts; her earlier receipt stays `HistoricalOnly` |
| 3 | Mallory rotates Alice's key | refused: authorship |
| 4 | stolen media key alone | refused on Mallory's chain (predecessor) and relabelled (authorship); continuity by a foreign key refused (signature) |
| 5 | cross-purpose | refused (no predecessor in that purpose) |
| 6 | cross-DNA | refused (different DNA; relabelled → proof fails) |
| 7 | replay | rotation and revocation replays refused; reader: duplicate delivery idempotent, re-authored copy `Ambiguous` |
| 8 | invalid predecessor | skipped generation, non-transition predecessor refused |
| 9 | competing successors | refused by DNA; reader `Ambiguous` (vectors) |
| 10 | revoked key, new operation | reader `KeyRevoked`; DNA refuses a rotation continuity-signed by a revoked key |
| 11 | historical content | p1 (gen 1, anchored before rotation) `HistoricalOnly`; p3 (gen 1, committed after) refused `KeyRotated`; p2 (gen 2) `Active` |
| 12 | Mallory revokes Alice's key | refused: authorship, and target not on her chain |
| 13 | forged receipt | rejected |
| 14 | receipt claiming another host | Mallory's real QUIC host serving Carol's receipt is excluded with `ReceiptHostMismatch`; renamed receipt rejected |
| 15 | valid host-attributed receipt | verified over MoQ, then ciphertext fetched into VerifiedCas, CORE-005 accepts Bob's licence, Music decrypts (SHA-256 matches) |
| 16 | legacy receipt | not accepted as v2; readable as `LegacyUnattributedV1` only |

Music's own reader (`v21-resolve` fixture command) gives the same verdict as
Media Core on the real conductor rows.

## 13. How to run

```bash
# Music (feat/s2-v21-key-lifecycle)
(cd dna-v21 && cargo test -p music_storage_integrity_v21 \
   && cargo build --release --target wasm32-unknown-unknown && hc-dna pack workdir)
python -m unittest tests.test_s2_key_lifecycle_v21

# Media Core
python scripts/generate_music_key_lifecycle_vectors.py --music-repo ../holochain-music \
  --output target/kl.json                                  # Music @ cfd4807
MUSIC_KEY_LIFECYCLE_VECTORS=target/kl.json cargo test -p holochain-content-core
cargo test --workspace --all-targets [--features serde_json/preserve_order]

# Real conductors (CORE-004 prerequisites + the v2.1 DNA; IPv6 shim if needed)
export HOLOCHAIN_MUSIC_REPO=../holochain-music CORE004_ALLOW_UNPINNED_MUSIC=1
export MUSIC_STORAGE_DNA=../holochain-music/dna/workdir/music_storage.dna
export MUSIC_STORAGE_V21_DNA=../holochain-music/dna-v21/workdir/music_storage_v21.dna
cargo test --manifest-path integration/Cargo.toml -p holochain-content-core-e2e \
  --test s2_key_lifecycle_v21 -- --nocapture
```

## 14. Results (13 November 2026, this container: 4 vCPU, Rust 1.97, Python 3.13, cryptography 46.0.4, Holochain 0.7.0 Sweettest, IPv6 errno shim)

| Check | Before (v2 heads) | After (v2.1 branches) |
|---|---|---|
| v1 / v2 DNA rebuilt from unchanged source | hashes as recorded | identical (`uhC0kkLUOg2…9G4RV`, `uhC0k_-f-D4…GRamb`) |
| v2.1 DNA | — | `uhC0kiNH8oLxWdMyNxpTP-cxCnB6M04rVfcdPkcFmY2cUbVm8Brti`; integrity unit tests **12 pass** (v2: 6 pass) |
| Media Core `cargo test --workspace --all-targets` | 63 pass (core 40, retrieval 12, cli 7, release 4) | **74 pass** (core 48, retrieval 15, cli 7, release 4) |
| same, `serde_json/preserve_order` | 63 pass | **74 pass** |
| Interop with fresh vectors (S1 + CORE-005 from Music `bd7aabc`, key-binding v2 from `f091d5a`, lifecycle v2.1 from `cfd4807`) | — | core **69 pass**; also with `preserve_order`: **69 pass** |
| Python → Rust lifecycle parity | — | 39 scenarios, **154 queries** and 23 receipt cases: Rust verdict = Music verdict for all |
| fmt; clippy `-D warnings` (root, also `preserve_order`; integration) | — | pass |
| `s2_key_lifecycle_v21` (4 real conductors, real MoQ, CORE-005, Music decrypt) | — | **pass 154.3 s, and 143.0 s on the committed code**: 21 forged/replayed/out-of-order writes refused by the named integrity rule, both flows complete, Music's reader agrees with Media Core on real rows |
| `s2_key_binding_v2` regression | pass 231.3 s (recorded) | **pass 304.4 s** (23 integrity refusals; ran concurrently with the Python suite) |
| `core004_acceptance` v1 (Music pinned `bd7aabc`, no unpinned override) | pass 185.2 s (recorded) | **pass 235.1 s** |
| `core004_acceptance` `CORE_S2_KEY_BINDING=v2` | pass 186.6 s (recorded) | **pass 215.8 s** |
| Music app bridge `cargo check` with the v2.1 routes | — | pass |
| Music `unittest discover -s tests` (adapter disabled) | 479 run: 431 OK, 48 skipped, 0 fail | **506 run: 458 OK, 48 skipped, 0 fail** |

One Music run made concurrently with four conductors failed a p95 seek-latency
budget (616 ms > 500 ms, `test_v1_seek_performance`); it passes alone and in
the quiet full run above. It is a timing test unrelated to this change.

Not run: Windows CI (nothing pushed); GitHub Actions for the new
`music-s2-identity-interop` job (needs Music `cfd4807` to be pushed);
two-device network; Music `music-e2e` Sweettests (v1 DNA, unchanged).

## 14a. Branches and intended pull-request chain

Nothing here is pushed or merged. Each PR targets the branch below it, so the
diff shows only its own increment; no CORE-004, CORE-005 or S2 v2 branch is
merged by this work.

```text
holochain-music                               holochain-media-core
main                                          main
 └ ccr-53e220c1-45x2cc (CORE-004 adapter)      └ #1 → #2 → #3 (CORE-001..003)
   └ claude/core-005-entitlements-i7zm0e         └ ccr-53e220c1-45x2cc (CORE-004)
     └ feat/s2-key-binding-v2  (17a6276)           └ claude/core-005-entitlements-i7zm0e
       └ feat/s2-v21-key-lifecycle                   └ feat/s2-key-binding-v2  (d42b20f)
         (cfd4807 code, 8f9a90c docs)                  └ feat/s2-v21-key-lifecycle
```

Push the Music branch first: Media Core's `music-s2-identity-interop` CI job
checks out Music `cfd4807` and `f091d5a`, which must be reachable on GitHub.
The S1 and CORE-005 CI references (`bd7aabc`) are unchanged.

## 15. Remaining limitations and review gates

1. **S10 grant issuer = manifest signer.** After a rotation, Music cannot
   issue *new* grants for content signed by an earlier generation; the v2.1
   app refuses rather than sign with a rotated key. The fix is a versioned
   grant format with a separate issuer field, or a `grant-issuer` purpose.
   This blocks a rotation-transparent paid-access flow (CORE-006).
2. **Agent-key compromise** has no in-protocol recovery (§7).
3. **Revocation freshness** depends on DHT propagation (§11).
4. `get_key_lifecycle_v21` reads agent links. A future version could add
   validated agent activity and fork warrants for chain status.
5. Validation reads the author's whole chain (`must_get_agent_activity` to
   genesis) for each lifecycle entry: O(chain length). That is acceptable
   for rare lifecycle operations; a bounded variant needs a reviewed design.
6. Music's catalogue resolution and app bundle are not switched to v2.1
   (CORE-007). The bridge routes v2.1 but the app default is v1.
7. Review gates before any release:
   * external review of the formats;
   * Windows CI;
   * a two-device run;
   * a decision on (1);
   * a migration rehearsal on a disposable network.

## 16. Revision: grant anchors (pre-release DNA change)

By reviewer decision (docs/ACCESS-GRANT-V2.md §4, option A) the v2.1 storage
DNA gains `GrantAnchorV2` and `AgentToGrantAnchorV2`, appended after the
lifecycle types. This is a deliberate, security-sensitive change to an
already-tested, undeployed DNA. It is made as follow-up commits; the
reviewed v2.1 history is not rewritten.

| DNA | Integrity wasm SHA-256 | DNA hash |
|---|---|---|
| v1 `music_storage` (unchanged; rebuilt) | `cf75c4bda7100b62…` | `uhC0kkLUOg2uytGWLz_sTeVtfJBqa0criBmAYAPwAIUhoDp_9G4RV` |
| v2 `music_storage_v2` (unchanged; rebuilt) | `22e74d3d6a53ba8a…` | `uhC0k_-f-D4bF9w53gD2jXkA4RqYQ_bf0dRdF8rMkJG_tS8WGRamb` |
| v2.1 `music_storage_v21` before (Music `cfd4807`) | `a88f871a2d0296cc…` | `uhC0kiNH8oLxWdMyNxpTP-cxCnB6M04rVfcdPkcFmY2cUbVm8Brti` (superseded) |
| **v2.1 `music_storage_v21` with grant anchors (Music `64f57d4`)** | `ae3f068d54cca6e3…` | **`uhC0kF7I2QWYZf2K5-cziQFYZev-7WwNrNQFSSeOtwcLpN5Y98mlf`** |

The lifecycle rules of §5 are unchanged. The chain walk now also collects
the author's earlier anchors (one pass). The anchor rules and the split
between conductor and verifier responsibilities are in
docs/ACCESS-GRANT-V2.md §4. The Media Core verifier is
`grant_anchor::verify_grant_anchor_v2`.

Every result in §14 was measured on the superseded DNA. The re-runs on the
revised DNA are recorded in docs/current-state.md and in the
grant-anchor PRs; none of the earlier figures are carried over without a
re-run.
