# Media Core integration plan — 17 November 2026

Status: **review plan**, not an approval to merge, publish crates, switch a Music DNA or migrate user data. This document is authoritative for the proposed PR order; the earlier dates/evidence in `current-state.md` remain historical snapshots.

## Latest live-GitHub reconciliation — 17 November 2026, 15:05 UTC

This addendum is a documentation-only delta to the earlier Agent 2 audit. GitHub remains the source of truth if any branch moves again.

- **Unchanged integration root:** Media Core `main` remains `0e0a6290729debdb0d1e87c9201900a901adc102`. No foundational milestone, corrective PR or Agent 2 documentation PR is merged.
- **#7 moved after #11 branched:** `docs/async-private-delivery-design` (PR #7) now points to `978441420948a7c4aa538b285a809b7ae245cb03`, a one-commit *append-only* advance over the `1c68bdd373287307013bb9eac5b3530796038429` snapshot cited in the original plan. The change adds 91 documentation lines to `docs/ASYNCHRONOUS-PRIVATE-DELIVERY.md`. Its new [hosted run 44074441650](https://github.com/ConorTttttt/holochain-media-core/actions/runs/44074441650) has four successful jobs (Rust, Windows, Music S1 and S2 interop). #11's recorded base SHA remains the *older* `1c68bdd...`, and #15 descends from #11, so **forward-integrate current #7 into #11 before finally retargeting/integrating #15**; do not represent #11/#15 as already containing the newer #7 addendum.
- **Formal static review trail:** Non-approving `COMMENT` reviews were submitted on [CORE-001 #1](https://github.com/ConorTttttt/holochain-media-core/pull/1) (review ID `5940892538`), [portable clock #12](https://github.com/ConorTttttt/holochain-media-core/pull/12) (`5940893996`), and [canonical JSON #13](https://github.com/ConorTttttt/holochain-media-core/pull/13) (`5940893281`). These record source-review/CI findings but **are not approvals**; no correction or milestone integration was performed.
- **Separate new child work, not part of this foundation merge:** #14 (`314b19dec9e506298c2f2ca38c5aebb32d4e3cec`, new grant v2 after #6), #16 (`2aad791a77332bf2786ca5013e1c46cf73be51e8`, child of #14), #17 (`5ce18668427651d43068cad67824c54004966727`, child of the updated #7), and #18 (`069cd59a5d73763336fd54ba22473ab51d4ad19a`, separate CAS test child of #6) need their own reviews and integration gates. Do **not** accidentally include any of these branches in sequential foundational PR integration.
- **Local test status unchanged:** This audit did not execute Cargo, Python vector generation, Windows, Holochain or MoQ suites locally; only hosted checks were inspected. A successful CI run on a historical or documentation head is not a substitute for fresh exact-head integration and real-conductor acceptance.

## Agent 2 integration audit — 17 November 2026

**Scope and safety:** Review-only integration preparation on a documentation branch based on the unchanged #11 head `929a8f7d1e0a726540a2764890662efcefa549a8`. No root implementation, signature, key, DNA, fixture, stored content or production behaviour is changed. No milestone PR has been merged. This section supersedes older *pending CI* descriptions for #12 and #13 below; their changes are **CI-verified but unintegrated**.

### Independently checked correction PRs

| Correction | Base commit; head commit | Exact files changed | Hosted run at head | Outcome |
| --- | --- | --- | --- | --- |
| [#13 CORE-002 canonical JSON](https://github.com/ConorTttttt/holochain-media-core/pull/13) | `9277b621cbec6a67f31a41aa9b5927585fe771c6` → `58a2e80f7f4717cabd30da0232e21dd231bb7d91` (4 append-only commits) | `.github/workflows/ci.yml`, `crates/content-core/src/compat.rs`, `crates/content-core/src/compat_tests.rs` | [44071691059](https://github.com/ConorTttttt/holochain-media-core/actions/runs/44071691059) | Both jobs green: Linux fmt/Clippy/unit, unit tests under `serde_json/preserve_order`, Music-generated S1 vectors and signed-envelope/digest/negative checks with and without `preserve_order`. No Windows job exists at this CORE-002 scope. |
| [#12 CORE-005 Windows test](https://github.com/ConorTttttt/holochain-media-core/pull/12) | `5f7adf5ff2e3bc7f10836fc1f739114a8a703ff9` → `fdd958a3fffda8efc3759f9878618c8bcdba0db5` (1 append-only commit) | `crates/content-core/src/entitlement_tests.rs` | [44070826318](https://github.com/ConorTttttt/holochain-media-core/actions/runs/44070826318) | All three jobs green: Linux fmt/Clippy/unit/feature-mode, Music S1 and CORE-005 generated entitlement interop in both modes, native Windows tests. |

**Canonical bytes review:** Before #13, CORE-002 used `serde_json::to_vec(Value)`, which can switch to insertion order when `preserve_order` is unified by a downstream Holochain build. #13 recursively sorts every object's keys and compact-serialises scalars/arrays, rejecting floating-point numbers outside the signed S1 schema. Inspection against CORE-004's *already committed* canonical fix `53e47c72c11d053edc53b176e11145db60468474` confirms the **same recursive writer and signature input logic**. CORE-004 has additional Unicode/escape regression coverage and downstream adapter/tests (`content-retrieval`) that must be retained. #13 adds an independent CORE-002 level nested-order test; its hosted Python-vector runs cover signed manifests and receipts both with and without `preserve_order`. No signed byte format change or fixture repin is intended. Retain **one** canonical helper, not parallel implementations; resolve any merge conflict in favour of the validated writer and preserve the later CORE-004 call sites/tests.

**Portable-clock review:** #12 changes only a test's artificial far-future second from `1_i64 << 40` (outside Windows `SystemTime`) to `253_402_300_799` (9999-12-31 23:59:59 UTC). The same numeric fix already appears on `feat/s2-v21-key-lifecycle`; no entitlement policy or production timestamp handling changes. An inherited copy must not be reapplied as a second behaviour change.

**Review status:** GitHub shows no submitted PR review approvals for #1–#13 at this audit. CI success is not a security review, and neither correction is currently merged into its stage. #9 and #10 original heads remain **red on Windows**, notwithstanding #12's green independent run.

### History-preserving proposed sequencing

**Mandatory rule:** Keep original milestone commits and two existing merge commits (`09d8e8c` and `a74a8ae`) reachable. Use merge commits / append-only forward merges; no squash, rebase, force-push, bulk merge, silent fixture regeneration or Music pin update. Each stage must have a fresh hosted run against its **updated** exact head and integration base. If any conflict is unresolved, stop rather than marking it green.

1. Complete CORE-001 review on [#1](https://github.com/ConorTttttt/holochain-media-core/pull/1) and land **only #1** into `main` with a merge commit after approval. Verify its post-merge smoke workflow. CORE-001 remains a foundation, not a shipped protocol.
2. Review #13 and append-only merge that **fix PR into its existing CORE-002 branch** `feat/core-002-music-interop`, preserving the original `9277b62` ancestor. Retarget #2 to the new `main`, rerun Linux default + `preserve_order` and both fresh pinned Music S1 vector modes **at the resulting #2 head**; only then independently approve/merge #2.
3. Forward-merge updated `main` into #3's branch (not rebase), resolve any `compat.rs` / `compat_tests.rs` conflict preserving #13, retarget #3, run Linux/Windows/S1 vector modes plus CAS corruption/restart/replica tests, then review/merge #3 alone.
4. Forward-merge updated `main` into #8's CORE-004 branch; reconcile its earlier canonical fix `53e47c7` with #13 **once**, retaining `canonical_json` uses in retrieval and regression tests. Retarget #8, rerun both root + `integration/` workspace checks and `core004_acceptance` real-service suite with unchanged Music/DNA references. Independently approve/merge #8 only when all gates pass.
5. Review #12 and merge it into the **CORE-005 branch** `claude/core-005-entitlements-i7zm0e` without modifying the original `5f7adf5` commit. Forward-merge current `main`, retarget #9, rerun its *new exact head* on Linux, Windows, Music S1/entitlement vectors, and the real-service grant/denial checks, then review/merge #9.
6. Forward-merge updated `main` into #10's `feat/s2-key-binding-v2` branch, carrying the #12 test-only correction; retarget #10, rerun Linux/Windows, S2 v2 independently generated Music vectors and `s2_key_binding_v2` acceptance, then review/merge #10. The original `d42b20f` Windows failure cannot be treated as fixed solely from #12's run.
7. Forward-merge updated `main` through #4 → #5 → #6 in sequence, treating the later identical clock line in #4 as already integrated. At each gate retarget exactly one PR and rerun Linux/Windows/Music S1, S2 and lifecycle test jobs as defined for that stage. For #4 rerun `s2_key_lifecycle_v21` and v1/v2 regression suites. For #6 rerun `grant_anchor_v21` acceptance and verify Music #44/#47 pairing and unchanged opt-in DNA hashes. #5 is **specification only**; #6 is **anchor verification**, not completion of signed `access-grant/v2` issuance/key-wrap.
8. Only after those milestones, review/retarget optional docs #7 → #11 → this Agent 2 documentation follow-up. Documentation additions must not be misrepresented as implementations or block RC1 unless a release-blocking inconsistency is uncovered.

**Per-stage required recordings:** PR number/base SHA/head SHA/merge SHA, changed-file diff and intended scope, reviewers, exact commands, OS/feature mode, Music source pin, generated vector provenance, test counts (passes/failures/skips), any pending or unexecuted manual scenarios, real conductor count/DNA hash/MoQ host revision/logs, and remaining security risks. Update this table on *every* merge; never infer a downstream green run from an ancestor or descendant.

### Test and interoperability gate ledger

| Milestone | Currently available evidence | Still required before merge |
| --- | --- | --- |
| #1 CORE-001 | [42495525394](https://github.com/ConorTttttt/holochain-media-core/actions/runs/42495525394) Linux green | Review; post-retarget/merge workflow; licence decision remains separately open. |
| #2 CORE-002 | Original [42524069558](https://github.com/ConorTttttt/holochain-media-core/actions/runs/42524069558) green, #13 [44071691059](https://github.com/ConorTttttt/holochain-media-core/actions/runs/44071691059) green | Forward-integrated #2 head Linux, both `serde_json` modes, Music fresh pinned S1 vectors; reviewer approval. |
| #3 CORE-003 | [42531817223](https://github.com/ConorTttttt/holochain-media-core/actions/runs/42531817223) Linux/Windows/interop green | New base with #13, CAS corruption/recovery checks and review; operational stress still outstanding. |
| #8 CORE-004 | [44070154615](https://github.com/ConorTttttt/holochain-media-core/actions/runs/44070154615) Linux/Windows/interop green | New base with #13; integration workspace and five-conductor MoQ fixture re-run, TLS/binding review. |
| #9 CORE-005 | Original [44070167413](https://github.com/ConorTttttt/holochain-media-core/actions/runs/44070167413) Windows **FAIL**; #12 [44070826318](https://github.com/ConorTttttt/holochain-media-core/actions/runs/44070826318) green | Merge #12, then new #9 head CI and entitlement real-conductor checks; review. |
| #10 S2 v2 | Original [44070181258](https://github.com/ConorTttttt/holochain-media-core/actions/runs/44070181258) Windows **FAIL** | New #10 head with #12, fresh three hosted jobs and PoP adversarial acceptance; review. |
| #4 / #5 / #6 | Original exact-head hosted four-job runs [43577300233](https://github.com/ConorTttttt/holochain-media-core/actions/runs/43577300233), [43577313135](https://github.com/ConorTttttt/holochain-media-core/actions/runs/43577313135), [43577314159](https://github.com/ConorTttttt/holochain-media-core/actions/runs/43577314159) green | New integration bases, real conductor lifecycle/anchor acceptance, verified opt-in DNA+Music companion ordering, security reviews. |
| #7 / #11 | Original CI at [43736181347](https://github.com/ConorTttttt/holochain-media-core/actions/runs/43736181347), [44071382518](https://github.com/ConorTttttt/holochain-media-core/actions/runs/44071382518) green | Docs consistency and retarget checks after protocol stack integration. |

**Commands for a suitably provisioned Linux acceptance runner** (illustrative, *not executed by Agent 2*):

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
cargo test --workspace --all-targets --features serde_json/preserve_order
cargo fmt --manifest-path integration/Cargo.toml --all -- --check
cargo clippy --manifest-path integration/Cargo.toml --workspace --all-targets -- -D warnings
cargo test --manifest-path integration/Cargo.toml --workspace --all-targets
# Pin the Music checkout to the exact reference demanded by each test;
# build the matching storage DNA and real host, then run the applicable suite:
cargo test --manifest-path integration/Cargo.toml -p holochain-content-core-e2e --test core004_acceptance -- --nocapture
cargo test --manifest-path integration/Cargo.toml -p holochain-content-core-e2e --test s2_key_binding_v2 -- --nocapture
cargo test --manifest-path integration/Cargo.toml -p holochain-content-core-e2e --test s2_key_lifecycle_v21 -- --nocapture
cargo test --manifest-path integration/Cargo.toml -p holochain-content-core-e2e --test grant_anchor_v21 -- --nocapture
```

Do not run v2/v2.1 suites against the v1 DNA. For v2 set `MUSIC_STORAGE_V2_DNA` / `CORE_S2_KEY_BINDING=v2`; for v2.1 set `MUSIC_STORAGE_V21_DNA` and companion Music source as specified by that milestone. Preserve logs, DNA hashes and exact Music commits. Some suites require the five-conductor local Holochain 0.7.0 setup, wasm build, pinned MoQ host and potentially the documented IPv6 workaround; a timeout, skip or unavailable dependency is **not a pass**.

Verified GitHub Music commit references (exist, no repin): S1 `bd7aabc3e9ea1fef1e8e8f674301e1b5ffecb637`; S2 v2 `f091d5a5da0c2cb46228ea619ab816338311ef9b`; S2 v2.1 + grant-anchor `64f57d416f42c37d3e3aca1a2170142c0a4cf206`. No Music fixtures were regenerated in this audit.

**Environment limitation / actual execution:** Agent 2 directly inspected live GitHub code, diffs, ancestry, review state, workflow jobs and their individual step conclusions. No Rust toolchain, dependency cache, Holochain conductors or MoQ host executable is installed in the available execution container; network cloning also failed. Consequently **no local Rust, Music Python, Windows or real-conductor tests were run during this audit**; links above are pre-existing hosted runs inspected directly, not fresh local executions. Real-conductor evidence in older design docs is historical, and re-execution after merge is **pending**.

**Merge readiness on 17 November:** No full milestone is unconditionally safe to merge to `main` yet: PRs remain draft, review approvals are absent, and updated integration-head CI has not run. #1 is the first *candidate* after approval; #13 and #12 are *technical-fix candidates for their existing parent development branches*, not direct merges into `main`. Subsequent stages are gated in the order above. No approvals, merges, production DNA changes or data migration are implied.

## Verified repository state

- `main`: `0e0a6290729debdb0d1e87c9201900a901adc102` — initial README only; **none** of CORE-001 through grant-anchor is merged.
- `feat/grant-anchor-v21`: `a74a8aec32da03962788ad92810c413103b2ffd3`, **45 commits ahead of main**; contains S1, CAS, Holochain/MoQ, entitlement, S2 and grant-anchor work as *development-only*.
- `docs/async-private-delivery-design`: current `978441420948a7c4aa538b285a809b7ae245cb03` (three documentation commits after grant-anchor; prior recorded head `1c68bdd373287307013bb9eac5b3530796038429`).
- No rebase or squash of existing protocol branches is authorised. The history already contains merge commits `09d8e8c` and `a74a8ae` preserving original reviewed branch commits; preserve both parent relationships.

## Exact staged review points

Every SHA below is the observed branch head on 17 November 2026. Each branch is a descendant of the preceding head; each PR must be independently reviewed against the *preceding* stage, not against `main` until that preceding stage has landed.

| Stage | PR | Head branch | Exact head | Commits over previous | Target / prerequisite |
| --- | --- | --- | --- | ---: | --- |
| CORE-001 bootstrap | #1 | `feat/core-001-bootstrap` | `84b775729ef56b8b9c3d8718000a908b85e76966` | 2 | `main` |
| CORE-002 Music S1 | #2 (fix draft #13) | `feat/core-002-music-interop` | `9277b621cbec6a67f31a41aa9b5927585fe771c6` | 5 | #1 |
| CORE-003 verified CAS | #3 | `feat/core-003-verified-cas` | `5420d57479fc1453424cac0ffc1c978615798302` | 4 | #2 |
| CORE-004 Holochain/MoQ | **#8 (new draft)** | `ccr-53e220c1-45x2cc` | `4989ee400cec7f60abee91985cea95f494a28a0c` | 13 | #3 |
| CORE-005 entitlements | **#9 (new draft; fix draft #12)** | `claude/core-005-entitlements-i7zm0e` | `5f7adf5ff2e3bc7f10836fc1f739114a8a703ff9` | 5 | #8 |
| S2 key binding v2 | **#10 (new draft)** | `feat/s2-key-binding-v2` | `d42b20fc94af491f71d9595fbc3ee01e187ddb57` | 4 | #9 |
| S2 key lifecycle v2.1 | #4 | `feat/s2-v21-key-lifecycle` | `6c1a452306c38818315c1f974a6eb6fe9f33dae8` | 5 | #10 |
| access-grant/v2 specification | #5 | `feat/access-grant-v2-spec` | `09d8e8c80f780e7a83b974d2df7a9c2a485e3013` | 3 | #4 |
| grant-anchor/v2 | #6 | `feat/grant-anchor-v21` | `a74a8aec32da03962788ad92810c413103b2ffd3` | 4 | #5; Music #47 companion |
| async private delivery **design only** | #7 | `docs/async-private-delivery-design` | `978441420948a7c4aa538b285a809b7ae245cb03` | 3 | #6; #11 uses earlier snapshot |
| integration status documentation | #11 | `docs/agent5-integration-gates-20261117` | `929a8f7d1e0a726540a2764890662efcefa549a8` | 2 | earlier #7 head `1c68bdd` (forward-integration pending) |

Links: [PRs #1–#10](https://github.com/ConorTttttt/holochain-media-core/pulls), [Music PR #44](https://github.com/ConorTttttt/holochain-music/pull/44), [Music PR #47](https://github.com/ConorTttttt/holochain-music/pull/47).

### Current hosted CI evidence by observed head

| Stage | GitHub Actions run | Evidence |
| --- | --- | --- |
| CORE-001 `84b7757` | [42495525394](https://github.com/ConorTttttt/holochain-media-core/actions/runs/42495525394) | Linux rust fmt, Clippy, test: green |
| CORE-002 `9277b62` | [42524069558](https://github.com/ConorTttttt/holochain-media-core/actions/runs/42524069558) | Linux rust and pinned Music-Python S1 interop green, **but not feature-unification safe by itself**; isolated preserve_order repair passes hosted checks in draft [#13](https://github.com/ConorTttttt/holochain-media-core/pull/13). |
| CORE-003 `5420d57` | [42531817223](https://github.com/ConorTttttt/holochain-media-core/actions/runs/42531817223) | Rust, Music-Python and Windows: green |
| CORE-004 `4989ee4` | [44070154615](https://github.com/ConorTttttt/holochain-media-core/actions/runs/44070154615) | **Green**: Rust fmt/Clippy/tests, Music interop, Windows (three jobs) |
| CORE-005 `5f7adf5` | [44070167413](https://github.com/ConorTttttt/holochain-media-core/actions/runs/44070167413) | **Red**: Rust and Music interop green, Windows time overflow; isolated [draft #12](https://github.com/ConorTttttt/holochain-media-core/pull/12) **green in all three jobs** at [44070826318](https://github.com/ConorTttttt/holochain-media-core/actions/runs/44070826318). Still requires review/integration and stage rerun. |
| S2 v2 `d42b20f` | [44070181258](https://github.com/ConorTttttt/holochain-media-core/actions/runs/44070181258) | **Red**: same inherited Windows `SystemTime` overflow. Rust and Music interop green; rerun after reviewing and integrating portable-clock fix #12. |
| S2 v2.1 `6c1a452` | [43577300233](https://github.com/ConorTttttt/holochain-media-core/actions/runs/43577300233) | Rust (incl. preserve_order), Windows, S1 and S2 Music interoperability: four green jobs |
| grant specification `09d8e8c` | [43577313135](https://github.com/ConorTttttt/holochain-media-core/actions/runs/43577313135) | Four green jobs |
| grant anchor `a74a8ae` | [43577314159](https://github.com/ConorTttttt/holochain-media-core/actions/runs/43577314159) | Four green jobs |
| async design previous `1c68bdd` | [43736181347](https://github.com/ConorTttttt/holochain-media-core/actions/runs/43736181347) | Four green jobs at historical head |\n| async design current `9784414` | [44074441650](https://github.com/ConorTttttt/holochain-media-core/actions/runs/44074441650) | Four green jobs at current #7 head; #11/#15 ancestry still based on older snapshot |

The old assertion that hosted Actions are blocked by billing is superseded by successful runs on 14–15 November. However GitHub Actions does **not** run the slow, multi-conductor real-MoQ suites in the hosted workflow; those remain local test evidence and need per-stage repeatable logs/artifacts.

### Frozen cross-repository references

The development workflow checks out Music source at exact commits:
- S1 packages and CORE-005 grants: `bd7aabc3e9ea1fef1e8e8f674301e1b5ffecb637`.
- S2 proof-of-possession: `f091d5a5da0c2cb46228ea619ab816338311ef9b`.
- S2 v2.1 lifecycle and grant anchors: `64f57d416f42c37d3e3aca1a2170142c0a4cf206`.

Generator scripts import Music's original Python issuance/verifier modules, check the checked-out Music source revision, and generate new cases. Rust compares against Python results and typed negative-case expectations; committed fixture reproduction tests guard deterministic portions only. This is **meaningfully independent signing and verdict execution**, but not a substitute for an external protocol implementation/auditor: the Python testcase expectations are still locally authored, synthetic chain positions model conductor records, and a change to Music's pinned generator would need a review of both sides.

Never change a pin, rebase a referenced branch, or mix the new v2.1 DNA with old v1/v2 persisted data without explicit cross-repo review, fresh Music vector generation, real-conductor tests and a documented opt-in migration/rollback.

## Sequential integration gates

**Pre-merge repair order:** review/verify [#13](https://github.com/ConorTttttt/holochain-media-core/pull/13) on CORE-002 before accepting #2; review/verify [#12](https://github.com/ConorTttttt/holochain-media-core/pull/12) on CORE-005 before accepting #9. Both are append-only children of the original stage heads. Preserve the original commits, merge approved fixes without rewriting, then retest each affected stage and check downstream conflicts (especially the same canonicalisation code already present in CORE-004 and the same clock fix already present in S2 v2.1).

1. At each stage inspect its PR against the preceding stage head, verify changed-file scope, request a domain review and resolve findings. **No bulk stack merge.**
2. Ensure required hosted checks on that exact PR head: `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace --all-targets`, `cargo test --workspace --all-targets --features serde_json/preserve_order` where present, Windows `cargo test --workspace --all-targets`, and the pinned Music interop jobs actually defined for that stage. For integration workspace changes, also run independent integration workspace fmt/Clippy/test.
3. Where milestone touches conductor/MoQ/S2/grants, rerun the named real-conductor acceptance suite, preserve the Music SHA, DNA hash, logs, invocation and result. Recheck v1 compatibility and user-data migration non-event.
4. Integrate **one** approved PR via a history-preserving merge, without squash or rebase; then retarget only the *next* draft PR to updated `main`. A prior green run is not a green run for the new merge/retarget commit; require post-retarget CI. Confirm merged functionality in `main` before changing roadmap status.
5. Recheck cross-repository Music PR #44/#47 ordering **before** accepting grant-anchor changes. The current Rust-only `grant-anchor/v2` verifier is not the same as delivering the full `access-grant/v2` issuer/recipient grant protocol.
6. Document any impossible/blocked stage as blocked, not as a pass. No schema activation, app default switch, crate publication, licensing claim or production release is authorised by this plan.

## Review findings and remaining work

- **CORE-001:** green Linux bootstrap; architecture and project licence decision still require owner approval before public distribution.
- **CORE-002:** green S1 interoperability at a pinned Python implementation, but the old `serde_json::Value` canonicaliser is invalid when Holochain enables `serde_json/preserve_order` through feature unification. Draft [PR #13](https://github.com/ConorTttttt/holochain-media-core/pull/13) isolates the later-stack fix and adds fresh pinned Music vector tests under both feature modes; its hosted checks now pass; acceptance is still blocked on review, append-only integration and repeat CI. Expected key input must already be trusted by a caller; this is not a Holochain identity binding.
- **CORE-003:** green Windows/CAS tests; risk remains if the CAS root is maliciously mutated concurrently. Disk-full/power-loss/large-file stress, quota and garbage collection are open.
- **CORE-004:** review the 13-commit, ~40-file scope including inherited CORE-002 canonical JSON fix and synthetic Video release work; least-privilege conductor credentials, MoQ TLS host pinning and blocking I/O. Real-conductor and actual two-device network evidence are different.
- **CORE-005:** typed Rust policy evaluation (not key unwrap), independently issued Music v1 grant/licence vectors; do not infer public/paid entitlements or revocation. Exact milestone Windows CI currently **fails** on a test fixture `SystemTime` overflow; isolated follow-up [PR #12](https://github.com/ConorTttttt/holochain-media-core/pull/12) reproduces the already-applied downstream fix without rewriting any historical SHA. #9 cannot be approved until the fix is reviewed, and #10 cannot be approved until it is included in its integration base.
- **S2 v2 / v2.1:** v2 PoP is a separate opt-in DNA; v2.1 lineage and receipt policy further revise DNA. Historical key policy, DHT freshness, host-attribution enforcement and lost-key recovery require specialist security review; no silent migration.
- **access-grant/v2 / grant anchor:** PR #5 specifies issuance format; PR #6 adds the anchor verifier and a revised DNA. The complete new grant issuance/transport implementation and full application switch are separate cross-repository work. Default recovery refusal is intentional.
- **async private delivery:** proposal only, deferred after Music RC1; no DHT payload or private grant transport change in Media Core.

This document distinguishes **implemented on development branches**, **tested by hosted CI**, **locally tested real-conductor behavior**, and **merged/released**. Only the last category is `main`, and it is currently only the README.
