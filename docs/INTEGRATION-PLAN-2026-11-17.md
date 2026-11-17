# Media Core integration plan — 17 November 2026

Status: **review plan**, not an approval to merge, publish crates, switch a Music DNA or migrate user data. This document is authoritative for the proposed PR order; the earlier dates/evidence in `current-state.md` remain historical snapshots.

## Verified repository state

- `main`: `0e0a6290729debdb0d1e87c9201900a901adc102` — initial README only; **none** of CORE-001 through grant-anchor is merged.
- `feat/grant-anchor-v21`: `a74a8aec32da03962788ad92810c413103b2ffd3`, **45 commits ahead of main**; contains S1, CAS, Holochain/MoQ, entitlement, S2 and grant-anchor work as *development-only*.
- `docs/async-private-delivery-design`: `1c68bdd373287307013bb9eac5b3530796038429` (two further documentation commits).
- No rebase or squash of existing protocol branches is authorised. The history already contains merge commits `09d8e8c` and `a74a8ae` preserving original reviewed branch commits; preserve both parent relationships.

## Exact staged review points

Every SHA below is the observed branch head on 17 November 2026. Each branch is a descendant of the preceding head; each PR must be independently reviewed against the *preceding* stage, not against `main` until that preceding stage has landed.

| Stage | PR | Head branch | Exact head | Commits over previous | Target / prerequisite |
| --- | --- | --- | --- | ---: | --- |
| CORE-001 bootstrap | #1 | `feat/core-001-bootstrap` | `84b775729ef56b8b9c3d8718000a908b85e76966` | 2 | `main` |
| CORE-002 Music S1 | #2 | `feat/core-002-music-interop` | `9277b621cbec6a67f31a41aa9b5927585fe771c6` | 5 | #1 |
| CORE-003 verified CAS | #3 | `feat/core-003-verified-cas` | `5420d57479fc1453424cac0ffc1c978615798302` | 4 | #2 |
| CORE-004 Holochain/MoQ | **#8 (new draft)** | `ccr-53e220c1-45x2cc` | `4989ee400cec7f60abee91985cea95f494a28a0c` | 13 | #3 |
| CORE-005 entitlements | **#9 (new draft)** | `claude/core-005-entitlements-i7zm0e` | `5f7adf5ff2e3bc7f10836fc1f739114a8a703ff9` | 5 | #8 |
| S2 key binding v2 | **#10 (new draft)** | `feat/s2-key-binding-v2` | `d42b20fc94af491f71d9595fbc3ee01e187ddb57` | 4 | #9 |
| S2 key lifecycle v2.1 | #4 | `feat/s2-v21-key-lifecycle` | `6c1a452306c38818315c1f974a6eb6fe9f33dae8` | 5 | #10 |
| access-grant/v2 specification | #5 | `feat/access-grant-v2-spec` | `09d8e8c80f780e7a83b974d2df7a9c2a485e3013` | 3 | #4 |
| grant-anchor/v2 | #6 | `feat/grant-anchor-v21` | `a74a8aec32da03962788ad92810c413103b2ffd3` | 4 | #5; Music #47 companion |
| async private delivery **design only** | #7 | `docs/async-private-delivery-design` | `1c68bdd373287307013bb9eac5b3530796038429` | 2 | #6 |
| integration status documentation | **subsequent draft** | `docs/agent5-integration-gates-20261117` | new documentation-only commits | — | #7 |

Links: [PRs #1–#10](https://github.com/ConorTttttt/holochain-media-core/pulls), [Music PR #44](https://github.com/ConorTttttt/holochain-music/pull/44), [Music PR #47](https://github.com/ConorTttttt/holochain-music/pull/47).

### Current hosted CI evidence by observed head

| Stage | GitHub Actions run | Evidence |
| --- | --- | --- |
| CORE-001 `84b7757` | [42495525394](https://github.com/ConorTttttt/holochain-media-core/actions/runs/42495525394) | Linux rust fmt, Clippy, test: green |
| CORE-002 `9277b62` | [42524069558](https://github.com/ConorTttttt/holochain-media-core/actions/runs/42524069558) | Linux rust, pinned Music-Python S1 interop: green |
| CORE-003 `5420d57` | [42531817223](https://github.com/ConorTttttt/holochain-media-core/actions/runs/42531817223) | Rust, Music-Python and Windows: green |
| CORE-004 `4989ee4` | [44070154615](https://github.com/ConorTttttt/holochain-media-core/actions/runs/44070154615) | **Green**: Rust fmt/Clippy/tests, Music interop, Windows (three jobs) |
| CORE-005 `5f7adf5` | [44070167413](https://github.com/ConorTttttt/holochain-media-core/actions/runs/44070167413) | **Red**: Rust and Music interop green; Windows overflow in `entitlement_tests::time_policy_boundaries_use_the_injected_clock`. Isolated test-only correction: draft PR #12. |
| S2 v2 `d42b20f` | [44070181258](https://github.com/ConorTttttt/holochain-media-core/actions/runs/44070181258) | **Red**: same inherited Windows `SystemTime` overflow. Rust and Music interop green; rerun after reviewing and integrating portable-clock fix #12. |
| S2 v2.1 `6c1a452` | [43577300233](https://github.com/ConorTttttt/holochain-media-core/actions/runs/43577300233) | Rust (incl. preserve_order), Windows, S1 and S2 Music interoperability: four green jobs |
| grant specification `09d8e8c` | [43577313135](https://github.com/ConorTttttt/holochain-media-core/actions/runs/43577313135) | Four green jobs |
| grant anchor `a74a8ae` | [43577314159](https://github.com/ConorTttttt/holochain-media-core/actions/runs/43577314159) | Four green jobs |
| async design `1c68bdd` | [43736181347](https://github.com/ConorTttttt/holochain-media-core/actions/runs/43736181347) | Four green jobs |

The old assertion that hosted Actions are blocked by billing is superseded by successful runs on 14–15 November. However GitHub Actions does **not** run the slow, multi-conductor real-MoQ suites in the hosted workflow; those remain local test evidence and need per-stage repeatable logs/artifacts.

### Frozen cross-repository references

The development workflow checks out Music source at exact commits:
- S1 packages and CORE-005 grants: `bd7aabc3e9ea1fef1e8e8f674301e1b5ffecb637`.
- S2 proof-of-possession: `f091d5a5da0c2cb46228ea619ab816338311ef9b`.
- S2 v2.1 lifecycle and grant anchors: `64f57d416f42c37d3e3aca1a2170142c0a4cf206`.

Generator scripts import Music's original Python issuance/verifier modules, check the checked-out Music source revision, and generate new cases. Rust compares against Python results and typed negative-case expectations; committed fixture reproduction tests guard deterministic portions only. This is **meaningfully independent signing and verdict execution**, but not a substitute for an external protocol implementation/auditor: the Python testcase expectations are still locally authored, synthetic chain positions model conductor records, and a change to Music's pinned generator would need a review of both sides.

Never change a pin, rebase a referenced branch, or mix the new v2.1 DNA with old v1/v2 persisted data without explicit cross-repo review, fresh Music vector generation, real-conductor tests and a documented opt-in migration/rollback.

## Sequential integration gates

1. At each stage inspect its PR against the preceding stage head, verify changed-file scope, request a domain review and resolve findings. **No bulk stack merge.**
2. Ensure required hosted checks on that exact PR head: `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace --all-targets`, `cargo test --workspace --all-targets --features serde_json/preserve_order` where present, Windows `cargo test --workspace --all-targets`, and the pinned Music interop jobs actually defined for that stage. For integration workspace changes, also run independent integration workspace fmt/Clippy/test.
3. Where milestone touches conductor/MoQ/S2/grants, rerun the named real-conductor acceptance suite, preserve the Music SHA, DNA hash, logs, invocation and result. Recheck v1 compatibility and user-data migration non-event.
4. Integrate **one** approved PR via a history-preserving merge, without squash or rebase; then retarget only the *next* draft PR to updated `main`. A prior green run is not a green run for the new merge/retarget commit; require post-retarget CI. Confirm merged functionality in `main` before changing roadmap status.
5. Recheck cross-repository Music PR #44/#47 ordering **before** accepting grant-anchor changes. The current Rust-only `grant-anchor/v2` verifier is not the same as delivering the full `access-grant/v2` issuer/recipient grant protocol.
6. Document any impossible/blocked stage as blocked, not as a pass. No schema activation, app default switch, crate publication, licensing claim or production release is authorised by this plan.

## Review findings and remaining work

- **CORE-001:** green Linux bootstrap; architecture and project licence decision still require owner approval before public distribution.
- **CORE-002:** green S1 interoperability at a pinned Python implementation; expected key input must already be trusted by a caller. This is not a Holochain identity binding.
- **CORE-003:** green Windows/CAS tests; risk remains if the CAS root is maliciously mutated concurrently. Disk-full/power-loss/large-file stress, quota and garbage collection are open.
- **CORE-004:** review the 13-commit, ~40-file scope including inherited CORE-002 canonical JSON fix and synthetic Video release work; least-privilege conductor credentials, MoQ TLS host pinning and blocking I/O. Real-conductor and actual two-device network evidence are different.
- **CORE-005:** typed Rust policy evaluation (not key unwrap), independently issued Music v1 grant/licence vectors; do not infer public/paid entitlements or revocation. Exact milestone Windows CI currently **fails** on a test fixture `SystemTime` overflow; isolated follow-up [PR #12](https://github.com/ConorTttttt/holochain-media-core/pull/12) reproduces the already-applied downstream fix without rewriting any historical SHA. #9 cannot be approved until the fix is reviewed, and #10 cannot be approved until it is included in its integration base.
- **S2 v2 / v2.1:** v2 PoP is a separate opt-in DNA; v2.1 lineage and receipt policy further revise DNA. Historical key policy, DHT freshness, host-attribution enforcement and lost-key recovery require specialist security review; no silent migration.
- **access-grant/v2 / grant anchor:** PR #5 specifies issuance format; PR #6 adds the anchor verifier and a revised DNA. The complete new grant issuance/transport implementation and full application switch are separate cross-repository work. Default recovery refusal is intentional.
- **async private delivery:** proposal only, deferred after Music RC1; no DHT payload or private grant transport change in Media Core.

This document distinguishes **implemented on development branches**, **tested by hosted CI**, **locally tested real-conductor behavior**, and **merged/released**. Only the last category is `main`, and it is currently only the README.
