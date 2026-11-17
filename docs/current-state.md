# Audit baseline and completion status

> **Audit update (17 November 2026):** Earlier sections below are dated historical evidence; assertions that Media Core hosted GitHub Actions remain blocked by billing are **superseded** by successful 14–15 November runs ([43577300233](https://github.com/ConorTttttt/holochain-media-core/actions/runs/43577300233), [43577314159](https://github.com/ConorTttttt/holochain-media-core/actions/runs/43577314159), [43736181347](https://github.com/ConorTttttt/holochain-media-core/actions/runs/43736181347)). All implementation described below is **development-branch only**; `main` remains README-only `0e0a629`. The missing scoped review points now exist as draft PRs #8 (CORE-004), #9 (CORE-005), #10 (S2 key-binding v2). #8 passed all three hosted jobs in [44070154615](https://github.com/ConorTttttt/holochain-media-core/actions/runs/44070154615); #9 ([44070167413](https://github.com/ConorTttttt/holochain-media-core/actions/runs/44070167413)) and #10 ([44070181258](https://github.com/ConorTttttt/holochain-media-core/actions/runs/44070181258)) have green Linux and Music interoperability but Windows fails the inherited out-of-range SystemTime test. Non-rewriting correction is isolated in draft PR #12. Their gates remain open. See [integration plan](INTEGRATION-PLAN-2026-11-17.md). No user-data migration or release approved.


## Grant anchors on the v2.1 DNA (14 November 2026, latest)

Branches: Music `feat/grant-anchor-v21` (code `64f57d4`, docs `b4173fc`) on
`feat/s2-v21-key-lifecycle`; Media Core `feat/grant-anchor-v21` on
`feat/access-grant-v2-spec`. **v2.1 DNA hash is now
`uhC0kF7I2QWYZf2K5-cziQFYZev-7WwNrNQFSSeOtwcLpN5Y98mlf`** (was
`uhC0kiNH8o…`); v1 and v2 rebuilt unchanged. Every row below was re-run on the
new DNA; nothing is carried over from the earlier DNA.

| Check | Result |
|---|---|
| v2.1 integrity unit tests / v2 | 16 pass (12 lifecycle + 4 anchor) / 6 pass |
| Media Core workspace (also `preserve_order`), fmt, clippy | **75 pass** (core 49, retrieval 15, cli 7, release 4); clean |
| Interop, fresh vectors from Music `bd7aabc` / `f091d5a` / `64f57d4` (also `preserve_order`) | core **70 pass**; 154/154 lifecycle queries, 23/23 receipt cases and **16/16 grant-anchor cases** match Music |
| `grant_anchor_v21` (3 real conductors) | **pass 99.1 s**: 8 anchors refused by named integrity rules, 1 refused at decoding; Bob's least-privilege reader and Media Core verify; Music's verifier agrees (5/5) |
| `s2_key_lifecycle_v21` (4 conductors, real MoQ, CORE-005, Music decrypt) | **pass 142.4 s, 21 integrity refusals reproduced** |
| `s2_key_binding_v2` / `core004_acceptance` v1 (Music pinned `bd7aabc`) / v2 | **pass** 247.6 s (23 refusals) / 189.1 s / 193.7 s |
| Music `unittest discover -s tests`; bridge `cargo check` | **513 run: 465 OK / 48 skipped / 0 fail**; pass |

Hosted Media Core CI is still blocked by account billing; nothing above is a
hosted result.

## S2 key lifecycle v2.1 update (13 November 2026)

Branches (local, not pushed): Media Core `feat/s2-v21-key-lifecycle` from
`feat/s2-key-binding-v2` @ d42b20f; Music `feat/s2-v21-key-lifecycle` from
`feat/s2-key-binding-v2` @ 17a6276, code at cfd4807 (lifecycle vectors pinned
there). Full results table: docs/S2-KEY-LIFECYCLE-V21.md §14.

| Check | Result |
|---|---|
| v1 / v2 DNA hashes | unchanged (rebuilt) |
| v2.1 DNA | `uhC0kiNH8oLxWdMyNxpTP-cxCnB6M04rVfcdPkcFmY2cUbVm8Brti`; integrity tests 12 pass |
| Media Core workspace (also `preserve_order`) | **74 pass** (core 48, retrieval 15, cli 7, release 4) |
| Interop, fresh vectors from all pinned Music commits (also `preserve_order`) | core **69 pass**; 154/154 lifecycle queries and 23/23 receipt cases match Music |
| `s2_key_lifecycle_v21` (4 conductors, MoQ, CORE-005, Music decrypt) | **pass 154.3 s; 143.0 s on committed code** |
| `s2_key_binding_v2`, `core004_acceptance` v1 and v2 | **pass** 304.4 s / 235.1 s / 215.8 s |
| Music unittest | **506 run: 458 OK / 48 skipped / 0 fail** |

Not run: Windows CI, GitHub Actions (nothing pushed), two-device network.

## S2 key-binding v2 update (13 November 2026)

Branches (local, not pushed): Media Core `feat/s2-key-binding-v2` from
`claude/core-005-entitlements-i7zm0e` @ 5f7adf5 (pushed CORE-005); Music
`feat/s2-key-binding-v2` from `claude/core-005-entitlements-i7zm0e` @ 4bd3db4,
code at f091d5a (key-binding vectors pinned there), docs 17a6276.

| Check | Result |
|---|---|
| Media Core fmt; clippy `-D warnings` (also with `preserve_order`) | pass |
| `cargo test --workspace --all-targets` (also `preserve_order`) | **63 pass** (core 40, retrieval 12, cli 7, release 4) |
| Interop with fresh S1 + entitlement + key-binding vectors (also `preserve_order`) | core **61 pass** |
| `generate_music_key_binding_vectors.py` (Music @ f091d5a) | 26 cases, Python self-check passes |
| `integration` fmt + clippy `-D warnings` | pass |
| v1 storage DNA rebuilt from unchanged `dna/` | wasm `cf75c4bd…`, DNA `uhC0kkLUOg2uytGWLz_sTeVtfJBqa0criBmAYAPwAIUhoDp_9G4RV` (identical) |
| v2 storage DNA `dna-v2/` | DNA `uhC0k_-f-D4bF9w53gD2jXkA4RqYQ_bf0dRdF8rMkJG_tS8WGRamb`; integrity unit tests 6 pass |
| `s2_key_binding_v2` (4 real conductors, v1 + v2 DNAs) | **pass 231.3 s**: 23 forged writes refused by integrity rules (B, C, D, E, F, G×13, I, J×2), 2 refused at entry decoding, discovery + Media Core verification, legacy v1, duplicate/conflict policy |
| `core004_acceptance` with `CORE_S2_KEY_BINDING=v2` (v2 DNA, 5 conductors, MoQ, CORE-005, Music unwrap) | **pass 186.6 s** |
| `core004_acceptance` v1 regression (Music @ bd7aabc) | **pass 185.2 s** |
| Music `unittest discover`, adapter enabled, S2 branch | **445 OK / 34 skipped / 0 fail** (479 run) |
| Music app bridge `cargo check` with v2 routes | pass |

Not run: Windows CI; Music `music-e2e` Sweettests (they target the v1 DNA,
which is unchanged); physical network.

## CORE-005 update (13 November 2026, later session)

Branches: Media Core `claude/core-005-entitlements-i7zm0e` on top of
`ccr-53e220c1-45x2cc` @ 4989ee4 (history unchanged); Music
`claude/core-005-entitlements-i7zm0e` on top of `ccr-53e220c1-45x2cc` @
5d37b76. Vectors and the acceptance suite use Music `bd7aabc` (its
`content_grants.py` is identical on 5d37b76). Same container/toolchain as
below (Rust 1.97.0, Python 3.13, cryptography 46.0.4, no IPv6 → shim).

| Command | Before CORE-005 | After CORE-005 |
|---|---|---|
| `cargo fmt --all -- --check`; `cargo clippy --workspace --all-targets -- -D warnings` | pass | pass |
| `cargo test --workspace --all-targets` | 38 pass (core 20, retrieval 10, cli 4, release 4) | **54 pass** (core 33, retrieval 10, cli 7, release 4) |
| same with `--features serde_json/preserve_order` | 38 pass | **54 pass** |
| S1 + entitlement Python interop (`music-interop-tests`, fresh vectors from both generators) | core 41 | **core 54** (+ cli 7, retrieval 10, release 4); also with `preserve_order`: core 54 |
| `scripts/generate_music_entitlement_vectors.py` (pinned Music) | — | 81 cases; Python self-check passes; Rust tests pass on the committed run and on a fresh run |
| `integration` fmt, `clippy -D warnings`, content-moq unit tests | pass, 2 | pass, 2 |
| `core004_acceptance` (5 conductors, real MoQ hosts, IPv6 shim) | pass 191.0 s (CORE-005 code present, before new e2e checks) | **pass 197.8 s** with `[core005]` Rust entitlement checks |
| Music `unittest discover -s tests`, adapter enabled (short `TMPDIR`) | 453 OK / 34 skipped (CORE-004 record) | **428 OK / 34 skipped / 0 fail** (462 run; +9 CORE-005 tests) |
| Music full suite, adapter disabled | — | 414 OK / 48 skipped / 0 fail |

Note: one Music test (`test_v1_app_storage.PathTests`) refuses data paths
whose keystore socket exceeds 100 bytes; with this session's long scratchpad
`TMPDIR` it errors before any CORE-005 code runs. Rerun with a short
`TMPDIR` passes; it is environmental.

**Not run:** Windows CI (nothing pushed); physical two-device network.

| Component | Implemented | Tested | End-to-end verified | Remaining |
|---|---|---|---|---|
| Content permissions | **Yes: Rust verifier for Music `content-grant/v1` and `personal-licence/v1`** (policy level; unwrap stays in app) | 81 Python vectors, mutation sweep, Alice/Bob/Mallory, CLI tests, Music comparison (9) | Yes: Rust check on real-conductor content before Music unwrap/decrypt | PoP key binding; public/commercial policies; revocation; Windows CI |

## CORE-004 baseline (earlier the same day)

Fresh audit: **13 November 2026** (remote heads fetched in this session).
Previous snapshot (8 November) is superseded.

## Repository heads

| Repository | Default branch head | Relevant development head | Open PR dependencies |
|---|---|---|---|
| holochain-media-core | `main` 0e0a629 (README only) | `feat/core-003-verified-cas` 5420d57 (CI run 42531817223: Rust, Python interop, Windows all pass); CORE-004 on `ccr-53e220c1-45x2cc` | #1 → #2 → #3 stacked drafts; CORE-004 stacks on #3 |
| holochain-music | `main` bd7aabc | CORE-004 adapter on `ccr-53e220c1-45x2cc` (5d37b76) | #38 artwork (two-device pending), #43 pause/resume (real MoQ acceptance pending): not adopted |
| Holochain_Video | `main` 6e878c4 | unchanged | #30 → #32 → #33 stacked; #33: 53 pass / 1 fail (runtime capability revocation) |
| holochain-moq | `main` fba4ccf (PR #1 watch ownership merged) | unchanged | `crates/realtime`, `crates/protocol` identical to ccd9a8e used by Music's host |

## Environment used for evidence

Linux 6.18 container, 4 vCPU, no IPv6 in the kernel, no audio/camera
hardware; Rust 1.97.0 + wasm32 target; Python 3.13 venv with
cryptography 46.0.4; Holochain 0.7.0 (Sweettest, compiled from crates.io);
`hc-dna` from holochain_cli_bundle 0.7.0; no installed `holochain`/`lair`
binaries (not needed by Sweettest). Holochain websockets need the
test-only IPv6 errno shim on this kernel.

## Test commands that actually ran

| Command | Result |
|---|---|
| CORE-003 `cargo fmt --check`, `clippy -D warnings`, `cargo test --workspace --all-targets` | pass (13 tests) before changes |
| CORE-003 Python interop (`scripts/generate_music_vectors.py` + `--features music-interop-tests`) | pass (28) before changes |
| Root workspace after CORE-004 (fmt, clippy, tests; plus `serde_json/preserve_order`) | pass: core 20, retrieval 10, cli 4, release 4 |
| Python interop after CORE-004 (with and without `preserve_order`) | pass: core 41 |
| `integration` `holochain-content-moq` unit tests | pass (2) |
| `core004_acceptance` (5 conductors, real MoQ hosts) | **pass** twice: 240.8 s, and 246.7 s on final code |
| `integration` workspace fmt + `clippy -D warnings` | pass |
| Music `python -m unittest discover -s tests` on `main` | 444 OK, 34 skipped |
| Same on Music CORE-004 branch with adapter enabled | 453 OK, 34 skipped |

Windows CI for CORE-004 has **not** run (no push in this session).

## Status matrix (evidence-based)

| Component | Implemented | Tested | End-to-end verified | Remaining work |
|---|---|---|---|---|
| Core contracts | Yes: typed IDs, rights flags, S1/S2 types, retrieval traits | Unit + Python vectors | Yes (acceptance suite) | Grant/entitlement contract (CORE-005); release record format review |
| Music S1 compatibility | Yes (CORE-002 + canonical-JSON fix) | 41 Python-vector tests, with/without `preserve_order` | Yes: Python-made packages verified and decrypted by Music after Rust retrieval | Windows run of new CI steps |
| Verified ciphertext CAS | Yes (CORE-003 + `repair_chunk`) | Unit, mock-transport, Music adapter comparison | Yes: real interruption, resume, repair, duplicate, bounded files | Quotas/GC, no-follow fs ops, power-loss, 1 GiB, Windows hardware |
| Holochain identity binding | Yes (Rust port of Music S2 checks + conductor resolver) | Unit + Python vectors + Music comparison | Yes: real conductors, forged writes refused, false ownership rejected | Proof-of-possession key binding, rotation/revocation, host-agent in receipt (findings 2–3) |
| MoQ encrypted retrieval | Yes (Music v1 host protocol client, pinned TLS) | Unit + acceptance | Yes: real QUIC/MoQT, pin mismatch, tampered host, host kill, alternate host, outages | NAT/relay, reconnect/back-off, non-loopback deployment review |
| Content permissions | Not in Media Core (Music's existing grants/licences used) | Music's suite + acceptance negative cases | Partially: Music boundaries exercised on a VerifiedCas replica | CORE-005 Rust evaluator; rentals/subscriptions/payments not started |
| Music adapter | Yes: opt-in CLI + Python module, disabled by default | 9 Music tests (7 comparisons) + full regression | Library offline readiness and PCM playback from Core store | Windows CLI run; decision on any production switch |
| Video adapter | Contract + test-only synthetic authority (`content-release`) | 4 unit tests | No (no production authority; no Video code changed) | Video #22/#23/#24, PR #33 revocation fix, packaging path, DNA migration plan |

This is a technical milestone, not production readiness.
