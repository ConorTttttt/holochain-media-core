# Audit baseline and completion status

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
