# Audit baseline and external dependencies

Snapshot: 8 November 2026. GitHub state was inspected via the connected repository API. This is not a fresh build, CI execution or real-device test.

| Repository | Audited main/head | Existing work | Open integration gate |
|---|---|---|---|
| ConorTttttt/holochain-media-core | previously empty; bootstrap seed 0e0a629 | CORE-001 branch | first PR, CI and review |
| ConorTttttt/holochain-moq | ccd9a8e | Holochain discovery, QUIC/MoQ, video/audio crates, app-web | PR #1 watch-scoped stop API is draft and client-breaking |
| ConorTttttt/holochain-music | bd7aabc | encrypted package/receipts, Holochain bindings, private grants, streaming and offline library | PR #38 two-device artwork testing; PR #43 real-transfer pause/resume/retry acceptance |
| ConorTttttt/Holochain_Video | 3556592 | main is minimal; Sprints 1–8 in draft branches | PRs #1–#8 stacked; PR #9 bridges MoQ with development workaround; real reviewed public release absent |

## Dependency and merge notes

- MoQ PR #1 (feature/watch-ownership, base main) introduces watch_id and bearer-token stop. Video PR #9 (sprint-3/moq-dev-port, base sprint-3/moq-live-lab) predates the upstream protocol fix. Integrate and test as one coordinated change; no blind merge of incompatible APIs.
- Video PRs #1 to #8 form a stacked dependency chain, with PR #9 branching off Sprint 3. Changes to Sprint 3 require careful downstream rebasing and regression tests.
- Video PR #7 records independent reviewer findings but does not approve legal rights, create a release event or provide a public playable URL.
- Music PRs #41 and #42 merged on 7 November 2026. PR #43 reported 455 Python tests (34 skipped) on Ubuntu but still needs a real browser/MoQ transfer test. PR #38 lacks required live two-device tests.
- Music has many older open draft PRs that overlap code now on main; triage each by ancestry and test evidence rather than merging all.
- A Windows WASAPI physical sound-quality issue and CAL-1.0 redistribution/licensing review remain app release gates; they are not solved by core scaffolding.

## Freeze points for CORE-002

- Music v1 source file: holochain_storage/package.py at bd7aabc or an explicitly recorded adapter-compatible revision.
- Signing and receipt key bindings: compare holochain_storage/holochain_identity.py, relevant Holochain DNA and catalogue integrity zomes.
- MoQ adapter: select a documented, tested commit once PR #1 is integrated with Video #9.
- Preserve byte-identical Python canonicalisation for Music fixtures, not only JSON structure.

## Review links

- https://github.com/ConorTttttt/holochain-moq/pull/1
- https://github.com/ConorTttttt/Holochain_Video/pull/9
- https://github.com/ConorTttttt/Holochain_Video/pull/7
- https://github.com/ConorTttttt/holochain-music/pull/38
- https://github.com/ConorTttttt/holochain-music/pull/43
