# Video integration groundwork (CORE-004, Phase 5)

Status: **contract + test-only adapter. No Video code changed. No public
delivery enabled.** Audited Holochain_Video `main` 6e878c4; open stack PR #30
(reviewer governance/viewer/security), #32 (isolated local CI), #33 (real
agent/reviewer acceptance: 53 pass, **1 fail — old revoked capability
credential still accepted at runtime**). Issues #20–#29 reviewed; #23
(reviewed publishing) and #24 (authorised media delivery) are open.

A separate capability-only reproduction of the PR #33 revocation failure was
**not found** in any repository, pull request or issue reachable from this
session (searched issues, PRs, commits and code for revocation/capability).
CORE-004 does not depend on, or claim, its resolution.

## Two different "receipts"

| | Video ingest receipt | Music replica receipt |
|---|---|---|
| Schema | `holochain-video.ingest-receipt.v1` | `holochain-storage/replica-receipt/v1` |
| Produced by | local `creator-ingest.mjs` server | storage host |
| Signed | no (local JSON, 0600) | Ed25519 by a Holochain-bound host key |
| Proves | bytes with this plaintext SHA-256 were received and **quarantined** (`published:false`, `rightsVerified:false`) | host accepted and verified ciphertext for an exact signed manifest digest at a time |
| Authorises | nothing | nothing (not custody, not access) |

Neither is a publication decision. A catalogue proposal is agent-authored
metadata awaiting review; a reviewer finding is an opinion that can conflict
with others. None of them may be turned into release or distribution.

## Contract (`crates/content-release`)

```
creator upload → quarantine → checks → proposal → independent review
      │ (Video, unchanged)                                    │
      ▼                                                       ▼
GovernanceEvidence::{IngestReceipt, CatalogueProposal, ReviewerFinding}
      .authorize()  ── always Err(NotAnAuthorization) ──✗

PublicationAuthority::authorize(ReleaseRequest{publisher_agent, source_sha256, decision_ref})
      ── only way to mint ──► ReleaseAuthorization (no public constructor)
                                   │
register_release(&auth, &OwnedManifest, source_sha256, ciphertext, &VerifiedCas)
      checks publisher == owner agent, source hash == authorised hash,
      stores manifest-verified ciphertext, returns UNSENT S2 file commitment
      + draft release record {publisher, source_sha256, file_id, manifest_sha256,
        decision_ref, authority}
```

* No production `PublicationAuthority` exists. One must verify, from
  Holochain, an authorised, non-revoked decision by an allowlisted reviewer
  governance process for exactly this source hash — which depends on Video
  #22/#23 and on resolving the PR #33 runtime revocation failure.
* `SyntheticTestAuthority` compiles only in tests or with the
  `synthetic-release-fixture` feature and approves only decision references
  beginning `synthetic-test-decision:`.
* `register_release` does not write to Holochain, start a listener, receive
  a content key, or expose plaintext. Distribution would still require the
  CORE-004 host records (key binding, replica claim, endpoint) **and** an
  access decision (CORE-005).
* The plaintext ↔ package link (`source_sha256` ↔ `manifest_sha256`) can only
  be attested by the packager, who holds the content key. A grant holder can
  verify it after decryption.

Tests (`cargo test -p holochain-content-release`): evidence never authorises
(including a receipt edited to claim `published:true`); synthetic authority
refuses non-synthetic references; synthetic release registers verified
ciphertext idempotently; publisher/source mismatches are denied before any
write; tampered ciphertext is refused by `VerifiedCas`.

## What Video would do next (not done here)

1. Package an approved rendition with an S1-compatible packager (Music's
   Python packager today; a Rust packager would be a separate reviewed task)
   inside a non-public directory, outside `public/` and outside the tus
   quarantine store.
2. Publish S2 key binding + file commitment from the publisher agent, and host
   records from storage agents, in a **new** storage DNA instance or after an
   approved migration — never by changing existing DNA hashes, reviewer
   allowlists or live conductors.
3. Serve ciphertext only through the certificate-pinned host protocol; gate
   keys through CORE-005 access decisions; keep HLS/MP4 and MoQ live
   development paths as they are.
