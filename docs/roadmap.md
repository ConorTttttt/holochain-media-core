# Development milestones

The full plan is maintained alongside project discussions. These tasks are the repository implementation order, with no claims of completion beyond verified CI/PR evidence.

| ID | Deliverable | Done when |
|---|---|---|
| CORE-001 | Buildable workspace, boundaries, source map, CI and typed identifiers | GitHub CI passes formatting, lint and tests; architecture and threat assumptions reviewed |
| CORE-002 | Python Music v1 package/receipt compatibility | Real Music-generated golden vectors (including invalid cases) verify byte-for-byte in a Rust reader; no Music change |
| CORE-003 | Generic verified storage and interrupted download support | Arbitrary bytes survive corruption, restart and host-outage tests; no keys leak |
| CORE-004 | Holochain/MoQ adapters | Two real agents discover an authenticated storage host and retrieve verified chunks with certificate pinning |
| CORE-005 | Free/private/perpetual entitlement evaluator | Signed grants require matching issuer, recipient, manifest and permissions; duplicate requests and denials have clear outcomes |
| CORE-006 | Reviewed publication lifecycle | Quarantine, independent finding, authorised release/withdrawal are distinct and tamper-resistant |
| CORE-007 | Music and Video adapters | Music regression suite passes unchanged, then Video uses shared contracts without granting unreviewed playback |
| CORE-008 | Advanced offerings and production readiness | Rental/subscription policy, verified settlement provider, key rotation, NAT/relay, operational hardening, audits and legal review |
| CORE-009 (proposed; after Music RC1) | Asynchronous encrypted private control-message delivery | [Design note](ASYNCHRONOUS-PRIVATE-DELIVERY.md): direct-first / recipient-encrypted DHT fallback for *small* access requests and grants, authenticated receipts, deduplication, privacy/threat review and 3-conductor offline acceptance. No media bytes on DHT; no change to RC1. |

## Release sequence

- **v0.1 technical preview:** CORE-001 through CORE-005 plus the Music adapter with real two-agent streaming, verified offline playback/export and failure injection. Not production.
- **v0.2 multi-app preview:** verified Video approved-release flow and media adapters; public access remains gated on reviewed authority.
- **Production candidate:** audited security, clear pricing/settlement semantics, robust internet delivery, key recovery, platform/hardware testing, licensing and migration/rollback.

## Next PR: CORE-002

1. Obtain disposable golden test fixtures by executing Music's existing S1 Python module at a frozen commit.
2. Implement strict signed-envelope parsing and canonicalisation with matching limits.
3. Verify Ed25519 only against independently trusted artist and host public keys.
4. Verify all required chunk metadata invariants and digest binding.
5. Add cross-language positive and negative tests in CI, with a documented compatibility/migration policy.
6. Leave Music code and user data untouched until its own adapter PR.

**Do not shortcut the golden-vector step by constructing fixtures with the Rust implementation itself.**
