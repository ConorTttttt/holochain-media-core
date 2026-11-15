# Development milestones

The full plan is maintained alongside project discussions. These tasks are the repository implementation order, with no claims of completion beyond verified CI/PR evidence.

| ID | Deliverable | Done when |
|---|---|---|
| CORE-001 | Buildable workspace, boundaries, source map, CI and typed identifiers | GitHub CI passes formatting, lint and tests; architecture and threat assumptions reviewed |
| CORE-002 | Python Music v1 package/receipt compatibility | Real Music-generated golden vectors (including invalid cases) verify byte-for-byte in a Rust reader; no Music change |
| CORE-003 | Generic verified storage and interrupted download support | Arbitrary bytes survive corruption, restart and host-outage tests; no keys leak |
| CORE-004 | Holochain/MoQ adapters | Two real agents discover an authenticated storage host and retrieve verified chunks with certificate pinning — **met locally 13 Nov 2026** (five-conductor acceptance; see docs/CORE-004-holochain-moq-integration.md); Windows CI and review pending |
| CORE-005 | Free/private/perpetual entitlement evaluator | Signed grants require matching issuer, recipient, manifest and permissions; duplicate requests and denials have clear outcomes — **verifier for Music private grants/licences implemented 13 Nov 2026** (81 Python vectors, Music opt-in comparison, real-conductor acceptance; see docs/CORE-005-entitlement-verification.md). Public/free policy deferred to CORE-006 publication authority; Windows CI and review pending |
| CORE-006 | Reviewed publication lifecycle | Quarantine, independent finding, authorised release/withdrawal are distinct and tamper-resistant |
| CORE-007 | Music and Video adapters | Music regression suite passes unchanged, then Video uses shared contracts without granting unreviewed playback |
| CORE-008 | Advanced offerings and production readiness | Rental/subscription policy, verified settlement provider, key rotation, NAT/relay, operational hardening, audits and legal review |
| CORE-009 (proposed; after Music RC1) | Asynchronous encrypted private control-message delivery | [Design note](ASYNCHRONOUS-PRIVATE-DELIVERY.md): direct-first / recipient-encrypted DHT fallback for *small* access requests and grants, authenticated receipts, deduplication, privacy/threat review and 3-conductor offline acceptance. No media bytes on DHT; no change to RC1. |

## Release sequence

- **v0.1 technical preview:** CORE-001 through CORE-005 plus the Music adapter with real two-agent streaming, verified offline playback/export and failure injection. Not production.
- **v0.2 multi-app preview:** verified Video approved-release flow and media adapters; public access remains gated on reviewed authority.
- **Production candidate:** audited security, clear pricing/settlement semantics, robust internet delivery, key recovery, platform/hardware testing, licensing and migration/rollback.

## S2 key lifecycle v2.1 — implemented on `feat/s2-v21-key-lifecycle` (13 Nov 2026)

Rotation (continuity-signed), recovery and revocation validated in chain order
by a separate opt-in v2.1 storage DNA (v1 and v2 hashes unchanged); Media Core
`KeyValidity` with an explicit chain-anchored historical policy; host-attributed
`replica-receipt/v2`; four-agent real-conductor suite covering 16 adversarial
cases plus the full MoQ → CORE-005 → Music decrypt path
(docs/S2-KEY-LIFECYCLE-V21.md). Outstanding, explicitly: a grant format whose
issuer is independent of the manifest signer (needed before rotation is
transparent to new grants for older content, and a CORE-006 prerequisite),
agent-key rotation, switching the Music app to v2.1, migration execution.

## S2 key-binding v2 — implemented on `feat/s2-key-binding-v2` (13 Nov 2026)

Proof-of-possession bindings in a separate opt-in v2 storage DNA (v1 DNA hash
unchanged), Media Core assurance levels and policy, real-conductor adversarial
suite and v2 end-to-end acceptance (docs/S2-KEY-BINDING-V2.md). Outstanding,
explicitly: rotation/revocation (`v2.1`), `replica-receipt/v2`, switching the
Music app to the v2 DNA, migration execution.

## Previously next: S2 key-binding v2 (proof of possession), then CORE-006

CORE-005 delivered `check_content_access` for Music `content-grant/v1` and
`personal-licence/v1` (verification only) with Python-generated vectors. The
proof-of-possession key binding proposed alongside it was **not** done: it
needs a versioned Music DNA/format change and a migration plan, and remains
the next security task (CORE-004 finding 2; CORE-005 doc §9). After it,
CORE-006 publication lifecycle supplies the authenticated policy that public
access requires.

## Historical: CORE-005 proposal (as written after CORE-004)

Rust `check_content_access` for Music `content-grant/v1` and `personal-licence/v1` (verification only), Python-generated golden vectors, and a versioned S2 key-binding v2 with proof of possession. See docs/CORE-004-holochain-moq-integration.md.

## Historical: CORE-002 plan

1. Obtain disposable golden test fixtures by executing Music's existing S1 Python module at a frozen commit.
2. Implement strict signed-envelope parsing and canonicalisation with matching limits.
3. Verify Ed25519 only against independently trusted artist and host public keys.
4. Verify all required chunk metadata invariants and digest binding.
5. Add cross-language positive and negative tests in CI, with a documented compatibility/migration policy.
6. Leave Music code and user data untouched until its own adapter PR.

**Do not shortcut the golden-vector step by constructing fixtures with the Rust implementation itself.**
