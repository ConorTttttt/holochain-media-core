# Architecture and ownership boundaries

Status: proposed for CORE-001. This document is an interface decision, not a security certification.

## System map

                 Holochain durable control plane
                 agent identity, signed metadata, host claims
                                      |
                                      v
  Music / Video ---------> Media Core contracts and policy
    presentation            |                 |
    codecs & UX             |                 v
                            |        independently verified grants
                            |
                            +--------> verified storage / cache
                            |              ciphertext only
                            |
                            +--------> MoQ adapter -----------> remote peer
                                   transport bytes        content objects or
                                   and realtime frames    ephemeral live media

## Trust and data placement

**Holochain public DHT:** authenticated agent-authored metadata, immutable content commitments, validated host discovery and future reviewed release records. Never store source media, ciphertext file contents, encrypted private grants or plaintext keys on the public DHT. Privacy-sensitive metadata still requires review.

**Media Core:** owns portable domain types, signatures/commitments validation, rights evaluation, content lifecycle, chunk authenticity and storage/retrieval coordination. It does not own the Holochain conductor, artist UI, payment settlement, codec or player. Implemented: S1 verification (CORE-002), VerifiedCas (CORE-003), S2 identity bindings and resolve/authenticate/fetch orchestration with Holochain and MoQ adapters (CORE-004). Not implemented: grant evaluation (CORE-005), publication authority (CORE-006). Crate map and trust table: docs/CORE-004-holochain-moq-integration.md.

**MoQ:** transport adapter to move already-authorised opaque objects and separate live streams. Transport identity must be bound to Holochain identity, and the data delivered must still be checked against the signed manifest. The transport itself never decides who owns copyright or what a licence allows.

**Storage hosts:** store signed manifests, ciphertext objects and receipts. A receipt proves an authenticated claim that chunks were accepted at one point, not permanent custody, independent replication or proof of retrievability.

**Client:** owns package keys or recipient private key material, verifies grants locally and decrypts only after authenticating signatures and matching package and recipient. Keys must never be exposed in response bodies, logs or DHT entries.

## Separate domains

- PackageId: random 32-byte package identity, never equivalent to a content hash.
- ManifestDigest: SHA-256 of the complete canonical signed manifest envelope.
- Content / publication identity: future durable catalogue identity that can point at immutable package revisions; not implicitly PackageId or ManifestDigest.
- Public artwork and confidential media: independent trust and key-derivation domains.
- Signature verification: cryptographic provenance; not legal copyright ownership or payment proof.
- Reviewer finding: a signed review record; not public release authority.
- Rights declaration: stream / managed-offline / export flags; not a signed, verified entitlement by itself.

## Migration approach

1. Freeze existing Music v1 signed-package and replica-receipt golden fixtures.
2. Implement readers against those fixtures without modifying their canonicalisation or signing rules.
3. Introduce a compatibility adapter into Music with an opt-in test path first.
4. Only after cross-language and two-agent tests may read and write paths be switched.
5. Any new schema is versioned, accepted only by explicit parsers, and retains a tested old-schema path for existing licensed files.
6. Video reuse comes after secure storage and entitlement adapters; retain the independent rights-review boundary.

No shared rewrite of Music playback or Video rendering is required.

## Quality gates

CORE-001: workspace compiles/tests in CI, architecture and threat assumptions documented.
CORE-002: exact Music v1 compatibility vectors and negative cases.
CORE-003: validated ciphertext storage. CORE-004: identity binding, MoQ retrieval and five-conductor separate-agent acceptance (real services; evidence in docs/CORE-004-holochain-moq-integration.md).
A build result is not proof of hardware or internet-readiness.
