# ADR 0002 — Versioning and migration

Status: proposed, 8 November 2026.

## Decision

Treat immutable package identity, signed manifest digest, catalogue identity and rights grant as distinct domain objects. Avoid guessing a new universal on-wire format before verifying Music S1 compatibility. Reject unknown schema versions and unknown rights flags.

## Compatibility discipline

- PackageId remains a randomly generated 32-byte identifier.
- ManifestDigest denotes SHA-256 of the complete canonical signed envelope.
- Existing Music S1 canonical JSON bytes and Ed25519 signatures are authoritative golden fixtures until a reviewed schema upgrade.
- A future catalogue ContentId is separately versioned and may reference multiple immutable package revisions.
- Schema migration requires explicit parsing, recorded fixture provenance, old-data tests, rollback guidance and no implicit re-signing.
- The rights bitset is currently local type scaffolding, **not** a signed wire protocol and not an authorisation engine.

## Consequences

CORE-001 implements only typed markers. CORE-002 defines stable wire compatibility after comparison to independently generated Python fixtures. Users must not infer that current types validate provenance or licences.
