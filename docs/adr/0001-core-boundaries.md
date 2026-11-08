# ADR 0001 — Shared Content Core boundaries

Status: proposed, 8 November 2026.

## Decision

Use one reusable file-type-independent content library for package/receipt verification, storage integrity, rights evaluation and lifecycle contracts. Keep Holochain as durable identity/control, MoQ as transport and host nodes as ciphertext holders. Keep codec/transcoding/playback and UI in Music and Video.

## Reasons

Music already contains generic encrypted storage but it is embedded in a media-specific repository. Video is building independent creator/review logic. Extracting contract-first adapters reduces duplicated security code without destabilising tested playback.

## Guardrails

No content or private keys in public DHT. Signatures are provenance, not proof of legal rights or payment. Receipt is not proof of long-term custody. Offline rental is not secure DRM on untrusted clients. Public artwork and confidential media have separate key/trust domains.

## Consequences

The core must accept existing Music S1 fixtures unchanged before it introduces a new format. Music and Video retain their existing data and APIs until explicit migration tests pass. Licensing and legal distribution review remain separate release gates.
