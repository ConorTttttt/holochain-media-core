# Contract compatibility baseline (CORE-001)

Originally the CORE-001 reference for CORE-002. Since then the manifest/receipt verifier (CORE-002), VerifiedCas (CORE-003), S2 identity bindings (CORE-004) and grant/licence **verification** (CORE-005, see "Existing Music grants" below) are implemented. Canonical JSON is now byte-for-byte tested against Python and no longer depends on serde_json map ordering. Do not use these notes as an implementation of access control.

## Existing Music S1 format

Source of truth: holochain-music/holochain_storage/package.py on the audited main branch (see current-state.md).

- Signed package wrapper fields: body, signer, signature (exact key names).
- Body schema: holochain-storage/encrypted-package/v1.
- Body fields: schema, file_id, cipher, chunk_size, total_plain_bytes, chunks.
- file_id: random 32 bytes rendered as 64 lowercase hexadecimal characters.
- cipher: AES-256-GCM.
- Encrypted chunks: index, sha256 of ciphertext, cipher_bytes, plain_bytes, nonce.
- Chunk authentication data: domain prefix "holochain-storage/chunk/v1", NUL byte, file_id bytes, 64-bit big-endian chunk index.
- Manifest signing: Ed25519 signature over canonical JSON of the body, with a separately pinned and Holochain-authenticated signer.
- Canonical JSON: Python json.dumps with sort_keys=True, separators=(',', ':'), ensure_ascii=False and allow_nan=False, encoded UTF-8. Cross-language byte-for-byte agreement is tested (CORE-002 vectors); keys are sorted explicitly in Rust (`compat::canonical_json`).
- **Manifest digest:** SHA-256 over the canonical JSON of the complete signed package wrapper, not merely its body.
- Existing prototype limits: 4 MiB maximum chunk bytes, 16,384 chunks, 64 GiB maximum source size, 8 MiB maximum manifest JSON; the later integrated app may impose additional restrictions.

## Existing S1 receipt

- Schema: holochain-storage/replica-receipt/v1.
- Body fields: schema, file_id, manifest_sha256, chunk_count, received_at.
- Signature: storage-node Ed25519 signing key, checked against the independently expected node identity; recipient must also verify exact package digest.
- Receipt means the node asserted successful reception and verification at that moment. It is **not** a custody SLA or formal proof of retrievability.

## Key separation and rights

- Media content-key never appears in the public signed manifest, DHT, host receipts or transport-identity record.
- Perpetual personal grants wrap the content key to a recipient X25519 public key; payment is separate and not established by the grant signature.
- Streaming access, managed offline caching and independent plaintext export are distinct permissions.
- A permanent exported copy cannot be cryptographically revoked.
- No automatic legal rights verification or rental DRM guarantee is implied.

## Existing Music grants (CORE-005)

Source of truth: holochain-music/music_catalogue/content_grants.py at bd7aabc.
Envelope `{body, signer, signature}`; Ed25519 over canonical(body) by the
owner's S2 `owner-manifest` key; canonical(envelope) ≤ 4096 bytes.

- `holochain-music/content-grant/v1` body: schema, owner_agent,
  listener_agent, file_id, manifest_sha256, recipient_key_hex,
  ephemeral_key_hex, salt_b64, nonce_b64, wrapped_key_b64, issued_at,
  expires_at. `issued_at ≤ now + 120`, `now < expires_at`,
  `1 ≤ expires_at − issued_at ≤ 86400`. Rights: stream only.
- `holochain-music/personal-licence/v1` body: the same minus expires_at, plus
  licence_id (32 lowercase hex) and terms (`perpetual-personal-use`).
  `issued_at ≤ now + 120`; no expiry. Rights: stream, managed offline, export.
- Key wrap: X25519(ephemeral, recipient) → HKDF-SHA256(salt, info=context) →
  AES-256-GCM(nonce, aad=context) of the 32-byte content key; context =
  domain prefix + NUL + canonical JSON of the signed scope (stream:
  `content-grant/hkdf-aad/v1`; licence: `personal-licence/hkdf-aad/v1`).
- `holochain-music/personal-perpetual-grant/v1` (S1 prototype,
  holochain_storage/grant.py): not used by the app; rejected as unsupported.

Rust verification and its exact semantics: docs/CORE-005-entitlement-verification.md.

## CORE-002 required vectors

Generate fixtures from a fixed Music revision and record that revision and provenance:
1. Signed non-empty package and exact canonical body bytes.
2. Signed empty package.
3. Signed receipt from a distinct node signer.
4. SHA-256 of exact signed package wrapper.
5. Expected chunk nonce, AAD, ciphertext length, hash and file-id representation.
6. Tampered signatures, changed body after signing, wrong signer, wrong file ID, changed digest, duplicate chunk index, reused nonce, oversized inputs, mixed-case hex and unsupported schema.
7. Unicode canonicalisation and numeric boundary cases to prevent Python/Rust divergences.

Never check in private content keys, production credentials or actual users' media. Use independently generated disposable fixtures only. Golden vectors must be compared against the current Music implementation, not hand-reconstructed assumptions.
