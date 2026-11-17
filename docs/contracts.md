# Contract compatibility baseline (CORE-001)

This is a reference for CORE-002. **No signature, manifest or grant verifier is implemented in the current core crate.** Do not use these notes as an implementation of access control.

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
- Canonical JSON: Python json.dumps with sort_keys=True, separators=(',', ':'), ensure_ascii=False and allow_nan=False, encoded UTF-8. Cross-language byte-for-byte agreement is not yet tested.
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
