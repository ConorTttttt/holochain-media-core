# CORE-002 — Python Music S1 signing and verification compatibility

Status: pre-release. Source of truth for the existing wire format:
[holochain-music package.py](https://github.com/ConorTttttt/holochain-music/blob/bd7aabc3e9ea1fef1e8e8f674301e1b5ffecb637/holochain_storage/package.py),
at commit bd7aabc3e9ea1fef1e8e8f674301e1b5ffecb637.

## Boundaries

This increment adds a read-only Rust verification API for Music S1 signed encrypted-package manifests and signed replica receipts. The caller must supply a separately authenticated expected artist/host Ed25519 public key; the embedded signer in a JSON message is never considered sufficient authority. Exact signed-envelope digest binding is checked.

The SHA-256 of a ciphertext object and its byte length can be checked against the signed chunk manifest; this is **not** AES-GCM plaintext authentication or proof that the caller has a grant. The core does not decrypt, wrap keys, authorise playback, take payments, validate legal rights, enforce expiry or prove continuing replica custody. These require separate milestones.

## Public Rust API

- verify_music_manifest(raw_json_bytes, pinned_publisher_key) -> VerifiedManifest
- verify_music_ciphertext(verified_manifest, chunk_index, ciphertext) -> Result
- verify_music_receipt(raw_json_bytes, verified_manifest, pinned_host_key) -> VerifiedReceipt

Unknown schemas, keys, duplicate fields and malformed data are rejected. Data limits match Music S1, with a strict 8 MiB + 1024 byte transport-envelope cap. The verifier accepts only Python S1 data types (integers and strings) and exact named fields; it does not permit arbitrary metadata extensions.

**Binding limitation:** Passing a raw public key is not itself Holochain identity verification. The separately authenticated identity-to-key binding belongs in CORE-004.

## Independent reference verification in CI

The cross-language test *executes Music's real Python package.py*, pinned to a specific commit, with synthetic disposable data and deterministic development signer seeds. Music's code produces fresh signatures, encrypted chunks and replica receipts, then Rust verifies them. This avoids Rust testing signatures it made itself.

Run with an installed Rust toolchain, Python 3.12 and git access:

    git clone https://github.com/ConorTttttt/holochain-music target/music-reference
    git -C target/music-reference checkout bd7aabc3e9ea1fef1e8e8f674301e1b5ffecb637
    python -m pip install cryptography==46.0.4
    python scripts/generate_music_vectors.py --music-repo target/music-reference --output target/music-golden-vectors.json
    MUSIC_VECTORS=target/music-golden-vectors.json cargo test --workspace --all-targets --features music-interop-tests

Ordinary cargo test runs the self-contained crate tests; the additional feature cannot run without independent Python vectors.

## Review gates remaining for CORE-002

- CI green for native Rust and pinned Python compatibility jobs.
- Verify real Music generated signatures, ciphertext hashes, signed receipts and empty-package digests.
- Negative cases: bad signer, altered body, duplicate keys, unknown fields, wrong types, reused nonces, invalid chunk indexes/sizes, incorrect receipt binding, oversized inputs.
- Confirm actual Holochain identity-to-key binding separately (CORE-004).
- Independent cryptographic input-handling review before a production security claim.
- No changes to Music existing data or schema; additional incompatible formats require explicit versioned adapters.

Tests use ephemeral synthetic binary content only. No private production keys or real users' content are committed.
