//! Read-only verification of Holochain Music's S1 signed packages and receipts.
//! Caller MUST independently authenticate the expected signer from Holochain.
//! This module does not decrypt media or authorise licences/payment.

use crate::{ManifestDigest, PackageId, MUSIC_PACKAGE_V1, MUSIC_RECEIPT_V1};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::DateTime;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashSet;

pub const MAX_CHUNK_BYTES: u64 = 4 * 1024 * 1024;
pub const MAX_CHUNKS: usize = 16_384;
pub const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024 * 1024;
pub const MAX_MANIFEST_BYTES: usize = 8 * 1024 * 1024;
const MAX_ENVELOPE_BYTES: usize = MAX_MANIFEST_BYTES + 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerifyError {
    TooLarge,
    InvalidJson,
    WrongSigner,
    InvalidSignature,
    InvalidManifest,
    InvalidReceipt,
    InvalidCiphertext,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope<T> {
    body: T,
    signer: String,
    signature: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestBody {
    schema: String,
    file_id: String,
    cipher: String,
    chunk_size: u64,
    total_plain_bytes: u64,
    chunks: Vec<ChunkBody>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChunkBody {
    index: u64,
    sha256: String,
    nonce: String,
    plain_bytes: u64,
    cipher_bytes: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiptBody {
    schema: String,
    file_id: String,
    manifest_sha256: String,
    chunk_count: u64,
    received_at: String,
}

/// Metadata authenticated by a trusted publisher signature.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChunkMetadata {
    pub index: u64,
    pub ciphertext_sha256: [u8; 32],
    pub nonce: [u8; 12],
    pub plain_bytes: u64,
    pub cipher_bytes: u64,
}

/// Source-authenticated S1 package, not a content key or access grant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedManifest {
    pub(crate) package_id: PackageId,
    pub(crate) digest: ManifestDigest,
    pub(crate) signer: [u8; 32],
    pub(crate) total_plain_bytes: u64,
    pub(crate) chunk_size: u64,
    pub(crate) chunks: Vec<ChunkMetadata>,
}

/// Authenticated host acceptance claim; not proof of continuing custody.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedReceipt {
    pub(crate) signer: [u8; 32],
    pub(crate) manifest_digest: ManifestDigest,
    pub(crate) chunk_count: u64,
    pub(crate) received_at: String,
}

impl VerifiedManifest {
    /// Cryptographically authenticated opaque package identity.
    pub fn package_id(&self) -> PackageId {
        self.package_id
    }
    /// SHA-256 of the exact canonical signed wrapper.
    pub fn digest(&self) -> ManifestDigest {
        self.digest
    }
    /// Key authenticated as the publisher of this package.
    pub fn signer(&self) -> &[u8; 32] {
        &self.signer
    }
    /// Total original unencrypted file size.
    pub fn total_plain_bytes(&self) -> u64 {
        self.total_plain_bytes
    }
    /// Chunk size used in the original package.
    pub fn chunk_size(&self) -> u64 {
        self.chunk_size
    }
    /// The authenticated ordered object descriptions.
    pub fn chunks(&self) -> &[ChunkMetadata] {
        &self.chunks
    }
}

impl VerifiedReceipt {
    /// Verified storage-host Ed25519 key.
    pub fn signer(&self) -> &[u8; 32] {
        &self.signer
    }
    /// Exact canonical signed envelope digest accepted by the host.
    pub fn manifest_digest(&self) -> ManifestDigest {
        self.manifest_digest
    }
    /// Number of objects claimed accepted at signature time.
    pub fn chunk_count(&self) -> u64 {
        self.chunk_count
    }
    /// Self-declared signed instant; not evidence of future custody.
    pub fn received_at(&self) -> &str {
        &self.received_at
    }
}

fn decode_array<const N: usize>(text: &str, error: VerifyError) -> Result<[u8; N], VerifyError> {
    let decoded = STANDARD.decode(text).map_err(|_| error)?;
    decoded.try_into().map_err(|_| error)
}

fn hash(input: &[u8]) -> [u8; 32] {
    Sha256::digest(input).into()
}

fn hex32(input: &str, error: VerifyError) -> Result<[u8; 32], VerifyError> {
    if input.len() != 64
        || !input
            .as_bytes()
            .iter()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(error);
    }
    let mut bytes = [0u8; 32];
    for (index, pair) in input.as_bytes().chunks_exact(2).enumerate() {
        let nibble = |c: u8| match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => unreachable!(),
        };
        bytes[index] = (nibble(pair[0]) << 4) | nibble(pair[1]);
    }
    Ok(bytes)
}

/// Canonical Python S1 JSON is key-sorted regardless of serde_json feature
/// unification. Holochain can enable serde_json/preserve_order downstream.
fn write_canonical(value: &Value, out: &mut Vec<u8>) -> Result<(), ()> {
    match value {
        Value::Object(map) => {
            let mut entries: Vec<(&String, &Value)> = map.iter().collect();
            entries.sort_unstable_by(|a, b| a.0.cmp(b.0));
            out.push(b'{');
            for (n, (key, item)) in entries.into_iter().enumerate() {
                if n > 0 {
                    out.push(b',');
                }
                serde_json::to_writer(&mut *out, key).map_err(|_| ())?;
                out.push(b':');
                write_canonical(item, out)?;
            }
            out.push(b'}');
        }
        Value::Array(items) => {
            out.push(b'[');
            for (n, item) in items.iter().enumerate() {
                if n > 0 {
                    out.push(b',');
                }
                write_canonical(item, out)?;
            }
            out.push(b']');
        }
        Value::Number(number) if number.is_f64() => return Err(()),
        scalar => serde_json::to_writer(&mut *out, scalar).map_err(|_| ())?,
    }
    Ok(())
}

/// Python Music S1 compact, sorted JSON for strings, integers, arrays and
/// objects. The S1 format does not sign floating-point values.
pub fn canonical_json(value: &Value) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    write_canonical(value, &mut out).ok()?;
    Some(out)
}

fn canonical<T: Serialize>(input: &T, error: VerifyError) -> Result<Vec<u8>, VerifyError> {
    let value: Value = serde_json::to_value(input).map_err(|_| error)?;
    let mut out = Vec::new();
    write_canonical(&value, &mut out).map_err(|_| error)?;
    Ok(out)
}

fn signed_body<T: Serialize>(
    signed: &Envelope<T>,
    trusted_signer: &[u8; 32],
    error: VerifyError,
) -> Result<(), VerifyError> {
    let signer = decode_array::<32>(&signed.signer, error)?;
    if signer != *trusted_signer {
        return Err(VerifyError::WrongSigner);
    }
    let signature = Signature::from_bytes(&decode_array::<64>(&signed.signature, error)?);
    let key = VerifyingKey::from_bytes(trusted_signer).map_err(|_| error)?;
    let data = canonical(&signed.body, error)?;
    if data.len() > MAX_MANIFEST_BYTES {
        return Err(VerifyError::TooLarge);
    }
    key.verify_strict(&data, &signature)
        .map_err(|_| VerifyError::InvalidSignature)
}

/// Authenticate a Python Music S1 signed package, using an independently
/// pinned publisher key. Rejects duplicate/unknown JSON fields and size abuse.
pub fn verify_music_manifest(
    input: &[u8],
    trusted_artist: &[u8; 32],
) -> Result<VerifiedManifest, VerifyError> {
    if input.len() > MAX_ENVELOPE_BYTES {
        return Err(VerifyError::TooLarge);
    }
    let package: Envelope<ManifestBody> =
        serde_json::from_slice(input).map_err(|_| VerifyError::InvalidJson)?;
    signed_body(&package, trusted_artist, VerifyError::InvalidManifest)?;
    let body = &package.body;
    if body.schema != MUSIC_PACKAGE_V1 || body.cipher != "AES-256-GCM" {
        return Err(VerifyError::InvalidManifest);
    }
    let file_id = hex32(&body.file_id, VerifyError::InvalidManifest)?;
    if !(1..=MAX_CHUNK_BYTES).contains(&body.chunk_size)
        || body.total_plain_bytes > MAX_FILE_BYTES
        || body.chunks.len() > MAX_CHUNKS
        || (body.chunks.is_empty() && body.total_plain_bytes != 0)
    {
        return Err(VerifyError::InvalidManifest);
    }
    let mut nonces = HashSet::with_capacity(body.chunks.len());
    let mut total = 0u64;
    let mut chunks = Vec::with_capacity(body.chunks.len());
    for (index, chunk) in body.chunks.iter().enumerate() {
        let nonce = decode_array::<12>(&chunk.nonce, VerifyError::InvalidManifest)?;
        if !nonces.insert(nonce)
            || chunk.index != index as u64
            || !(1..=body.chunk_size).contains(&chunk.plain_bytes)
            || chunk.cipher_bytes != chunk.plain_bytes + 16
            || (index < body.chunks.len() - 1 && chunk.plain_bytes != body.chunk_size)
        {
            return Err(VerifyError::InvalidManifest);
        }
        total += chunk.plain_bytes;
        chunks.push(ChunkMetadata {
            index: chunk.index,
            ciphertext_sha256: hex32(&chunk.sha256, VerifyError::InvalidManifest)?,
            nonce,
            plain_bytes: chunk.plain_bytes,
            cipher_bytes: chunk.cipher_bytes,
        });
    }
    if total != body.total_plain_bytes {
        return Err(VerifyError::InvalidManifest);
    }
    let signed_bytes = canonical(&package, VerifyError::InvalidManifest)?;
    Ok(VerifiedManifest {
        package_id: PackageId::from_bytes(file_id),
        digest: ManifestDigest::from_bytes(hash(&signed_bytes)),
        signer: *trusted_artist,
        total_plain_bytes: total,
        chunk_size: body.chunk_size,
        chunks,
    })
}

/// Checks the ciphertext's signed SHA-256 and length, but NOT its AES-GCM tag.
/// A separately authorised AEAD decrypt is needed to release plaintext.
pub fn verify_music_ciphertext(
    manifest: &VerifiedManifest,
    index: usize,
    ciphertext: &[u8],
) -> Result<(), VerifyError> {
    let chunk = manifest
        .chunks
        .get(index)
        .ok_or(VerifyError::InvalidCiphertext)?;
    if chunk.index != index as u64
        || ciphertext.len() as u64 != chunk.cipher_bytes
        || hash(ciphertext) != chunk.ciphertext_sha256
    {
        return Err(VerifyError::InvalidCiphertext);
    }
    Ok(())
}

/// Verify a signed replica receipt for an exact verified manifest.
/// A receipt is not proof of ongoing storage or guaranteed availability.
pub fn verify_music_receipt(
    input: &[u8],
    manifest: &VerifiedManifest,
    trusted_host: &[u8; 32],
) -> Result<VerifiedReceipt, VerifyError> {
    if input.len() > MAX_ENVELOPE_BYTES {
        return Err(VerifyError::TooLarge);
    }
    let receipt: Envelope<ReceiptBody> =
        serde_json::from_slice(input).map_err(|_| VerifyError::InvalidJson)?;
    signed_body(&receipt, trusted_host, VerifyError::InvalidReceipt)?;
    let body = &receipt.body;
    if body.schema != MUSIC_RECEIPT_V1
        || hex32(&body.file_id, VerifyError::InvalidReceipt)? != *manifest.package_id.as_bytes()
        || hex32(&body.manifest_sha256, VerifyError::InvalidReceipt)? != *manifest.digest.as_bytes()
        || body.chunk_count != manifest.chunks.len() as u64
        || DateTime::parse_from_rfc3339(&body.received_at).is_err()
    {
        return Err(VerifyError::InvalidReceipt);
    }
    Ok(VerifiedReceipt {
        signer: *trusted_host,
        manifest_digest: manifest.digest,
        chunk_count: body.chunk_count,
        received_at: body.received_at.clone(),
    })
}
