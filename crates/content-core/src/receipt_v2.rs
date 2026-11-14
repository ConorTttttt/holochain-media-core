//! Host-attributed replica receipts: `holochain-storage/replica-receipt/v2`.
//!
//! A v2 receipt is a JSON object of exactly these string fields:
//! `schema, dna_hash, host_agent, host_key_hex, host_key_generation,
//! host_key_action, owner_agent, file_id, manifest_sha256, chunk_count,
//! received_at, context, signature_hex`. The Ed25519 signature covers the
//! length-prefixed message [`replica_receipt_v2_message`] (domain-separated,
//! fixed field order, no JSON canonicalisation), made by the host key of the
//! exact lifecycle generation it names. Its digest (SHA-256 of that message)
//! is what the host's Holochain replica claim commits to.
//!
//! A verified receipt proves a historical acceptance claim by that host agent
//! for that exact signed manifest; it is not proof of continuing storage or
//! current availability. S1 `replica-receipt/v1` is unchanged and remains
//! readable at [`ReceiptAttribution::LegacyUnattributedV1`].

use crate::binding::{
    AuthenticatedReplica, BindingAssurance, BindingError, ConductorRecord, KeyPurpose,
    OwnedManifest, ReceiptAttribution, REPLICA_CLAIM_V1,
};
use crate::compat::{VerifiedReceipt, VerifyError};
use crate::lifecycle::{
    parse_generation, strict_hex, verify_ed25519, ChainAnchor, KeyLifecycle, KeyUse, KeyValidity,
};
use crate::{ManifestDigest, PackageId};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// Schema of a host-attributed receipt.
pub const REPLICA_RECEIPT_V2: &str = "holochain-storage/replica-receipt/v2";
/// Signing domain (NUL-terminated).
pub const REPLICA_RECEIPT_V2_DOMAIN: &[u8] = b"holochain-storage/replica-receipt/v2\0";
/// The only receipt context defined by v2.
pub const RECEIPT_V2_CONTEXT: &str = "replica-acceptance";
/// Size cap for the transported JSON document.
pub const MAX_RECEIPT_V2_BYTES: usize = 4096;
/// Signed fields, in signing order.
pub const RECEIPT_V2_SIGNED_FIELDS: [&str; 12] = [
    "schema",
    "dna_hash",
    "host_agent",
    "host_key_hex",
    "host_key_generation",
    "host_key_action",
    "owner_agent",
    "file_id",
    "manifest_sha256",
    "chunk_count",
    "received_at",
    "context",
];
const MAX_CHUNK_COUNT: u64 = 9_999_999;

/// A verified host-attributed receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedReceiptV2 {
    dna_hash: String,
    host_agent: String,
    owner_agent: String,
    host_key: [u8; 32],
    host_key_generation: u32,
    host_key_action: String,
    host_key_validity: KeyValidity,
    host_assurance: BindingAssurance,
    package_id: PackageId,
    manifest_digest: ManifestDigest,
    chunk_count: u64,
    received_at: String,
    digest: [u8; 32],
}

impl VerifiedReceiptV2 {
    /// The v2.1 DNA the receipt was made for.
    pub fn dna_hash(&self) -> &str {
        &self.dna_hash
    }
    /// The host agent named (and authenticated) by the receipt.
    pub fn host_agent(&self) -> &str {
        &self.host_agent
    }
    /// The content owner named by the receipt.
    pub fn owner_agent(&self) -> &str {
        &self.owner_agent
    }
    /// The host signing key.
    pub fn host_key(&self) -> &[u8; 32] {
        &self.host_key
    }
    /// The host key's lifecycle generation.
    pub fn host_key_generation(&self) -> u32 {
        self.host_key_generation
    }
    /// The transition action that introduced the host key.
    pub fn host_key_action(&self) -> &str {
        &self.host_key_action
    }
    /// Validity of the host key for this receipt (Active or HistoricalOnly).
    pub fn host_key_validity(&self) -> KeyValidity {
        self.host_key_validity
    }
    /// Assurance of the host key binding.
    pub fn host_assurance(&self) -> BindingAssurance {
        self.host_assurance
    }
    /// Accepted package.
    pub fn package_id(&self) -> PackageId {
        self.package_id
    }
    /// Accepted exact signed manifest.
    pub fn manifest_digest(&self) -> ManifestDigest {
        self.manifest_digest
    }
    /// Number of objects accepted.
    pub fn chunk_count(&self) -> u64 {
        self.chunk_count
    }
    /// Host-declared UTC acceptance time (`YYYY-MM-DDTHH:MM:SSZ`); a claim,
    /// not a trusted timestamp.
    pub fn received_at(&self) -> &str {
        &self.received_at
    }
    /// SHA-256 of the signed message (what the replica claim commits to).
    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
}

/// `REPLICA_RECEIPT_V2_DOMAIN || for f in RECEIPT_V2_SIGNED_FIELDS:
/// u32_be(len(f)) || utf8(f)`.
pub fn replica_receipt_v2_message(fields: &[&str; 12]) -> Vec<u8> {
    let mut out = REPLICA_RECEIPT_V2_DOMAIN.to_vec();
    for field in fields {
        out.extend_from_slice(&(field.len() as u32).to_be_bytes());
        out.extend_from_slice(field.as_bytes());
    }
    out
}

fn received_at_ok(text: &str) -> bool {
    // YYYY-MM-DDTHH:MM:SSZ, ASCII digits in the numeric positions.
    let b = text.as_bytes();
    b.len() == 20
        && b.iter().enumerate().all(|(i, c)| match i {
            4 | 7 => *c == b'-',
            10 => *c == b'T',
            13 | 16 => *c == b':',
            19 => *c == b'Z',
            _ => c.is_ascii_digit(),
        })
        && chrono::NaiveDateTime::parse_from_str(&text[..19], "%Y-%m-%dT%H:%M:%S").is_ok()
}

fn chunk_count(text: &str) -> Option<u64> {
    if text.is_empty()
        || text.len() > 7
        || !text.bytes().all(|b| b.is_ascii_digit())
        || text.starts_with('0')
    {
        return None;
    }
    text.parse::<u64>()
        .ok()
        .filter(|n| (1..=MAX_CHUNK_COUNT).contains(n))
}

const INVALID: BindingError = BindingError::Receipt(VerifyError::InvalidReceipt);

/// Verify a v2 receipt for `owned` against the host's verified lifecycle.
///
/// The receipt must name `host.agent()`, the owner of `owned`, the exact
/// manifest, the host lifecycle's DNA and an exact generation of that
/// lifecycle (action, number and key) acceptable for `key_use`.
pub fn verify_replica_receipt_v2(
    receipt_json: &[u8],
    owned: &OwnedManifest,
    host: &KeyLifecycle,
    key_use: &KeyUse,
) -> Result<VerifiedReceiptV2, BindingError> {
    if host.purpose() != KeyPurpose::HostReceipt {
        return Err(BindingError::KeyNotBound);
    }
    if receipt_json.len() > MAX_RECEIPT_V2_BYTES {
        return Err(BindingError::Receipt(VerifyError::TooLarge));
    }
    let value: Value = serde_json::from_slice(receipt_json)
        .map_err(|_| BindingError::Receipt(VerifyError::InvalidJson))?;
    let Value::Object(map) = value else {
        return Err(INVALID);
    };
    if map.len() != RECEIPT_V2_SIGNED_FIELDS.len() + 1
        || !map.values().all(Value::is_string)
        || !map.contains_key("signature_hex")
        || RECEIPT_V2_SIGNED_FIELDS
            .iter()
            .any(|f| !map.contains_key(*f))
    {
        return Err(INVALID);
    }
    let text = |k: &str| map.get(k).and_then(Value::as_str).unwrap_or_default();
    if text("schema") != REPLICA_RECEIPT_V2 || text("context") != RECEIPT_V2_CONTEXT {
        return Err(INVALID);
    }
    if text("dna_hash") != host.dna_hash() {
        return Err(BindingError::WrongDna);
    }
    if text("host_agent") != host.agent() {
        return Err(BindingError::ReceiptHostMismatch);
    }
    let manifest = owned.manifest();
    if text("owner_agent") != owned.owner_agent()
        || text("file_id") != manifest.package_id().to_string()
        || text("manifest_sha256") != manifest.digest().to_string()
        || chunk_count(text("chunk_count")) != Some(manifest.chunks().len() as u64)
        || !received_at_ok(text("received_at"))
    {
        return Err(INVALID);
    }
    let key = strict_hex::<32>(text("host_key_hex")).ok_or(INVALID)?;
    let generation = parse_generation(text("host_key_generation")).ok_or(INVALID)?;
    let signature = strict_hex::<64>(text("signature_hex")).ok_or(INVALID)?;
    if host
        .generation_at(text("host_key_action"), generation, &key)
        .is_none()
    {
        return Err(BindingError::KeyNotBound);
    }
    let binding = host.authorize(&key, key_use)?;
    let fields: [&str; 12] = RECEIPT_V2_SIGNED_FIELDS.map(text);
    let message = replica_receipt_v2_message(&fields);
    if !verify_ed25519(&key, &signature, &message) {
        return Err(BindingError::Receipt(VerifyError::InvalidSignature));
    }
    Ok(VerifiedReceiptV2 {
        dna_hash: text("dna_hash").to_owned(),
        host_agent: text("host_agent").to_owned(),
        owner_agent: text("owner_agent").to_owned(),
        host_key: key,
        host_key_generation: generation,
        host_key_action: text("host_key_action").to_owned(),
        host_key_validity: binding.validity(),
        host_assurance: binding.assurance(),
        package_id: manifest.package_id(),
        manifest_digest: manifest.digest(),
        chunk_count: manifest.chunks().len() as u64,
        received_at: text("received_at").to_owned(),
        digest: Sha256::digest(&message).into(),
    })
}

/// Verify a host's Holochain replica claim and its v2 receipt for one owned
/// manifest. The receipt is a historical acceptance claim: its host key is
/// checked as historical use anchored at the claim's chain position (when
/// the conductor returned it), so a key that ended before the claim was
/// published — or a `compromised` key without an anchor — is refused.
pub fn verify_replica_claim_v2(
    receipt_json: &[u8],
    owned: &OwnedManifest,
    host: &KeyLifecycle,
    node_claim: &ConductorRecord,
) -> Result<AuthenticatedReplica, BindingError> {
    let node_agent = host.agent();
    if node_claim.author() != node_agent {
        return Err(BindingError::AuthorMismatch);
    }
    let anchor = match node_claim.action_seq() {
        Some(_) => Some(ChainAnchor::from_record(node_claim)?),
        None => None,
    };
    let receipt =
        verify_replica_receipt_v2(receipt_json, owned, host, &KeyUse::Historical { anchor })?;
    let body = node_claim.body();
    let fields = [
        "schema",
        "node_agent",
        "owner_agent",
        "file_id",
        "manifest_sha256",
        "receipt_sha256",
    ];
    if body.len() != fields.len()
        || fields.iter().any(|f| !body.contains_key(*f))
        || !body.values().all(Value::is_string)
        || node_claim.schema() != Some(REPLICA_CLAIM_V1)
    {
        return Err(BindingError::InvalidRecord);
    }
    let digest_hex: String = receipt.digest.iter().map(|b| format!("{b:02x}")).collect();
    if node_claim.text("node_agent")? != node_agent
        || node_claim.text("owner_agent")? != owned.owner_agent()
        || node_claim.text("file_id")? != owned.manifest().package_id().to_string()
        || node_claim.text("manifest_sha256")? != owned.manifest().digest().to_string()
        || node_claim.text("receipt_sha256")? != digest_hex
    {
        return Err(BindingError::ClaimMismatch);
    }
    Ok(AuthenticatedReplica {
        node_agent: node_agent.to_owned(),
        node_key: receipt.host_key,
        receipt: VerifiedReceipt {
            signer: receipt.host_key,
            manifest_digest: receipt.manifest_digest,
            chunk_count: receipt.chunk_count,
            received_at: receipt.received_at.clone(),
            envelope_sha256: receipt.digest,
        },
        node_assurance: receipt.host_assurance,
        attribution: ReceiptAttribution::HostAttributedV2,
        receipt_v2: Some(receipt),
    })
}

/// Fail unless `replica` carries a host-attributed v2 receipt.
pub fn require_host_attribution(
    replica: &AuthenticatedReplica,
) -> Result<&AuthenticatedReplica, BindingError> {
    if replica.attribution() == ReceiptAttribution::HostAttributedV2 {
        Ok(replica)
    } else {
        Err(BindingError::InsufficientReceiptAttribution)
    }
}
