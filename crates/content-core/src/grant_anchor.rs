//! Grant anchors (`holochain-storage/grant-anchor/v2`): the public, minimal
//! record by which a content owner anchors one access grant on their own
//! source chain (docs/ACCESS-GRANT-V2.md §3.5, §4).
//!
//! The v2.1 DNA already refuses anchors that do not name the author's
//! current, unrevoked `owner-manifest` transition or that reuse a grant id.
//! This verifier re-derives the key rule from the reader's own verified
//! lifecycle (a modified conductor gains nothing) and checks what the DNA
//! cannot see: that the anchor is the owner's, that it commits to exactly
//! this (private) grant, and the recovered-issuer policy. The grant format
//! itself is out of scope here.

use crate::binding::{
    BindingAssurance, BindingError, ConductorRecord, KeyPurpose, VerifiedKeyBinding,
};
use crate::lifecycle::{strict_hex, ChainAnchor, KeyLifecycle, KeyUse};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// Schema of a grant anchor.
pub const GRANT_ANCHOR_V2: &str = "holochain-storage/grant-anchor/v2";
/// Domain of the commitment: `SHA-256(domain || grant_message)`.
pub const GRANT_ANCHOR_COMMITMENT_DOMAIN_V2: &[u8] =
    b"holochain-storage/grant-anchor-commitment/v2\0";
const FIELDS: [&str; 5] = [
    "schema",
    "dna_hash",
    "grant_id",
    "grant_commitment",
    "issuer_key_action",
];

/// The domain-separated commitment to a grant's exact signed message.
pub fn grant_anchor_commitment(grant_message: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(GRANT_ANCHOR_COMMITMENT_DOMAIN_V2);
    h.update(grant_message);
    h.finalize().into()
}

/// What to do with an issuer generation reached through a recovery without
/// continuity. The default refuses (fail closed).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum RecoveredIssuerPolicy {
    /// Refuse (default).
    #[default]
    Reject,
    /// Accept, labelled by the returned binding's assurance and continuity.
    Accept,
}

/// What a grant claims about its anchor.
#[derive(Clone, Copy, Debug)]
pub struct GrantAnchorClaim<'a> {
    /// The grant's random id (32 lowercase hex).
    pub grant_id: &'a str,
    /// The grant's exact signed message (the anchor commits to it).
    pub grant_message: &'a [u8],
    /// The issuer's lifecycle transition action named by the grant.
    pub issuer_key_action: &'a str,
}

/// A grant anchor verified against the owner's lifecycle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedGrantAnchor {
    issuer: VerifiedKeyBinding,
    anchor_action: String,
    anchor_seq: u32,
    grant_id: String,
}

impl VerifiedGrantAnchor {
    /// The issuer key binding (generation, continuity, assurance and its
    /// validity at the anchor: `Active` or `HistoricalOnly`).
    pub fn issuer(&self) -> &VerifiedKeyBinding {
        &self.issuer
    }
    /// The anchor's action hash.
    pub fn anchor_action(&self) -> &str {
        &self.anchor_action
    }
    /// The anchor's position on the owner's chain.
    pub fn anchor_seq(&self) -> u32 {
        self.anchor_seq
    }
    /// The anchored grant id.
    pub fn grant_id(&self) -> &str {
        &self.grant_id
    }
}

/// Verify `record` (from the reader's trusted conductor, with its chain
/// position) as the anchor of the grant described by `claim`, issued under
/// `owner`'s `owner-manifest` lifecycle.
pub fn verify_grant_anchor_v2(
    record: &ConductorRecord,
    owner: &KeyLifecycle,
    claim: &GrantAnchorClaim<'_>,
    policy: RecoveredIssuerPolicy,
) -> Result<VerifiedGrantAnchor, BindingError> {
    if owner.purpose() != KeyPurpose::OwnerManifest {
        return Err(BindingError::KeyNotBound);
    }
    let seq = record.action_seq().ok_or(BindingError::MissingRecord)?;
    if record.author() != owner.agent() {
        return Err(BindingError::AuthorMismatch);
    }
    let body = record.body();
    if body.len() != FIELDS.len()
        || FIELDS.iter().any(|f| !body.contains_key(*f))
        || !body.values().all(Value::is_string)
        || record.schema() != Some(GRANT_ANCHOR_V2)
    {
        return Err(BindingError::InvalidRecord);
    }
    if record.text("dna_hash")? != owner.dna_hash() {
        return Err(BindingError::WrongDna);
    }
    let commitment =
        strict_hex::<32>(record.text("grant_commitment")?).ok_or(BindingError::InvalidRecord)?;
    if record.text("grant_id")? != claim.grant_id
        || record.text("issuer_key_action")? != claim.issuer_key_action
        || commitment != grant_anchor_commitment(claim.grant_message)
    {
        return Err(BindingError::GrantAnchorMismatch);
    }
    let generation = owner
        .generation_by_action(claim.issuer_key_action)
        .ok_or(BindingError::KeyNotBound)?;
    if seq <= generation.action_seq() {
        return Err(BindingError::GrantAnchorOutOfOrder);
    }
    let anchor = ChainAnchor::from_record(record)?;
    let issuer = owner.authorize(
        generation.key(),
        &KeyUse::Historical {
            anchor: Some(anchor),
        },
    )?;
    if issuer.assurance() == BindingAssurance::KeyLifecycleRecoveredV21
        && policy == RecoveredIssuerPolicy::Reject
    {
        return Err(BindingError::RecoveredIssuerRefused);
    }
    Ok(VerifiedGrantAnchor {
        issuer,
        anchor_action: record.action_hash().to_owned(),
        anchor_seq: seq,
        grant_id: claim.grant_id.to_owned(),
    })
}
