//! Governed-release contract (CORE-004 groundwork for Holochain Video).
//!
//! Video's lifecycle is: creator upload → local quarantine → integrity and
//! processing checks → agent-authored metadata proposal → independent rights
//! review → **authorised publication decision** → media manifest and storage
//! registration → approved distribution.
//!
//! This crate defines only the last two boundaries and makes the ordering a
//! type rule: [`register_release`] needs a [`ReleaseAuthorization`], and the
//! only way to obtain one is from a [`PublicationAuthority`]. Video's existing
//! evidence types — server-generated ingest receipts, catalogue proposals and
//! reviewer findings — are classified by [`GovernanceEvidence`] and **can never
//! be converted into an authorisation** ([`GovernanceEvidence::authorize`]
//! always denies).
//!
//! No production `PublicationAuthority` exists: Video's reviewed publishing
//! workflow (Video #23) and authorised delivery (Video #24) are not
//! implemented, and runtime capability revocation is an open blocker (Video
//! PR #33). [`SyntheticTestAuthority`] exists only for tests, or behind the
//! `synthetic-release-fixture` feature, and only ever approves fixtures that
//! are explicitly marked synthetic.
//!
//! Registration stores ciphertext in a `VerifiedCas` and returns the Music S2
//! records the publisher would author. It never writes to Holochain, opens a
//! network listener, receives a content key, or exposes plaintext.

#![forbid(unsafe_code)]

use holochain_content_core::binding::{OwnedManifest, FILE_COMMITMENT_V1};
use holochain_content_core::storage::{StoreError, VerifiedCas};
use serde_json::{json, Value};
use std::fmt;

/// Video's server-generated quarantine receipt schema.
pub const VIDEO_INGEST_RECEIPT_V1: &str = "holochain-video.ingest-receipt.v1";
/// Video's agent-authored catalogue proposal schema.
pub const VIDEO_CATALOGUE_PROPOSAL_V1: &str = "holochain-video.catalogue-proposal.v1";
/// Marker every synthetic fixture must carry in its decision reference.
pub const SYNTHETIC_DECISION_PREFIX: &str = "synthetic-test-decision:";

/// Why a release was not authorised or registered.
#[derive(Debug, Eq, PartialEq)]
pub enum ReleaseDenied {
    /// The evidence presented is not a publication decision.
    NotAnAuthorization(&'static str),
    /// No authority approved this request.
    NotApproved(String),
    /// The authorisation is for a different publisher agent.
    PublisherMismatch,
    /// The authorisation is for different source/rendition bytes.
    SourceMismatch,
    /// The ciphertext could not be stored as the signed manifest requires.
    Storage(String),
}

impl fmt::Display for ReleaseDenied {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAnAuthorization(kind) => {
                write!(f, "{kind} is not a publication decision")
            }
            Self::NotApproved(reason) => write!(f, "release not approved: {reason}"),
            Self::PublisherMismatch => f.write_str("authorisation is for another publisher"),
            Self::SourceMismatch => f.write_str("authorisation is for other source bytes"),
            Self::Storage(e) => write!(f, "ciphertext registration failed: {e}"),
        }
    }
}

impl std::error::Error for ReleaseDenied {}

/// Evidence Video already produces. Each proves something real, and none of
/// it is permission to publish or distribute.
#[derive(Clone, Debug)]
pub enum GovernanceEvidence {
    /// `holochain-video.ingest-receipt.v1`: a local, unsigned server record
    /// that some bytes with this SHA-256 were received and quarantined.
    /// (Contrast: a Music replica receipt is an Ed25519-signed host claim of
    /// having accepted and verified ciphertext for a signed manifest.)
    IngestReceipt(Value),
    /// `holochain-video.catalogue-proposal.v1`: agent-authored metadata,
    /// awaiting review.
    CatalogueProposal(Value),
    /// An independent reviewer's finding (may conflict with others).
    ReviewerFinding(Value),
}

impl GovernanceEvidence {
    /// Always denies: no evidence type is a release decision.
    pub fn authorize(&self) -> Result<ReleaseAuthorization, ReleaseDenied> {
        Err(ReleaseDenied::NotAnAuthorization(match self {
            Self::IngestReceipt(_) => "an ingest/quarantine receipt",
            Self::CatalogueProposal(_) => "a catalogue proposal",
            Self::ReviewerFinding(_) => "a reviewer finding",
        }))
    }
}

/// What a publisher asks to release.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseRequest {
    /// Holochain agent that will own the release (S2 owner agent).
    pub publisher_agent: String,
    /// SHA-256 of the exact reviewed source/rendition bytes being packaged.
    pub source_sha256: [u8; 32],
    /// Opaque reference to the decision (e.g. an action hash).
    pub decision_ref: String,
}

/// Proof that an authority approved one request. Fields are private and
/// there is no public constructor: only [`PublicationAuthority`]
/// implementations in this crate can mint one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseAuthorization {
    request: ReleaseRequest,
    authority: &'static str,
}

impl ReleaseAuthorization {
    /// The approved request.
    pub fn request(&self) -> &ReleaseRequest {
        &self.request
    }
    /// Which authority approved it (e.g. `"synthetic-test"`).
    pub fn authority(&self) -> &'static str {
        self.authority
    }
}

/// Decides publication. A production implementation must verify a reviewed,
/// non-revoked, independently authorised decision from Holochain; none exists.
pub trait PublicationAuthority {
    /// Approve or deny a specific request.
    fn authorize(&self, request: &ReleaseRequest) -> Result<ReleaseAuthorization, ReleaseDenied>;
}

/// Test-only authority: approves only requests whose decision reference is
/// explicitly marked synthetic. Never wire this into an application.
#[cfg(any(test, feature = "synthetic-release-fixture"))]
#[derive(Clone, Copy, Debug, Default)]
pub struct SyntheticTestAuthority;

#[cfg(any(test, feature = "synthetic-release-fixture"))]
impl PublicationAuthority for SyntheticTestAuthority {
    fn authorize(&self, request: &ReleaseRequest) -> Result<ReleaseAuthorization, ReleaseDenied> {
        if !request.decision_ref.starts_with(SYNTHETIC_DECISION_PREFIX) {
            return Err(ReleaseDenied::NotApproved(
                "synthetic authority only approves synthetic fixtures".into(),
            ));
        }
        Ok(ReleaseAuthorization {
            request: request.clone(),
            authority: "synthetic-test",
        })
    }
}

/// Result of registering an authorised encrypted release.
#[derive(Clone, Debug, PartialEq)]
pub struct RegisteredRelease {
    /// Objects newly stored or already verified in the CAS.
    pub verified_objects: usize,
    /// Music S2 file commitment body the publisher would author (unsent).
    pub file_commitment: Value,
    /// Release record binding the reviewed source hash to the package.
    /// Publisher-authored; viewers holding a grant can check the plaintext
    /// SHA-256 after decryption. Not signed or published here.
    pub release_record: Value,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Register an authorised encrypted release: verify the authorisation
/// matches this owner and source, then store every ciphertext object in
/// `cas` (each verified against the signed manifest).
///
/// `objects[i]` is the ciphertext for manifest chunk `i`. `source_sha256` is
/// the publisher's SHA-256 of the plaintext it packaged; the publisher holds
/// the content key, so only the publisher can attest that link.
pub fn register_release(
    authorization: &ReleaseAuthorization,
    owned: &OwnedManifest,
    source_sha256: [u8; 32],
    objects: &[Vec<u8>],
    cas: &VerifiedCas,
) -> Result<RegisteredRelease, ReleaseDenied> {
    let request = authorization.request();
    if request.publisher_agent != owned.owner_agent() {
        return Err(ReleaseDenied::PublisherMismatch);
    }
    if request.source_sha256 != source_sha256 {
        return Err(ReleaseDenied::SourceMismatch);
    }
    let manifest = owned.manifest();
    if objects.len() != manifest.chunks().len() {
        return Err(ReleaseDenied::Storage(
            "object count differs from the signed manifest".into(),
        ));
    }
    for (index, bytes) in objects.iter().enumerate() {
        cas.put_chunk(manifest, index, bytes)
            .map_err(|e: StoreError| ReleaseDenied::Storage(format!("object {index}: {e}")))?;
    }
    let audit = cas
        .audit(manifest)
        .map_err(|e| ReleaseDenied::Storage(e.to_string()))?;
    let file_id = manifest.package_id().to_string();
    let digest = manifest.digest().to_string();
    Ok(RegisteredRelease {
        verified_objects: audit.verified,
        file_commitment: json!({
            "schema": FILE_COMMITMENT_V1,
            "owner_agent": owned.owner_agent(),
            "file_id": file_id,
            "manifest_sha256": digest,
        }),
        release_record: json!({
            "schema": "holochain-media-core/release-record/v0-draft",
            "publisher_agent": owned.owner_agent(),
            "source_sha256": hex(&source_sha256),
            "file_id": file_id,
            "manifest_sha256": digest,
            "decision_ref": request.decision_ref,
            "authority": authorization.authority(),
        }),
    })
}

#[cfg(test)]
mod tests;
