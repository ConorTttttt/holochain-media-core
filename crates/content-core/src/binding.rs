//! CORE-004 Task A: Music S2 Holochain identity bindings, checked in Rust.
//!
//! This is a strict port of the checks in Holochain Music's
//! `holochain_storage/holochain_identity.py` and
//! `music_catalogue/moq_conductor.py` (endpoint binding) at
//! bd7aabc3e9ea1fef1e8e8f674301e1b5ffecb637. It does **not** re-implement
//! Holochain signature or DHT validation.
//!
//! The trust boundary is a [`ConductorRecord`]: an entry body returned by a
//! *trusted, validating local conductor* together with the author of the
//! validated Holochain action that created it. The storage DNA's integrity
//! zome (`music_storage_integrity`) already rejects entries whose claimed
//! agent differs from the action author. This module re-checks that and then
//! binds those Holochain-authored claims to the Ed25519 signatures on the
//! S1 manifest and replica receipt, and to the advertised QUIC certificate.
//!
//! Nothing here accepts a key, URL or fingerprint because it appears in a
//! manifest, receipt or network response. Every value flows from a record
//! authored by the expected agent.

use crate::compat::{
    verify_music_manifest, verify_music_receipt, VerifiedManifest, VerifiedReceipt, VerifyError,
};
pub use crate::lifecycle::{KeyContinuity, KeyValidity};
use crate::{ManifestDigest, PackageId};
use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::{Map, Value};
use std::fmt;
use std::net::Ipv4Addr;

/// Music S2 signing-key binding entry schema.
pub const KEY_BINDING_V1: &str = "holochain-storage/key-binding/v1";
/// Music S2 owner file-commitment entry schema.
pub const FILE_COMMITMENT_V1: &str = "holochain-storage/file-commitment/v1";
/// Music S2 storage-host replica-claim entry schema.
pub const REPLICA_CLAIM_V1: &str = "holochain-storage/replica-claim/v1";
/// Music S9 host-authored MoQ endpoint entry schema.
pub const MOQ_ENDPOINT_V1: &str = "holochain-storage/moq-endpoint/v1";
/// S2 key binding with proof of possession (Music `dna-v2/`).
pub const KEY_BINDING_V2: &str = "holochain-storage/key-binding/v2";
/// Domain of the v2 proof-of-possession signature (NUL-terminated).
pub const KEY_BINDING_POP_DOMAIN_V2: &[u8] = b"holochain-storage/key-binding-pop/v2\0";
/// The only key generation defined by key-binding v2.0.
pub const KEY_GENERATION_V2: &str = "1";
const KEY_BINDING_V2_FIELDS: [&str; 7] = [
    "schema",
    "dna_hash",
    "agent",
    "purpose",
    "signing_key_hex",
    "generation",
    "proof_signature_hex",
];
/// Cap on DNA hash text (`uhC0k…` is 53 bytes).
const MAX_DNA_HASH_BYTES: usize = 160;

/// Holochain agent identifiers are carried as their canonical string form
/// (`uhCAk…`). The DNA caps them at 160 bytes; so do we.
const MAX_AGENT_BYTES: usize = 160;
const MAX_ACTION_HASH_BYTES: usize = 160;
/// Music's `_bound_local_url` cap.
const MAX_URL_BYTES: usize = 80;

/// Why an S2 binding check failed. Each variant names the boundary that
/// rejected the input; none of them represents a network or timeout error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BindingError {
    /// A required agent or record was absent/empty.
    MissingRecord,
    /// The validated Holochain action author is not the expected agent.
    AuthorMismatch,
    /// Unknown schema, missing/extra field, non-string value or bad encoding.
    InvalidRecord,
    /// The key binding is for a different agent or purpose.
    KeyNotBound,
    /// More than one record matched where exactly one is required; a key or
    /// claim rotation policy must decide, never "first match wins".
    Ambiguous,
    /// The owner's file commitment does not match the signed manifest.
    CommitmentMismatch,
    /// The host's replica claim does not match the package or its receipt.
    ClaimMismatch,
    /// The host-authored endpoint does not bind exactly this host/file/manifest.
    EndpointMismatch,
    /// The endpoint URL is not an allowed canonical `https://IPv4:port`.
    EndpointNotAllowed,
    /// The S1 manifest failed verification against the bound owner key.
    Manifest(VerifyError),
    /// The S1 receipt failed verification against the bound host key.
    Receipt(VerifyError),
    /// A v2 binding's proof of possession is malformed or does not verify:
    /// the author has not shown control of the bound key for this agent,
    /// purpose and DNA.
    InvalidProof,
    /// A v2 binding was made for a different DNA (network/application scope).
    WrongDna,
    /// The binding's assurance level is below what the operation requires
    /// (for example a legacy v1 binding where proof of possession is needed).
    InsufficientAssurance,
    /// v2.1: a lifecycle record refers to a predecessor/target that was not
    /// returned (a gap). May be DHT propagation; never resolved by guessing.
    LifecycleIncomplete,
    /// v2.1: the key was superseded by a rotation/recovery and is not
    /// acceptable for this use (a new operation, or an artifact anchored
    /// after the key ended).
    KeyRotated,
    /// v2.1: the key was revoked and is not acceptable for this use.
    KeyRevoked,
    /// v2.1: a replica receipt names a different host agent than the one
    /// whose lifecycle and claim authenticate it.
    ReceiptHostMismatch,
    /// v2.1: the operation requires a host-attributed `replica-receipt/v2`
    /// and was given a legacy, unattributed receipt.
    InsufficientReceiptAttribution,
    /// A grant anchor does not match the grant (id, commitment or issuer
    /// transition), names another DNA, or is malformed.
    GrantAnchorMismatch,
    /// The grant anchor precedes the issuer key it names (impossible on an
    /// honest chain; fail closed).
    GrantAnchorOutOfOrder,
    /// The issuer generation was reached through a recovery without
    /// continuity and the verifier's policy refuses such issuers.
    RecoveredIssuerRefused,
}

impl fmt::Display for BindingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingRecord => f.write_str("missing authenticated Holochain record/agent"),
            Self::AuthorMismatch => f.write_str("Holochain action author mismatch"),
            Self::InvalidRecord => f.write_str("invalid Holochain storage record"),
            Self::KeyNotBound => f.write_str("signing key not bound to expected agent/purpose"),
            Self::Ambiguous => f.write_str("ambiguous records: rotation policy required"),
            Self::CommitmentMismatch => {
                f.write_str("owner commitment does not match signed manifest")
            }
            Self::ClaimMismatch => f.write_str("storage node claim does not match receipt/package"),
            Self::EndpointMismatch => {
                f.write_str("MoQ endpoint does not bind the exact host/file/manifest")
            }
            Self::EndpointNotAllowed => f.write_str("MoQ endpoint URL is not allowed"),
            Self::Manifest(e) => write!(f, "signed manifest rejected: {e:?}"),
            Self::Receipt(e) => write!(f, "signed receipt rejected: {e:?}"),
            Self::InvalidProof => f.write_str("key binding proof of possession does not verify"),
            Self::WrongDna => f.write_str("key binding is for a different DNA"),
            Self::InsufficientAssurance => {
                f.write_str("key binding assurance is below the required level")
            }
            Self::LifecycleIncomplete => f.write_str("key lifecycle incomplete (missing record)"),
            Self::KeyRotated => {
                f.write_str("signing key was rotated and is not valid for this use")
            }
            Self::KeyRevoked => {
                f.write_str("signing key was revoked and is not valid for this use")
            }
            Self::ReceiptHostMismatch => f.write_str("replica receipt names a different host"),
            Self::InsufficientReceiptAttribution => {
                f.write_str("a host-attributed replica receipt is required")
            }
            Self::GrantAnchorMismatch => f.write_str("grant anchor does not match this grant"),
            Self::GrantAnchorOutOfOrder => f.write_str("grant anchor precedes its issuer key"),
            Self::RecoveredIssuerRefused => {
                f.write_str("issuer key was recovered without continuity; refused by policy")
            }
        }
    }
}

impl std::error::Error for BindingError {}

/// One entry body plus the author of its validated Holochain action.
///
/// Construct this **only** from a trusted, validating local conductor's
/// response (the action's author, not a body field). A JSON document from a
/// peer, a host, or an HTTP API is not a `ConductorRecord`.
#[derive(Clone, Debug, PartialEq)]
pub struct ConductorRecord {
    author: String,
    action_hash: String,
    action_seq: Option<u32>,
    body: Map<String, Value>,
}

impl ConductorRecord {
    /// Wrap a record read from a validating conductor.
    ///
    /// `author` MUST be the Holochain action author as returned by the
    /// conductor; `body` the deserialised entry. Bodies that are not JSON
    /// objects, and empty or oversized identifiers, are rejected.
    pub fn from_validated_conductor(
        author: impl Into<String>,
        action_hash: impl Into<String>,
        body: Value,
    ) -> Result<Self, BindingError> {
        let author = author.into();
        let action_hash = action_hash.into();
        let Value::Object(body) = body else {
            return Err(BindingError::InvalidRecord);
        };
        if !valid_agent(&author)
            || action_hash.is_empty()
            || action_hash.len() > MAX_ACTION_HASH_BYTES
        {
            return Err(BindingError::MissingRecord);
        }
        Ok(Self {
            author,
            action_hash,
            action_seq: None,
            body,
        })
    }

    /// [`Self::from_validated_conductor`] plus the action's position on its
    /// author's source chain (`action_seq`), as returned by the conductor.
    /// v2.1 lifecycle records and historical anchors need it.
    pub fn from_validated_conductor_at(
        author: impl Into<String>,
        action_hash: impl Into<String>,
        action_seq: u32,
        body: Value,
    ) -> Result<Self, BindingError> {
        let mut record = Self::from_validated_conductor(author, action_hash, body)?;
        record.action_seq = Some(action_seq);
        Ok(record)
    }

    /// Position of the action on its author's chain, when the conductor
    /// returned it.
    pub fn action_seq(&self) -> Option<u32> {
        self.action_seq
    }

    /// The validated Holochain action author.
    pub fn author(&self) -> &str {
        &self.author
    }

    /// The action hash (opaque; for audit trails and diagnostics).
    pub fn action_hash(&self) -> &str {
        &self.action_hash
    }

    /// The entry body as returned by the conductor.
    pub fn body(&self) -> &Map<String, Value> {
        &self.body
    }

    pub(crate) fn schema(&self) -> Option<&str> {
        self.body.get("schema").and_then(Value::as_str)
    }

    pub(crate) fn text(&self, key: &str) -> Result<&str, BindingError> {
        self.body
            .get(key)
            .and_then(Value::as_str)
            .ok_or(BindingError::InvalidRecord)
    }
}

/// Purpose of an S2 signing-key binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyPurpose {
    /// Artist/owner key that signs S1 encrypted-package manifests.
    OwnerManifest,
    /// Storage-host key that signs S1 replica receipts.
    HostReceipt,
}

impl KeyPurpose {
    /// The exact on-DHT purpose string.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OwnerManifest => "owner-manifest",
            Self::HostReceipt => "host-receipt",
        }
    }
}

fn valid_agent(agent: &str) -> bool {
    !agent.is_empty() && agent.len() <= MAX_AGENT_BYTES && !agent.contains('\0')
}

fn hex32(text: &str) -> Result<[u8; 32], BindingError> {
    let id: PackageId = text.parse().map_err(|_| BindingError::InvalidRecord)?;
    Ok(*id.as_bytes())
}

fn lower_hex(bytes: &[u8; 32]) -> String {
    PackageId::from_bytes(*bytes).to_string()
}

/// Mirror of Python `_verified_claim`: author, schema and *exact* field set.
fn verified_claim<'a>(
    record: &'a ConductorRecord,
    expected_author: &str,
    schema: &str,
    fields: &[&str],
) -> Result<&'a ConductorRecord, BindingError> {
    if !valid_agent(expected_author) {
        return Err(BindingError::MissingRecord);
    }
    if record.author != expected_author {
        return Err(BindingError::AuthorMismatch);
    }
    if record.schema() != Some(schema)
        || record.body.len() != fields.len()
        || fields.iter().any(|f| !record.body.contains_key(*f))
        || record.body.values().any(|v| !v.is_string())
    {
        return Err(BindingError::InvalidRecord);
    }
    Ok(record)
}

/// Return the Ed25519 public key that `agent` bound for `purpose`.
///
/// Key registration is author-controlled; rotation/revocation is not modelled
/// by the Music S2 DNA. Choose the single binding with [`select_unique`].
pub fn key_for_agent(
    record: &ConductorRecord,
    agent: &str,
    purpose: KeyPurpose,
) -> Result<[u8; 32], BindingError> {
    let body = verified_claim(
        record,
        agent,
        KEY_BINDING_V1,
        &["schema", "agent", "purpose", "signing_key_hex"],
    )?;
    if body.text("agent")? != agent || body.text("purpose")? != purpose.as_str() {
        return Err(BindingError::KeyNotBound);
    }
    hex32(body.text("signing_key_hex")?)
}

/// Pick the one record satisfying `matches`; zero is `MissingRecord`, more
/// than one is `Ambiguous` (the Music bridge's `choose_unique` policy).
pub fn select_unique(
    records: &[ConductorRecord],
    mut matches: impl FnMut(&ConductorRecord) -> bool,
) -> Result<&ConductorRecord, BindingError> {
    let mut found = records.iter().filter(|r| matches(r));
    let first = found.next().ok_or(BindingError::MissingRecord)?;
    if found.next().is_some() {
        return Err(BindingError::Ambiguous);
    }
    Ok(first)
}

/// True when `record` is a well-formed key binding by `agent` for `purpose`.
/// Used as a [`select_unique`] predicate; the selected record is re-checked.
pub fn is_key_binding(record: &ConductorRecord, agent: &str, purpose: KeyPurpose) -> bool {
    record.author == agent
        && record.schema() == Some(KEY_BINDING_V1)
        && record.body.get("agent").and_then(Value::as_str) == Some(agent)
        && record.body.get("purpose").and_then(Value::as_str) == Some(purpose.as_str())
}

/// An S1 manifest authenticated by the owner's Holochain-bound signing key
/// **and** matching the owner's Holochain file commitment.
///
/// Only [`verify_owned_manifest`] constructs this type.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnedManifest {
    owner_agent: String,
    manifest: VerifiedManifest,
    owner_assurance: BindingAssurance,
    owner_key_generation: u32,
    owner_key_validity: KeyValidity,
}

impl OwnedManifest {
    /// How strongly the owner's signing key is bound to `owner_agent`.
    /// [`verify_owned_manifest`] always yields
    /// [`BindingAssurance::LegacyAuthoredV1`]; only
    /// [`verify_owned_manifest_with_key`] with a verified v2 binding yields
    /// [`BindingAssurance::ProofOfPossessionV2`].
    pub fn owner_assurance(&self) -> BindingAssurance {
        self.owner_assurance
    }
    /// Lifecycle generation of the key that signed the manifest (1 for v1/v2).
    pub fn owner_key_generation(&self) -> u32 {
        self.owner_key_generation
    }
    /// Validity of the signing key for this (historical) manifest:
    /// [`KeyValidity::Active`] or [`KeyValidity::HistoricalOnly`].
    pub fn owner_key_validity(&self) -> KeyValidity {
        self.owner_key_validity
    }
    /// Holochain agent that authored both the key binding and commitment.
    pub fn owner_agent(&self) -> &str {
        &self.owner_agent
    }
    /// The signature-verified manifest.
    pub fn manifest(&self) -> &VerifiedManifest {
        &self.manifest
    }
}

/// The `(file_id, manifest_sha256)` pair from an owner's commitment, read
/// before the manifest is available. It only pins what to fetch; it is not
/// itself proof of anything about the bytes a host later supplies.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommitmentPin {
    /// Committed opaque package identifier.
    pub package_id: PackageId,
    /// Committed SHA-256 of the canonical signed manifest envelope.
    pub manifest_digest: ManifestDigest,
}

/// Read the pins from an owner-authored file commitment.
pub fn commitment_pin(
    commitment: &ConductorRecord,
    owner_agent: &str,
) -> Result<CommitmentPin, BindingError> {
    let body = verified_claim(
        commitment,
        owner_agent,
        FILE_COMMITMENT_V1,
        &["schema", "owner_agent", "file_id", "manifest_sha256"],
    )?;
    if body.text("owner_agent")? != owner_agent {
        return Err(BindingError::CommitmentMismatch);
    }
    Ok(CommitmentPin {
        package_id: PackageId::from_bytes(hex32(body.text("file_id")?)?),
        manifest_digest: ManifestDigest::from_bytes(hex32(body.text("manifest_sha256")?)?),
    })
}

/// Authenticate an untrusted signed-manifest document (for example, bytes
/// received from a MoQ host) against the owner's Holochain key binding and
/// file commitment. Python: `verify_owned_manifest`.
pub fn verify_owned_manifest(
    manifest_json: &[u8],
    owner_agent: &str,
    key_binding: &ConductorRecord,
    commitment: &ConductorRecord,
) -> Result<OwnedManifest, BindingError> {
    let owner_key = verify_key_binding_v1(key_binding, owner_agent, KeyPurpose::OwnerManifest)?;
    verify_owned_manifest_with_key(manifest_json, owner_agent, &owner_key, commitment)
}

/// [`verify_owned_manifest`] with an already verified owner key binding (v1
/// or v2). The resulting [`OwnedManifest`] carries that binding's assurance.
pub fn verify_owned_manifest_with_key(
    manifest_json: &[u8],
    owner_agent: &str,
    owner_key: &VerifiedKeyBinding,
    commitment: &ConductorRecord,
) -> Result<OwnedManifest, BindingError> {
    if owner_key.agent != owner_agent || owner_key.purpose != KeyPurpose::OwnerManifest {
        return Err(BindingError::KeyNotBound);
    }
    let pin = commitment_pin(commitment, owner_agent)?;
    let manifest =
        verify_music_manifest(manifest_json, &owner_key.key).map_err(BindingError::Manifest)?;
    if manifest.package_id() != pin.package_id || manifest.digest() != pin.manifest_digest {
        return Err(BindingError::CommitmentMismatch);
    }
    Ok(OwnedManifest {
        owner_agent: owner_agent.to_owned(),
        manifest,
        owner_assurance: owner_key.assurance,
        owner_key_generation: owner_key.generation,
        owner_key_validity: owner_key.validity,
    })
}

/// v2.1: authenticate an untrusted signed manifest whose signing key is
/// governed by the owner's verified `owner-manifest` lifecycle. The signer
/// named by the envelope must be a generation of that lifecycle acceptable
/// for historical use anchored at the owner's commitment (when the conductor
/// returned its chain position): a manifest committed after its key was
/// rotated or revoked is a new operation with a stale key and is refused.
pub fn verify_owned_manifest_lifecycle(
    manifest_json: &[u8],
    owner: &crate::lifecycle::KeyLifecycle,
    commitment: &ConductorRecord,
) -> Result<OwnedManifest, BindingError> {
    if owner.purpose() != KeyPurpose::OwnerManifest {
        return Err(BindingError::KeyNotBound);
    }
    if commitment.author() != owner.agent() {
        return Err(BindingError::AuthorMismatch);
    }
    let anchor = match commitment.action_seq() {
        Some(_) => Some(crate::lifecycle::ChainAnchor::from_record(commitment)?),
        None => None,
    };
    let signer =
        crate::compat::music_envelope_signer(manifest_json).map_err(BindingError::Manifest)?;
    let key = owner.authorize(&signer, &crate::lifecycle::KeyUse::Historical { anchor })?;
    verify_owned_manifest_with_key(manifest_json, owner.agent(), &key, commitment)
}

/// A storage host whose signed receipt and Holochain replica claim both
/// verify for one owned manifest. A claim + receipt prove one historical
/// acceptance, **not** current custody or availability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedReplica {
    pub(crate) node_agent: String,
    pub(crate) node_key: [u8; 32],
    pub(crate) receipt: VerifiedReceipt,
    pub(crate) node_assurance: BindingAssurance,
    pub(crate) attribution: ReceiptAttribution,
    pub(crate) receipt_v2: Option<crate::receipt_v2::VerifiedReceiptV2>,
}

/// What a verified replica receipt says about *which* host accepted the
/// content. Ordered: v2 is stronger.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ReceiptAttribution {
    /// S1 `replica-receipt/v1`: signed by a key; does not name the host
    /// agent. Attribution comes only from the separate Holochain claim.
    LegacyUnattributedV1,
    /// `replica-receipt/v2`: the signed statement itself names the host
    /// agent, its exact key generation, DNA, owner and manifest.
    HostAttributedV2,
}

impl AuthenticatedReplica {
    /// How strongly the host's receipt key is bound to `node_agent`. Even at
    /// v2, a Music S1 receipt does not name the host agent; see
    /// docs/S2-KEY-BINDING-V2.md (receipt attribution).
    pub fn node_assurance(&self) -> BindingAssurance {
        self.node_assurance
    }
    /// Legacy unattributed (S1) or host-attributed (v2) receipt.
    pub fn attribution(&self) -> ReceiptAttribution {
        self.attribution
    }
    /// The verified v2 receipt, when [`Self::attribution`] is
    /// [`ReceiptAttribution::HostAttributedV2`].
    pub fn receipt_v2(&self) -> Option<&crate::receipt_v2::VerifiedReceiptV2> {
        self.receipt_v2.as_ref()
    }
    /// Holochain agent of the storage host.
    pub fn node_agent(&self) -> &str {
        &self.node_agent
    }
    /// The host's Holochain-bound receipt signing key.
    pub fn node_key(&self) -> &[u8; 32] {
        &self.node_key
    }
    /// The verified receipt.
    pub fn receipt(&self) -> &VerifiedReceipt {
        &self.receipt
    }
}

/// Verify a host-authored replica claim and its signed receipt for one owned
/// manifest. Python: `verify_replica_claim`.
pub fn verify_replica_claim(
    receipt_json: &[u8],
    owned: &OwnedManifest,
    node_agent: &str,
    node_key_binding: &ConductorRecord,
    node_claim: &ConductorRecord,
) -> Result<AuthenticatedReplica, BindingError> {
    let node_key = verify_key_binding_v1(node_key_binding, node_agent, KeyPurpose::HostReceipt)?;
    verify_replica_claim_with_key(receipt_json, owned, node_agent, &node_key, node_claim)
}

/// [`verify_replica_claim`] with an already verified host key binding.
pub fn verify_replica_claim_with_key(
    receipt_json: &[u8],
    owned: &OwnedManifest,
    node_agent: &str,
    node_key: &VerifiedKeyBinding,
    node_claim: &ConductorRecord,
) -> Result<AuthenticatedReplica, BindingError> {
    if node_key.agent != node_agent || node_key.purpose != KeyPurpose::HostReceipt {
        return Err(BindingError::KeyNotBound);
    }
    let node_assurance = node_key.assurance;
    let node_key = node_key.key;
    let receipt = verify_music_receipt(receipt_json, &owned.manifest, &node_key)
        .map_err(BindingError::Receipt)?;
    let claim = verified_claim(
        node_claim,
        node_agent,
        REPLICA_CLAIM_V1,
        &[
            "schema",
            "node_agent",
            "owner_agent",
            "file_id",
            "manifest_sha256",
            "receipt_sha256",
        ],
    )?;
    if claim.text("node_agent")? != node_agent
        || claim.text("owner_agent")? != owned.owner_agent
        || claim.text("file_id")? != owned.manifest.package_id().to_string()
        || claim.text("manifest_sha256")? != owned.manifest.digest().to_string()
        || claim.text("receipt_sha256")? != lower_hex(receipt.envelope_sha256())
    {
        return Err(BindingError::ClaimMismatch);
    }
    Ok(AuthenticatedReplica {
        node_agent: node_agent.to_owned(),
        node_key,
        receipt,
        node_assurance,
        attribution: ReceiptAttribution::LegacyUnattributedV1,
        receipt_v2: None,
    })
}

// ---------------------------------------------------------------------------
// S2 key-binding v2: proof of possession and explicit assurance
// ---------------------------------------------------------------------------

/// How a signing key is bound to a Holochain agent. Ordered: v2 is stronger.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum BindingAssurance {
    /// `key-binding/v1`: the agent *authored* a claim about a public key. It
    /// does not show the agent controls that key (anyone can bind anyone's
    /// public key). Acceptable for historical reads under an explicit policy.
    LegacyAuthoredV1,
    /// `key-binding/v2`: authored by the agent AND carrying a verified
    /// Ed25519 proof of possession for this agent, purpose and DNA.
    ProofOfPossessionV2,
    /// `key-lifecycle/v2.1` reached through a **recovery**: proof of
    /// possession, agent-authorised, DNA-enforced single lineage, but no
    /// continuity signature by the predecessor key.
    KeyLifecycleRecoveredV21,
    /// `key-lifecycle/v2.1` inception or normal rotation (continuity signed
    /// by the predecessor key): proof of possession, agent-authorised,
    /// DNA-enforced single lineage with revocation status.
    KeyLifecycleV21,
}

/// Which bindings a resolution may use. There is deliberately no "try v2,
/// fall back to v1" policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum KeyBindingPolicy {
    /// Read `key-binding/v1` records only (the existing v1 network). Results
    /// are labelled [`BindingAssurance::LegacyAuthoredV1`].
    LegacyV1,
    /// Read `key-binding/v2` records only, verified for this DNA hash (the
    /// reader's own storage cell, from its trusted conductor).
    ProofOfPossessionV2 {
        /// `uhC0k…` hash of the v2 storage DNA the records were read from.
        dna_hash: String,
    },
    /// Read `key-lifecycle/v2.1` / `key-revocation/v2.1` records only (the
    /// v2.1 DNA), resolved by predecessor references and chain positions.
    /// v1 and v2 records are never consulted.
    KeyLifecycleV21 {
        /// `uhC0k…` hash of the v2.1 storage DNA the records were read from.
        dna_hash: String,
    },
}

/// A signing key bound to an agent for one purpose, with its assurance level.
///
/// Only the verifiers in this module construct it; the assurance cannot be
/// raised by a caller.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedKeyBinding {
    pub(crate) agent: String,
    pub(crate) purpose: KeyPurpose,
    pub(crate) key: [u8; 32],
    pub(crate) assurance: BindingAssurance,
    pub(crate) action_hash: String,
    pub(crate) generation: u32,
    pub(crate) continuity: KeyContinuity,
    pub(crate) validity: KeyValidity,
}

impl VerifiedKeyBinding {
    /// The Holochain agent the key is bound to.
    pub fn agent(&self) -> &str {
        &self.agent
    }
    /// The bound purpose.
    pub fn purpose(&self) -> KeyPurpose {
        self.purpose
    }
    /// The Ed25519 public key.
    pub fn key(&self) -> &[u8; 32] {
        &self.key
    }
    /// v1 (authored claim) or v2 (proof of possession).
    pub fn assurance(&self) -> BindingAssurance {
        self.assurance
    }
    /// The binding record's action hash (audit trail).
    pub fn action_hash(&self) -> &str {
        &self.action_hash
    }
    /// Key generation (always 1 for v1/v2 bindings).
    pub fn generation(&self) -> u32 {
        self.generation
    }
    /// How this generation was introduced.
    pub fn continuity(&self) -> KeyContinuity {
        self.continuity
    }
    /// Validity of the key for the use it was resolved for. v1/v2 bindings
    /// have no lifecycle and are reported [`KeyValidity::Active`].
    pub fn validity(&self) -> KeyValidity {
        self.validity
    }
}

/// Fail unless `binding` has proof of possession. Use before any new
/// security-sensitive operation; historical reads may skip it explicitly.
pub fn require_proof_of_possession(
    binding: &VerifiedKeyBinding,
) -> Result<&VerifiedKeyBinding, BindingError> {
    if binding.assurance >= BindingAssurance::ProofOfPossessionV2 {
        Ok(binding)
    } else {
        Err(BindingError::InsufficientAssurance)
    }
}

/// The exact bytes signed by a v2 proof of possession:
/// `KEY_BINDING_POP_DOMAIN_V2 || for f in [schema, dna_hash, agent, purpose,
/// signing_key_hex, generation]: u32_be(len(f)) || f` (UTF-8). Identical to
/// Music's `key_binding_v2_message` and the v2 integrity zome.
pub fn key_binding_v2_message(
    dna_hash: &str,
    agent: &str,
    purpose: &str,
    signing_key_hex: &str,
    generation: &str,
) -> Vec<u8> {
    let mut out = KEY_BINDING_POP_DOMAIN_V2.to_vec();
    for field in [
        KEY_BINDING_V2,
        dna_hash,
        agent,
        purpose,
        signing_key_hex,
        generation,
    ] {
        // Fields are bounded strings (≤ a few hundred bytes); never > u32.
        out.extend_from_slice(&(field.len() as u32).to_be_bytes());
        out.extend_from_slice(field.as_bytes());
    }
    out
}

/// Verify a legacy `key-binding/v1` record (same rules as [`key_for_agent`]).
pub fn verify_key_binding_v1(
    record: &ConductorRecord,
    agent: &str,
    purpose: KeyPurpose,
) -> Result<VerifiedKeyBinding, BindingError> {
    let key = key_for_agent(record, agent, purpose)?;
    Ok(VerifiedKeyBinding {
        agent: agent.to_owned(),
        purpose,
        key,
        assurance: BindingAssurance::LegacyAuthoredV1,
        action_hash: record.action_hash.clone(),
        generation: 1,
        continuity: KeyContinuity::Inception,
        validity: KeyValidity::Active,
    })
}

/// Verify a `key-binding/v2` record: authored by `agent`, exact fields, for
/// `purpose` on `dna_hash`, generation `"1"`, and an Ed25519 (strict) proof
/// of possession by the bound key over [`key_binding_v2_message`].
pub fn verify_key_binding_v2(
    record: &ConductorRecord,
    agent: &str,
    purpose: KeyPurpose,
    dna_hash: &str,
) -> Result<VerifiedKeyBinding, BindingError> {
    if dna_hash.is_empty() || dna_hash.len() > MAX_DNA_HASH_BYTES {
        return Err(BindingError::MissingRecord);
    }
    let body = verified_claim(record, agent, KEY_BINDING_V2, &KEY_BINDING_V2_FIELDS)?;
    if body.text("agent")? != agent || body.text("purpose")? != purpose.as_str() {
        return Err(BindingError::KeyNotBound);
    }
    if body.text("dna_hash")? != dna_hash {
        return Err(BindingError::WrongDna);
    }
    if body.text("generation")? != KEY_GENERATION_V2 {
        return Err(BindingError::InvalidRecord);
    }
    let key_hex = body.text("signing_key_hex")?;
    let key = hex32(key_hex)?;
    let proof = body.text("proof_signature_hex")?;
    if proof.len() != 128 {
        return Err(BindingError::InvalidProof);
    }
    let (hi, lo) = proof.split_at(64);
    let mut signature = [0u8; 64];
    signature[..32].copy_from_slice(&hex32(hi).map_err(|_| BindingError::InvalidProof)?);
    signature[32..].copy_from_slice(&hex32(lo).map_err(|_| BindingError::InvalidProof)?);
    let message = key_binding_v2_message(
        dna_hash,
        agent,
        purpose.as_str(),
        key_hex,
        KEY_GENERATION_V2,
    );
    VerifyingKey::from_bytes(&key)
        .map_err(|_| BindingError::InvalidProof)?
        .verify_strict(&message, &Signature::from_bytes(&signature))
        .map_err(|_| BindingError::InvalidProof)?;
    Ok(VerifiedKeyBinding {
        agent: agent.to_owned(),
        purpose,
        key,
        assurance: BindingAssurance::ProofOfPossessionV2,
        action_hash: record.action_hash.clone(),
        generation: 1,
        continuity: KeyContinuity::Inception,
        validity: KeyValidity::Active,
    })
}

/// Resolve the one signing key `agent` bound for `purpose` under `policy`.
///
/// Only records of the policy's schema are considered. Every such record for
/// this agent and purpose must verify (a bad one is an error, never skipped,
/// and never a reason to try a weaker schema). Several records naming the
/// *same* key resolve to it (the first record is returned for audit); records
/// naming *different* keys are [`BindingError::Ambiguous`] — no first-match,
/// latest-match or timestamp rule is applied. None is
/// [`BindingError::MissingRecord`].
pub fn resolve_signing_key(
    records: &[ConductorRecord],
    agent: &str,
    purpose: KeyPurpose,
    policy: &KeyBindingPolicy,
) -> Result<VerifiedKeyBinding, BindingError> {
    let schema = match policy {
        KeyBindingPolicy::LegacyV1 => KEY_BINDING_V1,
        KeyBindingPolicy::ProofOfPossessionV2 { .. } => KEY_BINDING_V2,
        KeyBindingPolicy::KeyLifecycleV21 { dna_hash } => {
            // The key for NEW operations: the active generation only.
            return crate::lifecycle::resolve_key_lifecycle(records, agent, purpose, dna_hash)?
                .active();
        }
    };
    let mut found: Option<VerifiedKeyBinding> = None;
    for record in records.iter().filter(|r| {
        r.schema() == Some(schema)
            && r.body.get("agent").and_then(Value::as_str) == Some(agent)
            && r.body.get("purpose").and_then(Value::as_str) == Some(purpose.as_str())
    }) {
        let verified = match policy {
            KeyBindingPolicy::LegacyV1 => verify_key_binding_v1(record, agent, purpose)?,
            KeyBindingPolicy::ProofOfPossessionV2 { dna_hash } => {
                verify_key_binding_v2(record, agent, purpose, dna_hash)?
            }
            // Returned before the loop; never reached.
            KeyBindingPolicy::KeyLifecycleV21 { .. } => return Err(BindingError::InvalidRecord),
        };
        match &found {
            None => found = Some(verified),
            Some(first) if first.key == verified.key => {}
            Some(_) => return Err(BindingError::Ambiguous),
        }
    }
    found.ok_or(BindingError::MissingRecord)
}

/// Which endpoint addresses a caller is willing to dial.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum EndpointPolicy {
    /// `127.0.0.1` only (Music's default).
    #[default]
    LoopbackOnly,
    /// Loopback or literal RFC1918 IPv4 (Music S17 explicit LAN opt-in).
    AllowPrivateLan,
}

/// A host-authored, certificate-pinned QUIC endpoint for one package.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PinnedEndpoint {
    node_agent: String,
    url: String,
    ip: Ipv4Addr,
    port: u16,
    cert_fingerprint: [u8; 32],
}

impl PinnedEndpoint {
    /// Holochain agent that authored the endpoint record.
    pub fn node_agent(&self) -> &str {
        &self.node_agent
    }
    /// Canonical `https://a.b.c.d:port` URL.
    pub fn url(&self) -> &str {
        &self.url
    }
    /// Literal IPv4 host.
    pub fn ip(&self) -> Ipv4Addr {
        self.ip
    }
    /// UDP port.
    pub fn port(&self) -> u16 {
        self.port
    }
    /// SHA-256 of the complete DER X.509 certificate the host must present.
    pub fn cert_fingerprint(&self) -> &[u8; 32] {
        &self.cert_fingerprint
    }
}

fn canonical_port(text: &str) -> Option<u16> {
    if text.is_empty()
        || text.len() > 5
        || !text.bytes().all(|b| b.is_ascii_digit())
        || (text.len() > 1 && text.starts_with('0'))
    {
        return None;
    }
    text.parse::<u16>().ok().filter(|p| *p != 0)
}

fn canonical_ipv4(text: &str) -> Option<Ipv4Addr> {
    let ip: Ipv4Addr = text.parse().ok()?;
    // Reject non-canonical spellings such as leading zeros.
    (ip.to_string() == text).then_some(ip)
}

/// Parse an endpoint URL with Music's `_bound_local_url` rules: canonical
/// `https://IPv4:port` only; no DNS, userinfo, path, query or fragment.
pub fn parse_endpoint_url(
    url: &str,
    policy: EndpointPolicy,
) -> Result<(Ipv4Addr, u16), BindingError> {
    if url.len() > MAX_URL_BYTES {
        return Err(BindingError::EndpointNotAllowed);
    }
    let rest = url
        .strip_prefix("https://")
        .ok_or(BindingError::EndpointNotAllowed)?;
    let (host, port) = rest
        .rsplit_once(':')
        .ok_or(BindingError::EndpointNotAllowed)?;
    let ip = canonical_ipv4(host).ok_or(BindingError::EndpointNotAllowed)?;
    let port = canonical_port(port).ok_or(BindingError::EndpointNotAllowed)?;
    let allowed =
        ip == Ipv4Addr::LOCALHOST || (policy == EndpointPolicy::AllowPrivateLan && ip.is_private());
    if !allowed {
        return Err(BindingError::EndpointNotAllowed);
    }
    Ok((ip, port))
}

/// True when `record` is a host-authored endpoint for exactly this host,
/// owner, file and manifest (a [`select_unique`] predicate).
pub fn is_endpoint_for(
    record: &ConductorRecord,
    node_agent: &str,
    owner_agent: &str,
    pin: &CommitmentPin,
) -> bool {
    let text = |k: &str| record.body.get(k).and_then(Value::as_str);
    record.author == node_agent
        && record.schema() == Some(MOQ_ENDPOINT_V1)
        && text("node_agent") == Some(node_agent)
        && text("owner_agent") == Some(owner_agent)
        && text("file_id") == Some(pin.package_id.to_string().as_str())
        && text("manifest_sha256") == Some(pin.manifest_digest.to_string().as_str())
}

/// Authenticate a host-authored MoQ endpoint record for one committed
/// package. Python: the endpoint checks in `receive_moq_from_live_conductor`.
pub fn verify_moq_endpoint(
    record: &ConductorRecord,
    node_agent: &str,
    owner_agent: &str,
    pin: &CommitmentPin,
    policy: EndpointPolicy,
) -> Result<PinnedEndpoint, BindingError> {
    let body = verified_claim(
        record,
        node_agent,
        MOQ_ENDPOINT_V1,
        &[
            "schema",
            "node_agent",
            "owner_agent",
            "file_id",
            "manifest_sha256",
            "url",
            "cert_fingerprint_hex",
        ],
    )?;
    if body.text("node_agent")? != node_agent
        || body.text("owner_agent")? != owner_agent
        || body.text("file_id")? != pin.package_id.to_string()
        || body.text("manifest_sha256")? != pin.manifest_digest.to_string()
    {
        return Err(BindingError::EndpointMismatch);
    }
    let url = body.text("url")?;
    let (ip, port) = parse_endpoint_url(url, policy)?;
    Ok(PinnedEndpoint {
        node_agent: node_agent.to_owned(),
        url: url.to_owned(),
        ip,
        port,
        cert_fingerprint: hex32(body.text("cert_fingerprint_hex")?)?,
    })
}
