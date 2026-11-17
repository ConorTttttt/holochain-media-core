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
use crate::{ManifestDigest, PackageId};
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
            body,
        })
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

    fn schema(&self) -> Option<&str> {
        self.body.get("schema").and_then(Value::as_str)
    }

    fn text(&self, key: &str) -> Result<&str, BindingError> {
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
}

impl OwnedManifest {
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
    let pin = commitment_pin(commitment, owner_agent)?;
    let owner_key = key_for_agent(key_binding, owner_agent, KeyPurpose::OwnerManifest)?;
    let manifest =
        verify_music_manifest(manifest_json, &owner_key).map_err(BindingError::Manifest)?;
    if manifest.package_id() != pin.package_id || manifest.digest() != pin.manifest_digest {
        return Err(BindingError::CommitmentMismatch);
    }
    Ok(OwnedManifest {
        owner_agent: owner_agent.to_owned(),
        manifest,
    })
}

/// A storage host whose signed receipt and Holochain replica claim both
/// verify for one owned manifest. A claim + receipt prove one historical
/// acceptance, **not** current custody or availability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedReplica {
    node_agent: String,
    node_key: [u8; 32],
    receipt: VerifiedReceipt,
}

impl AuthenticatedReplica {
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
    let node_key = key_for_agent(node_key_binding, node_agent, KeyPurpose::HostReceipt)?;
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
    })
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
