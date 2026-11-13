//! `resolve_content` and `authenticate_content`: from a Holochain agent and
//! package identifier to an owner-authenticated manifest and a set of
//! authenticated, certificate-pinned storage hosts.
//!
//! Resolution only reads records from a [`MetadataSource`] backed by a
//! trusted, validating local conductor. Host authentication then fetches the
//! signed manifest and each host's signed receipt over the pinned transport
//! and checks them against those records. A host that fails any check is
//! excluded and reported with the boundary that excluded it.

use crate::transport::{DocumentKind, HostConnector, ObjectTransport, TransportFailure};
use holochain_content_core::binding::{
    commitment_pin, is_endpoint_for, is_key_binding, select_unique, verify_moq_endpoint,
    verify_owned_manifest, verify_replica_claim, AuthenticatedReplica, BindingError, CommitmentPin,
    ConductorRecord, EndpointPolicy, KeyPurpose, OwnedManifest, PinnedEndpoint, FILE_COMMITMENT_V1,
    REPLICA_CLAIM_V1,
};
use holochain_content_core::PackageId;
use serde_json::Value;
use std::fmt;
use std::future::Future;

/// The conductor could not answer. This is an availability failure and must
/// never be reported as a denial.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MetadataError(pub String);

impl fmt::Display for MetadataError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Holochain metadata unavailable: {}", self.0)
    }
}

impl std::error::Error for MetadataError {}

/// Read-only access to Music S2 storage-DNA records through a trusted local
/// conductor. Every returned [`ConductorRecord`] must carry the validated
/// action author, not a body field.
pub trait MetadataSource {
    /// `get_signing_keys(agent)`.
    fn signing_keys(
        &mut self,
        agent: &str,
    ) -> impl Future<Output = Result<Vec<ConductorRecord>, MetadataError>> + Send;
    /// `get_file_commitments(agent)`.
    fn file_commitments(
        &mut self,
        agent: &str,
    ) -> impl Future<Output = Result<Vec<ConductorRecord>, MetadataError>> + Send;
    /// `get_replica_claims({owner_agent, file_id})`.
    fn replica_claims(
        &mut self,
        owner_agent: &str,
        package: PackageId,
    ) -> impl Future<Output = Result<Vec<ConductorRecord>, MetadataError>> + Send;
    /// `get_moq_endpoints(host)`.
    fn moq_endpoints(
        &mut self,
        host: &str,
    ) -> impl Future<Output = Result<Vec<ConductorRecord>, MetadataError>> + Send;
}

/// Why a host was excluded.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RejectReason {
    /// A Holochain binding, signature, receipt or endpoint check failed.
    Binding(BindingError),
    /// The host could not be reached or answered incorrectly at transport
    /// level. Availability only; not an authorisation outcome.
    Transport(TransportFailure),
    /// Conductor lookup for this host failed (availability).
    Metadata(MetadataError),
}

/// A host excluded from retrieval, and the boundary that excluded it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostRejection {
    /// Holochain agent of the host.
    pub node_agent: String,
    /// Why it was excluded.
    pub reason: RejectReason,
}

/// Per-host pins from Holochain, before any network contact.
#[derive(Clone, Debug, PartialEq)]
pub struct HostPins {
    /// Host Holochain agent (author of the claim, key and endpoint records).
    pub node_agent: String,
    /// The host's `host-receipt` key binding record.
    pub key_binding: ConductorRecord,
    /// The host's replica claim for this package.
    pub claim: ConductorRecord,
    /// The host-authored certificate-pinned endpoint.
    pub endpoint: PinnedEndpoint,
}

/// Owner and host pins for one package, from Holochain only.
#[derive(Clone, Debug, PartialEq)]
pub struct ResolvedContent {
    /// The owner (publisher) Holochain agent.
    pub owner_agent: String,
    /// Package identity and manifest digest committed by the owner.
    pub pin: CommitmentPin,
    /// The owner's `owner-manifest` key binding record.
    pub owner_key_binding: ConductorRecord,
    /// The owner's file commitment record.
    pub commitment: ConductorRecord,
    /// Hosts whose Holochain records are complete and consistent.
    pub hosts: Vec<HostPins>,
    /// Hosts excluded during resolution.
    pub rejected: Vec<HostRejection>,
}

/// Resolution failed for the owner/package as a whole.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResolveError {
    /// The conductor could not answer (availability, not denial).
    Metadata(MetadataError),
    /// The owner's own records are missing, ambiguous or inconsistent.
    Binding(BindingError),
    /// No host survived resolution/authentication.
    NoAuthenticatedHost(Vec<HostRejection>),
}

impl fmt::Display for ResolveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Metadata(e) => write!(f, "{e}"),
            Self::Binding(e) => write!(f, "owner binding rejected: {e}"),
            Self::NoAuthenticatedHost(r) => {
                write!(f, "no authenticated host ({} rejected)", r.len())
            }
        }
    }
}

impl std::error::Error for ResolveError {}

fn is_commitment_for(record: &ConductorRecord, owner: &str, package: PackageId) -> bool {
    let text = |k: &str| record.body().get(k).and_then(Value::as_str);
    record.author() == owner
        && text("schema") == Some(FILE_COMMITMENT_V1)
        && text("owner_agent") == Some(owner)
        && text("file_id") == Some(package.to_string().as_str())
}

fn claim_node(record: &ConductorRecord) -> Option<&str> {
    let text = |k: &str| record.body().get(k).and_then(Value::as_str);
    (text("schema") == Some(REPLICA_CLAIM_V1) && text("node_agent") == Some(record.author()))
        .then(|| record.author())
}

async fn host_pins<M: MetadataSource>(
    meta: &mut M,
    node: &str,
    claims: &[ConductorRecord],
    owner_agent: &str,
    pin: &CommitmentPin,
    policy: EndpointPolicy,
) -> Result<HostPins, RejectReason> {
    let claim = select_unique(claims, |r| claim_node(r) == Some(node))
        .map_err(RejectReason::Binding)?
        .clone();
    let keys = meta
        .signing_keys(node)
        .await
        .map_err(RejectReason::Metadata)?;
    let key_binding = select_unique(&keys, |r| is_key_binding(r, node, KeyPurpose::HostReceipt))
        .map_err(RejectReason::Binding)?
        .clone();
    let endpoints = meta
        .moq_endpoints(node)
        .await
        .map_err(RejectReason::Metadata)?;
    let record = select_unique(&endpoints, |r| is_endpoint_for(r, node, owner_agent, pin))
        .map_err(RejectReason::Binding)?;
    let endpoint = verify_moq_endpoint(record, node, owner_agent, pin, policy)
        .map_err(RejectReason::Binding)?;
    Ok(HostPins {
        node_agent: node.to_owned(),
        key_binding,
        claim,
        endpoint,
    })
}

/// Read the owner's commitment and key binding and every host's claim, key
/// binding and endpoint for `package` from the conductor.
///
/// `owner_agent` is supplied by the caller from an independent source (an
/// invite, a catalogue entry authored by that agent); it is never learned
/// from the network.
pub async fn resolve_content<M: MetadataSource>(
    meta: &mut M,
    owner_agent: &str,
    package: PackageId,
    policy: EndpointPolicy,
) -> Result<ResolvedContent, ResolveError> {
    let commitments = meta
        .file_commitments(owner_agent)
        .await
        .map_err(ResolveError::Metadata)?;
    let commitment = select_unique(&commitments, |r| is_commitment_for(r, owner_agent, package))
        .map_err(ResolveError::Binding)?
        .clone();
    let pin = commitment_pin(&commitment, owner_agent).map_err(ResolveError::Binding)?;
    let owner_keys = meta
        .signing_keys(owner_agent)
        .await
        .map_err(ResolveError::Metadata)?;
    let owner_key_binding = select_unique(&owner_keys, |r| {
        is_key_binding(r, owner_agent, KeyPurpose::OwnerManifest)
    })
    .map_err(ResolveError::Binding)?
    .clone();

    let claims = meta
        .replica_claims(owner_agent, package)
        .await
        .map_err(ResolveError::Metadata)?;
    let mut nodes: Vec<&str> = Vec::new();
    for record in &claims {
        if let Some(node) = claim_node(record) {
            if !nodes.contains(&node) {
                nodes.push(node);
            }
        }
    }
    let mut hosts = Vec::new();
    let mut rejected = Vec::new();
    for node in nodes {
        match host_pins(meta, node, &claims, owner_agent, &pin, policy).await {
            Ok(pins) => hosts.push(pins),
            Err(reason) => rejected.push(HostRejection {
                node_agent: node.to_owned(),
                reason,
            }),
        }
    }
    if hosts.is_empty() {
        return Err(ResolveError::NoAuthenticatedHost(rejected));
    }
    Ok(ResolvedContent {
        owner_agent: owner_agent.to_owned(),
        pin,
        owner_key_binding,
        commitment,
        hosts,
        rejected,
    })
}

/// A host whose endpoint, receipt and claim all verified for the manifest.
pub struct AuthenticatedHost<T> {
    /// Verified replica claim + receipt.
    pub replica: AuthenticatedReplica,
    /// Holochain-authored, certificate-pinned endpoint.
    pub endpoint: PinnedEndpoint,
    /// Transport pinned to `endpoint`.
    pub transport: T,
}

/// Owner-authenticated manifest plus the hosts that proved their receipts.
pub struct AuthenticatedContent<T> {
    /// Manifest bound to the owner's key binding and commitment.
    pub owned: OwnedManifest,
    /// Hosts usable for retrieval, in resolution order.
    pub hosts: Vec<AuthenticatedHost<T>>,
    /// Every host excluded so far (resolution and authentication).
    pub rejected: Vec<HostRejection>,
}

impl<T> AuthenticatedContent<T> {
    /// Hosts as retrieval sources for [`crate::fetch_verified_content`].
    pub fn into_sources(self) -> (OwnedManifest, Vec<crate::fetch::HostSource<T>>) {
        let sources = self
            .hosts
            .into_iter()
            .map(|h| crate::fetch::HostSource {
                node_agent: h.replica.node_agent().to_owned(),
                transport: h.transport,
            })
            .collect();
        (self.owned, sources)
    }
}

/// Fetch the signed manifest from the first host that serves the committed
/// one, then each host's signed receipt, and verify all of them against the
/// Holochain records in `resolved`.
pub async fn authenticate_content<C: HostConnector>(
    resolved: ResolvedContent,
    connector: &C,
) -> Result<AuthenticatedContent<C::Transport>, ResolveError> {
    let ResolvedContent {
        owner_agent,
        pin,
        owner_key_binding,
        commitment,
        hosts,
        mut rejected,
    } = resolved;
    let mut candidates: Vec<(HostPins, C::Transport)> = hosts
        .into_iter()
        .map(|h| {
            let transport = connector.connect(&h.endpoint);
            (h, transport)
        })
        .collect();

    // 1. The manifest: any host may serve it; only the committed bytes signed
    //    by the bound owner key are accepted.
    let mut owned: Option<OwnedManifest> = None;
    let mut manifest_failures: Vec<(usize, RejectReason)> = Vec::new();
    for (position, (_, transport)) in candidates.iter_mut().enumerate() {
        match transport
            .fetch_document(pin.package_id, DocumentKind::Manifest)
            .await
        {
            Ok(bytes) => {
                match verify_owned_manifest(&bytes, &owner_agent, &owner_key_binding, &commitment) {
                    Ok(manifest) => {
                        owned = Some(manifest);
                        break;
                    }
                    Err(e) => manifest_failures.push((position, RejectReason::Binding(e))),
                }
            }
            Err(e) => manifest_failures.push((position, RejectReason::Transport(e))),
        }
    }
    let Some(owned) = owned else {
        for (position, reason) in manifest_failures {
            rejected.push(HostRejection {
                node_agent: candidates[position].0.node_agent.clone(),
                reason,
            });
        }
        return Err(ResolveError::NoAuthenticatedHost(rejected));
    };
    // A host that served a *wrong* manifest is misbehaving even if another
    // host served the right one; exclude it. Transport failures are retried
    // below when its receipt is requested.
    let bad_manifest: Vec<usize> = manifest_failures
        .iter()
        .filter(|(_, r)| matches!(r, RejectReason::Binding(_)))
        .map(|(p, _)| *p)
        .collect();

    // 2. Each host's receipt must match its own Holochain claim and key.
    let mut authenticated = Vec::new();
    for (position, (pins, mut transport)) in candidates.drain(..).enumerate() {
        if bad_manifest.contains(&position) {
            let reason = manifest_failures
                .iter()
                .find(|(p, _)| *p == position)
                .map(|(_, r)| r.clone())
                .expect("recorded failure");
            rejected.push(HostRejection {
                node_agent: pins.node_agent,
                reason,
            });
            continue;
        }
        let receipt = match transport
            .fetch_document(pin.package_id, DocumentKind::Receipt)
            .await
        {
            Ok(bytes) => bytes,
            Err(e) => {
                rejected.push(HostRejection {
                    node_agent: pins.node_agent,
                    reason: RejectReason::Transport(e),
                });
                continue;
            }
        };
        match verify_replica_claim(
            &receipt,
            &owned,
            &pins.node_agent,
            &pins.key_binding,
            &pins.claim,
        ) {
            Ok(replica) => authenticated.push(AuthenticatedHost {
                replica,
                endpoint: pins.endpoint,
                transport,
            }),
            Err(e) => rejected.push(HostRejection {
                node_agent: pins.node_agent,
                reason: RejectReason::Binding(e),
            }),
        }
    }
    if authenticated.is_empty() {
        return Err(ResolveError::NoAuthenticatedHost(rejected));
    }
    Ok(AuthenticatedContent {
        owned,
        hosts: authenticated,
        rejected,
    })
}
