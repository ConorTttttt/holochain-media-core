//! `fetch_verified_content`: resumable, multi-host ciphertext retrieval.
//!
//! The local `VerifiedCas` is the source of truth for progress. Each call
//! audits it first, so an interrupted or restarted transfer resumes from the
//! verified objects already on disk; corrupt local objects are re-fetched and
//! atomically repaired. Hosts are tried in the caller's order; an object a
//! host sends that fails the signed length/SHA-256 is rejected, that host is
//! abandoned for this call, and the next host is asked for what remains.

use crate::transport::{Delivery, ObjectTransport, TransportFailure};
use holochain_content_core::compat::VerifiedManifest;
use holochain_content_core::storage::{AuditReport, StoreError, VerifiedCas, WriteOutcome};
use std::fmt;

/// Music v1 host limit on objects per request (`MAX_OBJECTS_PER_REQUEST`).
pub const DEFAULT_MAX_OBJECTS_PER_REQUEST: usize = 64;

/// Retrieval tuning. Defaults match the Music v1 host.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FetchOptions {
    /// Objects requested per transport call (1..=64 for Music v1 hosts).
    pub max_objects_per_request: usize,
}

impl Default for FetchOptions {
    fn default() -> Self {
        Self {
            max_objects_per_request: DEFAULT_MAX_OBJECTS_PER_REQUEST,
        }
    }
}

/// Outcome for one host during one call.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct HostReport {
    /// Holochain agent of the host.
    pub node_agent: String,
    /// Verified objects this host supplied and the CAS persisted.
    pub delivered: usize,
    /// Index of an object this host sent that failed verification, if any.
    pub rejected_object: Option<usize>,
    /// Why the host stopped being used, if it did not finish its share.
    pub failure: Option<TransportFailure>,
}

/// Verified progress of one call.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FetchReport {
    /// Objects in the signed manifest.
    pub total: usize,
    /// Local state before any network request.
    pub initial: AuditReport,
    /// Objects that were already verified locally and not requested.
    pub already_verified: usize,
    /// Missing objects stored from a host.
    pub downloaded: usize,
    /// Corrupt local objects replaced with verified host bytes.
    pub repaired: usize,
    /// Per-host outcomes, in the order hosts were tried.
    pub hosts: Vec<HostReport>,
}

/// Retrieval did not produce a complete verified replica.
#[derive(Debug)]
pub enum FetchError {
    /// Some objects could not be obtained from any authenticated host. All
    /// verified progress is retained in the CAS for the next attempt.
    Incomplete {
        /// What was achieved.
        report: FetchReport,
        /// Indices still missing or corrupt locally.
        missing: Vec<usize>,
    },
    /// A local storage failure (unsafe path, I/O). Not a network outcome.
    Store {
        /// What was achieved before the failure.
        report: FetchReport,
        /// Object index being processed.
        index: usize,
        /// Underlying storage error.
        error: StoreError,
    },
}

impl FetchError {
    /// Report of verified progress, whichever way the call failed.
    pub fn report(&self) -> &FetchReport {
        match self {
            Self::Incomplete { report, .. } | Self::Store { report, .. } => report,
        }
    }
}

impl fmt::Display for FetchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Incomplete { missing, .. } => write!(
                f,
                "{} objects unavailable from every authenticated host",
                missing.len()
            ),
            Self::Store { index, error, .. } => {
                write!(f, "local store failure at object {index}: {error}")
            }
        }
    }
}

impl std::error::Error for FetchError {}

/// A host to try, identified by its Holochain agent.
pub struct HostSource<T> {
    /// Holochain agent of the authenticated host (for reports).
    pub node_agent: String,
    /// Transport pinned to that host's authenticated endpoint.
    pub transport: T,
}

enum Local {
    Missing,
    Corrupt,
}

/// Local audit plus the indices that need a network fetch.
type Audited = (AuditReport, Vec<(usize, Local)>);

fn audit_indices(
    cas: &VerifiedCas,
    manifest: &VerifiedManifest,
) -> Result<Audited, (usize, StoreError)> {
    let mut report = AuditReport::default();
    let mut needed = Vec::new();
    for index in 0..manifest.chunks().len() {
        match cas.read_chunk(manifest, index) {
            Ok(_) => report.verified += 1,
            Err(StoreError::Missing) => {
                report.missing += 1;
                needed.push((index, Local::Missing));
            }
            Err(StoreError::Corrupt) => {
                report.corrupt += 1;
                needed.push((index, Local::Corrupt));
            }
            Err(error) => return Err((index, error)),
        }
    }
    Ok((report, needed))
}

/// Retrieve every object of `manifest` that is not already verified in
/// `cas`, from `hosts` in order, verifying each before it is stored.
///
/// `manifest` must come from an authenticated path (for example
/// [`crate::authenticate_content`]); this function trusts only its signed
/// lengths and hashes, never a host's claim about an object.
pub async fn fetch_verified_content<T: ObjectTransport>(
    manifest: &VerifiedManifest,
    hosts: &mut [HostSource<T>],
    cas: &VerifiedCas,
    options: FetchOptions,
) -> Result<FetchReport, FetchError> {
    let batch = options.max_objects_per_request.clamp(1, 1024);
    let mut report = FetchReport {
        total: manifest.chunks().len(),
        ..FetchReport::default()
    };
    let (initial, needed) =
        audit_indices(cas, manifest).map_err(|(index, error)| FetchError::Store {
            report: report.clone(),
            index,
            error,
        })?;
    report.initial = initial;
    report.already_verified = initial.verified;
    let mut remaining: Vec<usize> = needed.iter().map(|(i, _)| *i).collect();

    for host in hosts.iter_mut() {
        if remaining.is_empty() {
            break;
        }
        let mut host_report = HostReport {
            node_agent: host.node_agent.clone(),
            ..HostReport::default()
        };
        let mut done: Vec<usize> = Vec::new();
        let mut local_error: Option<(usize, StoreError)> = None;
        'batches: for request in remaining.chunks(batch) {
            let mut rejected: Option<usize> = None;
            let mut downloaded = 0usize;
            let mut repaired = 0usize;
            let mut accepted: Vec<usize> = Vec::new();
            let mut deliver = |index: usize, bytes: Vec<u8>| -> Delivery {
                // `repair_chunk` verifies length + SHA-256 against the signed
                // manifest BEFORE touching the filesystem.
                match cas.repair_chunk(manifest, index, &bytes) {
                    Ok(WriteOutcome::Created) => {
                        downloaded += 1;
                        accepted.push(index);
                        Delivery::Continue
                    }
                    Ok(WriteOutcome::Repaired) => {
                        repaired += 1;
                        accepted.push(index);
                        Delivery::Continue
                    }
                    Ok(WriteOutcome::AlreadyVerified) => {
                        accepted.push(index);
                        Delivery::Continue
                    }
                    Err(StoreError::InvalidChunk) => {
                        rejected = Some(index);
                        Delivery::Stop
                    }
                    Err(error) => {
                        local_error = Some((index, error));
                        Delivery::Stop
                    }
                }
            };
            let outcome = host
                .transport
                .fetch_objects(manifest, request, &mut deliver)
                .await;
            report.downloaded += downloaded;
            report.repaired += repaired;
            host_report.delivered += accepted.len();
            done.extend_from_slice(&accepted);
            if let Some((index, error)) = local_error.take() {
                report.hosts.push(host_report);
                return Err(FetchError::Store {
                    report,
                    index,
                    error,
                });
            }
            if let Some(index) = rejected {
                host_report.rejected_object = Some(index);
                break 'batches;
            }
            match outcome {
                Ok(()) if accepted.len() == request.len() => {}
                Ok(()) => {
                    host_report.failure = Some(TransportFailure::Interrupted {
                        delivered: accepted.len(),
                        detail: "transport finished without delivering every request".into(),
                    });
                    break 'batches;
                }
                Err(failure) => {
                    host_report.failure = Some(failure);
                    break 'batches;
                }
            }
        }
        remaining.retain(|i| !done.contains(i));
        report.hosts.push(host_report);
    }

    // Defence in depth: completion is decided by re-reading the CAS, not by
    // counting callbacks.
    let (final_audit, still_needed) =
        audit_indices(cas, manifest).map_err(|(index, error)| FetchError::Store {
            report: report.clone(),
            index,
            error,
        })?;
    if final_audit.verified == report.total {
        Ok(report)
    } else {
        Err(FetchError::Incomplete {
            report,
            missing: still_needed.into_iter().map(|(i, _)| i).collect(),
        })
    }
}
