//! Certificate-pinned MoQ/QUIC client for the **existing** Holochain Music
//! v1 ciphertext host protocol (`holochain-music-moq serve`,
//! `crates/moq-music/src/serve.rs` at holochain-music bd7aabc).
//!
//! No new wire protocol is defined here. Namespace and track names are the
//! Music host's:
//!
//! * `holochain-music/host/v1` namespace;
//! * `file/<file_id>/manifest`, `file/<file_id>/receipt` — one object each;
//! * `file/<file_id>/objects/<i>,<j>,…` — exactly those ciphertext objects,
//!   in order, at most 64 per request.
//!
//! Transport is the holochain-moq `realtime` crate (IETF MoQT draft-14 over
//! QUIC) with `MoqSubscribeNode::new_with_pinned_identity`: the TLS handshake
//! succeeds only if the host presents the certificate whose complete-DER
//! SHA-256 equals the Holochain-authored pin. There is no CA, hostname or
//! trust-on-first-use path.
//!
//! This crate makes **no Holochain calls**. Every byte it returns is
//! untrusted; `holochain-content-retrieval` verifies documents against
//! Holochain bindings and objects against the signed manifest via
//! `VerifiedCas` before anything is persisted.

#![forbid(unsafe_code)]

use holochain_content_core::binding::PinnedEndpoint;
use holochain_content_core::compat::VerifiedManifest;
use holochain_content_core::PackageId;
use holochain_content_retrieval::transport::DeliverFn;
use holochain_content_retrieval::{
    Delivery, DocumentKind, HostConnector, ObjectTransport, TransportFailure,
};
use holochain_moq_protocol::TransportIdentity;
use holochain_moq_realtime::transport::{SubscribeTransport, Subscription};
use holochain_moq_realtime::{MoqSubscribeNode, MoqSubscription};
use std::time::Duration;
use url::Url;

/// Music v1 host namespace (`serve.rs::HOST_NAMESPACE`).
pub const HOST_NAMESPACE: &str = "holochain-music/host/v1";
/// Music v1 host per-request object limit (`MAX_OBJECTS_PER_REQUEST`).
pub const MAX_OBJECTS_PER_REQUEST: usize = 64;

/// `file/<file_id>/manifest` or `file/<file_id>/receipt`.
pub fn document_track(package: PackageId, kind: DocumentKind) -> String {
    let name = match kind {
        DocumentKind::Manifest => "manifest",
        DocumentKind::Receipt => "receipt",
    };
    format!("file/{package}/{name}")
}

/// `file/<file_id>/objects/<i>,<j>,…` (canonical decimal, no padding).
pub fn objects_track(package: PackageId, indices: &[usize]) -> String {
    let list: Vec<String> = indices.iter().map(usize::to_string).collect();
    format!("file/{package}/objects/{}", list.join(","))
}

/// Bounds for one host's QUIC/MoQ exchanges.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Timeouts {
    /// QUIC + TLS + MoQT session establishment.
    pub handshake: Duration,
    /// Wait for each object (or document) once subscribed.
    pub object: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            handshake: Duration::from_secs(30),
            object: Duration::from_secs(30),
        }
    }
}

/// Marker text produced by `holochain_moq_realtime::PinnedFingerprintVerifier`
/// when the presented certificate does not match the expected fingerprint.
const PIN_MISMATCH_MARKER: &str = "transport identity mismatch";

fn classify_connect(error: anyhow::Error) -> TransportFailure {
    let text = format!("{error:#}");
    if text.contains(PIN_MISMATCH_MARKER) {
        TransportFailure::IdentityMismatch(text)
    } else {
        TransportFailure::Unavailable(text)
    }
}

fn classify_track_error(error: anyhow::Error, delivered: usize) -> TransportFailure {
    let text = format!("{error:#}");
    if text.contains(PIN_MISMATCH_MARKER) {
        TransportFailure::IdentityMismatch(text)
    } else if delivered == 0 && text.to_ascii_lowercase().contains("not found") {
        TransportFailure::Refused(text)
    } else {
        TransportFailure::Interrupted {
            delivered,
            detail: text,
        }
    }
}

/// One certificate-pinned Music v1 host. Each request uses a fresh QUIC/MoQ
/// session (the realtime subscriber carries one subscription per session,
/// exactly as Music's own `fetch` client does).
#[derive(Clone, Debug)]
pub struct MoqHostTransport {
    url: Url,
    identity: TransportIdentity,
    timeouts: Timeouts,
}

impl MoqHostTransport {
    /// Transport for an endpoint authenticated from Holochain.
    pub fn new(endpoint: &PinnedEndpoint, timeouts: Timeouts) -> Self {
        // `PinnedEndpoint::url` is already canonical `https://IPv4:port`.
        let url = Url::parse(endpoint.url()).expect("PinnedEndpoint URL is canonical");
        Self {
            url,
            identity: TransportIdentity {
                fingerprint: *endpoint.cert_fingerprint(),
            },
            timeouts,
        }
    }

    async fn subscribe(&self, track: &str) -> Result<MoqSubscription, TransportFailure> {
        let mut node = MoqSubscribeNode::new_with_pinned_identity(
            self.url.clone(),
            HOST_NAMESPACE,
            self.identity,
        )
        .map_err(|e| TransportFailure::Protocol(format!("client setup: {e:#}")))?;
        match tokio::time::timeout(self.timeouts.handshake, node.connect()).await {
            Err(_) => {
                return Err(TransportFailure::TimedOut(
                    "QUIC/TLS/MoQT handshake".into(),
                ))
            }
            Ok(Err(e)) => return Err(classify_connect(e)),
            Ok(Ok(())) => {}
        }
        match tokio::time::timeout(self.timeouts.handshake, node.subscribe(track)).await {
            Err(_) => Err(TransportFailure::TimedOut("MoQT subscribe".into())),
            Ok(Err(e)) => Err(classify_connect(e)),
            Ok(Ok(subscription)) => Ok(subscription),
        }
    }

    async fn next_object(
        &self,
        subscription: &mut MoqSubscription,
        delivered: usize,
    ) -> Result<Vec<u8>, TransportFailure> {
        let next = tokio::time::timeout(self.timeouts.object, subscription.recv()).await;
        let object = match next {
            Err(_) => {
                return Err(if delivered == 0 {
                    TransportFailure::TimedOut("no object from host".into())
                } else {
                    TransportFailure::Interrupted {
                        delivered,
                        detail: "object stream stalled".into(),
                    }
                })
            }
            Ok(Err(e)) => return Err(classify_track_error(e, delivered)),
            Ok(Ok(None)) => {
                return Err(TransportFailure::Interrupted {
                    delivered,
                    detail: "host ended the track early".into(),
                })
            }
            Ok(Ok(Some(object))) => object,
        };
        // The realtime subscriber drops the *oldest* objects if the reader
        // falls behind its bounded queue. For a finite ordered transfer that
        // is a loss, not a corruption: report it and let the caller retry.
        if subscription.overflow_dropped() > 0 {
            return Err(TransportFailure::Protocol(
                "local subscription queue overflowed; objects were dropped".into(),
            ));
        }
        Ok(object.to_vec())
    }
}

impl ObjectTransport for MoqHostTransport {
    async fn fetch_document(
        &mut self,
        package: PackageId,
        kind: DocumentKind,
    ) -> Result<Vec<u8>, TransportFailure> {
        let mut subscription = self.subscribe(&document_track(package, kind)).await?;
        let document = self.next_object(&mut subscription, 0).await?;
        if document.len() > kind.max_bytes() {
            return Err(TransportFailure::Protocol(format!(
                "{kind:?} document of {} bytes exceeds {} byte bound",
                document.len(),
                kind.max_bytes()
            )));
        }
        Ok(document)
    }

    async fn fetch_objects<'a>(
        &'a mut self,
        manifest: &'a VerifiedManifest,
        indices: &'a [usize],
        deliver: &'a mut DeliverFn<'_>,
    ) -> Result<(), TransportFailure> {
        let package = manifest.package_id();
        let mut delivered = 0usize;
        for batch in indices.chunks(MAX_OBJECTS_PER_REQUEST) {
            if batch
                .iter()
                .any(|&i| i >= manifest.chunks().len())
            {
                return Err(TransportFailure::Protocol(
                    "requested index outside the signed manifest".into(),
                ));
            }
            let mut subscription = self.subscribe(&objects_track(package, batch)).await?;
            for &index in batch {
                let object = self.next_object(&mut subscription, delivered).await?;
                let expected = manifest.chunks()[index].cipher_bytes;
                // Larger than signed is never accepted. (Exact length and
                // SHA-256 are checked by VerifiedCas before persisting.)
                if object.len() as u64 > expected {
                    let _ = deliver(index, object);
                    return Ok(());
                }
                delivered += 1;
                if deliver(index, object) == Delivery::Stop {
                    return Ok(());
                }
            }
        }
        Ok(())
    }
}

/// Builds [`MoqHostTransport`]s for Holochain-authenticated endpoints.
#[derive(Clone, Copy, Debug, Default)]
pub struct MoqConnector {
    /// Bounds used for every host.
    pub timeouts: Timeouts,
}

impl HostConnector for MoqConnector {
    type Transport = MoqHostTransport;
    fn connect(&self, endpoint: &PinnedEndpoint) -> MoqHostTransport {
        MoqHostTransport::new(endpoint, self.timeouts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn track_names_match_music_v1_host() {
        // Expected strings from holochain-music crates/moq-music/src/serve.rs
        // (`document_track`, `objects_track`, strict `parse_track`).
        let id = PackageId::from_bytes([0xab; 32]);
        let hex = "ab".repeat(32);
        assert_eq!(
            document_track(id, DocumentKind::Manifest),
            format!("file/{hex}/manifest")
        );
        assert_eq!(
            document_track(id, DocumentKind::Receipt),
            format!("file/{hex}/receipt")
        );
        assert_eq!(
            objects_track(id, &[17, 2, 0]),
            format!("file/{hex}/objects/17,2,0")
        );
    }

    #[test]
    fn pin_mismatch_is_classified_as_identity_not_availability() {
        let e = anyhow::anyhow!(
            "QUIC connect failed: invalid peer certificate: transport identity mismatch: expected a, got b"
        );
        assert!(classify_connect(e).is_identity_mismatch());
        let e = anyhow::anyhow!("QUIC connect failed: timed out");
        assert!(matches!(
            classify_connect(e),
            TransportFailure::Unavailable(_)
        ));
        let e = anyhow::anyhow!("subscription ended with an error: not found");
        assert!(matches!(
            classify_track_error(e, 0),
            TransportFailure::Refused(_)
        ));
        let e = anyhow::anyhow!("session error: connection lost");
        assert!(matches!(
            classify_track_error(e, 3),
            TransportFailure::Interrupted { delivered: 3, .. }
        ));
    }
}
