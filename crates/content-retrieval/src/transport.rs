//! Transport contract for reliable encrypted-object retrieval.
//!
//! Implementations talk to exactly one host whose address and certificate
//! fingerprint were authenticated through Holochain. Everything a transport
//! returns is **untrusted**: documents are verified by `binding`, objects by
//! `VerifiedCas`. A transport never decides authorisation.
//!
//! Failure classification matters: [`TransportFailure`] distinguishes a
//! certificate-pin mismatch (a security boundary) from availability problems
//! (unreachable, refused, timed out, interrupted). Callers must never report
//! an availability failure as an authorisation denial.

use holochain_content_core::binding::PinnedEndpoint;
use holochain_content_core::compat::VerifiedManifest;
use holochain_content_core::PackageId;
use std::fmt;
use std::future::Future;

/// Upper bound for a signed manifest document (Music `MAX_MANIFEST_BYTES`
/// plus the signed-envelope allowance used by `verify_music_manifest`).
pub const MAX_MANIFEST_DOCUMENT_BYTES: usize =
    holochain_content_core::compat::MAX_MANIFEST_BYTES + 1024;
/// Upper bound for a signed receipt document (Music host `MAX_RECEIPT_BYTES`).
pub const MAX_RECEIPT_DOCUMENT_BYTES: usize = 16 * 1024;

/// Public signed documents a host serves alongside ciphertext.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DocumentKind {
    /// The artist-signed S1 encrypted-package manifest.
    Manifest,
    /// This host's signed S1 replica receipt.
    Receipt,
}

impl DocumentKind {
    /// Maximum accepted size before verification.
    pub const fn max_bytes(self) -> usize {
        match self {
            Self::Manifest => MAX_MANIFEST_DOCUMENT_BYTES,
            Self::Receipt => MAX_RECEIPT_DOCUMENT_BYTES,
        }
    }
}

/// Why a host could not supply what was asked. None of these is an
/// authorisation decision; only [`TransportFailure::IdentityMismatch`] is a
/// security rejection, and it is a rejection of the *host*, not of the user.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransportFailure {
    /// The peer's TLS certificate SHA-256 differs from the Holochain pin.
    IdentityMismatch(String),
    /// QUIC/MoQ session could not be established (unreachable, refused,
    /// handshake failure other than the pin check).
    Unavailable(String),
    /// The host answered but declined the request (unknown file, budget).
    Refused(String),
    /// No progress within the configured bound.
    TimedOut(String),
    /// The track ended or failed before all requested objects arrived.
    Interrupted {
        /// Objects delivered before the interruption.
        delivered: usize,
        /// Diagnostic text from the transport.
        detail: String,
    },
    /// The peer violated protocol bounds (oversized document, local queue
    /// overflow, malformed response).
    Protocol(String),
}

impl TransportFailure {
    /// Security rejection of the host (pin mismatch), as opposed to an
    /// availability failure.
    pub fn is_identity_mismatch(&self) -> bool {
        matches!(self, Self::IdentityMismatch(_))
    }
}

impl fmt::Display for TransportFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IdentityMismatch(d) => write!(f, "transport identity mismatch: {d}"),
            Self::Unavailable(d) => write!(f, "host unavailable: {d}"),
            Self::Refused(d) => write!(f, "host refused request: {d}"),
            Self::TimedOut(d) => write!(f, "host timed out: {d}"),
            Self::Interrupted { delivered, detail } => {
                write!(
                    f,
                    "transfer interrupted after {delivered} objects: {detail}"
                )
            }
            Self::Protocol(d) => write!(f, "protocol violation: {d}"),
        }
    }
}

impl std::error::Error for TransportFailure {}

/// What the receiver wants after one delivered object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Delivery {
    /// Keep streaming the requested objects.
    Continue,
    /// Stop this request now (the object was rejected or storage failed).
    Stop,
}

/// Callback receiving `(requested_index, untrusted_ciphertext)`.
pub type DeliverFn<'a> = dyn FnMut(usize, Vec<u8>) -> Delivery + Send + 'a;

/// One certificate-pinned host.
pub trait ObjectTransport {
    /// Fetch a public signed document for `package`, refusing anything
    /// larger than `kind.max_bytes()`. The result is untrusted bytes.
    fn fetch_document(
        &mut self,
        package: PackageId,
        kind: DocumentKind,
    ) -> impl Future<Output = Result<Vec<u8>, TransportFailure>> + Send;

    /// Request exactly `indices` (in this order) and deliver each object as
    /// it arrives, labelled with the *requested* index. Implementations must
    /// bound each object by the manifest's `cipher_bytes` and stop when the
    /// callback returns [`Delivery::Stop`].
    fn fetch_objects<'a>(
        &'a mut self,
        manifest: &'a VerifiedManifest,
        indices: &'a [usize],
        deliver: &'a mut DeliverFn<'_>,
    ) -> impl Future<Output = Result<(), TransportFailure>> + Send + 'a;
}

/// Creates a transport for an authenticated endpoint. Construction must not
/// perform network I/O; connections are made by the transport's methods.
pub trait HostConnector {
    /// Transport type produced for each host.
    type Transport: ObjectTransport + Send;
    /// Transport pinned to `endpoint`'s address and certificate fingerprint.
    fn connect(&self, endpoint: &PinnedEndpoint) -> Self::Transport;
}
