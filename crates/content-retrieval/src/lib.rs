//! CORE-004: authenticated, resumable retrieval of Music S1 ciphertext.
//!
//! This crate composes three independent boundaries without owning any of
//! them:
//!
//! 1. **Identity / provenance** — [`resolve::resolve_content`] reads
//!    conductor-validated Music S2 records through a [`resolve::MetadataSource`]
//!    and [`holochain_content_core::binding`] checks authorship and bindings.
//! 2. **Transport** — an [`transport::ObjectTransport`] fetches untrusted
//!    documents and ciphertext objects from one certificate-pinned host.
//! 3. **Storage integrity** — every object is length/SHA-256 verified by
//!    [`holochain_content_core::storage::VerifiedCas`] before it is persisted.
//!
//! It never sees a content key, grant, or plaintext. Entitlement evaluation,
//! key delivery and decryption are separate (see `docs/CORE-004-*.md`).
//!
//! The crate has no async runtime, Holochain, QUIC or MoQ dependency: those
//! live in adapter crates under `integration/`, so the CAS and this
//! orchestration stay testable locally with mock transports.

#![forbid(unsafe_code)]

/// Holochain S2 metadata resolution and host authentication.
pub mod resolve;

/// Resumable multi-host ciphertext retrieval into `VerifiedCas`.
pub mod fetch;

/// The transport contract implemented by MoQ (or any other) adapters.
pub mod transport;

pub use fetch::{
    fetch_verified_content, FetchError, FetchOptions, FetchReport, HostReport, HostSource,
};
pub use resolve::{
    authenticate_content, resolve_content, AuthenticatedContent, AuthenticatedHost, HostPins,
    HostRejection, MetadataError, MetadataSource, RejectReason, ResolveError, ResolvedContent,
};
pub use transport::{
    Delivery, DocumentKind, HostConnector, ObjectTransport, TransportFailure,
    MAX_MANIFEST_DOCUMENT_BYTES, MAX_RECEIPT_DOCUMENT_BYTES,
};

#[cfg(test)]
mod tests;
