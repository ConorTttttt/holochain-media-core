//! CORE-005: reusable entitlement verification for signed content grants.
//!
//! This module decides whether an owner-signed entitlement document lets one
//! authenticated subject exercise one [`Right`] over one [`OwnedManifest`] at
//! one instant. It is a strict, read-only port of the checks in Holochain
//! Music's `music_catalogue/content_grants.py::unwrap_content_grant` (pinned
//! at bd7aabc3e9ea1fef1e8e8f674301e1b5ffecb637), *minus the key unwrap*, plus
//! the per-operation gates in `holochain_music/app.py`.
//!
//! # Trust inputs
//!
//! * **Owner**: taken only from [`OwnedManifest`], i.e. from the owner's
//!   Holochain-authored `owner-manifest` key binding and file commitment
//!   (CORE-004). The grant's own `signer` field is compared against that key
//!   but is never evidence of ownership by itself.
//! * **Subject**: an [`AuthenticatedSubject`] built by the application from
//!   its own trusted context: the local conductor's agent and the X25519
//!   public key of a private key the application itself holds. Nothing about
//!   the subject is read from the grant.
//! * **Clock**: an explicit `now: SystemTime`, so policy is deterministic and
//!   testable without waiting.
//!
//! # What `Ok` certifies, and what it does not
//!
//! An [`AccessDecision`] certifies that: the document is a supported schema;
//! it is signed (Ed25519, strict) by the owner's Holochain-bound key; it
//! names exactly this owner agent, file ID and signed-manifest digest; it is
//! addressed to exactly this listener agent and X25519 recipient key; it is
//! inside its validity period at `now`; its terms confer the requested right;
//! and its wrapped-key fields are well-formed.
//!
//! It does **not** certify that the wrapped content key decrypts. Only the
//! holder of the recipient's X25519 private key can check that, by performing
//! X25519 + HKDF-SHA256 + AES-256-GCM over [`WrappedContentKey`]; a
//! corrupted, low-order or mis-wrapped key passes this module and fails
//! there. Plaintext access therefore still requires the application's
//! existing unwrap, and AES-GCM authentication of every content chunk. It is
//! not proof of payment, nor that the content is currently available from
//! any host. See `docs/CORE-005-entitlement-verification.md`.

use crate::binding::{BindingAssurance, KeyPurpose, OwnedManifest};
use crate::compat::canonical_json;
use crate::lifecycle::{KeyLifecycle, KeyUse, KeyValidity};
use crate::{ManifestDigest, PackageId, Right, Rights};
use base64::alphabet;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use base64::Engine as _;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

/// Music S10 time-limited streaming grant.
pub const MUSIC_CONTENT_GRANT_V1: &str = "holochain-music/content-grant/v1";
/// Music permanent personal-use licence.
pub const MUSIC_PERSONAL_LICENCE_V1: &str = "holochain-music/personal-licence/v1";
/// Opt-in lifecycle-anchored grant. Never parsed by v1 entry points.
pub const MUSIC_ACCESS_GRANT_V2: &str = "holochain-music/access-grant/v2";
/// Earlier S1-prototype perpetual grant (`holochain_storage/grant.py`).
/// Recognised only to reject it explicitly; see [`Unsupported::LegacyPerpetualGrant`].
pub const MUSIC_LEGACY_PERPETUAL_GRANT_V1: &str = "holochain-music/personal-perpetual-grant/v1";
/// The only licence terms defined by `personal-licence/v1`.
pub const MUSIC_PERSONAL_USE_TERMS: &str = "perpetual-personal-use";

/// Music `MAX_GRANT_BYTES`: limit on the *canonical* signed envelope.
pub const MAX_GRANT_BYTES: usize = 4096;
/// Limit on the raw input, checked before any parsing. Music's
/// `Library.grant()` refuses grant files above 16 KiB.
pub const MAX_GRANT_INPUT_BYTES: usize = 16 * 1024;
/// Music `MAX_LIFETIME_SECONDS` for streaming grants.
pub const MAX_STREAM_LIFETIME_SECONDS: i64 = 86_400;
/// Music `CLOCK_SKEW_SECONDS`: tolerated issuer clock lead. It applies only to
/// `issued_at`; Music applies no grace period after `expires_at`.
pub const CLOCK_SKEW_SECONDS: i64 = 120;
/// Music `_identity` limit for agent strings.
const MAX_AGENT_BYTES: usize = 160;

const STREAM_CONTEXT_PREFIX: &[u8] = b"holochain-music/content-grant/hkdf-aad/v1\x00";
const LICENCE_CONTEXT_PREFIX: &[u8] = b"holochain-music/personal-licence/hkdf-aad/v1\x00";

/// Python `base64.b64decode(text, validate=True)`: standard alphabet,
/// canonical `=` padding, no whitespace, *non-zero trailing bits ignored*.
const MUSIC_B64: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new()
        .with_decode_allow_trailing_bits(true)
        .with_decode_padding_mode(DecodePaddingMode::RequireCanonical),
);

// ---------------------------------------------------------------------------
// Schemes and rights
// ---------------------------------------------------------------------------

/// A supported, versioned entitlement scheme. New commercial or public
/// policies must be added as new variants with their own explicit rights;
/// existing variants never change meaning.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum EntitlementScheme {
    /// `holochain-music/content-grant/v1`: owner-issued, listener-specific,
    /// time-limited (≤ 24 h) playback.
    MusicContentGrantV1,
    /// `holochain-music/personal-licence/v1` with terms
    /// `perpetual-personal-use`: owner-issued, listener-specific, non-expiring.
    MusicPersonalLicenceV1,
    /// Lifecycle-anchored grants: verify only with access_grant_v2::verify_access_grant_v2.
    MusicAccessGrantV2,
}

impl EntitlementScheme {
    /// The exact signed `schema` string.
    pub const fn schema(self) -> &'static str {
        match self {
            Self::MusicContentGrantV1 => MUSIC_CONTENT_GRANT_V1,
            Self::MusicPersonalLicenceV1 => MUSIC_PERSONAL_LICENCE_V1,
            Self::MusicAccessGrantV2 => MUSIC_ACCESS_GRANT_V2,
        }
    }

    /// Rights conferred by a verified entitlement of this scheme.
    ///
    /// These mirror Music's application gates at the pinned commit:
    /// playback (`_session_for`) accepts any grant that verifies, while
    /// `download`, `offline_readiness` and `export_wav` additionally require
    /// `grant_kind == "perpetual-personal"`. A streaming grant therefore
    /// confers `Stream` only; a personal licence confers all three.
    pub const fn rights(self) -> Rights {
        match self {
            Self::MusicContentGrantV1 => Rights::STREAM,
            Self::MusicPersonalLicenceV1 => Rights::STREAM
                .union(Rights::MANAGED_OFFLINE)
                .union(Rights::EXPORT),
            // v2 rights vary per *signed grant*; never infer rights from the schema.
            Self::MusicAccessGrantV2 => Rights::NONE,
        }
    }

    /// Whether entitlements of this scheme carry an expiry.
    pub const fn expires(self) -> bool {
        matches!(self, Self::MusicContentGrantV1)
    }

    /// Classify a schema string. Unknown and legacy schemas fail closed.
    pub fn from_schema(schema: &str) -> Result<Self, Unsupported> {
        match schema {
            MUSIC_CONTENT_GRANT_V1 => Ok(Self::MusicContentGrantV1),
            MUSIC_PERSONAL_LICENCE_V1 => Ok(Self::MusicPersonalLicenceV1),
            // A v2 grant without authenticated lifecycle AND anchor is never access.
            MUSIC_ACCESS_GRANT_V2 => Err(Unsupported::RequiresLifecycle),
            MUSIC_LEGACY_PERPETUAL_GRANT_V1 => Err(Unsupported::LegacyPerpetualGrant),
            _ => Err(Unsupported::UnknownSchema),
        }
    }
}

// ---------------------------------------------------------------------------
// Subject
// ---------------------------------------------------------------------------

/// The listener on whose behalf access is being evaluated.
///
/// Construct this **only** from the application's own trusted context: the
/// agent of the local, validating Holochain conductor the application is
/// running as, and the public half of an X25519 private key the application
/// itself holds. Never build it from fields of a grant, a peer message or an
/// HTTP request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedSubject {
    listener_agent: String,
    recipient_key: [u8; 32],
}

/// The supplied subject context is unusable (caller error, not a denial).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubjectError {
    /// Empty, longer than 160 bytes, or containing NUL (Music `_identity`).
    InvalidListenerAgent,
}

impl fmt::Display for SubjectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid authenticated listener agent")
    }
}

impl std::error::Error for SubjectError {}

impl AuthenticatedSubject {
    /// Wrap the application's trusted listener identity and its own X25519
    /// recipient public key.
    pub fn from_trusted_context(
        listener_agent: impl Into<String>,
        recipient_x25519_public: [u8; 32],
    ) -> Result<Self, SubjectError> {
        let listener_agent = listener_agent.into();
        if !valid_agent(&listener_agent) {
            return Err(SubjectError::InvalidListenerAgent);
        }
        Ok(Self {
            listener_agent,
            recipient_key: recipient_x25519_public,
        })
    }

    /// The authenticated listener agent.
    pub fn listener_agent(&self) -> &str {
        &self.listener_agent
    }

    /// The listener's X25519 recipient public key.
    pub fn recipient_key(&self) -> &[u8; 32] {
        &self.recipient_key
    }
}

fn valid_agent(agent: &str) -> bool {
    !agent.is_empty() && agent.len() <= MAX_AGENT_BYTES && !agent.contains('\0')
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// The input is not a well-formed entitlement document.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Malformed {
    /// Raw input over [`MAX_GRANT_INPUT_BYTES`] or canonical envelope over
    /// [`MAX_GRANT_BYTES`].
    TooLarge,
    /// Not syntactically valid JSON (truncated, trailing data, empty).
    Json,
    /// Valid JSON with the wrong shape: missing, unknown, duplicate or
    /// wrongly typed fields; non-object envelope; missing schema.
    Structure,
    /// A number that Music's canonical JSON cannot be reproduced for
    /// (floats, integers outside 64-bit range).
    NonCanonicalNumber,
    /// `recipient_key_hex` is not 64 lowercase hex characters.
    RecipientKey,
    /// `ephemeral_key_hex` is not 64 lowercase hex characters.
    EphemeralKey,
    /// `licence_id` is not 32 lowercase hex characters.
    LicenceId,
    /// `salt_b64`/`nonce_b64`/`wrapped_key_b64` is not base64 of 16/12/48 bytes.
    KeyEnvelope,
}

/// The document is not authentically issued by the content owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Unauthenticated {
    /// `signer` is not the owner's Holochain-bound key.
    WrongIssuer,
    /// `signer` is not base64 of 32 bytes.
    MalformedIssuerKey,
    /// `signature` is not base64 of 64 bytes.
    MalformedSignature,
    /// Ed25519 (strict) verification over the canonical body failed.
    InvalidSignature,
    /// The issuer key is bound to the owner only at a lower assurance level
    /// than the caller required (e.g. a legacy v1 binding where S2 v2 proof
    /// of possession is required).
    InsufficientOwnerAssurance,
    /// v2.1: the issuer (manifest) key was revoked as compromised, so an
    /// unanchored grant/licence signed by it cannot be told apart from one
    /// forged with the stolen key.
    IssuerKeyRevoked,
    /// v2.1: the issuer key is not part of the owner's verified lifecycle
    /// for `owner-manifest` (or the lifecycle is for another agent).
    IssuerNotInLifecycle,
}

/// The document is (or claims to be) a scheme or term this version does not
/// implement. Never treated as access.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Unsupported {
    /// Unknown or future `schema`.
    UnknownSchema,
    /// `holochain-music/personal-perpetual-grant/v1`: not bound to owner or
    /// listener agents; needs its own compatibility increment.
    LegacyPerpetualGrant,
    /// access-grant/v2 requires an explicit trusted lifecycle and anchor.
    RequiresLifecycle,
    /// Authentic licence with terms other than `perpetual-personal-use`.
    LicenceTerms,
}

/// Authentic, but not for this owner, content, listener, key or right.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Denied {
    /// `owner_agent` is not the authenticated content owner.
    OwnerMismatch,
    /// `file_id` is not this package.
    FileMismatch,
    /// `manifest_sha256` is not this exact signed manifest.
    ManifestMismatch,
    /// `listener_agent` is not the authenticated subject.
    ListenerMismatch,
    /// Addressed to a different X25519 recipient key.
    RecipientKeyMismatch,
    /// The verified terms do not confer the requested right.
    RightNotGranted,
}

/// Authentic and correctly addressed, but not valid at `now`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Validity {
    /// `issued_at` is more than [`CLOCK_SKEW_SECONDS`] after `now`.
    NotYetValid,
    /// `now >= expires_at` (streaming grants only).
    Expired,
    /// `expires_at - issued_at` is not within `1..=86400` seconds.
    InvalidPeriod,
    /// A timestamp is not a 64-bit integer (string, bool, null, …).
    InvalidTimestamp,
}

/// Evaluation could not be performed with authoritative inputs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Unavailable {
    /// The supplied clock is before the Unix epoch or beyond `i64` seconds.
    Clock,
    /// The authenticated owner key is not a usable Ed25519 key.
    OwnerKey,
}

/// Why access was not authorised. Every variant is a rejection; the
/// categories exist so callers never confuse, for example, an expired
/// licence with a forged one, or a missing input with a denial.
///
/// None of these is a transport, timeout or host-availability failure: this
/// module performs no I/O.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccessError {
    /// Not a well-formed entitlement document.
    Malformed(Malformed),
    /// Not issued by the authenticated owner.
    Unauthenticated(Unauthenticated),
    /// Unknown/legacy schema or unsupported terms.
    Unsupported(Unsupported),
    /// Authentic but not applicable to this request.
    Denied(Denied),
    /// Authentic but outside its validity period.
    Validity(Validity),
    /// Authoritative input (clock, owner key) unusable.
    Unavailable(Unavailable),
}

impl AccessError {
    /// Stable lowercase category name (used by the CLI and vectors).
    pub const fn category(&self) -> &'static str {
        match self {
            Self::Malformed(_) => "malformed",
            Self::Unauthenticated(_) => "unauthenticated",
            Self::Unsupported(_) => "unsupported",
            Self::Denied(_) => "denied",
            Self::Validity(_) => "validity",
            Self::Unavailable(_) => "unavailable",
        }
    }

    /// Stable reason name within the category.
    pub fn reason(&self) -> String {
        match self {
            Self::Malformed(r) => format!("{r:?}"),
            Self::Unauthenticated(r) => format!("{r:?}"),
            Self::Unsupported(r) => format!("{r:?}"),
            Self::Denied(r) => format!("{r:?}"),
            Self::Validity(r) => format!("{r:?}"),
            Self::Unavailable(r) => format!("{r:?}"),
        }
    }

    /// True only for an authentic grant whose expiry has passed.
    pub const fn is_expired(&self) -> bool {
        matches!(self, Self::Validity(Validity::Expired))
    }
}

impl fmt::Display for AccessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.category(), self.reason())
    }
}

impl std::error::Error for AccessError {}

// ---------------------------------------------------------------------------
// Results
// ---------------------------------------------------------------------------

/// Public, recipient-specific key-wrapping material from a verified grant.
///
/// Contains no secret: opening it requires the recipient's X25519 private
/// key. The application performs (Music's scheme):
/// `shared = X25519(recipient_private, ephemeral_public)`,
/// `kek = HKDF-SHA256(ikm = shared, salt, info = context, len = 32)`,
/// `content_key = AES-256-GCM-Decrypt(kek, nonce, wrapped_key, aad = context)`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WrappedContentKey {
    pub(crate) ephemeral_public: [u8; 32],
    pub(crate) salt: [u8; 16],
    pub(crate) nonce: [u8; 12],
    pub(crate) wrapped_key: [u8; 48],
    pub(crate) context: Vec<u8>,
}

impl WrappedContentKey {
    /// Issuer's ephemeral X25519 public key (not validated as a curve point).
    pub fn ephemeral_public(&self) -> &[u8; 32] {
        &self.ephemeral_public
    }
    /// HKDF salt.
    pub fn salt(&self) -> &[u8; 16] {
        &self.salt
    }
    /// AES-GCM nonce.
    pub fn nonce(&self) -> &[u8; 12] {
        &self.nonce
    }
    /// AES-256-GCM ciphertext + tag of the 32-byte content key.
    pub fn wrapped_key(&self) -> &[u8; 48] {
        &self.wrapped_key
    }
    /// Music's HKDF `info` and AES-GCM associated data (domain-separated
    /// prefix + canonical JSON of the signed scope), byte-identical to
    /// Python `_context`/`_licence_context`.
    pub fn context(&self) -> &[u8] {
        &self.context
    }
}

/// An authenticated, correctly scoped, currently valid entitlement.
///
/// Only [`verify_entitlement`] constructs this. See the module docs for what
/// it does and does not certify.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedEntitlement {
    pub(crate) scheme: EntitlementScheme,
    pub(crate) granted_rights: Rights,
    pub(crate) owner_agent: String,
    pub(crate) listener_agent: String,
    pub(crate) recipient_key: [u8; 32],
    pub(crate) package_id: PackageId,
    pub(crate) manifest_digest: ManifestDigest,
    pub(crate) issued_at: i64,
    pub(crate) expires_at: Option<i64>,
    pub(crate) licence_id: Option<String>,
    pub(crate) key: WrappedContentKey,
    pub(crate) owner_assurance: BindingAssurance,
}

impl VerifiedEntitlement {
    /// Assurance of the owner key binding that authenticated the issuer
    /// (copied from the [`OwnedManifest`]; not settable by callers).
    pub fn owner_assurance(&self) -> BindingAssurance {
        self.owner_assurance
    }
    /// The verified scheme.
    pub fn scheme(&self) -> EntitlementScheme {
        self.scheme
    }
    /// Rights the verified terms confer.
    pub fn rights(&self) -> Rights {
        self.granted_rights
    }
    /// Authenticated owner agent (from the Holochain binding).
    pub fn owner_agent(&self) -> &str {
        &self.owner_agent
    }
    /// Authenticated listener agent (from the caller's trusted context).
    pub fn listener_agent(&self) -> &str {
        &self.listener_agent
    }
    /// X25519 recipient key the content key is wrapped to.
    pub fn recipient_key(&self) -> &[u8; 32] {
        &self.recipient_key
    }
    /// The exact package.
    pub fn package_id(&self) -> PackageId {
        self.package_id
    }
    /// The exact signed manifest.
    pub fn manifest_digest(&self) -> ManifestDigest {
        self.manifest_digest
    }
    /// Signed issue time (Unix seconds).
    pub fn issued_at(&self) -> i64 {
        self.issued_at
    }
    /// Signed expiry (Unix seconds); `None` for non-expiring licences.
    pub fn expires_at(&self) -> Option<i64> {
        self.expires_at
    }
    /// Licence identifier (32 lowercase hex); `None` for streaming grants.
    pub fn licence_id(&self) -> Option<&str> {
        self.licence_id.as_deref()
    }
    /// Wrapped content key for the application's recipient-side unwrap.
    pub fn wrapped_content_key(&self) -> &WrappedContentKey {
        &self.key
    }

    /// Evaluate one requested right against the verified terms.
    pub fn authorize(self, requested: Right) -> Result<AccessDecision, AccessError> {
        if !self.rights().contains(requested) {
            return Err(AccessError::Denied(Denied::RightNotGranted));
        }
        Ok(AccessDecision {
            entitlement: self,
            right: requested,
        })
    }
}

/// `requested` is authorised by `entitlement` (policy level; see module docs).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccessDecision {
    entitlement: VerifiedEntitlement,
    right: Right,
}

impl AccessDecision {
    /// The authorised right.
    pub fn right(&self) -> Right {
        self.right
    }
    /// The verified entitlement that authorises it.
    pub fn entitlement(&self) -> &VerifiedEntitlement {
        &self.entitlement
    }
    /// Consume into the verified entitlement.
    pub fn into_entitlement(self) -> VerifiedEntitlement {
        self.entitlement
    }
}

// ---------------------------------------------------------------------------
// Wire formats (exact Music field sets)
// ---------------------------------------------------------------------------

/// First pass: read only `body.schema` to select the strict format. Unknown
/// fields are ignored here; the strict pass rejects them.
#[derive(Deserialize)]
struct Probe {
    body: ProbeBody,
}

/// Other body fields are skipped (as `IgnoredAny`, without building a
/// `Value` tree); a duplicate `schema` key is already a structure error.
#[derive(Deserialize)]
struct ProbeBody {
    schema: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope<B> {
    body: B,
    signer: String,
    signature: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StreamBody {
    schema: String,
    owner_agent: String,
    listener_agent: String,
    file_id: String,
    manifest_sha256: String,
    recipient_key_hex: String,
    ephemeral_key_hex: String,
    salt_b64: String,
    nonce_b64: String,
    wrapped_key_b64: String,
    issued_at: Value,
    expires_at: Value,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LicenceBody {
    schema: String,
    owner_agent: String,
    listener_agent: String,
    file_id: String,
    manifest_sha256: String,
    recipient_key_hex: String,
    ephemeral_key_hex: String,
    salt_b64: String,
    nonce_b64: String,
    wrapped_key_b64: String,
    issued_at: Value,
    licence_id: String,
    terms: String,
}

/// Fields common to both schemas, borrowed for shared checks.
struct Common<'a> {
    owner_agent: &'a str,
    listener_agent: &'a str,
    file_id: &'a str,
    manifest_sha256: &'a str,
    recipient_key_hex: &'a str,
    ephemeral_key_hex: &'a str,
    salt_b64: &'a str,
    nonce_b64: &'a str,
    wrapped_key_b64: &'a str,
}

fn json_error(e: &serde_json::Error) -> AccessError {
    use serde_json::error::Category;
    AccessError::Malformed(match e.classify() {
        Category::Data => Malformed::Structure,
        Category::Io | Category::Syntax | Category::Eof => Malformed::Json,
    })
}

fn parse<'a, T: Deserialize<'a>>(input: &'a [u8]) -> Result<T, AccessError> {
    serde_json::from_slice(input).map_err(|e| json_error(&e))
}

fn canonical<T: Serialize>(value: &T) -> Result<Vec<u8>, AccessError> {
    let value =
        serde_json::to_value(value).map_err(|_| AccessError::Malformed(Malformed::Structure))?;
    canonical_json(&value).ok_or(AccessError::Malformed(Malformed::NonCanonicalNumber))
}

fn lower_hex<const N: usize>(text: &str) -> Option<[u8; N]> {
    let bytes = text.as_bytes();
    if bytes.len() != 2 * N {
        return None;
    }
    let nibble = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    let mut out = [0u8; N];
    for (i, pair) in bytes.chunks_exact(2).enumerate() {
        out[i] = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Some(out)
}

fn b64<const N: usize>(text: &str) -> Option<[u8; N]> {
    MUSIC_B64.decode(text).ok()?.try_into().ok()
}

fn timestamp(value: &Value) -> Result<i64, AccessError> {
    match value {
        Value::Number(n) => n
            .as_i64()
            .ok_or(AccessError::Validity(Validity::InvalidTimestamp)),
        _ => Err(AccessError::Validity(Validity::InvalidTimestamp)),
    }
}

/// Python `int(time.time())` (floor of non-negative Unix seconds).
fn unix_seconds(now: SystemTime) -> Result<i64, AccessError> {
    now.duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_secs()).ok())
        .ok_or(AccessError::Unavailable(Unavailable::Clock))
}

fn authenticate<B: Serialize>(
    envelope: &Envelope<B>,
    owner_key: &[u8; 32],
) -> Result<(), AccessError> {
    // Music: `len(canonical(grant)) > MAX_GRANT_BYTES` before anything else.
    if canonical(envelope)?.len() > MAX_GRANT_BYTES {
        return Err(AccessError::Malformed(Malformed::TooLarge));
    }
    let signer = b64::<32>(&envelope.signer).ok_or(AccessError::Unauthenticated(
        Unauthenticated::MalformedIssuerKey,
    ))?;
    if signer != *owner_key {
        return Err(AccessError::Unauthenticated(Unauthenticated::WrongIssuer));
    }
    let signature = b64::<64>(&envelope.signature).ok_or(AccessError::Unauthenticated(
        Unauthenticated::MalformedSignature,
    ))?;
    let key = VerifyingKey::from_bytes(owner_key)
        .map_err(|_| AccessError::Unavailable(Unavailable::OwnerKey))?;
    key.verify_strict(
        &canonical(&envelope.body)?,
        &Signature::from_bytes(&signature),
    )
    .map_err(|_| AccessError::Unauthenticated(Unauthenticated::InvalidSignature))
}

/// Owner/content/listener/recipient bindings (after authentication).
fn check_scope(
    common: &Common<'_>,
    content: &OwnedManifest,
    subject: &AuthenticatedSubject,
) -> Result<[u8; 32], AccessError> {
    let manifest = content.manifest();
    if common.owner_agent != content.owner_agent() {
        return Err(AccessError::Denied(Denied::OwnerMismatch));
    }
    if common.file_id != manifest.package_id().to_string() {
        return Err(AccessError::Denied(Denied::FileMismatch));
    }
    if common.manifest_sha256 != manifest.digest().to_string() {
        return Err(AccessError::Denied(Denied::ManifestMismatch));
    }
    if common.listener_agent != subject.listener_agent() {
        return Err(AccessError::Denied(Denied::ListenerMismatch));
    }
    let recipient = lower_hex::<32>(common.recipient_key_hex)
        .ok_or(AccessError::Malformed(Malformed::RecipientKey))?;
    if recipient != *subject.recipient_key() {
        return Err(AccessError::Denied(Denied::RecipientKeyMismatch));
    }
    lower_hex::<32>(common.ephemeral_key_hex).ok_or(AccessError::Malformed(Malformed::EphemeralKey))
}

fn key_envelope(
    common: &Common<'_>,
    ephemeral_public: [u8; 32],
    context: Vec<u8>,
) -> Result<WrappedContentKey, AccessError> {
    let bad = AccessError::Malformed(Malformed::KeyEnvelope);
    Ok(WrappedContentKey {
        ephemeral_public,
        salt: b64::<16>(common.salt_b64).ok_or(bad)?,
        nonce: b64::<12>(common.nonce_b64).ok_or(bad)?,
        wrapped_key: b64::<48>(common.wrapped_key_b64).ok_or(bad)?,
        context,
    })
}

fn context(prefix: &[u8], scope: Value) -> Result<Vec<u8>, AccessError> {
    let mut out = prefix.to_vec();
    out.extend(
        canonical_json(&scope).ok_or(AccessError::Malformed(Malformed::NonCanonicalNumber))?,
    );
    Ok(out)
}

fn verify_stream(
    input: &[u8],
    content: &OwnedManifest,
    subject: &AuthenticatedSubject,
    now: i64,
) -> Result<VerifiedEntitlement, AccessError> {
    let envelope: Envelope<StreamBody> = parse(input)?;
    authenticate(&envelope, content.manifest().signer())?;
    let b = &envelope.body;
    let common = Common {
        owner_agent: &b.owner_agent,
        listener_agent: &b.listener_agent,
        file_id: &b.file_id,
        manifest_sha256: &b.manifest_sha256,
        recipient_key_hex: &b.recipient_key_hex,
        ephemeral_key_hex: &b.ephemeral_key_hex,
        salt_b64: &b.salt_b64,
        nonce_b64: &b.nonce_b64,
        wrapped_key_b64: &b.wrapped_key_b64,
    };
    let ephemeral = check_scope(&common, content, subject)?;
    // Music order: both types, then not-yet-valid, expired, lifetime bounds.
    let issued_at = timestamp(&b.issued_at)?;
    let expires_at = timestamp(&b.expires_at)?;
    if i128::from(issued_at) > i128::from(now) + i128::from(CLOCK_SKEW_SECONDS) {
        return Err(AccessError::Validity(Validity::NotYetValid));
    }
    if expires_at <= now {
        return Err(AccessError::Validity(Validity::Expired));
    }
    let lifetime = i128::from(expires_at) - i128::from(issued_at);
    if !(1..=i128::from(MAX_STREAM_LIFETIME_SECONDS)).contains(&lifetime) {
        return Err(AccessError::Validity(Validity::InvalidPeriod));
    }
    let context = context(
        STREAM_CONTEXT_PREFIX,
        json!({
            "schema": b.schema, "owner_agent": b.owner_agent,
            "listener_agent": b.listener_agent, "file_id": b.file_id,
            "manifest_sha256": b.manifest_sha256,
            "recipient_key_hex": b.recipient_key_hex,
            "issued_at": b.issued_at, "expires_at": b.expires_at,
        }),
    )?;
    let key = key_envelope(&common, ephemeral, context)?;
    Ok(VerifiedEntitlement {
        scheme: EntitlementScheme::MusicContentGrantV1,
        granted_rights: Rights::STREAM,
        owner_agent: content.owner_agent().to_owned(),
        listener_agent: subject.listener_agent().to_owned(),
        recipient_key: *subject.recipient_key(),
        package_id: content.manifest().package_id(),
        manifest_digest: content.manifest().digest(),
        issued_at,
        expires_at: Some(expires_at),
        licence_id: None,
        key,
        owner_assurance: content.owner_assurance(),
    })
}

fn verify_licence(
    input: &[u8],
    content: &OwnedManifest,
    subject: &AuthenticatedSubject,
    now: i64,
) -> Result<VerifiedEntitlement, AccessError> {
    let envelope: Envelope<LicenceBody> = parse(input)?;
    authenticate(&envelope, content.manifest().signer())?;
    let b = &envelope.body;
    let common = Common {
        owner_agent: &b.owner_agent,
        listener_agent: &b.listener_agent,
        file_id: &b.file_id,
        manifest_sha256: &b.manifest_sha256,
        recipient_key_hex: &b.recipient_key_hex,
        ephemeral_key_hex: &b.ephemeral_key_hex,
        salt_b64: &b.salt_b64,
        nonce_b64: &b.nonce_b64,
        wrapped_key_b64: &b.wrapped_key_b64,
    };
    let ephemeral = check_scope(&common, content, subject)?;
    // Deliberately no expiry: offline use must not depend on a correct clock
    // beyond "not issued in the future" (Music's licence semantics).
    let issued_at = timestamp(&b.issued_at)?;
    if i128::from(issued_at) > i128::from(now) + i128::from(CLOCK_SKEW_SECONDS) {
        return Err(AccessError::Validity(Validity::NotYetValid));
    }
    if b.terms != MUSIC_PERSONAL_USE_TERMS {
        return Err(AccessError::Unsupported(Unsupported::LicenceTerms));
    }
    lower_hex::<16>(&b.licence_id).ok_or(AccessError::Malformed(Malformed::LicenceId))?;
    let context = context(
        LICENCE_CONTEXT_PREFIX,
        json!({
            "schema": b.schema, "owner_agent": b.owner_agent,
            "listener_agent": b.listener_agent, "file_id": b.file_id,
            "manifest_sha256": b.manifest_sha256,
            "recipient_key_hex": b.recipient_key_hex,
            "issued_at": b.issued_at, "licence_id": b.licence_id, "terms": b.terms,
        }),
    )?;
    let key = key_envelope(&common, ephemeral, context)?;
    Ok(VerifiedEntitlement {
        scheme: EntitlementScheme::MusicPersonalLicenceV1,
        granted_rights: Rights::STREAM
            .union(Rights::MANAGED_OFFLINE)
            .union(Rights::EXPORT),
        owner_agent: content.owner_agent().to_owned(),
        listener_agent: subject.listener_agent().to_owned(),
        recipient_key: *subject.recipient_key(),
        package_id: content.manifest().package_id(),
        manifest_digest: content.manifest().digest(),
        issued_at,
        expires_at: None,
        licence_id: Some(b.licence_id.clone()),
        key,
        owner_assurance: content.owner_assurance(),
    })
}

/// Verify an untrusted entitlement document for `subject` and `content` at
/// `now`, without evaluating a particular right.
///
/// Safe on arbitrary bytes: input size is capped before parsing, the
/// canonical envelope before signature verification, and every field is
/// type- and length-checked. Performs no I/O and no Holochain calls.
pub fn verify_entitlement(
    content: &OwnedManifest,
    subject: &AuthenticatedSubject,
    entitlement: &[u8],
    now: SystemTime,
) -> Result<VerifiedEntitlement, AccessError> {
    if entitlement.len() > MAX_GRANT_INPUT_BYTES {
        return Err(AccessError::Malformed(Malformed::TooLarge));
    }
    let now = unix_seconds(now)?;
    let probe: Probe = parse(entitlement)?;
    let schema = probe
        .body
        .schema
        .ok_or(AccessError::Malformed(Malformed::Structure))?;
    match EntitlementScheme::from_schema(&schema).map_err(AccessError::Unsupported)? {
        EntitlementScheme::MusicContentGrantV1 => verify_stream(entitlement, content, subject, now),
        EntitlementScheme::MusicPersonalLicenceV1 => {
            verify_licence(entitlement, content, subject, now)
        }
        EntitlementScheme::MusicAccessGrantV2 => {
            Err(AccessError::Unsupported(Unsupported::RequiresLifecycle))
        }
    }
}

/// Decide whether `subject` may exercise `requested` over `content` under the
/// untrusted `entitlement` document at `now`.
///
/// `content` must come from [`crate::binding::verify_owned_manifest`] (owner
/// identity and key from Holochain), and `subject` from the application's own
/// trusted context. `Ok` is a policy-level authorisation; see the module
/// documentation for what remains to be verified before plaintext access.
pub fn check_content_access(
    content: &OwnedManifest,
    subject: &AuthenticatedSubject,
    entitlement: &[u8],
    requested: Right,
    now: SystemTime,
) -> Result<AccessDecision, AccessError> {
    verify_entitlement(content, subject, entitlement, now)?.authorize(requested)
}

/// [`check_content_access`] that additionally requires the owner's key
/// binding to be at least `required` (use
/// [`BindingAssurance::ProofOfPossessionV2`] for new security-sensitive
/// operations). The assurance comes from how CORE-004/S2 verified the
/// content, never from the grant or the caller.
pub fn check_content_access_requiring(
    content: &OwnedManifest,
    subject: &AuthenticatedSubject,
    entitlement: &[u8],
    requested: Right,
    now: SystemTime,
    required: BindingAssurance,
) -> Result<AccessDecision, AccessError> {
    if content.owner_assurance() < required {
        return Err(AccessError::Unauthenticated(
            Unauthenticated::InsufficientOwnerAssurance,
        ));
    }
    check_content_access(content, subject, entitlement, requested, now)
}

/// [`check_content_access`] for content whose owner key is governed by an S2
/// v2.1 key lifecycle (`owner` must be the owner's verified `owner-manifest`
/// lifecycle from the reader's trusted conductor).
///
/// Music S10 binds the grant issuer to the manifest signer, so the issuer is
/// that key. A grant/licence carries no chain anchor, so the issuer key is
/// evaluated as unanchored historical use: an active, rotated or
/// `new-operations`-revoked key is accepted (existing licences survive
/// rotation), a `compromised` key is refused. Whether a *new* grant may be
/// issued is decided by the issuer (Music issues only with the active key);
/// a verifier cannot tell issuance time from an untrusted `issued_at`.
pub fn check_content_access_with_lifecycle(
    content: &OwnedManifest,
    subject: &AuthenticatedSubject,
    entitlement: &[u8],
    requested: Right,
    now: SystemTime,
    owner: &KeyLifecycle,
) -> Result<AccessDecision, AccessError> {
    if owner.agent() != content.owner_agent() || owner.purpose() != KeyPurpose::OwnerManifest {
        return Err(AccessError::Unauthenticated(
            Unauthenticated::IssuerNotInLifecycle,
        ));
    }
    match owner.classify(
        content.manifest().signer(),
        &KeyUse::Historical { anchor: None },
    ) {
        KeyValidity::Active | KeyValidity::HistoricalOnly => {}
        KeyValidity::Revoked => {
            return Err(AccessError::Unauthenticated(
                Unauthenticated::IssuerKeyRevoked,
            ))
        }
        KeyValidity::Rotated | KeyValidity::Ambiguous | KeyValidity::Invalid => {
            return Err(AccessError::Unauthenticated(
                Unauthenticated::IssuerNotInLifecycle,
            ))
        }
    }
    check_content_access(content, subject, entitlement, requested, now)
}
