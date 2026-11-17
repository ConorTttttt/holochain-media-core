//! Opt-in, lifecycle-anchored Music access-grant/v2 (ACCESS-GRANT-V2.md).
//!
//! The caller first authenticates S1 content using
//! binding::verify_owned_manifest_lifecycle(manifest_bytes, lifecycle, commitment).
//! This module independently verifies the new grant's *issuer* generation,
//! signature, scope, anchor commitment and chain ordering. An anchor alone is
//! never authority. Content keys are not available to this crate.

use crate::binding::{
    verify_owned_manifest_lifecycle, BindingError, ConductorRecord, KeyPurpose, VerifiedKeyBinding,
};
use crate::compat::canonical_json;
use crate::entitlements::{
    AccessDecision, AccessError, AuthenticatedSubject, EntitlementScheme, VerifiedEntitlement,
    WrappedContentKey, CLOCK_SKEW_SECONDS, MAX_GRANT_BYTES, MAX_GRANT_INPUT_BYTES,
    MUSIC_ACCESS_GRANT_V2,
};
use crate::grant_anchor::{
    verify_grant_anchor_v2, GrantAnchorClaim, RecoveredIssuerPolicy, VerifiedGrantAnchor,
};
use crate::lifecycle::{parse_generation, KeyLifecycle};
use crate::{Right, Rights};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::{SystemTime, UNIX_EPOCH};

pub const GRANT_SIGNATURE_DOMAIN: &[u8] = b"holochain-music/access-grant/v2\0";
pub const GRANT_KEY_WRAP_DOMAIN: &[u8] = b"holochain-music/access-grant/hkdf-aad/v2\0";
pub const KEY_WRAP_V2: &str = "x25519-hkdf-sha256-aes256gcm/v2";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum V2Error {
    Malformed(&'static str),
    Unsupported(&'static str),
    Denied(&'static str),
    Unauthenticated(&'static str),
    Validity(&'static str),
    Unavailable(&'static str),
}
impl V2Error {
    pub const fn category(self) -> &'static str {
        match self {
            Self::Malformed(_) => "malformed",
            Self::Unsupported(_) => "unsupported",
            Self::Denied(_) => "denied",
            Self::Unauthenticated(_) => "unauthenticated",
            Self::Validity(_) => "validity",
            Self::Unavailable(_) => "unavailable",
        }
    }
    pub const fn reason(self) -> &'static str {
        match self {
            Self::Malformed(r) | Self::Unsupported(r) | Self::Denied(r) |
            Self::Unauthenticated(r) | Self::Validity(r) | Self::Unavailable(r) => r,
        }
    }
}
impl std::fmt::Display for V2Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.category(), self.reason())
    }
}
impl std::error::Error for V2Error {}

/// Exactly the signed fields from §3.1. serde rejects unknown and duplicate
/// keys, including a v1 envelope; Value timestamps reject floats and booleans.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantBodyV2 {
    schema: String,
    grant_id: String,
    dna_hash: String,
    owner_agent: String,
    issuer_agent: String,
    issuer_purpose: String,
    issuer_key_hex: String,
    issuer_key_generation: String,
    issuer_key_action: String,
    file_id: String,
    manifest_sha256: String,
    manifest_key_hex: String,
    listener_agent: String,
    recipient_key_hex: String,
    rights: Vec<String>,
    term: String,
    issued_at: Value,
    not_before: Value,
    expires_at: Value,
    basis: String,
    entitlement_ref: String,
    key_wrap: String,
    ephemeral_key_hex: String,
    salt_b64: String,
    nonce_b64: String,
    wrapped_key_b64: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EnvelopeV2 {
    body: GrantBodyV2,
    signature_hex: String,
}

fn hex<const N: usize>(value: &str) -> Option<[u8; N]> {
    if value.len() != 2 * N { return None; }
    let nibble = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    let mut out = [0u8; N];
    for (i, p) in value.as_bytes().chunks_exact(2).enumerate() {
        out[i] = (nibble(p[0])? << 4) | nibble(p[1])?;
    }
    Some(out)
}
fn b64<const N: usize>(value: &str) -> Option<[u8; N]> {
    let decoded = B64.decode(value).ok()?;
    if B64.encode(&decoded) != value { return None; }
    decoded.try_into().ok()
}
fn identifier(value: &str) -> bool {
    !value.is_empty() && value.len() <= 160 && !value.contains('\0')
}
fn json_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, V2Error> {
    let value = serde_json::to_value(value).map_err(|_| V2Error::Malformed("Structure"))?;
    canonical_json(&value).ok_or(V2Error::Malformed("NonCanonicalNumber"))
}

/// Byte-exact domain-separated Ed25519 signed message and anchor input.
pub fn grant_message(body: &GrantBodyV2) -> Result<Vec<u8>, V2Error> {
    let mut out = GRANT_SIGNATURE_DOMAIN.to_vec();
    out.extend(json_bytes(body)?);
    Ok(out)
}
/// Recipient's HKDF info AND AES-GCM AAD; no private or plaintext key here.
pub fn grant_wrap_context(body: &GrantBodyV2) -> Result<Vec<u8>, V2Error> {
    let mut scope = serde_json::to_value(body)
        .map_err(|_| V2Error::Malformed("Structure"))?;
    let Value::Object(ref mut fields) = scope else {
        return Err(V2Error::Malformed("Structure"));
    };
    for field in ["ephemeral_key_hex", "salt_b64", "nonce_b64", "wrapped_key_b64"] {
        fields.remove(field);
    }
    let mut out = GRANT_KEY_WRAP_DOMAIN.to_vec();
    out.extend(canonical_json(&scope).ok_or(V2Error::Malformed("NonCanonicalNumber"))?);
    Ok(out)
}
fn time(value: &Value) -> Result<i64, V2Error> {
    match value {
        Value::Number(n) => n.as_i64().ok_or(V2Error::Validity("InvalidTimestamp")),
        _ => Err(V2Error::Validity("InvalidTimestamp")),
    }
}
fn clock(now: SystemTime) -> Result<i64, V2Error> {
    let dur = now.duration_since(UNIX_EPOCH).map_err(|_| V2Error::Unavailable("Clock"))?;
    i64::try_from(dur.as_secs()).map_err(|_| V2Error::Unavailable("Clock"))
}
fn rights(b: &GrantBodyV2, now: i64) -> Result<(Rights, Option<i64>), V2Error> {
    let options = ["export", "managed-offline", "stream"];
    if b.rights.is_empty() || b.rights.len() > options.len() ||
        b.rights.windows(2).any(|v| v[0] >= v[1]) ||
        b.rights.iter().any(|v| !options.contains(&v.as_str())) {
        return Err(V2Error::Unsupported("Terms"));
    }
    let mut rights = Rights::NONE;
    for right in &b.rights {
        rights = rights.union(match right.as_str() {
            "export" => Rights::EXPORT,
            "managed-offline" => Rights::MANAGED_OFFLINE,
            "stream" => Rights::STREAM,
            _ => unreachable!(),
        });
    }
    let issued = time(&b.issued_at)?;
    let start = time(&b.not_before)?;
    let end = time(&b.expires_at)?;
    let expiry = match b.term.as_str() {
        "perpetual" => {
            if end != 0 || start != issued ||
                !(rights == Rights::STREAM || rights == Rights::STREAM.union(Rights::MANAGED_OFFLINE).union(Rights::EXPORT)) {
                return Err(V2Error::Unsupported("Terms"));
            }
            None
        }
        "window" => {
            if rights != Rights::STREAM || start >= end ||
                i128::from(end) - i128::from(start) > 86_400 {
                return Err(V2Error::Unsupported("Terms"));
            }
            Some(end)
        }
        _ => return Err(V2Error::Unsupported("Terms")),
    };
    if i128::from(issued) > i128::from(now) + i128::from(CLOCK_SKEW_SECONDS) {
        return Err(V2Error::Validity("NotYetValid"));
    }
    if let Some(end) = expiry {
        if now < start { return Err(V2Error::Validity("NotYetValid")); }
        if now >= end { return Err(V2Error::Validity("Expired")); }
    }
    Ok((rights, expiry))
}

fn anchor_failure(err: BindingError) -> V2Error {
    match err {
        BindingError::KeyRotated => V2Error::Unauthenticated("KeyRotated"),
        BindingError::KeyRevoked => V2Error::Unauthenticated("KeyRevoked"),
        BindingError::RecoveredIssuerRefused => V2Error::Unauthenticated("RecoveredIssuerRefused"),
        BindingError::GrantAnchorMismatch | BindingError::AuthorMismatch | BindingError::WrongDna =>
            V2Error::Unauthenticated("AnchorMismatch"),
        BindingError::MissingRecord => V2Error::Unavailable("AnchorNotFound"),
        _ => V2Error::Unauthenticated("InvalidAnchor"),
    }
}

/// Verified, signed, authorised v2 grant. The only constructor performs the
/// complete lifecycle + signature + anchor check. Cannot be minted from JSON.
#[derive(Clone, Debug)]
pub struct VerifiedAccessGrantV2 {
    entitlement: VerifiedEntitlement,
    issuer: VerifiedKeyBinding,
    anchor: VerifiedGrantAnchor,
    grant_id: String,
}
impl VerifiedAccessGrantV2 {
    pub fn entitlement(&self) -> &VerifiedEntitlement { &self.entitlement }
    pub fn issuer(&self) -> &VerifiedKeyBinding { &self.issuer }
    pub fn anchor(&self) -> &VerifiedGrantAnchor { &self.anchor }
    pub fn grant_id(&self) -> &str { &self.grant_id }
    pub fn authorize(self, requested: Right) -> Result<AccessDecision, AccessError> {
        self.entitlement.authorize(requested)
    }
}

/// The caller must supply raw S1 bytes and the original file commitment,
/// plus a validated owner lifecycle and grant anchor from the SAME DNA.
/// This function itself invokes verify_owned_manifest_lifecycle: a caller
/// cannot substitute a legacy-v1 OwnedManifest to bypass historical checks.
/// For absent anchors, return AnchorNotFound; never accept without one.
/// A valid grant is returned only after all tests, in §5 B ordering.
pub fn verify_access_grant_v2(
    manifest_json: &[u8],
    commitment: &ConductorRecord,
    subject: &AuthenticatedSubject,
    grant_json: &[u8],
    owner: &KeyLifecycle,
    anchor: Option<&ConductorRecord>,
    now: SystemTime,
    recovered_policy: RecoveredIssuerPolicy,
) -> Result<VerifiedAccessGrantV2, V2Error> {
    // Content authenticity uses its historical signer at the ORIGINAL
    // on-chain commitment. Grant authority is verified separately below.
    let content = verify_owned_manifest_lifecycle(manifest_json, owner, commitment)
        .map_err(|err| match err {
            BindingError::CommitmentMismatch => V2Error::Denied("ManifestMismatch"),
            BindingError::MissingRecord => V2Error::Unavailable("CommitmentNotFound"),
            _ => V2Error::Unauthenticated("InvalidHistoricalKey"),
        })?;
    if grant_json.len() > MAX_GRANT_INPUT_BYTES {
        return Err(V2Error::Malformed("TooLarge"));
    }
    // A v1 grant/licence must not accidentally enter this protocol.
    let top: Value = serde_json::from_slice(grant_json)
        .map_err(|_| V2Error::Malformed("Json"))?;
    if top.get("signer").is_some() || top.get("signature").is_some() {
        return Err(V2Error::Unsupported("WrongVersion"));
    }
    let e: EnvelopeV2 = serde_json::from_slice(grant_json).map_err(|err| {
        if err.is_data() { V2Error::Malformed("Structure") } else { V2Error::Malformed("Json") }
    })?;
    if json_bytes(&e)?.len() > MAX_GRANT_BYTES {
        return Err(V2Error::Malformed("TooLarge"));
    }
    let b = &e.body;
    if b.schema != MUSIC_ACCESS_GRANT_V2 {
        return Err(V2Error::Unsupported("WrongVersion"));
    }
    hex::<64>(&e.signature_hex).ok_or(V2Error::Malformed("Signature"))?;
    hex::<16>(&b.grant_id).ok_or(V2Error::Malformed("grant_id"))?;
    let issuer_key = hex::<32>(&b.issuer_key_hex).ok_or(V2Error::Malformed("issuer_key_hex"))?;
    hex::<32>(&b.file_id).ok_or(V2Error::Malformed("file_id"))?;
    hex::<32>(&b.manifest_sha256).ok_or(V2Error::Malformed("manifest_sha256"))?;
    hex::<32>(&b.manifest_key_hex).ok_or(V2Error::Malformed("manifest_key_hex"))?;
    let recipient = hex::<32>(&b.recipient_key_hex).ok_or(V2Error::Malformed("recipient_key_hex"))?;
    let ephemeral = hex::<32>(&b.ephemeral_key_hex).ok_or(V2Error::Malformed("ephemeral_key_hex"))?;
    if !b.entitlement_ref.is_empty() && hex::<32>(&b.entitlement_ref).is_none() {
        return Err(V2Error::Malformed("entitlement_ref"));
    }
    if ![&b.dna_hash, &b.owner_agent, &b.issuer_agent, &b.issuer_key_action,
         &b.listener_agent].iter().all(|v| identifier(v)) {
        return Err(V2Error::Malformed("Structure"));
    }
    let gen_number = parse_generation(&b.issuer_key_generation)
        .ok_or(V2Error::Malformed("IssuerGeneration"))?;
    if b.issuer_purpose != KeyPurpose::OwnerManifest.as_str() ||
       b.key_wrap != KEY_WRAP_V2 || b.basis != "owner-decision" {
        return Err(V2Error::Unsupported("Terms"));
    }
    if owner.purpose() != KeyPurpose::OwnerManifest || owner.agent() != content.owner_agent() ||
       owner.agent() != b.issuer_agent || owner.agent() != b.owner_agent {
        return Err(V2Error::Denied("OwnerMismatch"));
    }
    if b.dna_hash != owner.dna_hash() {
        return Err(V2Error::Denied("NetworkMismatch"));
    }
    if b.file_id != content.manifest().package_id().to_string() {
        return Err(V2Error::Denied("FileMismatch"));
    }
    if b.manifest_sha256 != content.manifest().digest().to_string() ||
       b.manifest_key_hex != hex_string(content.manifest().signer()) {
        return Err(V2Error::Denied("ManifestMismatch"));
    }
    if b.listener_agent != subject.listener_agent() {
        return Err(V2Error::Denied("ListenerMismatch"));
    }
    if recipient != *subject.recipient_key() {
        return Err(V2Error::Denied("RecipientKeyMismatch"));
    }
    let generation = owner.generation_by_action(&b.issuer_key_action)
        .ok_or(V2Error::Unauthenticated("IssuerNotInLifecycle"))?;
    if gen_number != generation.generation() || issuer_key != *generation.key() {
        return Err(V2Error::Unauthenticated("IssuerGenerationMismatch"));
    }
    let msg = grant_message(b)?;
    VerifyingKey::from_bytes(&issuer_key)
        .map_err(|_| V2Error::Unauthenticated("InvalidSignature"))?
        .verify_strict(
            &msg,
            &Signature::from_bytes(&hex::<64>(&e.signature_hex)
                .ok_or(V2Error::Malformed("Signature"))?),
        ).map_err(|_| V2Error::Unauthenticated("InvalidSignature"))?;
    let anchor = anchor.ok_or(V2Error::Unavailable("AnchorNotFound"))?;
    let claim = GrantAnchorClaim {
        grant_id: &b.grant_id,
        grant_message: &msg,
        issuer_key_action: &b.issuer_key_action,
    };
    let verified = verify_grant_anchor_v2(anchor, owner, &claim, recovered_policy)
        .map_err(anchor_failure)?;
    let issuer = verified.issuer().clone();
    let (granted_rights, expires_at) = rights(b, clock(now)?)?;
    let context = grant_wrap_context(b)?;
    let wrapped = WrappedContentKey {
        ephemeral_public: ephemeral,
        salt: b64::<16>(&b.salt_b64).ok_or(V2Error::Malformed("KeyEnvelope"))?,
        nonce: b64::<12>(&b.nonce_b64).ok_or(V2Error::Malformed("KeyEnvelope"))?,
        wrapped_key: b64::<48>(&b.wrapped_key_b64).ok_or(V2Error::Malformed("KeyEnvelope"))?,
        context,
    };
    let entitlement = VerifiedEntitlement {
        scheme: EntitlementScheme::MusicAccessGrantV2,
        granted_rights,
        owner_agent: content.owner_agent().to_owned(),
        listener_agent: subject.listener_agent().to_owned(),
        recipient_key: *subject.recipient_key(),
        package_id: content.manifest().package_id(),
        manifest_digest: content.manifest().digest(),
        issued_at: time(&b.issued_at)?,
        expires_at,
        licence_id: Some(b.grant_id.clone()),
        key: wrapped,
        // Entitlement owner assurance describes the HISTORICAL authenticated
        // content owner (OwnedManifest), as in CORE-005 and the v2 spec.
        // Current grant issuer assurance remains separately available from
        // VerifiedAccessGrantV2::issuer() and must not overwrite this field.
        owner_assurance: content.owner_assurance(),
    };
    Ok(VerifiedAccessGrantV2 { entitlement, issuer, anchor: verified, grant_id: b.grant_id.clone() })
}

fn hex_string(value: &[u8]) -> String {
    value.iter().map(|b| format!("{b:02x}")).collect()
}

/// Authorisation-only convenience; never unwraps a content key.
pub fn check_content_access_v2(
    manifest_json: &[u8],
    commitment: &ConductorRecord,
    subject: &AuthenticatedSubject,
    grant_json: &[u8],
    owner: &KeyLifecycle,
    anchor: Option<&ConductorRecord>,
    requested: Right,
    now: SystemTime,
    recovered_policy: RecoveredIssuerPolicy,
) -> Result<AccessDecision, V2Error> {
    verify_access_grant_v2(manifest_json, commitment, subject, grant_json, owner, anchor, now, recovered_policy)?
        .authorize(requested)
        .map_err(|_| V2Error::Denied("RightNotGranted"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn domain_separation_and_basic_parse_rejection() {
        assert_ne!(GRANT_SIGNATURE_DOMAIN, GRANT_KEY_WRAP_DOMAIN);
        assert!(GRANT_SIGNATURE_DOMAIN.ends_with(&[0]));
        let fail = serde_json::from_slice::<EnvelopeV2>(
            br#"{"body":{"schema":"holochain-music/content-grant/v1"},"signer":"x","signature":"y"}"#);
        assert!(fail.is_err(), "a v1 envelope must never parse as v2");
        assert_eq!(hex::<16>(&"a".repeat(32)), Some([0xaa; 16]));
        assert!(hex::<16>(&"A".repeat(32)).is_none());
        assert!(b64::<12>("AAAAAAAAAAAAAAAA").is_some());
        assert!(b64::<12>("AAAAAAAAAAAAAAAA=").is_none());
    }
}
