//! Minimal, file-type-independent identifiers and rights declarations.
//!
//! This CORE-001 crate does not perform cryptographic verification or
//! authorisation. Applications must not grant access based on a parsed
//! identifier, a schema tag, or a rights bitset alone.

#![forbid(unsafe_code)]

use std::{error::Error, fmt, str::FromStr};

/// Legacy Music S1 encrypted-package schema, used for compatibility work.
pub const MUSIC_PACKAGE_V1: &str = "holochain-storage/encrypted-package/v1";
/// Legacy Music S1 signed replica-receipt schema.
pub const MUSIC_RECEIPT_V1: &str = "holochain-storage/replica-receipt/v1";

/// A randomly generated package identifier (32 bytes in Music S1).
///
/// A package ID is not a content hash, a signature or proof of ownership.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PackageId([u8; 32]);

/// SHA-256 of the complete canonical *signed* manifest envelope.
///
/// Construction from bytes does not compute or verify the digest.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ManifestDigest([u8; 32]);

/// Error parsing a lowercase, 32-byte hexadecimal identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentifierError {
    /// The string does not contain exactly 64 ASCII characters.
    WrongLength,
    /// Only lowercase ASCII hexadecimal is accepted.
    NonCanonicalHex,
}

impl fmt::Display for IdentifierError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongLength => f.write_str("expected 64 ASCII hexadecimal characters"),
            Self::NonCanonicalHex => f.write_str("expected lowercase ASCII hexadecimal"),
        }
    }
}

impl Error for IdentifierError {}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn parse_hex32(value: &str) -> Result<[u8; 32], IdentifierError> {
    if value.len() != 64 {
        return Err(IdentifierError::WrongLength);
    }
    let mut decoded = [0u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let hi = hex_nibble(pair[0]).ok_or(IdentifierError::NonCanonicalHex)?;
        let lo = hex_nibble(pair[1]).ok_or(IdentifierError::NonCanonicalHex)?;
        decoded[index] = (hi << 4) | lo;
    }
    Ok(decoded)
}

fn encode_hex32(bytes: &[u8; 32]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut value = String::with_capacity(64);
    for byte in bytes {
        value.push(char::from(DIGITS[(byte >> 4) as usize]));
        value.push(char::from(DIGITS[(byte & 0x0f) as usize]));
    }
    value
}

impl PackageId {
    /// Returns the raw opaque package identifier.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Constructs an identifier from already validated opaque bytes.
    ///
    /// Callers remain responsible for generating unpredictable IDs.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl ManifestDigest {
    /// Returns digest bytes without asserting their cryptographic correctness.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Wraps a digest produced by a separately trusted hashing implementation.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl FromStr for PackageId {
    type Err = IdentifierError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse_hex32(s).map(Self)
    }
}

impl FromStr for ManifestDigest {
    type Err = IdentifierError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse_hex32(s).map(Self)
    }
}

impl fmt::Display for PackageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&encode_hex32(&self.0))
    }
}

impl fmt::Display for ManifestDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&encode_hex32(&self.0))
    }
}

/// An explicit content-use permission, never proof of an entitlement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Right {
    /// Playback through a managed stream.
    Stream,
    /// Retention inside a managed offline application cache.
    ManagedOffline,
    /// Independent plaintext export when the verified licence permits it.
    Export,
}

impl Right {
    const fn flag(self) -> u8 {
        match self {
            Self::Stream => 0b001,
            Self::ManagedOffline => 0b010,
            Self::Export => 0b100,
        }
    }
}

/// A typed declaration of requested or granted rights.
///
/// No bit authorises anything by itself: verify issuer, subject, manifest,
/// signature, licence dates, and applicable policy before using a declaration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Rights(u8);

impl Rights {
    /// Empty rights.
    pub const NONE: Self = Self(0);
    /// Stream declaration.
    pub const STREAM: Self = Self(0b001);
    /// Managed offline declaration.
    pub const MANAGED_OFFLINE: Self = Self(0b010);
    /// Independent export declaration.
    pub const EXPORT: Self = Self(0b100);

    /// Reject unknown bits rather than silently accepting future permissions.
    pub const fn from_bits(bits: u8) -> Option<Self> {
        if bits & !0b111 == 0 {
            Some(Self(bits))
        } else {
            None
        }
    }

    /// Returns the stable flag representation; only meaningful within this API.
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// Combines declarations; this does not validate a licence.
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Checks whether a declaration includes a specific requested right.
    pub const fn contains(self, right: Right) -> bool {
        (self.0 & right.flag()) != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_package_id() {
        let original: PackageId = "ab".repeat(32).parse().unwrap();
        assert_eq!(original.to_string(), "ab".repeat(32));
        assert_eq!(original.as_bytes(), &[0xab; 32]);
    }

    #[test]
    fn round_trip_manifest_digest() {
        let digest = ManifestDigest::from_bytes([0xff; 32]);
        assert_eq!(digest.to_string(), "ff".repeat(32));
        assert_eq!(
            digest.to_string().parse::<ManifestDigest>().unwrap(),
            digest
        );
    }

    #[test]
    fn package_ids_are_distinct_types_from_manifest_digests() {
        let id = PackageId::from_bytes([0x12; 32]);
        let digest = ManifestDigest::from_bytes([0x12; 32]);
        assert_eq!(id.as_bytes(), digest.as_bytes());
        // Conversions are intentionally explicit rather than implicit.
    }

    #[test]
    fn identifier_length_is_strict() {
        assert_eq!("12".parse::<PackageId>(), Err(IdentifierError::WrongLength));
        assert_eq!(
            "00".repeat(33).parse::<ManifestDigest>(),
            Err(IdentifierError::WrongLength)
        );
    }

    #[test]
    fn identifier_hex_is_canonical() {
        assert_eq!(
            "AA".repeat(32).parse::<PackageId>(),
            Err(IdentifierError::NonCanonicalHex)
        );
        assert_eq!(
            "xz".repeat(32).parse::<ManifestDigest>(),
            Err(IdentifierError::NonCanonicalHex)
        );
        assert_eq!(
            "é".repeat(32).parse::<PackageId>(),
            Err(IdentifierError::NonCanonicalHex)
        );
    }

    #[test]
    fn rights_are_explicit_and_composable() {
        let rights = Rights::STREAM.union(Rights::MANAGED_OFFLINE);
        assert!(rights.contains(Right::Stream));
        assert!(rights.contains(Right::ManagedOffline));
        assert!(!rights.contains(Right::Export));
        assert_eq!(rights.bits(), 0b011);
    }

    #[test]
    fn unknown_rights_fail_closed() {
        assert_eq!(Rights::from_bits(0b1000), None);
        assert_eq!(Rights::from_bits(0xff), None);
        assert_eq!(Rights::from_bits(0b111).unwrap().bits(), 0b111);
    }
}

/// Read-only compatibility with the existing Python Music S1 signed format.
pub mod compat;

#[cfg(all(test, feature = "music-interop-tests"))]
mod compat_tests;

/// Verified, bounded ciphertext content-addressed storage (CORE-003).
pub mod storage;
