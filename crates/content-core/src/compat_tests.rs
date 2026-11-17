//! Tests against fixtures generated at runtime from Music's pinned Python S1
//! code. The Rust verifier never creates signatures to test itself.

use crate::compat::{
    canonical_json, verify_music_ciphertext, verify_music_manifest, verify_music_receipt,
    VerifyError,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::{json, Value};

fn vectors() -> Value {
    let path = std::env::var("MUSIC_VECTORS")
        .expect("set MUSIC_VECTORS to the independent Python Music S1 fixture path");
    let path = std::path::PathBuf::from(path);
    let path = if path.is_absolute() {
        path
    } else {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(path)
    };
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

fn key(b64: &str) -> [u8; 32] {
    let decoded = STANDARD.decode(b64).unwrap();
    decoded.try_into().unwrap()
}

fn json_bytes(v: &Value) -> Vec<u8> {
    canonical_json(v).unwrap()
}

#[test]
fn canonical_s1_json_is_sorted_with_or_without_preserve_order() {
    let unsorted =
        serde_json::from_str::<Value>(r#"{"z":2,"a":{"y":[1,"text"],"b":0},"A":3}"#).unwrap();
    assert_eq!(
        canonical_json(&unsorted).unwrap(),
        br#"{"A":3,"a":{"b":0,"y":[1,"text"]},"z":2}"#
    );
    assert!(canonical_json(&json!({"non_s1_float": 1.5})).is_none());
}

#[test]
fn package_canonical_json_matches_original_python_byte_for_byte() {
    let v = vectors();
    assert_eq!(
        json_bytes(&v["package"]["body"]),
        STANDARD
            .decode(v["canonical_body_b64"].as_str().unwrap())
            .unwrap()
    );
    assert_eq!(
        json_bytes(&v["package"]),
        STANDARD
            .decode(v["canonical_envelope_b64"].as_str().unwrap())
            .unwrap()
    );
}

#[test]
fn signed_nonempty_music_s1_package_and_chunks() {
    let v = vectors();
    let artist = key(v["artist_public_key"].as_str().unwrap());
    let verified = verify_music_manifest(&json_bytes(&v["package"]), &artist).unwrap();
    assert_eq!(
        verified.digest.to_string(),
        v["manifest_sha256"].as_str().unwrap()
    );
    assert_eq!(
        verified.total_plain_bytes,
        v["plaintext_bytes"].as_u64().unwrap()
    );
    assert_eq!(verified.chunks.len(), v["chunks"].as_array().unwrap().len());
    for c in v["chunks"].as_array().unwrap() {
        let index = c["index"].as_u64().unwrap() as usize;
        let ciphertext = STANDARD
            .decode(c["ciphertext_b64"].as_str().unwrap())
            .unwrap();
        verify_music_ciphertext(&verified, index, &ciphertext).unwrap();
        let mut tampered = ciphertext.clone();
        tampered[0] ^= 1;
        assert_eq!(
            verify_music_ciphertext(&verified, index, &tampered),
            Err(VerifyError::InvalidCiphertext)
        );
        assert_eq!(
            verify_music_ciphertext(&verified, index, &ciphertext[..ciphertext.len() - 1]),
            Err(VerifyError::InvalidCiphertext)
        );
    }
    assert_eq!(
        verify_music_ciphertext(&verified, verified.chunks.len(), b""),
        Err(VerifyError::InvalidCiphertext)
    );
}

#[test]
fn separately_signed_receipt_matches_exact_package_and_expected_host() {
    let v = vectors();
    let artist = key(v["artist_public_key"].as_str().unwrap());
    let host = key(v["host_public_key"].as_str().unwrap());
    let verified = verify_music_manifest(&json_bytes(&v["package"]), &artist).unwrap();
    let receipt = verify_music_receipt(&json_bytes(&v["receipt"]), &verified, &host).unwrap();
    assert_eq!(receipt.manifest_digest, verified.digest);
    assert_eq!(receipt.chunk_count, verified.chunks.len() as u64);
    assert_eq!(receipt.signer, host);
    assert_eq!(
        verify_music_receipt(&json_bytes(&v["receipt"]), &verified, &[88; 32]),
        Err(VerifyError::WrongSigner)
    );
}

#[test]
fn signed_empty_music_package_is_compatible() {
    let v = vectors();
    let artist = key(v["artist_public_key"].as_str().unwrap());
    let verified = verify_music_manifest(&json_bytes(&v["empty_package"]), &artist).unwrap();
    assert!(verified.chunks.is_empty());
    assert_eq!(verified.total_plain_bytes, 0);
    assert_eq!(
        verified.digest.to_string(),
        v["empty_manifest_sha256"].as_str().unwrap()
    );
}

#[test]
fn source_authenticated_invalid_manifests_are_rejected() {
    let v = vectors();
    let artist = key(v["artist_public_key"].as_str().unwrap());
    for (name, body) in v["signed_invalid"].as_object().unwrap() {
        if name.starts_with("receipt") {
            continue;
        }
        assert_eq!(
            verify_music_manifest(&json_bytes(body), &artist),
            Err(VerifyError::InvalidManifest),
            "case: {name}"
        );
    }
}

#[test]
fn source_authenticated_receipt_for_other_package_is_rejected() {
    let v = vectors();
    let artist = key(v["artist_public_key"].as_str().unwrap());
    let host = key(v["host_public_key"].as_str().unwrap());
    let verified = verify_music_manifest(&json_bytes(&v["package"]), &artist).unwrap();
    assert_eq!(
        verify_music_receipt(
            &json_bytes(&v["signed_invalid"]["receipt_wrong_package"]),
            &verified,
            &host
        ),
        Err(VerifyError::InvalidReceipt)
    );
}

#[test]
fn tampering_with_signature_and_expected_identity_is_rejected() {
    let v = vectors();
    let artist = key(v["artist_public_key"].as_str().unwrap());
    let mut modified = v["package"].clone();
    modified["body"]["chunk_size"] = json!(2);
    assert_eq!(
        verify_music_manifest(&json_bytes(&modified), &artist),
        Err(VerifyError::InvalidSignature)
    );
    assert_eq!(
        verify_music_manifest(&json_bytes(&v["package"]), &[88; 32]),
        Err(VerifyError::WrongSigner)
    );
    modified = v["package"].clone();
    modified["signature"] = json!("not-base64");
    assert_eq!(
        verify_music_manifest(&json_bytes(&modified), &artist),
        Err(VerifyError::InvalidManifest)
    );
}

#[test]
fn duplicate_json_fields_at_top_and_nested_level_are_rejected() {
    let v = vectors();
    let artist = key(v["artist_public_key"].as_str().unwrap());
    let original = String::from_utf8(json_bytes(&v["package"])).unwrap();
    let duplicate_signer =
        original.replacen("\"signer\":", "\"signer\":\"not-trusted\",\"signer\":", 1);
    assert_ne!(original, duplicate_signer);
    assert_eq!(
        verify_music_manifest(duplicate_signer.as_bytes(), &artist),
        Err(VerifyError::InvalidJson)
    );
    let duplicate_chunk_size =
        original.replacen("\"chunk_size\":", "\"chunk_size\":16,\"chunk_size\":", 1);
    assert_ne!(original, duplicate_chunk_size);
    assert_eq!(
        verify_music_manifest(duplicate_chunk_size.as_bytes(), &artist),
        Err(VerifyError::InvalidJson)
    );
}

#[test]
fn unsupported_objects_types_and_oversized_input_fail_closed() {
    let v = vectors();
    let artist = key(v["artist_public_key"].as_str().unwrap());
    let mut modified = v["package"].clone();
    modified["body"]["unknown"] = json!(123);
    assert_eq!(
        verify_music_manifest(&json_bytes(&modified), &artist),
        Err(VerifyError::InvalidJson)
    );
    modified = v["package"].clone();
    modified["body"]["chunk_size"] = json!(true);
    assert_eq!(
        verify_music_manifest(&json_bytes(&modified), &artist),
        Err(VerifyError::InvalidJson)
    );
    modified = v["package"].clone();
    modified["body"]["chunks"][0]["index"] = json!(-1);
    assert_eq!(
        verify_music_manifest(&json_bytes(&modified), &artist),
        Err(VerifyError::InvalidJson)
    );
    let too_long = vec![b' '; 8 * 1024 * 1024 + 1025];
    assert_eq!(
        verify_music_manifest(&too_long, &artist),
        Err(VerifyError::TooLarge)
    );
}
