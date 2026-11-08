//! Tests against fixtures generated at runtime from Music's pinned Python S1
//! code. The Rust verifier never creates signatures to test itself.

use crate::compat::{
    verify_music_ciphertext, verify_music_manifest, verify_music_receipt, VerifyError,
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
    serde_json::to_vec(v).unwrap()
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


#[test]
fn verified_cas_replicates_real_python_music_ciphertext() {
    use crate::storage::{VerifiedCas, WriteOutcome};
    let v = vectors();
    let artist = key(v["artist_public_key"].as_str().unwrap());
    let manifest = verify_music_manifest(&json_bytes(&v["package"]), &artist).unwrap();
    let temp = tempfile::tempdir().unwrap();
    let origin = VerifiedCas::new(temp.path().join("origin")).unwrap();
    let replica = VerifiedCas::new(temp.path().join("replica")).unwrap();
    assert_eq!(replica.audit(&manifest).unwrap().missing, manifest.chunks.len());

    for (index, fixture) in v["chunks"].as_array().unwrap().iter().enumerate() {
        let ciphertext = STANDARD.decode(fixture["ciphertext_b64"].as_str().unwrap()).unwrap();
        assert_eq!(origin.put_chunk(&manifest, index, &ciphertext).unwrap(), WriteOutcome::Created);
        assert_eq!(origin.put_chunk(&manifest, index, &ciphertext).unwrap(), WriteOutcome::AlreadyVerified);
        assert_eq!(origin.read_chunk(&manifest, index).unwrap(), ciphertext);
        let mut invalid = ciphertext.clone();
        invalid[0] ^= 1;
        assert!(matches!(origin.put_chunk(&manifest, index, &invalid), Err(crate::storage::StoreError::InvalidChunk)));
    }
    let result = replica.sync_from(&manifest, &[&origin]).unwrap();
    assert_eq!(result.downloaded, manifest.chunks.len());
    assert_eq!(result.repaired, 0);
    assert_eq!(replica.audit(&manifest).unwrap().verified, manifest.chunks.len());
    let repeat = replica.sync_from(&manifest, &[&origin]).unwrap();
    assert_eq!(repeat.already_verified, manifest.chunks.len());
    assert_eq!(repeat.downloaded, 0);
}

#[test]
fn verified_cas_resumes_partial_transfer_after_host_unavailability() {
    use crate::storage::{StoreError, VerifiedCas};
    let v = vectors();
    let artist = key(v["artist_public_key"].as_str().unwrap());
    let manifest = verify_music_manifest(&json_bytes(&v["package"]), &artist).unwrap();
    assert!(manifest.chunks.len() > 3);
    let tmp = tempfile::tempdir().unwrap();
    let first = VerifiedCas::new(tmp.path().join("first")).unwrap();
    let second = VerifiedCas::new(tmp.path().join("second")).unwrap();
    let target = VerifiedCas::new(tmp.path().join("target")).unwrap();
    for (i, fixture) in v["chunks"].as_array().unwrap().iter().enumerate() {
        let bytes = STANDARD.decode(fixture["ciphertext_b64"].as_str().unwrap()).unwrap();
        if i == 0 { first.put_chunk(&manifest, i, &bytes).unwrap(); }
        else { second.put_chunk(&manifest, i, &bytes).unwrap(); }
    }
    let failure = target.sync_from(&manifest, &[&first]).unwrap_err();
    assert_eq!(failure.failed_index, 1);
    assert_eq!(failure.progress.downloaded, 1);
    assert!(matches!(failure.source, StoreError::NoHealthySource));
    assert_eq!(target.audit(&manifest).unwrap().verified, 1);
    let restart = VerifiedCas::new(tmp.path().join("target")).unwrap();
    let report = restart.sync_from(&manifest, &[&first, &second]).unwrap();
    assert_eq!(report.already_verified, 1);
    assert_eq!(report.downloaded, manifest.chunks.len() - 1);
    assert_eq!(restart.audit(&manifest).unwrap().verified, manifest.chunks.len());
}

#[test]
fn verified_cas_detects_corruption_and_repairs_only_from_verified_source() {
    use crate::storage::{StoreError, VerifiedCas};
    let v = vectors();
    let artist = key(v["artist_public_key"].as_str().unwrap());
    let manifest = verify_music_manifest(&json_bytes(&v["package"]), &artist).unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let first = VerifiedCas::new(tmp.path().join("first")).unwrap();
    let second = VerifiedCas::new(tmp.path().join("second")).unwrap();
    for (i, fixture) in v["chunks"].as_array().unwrap().iter().enumerate() {
        let bytes = STANDARD.decode(fixture["ciphertext_b64"].as_str().unwrap()).unwrap();
        first.put_chunk(&manifest, i, &bytes).unwrap();
    }
    second.sync_from(&manifest, &[&first]).unwrap();
    let digest = manifest.chunks[0].ciphertext_sha256.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let filename = tmp.path().join("second").join("objects").join("sha256").join(&digest[..2]).join(&digest);
    std::fs::write(&filename, b"garbage").unwrap();
    assert!(matches!(second.read_chunk(&manifest, 0), Err(StoreError::Corrupt)));
    assert_eq!(second.audit(&manifest).unwrap().corrupt, 1);
    let authentic = first.read_chunk(&manifest, 0).unwrap();
    assert!(matches!(second.put_chunk(&manifest, 0, &authentic), Err(StoreError::Corrupt)));
    let report = second.sync_from(&manifest, &[&first]).unwrap();
    assert_eq!(report.repaired, 1);
    assert_eq!(report.already_verified, manifest.chunks.len() - 1);
    assert_eq!(second.read_chunk(&manifest, 0).unwrap(), authentic);
}

#[test]
fn verified_cas_empty_package_is_noop() {
    use crate::storage::VerifiedCas;
    let v = vectors();
    let artist = key(v["artist_public_key"].as_str().unwrap());
    let manifest = verify_music_manifest(&json_bytes(&v["empty_package"]), &artist).unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let store = VerifiedCas::new(tmp.path()).unwrap();
    let result = store.sync_from(&manifest, &[]).unwrap();
    assert_eq!(result.downloaded, 0);
    assert_eq!(store.audit(&manifest).unwrap().missing, 0);
}

#[cfg(unix)]
#[test]
fn verified_cas_refuses_symlinked_objects_and_root() {
    use crate::storage::{StoreError, VerifiedCas};
    use std::os::unix::fs::symlink;
    let v = vectors();
    let artist = key(v["artist_public_key"].as_str().unwrap());
    let manifest = verify_music_manifest(&json_bytes(&v["package"]), &artist).unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let real = tmp.path().join("real");
    let store = VerifiedCas::new(&real).unwrap();
    let linked_root = tmp.path().join("link");
    symlink(&real, &linked_root).unwrap();
    assert!(matches!(VerifiedCas::new(&linked_root), Err(StoreError::UnsafePath)));
    let first = STANDARD.decode(v["chunks"][0]["ciphertext_b64"].as_str().unwrap()).unwrap();
    store.put_chunk(&manifest, 0, &first).unwrap();
    let digest = manifest.chunks[0].ciphertext_sha256.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let obj = real.join("objects").join("sha256").join(&digest[..2]).join(&digest);
    std::fs::remove_file(&obj).unwrap();
    symlink(tmp.path().join("outside.txt"), &obj).unwrap();
    assert!(matches!(store.read_chunk(&manifest, 0), Err(StoreError::UnsafePath)));
    assert!(matches!(store.put_chunk(&manifest, 0, &first), Err(StoreError::UnsafePath)));
    assert!(matches!(store.sync_from(&manifest, &[]), Err(crate::storage::SyncFailure { source: StoreError::UnsafePath, .. })));
}

#[test]
fn verified_cas_concurrent_puts_preserve_verified_data() {
    use crate::storage::{VerifiedCas, WriteOutcome};
    let v = vectors();
    let artist = key(v["artist_public_key"].as_str().unwrap());
    let manifest = verify_music_manifest(&json_bytes(&v["package"]), &artist).unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let store = VerifiedCas::new(tmp.path()).unwrap();
    let bytes = STANDARD.decode(v["chunks"][0]["ciphertext_b64"].as_str().unwrap()).unwrap();
    let results: Vec<_> = (0..8).map(|_| {
        let store = store.clone();
        let manifest = manifest.clone();
        let bytes = bytes.clone();
        std::thread::spawn(move || store.put_chunk(&manifest, 0, &bytes))
    }).map(|task| task.join().unwrap().unwrap()).collect();
    assert!(results.iter().any(|r| *r == WriteOutcome::Created));
    assert!(results.iter().all(|r| *r == WriteOutcome::Created || *r == WriteOutcome::AlreadyVerified));
    assert_eq!(store.read_chunk(&manifest, 0).unwrap(), bytes);
}
