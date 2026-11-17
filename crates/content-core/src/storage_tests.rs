//! Synthetic trusted-metadata tests for platform-specific filesystem handling.
//! They do not test signatures; Python Music-generated signed vectors are
//! independently exercised by compat_tests in the CI interop job.

use crate::compat::{ChunkMetadata, VerifiedManifest};
use crate::storage::{StoreError, VerifiedCas, WriteOutcome};
use crate::{ManifestDigest, PackageId};
use sha2::{Digest, Sha256};

fn synthetic() -> (VerifiedManifest, Vec<Vec<u8>>) {
    let objects: Vec<Vec<u8>> = vec![vec![3; 32], vec![7; 32], vec![11; 32]];
    let chunks = objects
        .iter()
        .enumerate()
        .map(|(i, bytes)| ChunkMetadata {
            index: i as u64,
            ciphertext_sha256: Sha256::digest(bytes).into(),
            nonce: [i as u8; 12],
            plain_bytes: 16,
            cipher_bytes: 32,
        })
        .collect();
    (
        VerifiedManifest {
            package_id: PackageId::from_bytes([31; 32]),
            digest: ManifestDigest::from_bytes([42; 32]),
            signer: [9; 32],
            total_plain_bytes: 48,
            chunk_size: 16,
            chunks,
        },
        objects,
    )
}

#[test]
fn platform_store_replicates_and_resumes() {
    let (manifest, objects) = synthetic();
    let tmp = tempfile::tempdir().unwrap();
    let origin = VerifiedCas::new(tmp.path().join("origin")).unwrap();
    let target = VerifiedCas::new(tmp.path().join("target")).unwrap();
    assert_eq!(target.audit(&manifest).unwrap().missing, 3);
    origin.put_chunk(&manifest, 0, &objects[0]).unwrap();

    let error = target.sync_from(&manifest, &[&origin]).unwrap_err();
    assert_eq!(error.failed_index, 1);
    assert_eq!(error.progress.downloaded, 1);
    assert!(matches!(error.source, StoreError::NoHealthySource));

    origin.put_chunk(&manifest, 1, &objects[1]).unwrap();
    origin.put_chunk(&manifest, 2, &objects[2]).unwrap();
    let resumed = VerifiedCas::new(tmp.path().join("target")).unwrap();
    let progress = resumed.sync_from(&manifest, &[&origin]).unwrap();
    assert_eq!(progress.already_verified, 1);
    assert_eq!(progress.downloaded, 2);
    assert_eq!(resumed.audit(&manifest).unwrap().verified, 3);
    assert_eq!(resumed.read_chunk(&manifest, 2).unwrap(), objects[2]);
}

#[test]
fn platform_store_rejects_corrupt_and_repairs() {
    let (manifest, objects) = synthetic();
    let tmp = tempfile::tempdir().unwrap();
    let origin = VerifiedCas::new(tmp.path().join("origin")).unwrap();
    let target = VerifiedCas::new(tmp.path().join("target")).unwrap();
    for (i, bytes) in objects.iter().enumerate() {
        assert_eq!(
            origin.put_chunk(&manifest, i, bytes).unwrap(),
            WriteOutcome::Created
        );
    }
    target.sync_from(&manifest, &[&origin]).unwrap();

    let digest = manifest.chunks[0]
        .ciphertext_sha256
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let path = tmp
        .path()
        .join("target")
        .join("objects")
        .join("sha256")
        .join(&digest[..2])
        .join(&digest);
    std::fs::write(&path, b"invalid").unwrap();
    assert!(matches!(
        target.read_chunk(&manifest, 0),
        Err(StoreError::Corrupt)
    ));
    assert!(matches!(
        target.put_chunk(&manifest, 0, &objects[0]),
        Err(StoreError::Corrupt)
    ));
    let repaired = target.sync_from(&manifest, &[&origin]).unwrap();
    assert_eq!(repaired.repaired, 1);
    assert_eq!(repaired.already_verified, 2);
    assert_eq!(target.read_chunk(&manifest, 0).unwrap(), objects[0]);
}

#[test]
fn platform_store_fails_closed_for_wrong_bytes() {
    let (manifest, objects) = synthetic();
    let tmp = tempfile::tempdir().unwrap();
    let store = VerifiedCas::new(tmp.path()).unwrap();
    let mut tampered = objects[0].clone();
    tampered[10] ^= 1;
    assert!(matches!(
        store.put_chunk(&manifest, 0, &tampered),
        Err(StoreError::InvalidChunk)
    ));
    assert!(matches!(
        store.put_chunk(&manifest, 0, &objects[0][..31]),
        Err(StoreError::InvalidChunk)
    ));
    assert!(matches!(
        store.put_chunk(&manifest, 99, &objects[0]),
        Err(StoreError::InvalidChunk)
    ));
    assert_eq!(store.audit(&manifest).unwrap().missing, 3);
}

#[test]
fn platform_store_concurrent_verified_publishes() {
    let (manifest, objects) = synthetic();
    let tmp = tempfile::tempdir().unwrap();
    let store = VerifiedCas::new(tmp.path()).unwrap();
    let tasks: Vec<_> = (0..6)
        .map(|_| {
            let store = store.clone();
            let manifest = manifest.clone();
            let bytes = objects[0].clone();
            std::thread::spawn(move || store.put_chunk(&manifest, 0, &bytes).unwrap())
        })
        .collect();
    let results: Vec<_> = tasks.into_iter().map(|t| t.join().unwrap()).collect();
    assert_eq!(
        results
            .iter()
            .filter(|r| **r == WriteOutcome::Created)
            .count(),
        1
    );
    assert_eq!(store.read_chunk(&manifest, 0).unwrap(), objects[0]);
}

#[test]
fn platform_store_empty_manifest_is_safe() {
    let (mut manifest, _) = synthetic();
    manifest.chunks.clear();
    manifest.total_plain_bytes = 0;
    let tmp = tempfile::tempdir().unwrap();
    let store = VerifiedCas::new(tmp.path()).unwrap();
    assert_eq!(store.audit(&manifest).unwrap().verified, 0);
    assert_eq!(store.sync_from(&manifest, &[]).unwrap().downloaded, 0);
}

#[cfg(unix)]
#[test]
fn platform_store_rejects_symlinked_object_directories() {
    use std::os::unix::fs::symlink;
    let (manifest, objects) = synthetic();
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    let store = VerifiedCas::new(&root).unwrap();
    store.put_chunk(&manifest, 0, &objects[0]).unwrap();
    let subdir = root.join("objects").join("sha256");
    std::fs::remove_dir_all(&subdir).unwrap();
    symlink(tmp.path(), &subdir).unwrap();
    assert!(matches!(
        store.read_chunk(&manifest, 0),
        Err(StoreError::UnsafePath)
    ));
    assert!(matches!(
        store.put_chunk(&manifest, 0, &objects[0]),
        Err(StoreError::UnsafePath)
    ));
}

/// Executed only in the child test process spawned by the parent below.
/// The actual production CAS write routine runs up to the test-only pause,
/// with a partially written named temporary file and no published object.
#[test]
fn test_child_pauses_midwrite() {
    let Some(root) = std::env::var_os("HOLOCHAIN_CORE_TEST_CHILD_ROOT") else {
        return;
    };
    let (manifest, objects) = synthetic();
    let store = VerifiedCas::new(std::path::PathBuf::from(root)).unwrap();
    store.put_chunk(&manifest, 0, &objects[0]).unwrap();
}

#[test]
fn platform_store_deterministic_midwrite_kill_remains_unpublished_and_restartable() {
    use std::process::Command;
    use std::time::Duration;

    let (manifest, objects) = synthetic();
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("listener");
    let marker = temporary.path().join("paused-after-partial-write");
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "storage_tests::test_child_pauses_midwrite"])
        .env("HOLOCHAIN_CORE_TEST_CHILD_ROOT", &root)
        .env("HOLOCHAIN_CORE_TEST_PAUSE_PARTIAL_WRITE", &marker)
        .spawn()
        .unwrap();

    // Synchronize on the actual temp-file half-write, not a timing-based kill.
    let mut paused = false;
    for _ in 0..500 {
        if marker.is_file() {
            paused = true;
            break;
        }
        if child.try_wait().unwrap().is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }

    let digest = manifest.chunks[0]
        .ciphertext_sha256
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let folder = root.join("objects").join("sha256").join(&digest[..2]);
    let published = folder.join(&digest);
    let still_unpublished = !published.exists();
    let partial_temp_exists = paused
        && std::fs::read_dir(&folder)
            .unwrap()
            .filter_map(Result::ok)
            .any(|entry| {
                entry.path() != published
                    && entry
                        .metadata()
                        .map(|meta| meta.is_file() && meta.len() == (objects[0].len() / 2) as u64)
                        .unwrap_or(false)
            });

    // Kill the parked writer *before* inspecting or repairing its store.
    let _ = child.kill();
    let _ = child.wait();
    assert!(paused, "subprocess did not reach the real partial-write hook");
    assert!(still_unpublished, "partial ciphertext was published as an object");
    assert!(partial_temp_exists, "no half-written CAS temp file was observed");

    let restarted = VerifiedCas::new(&root).unwrap();
    let initial = restarted.audit(&manifest).unwrap();
    assert_eq!((initial.verified, initial.missing, initial.corrupt), (0, 3, 0));
    assert_eq!(
        restarted.put_chunk(&manifest, 0, &objects[0]).unwrap(),
        WriteOutcome::Created
    );
    let final_audit = restarted.audit(&manifest).unwrap();
    assert_eq!(
        (final_audit.verified, final_audit.missing, final_audit.corrupt),
        (1, 2, 0)
    );
    assert_eq!(restarted.read_chunk(&manifest, 0).unwrap(), objects[0]);
}
