//! Synthetic Video fixture tests. Manifests are S1-shaped and signed here
//! with fixed test keys; nothing in this file is a real video or approval.

use super::*;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signer, SigningKey};
use holochain_content_core::binding::{verify_owned_manifest, ConductorRecord, KEY_BINDING_V1};
use holochain_content_core::compat::canonical_json;
use sha2::{Digest, Sha256};

const PUBLISHER: &str = "uhCAkVideoPublisherTestAgent";
const OTHER: &str = "uhCAkSomeoneElseTestAgent";

struct Fixture {
    owned: OwnedManifest,
    objects: Vec<Vec<u8>>,
    source_sha256: [u8; 32],
}

fn signed(body: Value, key: &SigningKey) -> Vec<u8> {
    let sig = key.sign(&canonical_json(&body).unwrap());
    serde_json::to_vec(&json!({
        "body": body,
        "signer": STANDARD.encode(key.verifying_key().to_bytes()),
        "signature": STANDARD.encode(sig.to_bytes()),
    }))
    .unwrap()
}

fn record(author: &str, body: Value) -> ConductorRecord {
    ConductorRecord::from_validated_conductor(author, "uhCkkTestAction", body).unwrap()
}

/// A synthetic "rendition" whose ciphertext objects are opaque test bytes.
fn fixture() -> Fixture {
    let key = SigningKey::from_bytes(&[42; 32]);
    let source = b"synthetic approved video rendition (test fixture, not media)".to_vec();
    let objects: Vec<Vec<u8>> = (0..3u8).map(|i| vec![i.wrapping_mul(29); 40]).collect();
    let body = json!({
        "schema": "holochain-storage/encrypted-package/v1",
        "file_id": "7e".repeat(32), "cipher": "AES-256-GCM", "chunk_size": 24,
        "total_plain_bytes": 72,
        "chunks": objects.iter().enumerate().map(|(i, o)| json!({
            "index": i, "sha256": hex(&Sha256::digest(o)),
            "nonce": STANDARD.encode([i as u8 + 1; 12]), "plain_bytes": 24, "cipher_bytes": 40,
        })).collect::<Vec<_>>(),
    });
    let manifest = signed(body, &key);
    let digest = hex(&Sha256::digest(
        canonical_json(&serde_json::from_slice::<Value>(&manifest).unwrap()).unwrap(),
    ));
    let owned = verify_owned_manifest(
        &manifest,
        PUBLISHER,
        &record(
            PUBLISHER,
            json!({"schema": KEY_BINDING_V1, "agent": PUBLISHER, "purpose": "owner-manifest",
                   "signing_key_hex": hex(&key.verifying_key().to_bytes())}),
        ),
        &record(
            PUBLISHER,
            json!({"schema": FILE_COMMITMENT_V1, "owner_agent": PUBLISHER,
                   "file_id": "7e".repeat(32), "manifest_sha256": digest}),
        ),
    )
    .unwrap();
    Fixture {
        owned,
        objects,
        source_sha256: Sha256::digest(&source).into(),
    }
}

fn request(f: &Fixture, decision: &str) -> ReleaseRequest {
    ReleaseRequest {
        publisher_agent: PUBLISHER.into(),
        source_sha256: f.source_sha256,
        decision_ref: decision.into(),
    }
}

#[test]
fn video_evidence_never_becomes_a_release_authorisation() {
    let receipt = json!({
        "schema": VIDEO_INGEST_RECEIPT_V1, "id": "ab".repeat(16), "state": "quarantined",
        "bytes": 1024, "sha256": "cd".repeat(32), "published": false,
        "rightsVerified": false, "transcodeStarted": false,
    });
    // Even a receipt edited to *claim* publication/verification is evidence,
    // not a decision.
    let mut lying = receipt.clone();
    lying["published"] = json!(true);
    lying["rightsVerified"] = json!(true);
    lying["state"] = json!("approved");
    let proposal = json!({"schema": VIDEO_CATALOGUE_PROPOSAL_V1, "title": "x"});
    let finding = json!({"finding": "rights-cleared", "reviewer": "uhCAkReviewer"});
    for evidence in [
        GovernanceEvidence::IngestReceipt(receipt),
        GovernanceEvidence::IngestReceipt(lying),
        GovernanceEvidence::CatalogueProposal(proposal),
        GovernanceEvidence::ReviewerFinding(finding),
    ] {
        assert!(matches!(
            evidence.authorize(),
            Err(ReleaseDenied::NotAnAuthorization(_))
        ));
    }
}

#[test]
fn synthetic_authority_only_approves_marked_synthetic_fixtures() {
    let f = fixture();
    let real_looking = request(&f, "uhCkkSomeReviewerApprovalAction");
    assert!(matches!(
        SyntheticTestAuthority.authorize(&real_looking),
        Err(ReleaseDenied::NotApproved(_))
    ));
    let synthetic = request(&f, &format!("{SYNTHETIC_DECISION_PREFIX}fixture-1"));
    let auth = SyntheticTestAuthority.authorize(&synthetic).unwrap();
    assert_eq!(auth.authority(), "synthetic-test");
}

#[test]
fn authorised_synthetic_release_registers_verified_ciphertext() {
    let f = fixture();
    let auth = SyntheticTestAuthority
        .authorize(&request(
            &f,
            &format!("{SYNTHETIC_DECISION_PREFIX}fixture-1"),
        ))
        .unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let cas = VerifiedCas::new(tmp.path()).unwrap();
    let registered = register_release(&auth, &f.owned, f.source_sha256, &f.objects, &cas).unwrap();
    assert_eq!(registered.verified_objects, 3);
    assert_eq!(
        registered.file_commitment["manifest_sha256"],
        json!(f.owned.manifest().digest().to_string())
    );
    assert_eq!(
        registered.release_record["source_sha256"],
        json!(hex(&f.source_sha256))
    );
    assert_eq!(
        registered.release_record["authority"],
        json!("synthetic-test")
    );
    // Re-registration is idempotent.
    let again = register_release(&auth, &f.owned, f.source_sha256, &f.objects, &cas).unwrap();
    assert_eq!(again.verified_objects, 3);
}

#[test]
fn mismatched_publisher_source_or_bytes_are_denied_before_distribution() {
    let f = fixture();
    let tmp = tempfile::tempdir().unwrap();
    let cas = VerifiedCas::new(tmp.path()).unwrap();
    let mut other_publisher = request(&f, &format!("{SYNTHETIC_DECISION_PREFIX}x"));
    other_publisher.publisher_agent = OTHER.into();
    let auth = SyntheticTestAuthority.authorize(&other_publisher).unwrap();
    assert_eq!(
        register_release(&auth, &f.owned, f.source_sha256, &f.objects, &cas),
        Err(ReleaseDenied::PublisherMismatch)
    );
    let auth = SyntheticTestAuthority
        .authorize(&request(&f, &format!("{SYNTHETIC_DECISION_PREFIX}x")))
        .unwrap();
    assert_eq!(
        register_release(&auth, &f.owned, [0; 32], &f.objects, &cas),
        Err(ReleaseDenied::SourceMismatch)
    );
    // Nothing was stored by the denied attempts.
    assert_eq!(cas.audit(f.owned.manifest()).unwrap().missing, 3);
    let mut tampered = f.objects.clone();
    tampered[1][0] ^= 1;
    assert!(matches!(
        register_release(&auth, &f.owned, f.source_sha256, &tampered, &cas),
        Err(ReleaseDenied::Storage(_))
    ));
    assert_eq!(cas.audit(f.owned.manifest()).unwrap().verified, 1);
}
