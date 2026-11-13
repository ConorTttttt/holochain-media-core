//! CORE-004 Task A tests. Record-shape, author and endpoint rules use plain
//! JSON records; anything involving an S1 signature uses the independent
//! Python Music vectors (feature `music-interop-tests`), never a signature
//! created by this crate.

use crate::binding::*;
use crate::{ManifestDigest, PackageId};
use serde_json::{json, Value};

const ALICE: &str = "uhCAkAliceAgentPubKeyForTestsOnly000000000000000000";
const CAROL: &str = "uhCAkCarolAgentPubKeyForTestsOnly000000000000000000";
const MALLORY: &str = "uhCAkMalloryAgentPubKeyForTestsOnly00000000000000000";

fn record(author: &str, body: Value) -> ConductorRecord {
    ConductorRecord::from_validated_conductor(author, "uhCkkActionHash", body).unwrap()
}

fn key_binding(author: &str, agent: &str, purpose: &str, key_hex: &str) -> ConductorRecord {
    record(
        author,
        json!({"schema": KEY_BINDING_V1, "agent": agent, "purpose": purpose,
               "signing_key_hex": key_hex}),
    )
}

fn pin() -> CommitmentPin {
    CommitmentPin {
        package_id: PackageId::from_bytes([0x11; 32]),
        manifest_digest: ManifestDigest::from_bytes([0x22; 32]),
    }
}

fn endpoint(author: &str, node: &str, owner: &str, url: &str) -> ConductorRecord {
    record(
        author,
        json!({"schema": MOQ_ENDPOINT_V1, "node_agent": node, "owner_agent": owner,
               "file_id": "11".repeat(32), "manifest_sha256": "22".repeat(32),
               "url": url, "cert_fingerprint_hex": "ab".repeat(32)}),
    )
}

#[test]
fn conductor_record_requires_object_body_and_identifiers() {
    assert_eq!(
        ConductorRecord::from_validated_conductor(ALICE, "h", json!("x")),
        Err(BindingError::InvalidRecord)
    );
    assert_eq!(
        ConductorRecord::from_validated_conductor("", "h", json!({})),
        Err(BindingError::MissingRecord)
    );
    assert_eq!(
        ConductorRecord::from_validated_conductor(ALICE, "", json!({})),
        Err(BindingError::MissingRecord)
    );
    assert_eq!(
        ConductorRecord::from_validated_conductor("a".repeat(161), "h", json!({})),
        Err(BindingError::MissingRecord)
    );
}

#[test]
fn key_binding_requires_author_agent_purpose_and_exact_fields() {
    let key = "0a".repeat(32);
    let good = key_binding(ALICE, ALICE, "owner-manifest", &key);
    assert_eq!(
        key_for_agent(&good, ALICE, KeyPurpose::OwnerManifest).unwrap(),
        [0x0a; 32]
    );
    // Purpose is enforced: an owner key cannot be used to sign receipts.
    assert_eq!(
        key_for_agent(&good, ALICE, KeyPurpose::HostReceipt),
        Err(BindingError::KeyNotBound)
    );
    // Mallory cannot bind a key for Alice: the action author is checked.
    let forged = key_binding(MALLORY, ALICE, "owner-manifest", &key);
    assert_eq!(
        key_for_agent(&forged, ALICE, KeyPurpose::OwnerManifest),
        Err(BindingError::AuthorMismatch)
    );
    // Body agent must match too (integrity zome rule re-checked here).
    let other = key_binding(ALICE, MALLORY, "owner-manifest", &key);
    assert_eq!(
        key_for_agent(&other, ALICE, KeyPurpose::OwnerManifest),
        Err(BindingError::KeyNotBound)
    );
    for bad_key in ["0A".repeat(32), "0a".repeat(31), "zz".repeat(32)] {
        let bad = key_binding(ALICE, ALICE, "owner-manifest", &bad_key);
        assert_eq!(
            key_for_agent(&bad, ALICE, KeyPurpose::OwnerManifest),
            Err(BindingError::InvalidRecord),
            "{bad_key}"
        );
    }
    let extra = record(
        ALICE,
        json!({"schema": KEY_BINDING_V1, "agent": ALICE, "purpose": "owner-manifest",
               "signing_key_hex": key, "note": "unexpected"}),
    );
    assert_eq!(
        key_for_agent(&extra, ALICE, KeyPurpose::OwnerManifest),
        Err(BindingError::InvalidRecord)
    );
    let wrong_schema = record(
        ALICE,
        json!({"schema": "holochain-storage/key-binding/v2", "agent": ALICE,
               "purpose": "owner-manifest", "signing_key_hex": key}),
    );
    assert_eq!(
        key_for_agent(&wrong_schema, ALICE, KeyPurpose::OwnerManifest),
        Err(BindingError::InvalidRecord)
    );
}

#[test]
fn unique_selection_fails_closed_on_ambiguity() {
    let a = key_binding(ALICE, ALICE, "owner-manifest", &"01".repeat(32));
    let b = key_binding(ALICE, ALICE, "owner-manifest", &"02".repeat(32));
    let host = key_binding(ALICE, ALICE, "host-receipt", &"03".repeat(32));
    let records = vec![a.clone(), host.clone()];
    let chosen = select_unique(&records, |r| {
        is_key_binding(r, ALICE, KeyPurpose::OwnerManifest)
    })
    .unwrap();
    assert_eq!(chosen, &a);
    let records = vec![a, b, host];
    assert_eq!(
        select_unique(&records, |r| is_key_binding(
            r,
            ALICE,
            KeyPurpose::OwnerManifest
        )),
        Err(BindingError::Ambiguous)
    );
    assert_eq!(
        select_unique(&records, |r| is_key_binding(
            r,
            MALLORY,
            KeyPurpose::OwnerManifest
        )),
        Err(BindingError::MissingRecord)
    );
}

#[test]
fn commitment_pin_is_owner_authored() {
    let body = json!({"schema": FILE_COMMITMENT_V1, "owner_agent": ALICE,
                      "file_id": "11".repeat(32), "manifest_sha256": "22".repeat(32)});
    assert_eq!(
        commitment_pin(&record(ALICE, body.clone()), ALICE).unwrap(),
        pin()
    );
    assert_eq!(
        commitment_pin(&record(MALLORY, body), ALICE),
        Err(BindingError::AuthorMismatch)
    );
    let mixed_case = json!({"schema": FILE_COMMITMENT_V1, "owner_agent": ALICE,
                            "file_id": "AA".repeat(32), "manifest_sha256": "22".repeat(32)});
    assert_eq!(
        commitment_pin(&record(ALICE, mixed_case), ALICE),
        Err(BindingError::InvalidRecord)
    );
}

#[test]
fn endpoint_binds_exact_host_owner_file_and_manifest() {
    let good = endpoint(CAROL, CAROL, ALICE, "https://127.0.0.1:4443");
    assert!(is_endpoint_for(&good, CAROL, ALICE, &pin()));
    let pinned =
        verify_moq_endpoint(&good, CAROL, ALICE, &pin(), EndpointPolicy::LoopbackOnly).unwrap();
    assert_eq!(pinned.port(), 4443);
    assert_eq!(pinned.cert_fingerprint(), &[0xab; 32]);
    assert_eq!(pinned.node_agent(), CAROL);

    // Mallory advertising an endpoint that claims to be Carol's.
    let forged = endpoint(MALLORY, CAROL, ALICE, "https://127.0.0.1:4443");
    assert!(!is_endpoint_for(&forged, CAROL, ALICE, &pin()));
    assert_eq!(
        verify_moq_endpoint(&forged, CAROL, ALICE, &pin(), EndpointPolicy::LoopbackOnly),
        Err(BindingError::AuthorMismatch)
    );
    // Same host but for another owner's file.
    let other_owner = endpoint(CAROL, CAROL, MALLORY, "https://127.0.0.1:4443");
    assert_eq!(
        verify_moq_endpoint(
            &other_owner,
            CAROL,
            ALICE,
            &pin(),
            EndpointPolicy::LoopbackOnly
        ),
        Err(BindingError::EndpointMismatch)
    );
    let other_pin = CommitmentPin {
        manifest_digest: ManifestDigest::from_bytes([0x33; 32]),
        ..pin()
    };
    assert_eq!(
        verify_moq_endpoint(
            &good,
            CAROL,
            ALICE,
            &other_pin,
            EndpointPolicy::LoopbackOnly
        ),
        Err(BindingError::EndpointMismatch)
    );
}

#[test]
fn endpoint_urls_follow_music_bound_local_url_rules() {
    use std::net::Ipv4Addr;
    assert_eq!(
        parse_endpoint_url("https://127.0.0.1:443", EndpointPolicy::LoopbackOnly),
        Ok((Ipv4Addr::LOCALHOST, 443))
    );
    assert_eq!(
        parse_endpoint_url("https://192.168.1.5:9000", EndpointPolicy::AllowPrivateLan),
        Ok((Ipv4Addr::new(192, 168, 1, 5), 9000))
    );
    for (bad, policy) in [
        ("https://192.168.1.5:9000", EndpointPolicy::LoopbackOnly),
        ("https://8.8.8.8:443", EndpointPolicy::AllowPrivateLan),
        ("https://localhost:443", EndpointPolicy::LoopbackOnly),
        ("http://127.0.0.1:443", EndpointPolicy::LoopbackOnly),
        ("https://127.0.0.1:0", EndpointPolicy::LoopbackOnly),
        ("https://127.0.0.1:65536", EndpointPolicy::LoopbackOnly),
        ("https://127.0.0.1:0443", EndpointPolicy::LoopbackOnly),
        ("https://127.0.0.1:443/", EndpointPolicy::LoopbackOnly),
        ("https://u@127.0.0.1:443", EndpointPolicy::LoopbackOnly),
        ("https://127.000.0.1:443", EndpointPolicy::LoopbackOnly),
        ("https://[::1]:443", EndpointPolicy::LoopbackOnly),
        ("https://169.254.1.1:443", EndpointPolicy::AllowPrivateLan),
        ("https://127.0.0.1", EndpointPolicy::LoopbackOnly),
    ] {
        assert_eq!(
            parse_endpoint_url(bad, policy),
            Err(BindingError::EndpointNotAllowed),
            "{bad}"
        );
    }
}

/// Signed-path tests driven by the independent Python Music S1 vectors.
#[cfg(feature = "music-interop-tests")]
mod signed {
    use super::*;
    use crate::compat::VerifyError;
    use base64::{engine::general_purpose::STANDARD, Engine as _};

    fn vectors() -> Value {
        let path =
            std::path::PathBuf::from(std::env::var("MUSIC_VECTORS").expect("set MUSIC_VECTORS"));
        let path = if path.is_absolute() {
            path
        } else {
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../..")
                .join(path)
        };
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
    }

    fn hex_of_b64(b64: &str) -> String {
        STANDARD
            .decode(b64)
            .unwrap()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    struct Fixture {
        manifest: Vec<u8>,
        receipt: Vec<u8>,
        receipt_sha256: String,
        artist_hex: String,
        host_hex: String,
        file_id: String,
        digest: String,
    }

    fn fixture() -> Fixture {
        let v = vectors();
        Fixture {
            manifest: serde_json::to_vec(&v["package"]).unwrap(),
            receipt: serde_json::to_vec(&v["receipt"]).unwrap(),
            receipt_sha256: v["receipt_sha256"].as_str().unwrap().to_owned(),
            artist_hex: hex_of_b64(v["artist_public_key"].as_str().unwrap()),
            host_hex: hex_of_b64(v["host_public_key"].as_str().unwrap()),
            file_id: v["package"]["body"]["file_id"].as_str().unwrap().to_owned(),
            digest: v["manifest_sha256"].as_str().unwrap().to_owned(),
        }
    }

    fn commitment(author: &str, owner: &str, file_id: &str, digest: &str) -> ConductorRecord {
        record(
            author,
            json!({"schema": FILE_COMMITMENT_V1, "owner_agent": owner,
                   "file_id": file_id, "manifest_sha256": digest}),
        )
    }

    fn claim(
        author: &str,
        node: &str,
        owner: &str,
        f: &Fixture,
        receipt_sha256: &str,
    ) -> ConductorRecord {
        record(
            author,
            json!({"schema": REPLICA_CLAIM_V1, "node_agent": node, "owner_agent": owner,
                   "file_id": f.file_id, "manifest_sha256": f.digest,
                   "receipt_sha256": receipt_sha256}),
        )
    }

    fn owned(f: &Fixture) -> OwnedManifest {
        verify_owned_manifest(
            &f.manifest,
            ALICE,
            &key_binding(ALICE, ALICE, "owner-manifest", &f.artist_hex),
            &commitment(ALICE, ALICE, &f.file_id, &f.digest),
        )
        .unwrap()
    }

    #[test]
    fn music_manifest_is_bound_to_owner_key_and_commitment() {
        let f = fixture();
        let owned = owned(&f);
        assert_eq!(owned.owner_agent(), ALICE);
        assert_eq!(owned.manifest().digest().to_string(), f.digest);
        assert_eq!(owned.manifest().package_id().to_string(), f.file_id);
    }

    #[test]
    fn incorrect_artist_signing_key_is_rejected_by_signature_boundary() {
        let f = fixture();
        // Alice bound the *host's* key as her owner key: the manifest was
        // not signed by it, so the S1 signer check fails.
        let wrong = key_binding(ALICE, ALICE, "owner-manifest", &f.host_hex);
        assert_eq!(
            verify_owned_manifest(
                &f.manifest,
                ALICE,
                &wrong,
                &commitment(ALICE, ALICE, &f.file_id, &f.digest)
            ),
            Err(BindingError::Manifest(VerifyError::WrongSigner))
        );
        // Mallory binding Alice's real key is rejected by authorship.
        let mallory = key_binding(MALLORY, ALICE, "owner-manifest", &f.artist_hex);
        assert_eq!(
            verify_owned_manifest(
                &f.manifest,
                ALICE,
                &mallory,
                &commitment(ALICE, ALICE, &f.file_id, &f.digest)
            ),
            Err(BindingError::AuthorMismatch)
        );
    }

    #[test]
    fn wrong_manifest_digest_or_file_commitment_is_rejected() {
        let f = fixture();
        let key = key_binding(ALICE, ALICE, "owner-manifest", &f.artist_hex);
        let wrong_digest = commitment(ALICE, ALICE, &f.file_id, &"00".repeat(32));
        assert_eq!(
            verify_owned_manifest(&f.manifest, ALICE, &key, &wrong_digest),
            Err(BindingError::CommitmentMismatch)
        );
        let wrong_file = commitment(ALICE, ALICE, &"00".repeat(32), &f.digest);
        assert_eq!(
            verify_owned_manifest(&f.manifest, ALICE, &key, &wrong_file),
            Err(BindingError::CommitmentMismatch)
        );
        let mallory_commitment = commitment(MALLORY, ALICE, &f.file_id, &f.digest);
        assert_eq!(
            verify_owned_manifest(&f.manifest, ALICE, &key, &mallory_commitment),
            Err(BindingError::AuthorMismatch)
        );
        // A different (re-serialised but still validly signed) envelope
        // changes the digest; any byte change to the body breaks signature.
        let mut tampered: Value = serde_json::from_slice(&f.manifest).unwrap();
        tampered["body"]["chunk_size"] = json!(17);
        assert_eq!(
            verify_owned_manifest(
                &serde_json::to_vec(&tampered).unwrap(),
                ALICE,
                &key,
                &commitment(ALICE, ALICE, &f.file_id, &f.digest)
            ),
            Err(BindingError::Manifest(VerifyError::InvalidSignature))
        );
    }

    #[test]
    fn receipt_digest_matches_python_canonical_receipt_digest() {
        let f = fixture();
        let owned = owned(&f);
        let host = key_binding(CAROL, CAROL, "host-receipt", &f.host_hex);
        let replica = verify_replica_claim(
            &f.receipt,
            &owned,
            CAROL,
            &host,
            &claim(CAROL, CAROL, ALICE, &f, &f.receipt_sha256),
        )
        .unwrap();
        assert_eq!(replica.node_agent(), CAROL);
        assert_eq!(
            replica
                .receipt()
                .envelope_sha256()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
            f.receipt_sha256
        );
    }

    /// KNOWN LIMITATION (documented in docs/CORE-004-*.md, finding 2): the
    /// Music S2 key binding is not a proof of possession and the receipt does
    /// not name the host agent. An agent who binds a copy of another host's
    /// *public* key and authors her own claim over that host's receipt is
    /// accepted as a replica holder. Ciphertext integrity is unaffected
    /// (objects are still hash-verified); availability claims are spoofable.
    /// This test pins current behaviour so a future fix is a visible change.
    #[test]
    fn known_limitation_copied_public_key_claims_are_accepted() {
        let f = fixture();
        let owned = owned(&f);
        let copied = key_binding(MALLORY, MALLORY, "host-receipt", &f.host_hex);
        let her_claim = claim(MALLORY, MALLORY, ALICE, &f, &f.receipt_sha256);
        let replica = verify_replica_claim(&f.receipt, &owned, MALLORY, &copied, &her_claim)
            .expect("current S2 v1 semantics accept a copied public key");
        assert_eq!(replica.node_agent(), MALLORY);
    }

    #[test]
    fn forged_host_receipt_and_claims_are_rejected() {
        let f = fixture();
        let owned = owned(&f);
        let host = key_binding(CAROL, CAROL, "host-receipt", &f.host_hex);
        let good_claim = claim(CAROL, CAROL, ALICE, &f, &f.receipt_sha256);
        // Receipt signed by a key other than the host's bound key.
        let artist_as_host = key_binding(CAROL, CAROL, "host-receipt", &f.artist_hex);
        assert_eq!(
            verify_replica_claim(&f.receipt, &owned, CAROL, &artist_as_host, &good_claim),
            Err(BindingError::Receipt(VerifyError::WrongSigner))
        );
        // Receipt body altered after signing.
        let mut forged: Value = serde_json::from_slice(&f.receipt).unwrap();
        forged["body"]["received_at"] = json!("2030-01-01T00:00:00+00:00");
        assert_eq!(
            verify_replica_claim(
                &serde_json::to_vec(&forged).unwrap(),
                &owned,
                CAROL,
                &host,
                &good_claim
            ),
            Err(BindingError::Receipt(VerifyError::InvalidSignature))
        );
        // Signed receipt for a different package (Python-signed vector).
        let v = vectors();
        let other = serde_json::to_vec(&v["signed_invalid"]["receipt_wrong_package"]).unwrap();
        assert_eq!(
            verify_replica_claim(&other, &owned, CAROL, &host, &good_claim),
            Err(BindingError::Receipt(VerifyError::InvalidReceipt))
        );
        // Claim commits to a different receipt.
        assert_eq!(
            verify_replica_claim(
                &f.receipt,
                &owned,
                CAROL,
                &host,
                &claim(CAROL, CAROL, ALICE, &f, &"00".repeat(32))
            ),
            Err(BindingError::ClaimMismatch)
        );
        // Mallory authoring a claim in Carol's name.
        assert_eq!(
            verify_replica_claim(
                &f.receipt,
                &owned,
                CAROL,
                &host,
                &claim(MALLORY, CAROL, ALICE, &f, &f.receipt_sha256)
            ),
            Err(BindingError::AuthorMismatch)
        );
        // Mallory's binding of a key she does not hold, with a claim she did
        // not author, is still rejected by authorship.
        let mallory_key = key_binding(MALLORY, MALLORY, "host-receipt", &f.host_hex);
        assert_eq!(
            verify_replica_claim(
                &f.receipt,
                &owned,
                MALLORY,
                &mallory_key,
                &claim(CAROL, CAROL, ALICE, &f, &f.receipt_sha256)
            ),
            Err(BindingError::AuthorMismatch)
        );
    }
}
