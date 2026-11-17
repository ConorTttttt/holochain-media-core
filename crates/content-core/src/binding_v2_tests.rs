//! S2 key-binding v2 tests. Every binding, package, grant and licence here was
//! produced by Holochain Music's own Python code at a pinned commit
//! (`scripts/generate_music_key_binding_vectors.py`); a committed run lets
//! these run everywhere, and `MUSIC_KEY_BINDING_VECTORS` points at a fresh one.

use crate::binding::*;
use crate::entitlements::{
    check_content_access, check_content_access_requiring, AccessError, AuthenticatedSubject,
    Unauthenticated,
};
use crate::Right;
use serde_json::{json, Value};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const COMMITTED: &str = include_str!("../testdata/music-key-binding-v2-vectors.json");

fn vectors() -> Value {
    let text = match std::env::var("MUSIC_KEY_BINDING_VECTORS") {
        Ok(path) => {
            let path = std::path::PathBuf::from(path);
            let path = if path.is_absolute() {
                path
            } else {
                std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../..")
                    .join(path)
            };
            std::fs::read_to_string(path).expect("read MUSIC_KEY_BINDING_VECTORS")
        }
        Err(_) => COMMITTED.to_owned(),
    };
    let v: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(
        v["schema"],
        "holochain-media-core/music-key-binding-v2-vectors/v1"
    );
    v
}

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v[k].as_str().unwrap_or_else(|| panic!("missing {k}"))
}

fn purpose(text: &str) -> KeyPurpose {
    match text {
        "owner-manifest" => KeyPurpose::OwnerManifest,
        "host-receipt" => KeyPurpose::HostReceipt,
        other => panic!("{other}"),
    }
}

fn record(author: &str, action: &str, body: Value) -> ConductorRecord {
    ConductorRecord::from_validated_conductor(author, action, body).unwrap()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn v1_binding(agent: &str, purpose: &str, key_hex: &str) -> ConductorRecord {
    record(
        agent,
        "uhCkkV1",
        json!({"schema": KEY_BINDING_V1, "agent": agent, "purpose": purpose,
               "signing_key_hex": key_hex}),
    )
}

fn alice_v2(v: &Value, action: &str) -> ConductorRecord {
    record(
        s(&v["agents"], "alice"),
        action,
        v["bindings"]["alice_owner"].clone(),
    )
}

fn v2_policy(v: &Value) -> KeyBindingPolicy {
    KeyBindingPolicy::ProofOfPossessionV2 {
        dna_hash: s(v, "dna_hash").to_owned(),
    }
}

#[test]
fn proof_message_is_byte_identical_to_music() {
    let v = vectors();
    let alice = s(&v["agents"], "alice");
    let m = key_binding_v2_message(
        s(&v, "dna_hash"),
        alice,
        "owner-manifest",
        s(&v["keys"], "alice_ed25519_public_hex"),
        KEY_GENERATION_V2,
    );
    assert_eq!(hex(&m), s(&v, "message_hex"));
    assert!(m.starts_with(KEY_BINDING_POP_DOMAIN_V2));
}

/// Tests A–G and J: Rust agrees with Music on every Python-generated case,
/// for the expected reason.
#[test]
fn python_generated_bindings_match_music() {
    let v = vectors();
    let mut failures = Vec::new();
    for c in v["cases"].as_array().unwrap() {
        let name = s(c, "name");
        let expected = &c["expect"];
        let result =
            ConductorRecord::from_validated_conductor(s(c, "author"), "uhCkkS2", c["body"].clone())
                .and_then(|r| {
                    verify_key_binding_v2(
                        &r,
                        s(c, "agent"),
                        purpose(s(c, "purpose")),
                        s(c, "dna_hash"),
                    )
                });
        let python_ok = c["python"]["verdict"] == "accepted";
        match (&result, s(expected, "result")) {
            (Ok(binding), "accepted") => {
                if !python_ok || hex(binding.key()) != s(&c["python"], "key_hex") {
                    failures.push(format!("{name}: key differs from Music"));
                }
                if binding.assurance() != BindingAssurance::ProofOfPossessionV2 {
                    failures.push(format!("{name}: wrong assurance"));
                }
            }
            (Err(e), "rejected") => {
                if format!("{e:?}") != s(expected, "reason") {
                    failures.push(format!(
                        "{name}: expected {}, got {e:?}",
                        s(expected, "reason")
                    ));
                }
                if python_ok {
                    failures.push(format!("{name}: Music accepted"));
                }
            }
            (other, want) => failures.push(format!("{name}: expected {want}, got {other:?}")),
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// Test H: explicit duplicate/conflict policy, no first- or latest-match.
#[test]
fn duplicate_and_conflicting_bindings_policy() {
    let v = vectors();
    let alice = s(&v["agents"], "alice");
    let policy = v2_policy(&v);
    let one = alice_v2(&v, "uhCkkA1");
    let same = alice_v2(&v, "uhCkkA2");
    let other = record(
        alice,
        "uhCkkA3",
        v["bindings"]["alice_owner_second_key"].clone(),
    );
    let resolved = resolve_signing_key(
        &[one.clone(), same.clone()],
        alice,
        KeyPurpose::OwnerManifest,
        &policy,
    )
    .unwrap();
    assert_eq!(
        hex(resolved.key()),
        s(&v["keys"], "alice_ed25519_public_hex")
    );
    assert_eq!(resolved.action_hash(), "uhCkkA1");
    for order in [
        vec![one.clone(), other.clone()],
        vec![other.clone(), one.clone()],
    ] {
        assert_eq!(
            resolve_signing_key(&order, alice, KeyPurpose::OwnerManifest, &policy),
            Err(BindingError::Ambiguous)
        );
    }
    // A Carol host binding is irrelevant to Alice's owner key.
    let carol = record(
        s(&v["agents"], "carol"),
        "uhCkkC",
        v["bindings"]["carol_host"].clone(),
    );
    assert!(resolve_signing_key(&[carol, one], alice, KeyPurpose::OwnerManifest, &policy).is_ok());
    assert_eq!(
        resolve_signing_key(&[], alice, KeyPurpose::OwnerManifest, &policy),
        Err(BindingError::MissingRecord)
    );
}

/// Test I: v1 stays readable, labelled legacy; never upgraded, never a
/// fallback for v2; a bad v2 record is an error, not skipped.
#[test]
fn legacy_v1_is_explicit_and_never_confused_with_v2() {
    let v = vectors();
    let alice = s(&v["agents"], "alice");
    let key_hex = s(&v["keys"], "alice_ed25519_public_hex");
    let v1 = v1_binding(alice, "owner-manifest", key_hex);
    let v2 = alice_v2(&v, "uhCkkA1");
    let legacy = resolve_signing_key(
        &[v1.clone(), v2.clone()],
        alice,
        KeyPurpose::OwnerManifest,
        &KeyBindingPolicy::LegacyV1,
    )
    .unwrap();
    assert_eq!(legacy.assurance(), BindingAssurance::LegacyAuthoredV1);
    assert_eq!(legacy.action_hash(), "uhCkkV1");
    assert_eq!(
        require_proof_of_possession(&legacy),
        Err(BindingError::InsufficientAssurance)
    );
    // v2 policy never consults v1 records.
    assert_eq!(
        resolve_signing_key(
            std::slice::from_ref(&v1),
            alice,
            KeyPurpose::OwnerManifest,
            &v2_policy(&v)
        ),
        Err(BindingError::MissingRecord)
    );
    // An invalid v2 record is not skipped in favour of a valid one or of v1.
    let mut broken = v["bindings"]["alice_owner"].clone();
    broken["proof_signature_hex"] = json!("00".repeat(64));
    let broken = record(alice, "uhCkkBad", broken);
    for set in [
        vec![broken.clone(), v2.clone()],
        vec![v2.clone(), broken.clone()],
        vec![broken, v1],
    ] {
        assert_eq!(
            resolve_signing_key(&set, alice, KeyPurpose::OwnerManifest, &v2_policy(&v)),
            Err(BindingError::InvalidProof)
        );
    }
    let strong =
        resolve_signing_key(&[v2], alice, KeyPurpose::OwnerManifest, &v2_policy(&v)).unwrap();
    assert!(require_proof_of_possession(&strong).is_ok());
    assert!(BindingAssurance::ProofOfPossessionV2 > BindingAssurance::LegacyAuthoredV1);
}

fn commitment(v: &Value, owner: &str) -> ConductorRecord {
    record(
        owner,
        "uhCkkCommit",
        json!({"schema": FILE_COMMITMENT_V1, "owner_agent": owner,
               "file_id": v["chain"]["file_id"], "manifest_sha256": v["chain"]["manifest_sha256"]}),
    )
}

fn owned_v2(v: &Value) -> OwnedManifest {
    let alice = s(&v["agents"], "alice");
    let key = resolve_signing_key(
        &[alice_v2(v, "uhCkkA1")],
        alice,
        KeyPurpose::OwnerManifest,
        &v2_policy(v),
    )
    .unwrap();
    verify_owned_manifest_with_key(
        s(&v["chain"], "manifest_text").as_bytes(),
        alice,
        &key,
        &commitment(v, alice),
    )
    .unwrap()
}

#[test]
fn owned_manifest_carries_assurance_and_requires_matching_key() {
    let v = vectors();
    let alice = s(&v["agents"], "alice");
    let manifest = s(&v["chain"], "manifest_text").as_bytes();
    assert_eq!(
        owned_v2(&v).owner_assurance(),
        BindingAssurance::ProofOfPossessionV2
    );
    let legacy = verify_owned_manifest(
        manifest,
        alice,
        &v1_binding(
            alice,
            "owner-manifest",
            s(&v["keys"], "alice_ed25519_public_hex"),
        ),
        &commitment(&v, alice),
    )
    .unwrap();
    assert_eq!(legacy.owner_assurance(), BindingAssurance::LegacyAuthoredV1);
    // A verified key for another agent or purpose cannot authenticate Alice.
    let carol = s(&v["agents"], "carol");
    let carol_key = verify_key_binding_v2(
        &record(carol, "uhCkkC", v["bindings"]["carol_host"].clone()),
        carol,
        KeyPurpose::HostReceipt,
        s(&v, "dna_hash"),
    )
    .unwrap();
    assert_eq!(
        verify_owned_manifest_with_key(manifest, alice, &carol_key, &commitment(&v, alice)),
        Err(BindingError::KeyNotBound)
    );
}

/// The CORE-004 finding, closed: with v2, Mallory cannot bind Alice's key
/// (vectors B/C), and her own proven key does not authenticate Alice's
/// package as hers.
#[test]
fn mallory_cannot_claim_alices_package_under_v2() {
    let v = vectors();
    let mallory = s(&v["agents"], "mallory");
    let key = verify_key_binding_v2(
        &record(mallory, "uhCkkM", v["bindings"]["mallory_owner"].clone()),
        mallory,
        KeyPurpose::OwnerManifest,
        s(&v, "dna_hash"),
    )
    .unwrap();
    let err = verify_owned_manifest_with_key(
        s(&v["chain"], "manifest_text").as_bytes(),
        mallory,
        &key,
        &commitment(&v, mallory),
    )
    .unwrap_err();
    assert!(matches!(err, BindingError::Manifest(_)), "{err:?}");
}

/// CORE-005 with v1 versus v2 owner identity.
#[test]
fn entitlements_report_and_can_require_owner_assurance() {
    let v = vectors();
    let alice = s(&v["agents"], "alice");
    let subject = AuthenticatedSubject::from_trusted_context(s(&v["agents"], "bob"), {
        let id: crate::PackageId = s(&v["keys"], "bob_x25519_public_hex").parse().unwrap();
        *id.as_bytes()
    })
    .unwrap();
    let now = UNIX_EPOCH + Duration::from_secs(v["chain"]["now"].as_u64().unwrap());
    let strong = owned_v2(&v);
    let legacy = verify_owned_manifest(
        s(&v["chain"], "manifest_text").as_bytes(),
        alice,
        &v1_binding(
            alice,
            "owner-manifest",
            s(&v["keys"], "alice_ed25519_public_hex"),
        ),
        &commitment(&v, alice),
    )
    .unwrap();
    for (doc, right) in [
        ("licence_text", Right::Export),
        ("grant_text", Right::Stream),
    ] {
        let grant = s(&v["chain"], doc).as_bytes();
        let d = check_content_access(&strong, &subject, grant, right, now).unwrap();
        assert_eq!(
            d.entitlement().owner_assurance(),
            BindingAssurance::ProofOfPossessionV2
        );
        let d = check_content_access(&legacy, &subject, grant, right, now).unwrap();
        assert_eq!(
            d.entitlement().owner_assurance(),
            BindingAssurance::LegacyAuthoredV1
        );
        assert!(check_content_access_requiring(
            &strong,
            &subject,
            grant,
            right,
            now,
            BindingAssurance::ProofOfPossessionV2
        )
        .is_ok());
        assert_eq!(
            check_content_access_requiring(
                &legacy,
                &subject,
                grant,
                right,
                now,
                BindingAssurance::ProofOfPossessionV2
            )
            .unwrap_err(),
            AccessError::Unauthenticated(Unauthenticated::InsufficientOwnerAssurance)
        );
        assert!(check_content_access_requiring(
            &legacy,
            &subject,
            grant,
            right,
            now,
            BindingAssurance::LegacyAuthoredV1
        )
        .is_ok());
    }
    let _ = SystemTime::now();
}
