//! Independent Rust verification of Music/Python-generated grant vectors.
//! Set MUSIC_ACCESS_GRANT_V2_VECTORS to a JSON fixture produced by the
//! companion Music script. No Python code or verifier is called from Rust.
//! Without the fixture the unit-test suite retains its standalone build;
//! cross-language CI supplies this variable and exercises every case.

use crate::access_grant_v2::{grant_message, grant_wrap_context, verify_access_grant_v2, GrantBodyV2};
use crate::binding::{verify_owned_manifest_lifecycle, AuthenticatedSubject, ConductorRecord};
use crate::grant_anchor::RecoveredIssuerPolicy;
use crate::lifecycle::resolve_key_lifecycle;
use crate::binding::KeyPurpose;
use crate::Right;
use serde_json::Value;
use std::time::{Duration, UNIX_EPOCH};

fn str_at<'a>(v: &'a Value, key: &str) -> &'a str {
    v[key].as_str().unwrap_or_else(|| panic!("missing string {key} in {v}"))
}
fn bytes32(hex: &str) -> [u8; 32] {
    assert_eq!(hex.len(), 64);
    let mut out = [0_u8; 32];
    for (i, p) in hex.as_bytes().chunks_exact(2).enumerate() {
        out[i] = u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap();
    }
    out
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|x| format!("{x:02x}")).collect()
}
fn record(value: &Value) -> ConductorRecord {
    ConductorRecord::from_validated_conductor_at(
        str_at(value, "author"), str_at(value, "action_hash"),
        u32::try_from(value["action_seq"].as_u64().expect("action_seq")).unwrap(),
        value["body"].clone(),
    ).expect("fixture conductor record")
}
fn records(value: &Value) -> Vec<ConductorRecord> {
    value.as_array().expect("records array").iter().map(record).collect()
}

#[test]
fn media_core_agrees_with_independent_music_grant_vectors() {
    let Ok(path) = std::env::var("MUSIC_ACCESS_GRANT_V2_VECTORS") else {
        eprintln!("cross-language v2 test requires MUSIC_ACCESS_GRANT_V2_VECTORS; CI sets it");
        return;
    };
    let document = std::fs::read_to_string(path).expect("read Python vector file");
    let vectors: Value = serde_json::from_str(&document).expect("parse Python vectors");
    assert_eq!(str_at(&vectors, "schema"), "holochain-media-core/music-access-grant-v2-vectors/v1");
    let dna = str_at(&vectors, "dna_hash");
    let owner = str_at(&vectors, "owner_agent");
    let manifest = str_at(&vectors, "manifest_text").as_bytes();
    let now = UNIX_EPOCH + Duration::from_secs(1_800_000_120);
    let cases = vectors["cases"].as_array().expect("cases");
    assert!(cases.len() >= 12, "missing negative v2 security cases");
    let mut positive = 0;
    for case in cases {
        let name = str_at(case, "name");
        let lifecycle = resolve_key_lifecycle(
            &records(&case["lifecycle_records"]), owner,
            KeyPurpose::OwnerManifest, dna,
        ).unwrap_or_else(|e| panic!("{name}: lifecycle: {e}"));
        let commitment = record(&case["commitment"]);
        let content = verify_owned_manifest_lifecycle(manifest, &lifecycle, &commitment);
        if name == "invalid-historical-commit" {
            assert!(content.is_err(), "historical manifest must be refused after rotation");
            assert_eq!(str_at(&case["expected"], "category"), "unauthenticated");
            assert_eq!(str_at(&case["expected"], "reason"), "InvalidHistoricalKey");
            continue;
        }
        let content = content.unwrap_or_else(|e| panic!("{name}: manifest: {e}"));
        let listener = str_at(case, "listener_agent");
        let recipient = bytes32(str_at(case, "recipient_key_hex"));
        let subject = AuthenticatedSubject::from_trusted_context(listener, recipient).unwrap();
        let anchor = if case["anchor"].is_null() { None } else { Some(record(&case["anchor"])) };
        let res = verify_access_grant_v2(
            &content, &subject, str_at(case, "grant_text").as_bytes(),
            &lifecycle, anchor.as_ref(), now, RecoveredIssuerPolicy::Reject,
        );
        let expected_cat = str_at(&case["expected"], "category");
        let expected_reason = str_at(&case["expected"], "reason");
        if expected_cat == "ok" {
            let verified = res.unwrap_or_else(|e| panic!("{name}: unexpected denial {e}"));
            assert!(verified.entitlement().rights().contains(Right::Stream));
            assert!(verified.entitlement().wrapped_content_key().wrapped_key().len() == 48);
            assert_eq!(verified.issuer().generation(), 2);
            if name == "valid-after-rotation" {
                assert_ne!(content.manifest().signer(), verified.issuer().key());
                let json: Value = serde_json::from_str(str_at(case, "grant_text")).unwrap();
                let body: GrantBodyV2 = serde_json::from_value(json["body"].clone()).unwrap();
                assert_eq!(hex(&grant_message(&body).unwrap()), str_at(&vectors, "signed_message_hex"));
                assert_eq!(hex(&grant_wrap_context(&body).unwrap()), str_at(&vectors, "wrap_context_hex"));
                assert_eq!(verified.entitlement().wrapped_content_key().context(),
                           grant_wrap_context(&body).unwrap().as_slice());
            }
            positive += 1;
        } else {
            let err = res.expect_err(&format!("{name}: expected Python denial"));
            assert_eq!(err.category(), expected_cat, "{name} category");
            assert_eq!(err.reason(), expected_reason, "{name} reason");
        }
    }
    assert!(positive >= 2, "rotated grant + pre-revocation grant must pass");
}
