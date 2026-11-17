//! S2 key lifecycle v2.1 and replica-receipt/v2 tests. Every transition,
//! revocation, receipt, package, grant and licence here was produced by
//! Holochain Music's own Python code at a pinned commit
//! (`scripts/generate_music_key_lifecycle_vectors.py`), together with Music's
//! verdict for every query. A committed run lets these run everywhere;
//! `MUSIC_KEY_LIFECYCLE_VECTORS` points at a fresh one.

use crate::binding::*;
use crate::entitlements::{
    check_content_access_with_lifecycle, AccessError, AuthenticatedSubject, Unauthenticated,
};
use crate::lifecycle::*;
use crate::receipt_v2::*;
use crate::Right;
use serde_json::{json, Value};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const COMMITTED: &str = include_str!("../testdata/music-key-lifecycle-v21-vectors.json");

fn vectors() -> Value {
    let text = match std::env::var("MUSIC_KEY_LIFECYCLE_VECTORS") {
        Ok(path) => {
            let path = std::path::PathBuf::from(path);
            let path = if path.is_absolute() {
                path
            } else {
                std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../..")
                    .join(path)
            };
            std::fs::read_to_string(path).expect("read MUSIC_KEY_LIFECYCLE_VECTORS")
        }
        Err(_) => COMMITTED.to_owned(),
    };
    let v: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(
        v["schema"],
        "holochain-media-core/music-key-lifecycle-v21-vectors/v1"
    );
    v
}

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v[k].as_str()
        .unwrap_or_else(|| panic!("missing {k} in {v}"))
}

fn purpose(text: &str) -> KeyPurpose {
    match text {
        "owner-manifest" => KeyPurpose::OwnerManifest,
        "host-receipt" => KeyPurpose::HostReceipt,
        other => panic!("{other}"),
    }
}

fn hex32(text: &str) -> [u8; 32] {
    strict_hex::<32>(text).unwrap_or_else(|| panic!("hex {text}"))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A conductor record as the vectors model it (author, action, chain position).
fn record(r: &Value) -> Option<ConductorRecord> {
    let author = s(r, "author");
    let action = s(r, "action_hash");
    match r["action_seq"].as_u64() {
        Some(seq) => ConductorRecord::from_validated_conductor_at(
            author,
            action,
            u32::try_from(seq).unwrap(),
            r["body"].clone(),
        )
        .ok(),
        None => ConductorRecord::from_validated_conductor(author, action, r["body"].clone()).ok(),
    }
}

fn records(list: &Value) -> Vec<ConductorRecord> {
    list.as_array()
        .unwrap()
        .iter()
        .map(|r| record(r).expect("vector record"))
        .collect()
}

fn anchor(v: &Value, agent_records: &[ConductorRecord]) -> Option<ChainAnchor> {
    if v.is_null() {
        return None;
    }
    // Anchors are positions of agent-authored records; model one.
    let _ = agent_records;
    let r = ConductorRecord::from_validated_conductor_at(
        s(v, "author"),
        "uhCkkAnchor",
        u32::try_from(v["action_seq"].as_u64().unwrap()).unwrap(),
        json!({"schema": "holochain-storage/file-commitment/v1"}),
    )
    .unwrap();
    Some(ChainAnchor::from_record(&r).unwrap())
}

fn key_use(use_text: &str, anchor: Option<ChainAnchor>) -> KeyUse {
    match use_text {
        "new-operation" => {
            assert!(anchor.is_none());
            KeyUse::NewOperation
        }
        "historical" => KeyUse::Historical { anchor },
        other => panic!("{other}"),
    }
}

fn verdict(text: &str) -> KeyValidity {
    match text {
        "Active" => KeyValidity::Active,
        "Rotated" => KeyValidity::Rotated,
        "Revoked" => KeyValidity::Revoked,
        "HistoricalOnly" => KeyValidity::HistoricalOnly,
        "Ambiguous" => KeyValidity::Ambiguous,
        "Invalid" => KeyValidity::Invalid,
        other => panic!("{other}"),
    }
}

fn continuity(text: &str) -> KeyContinuity {
    match text {
        "inception" => KeyContinuity::Inception,
        "rotation" => KeyContinuity::Rotation,
        "recovered-without-continuity" => KeyContinuity::RecoveredWithoutContinuity,
        other => panic!("{other}"),
    }
}

#[test]
fn signed_messages_match_music_byte_for_byte() {
    let v = vectors();
    let g2 = &v["lifecycle"]["alice_g2"]["body"];
    for (role, field) in [
        (ROLE_SUCCESSOR, "rotation_successor_hex"),
        (ROLE_PREDECESSOR, "rotation_predecessor_hex"),
    ] {
        let message = key_transition_v21_message(
            role,
            s(g2, "dna_hash"),
            s(g2, "agent"),
            s(g2, "purpose"),
            s(g2, "generation"),
            s(g2, "kind"),
            s(g2, "signing_key_hex"),
            s(g2, "predecessor_action"),
            s(g2, "predecessor_key_hex"),
        );
        assert_eq!(hex(&message), s(&v["messages"], field), "{field}");
    }
    let receipt: Value = serde_json::from_str(s(&v["content"], "carol_receipt_text")).unwrap();
    let fields = RECEIPT_V2_SIGNED_FIELDS.map(|f| s(&receipt, f));
    let message = replica_receipt_v2_message(&fields);
    assert_eq!(hex(&message), s(&v["messages"], "receipt_v2_hex"));
    use sha2::{Digest, Sha256};
    assert_eq!(
        hex(&Sha256::digest(&message)),
        s(&v["messages"], "receipt_v2_digest")
    );
    // Domain separation from every other Music/Media Core signing domain.
    assert!(!message.starts_with(b"{"));
    assert!(!message.starts_with(KEY_BINDING_POP_DOMAIN_V2));
    assert!(!message.starts_with(KEY_LIFECYCLE_DOMAIN_V21));
}

#[test]
fn every_lifecycle_verdict_matches_music() {
    let v = vectors();
    let dna = s(&v, "dna_hash");
    let mut checked = 0;
    for scenario in v["scenarios"].as_array().unwrap() {
        let name = s(scenario, "name");
        let agent = s(scenario, "agent");
        let purpose = purpose(s(scenario, "purpose"));
        let list: Vec<ConductorRecord> = scenario["records"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(record)
            .collect();
        let resolved = resolve_key_lifecycle(&list, agent, purpose, dna);
        let python = &scenario["python"];
        match s(python, "result") {
            "resolved" => {
                let lifecycle = resolved.unwrap_or_else(|e| panic!("{name}: {e:?}"));
                let generations = python["generations"].as_array().unwrap();
                assert_eq!(lifecycle.generations().len(), generations.len(), "{name}");
                for (g, p) in lifecycle.generations().iter().zip(generations) {
                    assert_eq!(u64::from(g.generation()), p["generation"].as_u64().unwrap());
                    assert_eq!(hex(g.key()), s(p, "key_hex"), "{name}");
                    assert_eq!(g.action_hash(), s(p, "action_hash"), "{name}");
                    assert_eq!(g.continuity(), continuity(s(p, "continuity")), "{name}");
                    let scopes: Vec<&str> = g.revocations().iter().map(|r| r.as_str()).collect();
                    let expected: Vec<&str> = p["revocations"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|x| x.as_str().unwrap())
                        .collect();
                    assert_eq!(scopes, expected, "{name}");
                }
                match python["active_key_hex"].as_str() {
                    Some(k) => assert_eq!(hex(lifecycle.active().unwrap().key()), k, "{name}"),
                    None => assert_eq!(lifecycle.active(), Err(BindingError::KeyRevoked), "{name}"),
                }
            }
            "error" => {
                let error = resolved.expect_err(name);
                let expected = verdict(s(python, "verdict"));
                assert_eq!(
                    expected == KeyValidity::Ambiguous,
                    error == BindingError::Ambiguous,
                    "{name}: {error:?}"
                );
            }
            other => panic!("{other}"),
        }
        for q in scenario["queries"].as_array().unwrap() {
            let key = hex32(s(q, "key_hex"));
            let use_ = key_use(s(q, "use"), anchor(&q["anchor"], &list));
            assert_eq!(
                evaluate_key(&list, agent, purpose, dna, &key, &use_),
                verdict(s(q, "python")),
                "{name}: {q}"
            );
            checked += 1;
        }
    }
    assert!(checked >= 150, "only {checked} queries");
}

#[test]
fn missing_chain_position_is_never_resolved() {
    let v = vectors();
    let g1 = &v["lifecycle"]["alice_g1"];
    let unsequenced = ConductorRecord::from_validated_conductor(
        s(g1, "author"),
        s(g1, "action_hash"),
        g1["body"].clone(),
    )
    .unwrap();
    assert_eq!(
        resolve_key_lifecycle(
            &[unsequenced],
            s(&v["agents"], "alice"),
            KeyPurpose::OwnerManifest,
            s(&v, "dna_hash")
        ),
        Err(BindingError::MissingRecord)
    );
}

#[test]
fn assurance_continuity_and_policy_reads() {
    let v = vectors();
    let dna = s(&v, "dna_hash").to_owned();
    let alice = s(&v["agents"], "alice");
    let l = &v["lifecycle"];
    let rotated = records(&json!([l["alice_g1"], l["alice_g2"]]));
    let lifecycle =
        resolve_key_lifecycle(&rotated, alice, KeyPurpose::OwnerManifest, &dna).unwrap();
    let active = lifecycle.active().unwrap();
    assert_eq!(active.assurance(), BindingAssurance::KeyLifecycleV21);
    assert_eq!(active.generation(), 2);
    assert_eq!(active.continuity(), KeyContinuity::Rotation);
    assert!(require_proof_of_possession(&active).is_ok());
    // The policy-driven resolver returns the active generation only and never
    // reads v1/v2 records.
    let policy = KeyBindingPolicy::KeyLifecycleV21 {
        dna_hash: dna.clone(),
    };
    let via_policy =
        resolve_signing_key(&rotated, alice, KeyPurpose::OwnerManifest, &policy).unwrap();
    assert_eq!(via_policy, active);
    let v1 = ConductorRecord::from_validated_conductor(
        alice,
        "uhCkkV1",
        json!({"schema": KEY_BINDING_V1, "agent": alice, "purpose": "owner-manifest",
               "signing_key_hex": s(&v["keys"], "alice_g1")}),
    )
    .unwrap();
    assert_eq!(
        resolve_signing_key(&[v1], alice, KeyPurpose::OwnerManifest, &policy),
        Err(BindingError::MissingRecord),
        "v2.1 never falls back to v1"
    );
    // A recovered lineage is labelled and ranked below a continuous one.
    let scenario = v["scenarios"]
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["name"] == "lost_key_recovery")
        .unwrap();
    let recovered = resolve_key_lifecycle(
        &records(&scenario["records"]),
        alice,
        KeyPurpose::OwnerManifest,
        &dna,
    )
    .unwrap()
    .active()
    .unwrap();
    assert_eq!(
        recovered.continuity(),
        KeyContinuity::RecoveredWithoutContinuity
    );
    assert_eq!(
        recovered.assurance(),
        BindingAssurance::KeyLifecycleRecoveredV21
    );
    assert!(BindingAssurance::KeyLifecycleRecoveredV21 < BindingAssurance::KeyLifecycleV21);
    assert!(BindingAssurance::ProofOfPossessionV2 < BindingAssurance::KeyLifecycleRecoveredV21);
    // authorize() maps validity to errors; it never returns a stale key.
    let a1 = hex32(s(&v["keys"], "alice_g1"));
    assert_eq!(
        lifecycle.authorize(&a1, &KeyUse::NewOperation),
        Err(BindingError::KeyRotated)
    );
    let historical = lifecycle
        .authorize(&a1, &KeyUse::Historical { anchor: None })
        .unwrap();
    assert_eq!(historical.validity(), KeyValidity::HistoricalOnly);
    assert_eq!(historical.generation(), 1);
}

fn owned(
    v: &Value,
    which: &str,
    lifecycle: &KeyLifecycle,
    seq: u32,
) -> Result<OwnedManifest, BindingError> {
    let c = &v["content"];
    let alice = s(&v["agents"], "alice");
    let commitment = ConductorRecord::from_validated_conductor_at(
        alice,
        "uhCkkCommitment",
        seq,
        json!({"schema": FILE_COMMITMENT_V1, "owner_agent": alice,
               "file_id": s(c, &format!("{which}_file_id")),
               "manifest_sha256": s(c, &format!("{which}_manifest_sha256"))}),
    )
    .unwrap();
    verify_owned_manifest_lifecycle(
        s(c, &format!("{which}_manifest_text")).as_bytes(),
        lifecycle,
        &commitment,
    )
}

fn alice_lifecycle(v: &Value, names: &[&str]) -> KeyLifecycle {
    let l = &v["lifecycle"];
    let list: Vec<ConductorRecord> = names.iter().map(|n| record(&l[*n]).unwrap()).collect();
    resolve_key_lifecycle(
        &list,
        s(&v["agents"], "alice"),
        KeyPurpose::OwnerManifest,
        s(v, "dna_hash"),
    )
    .unwrap()
}

#[test]
fn historical_content_and_new_content_after_rotation() {
    let v = vectors();
    let rotated = alice_lifecycle(&v, &["alice_g1", "alice_g2"]);
    // Old content, committed while generation 1 was active (seq 10 < 20).
    let old = owned(&v, "old", &rotated, 10).unwrap();
    assert_eq!(old.owner_key_generation(), 1);
    assert_eq!(old.owner_key_validity(), KeyValidity::HistoricalOnly);
    assert_eq!(old.owner_assurance(), BindingAssurance::KeyLifecycleV21);
    // The same old-key manifest committed AFTER the rotation is a new
    // operation with a rotated key.
    assert_eq!(
        owned(&v, "old", &rotated, 25),
        Err(BindingError::KeyRotated)
    );
    // New content uses the replacement key.
    let new = owned(&v, "new", &rotated, 25).unwrap();
    assert_eq!(new.owner_key_generation(), 2);
    assert_eq!(new.owner_key_validity(), KeyValidity::Active);
    // Before the rotation existed, generation 2 is not Alice's key.
    let before = alice_lifecycle(&v, &["alice_g1"]);
    assert_eq!(
        owned(&v, "new", &before, 25),
        Err(BindingError::KeyNotBound)
    );
    // Retired gen-1 key: history still verifies; compromised: only anchored.
    let retired = alice_lifecycle(
        &v,
        &["alice_g1", "alice_g2", "alice_revoke_g1_new_operations"],
    );
    assert!(owned(&v, "old", &retired, 10).is_ok());
    let compromised = alice_lifecycle(
        &v,
        &[
            "alice_g1",
            "alice_g2",
            "alice_revoke_g1_new_operations",
            "alice_revoke_g1_compromised",
        ],
    );
    assert!(owned(&v, "old", &compromised, 10).is_ok());
    assert_eq!(
        owned(&v, "old", &compromised, 25),
        Err(BindingError::KeyRevoked)
    );
}

fn bob(v: &Value) -> AuthenticatedSubject {
    AuthenticatedSubject::from_trusted_context(
        s(&v["agents"], "bob"),
        hex32(s(&v["keys"], "bob_x25519")),
    )
    .unwrap()
}

fn at(v: &Value) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(v["content"]["now"].as_u64().unwrap())
}

#[test]
fn core005_licences_survive_rotation_but_not_compromise() {
    let v = vectors();
    let rotated = alice_lifecycle(&v, &["alice_g1", "alice_g2"]);
    let old = owned(&v, "old", &rotated, 10).unwrap();
    let licence = s(&v["content"], "old_licence_text").as_bytes();
    let decision = check_content_access_with_lifecycle(
        &old,
        &bob(&v),
        licence,
        Right::Stream,
        at(&v),
        &rotated,
    )
    .unwrap();
    let _ = decision;
    let new = owned(&v, "new", &rotated, 25).unwrap();
    check_content_access_with_lifecycle(
        &new,
        &bob(&v),
        s(&v["content"], "new_grant_text").as_bytes(),
        Right::Stream,
        at(&v),
        &rotated,
    )
    .unwrap();
    // After a compromise revocation an unanchored licence by that key is
    // indistinguishable from a forgery made with the stolen key.
    let compromised = alice_lifecycle(&v, &["alice_g1", "alice_g2", "alice_revoke_g1_compromised"]);
    assert_eq!(
        check_content_access_with_lifecycle(
            &old,
            &bob(&v),
            licence,
            Right::Stream,
            at(&v),
            &compromised
        )
        .unwrap_err(),
        AccessError::Unauthenticated(Unauthenticated::IssuerKeyRevoked)
    );
    // A lifecycle of the wrong agent or purpose is refused outright.
    let carol = resolve_key_lifecycle(
        &[record(&v["lifecycle"]["carol_g1"]).unwrap()],
        s(&v["agents"], "carol"),
        KeyPurpose::HostReceipt,
        s(&v, "dna_hash"),
    )
    .unwrap();
    assert_eq!(
        check_content_access_with_lifecycle(&old, &bob(&v), licence, Right::Stream, at(&v), &carol)
            .unwrap_err(),
        AccessError::Unauthenticated(Unauthenticated::IssuerNotInLifecycle)
    );
}

#[test]
fn every_receipt_verdict_matches_music() {
    let v = vectors();
    let alice_lc = alice_lifecycle(&v, &["alice_g1"]);
    let old = owned(&v, "old", &alice_lc, 10).unwrap();
    let dna = s(&v, "dna_hash");
    let mut accepted = 0;
    for case in v["receipts"].as_array().unwrap() {
        let name = s(case, "name");
        let host_agent = s(case, "host_agent");
        let host = resolve_key_lifecycle(
            &records(&case["host_records"]),
            host_agent,
            KeyPurpose::HostReceipt,
            dna,
        )
        .unwrap();
        let use_ = key_use(s(case, "use"), anchor(&case["anchor"], &[]));
        let bytes = serde_json::to_vec(&case["receipt"]).unwrap();
        let result = verify_replica_receipt_v2(&bytes, &old, &host, &use_);
        match s(&case["python"], "verdict") {
            "accepted" => {
                let r = result.unwrap_or_else(|e| panic!("{name}: {e:?}"));
                assert_eq!(hex(r.digest()), s(&case["python"], "digest"), "{name}");
                assert_eq!(r.host_agent(), host_agent);
                accepted += 1;
            }
            "rejected" => {
                assert!(
                    result.is_err(),
                    "{name}: accepted by Rust, rejected by Music"
                );
            }
            other => panic!("{other}"),
        }
    }
    assert_eq!(accepted, 4);
}

#[test]
fn host_attributed_replica_claims() {
    let v = vectors();
    let dna = s(&v, "dna_hash");
    let alice_lc = alice_lifecycle(&v, &["alice_g1"]);
    let old = owned(&v, "old", &alice_lc, 10).unwrap();
    let carol = s(&v["agents"], "carol");
    let host = resolve_key_lifecycle(
        &[record(&v["lifecycle"]["carol_g1"]).unwrap()],
        carol,
        KeyPurpose::HostReceipt,
        dna,
    )
    .unwrap();
    let receipt = s(&v["content"], "carol_receipt_text").as_bytes();
    let claim = |author: &str, digest: &str, seq: u32| {
        ConductorRecord::from_validated_conductor_at(
            author,
            "uhCkkClaim",
            seq,
            json!({"schema": REPLICA_CLAIM_V1, "node_agent": author,
                   "owner_agent": s(&v["agents"], "alice"),
                   "file_id": s(&v["content"], "old_file_id"),
                   "manifest_sha256": s(&v["content"], "old_manifest_sha256"),
                   "receipt_sha256": digest}),
        )
        .unwrap()
    };
    let digest = s(&v["messages"], "receipt_v2_digest");
    let replica = verify_replica_claim_v2(receipt, &old, &host, &claim(carol, digest, 8)).unwrap();
    assert_eq!(replica.attribution(), ReceiptAttribution::HostAttributedV2);
    assert_eq!(replica.node_agent(), carol);
    assert_eq!(hex(replica.receipt().envelope_sha256()), digest);
    assert_eq!(replica.receipt_v2().unwrap().host_key_generation(), 1);
    assert!(require_host_attribution(&replica).is_ok());
    // Claim for a different receipt, or authored by someone else.
    assert_eq!(
        verify_replica_claim_v2(receipt, &old, &host, &claim(carol, &"00".repeat(32), 8))
            .unwrap_err(),
        BindingError::ClaimMismatch
    );
    assert_eq!(
        verify_replica_claim_v2(
            receipt,
            &old,
            &host,
            &claim(s(&v["agents"], "mallory"), digest, 8)
        )
        .unwrap_err(),
        BindingError::AuthorMismatch
    );
    // A legacy S1 receipt is verified only by the legacy path and is labelled.
    let legacy = s(&v["content"], "legacy_receipt_text").as_bytes();
    assert!(verify_replica_claim_v2(legacy, &old, &host, &claim(carol, digest, 8)).is_err());
    let carol_v1 = ConductorRecord::from_validated_conductor(
        carol,
        "uhCkkCarolV1",
        json!({"schema": KEY_BINDING_V1, "agent": carol, "purpose": "host-receipt",
               "signing_key_hex": s(&v["keys"], "carol_g1")}),
    )
    .unwrap();
    let legacy_key = verify_key_binding_v1(&carol_v1, carol, KeyPurpose::HostReceipt).unwrap();
    let legacy_digest = {
        use sha2::{Digest, Sha256};
        hex(&Sha256::digest(legacy))
    };
    let legacy_replica = verify_replica_claim_with_key(
        legacy,
        &old,
        carol,
        &legacy_key,
        &claim(carol, &legacy_digest, 8),
    )
    .unwrap();
    assert_eq!(
        legacy_replica.attribution(),
        ReceiptAttribution::LegacyUnattributedV1
    );
    assert_eq!(
        require_host_attribution(&legacy_replica).unwrap_err(),
        BindingError::InsufficientReceiptAttribution
    );
    assert_eq!(
        legacy_replica.node_assurance(),
        BindingAssurance::LegacyAuthoredV1
    );
}

#[test]
fn every_grant_anchor_verdict_matches_music() {
    use crate::grant_anchor::*;
    let v = vectors();
    let alice = s(&v["agents"], "alice");
    let dna = s(&v, "dna_hash");
    let cases = v["grant_anchors"].as_array().unwrap();
    assert!(cases.len() >= 16);
    let mut accepted = 0;
    for case in cases {
        let name = s(case, "name");
        let owner = resolve_key_lifecycle(
            &records(&case["lifecycle"]),
            alice,
            KeyPurpose::OwnerManifest,
            dna,
        )
        .unwrap_or_else(|e| panic!("{name}: {e:?}"));
        let anchor = record(&case["record"]).unwrap();
        let message: Vec<u8> = (0..s(&case["claim"], "grant_message_hex").len())
            .step_by(2)
            .map(|i| {
                u8::from_str_radix(&s(&case["claim"], "grant_message_hex")[i..i + 2], 16).unwrap()
            })
            .collect();
        let claim = GrantAnchorClaim {
            grant_id: s(&case["claim"], "grant_id"),
            grant_message: &message,
            issuer_key_action: s(&case["claim"], "issuer_key_action"),
        };
        let policy = match s(case, "policy") {
            "reject" => RecoveredIssuerPolicy::Reject,
            "accept" => RecoveredIssuerPolicy::Accept,
            other => panic!("{other}"),
        };
        let result = verify_grant_anchor_v2(&anchor, &owner, &claim, policy);
        match s(&case["python"], "verdict") {
            "accepted" => {
                let a = result.unwrap_or_else(|e| panic!("{name}: Rust refused: {e:?}"));
                assert_eq!(
                    u64::from(a.issuer().generation()),
                    case["python"]["generation"].as_u64().unwrap(),
                    "{name}"
                );
                accepted += 1;
            }
            "rejected" => assert!(result.is_err(), "{name}: Rust accepted, Music refused"),
            other => panic!("{other}"),
        }
    }
    assert_eq!(accepted, 4);
    // The default policy is fail-closed.
    assert_eq!(
        RecoveredIssuerPolicy::default(),
        RecoveredIssuerPolicy::Reject
    );
}
