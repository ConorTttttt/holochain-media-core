//! CORE-005 tests.
//!
//! Every signed grant, licence and manifest used here was produced by Holochain
//! Music's own Python code at the pinned commit
//! (`scripts/generate_music_entitlement_vectors.py`). The Rust evaluator never
//! signs anything to test itself. A copy of one generator run is committed as
//! `testdata/music-entitlement-vectors.json` so these tests run on every
//! platform without Python; CI regenerates fresh vectors from the pinned Music
//! source and runs the same tests against them via `MUSIC_ENTITLEMENT_VECTORS`.

use crate::binding::{
    verify_owned_manifest, ConductorRecord, OwnedManifest, FILE_COMMITMENT_V1, KEY_BINDING_V1,
};
use crate::entitlements::*;
use crate::{Right, Rights};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const COMMITTED: &str = include_str!("../testdata/music-entitlement-vectors.json");

fn vectors() -> Value {
    let text = match std::env::var("MUSIC_ENTITLEMENT_VECTORS") {
        Ok(path) => {
            let path = std::path::PathBuf::from(path);
            let path = if path.is_absolute() {
                path
            } else {
                std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../..")
                    .join(path)
            };
            std::fs::read_to_string(path).expect("read MUSIC_ENTITLEMENT_VECTORS")
        }
        Err(_) => COMMITTED.to_owned(),
    };
    let v: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(
        v["schema"],
        "holochain-media-core/music-entitlement-vectors/v1"
    );
    assert_eq!(
        v["music_commit"], "bd7aabc3e9ea1fef1e8e8f674301e1b5ffecb637",
        "vectors must come from the pinned Music reference"
    );
    v
}

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v[k].as_str().unwrap_or_else(|| panic!("missing {k}"))
}

fn hex32(text: &str) -> [u8; 32] {
    let id: crate::PackageId = text.parse().unwrap();
    *id.as_bytes()
}

fn record(author: &str, body: Value) -> ConductorRecord {
    ConductorRecord::from_validated_conductor(author, "uhCkkCore005Action", body).unwrap()
}

/// CORE-004 authenticated content: Alice's Holochain-authored key binding and
/// file commitment, plus Music's Python-signed manifest.
fn owned(v: &Value, name: &str) -> OwnedManifest {
    let c = &v["content"][name];
    let owner = s(c, "owner_agent");
    let key_binding = record(
        owner,
        json!({"schema": KEY_BINDING_V1, "agent": owner, "purpose": "owner-manifest",
               "signing_key_hex": v["keys"]["alice_ed25519_public_hex"]}),
    );
    let commitment = record(
        owner,
        json!({"schema": FILE_COMMITMENT_V1, "owner_agent": owner,
               "file_id": c["file_id"], "manifest_sha256": c["manifest_sha256"]}),
    );
    verify_owned_manifest(
        s(c, "manifest_text").as_bytes(),
        owner,
        &key_binding,
        &commitment,
    )
    .unwrap()
}

fn at(seconds: i64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(u64::try_from(seconds).unwrap())
}

fn right(name: &str) -> Right {
    match name {
        "stream" => Right::Stream,
        "managed-offline" => Right::ManagedOffline,
        "export" => Right::Export,
        other => panic!("unknown right {other}"),
    }
}

fn subject(c: &Value) -> AuthenticatedSubject {
    AuthenticatedSubject::from_trusted_context(
        s(&c["subject"], "listener_agent"),
        hex32(s(&c["subject"], "recipient_key_hex")),
    )
    .unwrap()
}

fn evaluate(v: &Value, c: &Value) -> Result<AccessDecision, AccessError> {
    check_content_access(
        &owned(v, s(c, "content")),
        &subject(c),
        s(c, "grant_text").as_bytes(),
        right(s(c, "right")),
        at(c["now"].as_i64().unwrap()),
    )
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The core cross-language test: Rust's decision and classification for every
/// Python-generated case, compared with Music's own verdict.
#[test]
fn python_generated_grants_and_licences_match_music() {
    let v = vectors();
    let cases = v["cases"].as_array().unwrap();
    assert!(cases.len() >= 80, "vector set unexpectedly small");
    let mut failures = Vec::new();
    for c in cases {
        let name = s(c, "name");
        let result = evaluate(&v, c);
        let expect = &c["expect"];
        let python = &c["python"];
        let python_authorised =
            python["unwrap"] == "ok" && python["right_allowed"].as_bool().unwrap();
        // 1. Rust matches the expected decision and the exact reason.
        match (&result, s(expect, "decision")) {
            (Ok(decision), "authorized") => {
                let e = decision.entitlement();
                let body: Value = serde_json::from_str(s(c, "grant_text")).unwrap();
                let body = &body["body"];
                if hex(e.wrapped_content_key().context()) != s(c, "python_hkdf_context_hex") {
                    failures.push(format!("{name}: HKDF context differs from Python"));
                }
                if e.issued_at() != body["issued_at"].as_i64().unwrap()
                    || e.expires_at() != body["expires_at"].as_i64()
                    || e.licence_id() != body["licence_id"].as_str()
                    || e.listener_agent() != s(&c["subject"], "listener_agent")
                    || e.manifest_digest().to_string()
                        != s(&v["content"][s(c, "content")], "manifest_sha256")
                    || hex(e.wrapped_content_key().ephemeral_public())
                        != s(body, "ephemeral_key_hex")
                {
                    failures.push(format!(
                        "{name}: verified fields differ from the signed body"
                    ));
                }
            }
            (Err(error), "rejected") => {
                if error.category() != s(expect, "category")
                    || error.reason() != s(expect, "reason")
                {
                    failures.push(format!(
                        "{name}: expected {}/{}, got {}/{}",
                        s(expect, "category"),
                        s(expect, "reason"),
                        error.category(),
                        error.reason()
                    ));
                }
            }
            (other, wanted) => failures.push(format!("{name}: expected {wanted}, got {other:?}")),
        }
        // 2. Rust agrees with Music's verdict except where documented.
        let rust_authorised = result.is_ok();
        match c["divergence"].as_str() {
            None if rust_authorised != python_authorised => failures.push(format!(
                "{name}: Rust {rust_authorised} but Music {python_authorised} ({python})"
            )),
            Some("key-unwrap-boundary") if !(rust_authorised && python["unwrap"] == "rejected") => {
                failures.push(format!("{name}: not a key-unwrap-boundary case"))
            }
            Some(
                "rust-rejects-duplicate-json-keys"
                | "rust-caps-raw-input-at-music-library-read-limit"
                | "python-accepts-out-of-range-licence-issued-at",
            ) if !(python_authorised && !rust_authorised) => {
                failures.push(format!("{name}: documented divergence no longer holds"))
            }
            None
            | Some(
                "key-unwrap-boundary"
                | "rust-rejects-duplicate-json-keys"
                | "rust-caps-raw-input-at-music-library-read-limit"
                | "python-accepts-out-of-range-licence-issued-at",
            ) => {}
            Some(other) => failures.push(format!("{name}: unknown divergence {other}")),
        }
        // 3. Successful Python unwraps recover the exact content key.
        if python["unwrap"] == "ok" {
            assert_eq!(python["unwrapped_key_matches_content_key"], true, "{name}");
        }
    }
    assert!(
        failures.is_empty(),
        "{} mismatches:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// The CORE-005 required matrix must stay covered by the generated vectors.
#[test]
fn required_security_matrix_is_covered() {
    let v = vectors();
    let names: BTreeSet<&str> = v["cases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| s(c, "name"))
        .collect();
    for required in [
        "stream_grant_valid_for_stream",
        "licence_valid_for_export",
        "licence_valid_for_managed_offline",
        "stream_grant_expired_at_expires_at",
        "stream_grant_issued_in_future_beyond_skew",
        "grant_signed_by_mallory_key",
        "wrong_owner_agent_in_alice_signed_grant",
        "wrong_listener_agent",
        "wrong_recipient_public_key",
        "wrong_file_id_resigned",
        "wrong_manifest_digest_resigned",
        "modified_listener_without_resign",
        "forged_signature_under_alice_signer",
        "licence_unknown_terms",
        "stream_grant_does_not_confer_export",
        "stream_grant_string_timestamp",
        "unsupported_schema_version",
        "legacy_personal_perpetual_grant_v1",
        "unexpected_body_field",
        "duplicate_body_key_signed_value_last",
        "oversized_canonical_grant",
        "wrapped_key_wrong_length_resigned",
        "wrapped_key_corrupted_but_owner_signed",
        "truncated_envelope",
        "mallory_presents_bobs_grant",
        "mallory_substitutes_her_own_package_grant",
        "replay_grant_for_other_package",
    ] {
        assert!(names.contains(required), "missing vector {required}");
    }
}

fn case<'a>(v: &'a Value, name: &str) -> &'a Value {
    v["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == name)
        .unwrap_or_else(|| panic!("no case {name}"))
}

#[test]
fn rights_mapping_is_explicit_and_versioned() {
    assert_eq!(
        EntitlementScheme::MusicContentGrantV1.rights(),
        Rights::STREAM
    );
    let licence = EntitlementScheme::MusicPersonalLicenceV1.rights();
    assert!(licence.contains(Right::Stream));
    assert!(licence.contains(Right::ManagedOffline));
    assert!(licence.contains(Right::Export));
    assert!(EntitlementScheme::MusicContentGrantV1.expires());
    assert!(!EntitlementScheme::MusicPersonalLicenceV1.expires());
    assert_eq!(
        EntitlementScheme::from_schema(MUSIC_CONTENT_GRANT_V1),
        Ok(EntitlementScheme::MusicContentGrantV1)
    );
    assert_eq!(
        EntitlementScheme::from_schema(MUSIC_PERSONAL_LICENCE_V1),
        Ok(EntitlementScheme::MusicPersonalLicenceV1)
    );
    assert_eq!(
        EntitlementScheme::from_schema(MUSIC_LEGACY_PERPETUAL_GRANT_V1),
        Err(Unsupported::LegacyPerpetualGrant)
    );
    for unknown in [
        "",
        "holochain-music/content-grant/v2",
        "holochain-music/public/v1",
    ] {
        assert_eq!(
            EntitlementScheme::from_schema(unknown),
            Err(Unsupported::UnknownSchema)
        );
    }
}

#[test]
fn streaming_grant_confers_only_stream_and_licence_all_three() {
    let v = vectors();
    let grant = case(&v, "stream_grant_valid_for_stream");
    let licence = case(&v, "licence_valid_for_export");
    for (c, allowed) in [(grant, [true, false, false]), (licence, [true, true, true])] {
        let verified = verify_entitlement(
            &owned(&v, "p"),
            &subject(c),
            s(c, "grant_text").as_bytes(),
            at(c["now"].as_i64().unwrap()),
        )
        .unwrap();
        for (r, ok) in [Right::Stream, Right::ManagedOffline, Right::Export]
            .into_iter()
            .zip(allowed)
        {
            let decision = verified.clone().authorize(r);
            assert_eq!(decision.is_ok(), ok, "{r:?}");
            if let Ok(d) = decision {
                assert_eq!(d.right(), r);
            } else {
                assert_eq!(
                    decision.unwrap_err(),
                    AccessError::Denied(Denied::RightNotGranted)
                );
            }
        }
    }
}

#[test]
fn time_policy_boundaries_use_the_injected_clock() {
    let v = vectors();
    let c = case(&v, "stream_grant_valid_for_stream");
    let body: Value = serde_json::from_str(s(c, "grant_text")).unwrap();
    let issued = body["body"]["issued_at"].as_i64().unwrap();
    let expires = body["body"]["expires_at"].as_i64().unwrap();
    let check = |now: i64| {
        check_content_access(
            &owned(&v, "p"),
            &subject(c),
            s(c, "grant_text").as_bytes(),
            Right::Stream,
            at(now),
        )
    };
    assert!(check(issued - CLOCK_SKEW_SECONDS).is_ok());
    assert_eq!(
        check(issued - CLOCK_SKEW_SECONDS - 1).unwrap_err(),
        AccessError::Validity(Validity::NotYetValid)
    );
    assert!(check(expires - 1).is_ok());
    let expired = check(expires).unwrap_err();
    assert!(expired.is_expired());
    assert_eq!(expired.category(), "validity");
    // Sub-second clocks floor like Python `int(time.time())`.
    let just_before = at(expires - 1) + Duration::from_millis(999);
    assert!(check_content_access(
        &owned(&v, "p"),
        &subject(c),
        s(c, "grant_text").as_bytes(),
        Right::Stream,
        just_before,
    )
    .is_ok());
    // Licences never expire, and do not depend on the clock beyond "not
    // issued in the future". Use a far-future instant (9999-12-31T23:59:59Z)
    // representable on Windows as well as Unix.
    let l = case(&v, "licence_valid_for_export");
    for now in [issued, issued + 86_400 * 365 * 500, 253_402_300_799] {
        assert!(check_content_access(
            &owned(&v, "p"),
            &subject(l),
            s(l, "grant_text").as_bytes(),
            Right::Export,
            at(now),
        )
        .is_ok());
    }
}

#[test]
fn clock_before_unix_epoch_is_unavailable_not_denied() {
    let v = vectors();
    let c = case(&v, "licence_valid_for_export");
    let result = check_content_access(
        &owned(&v, "p"),
        &subject(c),
        s(c, "grant_text").as_bytes(),
        Right::Export,
        UNIX_EPOCH - Duration::from_secs(1),
    );
    assert_eq!(
        result.unwrap_err(),
        AccessError::Unavailable(Unavailable::Clock)
    );
}

#[test]
fn subject_context_is_validated() {
    let key = [7u8; 32];
    assert!(AuthenticatedSubject::from_trusted_context("uhCAkBob", key).is_ok());
    for bad in [String::new(), "a".repeat(161), "uhCAk\0Bob".to_owned()] {
        assert_eq!(
            AuthenticatedSubject::from_trusted_context(bad, key),
            Err(SubjectError::InvalidListenerAgent)
        );
    }
    let ok = AuthenticatedSubject::from_trusted_context("a".repeat(160), key).unwrap();
    assert_eq!(ok.recipient_key(), &key);
}

#[test]
fn oversized_input_is_rejected_before_parsing() {
    let v = vectors();
    let c = case(&v, "stream_grant_valid_for_stream");
    // Not JSON at all: the size cap must fire before the parser.
    let junk = vec![b'['; MAX_GRANT_INPUT_BYTES + 1];
    assert_eq!(
        check_content_access(&owned(&v, "p"), &subject(c), &junk, Right::Stream, at(0))
            .unwrap_err(),
        AccessError::Malformed(Malformed::TooLarge)
    );
    // Deep nesting within the cap is a bounded structure error, not a crash.
    let deep = format!("{}{}", "[".repeat(8000), "]".repeat(8000));
    let err = check_content_access(
        &owned(&v, "p"),
        &subject(c),
        deep.as_bytes(),
        Right::Stream,
        at(0),
    )
    .unwrap_err();
    assert_eq!(err.category(), "malformed");
    let deep_body = format!(
        "{{\"body\":{{\"schema\":\"{MUSIC_CONTENT_GRANT_V1}\",\"x\":{}{}}}}}",
        "[".repeat(5000),
        "]".repeat(5000)
    );
    assert_eq!(
        check_content_access(
            &owned(&v, "p"),
            &subject(c),
            deep_body.as_bytes(),
            Right::Stream,
            at(0)
        )
        .unwrap_err()
        .category(),
        "malformed"
    );
}

#[test]
fn non_utf8_and_binary_inputs_fail_closed() {
    let v = vectors();
    let c = case(&v, "stream_grant_valid_for_stream");
    for input in [
        &b"\xff\xfe{}"[..],
        b"\0",
        b"{\"body\":\"\xc3\x28\"}",
        b"null",
        b"{}",
    ] {
        let err = check_content_access(&owned(&v, "p"), &subject(c), input, Right::Stream, at(0))
            .unwrap_err();
        assert_eq!(err.category(), "malformed", "{input:?}");
    }
}

/// Byte-level mutation sweep over a genuine Python grant and licence: every
/// single-byte change and every truncation must be rejected, except a change
/// confined to the base64 padding bits of the unsigned `signer`/`signature`
/// encodings, which Music's `b64decode(validate=True)` also ignores.
#[test]
fn single_byte_mutations_and_truncations_never_authorise() {
    let v = vectors();
    for name in ["stream_grant_valid_for_stream", "licence_valid_for_export"] {
        let c = case(&v, name);
        let content = owned(&v, "p");
        let who = subject(c);
        let now = at(c["now"].as_i64().unwrap());
        let r = right(s(c, "right"));
        let original = s(c, "grant_text").as_bytes().to_vec();
        let parsed: Value = serde_json::from_slice(&original).unwrap();
        let reference = check_content_access(&content, &who, &original, r, now).unwrap();
        for len in 0..original.len() {
            assert!(
                check_content_access(&content, &who, &original[..len], r, now).is_err(),
                "{name}: truncation to {len} authorised"
            );
        }
        let mut accepted = 0;
        for i in 0..original.len() {
            for mask in [0x01u8, 0x20, 0x80] {
                let mut mutated = original.clone();
                mutated[i] ^= mask;
                if let Ok(decision) = check_content_access(&content, &who, &mutated, r, now) {
                    // Only an equivalent unsigned encoding may pass, and it
                    // must yield exactly the same verified entitlement.
                    let m: Value = serde_json::from_slice(&mutated).unwrap();
                    assert_eq!(m["body"], parsed["body"], "{name}: body changed at {i}");
                    assert_eq!(decision, reference, "{name}: different result at {i}");
                    accepted += 1;
                }
            }
        }
        // A handful of padding-bit-only variants exist; anything more would
        // indicate a parsing gap.
        assert!(accepted <= 8, "{name}: {accepted} mutations accepted");
    }
}

#[test]
fn error_categories_are_stable_strings() {
    let cases = [
        (AccessError::Malformed(Malformed::Json), "malformed", "Json"),
        (
            AccessError::Unauthenticated(Unauthenticated::InvalidSignature),
            "unauthenticated",
            "InvalidSignature",
        ),
        (
            AccessError::Unsupported(Unsupported::UnknownSchema),
            "unsupported",
            "UnknownSchema",
        ),
        (
            AccessError::Denied(Denied::RightNotGranted),
            "denied",
            "RightNotGranted",
        ),
        (
            AccessError::Validity(Validity::Expired),
            "validity",
            "Expired",
        ),
        (
            AccessError::Unavailable(Unavailable::Clock),
            "unavailable",
            "Clock",
        ),
    ];
    for (error, category, reason) in cases {
        assert_eq!(error.category(), category);
        assert_eq!(error.reason(), reason);
        assert_eq!(error.to_string(), format!("{category}: {reason}"));
        assert_eq!(error.is_expired(), reason == "Expired");
    }
}

/// CORE-004 → CORE-005 flow without any transport: the evaluator needs only
/// the Holochain-authenticated content and the local subject.
#[test]
fn access_evaluation_is_independent_of_transport_and_owner_records() {
    let v = vectors();
    let c = case(&v, "licence_valid_for_export");
    let content = owned(&v, "p");
    // Alice's key binding is what authenticates the grant issuer: a binding
    // for Mallory's key on the same package cannot be constructed, because
    // the manifest would then fail CORE-004 verification.
    let mallory_binding = record(
        s(&v["agents"], "alice"),
        json!({"schema": KEY_BINDING_V1, "agent": s(&v["agents"], "alice"),
               "purpose": "owner-manifest",
               "signing_key_hex": v["keys"]["mallory_ed25519_public_hex"]}),
    );
    let commitment = record(
        s(&v["agents"], "alice"),
        json!({"schema": FILE_COMMITMENT_V1, "owner_agent": s(&v["agents"], "alice"),
               "file_id": v["content"]["p"]["file_id"],
               "manifest_sha256": v["content"]["p"]["manifest_sha256"]}),
    );
    assert!(verify_owned_manifest(
        s(&v["content"]["p"], "manifest_text").as_bytes(),
        s(&v["agents"], "alice"),
        &mallory_binding,
        &commitment
    )
    .is_err());
    let decision = check_content_access(
        &content,
        &subject(c),
        s(c, "grant_text").as_bytes(),
        Right::Export,
        at(c["now"].as_i64().unwrap()),
    )
    .unwrap();
    let e = decision.entitlement();
    assert_eq!(e.scheme(), EntitlementScheme::MusicPersonalLicenceV1);
    assert_eq!(e.owner_agent(), content.owner_agent());
    assert_eq!(e.package_id(), content.manifest().package_id());
    assert_eq!(e.expires_at(), None);
    assert_eq!(e.licence_id().map(str::len), Some(32));
    assert_eq!(e.wrapped_content_key().wrapped_key().len(), 48);
}

/// CORE-004 finding 2 (no proof of possession): Mallory can bind Alice's
/// *public* key and commit Alice's package as her own, so CORE-004 yields an
/// `OwnedManifest` attributed to Mallory. Every grant Alice actually signed
/// names `owner_agent = Alice`, so none of them authorises access under
/// Mallory's attribution, and Mallory cannot sign one naming herself.
#[test]
fn unproven_key_binding_cannot_turn_alices_grants_into_mallorys() {
    let v = vectors();
    let mallory = s(&v["agents"], "mallory");
    let p = &v["content"]["p"];
    let key_binding = record(
        mallory,
        json!({"schema": KEY_BINDING_V1, "agent": mallory, "purpose": "owner-manifest",
               "signing_key_hex": v["keys"]["alice_ed25519_public_hex"]}),
    );
    let commitment = record(
        mallory,
        json!({"schema": FILE_COMMITMENT_V1, "owner_agent": mallory,
               "file_id": p["file_id"], "manifest_sha256": p["manifest_sha256"]}),
    );
    let misattributed = verify_owned_manifest(
        s(p, "manifest_text").as_bytes(),
        mallory,
        &key_binding,
        &commitment,
    )
    .expect("known CORE-004 limitation: binding is accepted");
    assert_eq!(misattributed.owner_agent(), mallory);
    for name in ["stream_grant_valid_for_stream", "licence_valid_for_export"] {
        let c = case(&v, name);
        assert_eq!(
            check_content_access(
                &misattributed,
                &subject(c),
                s(c, "grant_text").as_bytes(),
                right(s(c, "right")),
                at(c["now"].as_i64().unwrap()),
            )
            .unwrap_err(),
            AccessError::Denied(Denied::OwnerMismatch),
            "{name}"
        );
    }
    // A grant Mallory signs herself fails issuer authentication against the
    // Alice key that her (mis)binding points at.
    let c = case(&v, "mallory_substitutes_her_own_package_grant");
    assert_eq!(
        check_content_access(
            &misattributed,
            &subject(c),
            s(c, "grant_text").as_bytes(),
            Right::Stream,
            at(c["now"].as_i64().unwrap()),
        )
        .unwrap_err(),
        AccessError::Unauthenticated(Unauthenticated::WrongIssuer)
    );
}
