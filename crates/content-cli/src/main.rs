//! `holochain-media-core`: an opt-in, local, subprocess adapter that lets an
//! application (first: Holochain Music) exercise Media Core's Rust verifier
//! and `VerifiedCas` against its existing S1 packages.
//!
//! Design constraints:
//! * Accepts only **public** material: signed JSON documents, public keys,
//!   conductor-bridge records and ciphertext directories. There is no option
//!   that takes a content key, an X25519 *private* key or a private signing
//!   key. `check-access` (CORE-005) additionally reads an owner-signed,
//!   recipient-wrapped grant/licence document; it verifies it but cannot and
//!   does not unwrap the content key inside it.
//! * Prints exactly one JSON object on stdout. Exit 0 = accepted, 2 = rejected
//!   by a named verification boundary, 1 = usage or I/O failure (never a
//!   rejection).
//! * Never decrypts or unwraps keys. Playback, key unwrap and licence
//!   issuance stay in the application.
//! * No network and no Holochain calls.

#![forbid(unsafe_code)]

use holochain_content_core::binding::{
    verify_owned_manifest, verify_replica_claim, BindingError, ConductorRecord,
};
use holochain_content_core::compat::{
    canonical_json, verify_music_manifest, verify_music_receipt, VerifiedManifest, VerifyError,
};
use holochain_content_core::entitlements::{
    check_content_access, AccessError, AuthenticatedSubject, EntitlementScheme,
};
use holochain_content_core::storage::{StoreError, VerifiedCas};
use holochain_content_core::{ManifestDigest, Right};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const MAX_DOCUMENT_BYTES: u64 = 8 * 1024 * 1024 + 1024;
const MAX_BRIDGE_BYTES: u64 = 1024 * 1024;
/// Generous I/O bound: the evaluator itself rejects anything over its
/// 16 KiB input cap as `malformed/TooLarge` (exit 2), not as an I/O failure.
const MAX_GRANT_FILE_BYTES: u64 = 1024 * 1024;

const USAGE: &str = "usage:
  holochain-media-core verify-manifest --manifest FILE --trusted-artist-hex HEX
                                       [--expected-manifest-sha256 HEX]
  holochain-media-core verify-receipt  --manifest FILE --receipt FILE
                                       --trusted-artist-hex HEX --trusted-host-hex HEX
  holochain-media-core verify-bindings --bridge-json FILE --manifest FILE --receipt FILE
                                       --owner-agent AGENT --node-agent AGENT
  holochain-media-core import          --manifest FILE --trusted-artist-hex HEX
                                       --source-store DIR --cas DIR
  holochain-media-core audit           --manifest FILE --trusted-artist-hex HEX --cas DIR
  holochain-media-core check-access    --bridge-json FILE --manifest FILE --owner-agent AGENT
                                       --grant FILE --listener-agent AGENT
                                       --recipient-x25519-hex HEX
                                       --right stream|managed-offline|export
                                       [--now UNIX_SECONDS]";

/// Exit status classes.
enum Outcome {
    Accepted(Value),
    Rejected(Value),
}

struct Failure(String);

impl<E: std::fmt::Display> From<E> for Failure {
    fn from(e: E) -> Self {
        Self(e.to_string())
    }
}

fn parse_flags(args: &[String], allowed: &[&str]) -> Result<HashMap<String, String>, Failure> {
    let mut flags = HashMap::new();
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        if !allowed.contains(&flag.as_str()) {
            return Err(Failure(format!("unknown or misplaced argument {flag}")));
        }
        let value = it
            .next()
            .ok_or_else(|| Failure(format!("missing value for {flag}")))?;
        if flags.insert(flag.clone(), value.clone()).is_some() {
            return Err(Failure(format!("duplicate {flag}")));
        }
    }
    Ok(flags)
}

fn required<'a>(flags: &'a HashMap<String, String>, key: &str) -> Result<&'a str, Failure> {
    flags
        .get(key)
        .map(String::as_str)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| Failure(format!("missing {key}")))
}

fn key32(text: &str, label: &str) -> Result<[u8; 32], Failure> {
    let digest: ManifestDigest = text
        .parse()
        .map_err(|_| Failure(format!("{label} must be 64 lowercase hex characters")))?;
    Ok(*digest.as_bytes())
}

fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>, Failure> {
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.len() > limit {
        return Err(Failure(format!(
            "{} is not a regular file within {limit} bytes",
            path.display()
        )));
    }
    Ok(std::fs::read(path)?)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn rejected(boundary: &str, error: impl std::fmt::Debug) -> Outcome {
    Outcome::Rejected(json!({
        "ok": false, "boundary": boundary, "error": format!("{error:?}"),
    }))
}

fn manifest_summary(manifest: &VerifiedManifest) -> Value {
    json!({
        "ok": true,
        "file_id": manifest.package_id().to_string(),
        "manifest_sha256": manifest.digest().to_string(),
        "signer_hex": hex(manifest.signer()),
        "chunk_count": manifest.chunks().len(),
        "total_plain_bytes": manifest.total_plain_bytes(),
    })
}

fn load_manifest(
    flags: &HashMap<String, String>,
) -> Result<Result<VerifiedManifest, VerifyError>, Failure> {
    let bytes = read_bounded(
        Path::new(required(flags, "--manifest")?),
        MAX_DOCUMENT_BYTES,
    )?;
    let artist = key32(
        required(flags, "--trusted-artist-hex")?,
        "--trusted-artist-hex",
    )?;
    Ok(verify_music_manifest(&bytes, &artist))
}

fn verify_manifest_cmd(args: &[String]) -> Result<Outcome, Failure> {
    let flags = parse_flags(
        args,
        &[
            "--manifest",
            "--trusted-artist-hex",
            "--expected-manifest-sha256",
        ],
    )?;
    let manifest = match load_manifest(&flags)? {
        Ok(m) => m,
        Err(e) => return Ok(rejected("s1-manifest", e)),
    };
    if let Some(expected) = flags.get("--expected-manifest-sha256") {
        let expected = ManifestDigest::from_bytes(key32(expected, "--expected-manifest-sha256")?);
        if manifest.digest() != expected {
            return Ok(rejected("manifest-digest-pin", "DigestMismatch"));
        }
    }
    Ok(Outcome::Accepted(manifest_summary(&manifest)))
}

fn verify_receipt_cmd(args: &[String]) -> Result<Outcome, Failure> {
    let flags = parse_flags(
        args,
        &[
            "--manifest",
            "--receipt",
            "--trusted-artist-hex",
            "--trusted-host-hex",
        ],
    )?;
    let manifest = match load_manifest(&flags)? {
        Ok(m) => m,
        Err(e) => return Ok(rejected("s1-manifest", e)),
    };
    let receipt = read_bounded(Path::new(required(&flags, "--receipt")?), 16 * 1024)?;
    let host = key32(
        required(&flags, "--trusted-host-hex")?,
        "--trusted-host-hex",
    )?;
    match verify_music_receipt(&receipt, &manifest, &host) {
        Ok(r) => Ok(Outcome::Accepted(json!({
            "ok": true,
            "manifest_sha256": r.manifest_digest().to_string(),
            "chunk_count": r.chunk_count(),
            "received_at": r.received_at(),
            "receipt_sha256": hex(r.envelope_sha256()),
        }))),
        Err(e) => Ok(rejected("s1-receipt", e)),
    }
}

fn record(bridge: &Value, field: &str) -> Result<ConductorRecord, Failure> {
    let r = bridge
        .get(field)
        .ok_or_else(|| Failure(format!("bridge JSON lacks {field}")))?;
    let text = |k: &str| {
        r.get(k)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| Failure(format!("{field}.{k} missing")))
    };
    let body = r.get("body").cloned().unwrap_or(Value::Null);
    ConductorRecord::from_validated_conductor(text("author")?, text("action_hash")?, body)
        .map_err(|e| Failure(format!("{field}: {e}")))
}

/// Records in the bridge JSON MUST come from the caller's trusted local
/// conductor bridge (`music_conductor_bridge`), exactly as Music's Python
/// `AuthoredRecord`s must.
fn verify_bindings_cmd(args: &[String]) -> Result<Outcome, Failure> {
    let flags = parse_flags(
        args,
        &[
            "--bridge-json",
            "--manifest",
            "--receipt",
            "--owner-agent",
            "--node-agent",
        ],
    )?;
    let bridge: Value = serde_json::from_slice(&read_bounded(
        Path::new(required(&flags, "--bridge-json")?),
        MAX_BRIDGE_BYTES,
    )?)?;
    let manifest = read_bounded(
        Path::new(required(&flags, "--manifest")?),
        MAX_DOCUMENT_BYTES,
    )?;
    let receipt = read_bounded(Path::new(required(&flags, "--receipt")?), 16 * 1024)?;
    let owner = required(&flags, "--owner-agent")?;
    let node = required(&flags, "--node-agent")?;
    let owned = match verify_owned_manifest(
        &manifest,
        owner,
        &record(&bridge, "owner_key_binding")?,
        &record(&bridge, "owner_commitment")?,
    ) {
        Ok(o) => o,
        Err(e) => return Ok(binding_rejection(e)),
    };
    match verify_replica_claim(
        &receipt,
        &owned,
        node,
        &record(&bridge, "node_key_binding")?,
        &record(&bridge, "replica_claim")?,
    ) {
        Ok(replica) => {
            let mut out = manifest_summary(owned.manifest());
            out["owner_agent"] = json!(owned.owner_agent());
            out["node_agent"] = json!(replica.node_agent());
            out["node_key_hex"] = json!(hex(replica.node_key()));
            out["receipt_sha256"] = json!(hex(replica.receipt().envelope_sha256()));
            Ok(Outcome::Accepted(out))
        }
        Err(e) => Ok(binding_rejection(e)),
    }
}

fn binding_rejection(e: BindingError) -> Outcome {
    rejected("s2-binding", e)
}

fn store_counts(cas: &VerifiedCas, manifest: &VerifiedManifest) -> Result<Value, Failure> {
    let audit = cas.audit(manifest).map_err(|e| Failure(e.to_string()))?;
    Ok(json!({
        "verified": audit.verified,
        "missing": audit.missing,
        "corrupt": audit.corrupt,
        "offline_ready": audit.verified == manifest.chunks().len(),
    }))
}

fn import_cmd(args: &[String]) -> Result<Outcome, Failure> {
    let flags = parse_flags(
        args,
        &[
            "--manifest",
            "--trusted-artist-hex",
            "--source-store",
            "--cas",
        ],
    )?;
    let manifest = match load_manifest(&flags)? {
        Ok(m) => m,
        Err(e) => return Ok(rejected("s1-manifest", e)),
    };
    let source_dir = PathBuf::from(required(&flags, "--source-store")?);
    if !std::fs::symlink_metadata(&source_dir)?.is_dir() {
        return Err(Failure(
            "--source-store must be an existing directory".into(),
        ));
    }
    let source = VerifiedCas::new(&source_dir).map_err(|e| Failure(e.to_string()))?;
    let cas = VerifiedCas::new(required(&flags, "--cas")?).map_err(|e| Failure(e.to_string()))?;
    match cas.sync_from(&manifest, &[&source]) {
        Ok(report) => {
            let mut out = json!({
                "ok": true,
                "file_id": manifest.package_id().to_string(),
                "already_verified": report.already_verified,
                "imported": report.downloaded,
                "repaired": report.repaired,
            });
            out["store"] = store_counts(&cas, &manifest)?;
            Ok(Outcome::Accepted(out))
        }
        Err(failure) => match failure.source {
            StoreError::NoHealthySource => {
                let mut out = json!({
                    "ok": false,
                    "boundary": "ciphertext-integrity",
                    "error": "NoHealthySource",
                    "failed_index": failure.failed_index,
                    "imported": failure.progress.downloaded,
                });
                out["store"] = store_counts(&cas, &manifest)?;
                Ok(Outcome::Rejected(out))
            }
            other => Err(Failure(format!(
                "store failure at chunk {}: {other}",
                failure.failed_index
            ))),
        },
    }
}

fn audit_cmd(args: &[String]) -> Result<Outcome, Failure> {
    let flags = parse_flags(args, &["--manifest", "--trusted-artist-hex", "--cas"])?;
    let manifest = match load_manifest(&flags)? {
        Ok(m) => m,
        Err(e) => return Ok(rejected("s1-manifest", e)),
    };
    let cas_dir = PathBuf::from(required(&flags, "--cas")?);
    if !std::fs::symlink_metadata(&cas_dir)?.is_dir() {
        return Err(Failure("--cas must be an existing directory".into()));
    }
    let cas = VerifiedCas::new(&cas_dir).map_err(|e| Failure(e.to_string()))?;
    let mut out = json!({"ok": true, "file_id": manifest.package_id().to_string()});
    out["store"] = store_counts(&cas, &manifest)?;
    Ok(Outcome::Accepted(out))
}

fn parse_right(text: &str) -> Result<Right, Failure> {
    match text {
        "stream" => Ok(Right::Stream),
        "managed-offline" => Ok(Right::ManagedOffline),
        "export" => Ok(Right::Export),
        _ => Err(Failure(
            "--right must be stream, managed-offline or export".into(),
        )),
    }
}

fn right_name(right: Right) -> &'static str {
    match right {
        Right::Stream => "stream",
        Right::ManagedOffline => "managed-offline",
        Right::Export => "export",
    }
}

fn parse_now(flags: &HashMap<String, String>) -> Result<SystemTime, Failure> {
    match flags.get("--now") {
        None => Ok(SystemTime::now()),
        Some(text) => {
            if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) || text.len() > 12 {
                return Err(Failure("--now must be non-negative Unix seconds".into()));
            }
            Ok(UNIX_EPOCH + Duration::from_secs(text.parse()?))
        }
    }
}

fn access_rejection(error: AccessError) -> Outcome {
    Outcome::Rejected(json!({
        "ok": false,
        "boundary": "entitlement",
        "category": error.category(),
        "reason": error.reason(),
        "error": error.to_string(),
    }))
}

/// CORE-005: verify a Music grant/licence for an authenticated owner and
/// listener, and evaluate one requested right. The owner identity and key
/// come only from the conductor-bridge records (as for `verify-bindings`);
/// the listener agent and X25519 *public* key are the caller's own trusted
/// context. `ok: true` is a policy decision: the application must still
/// unwrap the content key (AES-GCM authenticated) before plaintext access.
fn check_access_cmd(args: &[String]) -> Result<Outcome, Failure> {
    let flags = parse_flags(
        args,
        &[
            "--bridge-json",
            "--manifest",
            "--owner-agent",
            "--grant",
            "--listener-agent",
            "--recipient-x25519-hex",
            "--right",
            "--now",
        ],
    )?;
    let bridge: Value = serde_json::from_slice(&read_bounded(
        Path::new(required(&flags, "--bridge-json")?),
        MAX_BRIDGE_BYTES,
    )?)?;
    let manifest = read_bounded(
        Path::new(required(&flags, "--manifest")?),
        MAX_DOCUMENT_BYTES,
    )?;
    let grant = read_bounded(
        Path::new(required(&flags, "--grant")?),
        MAX_GRANT_FILE_BYTES,
    )?;
    let owner = required(&flags, "--owner-agent")?;
    let right = parse_right(required(&flags, "--right")?)?;
    let now = parse_now(&flags)?;
    let recipient = key32(
        required(&flags, "--recipient-x25519-hex")?,
        "--recipient-x25519-hex",
    )?;
    let subject = AuthenticatedSubject::from_trusted_context(
        required(&flags, "--listener-agent")?,
        recipient,
    )
    .map_err(|e| Failure(e.to_string()))?;
    let owned = match verify_owned_manifest(
        &manifest,
        owner,
        &record(&bridge, "owner_key_binding")?,
        &record(&bridge, "owner_commitment")?,
    ) {
        Ok(o) => o,
        Err(e) => return Ok(binding_rejection(e)),
    };
    match check_content_access(&owned, &subject, &grant, right, now) {
        Ok(decision) => {
            let e = decision.entitlement();
            let rights: Vec<&str> = [Right::Stream, Right::ManagedOffline, Right::Export]
                .into_iter()
                .filter(|r| e.rights().contains(*r))
                .map(right_name)
                .collect();
            let scheme = match e.scheme() {
                EntitlementScheme::MusicContentGrantV1 => "stream",
                EntitlementScheme::MusicPersonalLicenceV1 => "perpetual-personal",
                _ => "unknown",
            };
            Ok(Outcome::Accepted(json!({
                "ok": true,
                "decision": "authorized",
                "certifies": "policy-only; key unwrap and AES-GCM authentication remain",
                "right": right_name(decision.right()),
                "kind": scheme,
                "schema": e.scheme().schema(),
                "rights": rights,
                "owner_agent": e.owner_agent(),
                "listener_agent": e.listener_agent(),
                "file_id": e.package_id().to_string(),
                "manifest_sha256": e.manifest_digest().to_string(),
                "issued_at": e.issued_at(),
                "expires_at": e.expires_at(),
                "licence_id": e.licence_id(),
                "hkdf_context_hex": hex(e.wrapped_content_key().context()),
            })))
        }
        Err(e) => Ok(access_rejection(e)),
    }
}

fn run(args: &[String]) -> Result<Outcome, Failure> {
    let (command, rest) = args.split_first().ok_or_else(|| Failure(USAGE.into()))?;
    match command.as_str() {
        "verify-manifest" => verify_manifest_cmd(rest),
        "verify-receipt" => verify_receipt_cmd(rest),
        "verify-bindings" => verify_bindings_cmd(rest),
        "import" => import_cmd(rest),
        "audit" => audit_cmd(rest),
        "check-access" => check_access_cmd(rest),
        _ => Err(Failure(USAGE.into())),
    }
}

fn emit(value: &Value) {
    // canonical_json never fails for values built here (no floats).
    let bytes = canonical_json(value).unwrap_or_else(|| b"{}".to_vec());
    println!("{}", String::from_utf8_lossy(&bytes));
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(Outcome::Accepted(v)) => {
            emit(&v);
            ExitCode::SUCCESS
        }
        Ok(Outcome::Rejected(v)) => {
            emit(&v);
            ExitCode::from(2)
        }
        Err(Failure(message)) => {
            emit(&json!({"ok": false, "boundary": "usage-or-io", "error": message}));
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn flags_are_strict() {
        assert!(parse_flags(&strings(&["--manifest", "a"]), &["--manifest"]).is_ok());
        assert!(parse_flags(&strings(&["--manifest"]), &["--manifest"]).is_err());
        assert!(parse_flags(&strings(&["--content-key", "k"]), &["--manifest"]).is_err());
        assert!(parse_flags(
            &strings(&["--manifest", "a", "--manifest", "b"]),
            &["--manifest"]
        )
        .is_err());
    }

    #[test]
    fn keys_must_be_lowercase_hex() {
        assert!(key32(&"ab".repeat(32), "k").is_ok());
        assert!(key32(&"AB".repeat(32), "k").is_err());
        assert!(key32("ab", "k").is_err());
    }

    #[test]
    fn unknown_command_is_a_usage_failure_not_a_rejection() {
        assert!(matches!(run(&strings(&["decrypt"])), Err(Failure(_))));
        assert!(matches!(run(&[]), Err(Failure(_))));
    }

    #[test]
    fn rights_and_clock_flags_are_strict() {
        assert!(matches!(parse_right("stream"), Ok(Right::Stream)));
        assert!(matches!(
            parse_right("managed-offline"),
            Ok(Right::ManagedOffline)
        ));
        assert!(matches!(parse_right("export"), Ok(Right::Export)));
        for bad in ["Stream", "offline", "", "export "] {
            assert!(parse_right(bad).is_err(), "{bad}");
        }
        let mut flags = HashMap::new();
        flags.insert("--now".to_owned(), "1760000000".to_owned());
        assert_eq!(
            parse_now(&flags).ok(),
            Some(UNIX_EPOCH + Duration::from_secs(1_760_000_000))
        );
        for bad in ["-1", "1.5", "", "0x10", "9999999999999"] {
            flags.insert("--now".to_owned(), bad.to_owned());
            assert!(parse_now(&flags).is_err(), "{bad}");
        }
    }

    #[test]
    fn check_access_takes_no_private_key_options() {
        for secret in [
            "--content-key",
            "--recipient-private",
            "--x25519-private-hex",
        ] {
            let result = run(&strings(&["check-access", secret, "k"]));
            assert!(matches!(result, Err(Failure(_))), "{secret}");
        }
    }

    /// End-to-end through the CLI with Music's own Python-generated grants.
    #[test]
    fn check_access_with_python_generated_grants() {
        let v: Value = serde_json::from_str(include_str!(
            "../../content-core/testdata/music-entitlement-vectors.json"
        ))
        .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let alice = v["agents"]["alice"].as_str().unwrap();
        let p = &v["content"]["p"];
        let bridge = json!({
            "owner_key_binding": {"author": alice, "action_hash": "uhCkkA",
                "body": {"schema": "holochain-storage/key-binding/v1", "agent": alice,
                         "purpose": "owner-manifest",
                         "signing_key_hex": v["keys"]["alice_ed25519_public_hex"]}},
            "owner_commitment": {"author": alice, "action_hash": "uhCkkB",
                "body": {"schema": "holochain-storage/file-commitment/v1", "owner_agent": alice,
                         "file_id": p["file_id"], "manifest_sha256": p["manifest_sha256"]}},
        });
        let write = |name: &str, bytes: &[u8]| {
            let path = dir.path().join(name);
            std::fs::write(&path, bytes).unwrap();
            path.display().to_string()
        };
        let bridge_path = write("bridge.json", bridge.to_string().as_bytes());
        let manifest_path = write("m.json", p["manifest_text"].as_str().unwrap().as_bytes());
        let check = |case: &str| {
            let c = v["cases"]
                .as_array()
                .unwrap()
                .iter()
                .find(|c| c["name"] == case)
                .unwrap();
            let grant = write("g.json", c["grant_text"].as_str().unwrap().as_bytes());
            run(&strings(&[
                "check-access",
                "--bridge-json",
                &bridge_path,
                "--manifest",
                &manifest_path,
                "--owner-agent",
                alice,
                "--grant",
                &grant,
                "--listener-agent",
                c["subject"]["listener_agent"].as_str().unwrap(),
                "--recipient-x25519-hex",
                c["subject"]["recipient_key_hex"].as_str().unwrap(),
                "--right",
                c["right"].as_str().unwrap(),
                "--now",
                &c["now"].as_i64().unwrap().to_string(),
            ]))
        };
        match check("licence_valid_for_export") {
            Ok(Outcome::Accepted(out)) => {
                assert_eq!(out["kind"], "perpetual-personal");
                assert_eq!(
                    out["rights"],
                    json!(["stream", "managed-offline", "export"])
                );
                assert_eq!(out["expires_at"], Value::Null);
            }
            _ => panic!("licence not accepted"),
        }
        match check("stream_grant_valid_for_stream") {
            Ok(Outcome::Accepted(out)) => assert_eq!(out["rights"], json!(["stream"])),
            _ => panic!("grant not accepted"),
        }
        for (case, category, reason) in [
            (
                "stream_grant_does_not_confer_export",
                "denied",
                "RightNotGranted",
            ),
            ("stream_grant_expired_at_expires_at", "validity", "Expired"),
            (
                "grant_signed_by_mallory_key",
                "unauthenticated",
                "WrongIssuer",
            ),
            ("oversized_raw_input_whitespace", "malformed", "TooLarge"),
            (
                "legacy_personal_perpetual_grant_v1",
                "unsupported",
                "LegacyPerpetualGrant",
            ),
        ] {
            match check(case) {
                Ok(Outcome::Rejected(out)) => {
                    assert_eq!(out["boundary"], "entitlement", "{case}");
                    assert_eq!(out["category"], category, "{case}");
                    assert_eq!(out["reason"], reason, "{case}");
                }
                _ => panic!("{case} not rejected at the entitlement boundary"),
            }
        }
    }

    #[test]
    fn missing_documents_are_io_failures() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nope.json").display().to_string();
        let result = run(&strings(&[
            "verify-manifest",
            "--manifest",
            &missing,
            "--trusted-artist-hex",
            &"ab".repeat(32),
        ]));
        assert!(matches!(result, Err(Failure(_))));
    }
}
