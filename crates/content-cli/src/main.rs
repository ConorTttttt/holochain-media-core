//! `holochain-media-core`: an opt-in, local, subprocess adapter that lets an
//! application (first: Holochain Music) exercise Media Core's Rust verifier
//! and `VerifiedCas` against its existing S1 packages.
//!
//! Design constraints:
//! * Accepts only **public** material: signed JSON documents, public keys,
//!   conductor-bridge records and ciphertext directories. There is no option
//!   that takes a content key, grant, X25519 key or private signing key.
//! * Prints exactly one JSON object on stdout. Exit 0 = accepted, 2 = rejected
//!   by a named verification boundary, 1 = usage or I/O failure (never a
//!   rejection).
//! * Never decrypts. Playback and licences stay in the application.
//! * No network and no Holochain calls.

#![forbid(unsafe_code)]

use holochain_content_core::binding::{
    verify_owned_manifest, verify_replica_claim, BindingError, ConductorRecord,
};
use holochain_content_core::compat::{
    canonical_json, verify_music_manifest, verify_music_receipt, VerifiedManifest, VerifyError,
};
use holochain_content_core::storage::{StoreError, VerifiedCas};
use holochain_content_core::ManifestDigest;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const MAX_DOCUMENT_BYTES: u64 = 8 * 1024 * 1024 + 1024;
const MAX_BRIDGE_BYTES: u64 = 1024 * 1024;

const USAGE: &str = "usage:
  holochain-media-core verify-manifest --manifest FILE --trusted-artist-hex HEX
                                       [--expected-manifest-sha256 HEX]
  holochain-media-core verify-receipt  --manifest FILE --receipt FILE
                                       --trusted-artist-hex HEX --trusted-host-hex HEX
  holochain-media-core verify-bindings --bridge-json FILE --manifest FILE --receipt FILE
                                       --owner-agent AGENT --node-agent AGENT
  holochain-media-core import          --manifest FILE --trusted-artist-hex HEX
                                       --source-store DIR --cas DIR
  holochain-media-core audit           --manifest FILE --trusted-artist-hex HEX --cas DIR";

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

fn run(args: &[String]) -> Result<Outcome, Failure> {
    let (command, rest) = args.split_first().ok_or_else(|| Failure(USAGE.into()))?;
    match command.as_str() {
        "verify-manifest" => verify_manifest_cmd(rest),
        "verify-receipt" => verify_receipt_cmd(rest),
        "verify-bindings" => verify_bindings_cmd(rest),
        "import" => import_cmd(rest),
        "audit" => audit_cmd(rest),
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
