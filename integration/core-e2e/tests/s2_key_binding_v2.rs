//! S2 key-binding v2 against REAL Holochain 0.7 conductors (Sweettest).
//!
//! Four agents (Alice owner, Bob reader, Carol host, Mallory attacker) run
//! the opt-in v2 storage DNA (`music_storage_v2`, holochain-music `dna-v2/`)
//! and the unchanged v1 DNA side by side. Legitimate bindings are signed by
//! Music's own Python code (`bind-v2` fixture command). Every forged write
//! goes through the v2 coordinator's deliberately thin
//! `register_signing_key_v2`, so the accept/reject decision is made by the
//! integrity zome's validation callback; each rejection must carry that
//! rule's own message (a transport error or missing record never counts).
//!
//! Required environment (in addition to the CORE-004 suite's):
//! `MUSIC_STORAGE_V2_DNA` = path to `music_storage_v2.dna`.

mod common;

use common::*;
use ed25519_dalek::{Signer, SigningKey};
use holo_hash::ActionHash;
use holochain::sweettest::*;
use holochain_content_core::binding::{
    key_binding_v2_message, require_proof_of_possession, resolve_signing_key,
    verify_key_binding_v2, BindingAssurance, BindingError, ConductorRecord, KeyBindingPolicy,
    KeyPurpose, KEY_GENERATION_V2,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::PathBuf;

const ZOME: &str = "music_storage";
const APP: &str = "s2-key-binding-v2";
const ALICE: usize = 0;
const BOB: usize = 1;
const CAROL: usize = 2;
const MALLORY: usize = 3;

#[derive(Debug, Deserialize)]
struct WireRecord {
    author: String,
    action_hash: ActionHash,
    body: Value,
}

#[derive(Debug, Serialize)]
struct V1Binding {
    schema: String,
    agent: String,
    purpose: String,
    signing_key_hex: String,
}

struct Net {
    conductors: SweetConductorBatch,
    v2: Vec<SweetCell>,
    v1: Vec<SweetCell>,
}

impl Net {
    fn agent(&self, i: usize) -> String {
        self.v2[i].agent_pubkey().to_string()
    }
    fn v2_dna(&self) -> String {
        self.v2[0].cell_id().dna_hash().to_string()
    }
    async fn write(
        &self,
        i: usize,
        v1: bool,
        f: &str,
        payload: &Value,
    ) -> Result<ActionHash, String> {
        let cell = if v1 { &self.v1[i] } else { &self.v2[i] };
        self.conductors[i]
            .call_fallible::<_, ActionHash>(&cell.zome(ZOME), f, payload)
            .await
            .map_err(|e| format!("{e:?}"))
    }
    /// Test K: a write refused BY THE INTEGRITY RULE named by `needle`.
    async fn refused(&self, label: &str, i: usize, f: &str, payload: &Value, needle: &str) {
        match self.write(i, false, f, payload).await {
            Ok(hash) => panic!("{label}: forged binding was accepted as {hash}"),
            Err(error) => assert!(
                error.contains(needle),
                "{label}: refused, but not by the expected rule ({needle}): {error}"
            ),
        }
        eprintln!("[s2] refused by integrity validation: {label}");
    }
    async fn keys(&self, reader: usize, v1: bool, of: usize) -> Vec<ConductorRecord> {
        let (cell, f) = if v1 {
            (&self.v1[reader], "get_signing_keys")
        } else {
            (&self.v2[reader], "get_signing_keys_v2")
        };
        let rows: Vec<WireRecord> = self.conductors[reader]
            .call(&cell.zome(ZOME), f, self.v2[of].agent_pubkey().clone())
            .await;
        rows.into_iter()
            .map(|r| {
                ConductorRecord::from_validated_conductor(
                    r.author,
                    r.action_hash.to_string(),
                    r.body,
                )
                .unwrap()
            })
            .collect()
    }
    async fn settle(&self) {
        // Two separate networks: each converges on its own ops only.
        for cells in [&self.v2, &self.v1] {
            await_consistency_s(120, cells.iter())
                .await
                .expect("DHT consistency");
        }
    }
}

fn args(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| s.to_string()).collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn v2_bindings_require_proof_of_possession_on_real_conductors() {
    let paths = Paths::discover();
    let v2_path =
        PathBuf::from(std::env::var_os("MUSIC_STORAGE_V2_DNA").expect("set MUSIC_STORAGE_V2_DNA"));
    let temp = TempDir::new("s2v2");
    let root = temp.0.join("fixture");
    let r = root.display().to_string();
    // Keys live only in the fixture root (Music's key files); the test never
    // sees Alice's or Carol's private key.
    let pkg = paths
        .python_ok(args(&[
            "prepare",
            "--root",
            &r,
            "--package",
            "p",
            "--size",
            "4096",
            "--chunk-size",
            "1024",
        ]))
        .await;
    let carol_host = paths
        .python_ok(args(&[
            "host",
            "--root",
            &r,
            "--package",
            "p",
            "--host",
            "carol",
        ]))
        .await;
    let alice_second = paths
        .python_ok(args(&[
            "host",
            "--root",
            &r,
            "--package",
            "p",
            "--host",
            "alicetwo",
        ]))
        .await;
    let alice_hex = s(&pkg, "artist_public_hex");
    let carol_hex = s(&carol_host, "node_public_hex");

    let dna_v2 = SweetDnaFile::from_bundle(&v2_path)
        .await
        .expect("load v2 DNA");
    let dna_v1 = SweetDnaFile::from_bundle(&paths.storage_dna)
        .await
        .expect("load v1 DNA");
    let v1_hash = dna_v1.dna_hash().to_string();
    assert_ne!(
        dna_v2.dna_hash(),
        dna_v1.dna_hash(),
        "v2 must be a distinct network"
    );
    let mut conductors = SweetConductorBatch::standard(4).await;
    let apps = conductors
        .setup_app(APP, &[dna_v2.clone(), dna_v1.clone()])
        .await
        .expect("install");
    let (mut v2, mut v1) = (Vec::new(), Vec::new());
    for app in apps.into_inner() {
        for cell in app.into_cells() {
            if cell.cell_id().dna_hash() == dna_v2.dna_hash() {
                v2.push(cell);
            } else {
                v1.push(cell);
            }
        }
    }
    conductors.exchange_peer_info().await;
    let net = Net { conductors, v2, v1 };
    let (alice, carol, mallory) = (net.agent(ALICE), net.agent(CAROL), net.agent(MALLORY));
    let dna = net.v2_dna();
    eprintln!("[s2] v2 DNA {dna}; v1 DNA {v1_hash}");

    let bind = |key: &'static str, agent: String, purpose: &'static str, dna: String| {
        let paths = &paths;
        let r = r.clone();
        async move {
            paths
                .python_ok(args(&[
                    "bind-v2",
                    "--root",
                    &r,
                    "--key",
                    key,
                    "--agent",
                    &agent,
                    "--purpose",
                    purpose,
                    "--dna-hash",
                    &dna,
                ]))
                .await["entry"]
                .clone()
        }
    };

    // ---- A: Alice registers a Music-signed v2 owner binding --------------
    let alice_owner = bind("artist", alice.clone(), "owner-manifest", dna.clone()).await;
    assert_eq!(s(&alice_owner, "signing_key_hex"), alice_hex);
    net.write(ALICE, false, "register_signing_key_v2", &alice_owner)
        .await
        .expect("A: legitimate v2 owner binding accepted");
    // ---- J: Carol registers her host key ---------------------------------
    let carol_binding = bind("host:carol", carol.clone(), "host-receipt", dna.clone()).await;
    net.write(CAROL, false, "register_signing_key_v2", &carol_binding)
        .await
        .expect("J: legitimate v2 host binding accepted");
    eprintln!("[s2] A/J: Alice (owner-manifest) and Carol (host-receipt) v2 bindings accepted");

    // ---- B: Mallory binds Alice's public key, signing with her own key ----
    let mallory_key = SigningKey::from_bytes(&[0x66; 32]);
    let forge = |agent: &str, purpose: &str, key_hex: &str, dna: &str, signer: &SigningKey| {
        let proof = signer.sign(&key_binding_v2_message(
            dna,
            agent,
            purpose,
            key_hex,
            KEY_GENERATION_V2,
        ));
        json!({"schema": "holochain-storage/key-binding/v2", "dna_hash": dna, "agent": agent,
               "purpose": purpose, "signing_key_hex": key_hex, "generation": "1",
               "proof_signature_hex": hex(&proof.to_bytes())})
    };
    let pop = "proof of possession does not verify";
    net.refused(
        "B: Mallory binds Alice's key with her own signature",
        MALLORY,
        "register_signing_key_v2",
        &forge(&mallory, "owner-manifest", &alice_hex, &dna, &mallory_key),
        pop,
    )
    .await;
    // ---- C: Alice's genuine proof replayed in Mallory's binding ------------
    let mut replay = alice_owner.clone();
    replay["agent"] = json!(mallory);
    net.refused(
        "C: Alice's proof replayed for Mallory",
        MALLORY,
        "register_signing_key_v2",
        &replay,
        pop,
    )
    .await;
    net.refused(
        "C: Alice's binding authored by Mallory",
        MALLORY,
        "register_signing_key_v2",
        &alice_owner,
        "actual Holochain action author",
    )
    .await;
    // ---- J: Mallory binds Carol's host key ---------------------------------
    let mut stolen_host = carol_binding.clone();
    stolen_host["agent"] = json!(mallory);
    net.refused(
        "J: Mallory replays Carol's host proof",
        MALLORY,
        "register_signing_key_v2",
        &stolen_host,
        pop,
    )
    .await;
    net.refused(
        "J: Mallory binds Carol's host key with her own signature",
        MALLORY,
        "register_signing_key_v2",
        &forge(&mallory, "host-receipt", &carol_hex, &dna, &mallory_key),
        pop,
    )
    .await;
    // ---- D: owner-manifest proof used for host-receipt ---------------------
    let mut relabelled = alice_owner.clone();
    relabelled["purpose"] = json!("host-receipt");
    net.refused(
        "D: owner proof relabelled host-receipt",
        ALICE,
        "register_signing_key_v2",
        &relabelled,
        pop,
    )
    .await;
    // ---- E: application/DNA context ----------------------------------------
    let for_v1 = bind("artist", alice.clone(), "owner-manifest", v1_hash.clone()).await;
    net.refused(
        "E: binding made for another DNA",
        ALICE,
        "register_signing_key_v2",
        &for_v1,
        "key binding is for a different DNA",
    )
    .await;
    let mut moved = for_v1.clone();
    moved["dna_hash"] = json!(dna);
    net.refused(
        "E: other-DNA proof relabelled with this DNA",
        ALICE,
        "register_signing_key_v2",
        &moved,
        pop,
    )
    .await;
    // ---- F: public key changed without a new proof -------------------------
    let mut swapped = alice_owner.clone();
    swapped["signing_key_hex"] = json!(carol_hex);
    net.refused(
        "F: modified public key",
        ALICE,
        "register_signing_key_v2",
        &swapped,
        pop,
    )
    .await;
    // ---- G: malformed --------------------------------------------------------
    let integrity_cases: Vec<(&str, &str, Value, &str)> = vec![
        (
            "short signature",
            "proof_signature_hex",
            json!("ab".repeat(63)),
            "invalid proof signature encoding",
        ),
        (
            "uppercase signature",
            "proof_signature_hex",
            json!(s(&alice_owner, "proof_signature_hex").to_uppercase()),
            "invalid proof signature encoding",
        ),
        (
            "non-hex signature",
            "proof_signature_hex",
            json!("zz".repeat(64)),
            "invalid proof signature encoding",
        ),
        (
            "empty signature",
            "proof_signature_hex",
            json!(""),
            "invalid proof signature encoding",
        ),
        (
            "zero signature",
            "proof_signature_hex",
            json!("00".repeat(64)),
            pop,
        ),
        (
            "v1 schema in v2 entry",
            "schema",
            json!("holochain-storage/key-binding/v1"),
            "unsupported key binding schema",
        ),
        (
            "future schema",
            "schema",
            json!("holochain-storage/key-binding/v3"),
            "unsupported key binding schema",
        ),
        (
            "unsupported purpose",
            "purpose",
            json!("grant-issuer"),
            "unsupported signing key purpose",
        ),
        (
            "generation 2",
            "generation",
            json!("2"),
            "unsupported key generation",
        ),
        (
            "short key",
            "signing_key_hex",
            json!("ab".repeat(31)),
            "invalid public key encoding",
        ),
        (
            "oversized DNA field",
            "dna_hash",
            json!("x".repeat(200)),
            "key binding is for a different DNA",
        ),
        (
            "oversized agent",
            "agent",
            json!("A".repeat(161)),
            "actual Holochain action author",
        ),
        (
            "non-canonical agent",
            "agent",
            json!(alice.to_lowercase()),
            "actual Holochain action author",
        ),
    ];
    for (label, field, value, needle) in integrity_cases {
        let mut bad = alice_owner.clone();
        bad[field] = value;
        net.refused(
            &format!("G: {label}"),
            ALICE,
            "register_signing_key_v2",
            &bad,
            needle,
        )
        .await;
    }
    // Missing or extra fields cannot even be decoded as the entry type
    // (`deny_unknown_fields`): refused at zome-input decoding, before any
    // entry exists to validate. Still a refusal, but not an integrity verdict,
    // so it is reported separately.
    let mut missing = alice_owner.clone();
    missing
        .as_object_mut()
        .unwrap()
        .remove("proof_signature_hex");
    let mut extra = alice_owner.clone();
    extra["note"] = json!("x");
    for (label, bad) in [("missing signature field", missing), ("extra field", extra)] {
        let error = net
            .write(ALICE, false, "register_signing_key_v2", &bad)
            .await
            .expect_err(label);
        assert!(error.contains("Deserialize("), "G: {label}: {error}");
        eprintln!("[s2] refused at entry decoding (not storable): G: {label}");
    }
    // ---- I: v1 bindings are refused on the v2 network ------------------------
    let v1_entry = json!(V1Binding {
        schema: "holochain-storage/key-binding/v1".into(),
        agent: alice.clone(),
        purpose: "owner-manifest".into(),
        signing_key_hex: alice_hex.clone(),
    });
    net.refused(
        "I: v1 binding on the v2 DNA",
        ALICE,
        "register_signing_key",
        &v1_entry,
        "key-binding/v1 is not accepted",
    )
    .await;
    // ...but remain valid, and readable as legacy, on the v1 network.
    net.write(ALICE, true, "register_signing_key", &v1_entry)
        .await
        .expect("v1 DNA unchanged: v1 binding accepted");
    // A v1-network Mallory can still bind Alice's public key (the original
    // weakness, unchanged on v1 by design: it is a separate network).
    net.write(
        MALLORY,
        true,
        "register_signing_key",
        &json!(V1Binding {
            schema: "holochain-storage/key-binding/v1".into(),
            agent: mallory.clone(),
            purpose: "owner-manifest".into(),
            signing_key_hex: alice_hex.clone(),
        }),
    )
    .await
    .expect("documented v1 limitation still present on the v1 DNA");

    // ---- Discovery by Bob ------------------------------------------------------
    net.settle().await;
    let policy = KeyBindingPolicy::ProofOfPossessionV2 {
        dna_hash: dna.clone(),
    };
    let alice_keys = net.keys(BOB, false, ALICE).await;
    assert_eq!(alice_keys.len(), 1, "exactly Alice's one accepted binding");
    let found =
        resolve_signing_key(&alice_keys, &alice, KeyPurpose::OwnerManifest, &policy).unwrap();
    assert_eq!(hex(found.key()), alice_hex);
    assert_eq!(found.assurance(), BindingAssurance::ProofOfPossessionV2);
    let carol_keys = net.keys(BOB, false, CAROL).await;
    let host = resolve_signing_key(&carol_keys, &carol, KeyPurpose::HostReceipt, &policy).unwrap();
    assert_eq!(hex(host.key()), carol_hex);
    // Media Core re-verifies the proof independently of the DNA.
    verify_key_binding_v2(&alice_keys[0], &alice, KeyPurpose::OwnerManifest, &dna).unwrap();
    assert_eq!(
        verify_key_binding_v2(&alice_keys[0], &alice, KeyPurpose::OwnerManifest, &v1_hash),
        Err(BindingError::WrongDna)
    );
    // None of Mallory's forgeries exist anywhere.
    assert!(net.keys(BOB, false, MALLORY).await.is_empty());
    assert!(net.keys(ALICE, false, MALLORY).await.is_empty());
    eprintln!("[s2] Bob discovers Alice's and Carol's v2 bindings; Media Core verifies them; no forgery stored");
    // Legacy v1 records: readable, labelled legacy, never upgraded.
    let legacy = resolve_signing_key(
        &net.keys(BOB, true, ALICE).await,
        &alice,
        KeyPurpose::OwnerManifest,
        &KeyBindingPolicy::LegacyV1,
    )
    .unwrap();
    assert_eq!(legacy.assurance(), BindingAssurance::LegacyAuthoredV1);
    assert_eq!(
        require_proof_of_possession(&legacy),
        Err(BindingError::InsufficientAssurance)
    );
    assert_eq!(
        resolve_signing_key(
            &net.keys(BOB, true, ALICE).await,
            &alice,
            KeyPurpose::OwnerManifest,
            &policy
        ),
        Err(BindingError::MissingRecord),
        "v2 policy never reads v1 records"
    );
    eprintln!("[s2] I: v1 binding accepted only on the v1 DNA and resolved as LegacyAuthoredV1");

    // ---- H: duplicate and conflicting registrations -----------------------------
    net.write(ALICE, false, "register_signing_key_v2", &alice_owner)
        .await
        .expect("an identical re-registration is valid data");
    let second = bind(
        "host:alicetwo",
        alice.clone(),
        "owner-manifest",
        dna.clone(),
    )
    .await;
    assert_eq!(
        s(&second, "signing_key_hex"),
        s(&alice_second, "node_public_hex")
    );
    net.settle().await;
    let alice_keys = net.keys(BOB, false, ALICE).await;
    assert_eq!(alice_keys.len(), 2);
    assert_eq!(
        hex(
            resolve_signing_key(&alice_keys, &alice, KeyPurpose::OwnerManifest, &policy)
                .unwrap()
                .key()
        ),
        alice_hex,
        "duplicates of the same key resolve to that key"
    );
    net.write(ALICE, false, "register_signing_key_v2", &second)
        .await
        .expect("a second, different key is valid data for the DNA");
    net.settle().await;
    let alice_keys = net.keys(BOB, false, ALICE).await;
    assert_eq!(alice_keys.len(), 3);
    assert_eq!(
        resolve_signing_key(&alice_keys, &alice, KeyPurpose::OwnerManifest, &policy),
        Err(BindingError::Ambiguous),
        "two different v2 owner keys are refused, never first/latest-match"
    );
    eprintln!("[s2] H: duplicate binding resolves; conflicting keys are Ambiguous");
}
