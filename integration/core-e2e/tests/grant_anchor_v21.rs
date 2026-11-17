//! `grant-anchor/v2` against REAL Holochain 0.7 conductors (Sweettest) on the
//! v2.1 storage DNA (holochain-music `dna-v21/`, docs/ACCESS-GRANT-V2.md §4).
//!
//! Alice (owner), Bob (reader) and Mallory (attacker). Every anchor and
//! lifecycle entry is made by Music's own Python; every forged, replayed or
//! stale write goes through the check-free `publish_grant_anchor_v2`, so the
//! integrity zome decides, and each refusal must carry its own rule's
//! message. Bob then reads anchors through the least-privilege v2.1 resolver
//! and verifies them with Media Core; Music's verifier must agree.
//!
//! Required environment: as `s2_key_lifecycle_v21` (`MUSIC_STORAGE_V21_DNA`).

mod common;

use common::*;
use holo_hash::ActionHash;
use holochain::sweettest::*;
use holochain_content_core::binding::{
    BindingAssurance, BindingError, ConductorRecord, KeyPurpose,
};
use holochain_content_core::grant_anchor::{
    verify_grant_anchor_v2, GrantAnchorClaim, RecoveredIssuerPolicy,
};
use holochain_content_core::lifecycle::{
    resolve_key_lifecycle, KeyContinuity, KeyLifecycle, KeyValidity,
};
use holochain_content_holochain::{ConductorResolver, ConductorTarget, READ_FUNCTIONS_V21};
use serde::Deserialize;
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::path::PathBuf;

const ZOME: &str = "music_storage";
const APP: &str = "grant-anchor-v21";
const ALICE: usize = 0;
const BOB: usize = 1;
const MALLORY: usize = 2;
const O: &str = "owner-manifest";
const T: &str = "publish_key_transition_v21";
const RV: &str = "publish_key_revocation_v21";
const A: &str = "publish_grant_anchor_v2";

#[derive(Debug, Deserialize)]
struct SequencedWire {
    author: String,
    action_hash: ActionHash,
    action_seq: u32,
    body: Value,
}

struct Net {
    conductors: SweetConductorBatch,
    cells: Vec<SweetCell>,
}

impl Net {
    fn agent(&self, i: usize) -> String {
        self.cells[i].agent_pubkey().to_string()
    }
    fn dna(&self) -> String {
        self.cells[0].cell_id().dna_hash().to_string()
    }
    async fn write(&self, i: usize, f: &str, payload: &Value) -> Result<ActionHash, String> {
        self.conductors[i]
            .call_fallible::<_, ActionHash>(&self.cells[i].zome(ZOME), f, payload)
            .await
            .map_err(|e| format!("{e:?}"))
    }
    async fn ok(&self, label: &str, i: usize, f: &str, payload: &Value) -> String {
        let h = self
            .write(i, f, payload)
            .await
            .unwrap_or_else(|e| panic!("{label}: legitimate write refused: {e}"));
        eprintln!("[anchor] accepted: {label}");
        h.to_string()
    }
    async fn refused(&self, label: &str, i: usize, f: &str, payload: &Value, needle: &str) {
        match self.write(i, f, payload).await {
            Ok(h) => panic!("{label}: forged write was accepted as {h}"),
            Err(e) => assert!(
                e.contains(needle),
                "{label}: refused, but not by ({needle}): {e}"
            ),
        }
        eprintln!("[anchor] refused by integrity validation: {label}");
    }
    async fn lifecycle_rows(&self, of: usize) -> Vec<Value> {
        let rows: Vec<SequencedWire> = self.conductors[BOB]
            .call(
                &self.cells[BOB].zome(ZOME),
                "get_key_lifecycle_v21",
                self.cells[of].agent_pubkey().clone(),
            )
            .await;
        rows.into_iter()
            .map(|r| {
                json!({"author": r.author, "action_hash": r.action_hash.to_string(),
                            "action_seq": r.action_seq, "body": r.body})
            })
            .collect()
    }
    async fn lifecycle(&self, of: usize) -> KeyLifecycle {
        let records: Vec<ConductorRecord> = self
            .lifecycle_rows(of)
            .await
            .into_iter()
            .map(|r| {
                ConductorRecord::from_validated_conductor_at(
                    s(&r, "author"),
                    s(&r, "action_hash"),
                    r["action_seq"].as_u64().unwrap() as u32,
                    r["body"].clone(),
                )
                .unwrap()
            })
            .collect();
        resolve_key_lifecycle(
            &records,
            &self.agent(of),
            KeyPurpose::OwnerManifest,
            &self.dna(),
        )
        .expect("lifecycle")
    }
    async fn settle(&self) {
        await_consistency_s(180, self.cells.iter())
            .await
            .expect("DHT consistency");
    }
}

fn args(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| s.to_string()).collect()
}

struct Fx<'a> {
    paths: &'a Paths,
    root: String,
    dna: String,
}

impl Fx<'_> {
    async fn entry(&self, list: &[&str]) -> Value {
        self.paths.python_ok(args(list)).await["entry"].clone()
    }
    async fn incept(&self, key: &str, agent: &str) -> Value {
        self.entry(&[
            "v21-incept",
            "--root",
            &self.root,
            "--key",
            key,
            "--agent",
            agent,
            "--purpose",
            O,
            "--dna-hash",
            &self.dna,
        ])
        .await
    }
    async fn rotate(&self, old: &str, new: &str, agent: &str, pred: &str, gen: &str) -> Value {
        self.entry(&[
            "v21-rotate",
            "--root",
            &self.root,
            "--old",
            old,
            "--new",
            new,
            "--agent",
            agent,
            "--purpose",
            O,
            "--dna-hash",
            &self.dna,
            "--predecessor-action",
            pred,
            "--predecessor-generation",
            gen,
        ])
        .await
    }
    async fn recover(&self, new: &str, agent: &str, pred: &Value, pred_action: &str) -> Value {
        self.entry(&[
            "v21-recover",
            "--root",
            &self.root,
            "--new",
            new,
            "--agent",
            agent,
            "--purpose",
            O,
            "--dna-hash",
            &self.dna,
            "--predecessor-action",
            pred_action,
            "--predecessor-key-hex",
            &s(pred, "signing_key_hex"),
            "--predecessor-generation",
            &s(pred, "generation"),
        ])
        .await
    }
    async fn revoke(&self, agent: &str, target: &Value, target_action: &str) -> Value {
        self.entry(&[
            "v21-revoke",
            "--agent",
            agent,
            "--purpose",
            O,
            "--dna-hash",
            &self.dna,
            "--generation",
            &s(target, "generation"),
            "--key-hex",
            &s(target, "signing_key_hex"),
            "--target-action",
            target_action,
            "--scope",
            "compromised",
        ])
        .await
    }
    async fn anchor_for(&self, dna: &str, grant_id: &str, message: &[u8], action: &str) -> Value {
        self.entry(&[
            "v21-anchor",
            "--dna-hash",
            dna,
            "--grant-id",
            grant_id,
            "--grant-message-hex",
            &hex(message),
            "--issuer-key-action",
            action,
        ])
        .await
    }
    async fn anchor(&self, grant_id: &str, message: &[u8], action: &str) -> Value {
        let dna = self.dna.clone();
        self.anchor_for(&dna, grant_id, message, action).await
    }
    #[allow(clippy::too_many_arguments)]
    async fn music_verdict(
        &self,
        dir: &std::path::Path,
        rows: &[Value],
        anchor: &ConductorRecord,
        agent: &str,
        grant_id: &str,
        message: &[u8],
        action: &str,
        policy: &str,
    ) -> String {
        let records = dir.join("anchor-lifecycle.json");
        let anchor_file = dir.join("anchor.json");
        std::fs::write(&records, serde_json::to_vec(rows).unwrap()).unwrap();
        std::fs::write(
            &anchor_file,
            serde_json::to_vec(
                &json!({"author": anchor.author(), "action_hash": anchor.action_hash(),
                                        "action_seq": anchor.action_seq(), "body": anchor.body()}),
            )
            .unwrap(),
        )
        .unwrap();
        s(
            &self
                .paths
                .python_ok(args(&[
                    "v21-verify-anchor",
                    "--records",
                    &records.display().to_string(),
                    "--anchor",
                    &anchor_file.display().to_string(),
                    "--agent",
                    agent,
                    "--dna-hash",
                    &self.dna,
                    "--grant-id",
                    grant_id,
                    "--grant-message-hex",
                    &hex(message),
                    "--issuer-key-action",
                    action,
                    "--policy",
                    policy,
                ]))
                .await,
            "verdict",
        )
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn grant_anchors_are_authorised_by_the_current_owner_key_on_real_conductors() {
    // Same large-future handling as s2_key_lifecycle_v21 (harness only).
    let flow = std::thread::Builder::new()
        .name("grant-anchor-flow".into())
        .stack_size(64 << 20)
        .spawn(|| {
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .thread_stack_size(16 << 20)
                .build()
                .expect("tokio runtime")
                .block_on(Box::pin(anchor_flow()))
        })
        .expect("spawn flow thread");
    if let Err(panic) = flow.join() {
        std::panic::resume_unwind(panic);
    }
}

async fn anchor_flow() {
    let paths = Paths::discover();
    let v21_path = PathBuf::from(
        std::env::var_os("MUSIC_STORAGE_V21_DNA").expect("set MUSIC_STORAGE_V21_DNA"),
    );
    let temp = TempDir::new("anchor21");
    let root = temp.0.join("fixture");
    std::fs::create_dir_all(&root).unwrap();
    let r = root.display().to_string();
    let dna_v21 = SweetDnaFile::from_bundle(&v21_path)
        .await
        .expect("load v2.1 DNA");
    let v1 = SweetDnaFile::from_bundle(&paths.storage_dna)
        .await
        .expect("load v1 DNA");
    let v1_hash = v1.dna_hash().to_string();
    let mut conductors = SweetConductorBatch::standard(3).await;
    let apps = conductors
        .setup_app(APP, std::slice::from_ref(&dna_v21))
        .await
        .expect("install");
    let cells: Vec<SweetCell> = apps
        .into_inner()
        .into_iter()
        .map(|a| a.into_cells().into_iter().next().unwrap())
        .collect();
    conductors.exchange_peer_info().await;
    let net = Net { conductors, cells };
    let (alice, mallory) = (net.agent(ALICE), net.agent(MALLORY));
    let dna = net.dna();
    eprintln!("[anchor] v2.1 DNA {dna}");
    let fx = Fx {
        paths: &paths,
        root: r.clone(),
        dna: dna.clone(),
    };
    let msg1 = b"holochain-music/access-grant/v2\0{grant one, synthetic}".to_vec();
    let msg2 = b"holochain-music/access-grant/v2\0{grant two, synthetic}".to_vec();
    let msg3 = b"holochain-music/access-grant/v2\0{grant three, synthetic}".to_vec();
    let (id1, id2, id3) = ("a1".repeat(16), "a2".repeat(16), "a3".repeat(16));

    // No signing key yet: nothing to authorise a grant.
    let early = fx.anchor(&id1, &msg1, "uhCkkNotYet").await;
    net.refused(
        "anchor before any owner key",
        ALICE,
        A,
        &early,
        "no owner-manifest signing key",
    )
    .await;
    // Generation 1 and a first grant.
    let g1 = fx.incept("artist", &alice).await;
    let h_g1 = net.ok("Alice incepts generation 1", ALICE, T, &g1).await;
    let a1 = fx.anchor(&id1, &msg1, &h_g1).await;
    assert_eq!(
        a1.as_object().unwrap().keys().cloned().collect::<Vec<_>>(),
        [
            "dna_hash",
            "grant_commitment",
            "grant_id",
            "issuer_key_action",
            "schema"
        ],
        "minimal public anchor"
    );
    let h_a1 = net
        .ok("anchor of grant 1 by generation 1", ALICE, A, &a1)
        .await;
    // Replay and grant-id reuse.
    net.refused(
        "replayed anchor",
        ALICE,
        A,
        &a1,
        "grant id was already anchored",
    )
    .await;
    let reuse = fx.anchor(&id1, &msg2, &h_g1).await;
    net.refused(
        "grant id reused for another grant",
        ALICE,
        A,
        &reuse,
        "grant id was already anchored",
    )
    .await;
    // Cross-DNA and malformed.
    let other = fx.anchor_for(&v1_hash, &id2, &msg2, &h_g1).await;
    net.refused(
        "anchor for another DNA",
        ALICE,
        A,
        &other,
        "grant anchor is for a different DNA",
    )
    .await;
    let mut bad = fx.anchor(&id2, &msg2, &h_g1).await;
    bad["grant_commitment"] = json!("ZZ".repeat(32));
    net.refused(
        "malformed commitment",
        ALICE,
        A,
        &bad,
        "invalid grant commitment encoding",
    )
    .await;
    let mut extra = fx.anchor(&id2, &msg2, &h_g1).await;
    extra["recipient"] = json!("Bob");
    let e = net.write(ALICE, A, &extra).await.expect_err("extra field");
    assert!(e.contains("Deserialize("), "extra field: {e}");
    eprintln!("[anchor] refused at entry decoding: extra field (no recipient can be published)");
    // Mallory: her own key cannot anchor under Alice's transition; she cannot
    // author for Alice at all.
    let m1 = fx.incept("host:mallory", &mallory).await;
    net.ok("Mallory incepts her own key", MALLORY, T, &m1).await;
    let steal = fx.anchor(&id2, &msg2, &h_g1).await;
    net.refused(
        "Mallory anchors under Alice's key",
        MALLORY,
        A,
        &steal,
        "not the author's current",
    )
    .await;

    // Rotation: g1 can no longer anchor; g2 can.
    let g2 = fx.rotate("artist", "artist:2", &alice, &h_g1, "1").await;
    let h_g2 = net.ok("Alice rotates to generation 2", ALICE, T, &g2).await;
    let stale = fx.anchor(&id2, &msg2, &h_g1).await;
    net.refused(
        "generation 1 anchors after rotation",
        ALICE,
        A,
        &stale,
        "not the author's current",
    )
    .await;
    let a2 = fx.anchor(&id2, &msg2, &h_g2).await;
    let h_a2 = net
        .ok("anchor of grant 2 by generation 2", ALICE, A, &a2)
        .await;
    // Revocation: g2 can no longer anchor.
    let rv = fx.revoke(&alice, &g2, &h_g2).await;
    net.ok("Alice revokes generation 2 (compromised)", ALICE, RV, &rv)
        .await;
    let after = fx.anchor(&id3, &msg3, &h_g2).await;
    net.refused("revoked generation 2 anchors", ALICE, A, &after, "revoked")
        .await;
    // Recovery: the DNA accepts (agent-authorised), verifiers decide.
    let g3 = fx.recover("artist:3", &alice, &g2, &h_g2).await;
    let h_g3 = net
        .ok("Alice recovers to generation 3", ALICE, T, &g3)
        .await;
    let a3 = fx.anchor(&id3, &msg3, &h_g3).await;
    let h_a3 = net
        .ok("anchor of grant 3 by recovered generation 3", ALICE, A, &a3)
        .await;
    net.settle().await;

    // ---- Bob: least-privilege reader, Media Core and Music verifiers ----
    let port = net.conductors[BOB]
        .get_arbitrary_admin_websocket_port()
        .expect("admin");
    let bob = ConductorResolver::connect(&ConductorTarget {
        admin: SocketAddr::from(([127, 0, 0, 1], port)),
        app_id: APP.into(),
        storage_role: dna.clone(),
        expected_storage_dna: dna.clone(),
        key_binding_v2: false,
        key_lifecycle_v21: true,
    })
    .await
    .expect("Bob's v2.1 resolver");
    assert!(READ_FUNCTIONS_V21.contains(&"get_grant_anchor_v2"));
    let owner = net.lifecycle(ALICE).await;
    let rows = net.lifecycle_rows(ALICE).await;
    let read = |h: String| {
        let bob = &bob;
        async move {
            bob.grant_anchor_v21(&h)
                .await
                .expect("read")
                .expect("anchor present")
        }
    };
    let r1 = read(h_a1.clone()).await;
    let r2 = read(h_a2.clone()).await;
    let r3 = read(h_a3.clone()).await;
    let check = |rec: &ConductorRecord, id: &str, m: &[u8], a: &str, p: RecoveredIssuerPolicy| {
        verify_grant_anchor_v2(
            rec,
            &owner,
            &GrantAnchorClaim {
                grant_id: id,
                grant_message: m,
                issuer_key_action: a,
            },
            p,
        )
    };
    // Grant 1: g1 before the rotation stays historical.
    let v1a = check(&r1, &id1, &msg1, &h_g1, RecoveredIssuerPolicy::Reject).unwrap();
    assert_eq!(
        (v1a.issuer().generation(), v1a.issuer().validity()),
        (1, KeyValidity::HistoricalOnly)
    );
    // Grant 2: g2 before its compromise revocation (anchored) stays valid.
    let v2a = check(&r2, &id2, &msg2, &h_g2, RecoveredIssuerPolicy::Reject).unwrap();
    assert_eq!(v2a.issuer().generation(), 2);
    // Grant 3: recovered issuer refused by default; accepted, labelled, on opt-in.
    assert_eq!(
        check(&r3, &id3, &msg3, &h_g3, RecoveredIssuerPolicy::Reject).unwrap_err(),
        BindingError::RecoveredIssuerRefused
    );
    let v3a = check(&r3, &id3, &msg3, &h_g3, RecoveredIssuerPolicy::Accept).unwrap();
    assert_eq!(
        v3a.issuer().continuity(),
        KeyContinuity::RecoveredWithoutContinuity
    );
    assert_eq!(
        v3a.issuer().assurance(),
        BindingAssurance::KeyLifecycleRecoveredV21
    );
    // Binding to the exact grant.
    assert_eq!(
        check(&r1, &id1, &msg2, &h_g1, RecoveredIssuerPolicy::Reject).unwrap_err(),
        BindingError::GrantAnchorMismatch,
        "anchor 1 does not commit to grant 2"
    );
    assert_eq!(
        check(&r2, &id2, &msg2, &h_g1, RecoveredIssuerPolicy::Reject).unwrap_err(),
        BindingError::GrantAnchorMismatch,
        "grant claims a different generation than its anchor"
    );
    // Missing anchor: fail closed.
    assert!(
        bob.grant_anchor_v21(&h_g1).await.expect("read").is_none(),
        "a transition is not an anchor"
    );
    // Music's own verifier agrees on the real rows.
    for (rec, id, m, a, policy, expect) in [
        (&r1, &id1, &msg1, &h_g1, "reject", "accepted"),
        (&r2, &id2, &msg2, &h_g2, "reject", "accepted"),
        (&r3, &id3, &msg3, &h_g3, "reject", "rejected"),
        (&r3, &id3, &msg3, &h_g3, "accept", "accepted"),
        (&r1, &id1, &msg2, &h_g1, "reject", "rejected"),
    ] {
        let music = fx
            .music_verdict(&temp.0, &rows, rec, &alice, id, m, a, policy)
            .await;
        assert_eq!(music, expect, "{a} {policy}");
    }
    eprintln!("[anchor] Bob verified anchors (historical g1, anchored g2, recovered g3 by policy); Music agrees");
}
