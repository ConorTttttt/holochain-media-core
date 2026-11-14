//! S2 key lifecycle v2.1 against REAL Holochain 0.7 conductors (Sweettest),
//! real Music MoQ/QUIC hosts, CORE-005 and Music's own decryption.
//!
//! Four disposable agents (Alice owner, Bob listener, Carol host, Mallory
//! attacker) run the opt-in v2.1 storage DNA (`music_storage_v21`,
//! holochain-music `dna-v21/`). Every lifecycle entry and receipt is made by
//! Music's own Python code (fixture commands); every forged or replayed write
//! goes through the v2.1 coordinator's deliberately thin publish functions,
//! so each accept/reject decision is made by the integrity zome's chain-order
//! validation, and each rejection must carry that rule's own message.
//!
//! Flow 1: Alice registers generation 1 → publishes encrypted media → Bob
//! authenticates it → Alice rotates to generation 2 → Holochain validates →
//! Bob resolves the active key → new content uses generation 2 → historical
//! content still verifies → Alice revokes generation 1 → new operations with
//! it are refused.
//! Flow 2: Carol hosts → issues a host-attributed v2 receipt → Bob
//! authenticates Carol → Media Core verifies the receipt → MoQ retrieves
//! verified ciphertext → CORE-005 checks Bob's licence → Music decrypts.
//!
//! Required environment (in addition to the CORE-004 suite's):
//! `MUSIC_STORAGE_V21_DNA` = path to `music_storage_v21.dna`.

mod common;

use common::*;
use holo_hash::ActionHash;
use holochain::sweettest::*;
use holochain_content_core::binding::{
    verify_key_binding_v1, verify_owned_manifest_lifecycle, verify_replica_claim_with_key,
    BindingAssurance, BindingError, ConductorRecord, EndpointPolicy, KeyBindingPolicy, KeyPurpose,
    ReceiptAttribution,
};
use holochain_content_core::entitlements::{
    check_content_access_with_lifecycle, AuthenticatedSubject,
};
use holochain_content_core::lifecycle::{
    resolve_key_lifecycle, ChainAnchor, KeyContinuity, KeyLifecycle, KeyUse, KeyValidity,
};
use holochain_content_core::receipt_v2::{
    require_host_attribution, verify_replica_claim_v2, verify_replica_receipt_v2,
};
use holochain_content_core::storage::VerifiedCas;
use holochain_content_core::{PackageId, Right};
use holochain_content_holochain::{ConductorResolver, ConductorTarget};
use holochain_content_moq::{MoqConnector, Timeouts};
use holochain_content_retrieval::{
    authenticate_content, fetch_verified_content, resolve_content_with, FetchOptions, HostSource,
    RejectReason,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

const ZOME: &str = "music_storage";
const APP: &str = "s2-key-lifecycle-v21";
const ALICE: usize = 0;
const BOB: usize = 1;
const CAROL: usize = 2;
const MALLORY: usize = 3;
const O: &str = "owner-manifest";
const H: &str = "host-receipt";

#[derive(Debug, Deserialize, Serialize)]
struct SequencedWire {
    author: String,
    action_hash: ActionHash,
    action_seq: u32,
    body: Value,
}

#[derive(Debug, Deserialize)]
struct PositionWire {
    author: String,
    action_hash: ActionHash,
    action_seq: u32,
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
        let hash = self
            .write(i, f, payload)
            .await
            .unwrap_or_else(|e| panic!("{label}: legitimate write refused: {e}"));
        eprintln!("[v21] accepted: {label}");
        hash.to_string()
    }
    /// A write refused BY THE INTEGRITY RULE whose message contains `needle`.
    async fn refused(&self, label: &str, i: usize, f: &str, payload: &Value, needle: &str) {
        match self.write(i, f, payload).await {
            Ok(hash) => panic!("{label}: forged write was accepted as {hash}"),
            Err(error) => assert!(
                error.contains(needle),
                "{label}: refused, but not by the expected rule ({needle}): {error}"
            ),
        }
        eprintln!("[v21] refused by integrity validation: {label}");
    }
    async fn lifecycle_rows(&self, reader: usize, of: usize) -> Vec<SequencedWire> {
        self.conductors[reader]
            .call(
                &self.cells[reader].zome(ZOME),
                "get_key_lifecycle_v21",
                self.cells[of].agent_pubkey().clone(),
            )
            .await
    }
    async fn lifecycle(&self, reader: usize, of: usize, purpose: KeyPurpose) -> KeyLifecycle {
        let records = to_records(self.lifecycle_rows(reader, of).await);
        resolve_key_lifecycle(&records, &self.agent(of), purpose, &self.dna())
            .expect("lifecycle resolves")
    }
    /// A record by `author` with its chain position, as Bob's conductor sees it.
    async fn anchored(&self, author: usize, action: &str, body: Value) -> ConductorRecord {
        let hash = ActionHash::try_from(action).unwrap();
        let p: Option<PositionWire> = self.conductors[BOB]
            .call(&self.cells[BOB].zome(ZOME), "get_action_position_v21", hash)
            .await;
        let p = p.expect("position");
        assert_eq!(p.author, self.agent(author));
        assert_eq!(p.action_hash.to_string(), action);
        ConductorRecord::from_validated_conductor_at(p.author, action, p.action_seq, body).unwrap()
    }
    async fn settle(&self) {
        await_consistency_s(180, self.cells.iter())
            .await
            .expect("DHT consistency");
    }
    async fn bob_resolver(&self) -> ConductorResolver {
        let port = self.conductors[BOB]
            .get_arbitrary_admin_websocket_port()
            .expect("Bob admin websocket");
        let dna = self.dna();
        ConductorResolver::connect(&ConductorTarget {
            admin: SocketAddr::from(([127, 0, 0, 1], port)),
            app_id: APP.into(),
            storage_role: dna.clone(),
            expected_storage_dna: dna,
            key_binding_v2: false,
            key_lifecycle_v21: true,
        })
        .await
        .expect("Bob's v2.1 conductor resolver")
    }
}

fn to_records(rows: Vec<SequencedWire>) -> Vec<ConductorRecord> {
    rows.into_iter()
        .map(|r| {
            ConductorRecord::from_validated_conductor_at(
                r.author,
                r.action_hash.to_string(),
                r.action_seq,
                r.body,
            )
            .unwrap()
        })
        .collect()
}

fn args(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| s.to_string()).collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex32(text: &str) -> [u8; 32] {
    let id: PackageId = text.parse().unwrap();
    *id.as_bytes()
}

fn commitment(owner: &str, pkg: &Value) -> Value {
    json!({"schema": "holochain-storage/file-commitment/v1", "owner_agent": owner,
           "file_id": s(pkg, "file_id"), "manifest_sha256": s(pkg, "manifest_sha256")})
}

fn claim(node: &str, owner: &str, pkg: &Value, receipt_sha256: &str) -> Value {
    json!({"schema": "holochain-storage/replica-claim/v1", "node_agent": node,
           "owner_agent": owner, "file_id": s(pkg, "file_id"),
           "manifest_sha256": s(pkg, "manifest_sha256"), "receipt_sha256": receipt_sha256})
}

fn endpoint(node: &str, owner: &str, pkg: &Value, url: &str, fp: &str) -> Value {
    json!({"schema": "holochain-storage/moq-endpoint/v1", "node_agent": node,
           "owner_agent": owner, "file_id": s(pkg, "file_id"),
           "manifest_sha256": s(pkg, "manifest_sha256"), "url": url,
           "cert_fingerprint_hex": fp})
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
    async fn incept(&self, key: &str, agent: &str, purpose: &str) -> Value {
        self.incept_for(key, agent, purpose, &self.dna.clone())
            .await
    }
    async fn incept_for(&self, key: &str, agent: &str, purpose: &str, dna: &str) -> Value {
        self.entry(&[
            "v21-incept",
            "--root",
            &self.root,
            "--key",
            key,
            "--agent",
            agent,
            "--purpose",
            purpose,
            "--dna-hash",
            dna,
        ])
        .await
    }
    #[allow(clippy::too_many_arguments)]
    async fn rotate_for(
        &self,
        old: &str,
        new: &str,
        agent: &str,
        purpose: &str,
        pred_action: &str,
        pred_generation: &str,
        dna: &str,
    ) -> Value {
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
            purpose,
            "--dna-hash",
            dna,
            "--predecessor-action",
            pred_action,
            "--predecessor-generation",
            pred_generation,
        ])
        .await
    }
    async fn rotate(
        &self,
        old: &str,
        new: &str,
        agent: &str,
        purpose: &str,
        pred_action: &str,
        pred_generation: &str,
    ) -> Value {
        let dna = self.dna.clone();
        self.rotate_for(old, new, agent, purpose, pred_action, pred_generation, &dna)
            .await
    }
    async fn recover(
        &self,
        new: &str,
        agent: &str,
        purpose: &str,
        pred: &Value,
        pred_action: &str,
    ) -> Value {
        self.entry(&[
            "v21-recover",
            "--root",
            &self.root,
            "--new",
            new,
            "--agent",
            agent,
            "--purpose",
            purpose,
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
    async fn revoke(
        &self,
        agent: &str,
        purpose: &str,
        target: &Value,
        target_action: &str,
        scope: &str,
    ) -> Value {
        self.entry(&[
            "v21-revoke",
            "--agent",
            agent,
            "--purpose",
            purpose,
            "--dna-hash",
            &self.dna,
            "--generation",
            &s(target, "generation"),
            "--key-hex",
            &s(target, "signing_key_hex"),
            "--target-action",
            target_action,
            "--scope",
            scope,
        ])
        .await
    }
    /// Music's own reader verdict over the real conductor rows.
    #[allow(clippy::too_many_arguments)]
    async fn music_verdict(
        &self,
        rows: &[SequencedWire],
        dir: &Path,
        agent: &str,
        purpose: &str,
        key_hex: &str,
        use_: &str,
        anchor_seq: Option<u32>,
    ) -> String {
        let file = dir.join("lifecycle-rows.json");
        let plain: Vec<Value> = rows
            .iter()
            .map(|r| {
                json!({"author": r.author, "action_hash": r.action_hash.to_string(),
                            "action_seq": r.action_seq, "body": r.body})
            })
            .collect();
        std::fs::write(&file, serde_json::to_vec(&plain).unwrap()).unwrap();
        let anchor = anchor_seq.map(|a| a.to_string()).unwrap_or_default();
        s(
            &self
                .paths
                .python_ok(args(&[
                    "v21-resolve",
                    "--records",
                    &file.display().to_string(),
                    "--agent",
                    agent,
                    "--purpose",
                    purpose,
                    "--dna-hash",
                    &self.dna,
                    "--key-hex",
                    key_hex,
                    "--use",
                    use_,
                    "--anchor-seq",
                    &anchor,
                ]))
                .await,
            "verdict",
        )
    }
}

fn verdict_name(v: KeyValidity) -> &'static str {
    match v {
        KeyValidity::Active => "Active",
        KeyValidity::Rotated => "Rotated",
        KeyValidity::Revoked => "Revoked",
        KeyValidity::HistoricalOnly => "HistoricalOnly",
        KeyValidity::Ambiguous => "Ambiguous",
        KeyValidity::Invalid => "Invalid",
    }
}

fn connector() -> MoqConnector {
    MoqConnector {
        timeouts: Timeouts {
            handshake: Duration::from_secs(10),
            object: Duration::from_secs(8),
        },
    }
}

#[test]
fn key_lifecycle_v21_rotation_revocation_and_host_receipts_on_real_conductors() {
    // The whole flow is one large future whose debug-build poll frames
    // exceed the default 2 MiB test-thread stack. Run it on a dedicated
    // thread and runtime with explicit stack sizes (harness only; no
    // behaviour under test changes). A panic in the flow fails the test.
    let flow = std::thread::Builder::new()
        .name("s2-v21-flow".into())
        .stack_size(64 << 20)
        .spawn(|| {
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .thread_stack_size(16 << 20)
                .build()
                .expect("tokio runtime")
                .block_on(Box::pin(lifecycle_flow()))
        })
        .expect("spawn flow thread");
    if let Err(panic) = flow.join() {
        std::panic::resume_unwind(panic);
    }
}

async fn lifecycle_flow() {
    let paths = Paths::discover();
    let v21_path = PathBuf::from(
        std::env::var_os("MUSIC_STORAGE_V21_DNA").expect("set MUSIC_STORAGE_V21_DNA"),
    );
    let temp = TempDir::new("s2v21");
    let root = temp.0.join("fixture");
    let r = root.display().to_string();
    // p1: historical content, signed by Alice's generation-1 key.
    let p1 = paths
        .python_ok(args(&[
            "prepare",
            "--root",
            &r,
            "--package",
            "p1",
            "--size",
            "65536",
            "--chunk-size",
            "16384",
        ]))
        .await;
    // p2: new content, signed by Alice's generation-2 key (created locally
    // now; it becomes Alice's key only when her rotation is validated).
    let p2 = paths
        .python_ok(args(&[
            "prepare",
            "--root",
            &r,
            "--package",
            "p2",
            "--size",
            "20000",
            "--chunk-size",
            "16384",
            "--artist-key",
            "artist:2",
        ]))
        .await;
    // p3: content signed by the generation-1 key, committed after rotation.
    let p3 = paths
        .python_ok(args(&[
            "prepare",
            "--root",
            &r,
            "--package",
            "p3",
            "--size",
            "20000",
            "--chunk-size",
            "16384",
        ]))
        .await;
    let a1_hex = s(&p1, "artist_public_hex");
    let a2_hex = s(&p2, "artist_public_hex");
    assert_ne!(a1_hex, a2_hex);

    let dna_v21 = SweetDnaFile::from_bundle(&v21_path)
        .await
        .expect("load v2.1 DNA");
    let dna_v1 = SweetDnaFile::from_bundle(&paths.storage_dna)
        .await
        .expect("load v1 DNA");
    let v1_hash = dna_v1.dna_hash().to_string();
    assert_ne!(dna_v21.dna_hash(), dna_v1.dna_hash());
    let mut conductors = SweetConductorBatch::standard(4).await;
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
    let (alice, bob, carol, mallory) = (
        net.agent(ALICE),
        net.agent(BOB),
        net.agent(CAROL),
        net.agent(MALLORY),
    );
    let dna = net.dna();
    eprintln!("[v21] v2.1 DNA {dna} (v1 DNA {v1_hash} not installed: separate network)");
    let fx = Fx {
        paths: &paths,
        root: r.clone(),
        dna: dna.clone(),
    };
    const T: &str = "publish_key_transition_v21";
    const RV: &str = "publish_key_revocation_v21";

    // ---------------------------------------------------------- generation 1
    let alice_g1 = fx.incept("artist", &alice, O).await;
    assert_eq!(s(&alice_g1, "signing_key_hex"), a1_hex);
    let h_a1 = net
        .ok("Alice registers owner generation 1", ALICE, T, &alice_g1)
        .await;
    let carol_g1 = fx.incept("host:carol", &carol, H).await;
    let h_c1 = net
        .ok("Carol registers host generation 1", CAROL, T, &carol_g1)
        .await;
    let mallory_g1 = fx.incept("host:mallory", &mallory, O).await;
    net.ok(
        "Mallory registers her OWN owner key",
        MALLORY,
        T,
        &mallory_g1,
    )
    .await;
    // v1 and v2 bindings are refused on the v2.1 network.
    net.refused(
        "v1 binding on the v2.1 DNA",
        ALICE,
        "register_signing_key",
        &json!({"schema": "holochain-storage/key-binding/v1", "agent": alice,
                "purpose": O, "signing_key_hex": a1_hex}),
        "key-binding/v1 is not accepted by the v2.1",
    )
    .await;
    // DNA-level fork prevention: no second inception for a purpose.
    let second = fx.incept("artist:9", &alice, O).await;
    net.refused(
        "second inception for owner-manifest",
        ALICE,
        T,
        &second,
        "purpose already has a key lifecycle",
    )
    .await;
    net.refused(
        "replayed inception",
        ALICE,
        T,
        &alice_g1,
        "purpose already has a key lifecycle",
    )
    .await;
    // Cross-DNA: an inception made for another network, as is and relabelled.
    let other = fx.incept_for("artist", &alice, H, &v1_hash).await;
    net.refused(
        "6: inception signed for another DNA",
        ALICE,
        T,
        &other,
        "key lifecycle entry is for a different DNA",
    )
    .await;
    let mut moved = other.clone();
    moved["dna_hash"] = json!(dna);
    net.refused(
        "6: other-DNA proof relabelled with this DNA",
        ALICE,
        T,
        &moved,
        "proof of possession does not verify",
    )
    .await;

    // ---------------------------------------------- Alice publishes; Carol hosts
    let h_commit_p1 = net
        .ok(
            "Alice commits p1 (gen 1)",
            ALICE,
            "publish_file_commitment",
            &commitment(&alice, &p1),
        )
        .await;
    let carol_p1 = paths
        .python_ok(args(&[
            "host-v2",
            "--root",
            &r,
            "--package",
            "p1",
            "--host",
            "carol",
            "--host-key",
            "host:carol",
            "--dna-hash",
            &dna,
            "--host-agent",
            &carol,
            "--host-key-generation",
            "1",
            "--host-key-action",
            &h_c1,
            "--owner-agent",
            &alice,
        ]))
        .await;
    let carol_receipt_path = PathBuf::from(s(&carol_p1, "receipt"));
    let carol_receipt = std::fs::read(&carol_receipt_path).unwrap();
    let h_claim = net
        .ok(
            "Carol claims p1 with her v2 receipt digest",
            CAROL,
            "publish_replica_claim",
            &claim(&carol, &alice, &p1, &s(&carol_p1, "receipt_sha256")),
        )
        .await;
    let served = paths
        .python_ok(args(&[
            "served-list",
            "--root",
            &r,
            "--host",
            "carol",
            "--packages",
            "p1",
        ]))
        .await;
    let carol_host = MusicHost::start(
        &paths.moq_host,
        Path::new(&s(&served, "served_list")),
        &root.join("hosts/carol/store"),
        &temp.0.join("carol-moq"),
        8 * 1024 * 1024,
    )
    .await;
    net.ok(
        "Carol's endpoint",
        CAROL,
        "publish_moq_endpoint",
        &endpoint(
            &carol,
            &alice,
            &p1,
            &carol_host.url,
            &carol_host.fingerprint_hex,
        ),
    )
    .await;
    // Mallory serves Carol's genuine receipt as hers (14) from a real QUIC host.
    let mallory_g1_host = fx.incept("host:mallory2", &mallory, H).await;
    net.ok(
        "Mallory registers her own host key",
        MALLORY,
        T,
        &mallory_g1_host,
    )
    .await;
    net.ok(
        "Mallory claims p1 with Carol's receipt digest",
        MALLORY,
        "publish_replica_claim",
        &claim(&mallory, &alice, &p1, &s(&carol_p1, "receipt_sha256")),
    )
    .await;
    let mallory_host = MaliciousHost::start(
        &temp.0,
        &root.join("hosts/carol/store"),
        &[(root.join("p1/manifest.json"), carol_receipt_path.clone())],
        Tamper::FlipBit,
    )
    .await;
    net.ok(
        "Mallory's endpoint",
        MALLORY,
        "publish_moq_endpoint",
        &endpoint(
            &mallory,
            &alice,
            &p1,
            &mallory_host.url,
            &mallory_host.fingerprint_hex,
        ),
    )
    .await;
    net.settle().await;

    // ------------------------------------- Bob authenticates (gen 1, Flow 2)
    let mut bob_reader = net.bob_resolver().await;
    let policy = KeyBindingPolicy::KeyLifecycleV21 {
        dna_hash: bob_reader.dna_hash().to_owned(),
    };
    let resolved = resolve_content_with(
        &mut bob_reader,
        &alice,
        s(&p1, "file_id").parse().unwrap(),
        EndpointPolicy::LoopbackOnly,
        &policy,
    )
    .await
    .expect("p1 resolves under v2.1");
    let mut content = authenticate_content(resolved, &connector())
        .await
        .expect("p1 authenticates");
    assert_eq!(
        content.owned.owner_assurance(),
        BindingAssurance::KeyLifecycleV21
    );
    assert_eq!(content.owned.owner_key_validity(), KeyValidity::Active);
    assert_eq!(content.hosts.len(), 1, "only Carol authenticates");
    let replica = &content.hosts[0].replica;
    assert_eq!(replica.node_agent(), carol);
    assert_eq!(replica.attribution(), ReceiptAttribution::HostAttributedV2);
    assert_eq!(replica.receipt_v2().unwrap().host_key_generation(), 1);
    require_host_attribution(replica).unwrap();
    let mallory_rejection = content
        .rejected
        .iter()
        .find(|x| x.node_agent == mallory)
        .expect("Mallory rejected");
    assert_eq!(
        mallory_rejection.reason,
        RejectReason::Binding(BindingError::ReceiptHostMismatch),
        "14: Carol's receipt served as Mallory's"
    );
    eprintln!("[v21] 15: Bob authenticated Carol's host-attributed receipt over MoQ; 14: Mallory's re-use of it rejected");
    // MoQ retrieves verified ciphertext into Bob's VerifiedCas.
    let manifest = content.owned.manifest().clone();
    let bob_store = temp.0.join("bob-cas");
    let cas = VerifiedCas::new(&bob_store).unwrap();
    let h = content.hosts.remove(0);
    let mut sources = vec![HostSource {
        node_agent: carol.clone(),
        transport: h.transport,
    }];
    let report = fetch_verified_content(&manifest, &mut sources, &cas, FetchOptions::default())
        .await
        .expect("verified ciphertext over MoQ");
    assert_eq!(report.downloaded, manifest.chunks().len());
    ensure_files_bounded(&bob_store, &manifest).unwrap();

    // Receipt-level adversarial checks on the real receipt (13, 14, 16).
    let carol_lc = net.lifecycle(BOB, CAROL, KeyPurpose::HostReceipt).await;
    let claim_rec = net
        .anchored(
            CAROL,
            &h_claim,
            claim(&carol, &alice, &p1, &s(&carol_p1, "receipt_sha256")),
        )
        .await;
    let mut forged: Value = serde_json::from_slice(&carol_receipt).unwrap();
    forged["signature_hex"] = json!("00".repeat(64));
    assert!(
        verify_replica_claim_v2(
            &serde_json::to_vec(&forged).unwrap(),
            &content.owned,
            &carol_lc,
            &claim_rec
        )
        .is_err(),
        "13: forged receipt"
    );
    let mut renamed: Value = serde_json::from_slice(&carol_receipt).unwrap();
    renamed["host_agent"] = json!(mallory);
    assert!(verify_replica_receipt_v2(
        &serde_json::to_vec(&renamed).unwrap(),
        &content.owned,
        &carol_lc,
        &KeyUse::Historical { anchor: None }
    )
    .is_err());
    let legacy = paths
        .python_ok(args(&[
            "host",
            "--root",
            &r,
            "--package",
            "p1",
            "--host",
            "carol",
        ]))
        .await;
    let legacy_bytes = std::fs::read(s(&legacy, "receipt")).unwrap();
    assert!(
        verify_replica_claim_v2(&legacy_bytes, &content.owned, &carol_lc, &claim_rec).is_err(),
        "16: a legacy S1 receipt never passes as v2"
    );
    let carol_v1 = ConductorRecord::from_validated_conductor(
        &carol,
        "uhCkkLegacyBinding",
        json!({"schema": "holochain-storage/key-binding/v1", "agent": carol,
               "purpose": H, "signing_key_hex": s(&carol_g1, "signing_key_hex")}),
    )
    .unwrap();
    let legacy_claim = ConductorRecord::from_validated_conductor(
        &carol,
        "uhCkkLegacyClaim",
        claim(&carol, &alice, &p1, &s(&legacy, "receipt_sha256")),
    )
    .unwrap();
    let legacy_replica = verify_replica_claim_with_key(
        &legacy_bytes,
        &content.owned,
        &carol,
        &verify_key_binding_v1(&carol_v1, &carol, KeyPurpose::HostReceipt).unwrap(),
        &legacy_claim,
    )
    .unwrap();
    assert_eq!(
        legacy_replica.attribution(),
        ReceiptAttribution::LegacyUnattributedV1
    );
    eprintln!("[v21] 13/16: forged and renamed receipts rejected; legacy S1 receipt readable only as LegacyUnattributedV1");

    // CORE-005 then Music decryption (Flow 2).
    let issued = paths
        .python_ok(args(&[
            "grants",
            "--root",
            &r,
            "--package",
            "p1",
            "--owner-agent",
            &alice,
            "--bob-agent",
            &bob,
            "--mallory-agent",
            &mallory,
        ]))
        .await;
    let bob_subject =
        AuthenticatedSubject::from_trusted_context(&bob, hex32(&s(&issued["recipients"], "bob")))
            .unwrap();
    let licence = std::fs::read(root.join("p1/grants/bob_licence.json")).unwrap();
    let alice_lc = net.lifecycle(BOB, ALICE, KeyPurpose::OwnerManifest).await;
    check_content_access_with_lifecycle(
        &content.owned,
        &bob_subject,
        &licence,
        Right::Export,
        SystemTime::now(),
        &alice_lc,
    )
    .expect("CORE-005 accepts Bob's licence under the v2.1 lifecycle");
    let trusted = hex(manifest.signer());
    let out = temp.0.join("bob-plain.bin");
    let (code, v) = paths
        .python(args(&[
            "unlock",
            "--root",
            &r,
            "--package",
            "p1",
            "--store",
            &bob_store.display().to_string(),
            "--grant",
            "bob_licence",
            "--recipient",
            "bob",
            "--listener-agent",
            &bob,
            "--owner-agent",
            &alice,
            "--trusted-artist-hex",
            &trusted,
            "--out",
            &out.display().to_string(),
        ]))
        .await;
    assert_eq!(code, 0, "{v}");
    assert_eq!(s(&v, "sha256"), s(&p1, "sample_sha256"));
    eprintln!("[v21] Flow 2 complete: CORE-005 verified Bob's licence; Music decrypted the MoQ-retrieved replica");

    // ------------------------------------------------- adversarial rotations
    // 3: Mallory authors a rotation of Alice's key (any content): authorship.
    let foreign = fx
        .rotate("artist", "host:mallory", &alice, O, &h_a1, "1")
        .await;
    net.refused(
        "3: Mallory authors Alice's rotation",
        MALLORY,
        T,
        &foreign,
        "actual Holochain action author",
    )
    .await;
    // 4: Mallory holds Alice's media key (stolen) but not Alice's agent key.
    // On her own chain the transition cannot reach Alice's lifecycle.
    let stolen = fx
        .rotate("artist", "host:mallory:2", &mallory, O, &h_a1, "1")
        .await;
    net.refused(
        "4: stolen media key rotates via Mallory's chain",
        MALLORY,
        T,
        &stolen,
        "predecessor is not the author's current key",
    )
    .await;
    let mut relabelled = stolen.clone();
    relabelled["agent"] = json!(alice);
    net.refused(
        "4: stolen-key rotation relabelled as Alice's",
        MALLORY,
        T,
        &relabelled,
        "actual Holochain action author",
    )
    .await;
    // 12: Mallory cannot revoke Alice's key.
    let fake_revoke = fx.revoke(&alice, O, &alice_g1, &h_a1, "compromised").await;
    net.refused(
        "12: Mallory authors Alice's revocation",
        MALLORY,
        RV,
        &fake_revoke,
        "actual Holochain action author",
    )
    .await;
    let mut own_chain = fake_revoke.clone();
    own_chain["agent"] = json!(mallory);
    net.refused(
        "12: Mallory revokes Alice's transition from her own chain",
        MALLORY,
        RV,
        &own_chain,
        "revocation target is not a key transition of this agent and purpose",
    )
    .await;

    // ------------------------------------------------ 1: Alice rotates to gen 2
    let alice_g2 = fx.rotate("artist", "artist:2", &alice, O, &h_a1, "1").await;
    assert_eq!(s(&alice_g2, "signing_key_hex"), a2_hex);
    // 5: the rotation relabelled for another purpose; 6: for another DNA.
    let mut other_purpose = alice_g2.clone();
    other_purpose["purpose"] = json!(H);
    net.refused(
        "5: rotation relabelled host-receipt",
        ALICE,
        T,
        &other_purpose,
        "no predecessor key for this purpose",
    )
    .await;
    let mut other_dna = alice_g2.clone();
    other_dna["dna_hash"] = json!(v1_hash);
    net.refused(
        "6: rotation for another DNA",
        ALICE,
        T,
        &other_dna,
        "key lifecycle entry is for a different DNA",
    )
    .await;
    let no_cont = {
        let mut x = alice_g2.clone();
        x["continuity_signature_hex"] = json!("");
        x
    };
    net.refused(
        "rotation without continuity signature",
        ALICE,
        T,
        &no_cont,
        "invalid continuity signature encoding",
    )
    .await;
    let wrong_cont = fx
        .rotate("host:mallory", "artist:2", &alice, O, &h_a1, "1")
        .await;
    let mut wrong_cont = wrong_cont;
    wrong_cont["predecessor_key_hex"] = json!(a1_hex);
    net.refused(
        "4: continuity signed by a key other than the predecessor",
        ALICE,
        T,
        &wrong_cont,
        "does not verify for this transition",
    )
    .await;
    let skip = fx.rotate("artist", "artist:3", &alice, O, &h_a1, "2").await;
    net.refused(
        "8: skipped generation",
        ALICE,
        T,
        &skip,
        "generation must increase by exactly one",
    )
    .await;
    let unknown = fx
        .rotate("artist", "artist:3", &alice, O, &h_commit_p1, "1")
        .await;
    net.refused(
        "8: predecessor is not a transition",
        ALICE,
        T,
        &unknown,
        "predecessor is not the author's current key",
    )
    .await;
    let h_a2 = net
        .ok("1: Alice rotates to generation 2", ALICE, T, &alice_g2)
        .await;
    // 7: replay of the accepted rotation; 9: competing successor of gen 1.
    net.refused(
        "7: replayed rotation",
        ALICE,
        T,
        &alice_g2,
        "predecessor is not the author's current key",
    )
    .await;
    let fork = fx.rotate("artist", "artist:3", &alice, O, &h_a1, "1").await;
    net.refused(
        "9: competing successor of generation 1",
        ALICE,
        T,
        &fork,
        "predecessor is not the author's current key",
    )
    .await;
    let back = fx.rotate("artist:2", "artist", &alice, O, &h_a2, "2").await;
    net.refused(
        "reactivating generation 1",
        ALICE,
        T,
        &back,
        "no reactivation",
    )
    .await;
    // 2: Carol rotates her host key.
    let carol_g2 = fx
        .rotate("host:carol", "host:carol:2", &carol, H, &h_c1, "1")
        .await;
    net.ok("2: Carol rotates to host generation 2", CAROL, T, &carol_g2)
        .await;

    // New content uses the replacement key; a gen-1 manifest committed now
    // is a new operation with a rotated key.
    let h_commit_p2 = net
        .ok(
            "Alice commits p2 (gen 2)",
            ALICE,
            "publish_file_commitment",
            &commitment(&alice, &p2),
        )
        .await;
    let h_commit_p3 = net
        .ok(
            "Alice commits p3 (gen-1 key after rotation)",
            ALICE,
            "publish_file_commitment",
            &commitment(&alice, &p3),
        )
        .await;
    net.settle().await;

    // ------------------------------------ Bob resolves the active key (Flow 1)
    let rows = net.lifecycle_rows(BOB, ALICE).await;
    let alice_lc =
        resolve_key_lifecycle(&to_records(rows), &alice, KeyPurpose::OwnerManifest, &dna)
            .expect("Alice's lifecycle");
    let active = alice_lc.active().unwrap();
    assert_eq!(hex(active.key()), a2_hex);
    assert_eq!(active.generation(), 2);
    assert_eq!(active.continuity(), KeyContinuity::Rotation);
    assert_eq!(active.assurance(), BindingAssurance::KeyLifecycleV21);
    let manifest_of = |pkg: &str| std::fs::read(root.join(pkg).join("manifest.json")).unwrap();
    let c1 = net
        .anchored(ALICE, &h_commit_p1, commitment(&alice, &p1))
        .await;
    let c2 = net
        .anchored(ALICE, &h_commit_p2, commitment(&alice, &p2))
        .await;
    let c3 = net
        .anchored(ALICE, &h_commit_p3, commitment(&alice, &p3))
        .await;
    let old = verify_owned_manifest_lifecycle(&manifest_of("p1"), &alice_lc, &c1).unwrap();
    assert_eq!(
        (old.owner_key_generation(), old.owner_key_validity()),
        (1, KeyValidity::HistoricalOnly),
        "11: historical content remains verifiable"
    );
    let new = verify_owned_manifest_lifecycle(&manifest_of("p2"), &alice_lc, &c2).unwrap();
    assert_eq!(
        (new.owner_key_generation(), new.owner_key_validity()),
        (2, KeyValidity::Active)
    );
    assert_eq!(
        verify_owned_manifest_lifecycle(&manifest_of("p3"), &alice_lc, &c3).unwrap_err(),
        BindingError::KeyRotated,
        "gen-1 key cannot publish new content after rotation"
    );
    // Music's own reader agrees with Media Core on the real conductor rows.
    let rows = net.lifecycle_rows(BOB, ALICE).await;
    for (key, use_, anchor, rust) in [
        (&a2_hex, "new-operation", None, KeyUse::NewOperation),
        (&a1_hex, "new-operation", None, KeyUse::NewOperation),
        (
            &a1_hex,
            "historical",
            None,
            KeyUse::Historical { anchor: None },
        ),
        (
            &a1_hex,
            "historical",
            c1.action_seq(),
            KeyUse::Historical {
                anchor: Some(ChainAnchor::from_record(&c1).unwrap()),
            },
        ),
        (
            &a1_hex,
            "historical",
            c3.action_seq(),
            KeyUse::Historical {
                anchor: Some(ChainAnchor::from_record(&c3).unwrap()),
            },
        ),
    ] {
        let rust = verdict_name(alice_lc.classify(&hex32(key), &rust));
        let music = fx
            .music_verdict(&rows, &temp.0, &alice, O, key, use_, anchor)
            .await;
        assert_eq!(music, rust, "{key} {use_} {anchor:?}");
    }
    eprintln!("[v21] Bob resolved Alice's generation 2; p1 HistoricalOnly, p2 Active, p3 (gen 1 after rotation) refused; Music's reader agrees");
    // Carol's receipt from before her rotation still verifies historically.
    let carol_lc = net.lifecycle(BOB, CAROL, KeyPurpose::HostReceipt).await;
    let replica = verify_replica_claim_v2(&carol_receipt, &old, &carol_lc, &claim_rec).unwrap();
    assert_eq!(
        replica.receipt_v2().unwrap().host_key_validity(),
        KeyValidity::HistoricalOnly
    );
    assert_eq!(
        verify_replica_receipt_v2(&carol_receipt, &old, &carol_lc, &KeyUse::NewOperation)
            .unwrap_err(),
        BindingError::KeyRotated
    );

    // --------------------------------------------- 10: Alice revokes gen 1
    let revoke_g1 = fx
        .revoke(&alice, O, &alice_g1, &h_a1, "new-operations")
        .await;
    net.ok(
        "Alice revokes generation 1 for new operations",
        ALICE,
        RV,
        &revoke_g1,
    )
    .await;
    net.refused(
        "7: replayed revocation",
        ALICE,
        RV,
        &revoke_g1,
        "key is already revoked with this scope",
    )
    .await;
    // Revoke the CURRENT key: only a recovery may follow it (no continuity
    // signature from a revoked key).
    let revoke_g2 = fx.revoke(&alice, O, &alice_g2, &h_a2, "compromised").await;
    let _h_rv2 = net
        .ok(
            "Alice revokes generation 2 as compromised",
            ALICE,
            RV,
            &revoke_g2,
        )
        .await;
    let after = fx
        .rotate("artist:2", "artist:3", &alice, O, &h_a2, "2")
        .await;
    net.refused(
        "10: revoked key signs continuity for a rotation",
        ALICE,
        T,
        &after,
        "only a recovery may follow it",
    )
    .await;
    net.settle().await;
    let revoked_lc = net.lifecycle(BOB, ALICE, KeyPurpose::OwnerManifest).await;
    assert_eq!(revoked_lc.active().unwrap_err(), BindingError::KeyRevoked);
    assert_eq!(
        revoked_lc.authorize(&hex32(&a1_hex), &KeyUse::NewOperation),
        Err(BindingError::KeyRevoked),
        "10: revoked key cannot authorise new operations"
    );
    let still = verify_owned_manifest_lifecycle(&manifest_of("p1"), &revoked_lc, &c1).unwrap();
    assert_eq!(still.owner_key_validity(), KeyValidity::HistoricalOnly);
    // p2 was committed before gen 2 was revoked as compromised: anchored, so
    // it remains verifiable; its unanchored grants/licences do not.
    let p2_owned = verify_owned_manifest_lifecycle(&manifest_of("p2"), &revoked_lc, &c2).unwrap();
    assert_eq!(p2_owned.owner_key_validity(), KeyValidity::HistoricalOnly);
    check_content_access_with_lifecycle(
        &old,
        &bob_subject,
        &licence,
        Right::Export,
        SystemTime::now(),
        &revoked_lc,
    )
    .expect("gen-1 licence survives a new-operations revocation");
    eprintln!(
        "[v21] 10/11: revoked keys refused for new operations; historical content still verifies"
    );

    // Lost/compromised key: an agent-authorised recovery (no continuity).
    let recovery = fx.recover("artist:4", &alice, O, &alice_g2, &h_a2).await;
    net.ok("Alice recovers to generation 3", ALICE, T, &recovery)
        .await;
    net.settle().await;
    let recovered = net.lifecycle(BOB, ALICE, KeyPurpose::OwnerManifest).await;
    let g3 = recovered.active().unwrap();
    assert_eq!(g3.generation(), 3);
    assert_eq!(g3.continuity(), KeyContinuity::RecoveredWithoutContinuity);
    assert_eq!(g3.assurance(), BindingAssurance::KeyLifecycleRecoveredV21);
    eprintln!("[v21] recovery accepted and labelled RecoveredWithoutContinuity");

    // Nothing Mallory attempted exists on the DHT for Alice.
    let alice_rows = net.lifecycle_rows(BOB, ALICE).await;
    assert!(alice_rows.iter().all(|r| r.author == alice));
    assert_eq!(
        alice_rows.len(),
        5,
        "g1, g2, two revocations, recovery and nothing else"
    );
}
