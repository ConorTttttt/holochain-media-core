//! CORE-004 acceptance: real Holochain conductors, the unchanged Holochain
//! Music S2 storage DNA, real Music S1 packages/receipts/grants (Python, at
//! the pinned Music commit), real `holochain-music-moq serve` hosts over
//! QUIC/MoQT draft-14 with certificate pinning, and Media Core's Rust
//! verifier + `VerifiedCas` on the receiving side.
//!
//! Agents (each on its own Sweettest conductor, sharing one DHT):
//! * Alice  — artist/publisher, and storage host A for P1.
//! * Carol  — independent honest storage host for P1 and P2.
//! * Bob    — receiver. Knows only Alice's AgentPubKey and a package ID.
//! * Mallory — authenticated P1 host that serves tampered ciphertext; also
//!   attempts identity forgeries and a false ownership claim.
//! * Eve    — P1 endpoint whose certificate pin does not match the server
//!   at its URL; P2 host whose receipt is signed by an unbound key.
//!
//! Only Bob's resolver path (`ConductorResolver` over his conductor's app
//! WebSocket) decides what Bob trusts. Publishers' readiness files are read
//! only by the publishing agents, to author their own Holochain records.
//!
//! Run (see docs/CORE-004-holochain-moq-integration.md for prerequisites):
//!   cargo test --manifest-path integration/Cargo.toml -p holochain-content-core-e2e \
//!     --test core004_acceptance -- --nocapture

mod common;

use common::*;
use holo_hash::ActionHash;
use holochain::sweettest::*;
use holochain_content_core::binding::{BindingAssurance, KeyBindingPolicy};
use holochain_content_core::binding::{BindingError, EndpointPolicy};
use holochain_content_core::compat::VerifyError;
use holochain_content_core::entitlements::{
    check_content_access, check_content_access_requiring, AccessError, AuthenticatedSubject,
    Denied, Unauthenticated, Validity,
};
use holochain_content_core::storage::VerifiedCas;
use holochain_content_core::{PackageId, Right};
use holochain_content_holochain::{read_functions, ConductorResolver, ConductorTarget};
use holochain_content_moq::MoqHostTransport;
use holochain_content_moq::{MoqConnector, Timeouts};
use holochain_content_retrieval::{
    authenticate_content, fetch_verified_content, resolve_content_with, AuthenticatedContent,
    FetchError, FetchOptions, HostSource, RejectReason, ResolveError, TransportFailure,
};
use serde::Serialize;
use serde_json::Value;
use std::{
    net::SocketAddr,
    path::Path,
    sync::{atomic::AtomicUsize, Arc},
    time::{Duration, SystemTime},
};

const APP: &str = "core004-acceptance";
const ZOME: &str = "music_storage";
const ALICE: usize = 0;
const BOB: usize = 1;
const CAROL: usize = 2;
const MALLORY: usize = 3;
const EVE: usize = 4;

#[derive(Debug, Serialize)]
struct SigningKeyBinding {
    schema: String,
    agent: String,
    purpose: String,
    signing_key_hex: String,
}

#[derive(Debug, Serialize)]
struct FileCommitment {
    schema: String,
    owner_agent: String,
    file_id: String,
    manifest_sha256: String,
}

#[derive(Debug, Serialize)]
struct ReplicaClaim {
    schema: String,
    node_agent: String,
    owner_agent: String,
    file_id: String,
    manifest_sha256: String,
    receipt_sha256: String,
}

#[derive(Debug, Serialize)]
struct MoqEndpoint {
    schema: String,
    node_agent: String,
    owner_agent: String,
    file_id: String,
    manifest_sha256: String,
    url: String,
    cert_fingerprint_hex: String,
}

fn key(agent: &str, purpose: &str, hex: &str) -> SigningKeyBinding {
    SigningKeyBinding {
        schema: "holochain-storage/key-binding/v1".into(),
        agent: agent.into(),
        purpose: purpose.into(),
        signing_key_hex: hex.into(),
    }
}

fn commitment(owner: &str, pkg: &Value) -> FileCommitment {
    FileCommitment {
        schema: "holochain-storage/file-commitment/v1".into(),
        owner_agent: owner.into(),
        file_id: s(pkg, "file_id"),
        manifest_sha256: s(pkg, "manifest_sha256"),
    }
}

fn claim(node: &str, owner: &str, pkg: &Value, receipt_sha256: &str) -> ReplicaClaim {
    ReplicaClaim {
        schema: "holochain-storage/replica-claim/v1".into(),
        node_agent: node.into(),
        owner_agent: owner.into(),
        file_id: s(pkg, "file_id"),
        manifest_sha256: s(pkg, "manifest_sha256"),
        receipt_sha256: receipt_sha256.into(),
    }
}

fn endpoint(node: &str, owner: &str, pkg: &Value, url: &str, fp: &str) -> MoqEndpoint {
    MoqEndpoint {
        schema: "holochain-storage/moq-endpoint/v1".into(),
        node_agent: node.into(),
        owner_agent: owner.into(),
        file_id: s(pkg, "file_id"),
        manifest_sha256: s(pkg, "manifest_sha256"),
        url: url.into(),
        cert_fingerprint_hex: fp.into(),
    }
}

struct Net {
    conductors: SweetConductorBatch,
    cells: Vec<SweetCell>,
    /// S2 key-binding v2 mode (`CORE_S2_KEY_BINDING=v2`, v2 storage DNA).
    v2: bool,
}

impl Net {
    fn agent(&self, i: usize) -> String {
        self.cells[i].agent_pubkey().to_string()
    }
    async fn call<P: Serialize + std::fmt::Debug>(&self, i: usize, f: &str, payload: &P) {
        let _: ActionHash = self.conductors[i]
            .call(&self.cells[i].zome(ZOME), f, payload)
            .await;
    }
    /// A write the Music integrity zome must reject *by validation*.
    async fn forbidden<P: Serialize + std::fmt::Debug>(&self, i: usize, f: &str, payload: &P) {
        let result: Result<ActionHash, _> = self.conductors[i]
            .call_fallible(&self.cells[i].zome(ZOME), f, payload)
            .await;
        let error = format!("{:?}", result.expect_err("forged write was accepted"));
        assert!(
            error.contains("actual Holochain action author"),
            "{f} was refused, but not by the authorship validation rule: {error}"
        );
    }
    /// A write the integrity zome must reject for the stated reason.
    async fn forbidden_because<P: Serialize + std::fmt::Debug>(
        &self,
        i: usize,
        f: &str,
        payload: &P,
        needle: &str,
    ) {
        let result: Result<ActionHash, _> = self.conductors[i]
            .call_fallible(&self.cells[i].zome(ZOME), f, payload)
            .await;
        let error = format!("{:?}", result.expect_err("forged write was accepted"));
        assert!(
            error.contains(needle),
            "{f} was refused, but not by the expected validation rule ({needle}): {error}"
        );
    }
    /// Register a signing key: v1 entry, or (v2 mode) a v2 entry signed by
    /// Music's own Python code with the key held in the fixture root.
    async fn bind_key(
        &self,
        paths: &Paths,
        root: &str,
        i: usize,
        purpose: &str,
        key_name: &str,
        public_hex: &str,
    ) -> Value {
        let agent = self.agent(i);
        if !self.v2 {
            self.call(i, "register_signing_key", &key(&agent, purpose, public_hex))
                .await;
            return Value::Null;
        }
        let dna = self.cells[i].cell_id().dna_hash().to_string();
        let out = paths
            .python_ok(args(&[
                "bind-v2",
                "--root",
                root,
                "--key",
                key_name,
                "--agent",
                &agent,
                "--purpose",
                purpose,
                "--dna-hash",
                &dna,
            ]))
            .await;
        let entry = out["entry"].clone();
        assert_eq!(s(&entry, "signing_key_hex"), public_hex);
        self.call(i, "register_signing_key_v2", &entry).await;
        entry
    }
    async fn settle(&self) {
        await_consistency_s(120, self.cells.iter())
            .await
            .expect("DHT consistency");
    }
    async fn bob_resolver(&self) -> ConductorResolver {
        let port = self.conductors[BOB]
            .get_arbitrary_admin_websocket_port()
            .expect("Bob admin websocket");
        let dna = self.cells[BOB].cell_id().dna_hash().to_string();
        ConductorResolver::connect(&ConductorTarget {
            admin: SocketAddr::from(([127, 0, 0, 1], port)),
            app_id: APP.into(),
            // Sweettest names roles after the DNA hash.
            storage_role: dna.clone(),
            expected_storage_dna: dna,
            key_binding_v2: self.v2,
        })
        .await
        .expect("Bob's authenticated conductor resolver")
    }
}

fn package_id(pkg: &Value) -> PackageId {
    s(pkg, "file_id").parse().unwrap()
}

fn connector(handshake_secs: u64, object_secs: u64) -> MoqConnector {
    MoqConnector {
        timeouts: Timeouts {
            handshake: Duration::from_secs(handshake_secs),
            object: Duration::from_secs(object_secs),
        },
    }
}

async fn authenticate(
    resolver: &mut ConductorResolver,
    owner: &str,
    pkg: &Value,
    c: &MoqConnector,
) -> Result<AuthenticatedContent<MoqHostTransport>, ResolveError> {
    // The policy follows how the resolver was connected; it is never chosen
    // per record, so v2 cannot silently fall back to v1.
    let policy = if resolver.key_binding_v2() {
        KeyBindingPolicy::ProofOfPossessionV2 {
            dna_hash: resolver.dna_hash().to_owned(),
        }
    } else {
        KeyBindingPolicy::LegacyV1
    };
    let resolved = resolve_content_with(
        resolver,
        owner,
        package_id(pkg),
        EndpointPolicy::LoopbackOnly,
        &policy,
    )
    .await?;
    authenticate_content(resolved, c).await
}

fn take_host(
    content: &mut AuthenticatedContent<MoqHostTransport>,
    agent: &str,
) -> HostSource<MoqHostTransport> {
    let pos = content
        .hosts
        .iter()
        .position(|h| h.replica.node_agent() == agent)
        .unwrap_or_else(|| panic!("{agent} was not authenticated"));
    let h = content.hosts.remove(pos);
    HostSource {
        node_agent: agent.into(),
        transport: h.transport,
    }
}

fn rejection<'a>(
    rejected: &'a [holochain_content_retrieval::HostRejection],
    agent: &str,
) -> &'a RejectReason {
    &rejected
        .iter()
        .find(|r| r.node_agent == agent)
        .unwrap_or_else(|| panic!("{agent} was not rejected: {rejected:?}"))
        .reason
}

#[allow(clippy::too_many_arguments)] // test helper mirroring the CLI flags
fn unlock_args(
    root: &Path,
    pkg: &str,
    store: &Path,
    grant: &str,
    recipient: &str,
    listener: &str,
    owner: &str,
    trusted: &str,
    out: &Path,
) -> Vec<String> {
    vec![
        "unlock".into(),
        "--root".into(),
        root.display().to_string(),
        "--package".into(),
        pkg.into(),
        "--store".into(),
        store.display().to_string(),
        "--grant".into(),
        grant.into(),
        "--recipient".into(),
        recipient.into(),
        "--listener-agent".into(),
        listener.into(),
        "--owner-agent".into(),
        owner.into(),
        "--trusted-artist-hex".into(),
        trusted.into(),
        "--out".into(),
        out.display().to_string(),
    ]
}

fn args(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| s.to_string()).collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn alice_publishes_bob_discovers_retrieves_and_verifies_mallory_is_rejected() {
    let paths = Paths::discover();
    let temp = TempDir::new("core004");
    let root = temp.0.join("fixture");
    let r = root.display().to_string();

    // ------------------------------------------------------------ Alice: S1
    // P1: 24 x 16 KiB chunks; P2: small second package.
    let p1 = paths
        .python_ok(args(&[
            "prepare",
            "--root",
            &r,
            "--package",
            "p1",
            "--size",
            "393216",
            "--chunk-size",
            "16384",
        ]))
        .await;
    let p2 = paths
        .python_ok(args(&[
            "prepare",
            "--root",
            &r,
            "--package",
            "p2",
            "--size",
            "40000",
            "--chunk-size",
            "16384",
        ]))
        .await;
    let chunks = p1["chunk_count"].as_u64().unwrap() as usize;
    assert_eq!(chunks, 24);
    // Host replicas and Music-signed receipts. Eve's P2 receipt is forged.
    let mut hosts = std::collections::HashMap::new();
    for (host, pkg, forge) in [
        ("alice", "p1", false),
        ("carol", "p1", false),
        ("carol", "p2", false),
        ("mallory", "p1", false),
        ("eve", "p1", false),
        ("eve", "p2", true),
    ] {
        let mut a = args(&["host", "--root", &r, "--package", pkg, "--host", host]);
        if forge {
            a.push("--forge-receipt".into());
        }
        hosts.insert(format!("{host}/{pkg}"), paths.python_ok(a).await);
    }

    // ------------------------------------------------------------ Holochain
    let dna = SweetDnaFile::from_bundle(&paths.storage_dna)
        .await
        .expect("load unchanged Music storage DNA");
    let mut conductors = SweetConductorBatch::standard(5).await;
    let apps = conductors.setup_app(APP, &[dna]).await.expect("install");
    let cells: Vec<SweetCell> = apps
        .into_inner()
        .into_iter()
        .map(|a| a.into_cells().into_iter().next().unwrap())
        .collect();
    conductors.exchange_peer_info().await;
    let v2 = std::env::var("CORE_S2_KEY_BINDING").as_deref() == Ok("v2");
    let net = Net {
        conductors,
        cells,
        v2,
    };
    eprintln!(
        "[core004] storage DNA {} (key binding {})",
        net.cells[ALICE].cell_id().dna_hash(),
        if v2 { "v2" } else { "v1" }
    );
    let (alice, bob, carol, mallory, eve) = (
        net.agent(ALICE),
        net.agent(BOB),
        net.agent(CAROL),
        net.agent(MALLORY),
        net.agent(EVE),
    );
    let artist_hex = s(&p1, "artist_public_hex");

    // Alice: owner key, commitments, and her own host role for P1.
    let alice_binding = net
        .bind_key(&paths, &r, ALICE, "owner-manifest", "artist", &artist_hex)
        .await;
    net.call(ALICE, "publish_file_commitment", &commitment(&alice, &p1))
        .await;
    net.call(ALICE, "publish_file_commitment", &commitment(&alice, &p2))
        .await;
    for (i, agent, name) in [
        (ALICE, &alice, "alice"),
        (CAROL, &carol, "carol"),
        (MALLORY, &mallory, "mallory"),
        (EVE, &eve, "eve"),
    ] {
        let any = hosts
            .iter()
            .find(|(k, _)| k.starts_with(&format!("{name}/")))
            .unwrap()
            .1;
        assert_eq!(&net.agent(i), agent);
        net.bind_key(
            &paths,
            &r,
            i,
            "host-receipt",
            &format!("host:{name}"),
            &s(any, "node_public_hex"),
        )
        .await;
    }
    for (i, agent, k, pkg) in [
        (ALICE, &alice, "alice/p1", &p1),
        (CAROL, &carol, "carol/p1", &p1),
        (CAROL, &carol, "carol/p2", &p2),
        (MALLORY, &mallory, "mallory/p1", &p1),
        (EVE, &eve, "eve/p1", &p1),
        (EVE, &eve, "eve/p2", &p2),
    ] {
        net.call(
            i,
            "publish_replica_claim",
            &claim(agent, &alice, pkg, &s(&hosts[k], "receipt_sha256")),
        )
        .await;
    }

    // Mallory's forgeries are refused by the Music integrity zome itself.
    if net.v2 {
        // Authoring Alice's genuine v2 binding as Mallory: authorship rule.
        net.forbidden(MALLORY, "register_signing_key_v2", &alice_binding)
            .await;
        // Alice's proof copied into a binding of Alice's key to Mallory:
        // proof-of-possession rule (the CORE-004 finding, now refused).
        let mut stolen = alice_binding.clone();
        stolen["agent"] = Value::String(mallory.clone());
        net.forbidden_because(
            MALLORY,
            "register_signing_key_v2",
            &stolen,
            "proof of possession does not verify",
        )
        .await;
        // v1 bindings are not accepted on the v2 network at all.
        net.forbidden_because(
            MALLORY,
            "register_signing_key",
            &key(&mallory, "owner-manifest", &artist_hex),
            "key-binding/v1 is not accepted",
        )
        .await;
        eprintln!(
            "[s2] Mallory cannot bind Alice's key on the v2 DNA (authorship, proof, v1 refused)"
        );
    } else {
        net.forbidden(
            MALLORY,
            "register_signing_key",
            &key(&alice, "owner-manifest", &"ab".repeat(32)),
        )
        .await;
    }
    net.forbidden(MALLORY, "publish_file_commitment", &commitment(&alice, &p1))
        .await;
    net.forbidden(
        MALLORY,
        "publish_replica_claim",
        &claim(&carol, &alice, &p1, &"cd".repeat(32)),
    )
    .await;

    // ------------------------------------------------------------ MoQ hosts
    let mut music_hosts = std::collections::HashMap::new();
    for (name, pkgs, rate) in [
        ("alice", "p1", 64 * 1024),
        ("carol", "p1,p2", 8 * 1024 * 1024),
        ("eve", "p2", 8 * 1024 * 1024),
    ] {
        let served = paths
            .python_ok(args(&[
                "served-list",
                "--root",
                &r,
                "--host",
                name,
                "--packages",
                pkgs,
            ]))
            .await;
        let hdir = root.join("hosts").join(name);
        let host = MusicHost::start(
            &paths.moq_host,
            Path::new(&s(&served, "served_list")),
            &hdir.join("store"),
            &temp.0.join(format!("{name}-moq")),
            rate,
        )
        .await;
        music_hosts.insert(name, host);
    }
    let mallory_host = MaliciousHost::start(
        &temp.0,
        &root.join("hosts/mallory/store"),
        &[(
            root.join("p1/manifest.json"),
            root.join("hosts/mallory/p1.receipt.json"),
        )],
        Tamper::FlipBit,
    )
    .await;
    // Each host authors its own endpoint from its own readiness data.
    net.call(
        ALICE,
        "publish_moq_endpoint",
        &endpoint(
            &alice,
            &alice,
            &p1,
            &music_hosts["alice"].url,
            &music_hosts["alice"].fingerprint_hex,
        ),
    )
    .await;
    for pkg in [&p1, &p2] {
        net.call(
            CAROL,
            "publish_moq_endpoint",
            &endpoint(
                &carol,
                &alice,
                pkg,
                &music_hosts["carol"].url,
                &music_hosts["carol"].fingerprint_hex,
            ),
        )
        .await;
    }
    net.call(
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
    // Eve's P1 endpoint points at Carol's server with a pin Carol's
    // certificate does not have.
    net.call(
        EVE,
        "publish_moq_endpoint",
        &endpoint(
            &eve,
            &alice,
            &p1,
            &music_hosts["carol"].url,
            &"e5".repeat(32),
        ),
    )
    .await;
    net.call(
        EVE,
        "publish_moq_endpoint",
        &endpoint(
            &eve,
            &alice,
            &p2,
            &music_hosts["eve"].url,
            &music_hosts["eve"].fingerprint_hex,
        ),
    )
    .await;
    net.forbidden(
        MALLORY,
        "publish_moq_endpoint",
        &endpoint(
            &carol,
            &alice,
            &p1,
            &mallory_host.url,
            &mallory_host.fingerprint_hex,
        ),
    )
    .await;
    // Mallory claims Alice's P1 as her own content, with her own owner key.
    net.bind_key(
        &paths,
        &r,
        MALLORY,
        "owner-manifest",
        "host:mallory",
        &s(&hosts["mallory/p1"], "node_public_hex"),
    )
    .await;
    net.call(
        MALLORY,
        "publish_file_commitment",
        &commitment(&mallory, &p1),
    )
    .await;
    net.call(
        MALLORY,
        "publish_replica_claim",
        &claim(
            &mallory,
            &mallory,
            &p1,
            &s(&hosts["mallory/p1"], "receipt_sha256"),
        ),
    )
    .await;
    net.call(
        MALLORY,
        "publish_moq_endpoint",
        &endpoint(
            &mallory,
            &mallory,
            &p1,
            &mallory_host.url,
            &mallory_host.fingerprint_hex,
        ),
    )
    .await;
    net.settle().await;
    eprintln!("[core004] Holochain records published and consistent across 5 conductors");

    // ------------------------------------------------------------ Bob's reader
    // One resolver for the whole session (each connect commits a cap grant).
    // A second connect proves the app interface is reused, and every signing
    // grant is limited to the four read functions.
    let mut bob_reader = net.bob_resolver().await;
    assert_eq!(bob_reader.reader_agent(), bob);
    let admin = holochain_client::AdminWebsocket::connect(
        SocketAddr::from((
            [127, 0, 0, 1],
            net.conductors[BOB]
                .get_arbitrary_admin_websocket_port()
                .unwrap(),
        )),
        None,
    )
    .await
    .expect("test admin socket");
    let interfaces = admin.list_app_interfaces().await.unwrap().len();
    drop(net.bob_resolver().await);
    assert_eq!(
        admin.list_app_interfaces().await.unwrap().len(),
        interfaces,
        "resolver must reuse its app interface"
    );
    // Holochain 0.7.0's ListCapabilityGrants returns nothing when
    // include_revoked is false (every grant hits `continue`), so list all
    // grants and select the active ones by `revoked_at`.
    let grants = admin
        .list_capability_grants(APP.into(), true)
        .await
        .unwrap();
    let vacuous = admin
        .list_capability_grants(APP.into(), false)
        .await
        .unwrap();
    assert!(
        vacuous.0.iter().all(|(_, g)| g.is_empty()),
        "upstream include_revoked:false listing behaviour changed; revisit"
    );
    let read_only: std::collections::HashSet<(String, String)> = read_functions(net.v2)
        .iter()
        .map(|f| (ZOME.to_string(), f.to_string()))
        .collect();
    let signing: Vec<_> = grants
        .0
        .iter()
        .flat_map(|(_, g)| g.iter())
        .filter(|g| g.cap_grant.tag == "zome-call-signing-key" && g.revoked_at.is_none())
        .collect();
    assert_eq!(signing.len(), 2, "one assigned grant per resolver connect");
    for grant in signing {
        let holochain_client::GrantedFunctions::Listed(functions) = &grant.cap_grant.functions
        else {
            panic!("resolver signing grant is not least-privilege: {grant:?}");
        };
        let functions: std::collections::HashSet<(String, String)> = functions
            .iter()
            .map(|(z, f)| (z.to_string(), f.to_string()))
            .collect();
        assert_eq!(functions, read_only);
    }
    eprintln!("[core004] Bob's resolver: read-only signing grant, app interface reused");

    // ------------------------------------------------------------ Bob: P1
    let c = connector(10, 8);
    let mut content = authenticate(&mut bob_reader, &alice, &p1, &c)
        .await
        .expect("P1 authenticates");
    assert_eq!(content.owned.owner_agent(), alice);
    assert_eq!(
        content.owned.manifest().digest().to_string(),
        s(&p1, "manifest_sha256")
    );
    assert_eq!(hex(content.owned.manifest().signer()), artist_hex);
    let expected_assurance = if net.v2 {
        BindingAssurance::ProofOfPossessionV2
    } else {
        BindingAssurance::LegacyAuthoredV1
    };
    assert_eq!(content.owned.owner_assurance(), expected_assurance);
    for h in &content.hosts {
        assert_eq!(h.replica.node_assurance(), expected_assurance);
    }
    // TLS certificate mismatch: rejected by the pin, not reported as denial.
    assert!(
        matches!(
            rejection(&content.rejected, &eve),
            RejectReason::Transport(TransportFailure::IdentityMismatch(_))
        ),
        "Eve: {:?}",
        rejection(&content.rejected, &eve)
    );
    assert_eq!(
        content.hosts.len(),
        3,
        "Alice, Carol and Mallory hold valid receipts"
    );
    eprintln!(
        "[core004] P1 authenticated hosts: Alice, Carol, Mallory; Eve rejected by certificate pin"
    );

    // Interrupted transfer: Alice's host is killed after 5 verified objects.
    let bob_store = temp.0.join("bob-cas");
    let cas = VerifiedCas::new(&bob_store).unwrap();
    let alice_src = take_host(&mut content, &alice);
    let victim = music_hosts["alice"].child.clone();
    let mut sources = vec![HostSource {
        node_agent: alice.clone(),
        transport: KillAfter {
            inner: alice_src.transport,
            after: 5,
            delivered: Arc::new(AtomicUsize::new(0)),
            victim,
        },
    }];
    let manifest = content.owned.manifest().clone();
    let error = fetch_verified_content(&manifest, &mut sources, &cas, FetchOptions::default())
        .await
        .expect_err("Alice's host died mid-transfer");
    let FetchError::Incomplete { report, missing } = error else {
        panic!("expected an incomplete transfer, got {error:?}");
    };
    let partial = report.downloaded;
    assert!((5..chunks).contains(&partial), "partial = {partial}");
    assert_eq!(missing.len(), chunks - partial);
    assert!(matches!(
        report.hosts[0].failure,
        Some(TransportFailure::Interrupted { .. } | TransportFailure::TimedOut(_))
    ));
    eprintln!(
        "[core004] interrupted after {partial}/{chunks} verified objects: {:?}",
        report.hosts[0].failure
    );

    // Client restart: new store handle; Mallory first (tampered objects),
    // then Carol. Only missing objects are requested; Mallory's first object
    // is rejected before it touches disk; Carol completes.
    drop(cas);
    let cas = VerifiedCas::new(&bob_store).unwrap();
    let mut sources = vec![
        take_host(&mut content, &mallory),
        take_host(&mut content, &carol),
    ];
    let report = fetch_verified_content(&manifest, &mut sources, &cas, FetchOptions::default())
        .await
        .expect("resume completes from an alternate host");
    assert_eq!(report.already_verified, partial);
    assert_eq!(report.downloaded, chunks - partial);
    assert_eq!(report.hosts[0].node_agent, mallory);
    assert_eq!(report.hosts[0].delivered, 0);
    assert_eq!(report.hosts[0].rejected_object, Some(missing[0]));
    assert_eq!(report.hosts[1].delivered, chunks - partial);
    assert_eq!(cas.audit(&manifest).unwrap().verified, chunks);
    ensure_files_bounded(&bob_store, &manifest).unwrap();
    eprintln!("[core004] resumed: {partial} reused, Mallory's tampered object {} rejected, Carol supplied {}", missing[0], chunks - partial);

    // Corrupt local chunk repair, then duplicate retrieval is a no-op.
    let sha = hex(&manifest.chunks()[3].ciphertext_sha256);
    std::fs::write(
        bob_store.join("objects/sha256").join(&sha[..2]).join(&sha),
        b"bit rot",
    )
    .unwrap();
    let mut sources = vec![take_host(
        &mut authenticate(&mut bob_reader, &alice, &p1, &connector(3, 8))
            .await
            .unwrap(),
        &carol,
    )];
    let report = fetch_verified_content(&manifest, &mut sources, &cas, FetchOptions::default())
        .await
        .unwrap();
    assert_eq!(
        (report.initial.corrupt, report.repaired, report.downloaded),
        (1, 1, 0)
    );
    let report = fetch_verified_content(&manifest, &mut sources, &cas, FetchOptions::default())
        .await
        .unwrap();
    assert_eq!(
        (
            report.already_verified,
            report.downloaded,
            report.hosts.len()
        ),
        (chunks, 0, 0)
    );
    ensure_files_bounded(&bob_store, &manifest).unwrap();

    // ------------------------------------------------------------ Music grants
    // The trusted artist key handed to Music's grant/decrypt code is the one
    // Bob's Holochain path authenticated, not a fixture value.
    let trusted = hex(manifest.signer());
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

    // ------------------------------------------------------------ CORE-005
    // Rust entitlement verification of the Music-issued grants against the
    // Holochain-authenticated content (owner key from Alice's conductor
    // records) and listener agents from the real conductors, BEFORE Music's
    // own key unwrap. No transport, no Holochain call, injected clock.
    let x25519 = |who: &str| -> [u8; 32] {
        let id: PackageId = s(&issued["recipients"], who).parse().unwrap();
        *id.as_bytes()
    };
    let grant_bytes =
        |name: &str| std::fs::read(root.join("p1/grants").join(format!("{name}.json"))).unwrap();
    let subject = |agent: &str, key: &str| {
        AuthenticatedSubject::from_trusted_context(agent, x25519(key)).unwrap()
    };
    let now = SystemTime::now();
    let check = |name: &str, who: &AuthenticatedSubject, right: Right, at: SystemTime| {
        check_content_access(&content.owned, who, &grant_bytes(name), right, at)
    };
    let bob_subject = subject(&bob, "bob");
    for (name, right) in [
        ("bob_licence", Right::Export),
        ("bob_licence", Right::ManagedOffline),
        ("bob_licence", Right::Stream),
        ("bob_stream", Right::Stream),
    ] {
        let decision = check(name, &bob_subject, right, now)
            .unwrap_or_else(|e| panic!("CORE-005 {name}/{right:?}: {e}"));
        assert_eq!(decision.entitlement().owner_agent(), alice);
        assert_eq!(decision.entitlement().package_id(), manifest.package_id());
    }
    for (name, who, right, at, expected) in [
        (
            "bob_stream",
            subject(&bob, "bob"),
            Right::Export,
            now,
            AccessError::Denied(Denied::RightNotGranted),
        ),
        (
            "bob_licence",
            subject(&mallory, "mallory"),
            Right::Stream,
            now,
            AccessError::Denied(Denied::ListenerMismatch),
        ),
        (
            "mallory_licence",
            subject(&bob, "bob"),
            Right::Stream,
            now,
            AccessError::Denied(Denied::ListenerMismatch),
        ),
        (
            "mallory_licence",
            subject(&mallory, "bob"),
            Right::Stream,
            now,
            AccessError::Denied(Denied::RecipientKeyMismatch),
        ),
        (
            "forged_licence",
            subject(&bob, "bob"),
            Right::Stream,
            now,
            AccessError::Unauthenticated(Unauthenticated::WrongIssuer),
        ),
        (
            "bob_short",
            subject(&bob, "bob"),
            Right::Stream,
            now + Duration::from_secs(5),
            AccessError::Validity(Validity::Expired),
        ),
    ] {
        assert_eq!(
            check(name, &who, right, at).unwrap_err(),
            expected,
            "CORE-005 {name}"
        );
    }
    // S2: the entitlement result reports, and can require, owner assurance.
    let strict = check_content_access_requiring(
        &content.owned,
        &bob_subject,
        &grant_bytes("bob_licence"),
        Right::Export,
        now,
        BindingAssurance::ProofOfPossessionV2,
    );
    if net.v2 {
        assert_eq!(
            strict.unwrap().entitlement().owner_assurance(),
            BindingAssurance::ProofOfPossessionV2
        );
    } else {
        assert_eq!(
            strict.unwrap_err(),
            AccessError::Unauthenticated(Unauthenticated::InsufficientOwnerAssurance)
        );
    }
    eprintln!("[core005] Rust entitlement checks on Holochain-authenticated content agree with Music's boundaries");

    let out = temp.0.join("bob-plain.bin");
    for grant in ["bob_licence", "bob_stream"] {
        let (code, v) = paths
            .python(unlock_args(
                &root, "p1", &bob_store, grant, "bob", &bob, &alice, &trusted, &out,
            ))
            .await;
        assert_eq!(code, 0, "{grant}: {v}");
        assert_eq!(
            s(&v, "sha256"),
            s(&p1, "sample_sha256"),
            "Bob recovers the original bytes"
        );
    }
    eprintln!("[core004] Bob decrypted the VerifiedCas replica with Music grants; plaintext SHA-256 matches");
    // Each denial must come from the applicable Music boundary.
    for (grant, recipient, listener, wait, boundary, needle) in [
        // Mallory uses Bob's grant with her own key and identity.
        (
            "bob_licence",
            "mallory",
            &mallory,
            false,
            "content-grant",
            "not valid for this listener",
        ),
        // Bob presents a licence addressed to Mallory.
        (
            "mallory_licence",
            "bob",
            &bob,
            false,
            "content-grant",
            "not valid for this listener",
        ),
        // Bob claims to be Mallory but lacks her X25519 key.
        (
            "mallory_licence",
            "bob",
            &mallory,
            false,
            "content-grant",
            "not addressed to this X25519 reader",
        ),
        // Licence signed by a key that is not Alice's registered key.
        (
            "forged_licence",
            "bob",
            &bob,
            false,
            "content-grant",
            "not signed by registered artist",
        ),
        // Expired streaming grant.
        ("bob_short", "bob", &bob, true, "content-grant", "expired"),
        // No grant at all: guessing a content key fails AES-GCM.
        (
            "none-random-key",
            "bob",
            &bob,
            false,
            "aes-gcm",
            "decryption failed",
        ),
    ] {
        let mut a = unlock_args(
            &root, "p1", &bob_store, grant, recipient, listener, &alice, &trusted, &out,
        );
        if wait {
            a.push("--wait-expiry".into());
        }
        let (code, v) = paths.python(a).await;
        assert!(
            code == 3 || code == 4,
            "{grant}/{recipient}: expected a denial, got {code}: {v}"
        );
        assert_eq!(s(&v, "boundary"), boundary, "{grant}/{recipient}: {v}");
        assert!(s(&v, "error").contains(needle), "{grant}/{recipient}: {v}");
    }
    eprintln!("[core004] wrong-recipient, impersonation, forged, expired and keyless access denied by Music boundaries");

    // ------------------------------------------------------------ P2: forged receipt
    let mut p2_content = authenticate(&mut bob_reader, &alice, &p2, &c)
        .await
        .expect("P2 authenticates via Carol");
    assert_eq!(
        rejection(&p2_content.rejected, &eve),
        &RejectReason::Binding(BindingError::Receipt(VerifyError::WrongSigner))
    );
    let p2_store = temp.0.join("bob-p2");
    let p2_cas = VerifiedCas::new(&p2_store).unwrap();
    let mut sources = vec![take_host(&mut p2_content, &carol)];
    let manifest2 = p2_content.owned.manifest().clone();
    fetch_verified_content(&manifest2, &mut sources, &p2_cas, FetchOptions::default())
        .await
        .unwrap();
    assert_eq!(
        p2_cas.audit(&manifest2).unwrap().verified,
        manifest2.chunks().len()
    );
    eprintln!(
        "[core004] P2: Eve's forged receipt rejected by the receipt signer check; Carol served P2"
    );

    // ------------------------------------------------------------ false ownership
    // Bob asked for "Mallory's" P1. The manifest Mallory serves is Alice's,
    // signed by Alice's key, not the key Mallory bound: signature boundary.
    let Err(ResolveError::NoAuthenticatedHost(rejected)) =
        authenticate(&mut bob_reader, &mallory, &p1, &c).await
    else {
        panic!("Mallory's ownership claim must not authenticate");
    };
    assert_eq!(
        rejection(&rejected, &mallory),
        &RejectReason::Binding(BindingError::Manifest(VerifyError::WrongSigner))
    );
    eprintln!("[core004] Mallory's false ownership claim rejected by the S1 signer check");

    // ------------------------------------------------------------ outages
    // Missing conductor service is an availability error, not a denial.
    let missing = ConductorResolver::connect(&ConductorTarget {
        admin: SocketAddr::from(([127, 0, 0, 1], 9)),
        app_id: APP.into(),
        storage_role: "x".into(),
        expected_storage_dna: "x".into(),
        key_binding_v2: false,
    })
    .await;
    assert!(missing.is_err());
    // All hosts down: every exclusion is a transport outcome, never a
    // binding/authorisation outcome.
    for host in music_hosts.values() {
        host.kill();
    }
    drop(mallory_host);
    let Err(ResolveError::NoAuthenticatedHost(rejected)) =
        authenticate(&mut bob_reader, &alice, &p1, &connector(3, 3)).await
    else {
        panic!("no host is reachable");
    };
    assert_eq!(rejected.len(), 4);
    for r in &rejected {
        assert!(
            matches!(
                r.reason,
                RejectReason::Transport(
                    TransportFailure::Unavailable(_) | TransportFailure::TimedOut(_)
                )
            ),
            "{} : {:?}",
            r.node_agent,
            r.reason
        );
    }
    eprintln!("[core004] all hosts offline: classified as unavailable, not denied");
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
