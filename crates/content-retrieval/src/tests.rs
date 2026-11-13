//! Unit tests with mock transports and a mock conductor. These exercise
//! orchestration logic only; the real-service claim rests on the
//! `integration/core-e2e` acceptance suite (real conductors, real MoQ/QUIC).
//!
//! Fixtures are synthetic S1-shaped manifests signed here with fixed test
//! keys. The S1 verifier itself is tested against independent Python Music
//! vectors in `content-core`; nothing here tests signature verification.

use crate::fetch::HostSource;
use crate::*;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signer, SigningKey};
use holochain_content_core::binding::*;
use holochain_content_core::compat::{canonical_json, verify_music_manifest, VerifiedManifest};
use holochain_content_core::storage::VerifiedCas;
use holochain_content_core::PackageId;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Wake, Waker};

const ALICE: &str = "uhCAkAliceTestAgent";
const CAROL: &str = "uhCAkCarolTestAgent";
const DAVE: &str = "uhCAkDaveTestAgent";
const MALLORY: &str = "uhCAkMalloryTestAgent";

// ---------------------------------------------------------------- executor

struct ThreadWaker(std::thread::Thread);
impl Wake for ThreadWaker {
    fn wake(self: Arc<Self>) {
        self.0.unpark();
    }
}

fn block_on<F: Future>(future: F) -> F::Output {
    let waker = Waker::from(Arc::new(ThreadWaker(std::thread::current())));
    let mut cx = Context::from_waker(&waker);
    let mut future = std::pin::pin!(future);
    loop {
        if let Poll::Ready(v) = future.as_mut().poll(&mut cx) {
            return v;
        }
        std::thread::park();
    }
}

// ---------------------------------------------------------------- fixtures

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn sign(body: Value, key: &SigningKey) -> Value {
    let canonical = canonical_json(&body).unwrap();
    json!({
        "body": body,
        "signer": STANDARD.encode(key.verifying_key().to_bytes()),
        "signature": STANDARD.encode(key.sign(&canonical).to_bytes()),
    })
}

struct Package {
    artist: SigningKey,
    signed: Vec<u8>,
    manifest: VerifiedManifest,
    objects: Vec<Vec<u8>>,
}

fn package(chunks: usize) -> Package {
    let artist = SigningKey::from_bytes(&[7; 32]);
    let chunk_size = 16u64;
    let objects: Vec<Vec<u8>> = (0..chunks)
        .map(|i| (0..32u8).map(|b| b.wrapping_mul(i as u8 + 3)).collect())
        .collect();
    let body = json!({
        "schema": "holochain-storage/encrypted-package/v1",
        "file_id": "5a".repeat(32),
        "cipher": "AES-256-GCM",
        "chunk_size": chunk_size,
        "total_plain_bytes": chunk_size * chunks as u64,
        "chunks": objects.iter().enumerate().map(|(i, o)| json!({
            "index": i,
            "sha256": hex(&Sha256::digest(o)),
            "nonce": STANDARD.encode([i as u8; 12]),
            "plain_bytes": chunk_size,
            "cipher_bytes": chunk_size + 16,
        })).collect::<Vec<_>>(),
    });
    let signed = serde_json::to_vec(&sign(body, &artist)).unwrap();
    let manifest = verify_music_manifest(&signed, &artist.verifying_key().to_bytes()).unwrap();
    Package {
        artist,
        signed,
        manifest,
        objects,
    }
}

fn receipt(pkg: &Package, host: &SigningKey) -> Vec<u8> {
    serde_json::to_vec(&sign(
        json!({
            "schema": "holochain-storage/replica-receipt/v1",
            "file_id": pkg.manifest.package_id().to_string(),
            "manifest_sha256": pkg.manifest.digest().to_string(),
            "chunk_count": pkg.objects.len(),
            "received_at": "2026-11-13T00:00:00+00:00",
        }),
        host,
    ))
    .unwrap()
}

fn rec(author: &str, body: Value) -> ConductorRecord {
    ConductorRecord::from_validated_conductor(author, format!("uhCkk-{author}"), body).unwrap()
}

// ---------------------------------------------------------------- mock host

#[derive(Clone, Default)]
struct MockHost {
    manifest: Option<Vec<u8>>,
    receipt: Option<Vec<u8>>,
    objects: HashMap<usize, Vec<u8>>,
    /// Interrupt after delivering this many objects in total.
    interrupt_after: Option<usize>,
    unavailable: bool,
    identity_mismatch: bool,
    requests: Arc<Mutex<Vec<Vec<usize>>>>,
    delivered: Arc<Mutex<usize>>,
}

impl ObjectTransport for MockHost {
    async fn fetch_document(
        &mut self,
        _package: PackageId,
        kind: DocumentKind,
    ) -> Result<Vec<u8>, TransportFailure> {
        if self.identity_mismatch {
            return Err(TransportFailure::IdentityMismatch("mock pin".into()));
        }
        if self.unavailable {
            return Err(TransportFailure::Unavailable("mock offline".into()));
        }
        match kind {
            DocumentKind::Manifest => self.manifest.clone(),
            DocumentKind::Receipt => self.receipt.clone(),
        }
        .ok_or_else(|| TransportFailure::Refused("document not available".into()))
    }

    async fn fetch_objects<'a>(
        &'a mut self,
        _manifest: &'a VerifiedManifest,
        indices: &'a [usize],
        deliver: &'a mut transport::DeliverFn<'_>,
    ) -> Result<(), TransportFailure> {
        {
            if self.identity_mismatch {
                return Err(TransportFailure::IdentityMismatch("mock pin".into()));
            }
            if self.unavailable {
                return Err(TransportFailure::Unavailable("mock offline".into()));
            }
            self.requests.lock().unwrap().push(indices.to_vec());
            for (n, &index) in indices.iter().enumerate() {
                let mut delivered = self.delivered.lock().unwrap();
                if Some(*delivered) == self.interrupt_after {
                    return Err(TransportFailure::Interrupted {
                        delivered: n,
                        detail: "mock connection lost".into(),
                    });
                }
                let Some(bytes) = self.objects.get(&index).cloned() else {
                    return Err(TransportFailure::Refused("object not held".into()));
                };
                *delivered += 1;
                drop(delivered);
                if deliver(index, bytes) == Delivery::Stop {
                    return Ok(());
                }
            }
            Ok(())
        }
    }
}

fn full_host(pkg: &Package) -> MockHost {
    MockHost {
        manifest: Some(pkg.signed.clone()),
        objects: pkg.objects.iter().cloned().enumerate().collect(),
        ..MockHost::default()
    }
}

fn source(agent: &str, host: MockHost) -> HostSource<MockHost> {
    HostSource {
        node_agent: agent.into(),
        transport: host,
    }
}

// ---------------------------------------------------------------- fetch

#[test]
fn complete_fetch_stores_only_verified_objects() {
    let pkg = package(5);
    let tmp = tempfile::tempdir().unwrap();
    let cas = VerifiedCas::new(tmp.path()).unwrap();
    let mut hosts = vec![source(CAROL, full_host(&pkg))];
    let report = block_on(fetch_verified_content(
        &pkg.manifest,
        &mut hosts,
        &cas,
        FetchOptions::default(),
    ))
    .unwrap();
    assert_eq!(report.total, 5);
    assert_eq!(report.initial.missing, 5);
    assert_eq!(report.downloaded, 5);
    assert_eq!(report.hosts[0].delivered, 5);
    assert_eq!(cas.audit(&pkg.manifest).unwrap().verified, 5);
    for (i, o) in pkg.objects.iter().enumerate() {
        assert_eq!(&cas.read_chunk(&pkg.manifest, i).unwrap(), o);
    }
}

#[test]
fn interrupted_transfer_resumes_from_verified_objects_after_restart() {
    let pkg = package(6);
    let tmp = tempfile::tempdir().unwrap();
    let cas = VerifiedCas::new(tmp.path()).unwrap();
    let mut flaky = full_host(&pkg);
    flaky.interrupt_after = Some(2);
    let mut hosts = vec![source(CAROL, flaky)];
    let error = block_on(fetch_verified_content(
        &pkg.manifest,
        &mut hosts,
        &cas,
        FetchOptions::default(),
    ))
    .unwrap_err();
    let FetchError::Incomplete { report, missing } = error else {
        panic!("expected incomplete");
    };
    assert_eq!(report.downloaded, 2);
    assert_eq!(missing, vec![2, 3, 4, 5]);
    assert!(matches!(
        report.hosts[0].failure,
        Some(TransportFailure::Interrupted { delivered: 2, .. })
    ));

    // "Client restart": a new store handle over the same directory.
    let restarted = VerifiedCas::new(tmp.path()).unwrap();
    let healthy = full_host(&pkg);
    let requests = healthy.requests.clone();
    let mut hosts = vec![source(CAROL, healthy)];
    let report = block_on(fetch_verified_content(
        &pkg.manifest,
        &mut hosts,
        &restarted,
        FetchOptions::default(),
    ))
    .unwrap();
    assert_eq!(report.already_verified, 2);
    assert_eq!(report.downloaded, 4);
    // Only the missing objects were requested.
    assert_eq!(*requests.lock().unwrap(), vec![vec![2, 3, 4, 5]]);
}

#[test]
fn corrupt_or_truncated_host_object_is_rejected_and_alternate_host_used() {
    let pkg = package(4);
    let tmp = tempfile::tempdir().unwrap();
    let cas = VerifiedCas::new(tmp.path()).unwrap();
    let mut mallory = full_host(&pkg);
    let mut tampered = pkg.objects[1].clone();
    tampered[3] ^= 0x40;
    mallory.objects.insert(1, tampered);
    let mut truncating = full_host(&pkg);
    truncating.objects.insert(2, pkg.objects[2][..20].to_vec());
    let mut hosts = vec![
        source(MALLORY, mallory),
        source(DAVE, truncating),
        source(CAROL, full_host(&pkg)),
    ];
    let report = block_on(fetch_verified_content(
        &pkg.manifest,
        &mut hosts,
        &cas,
        FetchOptions::default(),
    ))
    .unwrap();
    assert_eq!(report.hosts[0].rejected_object, Some(1));
    assert_eq!(report.hosts[0].delivered, 1);
    // Dave supplies index 1 (Mallory's rejected object) then truncates 2.
    assert_eq!(report.hosts[1].rejected_object, Some(2));
    assert_eq!(report.hosts[1].delivered, 1);
    assert_eq!(report.hosts[2].delivered, 2);
    assert_eq!(cas.audit(&pkg.manifest).unwrap().verified, 4);
    assert_eq!(cas.read_chunk(&pkg.manifest, 1).unwrap(), pkg.objects[1]);
}

#[test]
fn corrupt_local_object_is_repaired_from_network() {
    let pkg = package(3);
    let tmp = tempfile::tempdir().unwrap();
    let cas = VerifiedCas::new(tmp.path()).unwrap();
    for (i, o) in pkg.objects.iter().enumerate() {
        cas.put_chunk(&pkg.manifest, i, o).unwrap();
    }
    let digest = hex(&pkg.manifest.chunks()[2].ciphertext_sha256);
    let path = tmp
        .path()
        .join("objects/sha256")
        .join(&digest[..2])
        .join(&digest);
    std::fs::write(&path, b"bit rot").unwrap();
    let host = full_host(&pkg);
    let requests = host.requests.clone();
    let mut hosts = vec![source(CAROL, host)];
    let report = block_on(fetch_verified_content(
        &pkg.manifest,
        &mut hosts,
        &cas,
        FetchOptions::default(),
    ))
    .unwrap();
    assert_eq!(report.initial.corrupt, 1);
    assert_eq!(report.repaired, 1);
    assert_eq!(report.downloaded, 0);
    assert_eq!(*requests.lock().unwrap(), vec![vec![2]]);
    assert_eq!(cas.read_chunk(&pkg.manifest, 2).unwrap(), pkg.objects[2]);
}

#[test]
fn unavailable_hosts_leave_explicit_missing_list_not_a_denial() {
    let pkg = package(3);
    let tmp = tempfile::tempdir().unwrap();
    let cas = VerifiedCas::new(tmp.path()).unwrap();
    let down = MockHost {
        unavailable: true,
        ..full_host(&pkg)
    };
    let mut hosts = vec![source(CAROL, down)];
    let error = block_on(fetch_verified_content(
        &pkg.manifest,
        &mut hosts,
        &cas,
        FetchOptions::default(),
    ))
    .unwrap_err();
    let FetchError::Incomplete { report, missing } = error else {
        panic!("expected incomplete");
    };
    assert_eq!(missing, vec![0, 1, 2]);
    assert!(matches!(
        report.hosts[0].failure,
        Some(TransportFailure::Unavailable(_))
    ));
    // No host at all is the same explicit outcome.
    let mut none: Vec<HostSource<MockHost>> = Vec::new();
    let error = block_on(fetch_verified_content(
        &pkg.manifest,
        &mut none,
        &cas,
        FetchOptions::default(),
    ))
    .unwrap_err();
    assert!(matches!(error, FetchError::Incomplete { .. }));
}

#[test]
fn empty_and_already_complete_packages_make_no_requests() {
    let empty = {
        let artist = SigningKey::from_bytes(&[7; 32]);
        let body = json!({
            "schema": "holochain-storage/encrypted-package/v1", "file_id": "6b".repeat(32),
            "cipher": "AES-256-GCM", "chunk_size": 16, "total_plain_bytes": 0, "chunks": [],
        });
        let signed = serde_json::to_vec(&sign(body, &artist)).unwrap();
        verify_music_manifest(&signed, &artist.verifying_key().to_bytes()).unwrap()
    };
    let tmp = tempfile::tempdir().unwrap();
    let cas = VerifiedCas::new(tmp.path()).unwrap();
    let host = MockHost::default();
    let requests = host.requests.clone();
    let mut hosts = vec![source(CAROL, host)];
    let report = block_on(fetch_verified_content(
        &empty,
        &mut hosts,
        &cas,
        FetchOptions::default(),
    ))
    .unwrap();
    assert_eq!(report.total, 0);
    assert!(requests.lock().unwrap().is_empty());

    // Duplicate retrieval of a complete package is idempotent.
    let pkg = package(3);
    let host = full_host(&pkg);
    let requests = host.requests.clone();
    let mut hosts = vec![source(CAROL, host)];
    block_on(fetch_verified_content(
        &pkg.manifest,
        &mut hosts,
        &cas,
        FetchOptions::default(),
    ))
    .unwrap();
    let again = block_on(fetch_verified_content(
        &pkg.manifest,
        &mut hosts,
        &cas,
        FetchOptions::default(),
    ))
    .unwrap();
    assert_eq!(again.already_verified, 3);
    assert_eq!(again.downloaded, 0);
    assert_eq!(requests.lock().unwrap().len(), 1);
}

#[test]
fn requests_are_bounded_by_batch_size() {
    let pkg = package(7);
    let tmp = tempfile::tempdir().unwrap();
    let cas = VerifiedCas::new(tmp.path()).unwrap();
    let host = full_host(&pkg);
    let requests = host.requests.clone();
    let mut hosts = vec![source(CAROL, host)];
    block_on(fetch_verified_content(
        &pkg.manifest,
        &mut hosts,
        &cas,
        FetchOptions {
            max_objects_per_request: 3,
        },
    ))
    .unwrap();
    assert_eq!(
        *requests.lock().unwrap(),
        vec![vec![0, 1, 2], vec![3, 4, 5], vec![6]]
    );
}

// ---------------------------------------------------------------- resolve

#[derive(Default)]
struct MockMeta {
    keys: HashMap<String, Vec<ConductorRecord>>,
    commitments: HashMap<String, Vec<ConductorRecord>>,
    claims: Vec<ConductorRecord>,
    endpoints: HashMap<String, Vec<ConductorRecord>>,
    offline: bool,
}

impl MetadataSource for MockMeta {
    async fn signing_keys(&mut self, agent: &str) -> Result<Vec<ConductorRecord>, MetadataError> {
        self.get(&self.keys, agent)
    }
    async fn file_commitments(
        &mut self,
        agent: &str,
    ) -> Result<Vec<ConductorRecord>, MetadataError> {
        self.get(&self.commitments, agent)
    }
    async fn replica_claims(
        &mut self,
        _owner: &str,
        _package: PackageId,
    ) -> Result<Vec<ConductorRecord>, MetadataError> {
        if self.offline {
            return Err(MetadataError("conductor offline".into()));
        }
        Ok(self.claims.clone())
    }
    async fn moq_endpoints(&mut self, host: &str) -> Result<Vec<ConductorRecord>, MetadataError> {
        self.get(&self.endpoints, host)
    }
}

impl MockMeta {
    fn get(
        &self,
        map: &HashMap<String, Vec<ConductorRecord>>,
        k: &str,
    ) -> Result<Vec<ConductorRecord>, MetadataError> {
        if self.offline {
            return Err(MetadataError("conductor offline".into()));
        }
        Ok(map.get(k).cloned().unwrap_or_default())
    }
}

struct World {
    pkg: Package,
    meta: MockMeta,
    receipts: HashMap<String, Vec<u8>>,
}

fn key_record(agent: &str, purpose: &str, key: &SigningKey) -> ConductorRecord {
    rec(
        agent,
        json!({"schema": KEY_BINDING_V1, "agent": agent, "purpose": purpose,
               "signing_key_hex": hex(&key.verifying_key().to_bytes())}),
    )
}

fn world(hosts: &[(&str, u8, u16)]) -> World {
    let pkg = package(3);
    let file_id = pkg.manifest.package_id().to_string();
    let digest = pkg.manifest.digest().to_string();
    let mut meta = MockMeta::default();
    meta.keys.insert(
        ALICE.into(),
        vec![key_record(ALICE, "owner-manifest", &pkg.artist)],
    );
    meta.commitments.insert(
        ALICE.into(),
        vec![rec(
            ALICE,
            json!({"schema": FILE_COMMITMENT_V1, "owner_agent": ALICE,
                   "file_id": file_id, "manifest_sha256": digest}),
        )],
    );
    let mut receipts = HashMap::new();
    for (agent, seed, port) in hosts {
        let host_key = SigningKey::from_bytes(&[*seed; 32]);
        let signed = receipt(&pkg, &host_key);
        let receipt_sha = hex(&Sha256::digest(
            canonical_json(&serde_json::from_slice::<Value>(&signed).unwrap()).unwrap(),
        ));
        meta.keys.insert(
            (*agent).into(),
            vec![key_record(agent, "host-receipt", &host_key)],
        );
        meta.claims.push(rec(
            agent,
            json!({"schema": REPLICA_CLAIM_V1, "node_agent": agent, "owner_agent": ALICE,
                   "file_id": file_id, "manifest_sha256": digest,
                   "receipt_sha256": receipt_sha}),
        ));
        meta.endpoints.insert(
            (*agent).into(),
            vec![rec(
                agent,
                json!({"schema": MOQ_ENDPOINT_V1, "node_agent": agent, "owner_agent": ALICE,
                       "file_id": file_id, "manifest_sha256": digest,
                       "url": format!("https://127.0.0.1:{port}"),
                       "cert_fingerprint_hex": hex(&[*seed; 32])}),
            )],
        );
        receipts.insert((*agent).to_string(), signed);
    }
    World {
        pkg,
        meta,
        receipts,
    }
}

struct Connector(HashMap<u16, MockHost>);
impl HostConnector for Connector {
    type Transport = MockHost;
    fn connect(&self, endpoint: &PinnedEndpoint) -> MockHost {
        self.0.get(&endpoint.port()).cloned().unwrap_or(MockHost {
            unavailable: true,
            ..MockHost::default()
        })
    }
}

#[test]
fn resolve_and_authenticate_two_hosts_then_fetch() {
    let mut w = world(&[(CAROL, 2, 4001), (DAVE, 3, 4002)]);
    let resolved = block_on(resolve_content(
        &mut w.meta,
        ALICE,
        w.pkg.manifest.package_id(),
        EndpointPolicy::LoopbackOnly,
    ))
    .unwrap();
    assert_eq!(resolved.hosts.len(), 2);
    assert_eq!(resolved.pin.manifest_digest, w.pkg.manifest.digest());
    let mut carol = full_host(&w.pkg);
    carol.receipt = Some(w.receipts[CAROL].clone());
    let mut dave = full_host(&w.pkg);
    dave.receipt = Some(w.receipts[DAVE].clone());
    let connector = Connector(HashMap::from([(4001, carol), (4002, dave)]));
    let content = block_on(authenticate_content(resolved, &connector)).unwrap();
    assert_eq!(content.hosts.len(), 2);
    assert!(content.rejected.is_empty());
    let (owned, mut sources) = content.into_sources();
    let tmp = tempfile::tempdir().unwrap();
    let cas = VerifiedCas::new(tmp.path()).unwrap();
    block_on(fetch_verified_content(
        owned.manifest(),
        &mut sources,
        &cas,
        FetchOptions::default(),
    ))
    .unwrap();
    assert_eq!(cas.audit(owned.manifest()).unwrap().verified, 3);
}

#[test]
fn forged_endpoint_wrong_manifest_forged_receipt_and_pin_mismatch_are_rejected() {
    let mut w = world(&[(CAROL, 2, 4001), (DAVE, 3, 4002), (MALLORY, 4, 4003)]);
    // Mallory advertises an extra endpoint claiming to be Carol's: it is
    // filtered by authorship (and the zome would refuse it anyway).
    let file_id = w.pkg.manifest.package_id().to_string();
    let digest = w.pkg.manifest.digest().to_string();
    w.meta.endpoints.get_mut(CAROL).unwrap().push(rec(
        MALLORY,
        json!({"schema": MOQ_ENDPOINT_V1, "node_agent": CAROL, "owner_agent": ALICE,
               "file_id": file_id, "manifest_sha256": digest,
               "url": "https://127.0.0.1:4999", "cert_fingerprint_hex": "ee".repeat(32)}),
    ));
    let resolved = block_on(resolve_content(
        &mut w.meta,
        ALICE,
        w.pkg.manifest.package_id(),
        EndpointPolicy::LoopbackOnly,
    ))
    .unwrap();
    assert_eq!(resolved.hosts.len(), 3);
    assert_eq!(resolved.hosts[0].endpoint.port(), 4001);

    // Carol: presents the wrong certificate (pin mismatch).
    let carol = MockHost {
        identity_mismatch: true,
        ..full_host(&w.pkg)
    };
    // Dave: serves a different (validly signed) manifest, then a receipt.
    let other = package(2);
    let mut dave = full_host(&w.pkg);
    dave.manifest = Some(other.signed.clone());
    dave.receipt = Some(w.receipts[DAVE].clone());
    // Mallory: right manifest, but a receipt she forged with another key.
    let mut mallory = full_host(&w.pkg);
    mallory.receipt = Some(receipt(&w.pkg, &SigningKey::from_bytes(&[99; 32])));
    let connector = Connector(HashMap::from([
        (4001, carol),
        (4002, dave),
        (4003, mallory),
    ]));
    let Err(ResolveError::NoAuthenticatedHost(rejected)) =
        block_on(authenticate_content(resolved, &connector))
    else {
        panic!("no host should authenticate");
    };
    let reason = |agent: &str| {
        rejected
            .iter()
            .find(|r| r.node_agent == agent)
            .map(|r| r.reason.clone())
            .unwrap()
    };
    assert!(matches!(
        reason(CAROL),
        RejectReason::Transport(TransportFailure::IdentityMismatch(_))
    ));
    assert_eq!(
        reason(DAVE),
        RejectReason::Binding(BindingError::CommitmentMismatch)
    );
    assert!(matches!(
        reason(MALLORY),
        RejectReason::Binding(BindingError::Receipt(_))
    ));
}

#[test]
fn resolution_failures_are_classified() {
    let mut w = world(&[(CAROL, 2, 4001)]);
    w.meta.offline = true;
    assert!(matches!(
        block_on(resolve_content(
            &mut w.meta,
            ALICE,
            w.pkg.manifest.package_id(),
            EndpointPolicy::LoopbackOnly
        )),
        Err(ResolveError::Metadata(_))
    ));
    let mut w = world(&[(CAROL, 2, 4001)]);
    assert_eq!(
        block_on(resolve_content(
            &mut w.meta,
            ALICE,
            PackageId::from_bytes([1; 32]),
            EndpointPolicy::LoopbackOnly
        )),
        Err(ResolveError::Binding(BindingError::MissingRecord))
    );
    // A second owner key makes the owner binding ambiguous.
    let mut w = world(&[(CAROL, 2, 4001)]);
    let extra = key_record(ALICE, "owner-manifest", &SigningKey::from_bytes(&[8; 32]));
    w.meta.keys.get_mut(ALICE).unwrap().push(extra);
    assert_eq!(
        block_on(resolve_content(
            &mut w.meta,
            ALICE,
            w.pkg.manifest.package_id(),
            EndpointPolicy::LoopbackOnly
        )),
        Err(ResolveError::Binding(BindingError::Ambiguous))
    );
    // A host whose endpoint is not loopback is excluded under the default
    // policy with the endpoint boundary as the reason.
    let mut w = world(&[(CAROL, 2, 4001)]);
    let ep = w.meta.endpoints.get_mut(CAROL).unwrap();
    let mut body = ep[0].body().clone();
    body.insert("url".into(), json!("https://192.168.1.20:4001"));
    ep[0] = rec(CAROL, Value::Object(body));
    let Err(ResolveError::NoAuthenticatedHost(rejected)) = block_on(resolve_content(
        &mut w.meta,
        ALICE,
        w.pkg.manifest.package_id(),
        EndpointPolicy::LoopbackOnly,
    )) else {
        panic!("expected exclusion");
    };
    assert_eq!(
        rejected[0].reason,
        RejectReason::Binding(BindingError::EndpointNotAllowed)
    );
}
