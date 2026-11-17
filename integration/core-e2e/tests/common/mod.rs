//! Shared harness for the CORE-004 acceptance suite: paths to the pinned
//! Holochain Music checkout, the Python fixture driver, real Music MoQ host
//! processes, and Mallory's deliberately malicious (but real) MoQ host.

#![allow(dead_code)]

use anyhow::{anyhow, ensure, Context, Result};
use bytes::Bytes;
use holochain_content_core::compat::VerifiedManifest;
use holochain_content_core::PackageId;
use holochain_content_retrieval::transport::DeliverFn;
use holochain_content_retrieval::{DocumentKind, ObjectTransport, TransportFailure};
use holochain_moq_realtime::certs;
use moq_native_ietf::{quic, tls};
use moq_transport::{
    coding::TrackNamespace,
    serve::{self, ServeError, Subgroup},
    session::Publisher,
};
use serde_json::Value;
use std::{
    collections::HashMap,
    env, fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

/// holochain-music commit whose S1/S2/S9 code this suite exercises.
pub const PINNED_MUSIC_COMMIT: &str = "bd7aabc3e9ea1fef1e8e8f674301e1b5ffecb637";

pub struct Paths {
    pub music: PathBuf,
    pub python: PathBuf,
    pub helper: PathBuf,
    pub moq_host: PathBuf,
    pub storage_dna: PathBuf,
}

fn env_path(name: &str, default: PathBuf) -> PathBuf {
    env::var_os(name).map(PathBuf::from).unwrap_or(default)
}

impl Paths {
    pub fn discover() -> Self {
        let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        let music = env_path(
            "HOLOCHAIN_MUSIC_REPO",
            manifest_dir.join("../../../holochain-music"),
        );
        let music = music.canonicalize().unwrap_or_else(|_| {
            panic!(
                "holochain-music checkout missing at {}; set HOLOCHAIN_MUSIC_REPO",
                music.display()
            )
        });
        let head = Command::new("git")
            .arg("-C")
            .arg(&music)
            .args(["rev-parse", "HEAD"])
            .output()
            .expect("git rev-parse");
        let head = String::from_utf8_lossy(&head.stdout).trim().to_owned();
        if env::var_os("CORE004_ALLOW_UNPINNED_MUSIC").is_none() {
            assert_eq!(
                head, PINNED_MUSIC_COMMIT,
                "acceptance suite is pinned to holochain-music {PINNED_MUSIC_COMMIT}; \
                 set CORE004_ALLOW_UNPINNED_MUSIC=1 to run against {head}"
            );
        }
        let paths = Self {
            python: env_path("HOLOCHAIN_MUSIC_PYTHON", PathBuf::from("python3")),
            helper: manifest_dir.join("tests/helpers/core004_fixture.py"),
            moq_host: env_path(
                "HOLOCHAIN_MUSIC_MOQ_BIN",
                music.join("crates/moq-music/target/debug/holochain-music-moq"),
            ),
            storage_dna: env_path(
                "MUSIC_STORAGE_DNA",
                music.join("dna/workdir/music_storage.dna"),
            ),
            music,
        };
        assert!(
            paths.moq_host.is_file(),
            "Music MoQ host binary missing at {}; build with \
             `cargo build --manifest-path <music>/crates/moq-music/Cargo.toml`",
            paths.moq_host.display()
        );
        assert!(
            paths.storage_dna.is_file(),
            "Music storage DNA missing at {}; build wasm and `hc dna pack <music>/dna/workdir`",
            paths.storage_dna.display()
        );
        paths
    }

    /// Run the Python fixture driver; returns (exit code, parsed JSON line).
    pub async fn python(&self, args: Vec<String>) -> (i32, Value) {
        let python = self.python.clone();
        let helper = self.helper.clone();
        let music = self.music.clone();
        let out = tokio::task::spawn_blocking(move || {
            Command::new(python)
                .arg(helper)
                .args(args)
                .env("PYTHONPATH", music)
                .output()
        })
        .await
        .expect("python task")
        .expect("start python fixture driver");
        let stdout = String::from_utf8_lossy(&out.stdout);
        let line = stdout.lines().last().unwrap_or_default();
        let value = serde_json::from_str(line).unwrap_or_else(|_| {
            panic!(
                "fixture driver produced no JSON (status {:?}): stdout={stdout} stderr={}",
                out.status,
                String::from_utf8_lossy(&out.stderr)
            )
        });
        (out.status.code().unwrap_or(-1), value)
    }

    /// Run the driver and require success.
    pub async fn python_ok(&self, args: Vec<String>) -> Value {
        let (code, value) = self.python(args.clone()).await;
        assert_eq!(code, 0, "fixture driver {args:?} failed: {value}");
        value
    }
}

pub fn s(v: &Value, key: &str) -> String {
    v.get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("missing JSON field {key} in {v}"))
        .to_owned()
}

/// Private temporary workspace, removed on drop.
pub struct TempDir(pub PathBuf);
impl TempDir {
    pub fn new(label: &str) -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = env::temp_dir().join(format!("{label}-{}-{nanos}", std::process::id()));
        fs::create_dir(&root).expect("create private test workspace");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        }
        Self(root)
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        if env::var_os("CORE004_KEEP_TEMP").is_none() {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
}

/// A real `holochain-music-moq serve` process (Music's v1 host).
pub struct MusicHost {
    pub child: Arc<Mutex<Option<Child>>>,
    pub url: String,
    pub fingerprint_hex: String,
}

impl MusicHost {
    pub async fn start(
        binary: &Path,
        served_list: &Path,
        store: &Path,
        state: &Path,
        bytes_per_second: u64,
    ) -> Self {
        fs::create_dir_all(state).unwrap();
        let ready = state.join("ready.json");
        let log = fs::File::create(state.join("moq-host.log")).unwrap();
        let child = Command::new(binary)
            .arg("serve")
            .arg("--served-list")
            .arg(served_list)
            .arg("--store")
            .arg(store)
            .arg("--cert-dir")
            .arg(state.join("cert"))
            .arg("--ready-file")
            .arg(&ready)
            .args(["--bind", "127.0.0.1:0", "--max-sessions", "32"])
            .arg("--bytes-per-second")
            .arg(bytes_per_second.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(log)
            .spawn()
            .expect("start real Holochain Music MoQ host");
        let child = Arc::new(Mutex::new(Some(child)));
        for _ in 0..300 {
            if let Some(c) = child.lock().unwrap().as_mut() {
                assert!(
                    c.try_wait().unwrap().is_none(),
                    "Music MoQ host exited during start-up; see {}",
                    state.join("moq-host.log").display()
                );
            }
            if let Ok(bytes) = fs::read(&ready) {
                if let Ok(v) = serde_json::from_slice::<Value>(&bytes) {
                    return Self {
                        child,
                        url: s(&v, "url"),
                        fingerprint_hex: s(&v, "cert_fingerprint_hex"),
                    };
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("Music MoQ host did not become ready");
    }

    pub fn kill(&self) {
        if let Some(mut c) = self.child.lock().unwrap().take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

impl Drop for MusicHost {
    fn drop(&mut self) {
        self.kill();
    }
}

/// Wraps a transport and kills a host process after `after` delivered
/// objects: a genuine mid-transfer network interruption.
pub struct KillAfter<T> {
    pub inner: T,
    pub after: usize,
    pub delivered: Arc<AtomicUsize>,
    pub victim: Arc<Mutex<Option<Child>>>,
}

impl<T: ObjectTransport + Send> ObjectTransport for KillAfter<T> {
    async fn fetch_document(
        &mut self,
        package: PackageId,
        kind: DocumentKind,
    ) -> Result<Vec<u8>, TransportFailure> {
        self.inner.fetch_document(package, kind).await
    }

    async fn fetch_objects<'a>(
        &'a mut self,
        manifest: &'a VerifiedManifest,
        indices: &'a [usize],
        deliver: &'a mut DeliverFn<'_>,
    ) -> Result<(), TransportFailure> {
        let after = self.after;
        let delivered = self.delivered.clone();
        let victim = self.victim.clone();
        let mut wrapped = move |index: usize, bytes: Vec<u8>| {
            let outcome = deliver(index, bytes);
            if delivered.fetch_add(1, Ordering::SeqCst) + 1 == after {
                if let Some(mut c) = victim.lock().unwrap().take() {
                    let _ = c.kill();
                    let _ = c.wait();
                }
            }
            outcome
        };
        self.inner
            .fetch_objects(manifest, indices, &mut wrapped)
            .await
    }
}

// ---------------------------------------------------------------- Mallory

/// What Mallory's host does with ciphertext objects.
#[derive(Clone, Copy, Debug)]
pub enum Tamper {
    /// Flip one bit in every object (same length, wrong SHA-256).
    FlipBit,
}

struct Served {
    manifest: Bytes,
    receipt: Bytes,
    objects: Vec<Bytes>,
}

/// Mallory's MoQ host: speaks the same Music v1 protocol over real QUIC with
/// its own certificate and serves the *correct* signed documents, but
/// tampered ciphertext objects. Built from the same moq-transport serve API
/// as Music's host, so only the bytes differ.
pub struct MaliciousHost {
    pub url: String,
    pub fingerprint_hex: String,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for MaliciousHost {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn load_served(
    manifest_path: &Path,
    receipt_path: &Path,
    store: &Path,
) -> Result<(String, Served)> {
    let manifest = fs::read(manifest_path)?;
    let value: Value = serde_json::from_slice(&manifest)?;
    let body = &value["body"];
    let file_id = body["file_id"].as_str().context("file id")?.to_owned();
    let mut objects = Vec::new();
    for chunk in body["chunks"].as_array().context("chunks")? {
        let sha = chunk["sha256"].as_str().context("sha")?;
        objects.push(Bytes::from(fs::read(
            store.join("objects/sha256").join(&sha[..2]).join(sha),
        )?));
    }
    Ok((
        file_id,
        Served {
            manifest: Bytes::from(manifest),
            receipt: Bytes::from(fs::read(receipt_path)?),
            objects,
        },
    ))
}

async fn serve_track(
    track: serve::TrackWriter,
    catalogue: Arc<HashMap<String, Served>>,
    tamper: Tamper,
) -> Result<()> {
    let name = track.name.to_string();
    let parts: Vec<&str> = name.split('/').collect();
    let served = match (parts.first(), parts.get(1)) {
        (Some(&"file"), Some(id)) => catalogue.get(*id),
        _ => None,
    };
    let Some(served) = served else {
        let _ = track.close(ServeError::not_found_ctx("not served"));
        return Ok(());
    };
    let payloads: Vec<Bytes> = match &parts[2..] {
        ["manifest"] => vec![served.manifest.clone()],
        ["receipt"] => vec![served.receipt.clone()],
        ["objects", list] => list
            .split(',')
            .map(|i| {
                let i: usize = i.parse()?;
                let mut bytes = served
                    .objects
                    .get(i)
                    .ok_or_else(|| anyhow!("index"))?
                    .to_vec();
                match tamper {
                    Tamper::FlipBit => bytes[0] ^= 0x01,
                }
                Ok(Bytes::from(bytes))
            })
            .collect::<Result<_>>()?,
        _ => {
            let _ = track.close(ServeError::not_found_ctx("malformed"));
            return Ok(());
        }
    };
    let mut subgroups = track.subgroups().map_err(|e| anyhow!("{e}"))?;
    let mut writer = subgroups
        .create(Subgroup {
            group_id: 0,
            subgroup_id: 0,
            priority: 0,
        })
        .map_err(|e| anyhow!("{e}"))?;
    tokio::time::sleep(Duration::from_millis(200)).await;
    for payload in payloads {
        writer.write(payload).map_err(|e| anyhow!("{e}"))?;
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    tokio::time::sleep(Duration::from_millis(600)).await;
    Ok(())
}

impl MaliciousHost {
    /// `files`: (manifest path, receipt path) pairs, objects read from `store`.
    pub async fn start(
        dir: &Path,
        store: &Path,
        files: &[(PathBuf, PathBuf)],
        tamper: Tamper,
    ) -> Self {
        let mut catalogue = HashMap::new();
        for (manifest, receipt) in files {
            let (id, served) = load_served(manifest, receipt, store).expect("load Mallory files");
            catalogue.insert(id, served);
        }
        let catalogue = Arc::new(catalogue);
        let (cert, key, identity) =
            certs::generate_localhost_cert_with_identity(&dir.join("mallory-cert")).unwrap();
        let tls = tls::Args {
            cert: vec![cert],
            key: vec![key],
            ..Default::default()
        }
        .load()
        .unwrap();
        let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let endpoint = quic::Endpoint::new(quic::Config::new(bind, None, tls).unwrap()).unwrap();
        let local = endpoint.client.local_addr().unwrap();
        let mut server = endpoint.server.expect("server config");
        let task = tokio::spawn(async move {
            while let Some((session, info)) = server.accept().await {
                let catalogue = catalogue.clone();
                tokio::spawn(async move {
                    let run = async move {
                        let (session, mut publisher) =
                            Publisher::accept(session, info.transport).await?;
                        let (writer, mut requests, reader) = serve::Tracks {
                            namespace: TrackNamespace::from_utf8_path(
                                holochain_content_moq::HOST_NAMESPACE,
                            ),
                        }
                        .produce();
                        let _keep = writer;
                        let serve_requests = async move {
                            while let Some(track) = requests.next().await {
                                let catalogue = catalogue.clone();
                                tokio::spawn(serve_track(track, catalogue, tamper));
                            }
                            Ok::<(), anyhow::Error>(())
                        };
                        tokio::select! {
                            r = session.run() => r.map_err(|e| anyhow!("{e}"))?,
                            r = publisher.publish_namespace(reader) => r.map_err(|e| anyhow!("{e}"))?,
                            r = serve_requests => r?,
                        }
                        Ok::<(), anyhow::Error>(())
                    };
                    let _ = run.await;
                });
            }
        });
        Self {
            url: format!("https://{local}"),
            fingerprint_hex: identity
                .fingerprint
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect(),
            task,
        }
    }
}

pub fn ensure_files_bounded(store: &Path, manifest: &VerifiedManifest) -> Result<()> {
    // Bounded resource check: exactly one object file per signed chunk, each
    // of the signed length, and no leftover temporary files.
    let mut files = Vec::new();
    let root = store.join("objects/sha256");
    for dir in fs::read_dir(&root)? {
        for f in fs::read_dir(dir?.path())? {
            files.push(f?.path());
        }
    }
    let expected: std::collections::HashSet<String> = manifest
        .chunks()
        .iter()
        .map(|c| {
            c.ciphertext_sha256
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect()
        })
        .collect();
    ensure!(
        files.len() == expected.len(),
        "unexpected file count {}",
        files.len()
    );
    for f in files {
        let name = f.file_name().unwrap().to_string_lossy().to_string();
        ensure!(expected.contains(&name), "unexpected file {name}");
    }
    Ok(())
}
