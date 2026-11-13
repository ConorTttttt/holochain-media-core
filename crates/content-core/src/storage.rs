//! Local content-addressed storage for ciphertext authenticated by a signed
//! Music S1 manifest. The store never receives or persists content keys.
//!
//! Files are named by SHA-256 of ciphertext and written via synced temporary
//! files and atomic no-clobber publish/verified repair. Reads are bounded by
//! signed chunk lengths before content hashing.
//!
//! Root directories MUST be owned by a trusted local user. Path checks reject
//! symlinks but do not stop a hostile concurrent filesystem path swap.
//! Descriptor-relative no-follow operations are a later hardening requirement.

use crate::compat::{verify_music_ciphertext, VerifiedManifest};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;

/// A filesystem or content-integrity failure.
#[derive(Debug)]
pub enum StoreError {
    /// Signed manifest has no object at the index, or supplied bytes do not match.
    InvalidChunk,
    /// Expected content-addressed object is missing.
    Missing,
    /// An existing content-addressed object has the wrong size or hash.
    Corrupt,
    /// Refuses symlinked, nonregular or unsafe paths.
    UnsafePath,
    /// No candidate replica returned authentic ciphertext.
    NoHealthySource,
    /// An underlying filesystem operation failed.
    Io(io::Error),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidChunk => f.write_str("object does not match the authenticated manifest"),
            Self::Missing => f.write_str("ciphertext object is missing"),
            Self::Corrupt => f.write_str("ciphertext object is corrupt"),
            Self::UnsafePath => f.write_str("unsafe or symlinked storage path"),
            Self::NoHealthySource => f.write_str("no healthy source contains the required object"),
            Self::Io(error) => write!(f, "storage I/O failure: {error}"),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<io::Error> for StoreError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

/// Result of an authenticated ciphertext write.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WriteOutcome {
    /// New object placed in the store.
    Created,
    /// Complete, verified object already existed.
    AlreadyVerified,
    /// Existing corrupt object atomically replaced with a verified copy.
    Repaired,
}

/// Per-package verified local store state.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AuditReport {
    /// Number of authentic complete ciphertext objects.
    pub verified: usize,
    /// Number of expected objects not found.
    pub missing: usize,
    /// Number of existing objects with bad length or SHA-256.
    pub corrupt: usize,
}

/// Transfer progress retained when a peer goes offline mid-sync.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SyncReport {
    /// Objects already verified before this attempt.
    pub already_verified: usize,
    /// Missing objects copied from a healthy source.
    pub downloaded: usize,
    /// Corrupted objects replaced from a healthy source.
    pub repaired: usize,
}

/// Partial sync failure. Successful chunks remain for the next attempt.
#[derive(Debug)]
pub struct SyncFailure {
    /// Index of the chunk that could not be retrieved.
    pub failed_index: usize,
    /// Verified progress from this attempt before failure.
    pub progress: SyncReport,
    /// Failure reason, never including content keys.
    pub source: StoreError,
}

impl std::fmt::Display for SyncFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "chunk {}: {}", self.failed_index, self.source)
    }
}

impl std::error::Error for SyncFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

/// Local ciphertext store rooted in a trusted non-symlink directory.
///
/// Requires an authenticated VerifiedManifest. This type alone does not
/// authenticate an agent identity, prove a grant, or authorise playback.
#[derive(Clone, Debug)]
pub struct VerifiedCas {
    root: PathBuf,
}

impl VerifiedCas {
    /// Creates a store. The caller must control and protect the directory.
    pub fn new(root: impl AsRef<Path>) -> Result<Self, StoreError> {
        let root = root.as_ref();
        if root.exists() || fs::symlink_metadata(root).is_ok() {
            let metadata = fs::symlink_metadata(root)?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(StoreError::UnsafePath);
            }
        } else {
            fs::create_dir_all(root)?;
        }
        let root = fs::canonicalize(root)?;
        let store = Self { root };
        store.require_root()?;
        Ok(store)
    }

    fn require_root(&self) -> Result<(), StoreError> {
        let metadata = fs::symlink_metadata(&self.root)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(StoreError::UnsafePath);
        }
        Ok(())
    }

    fn chunk(
        manifest: &VerifiedManifest,
        index: usize,
    ) -> Result<&crate::compat::ChunkMetadata, StoreError> {
        manifest.chunks.get(index).ok_or(StoreError::InvalidChunk)
    }

    fn hex(digest: &[u8; 32]) -> String {
        let mut result = String::with_capacity(64);
        for byte in digest {
            use std::fmt::Write as _;
            write!(result, "{byte:02x}").expect("writing to String cannot fail");
        }
        result
    }

    fn path_for(&self, digest: &[u8; 32]) -> PathBuf {
        let hex = Self::hex(digest);
        self.root
            .join("objects")
            .join("sha256")
            .join(&hex[..2])
            .join(hex)
    }

    fn ensure_dirs(&self, digest: &[u8; 32], create: bool) -> Result<(), StoreError> {
        self.require_root()?;
        let hex = Self::hex(digest);
        let paths = [
            self.root.join("objects"),
            self.root.join("objects").join("sha256"),
            self.root.join("objects").join("sha256").join(&hex[..2]),
        ];
        for path in paths {
            if create {
                match fs::create_dir(&path) {
                    Ok(()) => {}
                    Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(e) => return Err(StoreError::Io(e)),
                }
            }
            let metadata = match fs::symlink_metadata(&path) {
                Ok(m) => m,
                Err(e) if e.kind() == io::ErrorKind::NotFound && !create => {
                    return Err(StoreError::Missing);
                }
                Err(e) => return Err(StoreError::Io(e)),
            };
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(StoreError::UnsafePath);
            }
        }
        Ok(())
    }

    fn check_file(path: &Path) -> Result<bool, StoreError> {
        match fs::symlink_metadata(path) {
            Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => Ok(true),
            Ok(_) => Err(StoreError::UnsafePath),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(StoreError::Io(e)),
        }
    }

    /// Load one verified ciphertext object with bounded memory.
    ///
    /// SHA-256 verification does not substitute for AES-GCM authentication.
    pub fn read_chunk(
        &self,
        manifest: &VerifiedManifest,
        index: usize,
    ) -> Result<Vec<u8>, StoreError> {
        let chunk = Self::chunk(manifest, index)?;
        self.ensure_dirs(&chunk.ciphertext_sha256, false)?;
        let path = self.path_for(&chunk.ciphertext_sha256);
        if !Self::check_file(&path)? {
            return Err(StoreError::Missing);
        }
        let mut file = File::open(&path)?;
        let mut bytes = Vec::with_capacity(chunk.cipher_bytes as usize);
        (&mut file)
            .take(chunk.cipher_bytes + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 != chunk.cipher_bytes
            || verify_music_ciphertext(manifest, index, &bytes).is_err()
        {
            return Err(StoreError::Corrupt);
        }
        Ok(bytes)
    }

    fn synced_temp(dir: &Path, bytes: &[u8]) -> Result<NamedTempFile, StoreError> {
        let mut temp = NamedTempFile::new_in(dir)?;
        temp.write_all(bytes)?;
        temp.flush()?;
        temp.as_file().sync_all()?;
        Ok(temp)
    }

    fn sync_directory(dir: &Path) -> Result<(), StoreError> {
        #[cfg(unix)]
        File::open(dir)?.sync_all()?;
        #[cfg(not(unix))]
        let _ = dir;
        Ok(())
    }

    fn write_chunk(
        &self,
        manifest: &VerifiedManifest,
        index: usize,
        ciphertext: &[u8],
        repair: bool,
    ) -> Result<WriteOutcome, StoreError> {
        let chunk = Self::chunk(manifest, index)?;
        verify_music_ciphertext(manifest, index, ciphertext)
            .map_err(|_| StoreError::InvalidChunk)?;
        self.ensure_dirs(&chunk.ciphertext_sha256, true)?;
        let destination = self.path_for(&chunk.ciphertext_sha256);
        let prior = match self.read_chunk(manifest, index) {
            Ok(_) => return Ok(WriteOutcome::AlreadyVerified),
            Err(StoreError::Missing) => false,
            Err(StoreError::Corrupt) if repair => true,
            Err(error) => return Err(error),
        };
        let directory = destination.parent().ok_or(StoreError::UnsafePath)?;
        let temp = Self::synced_temp(directory, ciphertext)?;
        if prior {
            // Replace a corrupt destination only with verified ciphertext.
            if !Self::check_file(&destination)? {
                return Err(StoreError::Missing);
            }
            temp.persist(&destination)
                .map_err(|e| StoreError::Io(e.error))?;
            Self::sync_directory(directory)?;
            Ok(WriteOutcome::Repaired)
        } else {
            match temp.persist_noclobber(&destination) {
                Ok(_) => {
                    Self::sync_directory(directory)?;
                    Ok(WriteOutcome::Created)
                }
                Err(error) if error.error.kind() == io::ErrorKind::AlreadyExists => {
                    self.read_chunk(manifest, index)?;
                    Ok(WriteOutcome::AlreadyVerified)
                }
                Err(error) => Err(StoreError::Io(error.error)),
            }
        }
    }

    /// Store a valid ciphertext chunk without overwriting corruption.
    pub fn put_chunk(
        &self,
        manifest: &VerifiedManifest,
        index: usize,
        ciphertext: &[u8],
    ) -> Result<WriteOutcome, StoreError> {
        self.write_chunk(manifest, index, ciphertext, false)
    }

    /// Store verified ciphertext, atomically replacing an existing object only
    /// when that object is missing or fails its signed length/SHA-256.
    ///
    /// Used by network retrieval to repair local corruption with bytes from an
    /// authenticated host. The new bytes are verified before any write, so a
    /// healthy object is never replaced and corruption is never propagated.
    pub fn repair_chunk(
        &self,
        manifest: &VerifiedManifest,
        index: usize,
        ciphertext: &[u8],
    ) -> Result<WriteOutcome, StoreError> {
        self.write_chunk(manifest, index, ciphertext, true)
    }

    /// Audit authenticated local availability. Unsafe paths and I/O errors
    /// are not silently treated as missing data.
    pub fn audit(&self, manifest: &VerifiedManifest) -> Result<AuditReport, StoreError> {
        let mut report = AuditReport::default();
        for index in 0..manifest.chunks.len() {
            match self.read_chunk(manifest, index) {
                Ok(_) => report.verified += 1,
                Err(StoreError::Missing) => report.missing += 1,
                Err(StoreError::Corrupt) => report.corrupt += 1,
                Err(error) => return Err(error),
            }
        }
        Ok(report)
    }

    /// Fill missing/corrupt objects using verified independent local sources.
    ///
    /// This is a local adapter-level fallback, not a MoQ downloader. Failed
    /// attempts retain authenticated chunks for resumption. Signed host
    /// receipts and network identity checks are separate.
    pub fn sync_from(
        &self,
        manifest: &VerifiedManifest,
        candidates: &[&Self],
    ) -> Result<SyncReport, SyncFailure> {
        let mut progress = SyncReport::default();
        for index in 0..manifest.chunks.len() {
            match self.read_chunk(manifest, index) {
                Ok(_) => {
                    progress.already_verified += 1;
                    continue;
                }
                Err(StoreError::Missing | StoreError::Corrupt) => {}
                Err(error) => {
                    return Err(SyncFailure {
                        failed_index: index,
                        progress,
                        source: error,
                    });
                }
            }
            let mut recovered = false;
            for source in candidates {
                let bytes = match source.read_chunk(manifest, index) {
                    Ok(bytes) => bytes,
                    Err(StoreError::Missing | StoreError::Corrupt) => continue,
                    Err(error) => {
                        return Err(SyncFailure {
                            failed_index: index,
                            progress,
                            source: error,
                        });
                    }
                };
                match self.write_chunk(manifest, index, &bytes, true) {
                    Ok(WriteOutcome::Created) => progress.downloaded += 1,
                    Ok(WriteOutcome::Repaired) => progress.repaired += 1,
                    Ok(WriteOutcome::AlreadyVerified) => progress.already_verified += 1,
                    Err(error) => {
                        return Err(SyncFailure {
                            failed_index: index,
                            progress,
                            source: error,
                        });
                    }
                }
                recovered = true;
                break;
            }
            if !recovered {
                return Err(SyncFailure {
                    failed_index: index,
                    progress,
                    source: StoreError::NoHealthySource,
                });
            }
        }
        Ok(progress)
    }
}
