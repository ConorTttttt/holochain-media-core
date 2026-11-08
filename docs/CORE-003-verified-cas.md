# CORE-003 — Verified ciphertext CAS and local replica recovery

Status: draft implementation, not a production storage or distribution network.

## Delivered in this PR

- Create an on-disk content-addressed store for **opaque ciphertext only**.
- Accept exactly signed-manifest-authenticated chunk bytes from CORE-002; reject wrong length/SHA-256 before writing.
- Publish objects via random same-directory temporary files, sync file contents, atomically publish without overwriting an existing object.
- Report verified, missing and corrupt objects separately.
- Read with a signed-length bound (4 MiB + AES-GCM tag per S1 chunk), not an unchecked whole-file allocation.
- Continue interrupted local replica copies without losing verified earlier chunks.
- Try several independently verified local stores for missing objects and repair corrupt objects **only after** reading authentic bytes from a valid source.
- Explicitly reject symlinked object, intermediate object directory and root paths; do not interpret filesystem errors as a missing object.
- Hide VerifiedManifest and VerifiedReceipt structure fields from external Rust crates. Only a parser that verifies a pinned signature can create VerifiedManifest; access data through read-only getters.
- Exercise the store against independently signed, encrypted **Python Music S1-generated fixtures** with actual chunks.

## API

- VerifiedCas::new(trusted_local_root)
- VerifiedCas::put_chunk(verified_manifest, chunk_index, encrypted_bytes)
- VerifiedCas::read_chunk(verified_manifest, chunk_index) -> ciphertext
- VerifiedCas::audit(verified_manifest) -> { verified, missing, corrupt }
- VerifiedCas::sync_from(verified_manifest, &[verified_local_source]) -> SyncReport or SyncFailure with index and partial progress.

The store does not receive content keys or private grants, and it never outputs plaintext. The trust in each source's bytes comes from the separately authenticated expected publisher signing key and full signed manifest.

## What we still need

- **Network transport:** this is not a MoQ, HLS or HTTPS downloader; CORE-004 connects authenticated hosts, stream transfer and peer discovery.
- **Enforcement:** the store does not validate grants or authorise playback; CORE-005 handles rights.
- **Identity:** the expected publisher key is supplied by the caller and must be independently bound to a Holochain agent.
- **Availability:** a signed storage receipt attests one historical event, not continuous custody. No storage SLA or durable peer roster is implemented.
- **Garbage collection and quotas:** CAS objects may be shared between packages, so naive per-file deletion is unsafe. Safe reference-aware GC, quotas, persistence/cancellation tuning and large-file performance remain outstanding.
- **OS path races:** file metadata/path checks are insufficient when an attacker can mutate the storage root concurrently. The root must be private and owned by the trusted application process. Before hostile local-user deployment, use directory-handle-relative O_NOFOLLOW/openat-style operations on Unix and equivalent handle-based Windows APIs and test races.
- **Crash durability:** syncs file data and Unix directory metadata where supported; no verified power-loss test, disk-full torture test, or independent recoverable transaction journal yet.
- **1 GiB stress:** tested file fixture sizes are small synthetic chunks. The v1.0 scope's 1 GiB and real-device runs remain mandatory future work.
- **Native Windows:** CI compiles/runs the ordinary tests on Windows, but real file-sharing/hardware behaviour needs testing separately.

## Verification

Core CI: Rust formatting, Clippy, ordinary tests and a separate pinned-source Python Music interop suite. Python-generated encrypted test chunks drive local CAS replication, source unavailability, on-disk corruption/repair, root/object symlink refusal, concurrent safe puts, empty package handling and idempotent restart.

The full signed-manifest golden vectors come from Music at pinned commit bd7aabc3e9ea1fef1e8e8f674301e1b5ffecb637. This PR does not edit Music, Video or MoQ.

**Scope gate:** CORE-003 is an initial storage implementation and must not be marked fully complete against the Notion v1.0 G03 criteria until quota, disk failure, larger file, security race and physical network tests are supported and recorded.

## Dependency and merge order

CORE-001 PR #1 -> CORE-002 PR #2 -> CORE-003 PR #3, each reviewable separately. Don't merge stacked drafts out of order. Retarget after predecessors merge.
