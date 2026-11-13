# CORE-004 — Holochain identity, MoQ retrieval and VerifiedCas, end to end

Status: **technical milestone, not production.** Implemented on branch
`ccr-53e220c1-45x2cc`, stacked on CORE-003 (`feat/core-003-verified-cas`,
5420d57). It connects the existing CORE-002 verifier and CORE-003
`VerifiedCas` to real Holochain discovery and certificate-pinned MoQ/QUIC
transport **using the existing Holochain Music S2 DNA and Music v1 MoQ host
protocol unchanged**.

## What was built

```
Bob's app ──► ConductorResolver ──(app WebSocket, signed zome calls)──► Bob's conductor
                 │                                    Music S2 storage DNA (unchanged)
                 ▼
          resolve_content ── binding::{select_unique, key_for_agent, commitment_pin,
                 │                      verify_moq_endpoint}
                 ▼
        authenticate_content ── MoqHostTransport ──(QUIC/TLS pin, MoQT draft-14)──► Music v1 host
                 │   manifest  → binding::verify_owned_manifest  (S1 sig + owner commitment)
                 │   receipt   → binding::verify_replica_claim   (host key + claim)
                 ▼
        fetch_verified_content ── per object: VerifiedCas::repair_chunk (len + SHA-256 first)
                 │   audit-first resume · per-host rejection · alternate host · final re-audit
                 ▼
          VerifiedCas (ciphertext only)  ──►  Music grant/licence + decrypt (unchanged, in Music)
```

| Crate | Workspace | Depends on | Purpose |
|---|---|---|---|
| `holochain-content-core` (`crates/content-core`) | root | pure Rust | S1 verifier, `VerifiedCas`, **new** `binding` (S2), `canonical_json`, `VerifiedReceipt::envelope_sha256`, `VerifiedCas::repair_chunk` |
| `holochain-content-retrieval` (`crates/content-retrieval`) | root | content-core | `MetadataSource`, `ObjectTransport`, `HostConnector`, `resolve_content`, `authenticate_content`, `fetch_verified_content` |
| `holochain-content-cli` (`crates/content-cli`) | root | content-core | `holochain-media-core` opt-in local adapter for Music |
| `holochain-content-release` (`crates/content-release`) | root | content-core | governed-release contract (Video groundwork, test-only authority) |
| `holochain-content-moq` (`integration/content-moq`) | integration | holochain-moq `realtime`/`protocol` @ fba4ccf | Music v1 host client over pinned MoQ |
| `holochain-content-holochain` (`integration/content-holochain`) | integration | holochain_client 0.9.0 | read-only conductor resolver |
| `holochain-content-core-e2e` (`integration/core-e2e`) | integration | holochain 0.7.0 sweettest | real-service acceptance suite |

The `integration/` workspace is excluded from the root workspace so the
verified core keeps its small pure-Rust dependency set and existing Linux and
Windows CI. Its lockfile was seeded from holochain-moq@fba4ccf.

### Reuse decisions (no new protocols)

* **Identity**: Music S2 storage DNA (`dna/`, hdk 0.7.0) — `get_signing_keys`,
  `get_file_commitments`, `get_replica_claims`, `get_moq_endpoints`. No DNA,
  entry, link or zome change. Rust checks mirror
  `holochain_storage/holochain_identity.py` and the endpoint checks in
  `music_catalogue/moq_conductor.py`.
* **Transport**: Music v1 host (`crates/moq-music/src/serve.rs`): namespace
  `holochain-music/host/v1`; tracks `file/<id>/manifest`, `file/<id>/receipt`,
  `file/<id>/objects/<i>,<j>,…` (≤ 64). Client uses holochain-moq
  `MoqSubscribeNode::new_with_pinned_identity` (SHA-256 of complete DER cert).
  `crates/realtime` and `crates/protocol` are byte-identical between
  holochain-moq `main` (fba4ccf) and the revision Music's host is built from
  (ccd9a8e). Live streaming is untouched; this is reliable object retrieval.
* **Discovery path**: storage-DNA file commitments by the owner agent. The
  Music catalogue DNA (track → file) is app-specific and stays in Music.
* **Packaging, grants, decryption**: Music's Python code, unchanged.

## API contracts

`holochain_content_core::binding` — inputs are `ConductorRecord`s (entry body +
validated action author from a trusted local conductor):

| Function | Checks | Error boundary |
|---|---|---|
| `key_for_agent(rec, agent, purpose)` | author = agent, exact fields, schema, agent, purpose, lowercase hex | `AuthorMismatch`, `InvalidRecord`, `KeyNotBound` |
| `select_unique(records, pred)` | exactly one match | `MissingRecord`, `Ambiguous` (no "first wins") |
| `commitment_pin(rec, owner)` | owner-authored commitment | as above |
| `verify_owned_manifest(json, owner, key_rec, commit_rec)` → `OwnedManifest` | S1 signature by the **bound** key, commitment file ID + signed-envelope digest | `Manifest(VerifyError)`, `CommitmentMismatch` |
| `verify_replica_claim(json, &OwnedManifest, node, key_rec, claim_rec)` → `AuthenticatedReplica` | receipt signed by bound host key for this manifest; claim author/fields; `receipt_sha256` = SHA-256 of canonical receipt | `Receipt(VerifyError)`, `ClaimMismatch` |
| `verify_moq_endpoint(rec, node, owner, pin, policy)` → `PinnedEndpoint` | host-authored, exact host/owner/file/digest; canonical `https://IPv4:port`; loopback, or RFC1918 with `AllowPrivateLan` | `EndpointMismatch`, `EndpointNotAllowed` |

`holochain_content_retrieval`:

* `resolve_content(&mut impl MetadataSource, owner_agent, package_id, policy)
  -> ResolvedContent { pin, owner records, hosts: Vec<HostPins>, rejected }`.
  `owner_agent` must come from an independent source (invite, catalogue).
* `authenticate_content(ResolvedContent, &impl HostConnector)
  -> AuthenticatedContent { owned, hosts, rejected }`.
* `fetch_verified_content(&VerifiedManifest, &mut [HostSource<T>], &VerifiedCas, FetchOptions)
  -> Result<FetchReport, FetchError>` with `FetchError::Incomplete { report, missing }`
  or `FetchError::Store { index, error }`.
* Every exclusion is a `HostRejection { node_agent, reason }` where `reason` is
  `Binding(BindingError)` (security), `Transport(TransportFailure)` or
  `Metadata(MetadataError)` (availability). `TransportFailure::IdentityMismatch`
  is the certificate pin; `Unavailable`, `Refused`, `TimedOut`, `Interrupted`
  and `Protocol` are never authorisation outcomes.

Conceptual interfaces from the brief map to: `resolve_content` (resolve),
`authenticate_content` + `fetch_verified_content` (fetch). `check_content_access`
is **not implemented in Rust** (CORE-005); entitlement decisions remain Music's
`unwrap_content_grant`, which the acceptance suite exercises. See
"Access and entitlements" below.

## Quickstart

```bash
# Media Core (this repo, branch ccr-53e220c1-45x2cc)
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
cargo test --workspace --all-targets --features serde_json/preserve_order

# Python Music vectors (CORE-002 procedure, now incl. receipt digest)
python -m venv .venv && .venv/bin/pip install 'cryptography==46.0.4'
.venv/bin/python scripts/generate_music_vectors.py \
  --music-repo ../holochain-music --output target/music-golden-vectors.json
MUSIC_VECTORS=target/music-golden-vectors.json \
  cargo test --workspace --all-targets --features holochain-content-core/music-interop-tests
```

## Real-service acceptance suite

Prerequisites (one-time):

```bash
# Sibling checkout of holochain-music at the pinned commit
git -C ../holochain-music checkout bd7aabc3e9ea1fef1e8e8f674301e1b5ffecb637
rustup target add wasm32-unknown-unknown
cargo install holochain_cli_bundle --version =0.7.0 --locked     # provides hc-dna
(cd ../holochain-music/dna && cargo build --release --target wasm32-unknown-unknown \
   && hc-dna pack workdir)                                        # music_storage.dna
cargo build --manifest-path ../holochain-music/crates/moq-music/Cargo.toml  # v1 host
```

Run (first build of Holochain 0.7.0 takes ~15–30 min):

```bash
export HOLOCHAIN_MUSIC_PYTHON=$PWD/.venv/bin/python   # cryptography 46.x
cargo test --manifest-path integration/Cargo.toml -p holochain-content-core-e2e \
  --test core004_acceptance -- --nocapture
```

Environment variables: `HOLOCHAIN_MUSIC_REPO` (default `../holochain-music`),
`HOLOCHAIN_MUSIC_PYTHON`, `HOLOCHAIN_MUSIC_MOQ_BIN`, `MUSIC_STORAGE_DNA`,
`CORE004_ALLOW_UNPINNED_MUSIC=1` (skip the commit pin), `CORE004_KEEP_TEMP=1`.

**Kernels without IPv6.** Holochain 0.7.0's websocket listener always binds
IPv6 first and only falls back on `EADDRNOTAVAIL`; a kernel with no IPv6 at
all returns `EAFNOSUPPORT` and the conductor aborts. On such hosts only:

```bash
cc -shared -fPIC -O2 -o /tmp/libipv6_errno_shim.so \
   integration/core-e2e/support/ipv6_errno_shim.c -ldl
LD_PRELOAD=/tmp/libipv6_errno_shim.so cargo test --manifest-path integration/Cargo.toml ...
```

The shim only rewrites that errno so the conductor takes its own IPv4 path.

### Topology and matrix

Five Sweettest conductors (one agent each) on one DHT with the unchanged Music
storage DNA. Alice packages synthetic media with Music's Python S1 code
(P1: 24 × 16 KiB chunks; P2: 3 chunks). Hosts run the real
`holochain-music-moq serve` binary; Mallory runs a real QUIC/MoQ host built
on the same moq-transport serve API that serves correct documents but
bit-flipped ciphertext. Bob resolves only through his conductor's app
WebSocket.

| Case | Mechanism | Rejecting boundary / result |
|---|---|---|
| Mallory writes key binding / commitment / replica claim / endpoint in another agent's name | `call_fallible` | Music integrity zome: "actual Holochain action author" |
| Discover + authenticate P1 | resolver → hosts Alice, Carol, Mallory, Eve | 3 authenticated |
| TLS certificate mismatch (Eve's endpoint pin ≠ server cert) | real QUIC handshake | `Transport(IdentityMismatch)` from `PinnedFingerprintVerifier` |
| Interrupted transfer | Alice's host process killed after 5 objects | `Incomplete`, 5 verified objects retained |
| Client restart + resume | new `VerifiedCas` handle | only 19 missing objects requested |
| Corrupted ciphertext from an authenticated host | Mallory bit-flips | object rejected before disk; host abandoned |
| Alternate host recovery | Carol after Alice/Mallory | complete, 24/24 verified |
| Local corruption repair | overwrite one CAS object | `initial.corrupt = 1`, `repaired = 1` |
| Duplicate retrieval | second fetch | no requests, `already_verified = 24` |
| Bounded storage | file count/names in CAS | exactly the signed objects, no temp files |
| Grant decryption | Music licence + stream grant, Rust-authenticated artist key | plaintext SHA-256 = original |
| Unauthorized key access / wrong recipient / impersonation / forged / expired grant / no grant | Music `unwrap_content_grant`, AES-GCM | `content-grant` or `aes-gcm` boundary with specific message |
| Forged host receipt (P2, Eve) | receipt signed by unbound key | `Binding(Receipt(WrongSigner))`; Carol serves P2 |
| False ownership (Mallory commits Alice's P1 with her own key) | resolve owner=Mallory | `Binding(Manifest(WrongSigner))` |
| Conductor service missing | resolver to closed port | `MetadataError` (unavailability) |
| All hosts offline | hosts killed | 4 × `Transport(Unavailable|TimedOut)`, no binding reasons |

Wrong manifest digest, wrong file commitment, empty packages and truncated
objects are covered by unit tests (Python vectors / mock transports); the
Music v1 host refuses to serve empty packages, so empty-package retrieval is
verified locally (no network objects are needed).

### Evidence (13 November 2026, this sandbox)

* Root workspace: fmt/clippy clean; tests 20 (core) + 10 (retrieval) +
  4 (cli) + 4 (release) pass, also with `serde_json/preserve_order`; Python
  interop 41 (core) pass with and without `preserve_order` (includes a test
  pinning finding 2 below).
* Integration crates: `holochain-content-moq` unit tests 2 pass.
* `core004_acceptance`: **1 passed** in 240.8 s (5 conductors). Log lines:

```
[core004] Holochain records published and consistent across 5 conductors
[core004] P1 authenticated hosts: Alice, Carol, Mallory; Eve rejected by certificate pin
[core004] interrupted after 5/24 verified objects: Some(Interrupted { delivered: 5, detail: "object stream stalled" })
[core004] resumed: 5 reused, Mallory's tampered object 5 rejected, Carol supplied 19
[core004] Bob decrypted the VerifiedCas replica with Music grants; plaintext SHA-256 matches
[core004] wrong-recipient, impersonation, forged, expired and keyless access denied by Music boundaries
[core004] P2: Eve's forged receipt rejected by the receipt signer check; Carol served P2
[core004] Mallory's false ownership claim rejected by the S1 signer check
[core004] all hosts offline: classified as unavailable, not denied
```

* Music (branch `ccr-53e220c1-45x2cc`): `python -m unittest discover -s tests`
  444 OK / 34 skipped on `main`; 453 OK / 34 skipped with the adapter enabled.

## Security and trust boundaries

| Boundary | Trusted input | Never trusted |
|---|---|---|
| Conductor → `ConductorRecord` | loopback admin socket, pinned storage-DNA hash, validated action author | body `agent` fields, peer JSON |
| Owner identity | owner agent supplied by caller + owner-authored key binding/commitment | manifest `signer` field |
| Host identity | host-authored key binding, claim, endpoint | host readiness files, receipt `signer` field |
| Transport | SHA-256 certificate pin from host-authored endpoint | CA chain, hostname, TOFU |
| Ciphertext | signed manifest length + SHA-256 per object | host progress reports, object order claims |
| Plaintext | Music grant/licence unwrap + AES-GCM (in Music) | ciphertext availability |

No content key, grant, X25519 or signing private key enters any Media Core
crate. MoQ code makes no Holochain calls. No public-network listener is used:
hosts bind 127.0.0.1 and the default endpoint policy is loopback-only.

## Findings (reported, not silently fixed)

1. **Fixed — CORE-002 canonical JSON depended on serde_json map order.**
   Any workspace enabling `serde_json/preserve_order` (Holochain does, via
   `one_err`) made every Python signature fail. Now explicitly sorted; CI
   runs with and without the feature. Signed bytes/digests unchanged.
2. **S2 key bindings are not proof-of-possession.** An agent can bind someone
   else's *public* key. Consequences: (a) Mallory can author a replica claim
   naming Carol's receipt and Carol's public key bound to herself, appearing
   as an authenticated host for content she never received (integrity is
   unaffected — every object is still hash-verified); (b) Mallory can bind
   Alice's artist key and commit Alice's package as her own, so a reader who
   asks for "Mallory's" content would authenticate Alice's ciphertext under
   Mallory's attribution. Decryption still needs Alice's grant. Fix requires a
   signed proof of possession in the binding (a Music DNA/format change: out of
   scope for this milestone; needs versioning and a migration plan).
3. **Receipts do not name the host agent**, which enables (2a).
4. **Holochain 0.7.0 dual-bind on IPv6-less kernels** (see shim above).
5. **Music v1 host refuses empty packages** (`served package has no chunks`).
6. Hostile peers can still make `moq-transport` buffer large objects before
   length checks (known holochain-moq limitation); the realtime queue is
   bounded (256 objects / 32 MiB, drop-oldest → reported as `Protocol`).
7. `fetch_verified_content` performs blocking file I/O inside async code;
   acceptable for the local adapter, to be moved to a blocking pool for UI use.

## Access and entitlements (status)

Implemented and tested **in Music** (unchanged): temporary streaming grants,
perpetual personal licences, recipient X25519 binding, issuer = Holochain-bound
artist key, expiry and clock-skew rules, managed offline and licensed export.
Media Core does not yet evaluate grants (CORE-005). Required interface:

```text
check_content_access(subject_agent, &OwnedManifest, requested Right,
                     evidence = signed grant, issuer key from binding, now)
  -> Authorized { rights, expires } | Denied(reason) | Expired | Unavailable
```

It must verify issuer (bound owner key), subject (listener agent from the
reader's conductor), recipient key, manifest digest/file ID, schema/terms,
validity window and requested right, and must never treat ciphertext
availability, a rights flag, a timeout or a malformed response as permission
or as denial. Rentals, subscriptions, payments, refunds, settlement and
DRM-like offline enforcement are not implemented anywhere and need their own
modules; a permanent plaintext export cannot be revoked.

## Outstanding production hardening

Proof-of-possession key bindings and key rotation/revocation; host-agent
naming in receipts; NAT/relay and non-loopback deployment review; reconnect
and per-host back-off; quota and reference-aware GC; descriptor-relative
no-follow filesystem operations; power-loss/disk-full tests; 1 GiB and
endurance runs; Windows execution of the integration suite and CLI; physical
two-device test; independent security review; licence selection.

## Proposed next milestone — CORE-005

Rust `check_content_access` over Music `content-grant/v1` and
`personal-licence/v1` (verification only; key unwrap stays in the app), with
golden vectors generated by Music's Python, wired into
`authenticate_content` callers; plus a versioned S2 key-binding v2 with
proof-of-possession signatures and an explicit v1 compatibility path.
