#!/usr/bin/env python3
"""CORE-004 acceptance fixture driver over Holochain Music's REAL Python code.

Invoked by the Rust acceptance test (integration/core-e2e). It imports the
pinned Music modules from PYTHONPATH; it does not re-implement S1 packaging,
receipts, grants or decryption.

Every key it creates is a disposable test key inside the test's private
temporary directory (0600 files). Nothing here touches user data, production
keys, conductors or the network. Content keys never leave this process except
as the test-only `content.key` file that the Rust side never reads.

Exit codes for `unlock`: 0 decrypted; 3 denied by Music's content-grant
boundary; 4 denied by AES-GCM (wrong key/tampered data). Any other failure is
exit 1 and must fail the test (never counted as a denial).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from holochain_storage.package import (
    StorageError, b64, canonical, create_package, decrypt_package, manifest_digest,
    public_key_bytes, replicate_package, sha256, verify_receipt,
)
from music_catalogue.content_grants import (
    ContentGrantError, issue_content_grant, issue_personal_licence, unwrap_content_grant,
)


def _private(path: Path, data: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


def _ed25519(path: Path) -> Ed25519PrivateKey:
    if not path.exists():
        _private(path, Ed25519PrivateKey.generate().private_bytes_raw())
    return Ed25519PrivateKey.from_private_bytes(path.read_bytes())


def _x25519(path: Path) -> X25519PrivateKey:
    if not path.exists():
        _private(path, X25519PrivateKey.generate().private_bytes_raw())
    return X25519PrivateKey.from_private_bytes(path.read_bytes())


def _x_pub(key: X25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _manifest(root: Path, package: str) -> dict:
    return json.loads((root / package / "manifest.json").read_bytes())


def _out(value: dict) -> None:
    sys.stdout.write(json.dumps(value, sort_keys=True) + "\n")


def _key_path(root: Path, ref: str) -> Path:
    """Key references: `artist`, `artist:<generation>`, `host:<name>`,
    `host:<name>:<generation>` (generation >= 2 lives in its own file)."""
    parts = ref.split(":")
    if parts[0] == "artist" and len(parts) in (1, 2):
        base, gen = root, parts[1:]
        name = "artist"
    elif parts[0] == "host" and len(parts) in (2, 3) and parts[1].isalnum():
        base, gen = root / "hosts" / parts[1], parts[2:]
        name = "host"
    else:
        raise SystemExit(f"bad key reference {ref}")
    if gen and gen[0] != "1":
        if not gen[0].isdigit():
            raise SystemExit(f"bad key reference {ref}")
        return base / f"{name}.g{gen[0]}.ed25519"
    return base / f"{name}.ed25519"


def prepare(a) -> None:
    root = Path(a.root)
    pkg = root / a.package
    pkg.mkdir(mode=0o700, parents=True, exist_ok=False)
    artist = _ed25519(_key_path(root, a.artist_key))
    # Synthetic, non-sensitive "media": deterministic header + random tail.
    head = (f"CORE-004 synthetic media {a.package} ".encode() * 4096)[: a.size // 2]
    sample = head + os.urandom(a.size - len(head))
    (pkg / "sample.bin").write_bytes(sample)
    manifest, key = create_package(pkg / "sample.bin", pkg / "origin", artist,
                                   chunk_size=a.chunk_size)
    _private(pkg / "content.key", key)
    (pkg / "manifest.json").write_bytes(canonical(manifest))
    _out({
        "package": a.package,
        "file_id": manifest["body"]["file_id"],
        "manifest_sha256": manifest_digest(manifest),
        "artist_public_hex": public_key_bytes(artist).hex(),
        "sample_sha256": sha256(sample),
        "chunk_count": len(manifest["body"]["chunks"]),
    })


def host(a) -> None:
    root = Path(a.root)
    hdir = root / "hosts" / a.host
    host_key = _ed25519(hdir / "host.ed25519")
    artist_pub = public_key_bytes(_ed25519(root / "artist.ed25519"))
    manifest = _manifest(root, a.package)
    receipt = replicate_package(manifest, root / a.package / "origin", hdir / "store",
                                artist_pub, host_key)
    verify_receipt(receipt, manifest, public_key_bytes(host_key), artist_pub)
    if a.forge_receipt:
        # Same well-formed body, signed by a key the host never bound in
        # Holochain: the receipt signer check must reject it.
        other = Ed25519PrivateKey.generate()
        receipt = {"body": receipt["body"], "signer": b64(public_key_bytes(other)),
                   "signature": b64(other.sign(canonical(receipt["body"])))}
    path = hdir / f"{a.package}.receipt.json"
    path.write_bytes(canonical(receipt))
    _out({
        "host": a.host,
        "node_public_hex": public_key_bytes(host_key).hex(),
        "receipt_sha256": sha256(canonical(receipt)),
        "store": str(hdir / "store"),
        "receipt": str(path),
    })


def served_list(a) -> None:
    root = Path(a.root)
    hdir = root / "hosts" / a.host
    artist_hex = public_key_bytes(_ed25519(root / "artist.ed25519")).hex()
    files = []
    for package in a.packages.split(","):
        manifest = _manifest(root, package)
        files.append({
            "manifest": str(root / package / "manifest.json"),
            "trusted_artist_hex": artist_hex,
            "manifest_sha256": manifest_digest(manifest),
            "receipt": str(hdir / f"{package}.receipt.json"),
        })
    out = hdir / "served.json"
    out.write_text(json.dumps({"files": files}), encoding="utf-8")
    _out({"served_list": str(out)})


def grants(a) -> None:
    root = Path(a.root)
    gdir = root / a.package / "grants"
    gdir.mkdir(mode=0o700, parents=True, exist_ok=True)
    artist = _ed25519(root / "artist.ed25519")
    manifest = _manifest(root, a.package)
    key = (root / a.package / "content.key").read_bytes()
    bob = _x25519(root / "bob.x25519")
    mallory = _x25519(root / "mallory.x25519")
    issued = {
        "bob_licence": issue_personal_licence(
            owner_signer=artist, owner_agent=a.owner_agent, listener_agent=a.bob_agent,
            recipient_public=_x_pub(bob), signed_manifest=manifest, content_key=key),
        "bob_stream": issue_content_grant(
            owner_signer=artist, owner_agent=a.owner_agent, listener_agent=a.bob_agent,
            recipient_public=_x_pub(bob), signed_manifest=manifest, content_key=key,
            lifetime_seconds=1800),
        "bob_short": issue_content_grant(
            owner_signer=artist, owner_agent=a.owner_agent, listener_agent=a.bob_agent,
            recipient_public=_x_pub(bob), signed_manifest=manifest, content_key=key,
            lifetime_seconds=1),
        "mallory_licence": issue_personal_licence(
            owner_signer=artist, owner_agent=a.owner_agent, listener_agent=a.mallory_agent,
            recipient_public=_x_pub(mallory), signed_manifest=manifest, content_key=key),
    }
    # A licence for Bob signed by a key that is NOT Alice's registered key.
    forger = Ed25519PrivateKey.generate()
    body = dict(issued["bob_licence"]["body"])
    issued["forged_licence"] = {"body": body, "signer": b64(public_key_bytes(forger)),
                                "signature": b64(forger.sign(canonical(body)))}
    for name, grant in issued.items():
        (gdir / f"{name}.json").write_bytes(canonical(grant))
    # X25519 *public* keys only: the Rust CORE-005 check needs the listener's
    # recipient key, never a private key.
    _out({"grants": sorted(issued),
          "recipients": {"bob": _x_pub(bob).hex(), "mallory": _x_pub(mallory).hex()}})


def unlock(a) -> int:
    root = Path(a.root)
    manifest = _manifest(root, a.package)
    trusted_artist = bytes.fromhex(a.trusted_artist_hex)
    recipient = _x25519(root / f"{a.recipient}.x25519")
    out = Path(a.out)
    try:
        if a.grant == "none-random-key":
            key = os.urandom(32)  # no grant: guessing a content key
        else:
            if a.wait_expiry:
                time.sleep(2.5)
            grant = json.loads((root / a.package / "grants" / f"{a.grant}.json").read_bytes())
            key = unwrap_content_grant(
                grant, trusted_artist=trusted_artist, owner_agent=a.owner_agent,
                listener_agent=a.listener_agent, recipient_private=recipient,
                signed_manifest=manifest)
    except ContentGrantError as exc:
        _out({"ok": False, "boundary": "content-grant", "error": str(exc)})
        return 3
    try:
        decrypt_package(manifest, Path(a.store), out, key, trusted_artist)
    except StorageError as exc:
        if "decryption failed" in str(exc):
            _out({"ok": False, "boundary": "aes-gcm", "error": str(exc)})
            return 4
        raise
    _out({"ok": True, "sha256": hashlib.sha256(out.read_bytes()).hexdigest()})
    return 0


def bind_v2(a) -> None:
    """S2 key-binding v2 entry signed LOCALLY with Music's own
    make_key_binding_v2 (needs a Music checkout that has it). Prints only the
    public entry; the private key never leaves this process."""
    from holochain_storage.holochain_identity import key_for_agent_v2, make_key_binding_v2, AuthoredRecord
    root = Path(a.root)
    if a.key == "artist":
        path = root / "artist.ed25519"
    elif a.key.startswith("host:") and a.key[5:].isalnum():
        path = root / "hosts" / a.key[5:] / "host.ed25519"
    else:
        raise SystemExit("--key must be artist or host:<name>")
    if not path.is_file():
        raise SystemExit(f"no such key: {a.key}")
    entry = make_key_binding_v2(_ed25519(path), dna_hash=a.dna_hash, agent=a.agent, purpose=a.purpose)
    # Self-check with Music's verifier before handing it to the conductor.
    key_for_agent_v2(AuthoredRecord(a.agent, "local", entry), a.agent, a.purpose, a.dna_hash)
    _out({"entry": entry})


# ---- S2 key lifecycle v2.1 (Music's holochain_storage.key_lifecycle) -------

def _kl():
    from holochain_storage import key_lifecycle
    return key_lifecycle


def v21_incept(a) -> None:
    kl = _kl()
    entry = kl.make_inception(_ed25519(_key_path(Path(a.root), a.key)), dna_hash=a.dna_hash,
                              agent=a.agent, purpose=a.purpose)
    _out({"entry": entry})


def v21_rotate(a) -> None:
    kl = _kl()
    root = Path(a.root)
    entry = kl.make_rotation(_ed25519(_key_path(root, a.new)), _ed25519(_key_path(root, a.old)),
                             dna_hash=a.dna_hash, agent=a.agent, purpose=a.purpose,
                             predecessor_action=a.predecessor_action,
                             predecessor_generation=a.predecessor_generation)
    _out({"entry": entry})


def v21_recover(a) -> None:
    kl = _kl()
    entry = kl.make_recovery(_ed25519(_key_path(Path(a.root), a.new)), dna_hash=a.dna_hash,
                             agent=a.agent, purpose=a.purpose, predecessor_action=a.predecessor_action,
                             predecessor_key_hex=a.predecessor_key_hex,
                             predecessor_generation=a.predecessor_generation)
    _out({"entry": entry})


def v21_revoke(a) -> None:
    kl = _kl()
    _out({"entry": kl.make_revocation(dna_hash=a.dna_hash, agent=a.agent, purpose=a.purpose,
                                      generation=a.generation, signing_key_hex=a.key_hex,
                                      target_action=a.target_action, scope=a.scope)})


def v21_resolve(a) -> None:
    """Music's own reader verdict over records from a real conductor."""
    kl = _kl()
    rows = json.loads(Path(a.records).read_text())
    records = [kl.SequencedRecord(r["author"], r["action_hash"], r["action_seq"], r["body"]) for r in rows]
    anchor = kl.ChainAnchor(a.agent, int(a.anchor_seq)) if a.anchor_seq else None
    verdict = kl.evaluate_key(records, a.agent, a.purpose, a.dna_hash, a.key_hex, a.use, anchor)
    _out({"verdict": verdict})


def v21_anchor(a) -> None:
    """A grant-anchor/v2 entry made by Music's make_grant_anchor."""
    kl = _kl()
    _out({"entry": kl.make_grant_anchor(dna_hash=a.dna_hash, grant_id=a.grant_id,
                                        grant_message=bytes.fromhex(a.grant_message_hex),
                                        issuer_key_action=a.issuer_key_action)})


def v21_verify_anchor(a) -> None:
    """Music's own verdict on a real conductor's anchor and lifecycle rows."""
    kl = _kl()
    rows = json.loads(Path(a.records).read_text())
    lc = kl.resolve_key_lifecycle(
        [kl.SequencedRecord(r["author"], r["action_hash"], r["action_seq"], r["body"]) for r in rows],
        a.agent, "owner-manifest", a.dna_hash)
    r = json.loads(Path(a.anchor).read_text())
    try:
        g = kl.verify_grant_anchor(kl.SequencedRecord(r["author"], r["action_hash"], r["action_seq"], r["body"]),
                                   lc, grant_id=a.grant_id, grant_message=bytes.fromhex(a.grant_message_hex),
                                   issuer_key_action=a.issuer_key_action, recovered_policy=a.policy)
        _out({"verdict": "accepted", "generation": g.generation})
    except StorageError as exc:
        _out({"verdict": "rejected", "error": str(exc)})


def host_v2(a) -> None:
    """Replicate and sign a host-attributed replica-receipt/v2 with Music's code."""
    kl = _kl()
    root = Path(a.root)
    hdir = root / "hosts" / a.host
    host_key = _ed25519(_key_path(root, a.host_key))
    artist_pub = public_key_bytes(_ed25519(_key_path(root, a.artist_key)))
    manifest = _manifest(root, a.package)
    receipt = kl.replicate_package_v2(
        manifest, root / a.package / "origin", hdir / "store", artist_pub, host_key,
        dna_hash=a.dna_hash, host_agent=a.host_agent, host_key_generation=a.host_key_generation,
        host_key_action=a.host_key_action, owner_agent=a.owner_agent)
    path = hdir / f"{a.package}.receipt.json"
    path.write_bytes(kl.receipt_v2_bytes(receipt))
    _out({"host": a.host, "node_public_hex": public_key_bytes(host_key).hex(),
          "receipt_sha256": kl.receipt_v2_digest(receipt), "store": str(hdir / "store"),
          "receipt": str(path), "receipt_json": receipt})


def main() -> int:
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("prepare")
    s.add_argument("--root", required=True)
    s.add_argument("--package", required=True)
    s.add_argument("--size", type=int, required=True)
    s.add_argument("--chunk-size", type=int, required=True)
    s.add_argument("--artist-key", default="artist")
    s = sub.add_parser("host")
    s.add_argument("--root", required=True)
    s.add_argument("--package", required=True)
    s.add_argument("--host", required=True)
    s.add_argument("--forge-receipt", action="store_true")
    s = sub.add_parser("served-list")
    s.add_argument("--root", required=True)
    s.add_argument("--host", required=True)
    s.add_argument("--packages", required=True)
    s = sub.add_parser("grants")
    s.add_argument("--root", required=True)
    s.add_argument("--package", required=True)
    s.add_argument("--owner-agent", required=True)
    s.add_argument("--bob-agent", required=True)
    s.add_argument("--mallory-agent", required=True)
    s = sub.add_parser("unlock")
    for name in ("--root", "--package", "--store", "--grant", "--recipient",
                 "--listener-agent", "--owner-agent", "--trusted-artist-hex", "--out"):
        s.add_argument(name, required=True)
    s.add_argument("--wait-expiry", action="store_true")
    s = sub.add_parser("bind-v2")
    for name in ("--root", "--key", "--agent", "--purpose", "--dna-hash"):
        s.add_argument(name, required=True)
    s = sub.add_parser("v21-incept")
    for name in ("--root", "--key", "--agent", "--purpose", "--dna-hash"):
        s.add_argument(name, required=True)
    s = sub.add_parser("v21-rotate")
    for name in ("--root", "--old", "--new", "--agent", "--purpose", "--dna-hash",
                 "--predecessor-action", "--predecessor-generation"):
        s.add_argument(name, required=True)
    s = sub.add_parser("v21-recover")
    for name in ("--root", "--new", "--agent", "--purpose", "--dna-hash", "--predecessor-action",
                 "--predecessor-key-hex", "--predecessor-generation"):
        s.add_argument(name, required=True)
    s = sub.add_parser("v21-revoke")
    for name in ("--agent", "--purpose", "--dna-hash", "--generation", "--key-hex", "--target-action",
                 "--scope"):
        s.add_argument(name, required=True)
    s = sub.add_parser("v21-resolve")
    for name in ("--records", "--agent", "--purpose", "--dna-hash", "--key-hex", "--use"):
        s.add_argument(name, required=True)
    s.add_argument("--anchor-seq", default="")
    s = sub.add_parser("v21-anchor")
    for name in ("--dna-hash", "--grant-id", "--grant-message-hex", "--issuer-key-action"):
        s.add_argument(name, required=True)
    s = sub.add_parser("v21-verify-anchor")
    for name in ("--records", "--anchor", "--agent", "--dna-hash", "--grant-id", "--grant-message-hex",
                 "--issuer-key-action", "--policy"):
        s.add_argument(name, required=True)
    s = sub.add_parser("host-v2")
    for name in ("--root", "--package", "--host", "--host-key", "--dna-hash", "--host-agent",
                 "--host-key-generation", "--host-key-action", "--owner-agent"):
        s.add_argument(name, required=True)
    s.add_argument("--artist-key", default="artist")
    a = p.parse_args()
    if a.cmd == "unlock":
        return unlock(a)
    {"prepare": prepare, "host": host, "served-list": served_list, "grants": grants,
     "bind-v2": bind_v2, "v21-incept": v21_incept, "v21-rotate": v21_rotate,
     "v21-recover": v21_recover, "v21-revoke": v21_revoke, "v21-resolve": v21_resolve,
     "host-v2": host_v2, "v21-anchor": v21_anchor, "v21-verify-anchor": v21_verify_anchor}[a.cmd](a)
    return 0


if __name__ == "__main__":
    sys.exit(main())
