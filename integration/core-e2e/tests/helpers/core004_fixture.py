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


def prepare(a) -> None:
    root = Path(a.root)
    pkg = root / a.package
    pkg.mkdir(mode=0o700, parents=True, exist_ok=False)
    artist = _ed25519(root / "artist.ed25519")
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
    _out({"grants": sorted(issued)})


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


def main() -> int:
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("prepare")
    s.add_argument("--root", required=True)
    s.add_argument("--package", required=True)
    s.add_argument("--size", type=int, required=True)
    s.add_argument("--chunk-size", type=int, required=True)
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
    a = p.parse_args()
    if a.cmd == "unlock":
        return unlock(a)
    {"prepare": prepare, "host": host, "served-list": served_list, "grants": grants}[a.cmd](a)
    return 0


if __name__ == "__main__":
    sys.exit(main())
