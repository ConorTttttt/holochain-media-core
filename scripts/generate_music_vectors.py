#!/usr/bin/env python3
"""Generate disposable cross-language vectors using the REAL pinned Music package.py.

This script imports Music's Python implementation. It is intentionally not
a second reimplementation of its signing or ciphertext algorithms.
Never use user data, production keys, or sensitive original media in fixtures.
"""
from __future__ import annotations

import argparse
import copy
import json
import subprocess
import sys
import tempfile
from pathlib import Path

PINNED_MUSIC_COMMIT = "bd7aabc3e9ea1fef1e8e8f674301e1b5ffecb637"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--music-repo", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    music_root = args.music_repo.resolve()
    commit = subprocess.check_output(
        ["git", "-C", str(music_root), "rev-parse", "HEAD"], text=True
    ).strip()
    if commit != PINNED_MUSIC_COMMIT:
        raise SystemExit(f"Wrong Music source version: {commit}; expected {PINNED_MUSIC_COMMIT}")
    sys.path.insert(0, str(music_root))

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from holochain_storage import package as music

    artist_key = Ed25519PrivateKey.from_private_bytes(bytes([1]) * 32)
    host_key = Ed25519PrivateKey.from_private_bytes(bytes([2]) * 32)
    artist_public = music.public_key_bytes(artist_key)
    host_public = music.public_key_bytes(host_key)

    # Nonempty, non-music synthetic binary including nonprintable bytes;
    # intentionally several chunks to exercise ordering and AEAD metadata.
    synthetic = bytes(range(64)) + b"\x00\xffS1 interoperability"
    with tempfile.TemporaryDirectory(prefix="music-core-vectors-") as td:
        root = Path(td)
        source = root / "source.bin"
        source.write_bytes(synthetic)
        manifest, _ = music.create_package(
            source, root / "origin", artist_key, chunk_size=16
        )
        music.verify_package(manifest, root / "origin", artist_public)
        receipt = music.replicate_package(
            manifest, root / "origin", root / "replica", artist_public, host_key
        )
        music.verify_receipt(receipt, manifest, host_public, artist_public)

        source.write_bytes(b"")
        empty, _ = music.create_package(
            source, root / "empty", artist_key, chunk_size=16
        )
        music.verify_package(empty, root / "empty", artist_public)

        chunks = [
            {
                "index": chunk["index"],
                "ciphertext_b64": music.b64(
                    music.object_path(root / "origin", chunk["sha256"]).read_bytes()
                ),
            }
            for chunk in manifest["body"]["chunks"]
        ]

        def valid_signed_invalid_body(name: str, transform):
            body = copy.deepcopy(manifest["body"])
            transform(body)
            return name, music._sign(body, artist_key)

        invalid = dict([
            valid_signed_invalid_body(
                "reused_nonce",
                lambda body: body["chunks"][1].update(
                    nonce=body["chunks"][0]["nonce"]
                ),
            ),
            valid_signed_invalid_body(
                "skipped_chunk_index",
                lambda body: body["chunks"][1].update(index=3),
            ),
            valid_signed_invalid_body(
                "incorrect_total",
                lambda body: body.update(total_plain_bytes=body["total_plain_bytes"] + 1),
            ),
            valid_signed_invalid_body(
                "unsupported_cipher",
                lambda body: body.update(cipher="AES-128-GCM"),
            ),
            valid_signed_invalid_body(
                "short_nonfinal_chunk",
                lambda body: body["chunks"][0].update(plain_bytes=7, cipher_bytes=23),
            ),
            valid_signed_invalid_body(
                "oversized_chunk",
                lambda body: body.update(chunk_size=music.MAX_CHUNK_BYTES + 1),
            ),
        ])
        bad_receipt = copy.deepcopy(receipt["body"])
        bad_receipt["manifest_sha256"] = "00" * 32
        invalid["receipt_wrong_package"] = music._sign(bad_receipt, host_key)

        vectors = {
            "music_commit": PINNED_MUSIC_COMMIT,
            "artist_public_key": music.b64(artist_public),
            "host_public_key": music.b64(host_public),
            "package": manifest,
            "manifest_sha256": music.manifest_digest(manifest),
            "canonical_body_b64": music.b64(music.canonical(manifest["body"])),
            "canonical_envelope_b64": music.b64(music.canonical(manifest)),
            "plaintext_bytes": len(synthetic),
            "chunks": chunks,
            "receipt": receipt,
            "empty_package": empty,
            "empty_manifest_sha256": music.manifest_digest(empty),
            "signed_invalid": invalid,
        }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(vectors, sort_keys=True, indent=2), encoding="utf-8")
    print(f"Created non-sensitive Music S1 interoperability vectors from {commit}")


if __name__ == "__main__":
    main()
