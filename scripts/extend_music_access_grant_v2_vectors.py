#!/usr/bin/env python3
"""Extend pinned Music/Python v2 vectors with independently signed recovery cases.

All S1 content, Ed25519 signatures and wrapped keys come from Music Python.
Rust is solely the verifier; no Rust-generated acceptance data is used.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import sys
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--music-repo", type=Path, required=True)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    repo = args.music_repo.resolve()
    sys.path[:0] = [str(repo), str(repo / "tests"), str(repo / "scripts")]
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from holochain_storage import key_lifecycle as kl
    from holochain_storage.package import public_key_bytes
    from music_catalogue.access_grant_v2 import grant_message, grant_wrap_context
    from generate_music_access_grant_v2_vectors import case
    from test_access_grant_v2 import (
        ALICE, DNA, checked, make_world, record, signed_grant,
    )

    vectors = json.loads(args.input.read_text(encoding="utf-8"))
    assert vectors["generator"] == "holochain-music/scripts/generate_music_access_grant_v2_vectors.py"
    world = make_world()
    g3 = Ed25519PrivateKey.from_private_bytes(bytes(range(99, 131)))
    recovery = kl.make_recovery(
        g3, dna_hash=DNA, agent=ALICE, purpose=kl.OWNER_PURPOSE,
        predecessor_action="alice-g2",
        predecessor_key_hex=public_key_bytes(world["g2"]).hex(),
        predecessor_generation="2",
    )
    rows = world["lifecycle_rows"] + [record(ALICE, "alice-g3", 9, recovery)]
    recovered = kl.resolve_key_lifecycle(rows, ALICE, kl.OWNER_PURPOSE, DNA)
    grant, _ = signed_grant(
        {**world, "lifecycle": recovered}, issuer=g3,
        recovered_policy=kl.RECOVERED_ISSUER_ACCEPT,
    )
    body = grant["body"]
    assert body["issuer_key_action"] == "alice-g3"
    assert body["issuer_key_generation"] == "3"
    assert body["issuer_key_hex"] == public_key_bytes(g3).hex()
    message = grant_message(body)
    anchor_body = kl.make_grant_anchor(
        dna_hash=DNA, grant_id=body["grant_id"],
        grant_message=message, issuer_key_action="alice-g3",
    )
    anchor = record(ALICE, "alice-anchor-g3", 10, anchor_body)
    denied = case("recovered-issuer-default-rejected", world, grant, anchor, rows=rows)
    assert denied["expected"] == {
        "category": "unauthenticated", "reason": "RecoveredIssuerRefused",
    }, denied["expected"]

    verified = checked(
        world, grant, anchor, lifecycle=recovered,
        recovered_policy=kl.RECOVERED_ISSUER_ACCEPT,
    )
    verified.authorize("stream")
    assert verified.owner_assurance == "KeyLifecycleV21"
    assert verified.issuer_continuity == kl.CONTINUITY_RECOVERED
    accepted = case(
        "recovered-issuer-accepted", world, grant, anchor, rows=rows,
        expected={"category": "ok", "reason": "ok"},
    )
    accepted["recovered_policy"] = "accept"
    accepted["signed_message_hex"] = message.hex()
    accepted["wrap_context_hex"] = grant_wrap_context(body).hex()
    accepted["anchor_commitment_hex"] = hashlib.sha256(
        b"holochain-storage/grant-anchor-commitment/v2\0" + message
    ).hexdigest()
    assert anchor_body["grant_commitment"] == accepted["anchor_commitment_hex"]
    vectors["cases"].extend([denied, accepted])

    extra_field = copy.deepcopy(grant)
    extra_field["body"]["unexpected_signed_field"] = "no"
    vectors["cases"].append(
        case("malformed-extra-body-field", world, extra_field, anchor, rows=rows)
    )
    wrong_schema = copy.deepcopy(grant)
    wrong_schema["body"]["schema"] = "holochain-music/access-grant/v3"
    vectors["cases"].append(
        case("unsupported-schema-version", world, wrong_schema, anchor, rows=rows)
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(vectors, ensure_ascii=False, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
