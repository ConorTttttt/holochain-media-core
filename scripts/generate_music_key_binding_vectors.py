#!/usr/bin/env python3
"""S2 key-binding v2 vectors produced by Holochain Music's own Python code.

Every binding is made by Music's ``make_key_binding_v2`` (proofs signed with
Music's key handling), every malformed/forged binding is derived from those
with Music's own ``key_binding_v2_message``, and Music's verdict for each case
comes from its own ``key_for_agent_v2``. The S1 package, streaming grant and
licence are issued by Music's ``create_package`` / ``content_grants`` with the
same owner key, so Media Core can test the full v2 owner → manifest → CORE-005
chain. Nothing here re-implements Music's signing.

Disposable synthetic identities only.
"""
from __future__ import annotations

import argparse
import copy
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest import mock

PINNED_MUSIC_COMMIT = "f091d5a5da0c2cb46228ea619ab816338311ef9b"
VECTOR_SCHEMA = "holochain-media-core/music-key-binding-v2-vectors/v1"
T0 = 1_760_000_000
DNA = "uhC0kStorageV2DnaForCore005S2TestsOnly0000000000000"
OTHER_DNA = "uhC0kADifferentStorageDnaForS2TestsOnly00000000000"
ALICE = "uhCAkAliceOwnerAgentForS2TestsOnly000000000000000000"
CAROL = "uhCAkCarolHostAgentForS2TestsOnly0000000000000000000"
MALLORY = "uhCAkMalloryAgentForS2TestsOnly000000000000000000000"
BOB = "uhCAkBobListenerAgentForS2TestsOnly00000000000000000"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--music-repo", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    music_root = args.music_repo.resolve()
    commit = subprocess.check_output(["git", "-C", str(music_root), "rev-parse", "HEAD"], text=True).strip()
    if commit != PINNED_MUSIC_COMMIT:
        raise SystemExit(f"Wrong Music source version: {commit}; expected {PINNED_MUSIC_COMMIT}")
    sys.path.insert(0, str(music_root))

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    from holochain_storage import holochain_identity as hi
    from holochain_storage import package as music
    from music_catalogue import content_grants as cg

    alice = Ed25519PrivateKey.from_private_bytes(bytes([0x51]) * 32)
    carol = Ed25519PrivateKey.from_private_bytes(bytes([0x52]) * 32)
    mallory = Ed25519PrivateKey.from_private_bytes(bytes([0x53]) * 32)
    bob_x = X25519PrivateKey.from_private_bytes(bytes([0x54]) * 32)
    pub = music.public_key_bytes

    alice_owner = hi.make_key_binding_v2(alice, dna_hash=DNA, agent=ALICE, purpose=hi.OWNER_PURPOSE)
    carol_host = hi.make_key_binding_v2(carol, dna_hash=DNA, agent=CAROL, purpose=hi.HOST_PURPOSE)
    mallory_owner = hi.make_key_binding_v2(mallory, dna_hash=DNA, agent=MALLORY, purpose=hi.OWNER_PURPOSE)

    def resign(body: dict, signer, **changes) -> dict:
        b = dict(body, **changes)
        b["proof_signature_hex"] = signer.sign(hi.key_binding_v2_message(
            b["dna_hash"], b["agent"], b["purpose"], b["signing_key_hex"], b["generation"])).hex()
        return b

    cases = []

    def case(name, author, body, agent, purpose, dna, expect, note=""):
        try:
            key = hi.key_for_agent_v2(hi.AuthoredRecord(author, "uhCkkS2Action", body), agent, purpose, dna)
            python = {"verdict": "accepted", "key_hex": key.hex()}
        except music.StorageError as exc:
            python = {"verdict": "rejected", "error": str(exc)}
        cases.append({"name": name, "note": note, "author": author, "body": body, "agent": agent,
                      "purpose": purpose, "dna_hash": dna, "python": python, "expect": expect})

    ok = {"result": "accepted"}

    def rej(reason):
        return {"result": "rejected", "reason": reason}

    O, H = hi.OWNER_PURPOSE, hi.HOST_PURPOSE
    # A / J: legitimate bindings.
    case("a_alice_owner_v2", ALICE, alice_owner, ALICE, O, DNA, ok)
    case("j_carol_host_v2", CAROL, carol_host, CAROL, H, DNA, ok)
    case("mallory_own_key_v2", MALLORY, mallory_owner, MALLORY, O, DNA, ok,
         "Mallory may bind HER OWN key; that gives her nothing over Alice's content")
    # B: Mallory binds Alice's public key without Alice's private key.
    case("b_mallory_binds_alice_key_own_signature", MALLORY,
         resign(dict(alice_owner, agent=MALLORY), mallory), MALLORY, O, DNA, rej("InvalidProof"))
    # C: proof replay — Alice's genuine proof copied into Mallory's binding.
    case("c_alice_proof_replayed_for_mallory", MALLORY, dict(alice_owner, agent=MALLORY),
         MALLORY, O, DNA, rej("InvalidProof"))
    case("j_mallory_binds_carol_host_key", MALLORY, dict(carol_host, agent=MALLORY),
         MALLORY, H, DNA, rej("InvalidProof"))
    # D: owner-manifest proof relabelled as host-receipt.
    case("d_owner_proof_used_for_host_purpose", ALICE, dict(alice_owner, purpose=H), ALICE, H, DNA,
         rej("InvalidProof"))
    case("d_owner_binding_requested_as_host", ALICE, alice_owner, ALICE, H, DNA, rej("KeyNotBound"))
    # E: application/DNA context.
    case("e_proof_for_other_dna_moved_here", ALICE, dict(alice_owner, dna_hash=OTHER_DNA), ALICE, O,
         OTHER_DNA, rej("InvalidProof"))
    case("e_binding_read_on_other_dna", ALICE, alice_owner, ALICE, O, OTHER_DNA, rej("WrongDna"))
    # F: public key swapped without a new proof.
    case("f_modified_public_key", ALICE, dict(alice_owner, signing_key_hex=pub(mallory).hex()), ALICE, O,
         DNA, rej("InvalidProof"))
    # Author / agent mismatch (Holochain authorship rule).
    case("author_is_not_agent", MALLORY, alice_owner, ALICE, O, DNA, rej("AuthorMismatch"))
    # G: malformed.
    def mutate(name, reason, **changes):
        body = dict(alice_owner, **changes)
        case(name, ALICE, body, ALICE, O, DNA, rej(reason))
    no_sig = dict(alice_owner)
    del no_sig["proof_signature_hex"]
    case("g_missing_signature", ALICE, no_sig, ALICE, O, DNA, rej("InvalidRecord"))
    mutate("g_short_signature", "InvalidProof", proof_signature_hex="ab" * 63)
    mutate("g_uppercase_signature", "InvalidProof",
           proof_signature_hex=alice_owner["proof_signature_hex"].upper())
    mutate("g_non_hex_signature", "InvalidProof", proof_signature_hex="zz" * 64)
    mutate("g_zero_signature", "InvalidProof", proof_signature_hex="00" * 64)
    mutate("g_v1_schema", "InvalidRecord", schema=hi.KEY_SCHEMA)
    mutate("g_future_schema", "InvalidRecord", schema="holochain-storage/key-binding/v3")
    case("g_unsupported_purpose", ALICE, resign(alice_owner, alice, purpose="grant-issuer"), ALICE, O,
         DNA, rej("KeyNotBound"))
    mutate("g_extra_field", "InvalidRecord", note="x")
    mutate("g_generation_2", "InvalidRecord", generation="2")
    mutate("g_numeric_generation", "InvalidRecord", generation=1)
    mutate("g_short_key", "InvalidRecord", signing_key_hex="ab" * 31)
    mutate("g_uppercase_key", "InvalidRecord", signing_key_hex=alice_owner["signing_key_hex"].upper())
    case("g_oversized_agent", "A" * 161, dict(alice_owner, agent="A" * 161), "A" * 161, O, DNA,
         rej("MissingRecord"))

    # H: duplicate (same key) and conflicting (different key) bindings.
    alice_second = hi.make_key_binding_v2(Ed25519PrivateKey.from_private_bytes(bytes([0x55]) * 32),
                                          dna_hash=DNA, agent=ALICE, purpose=O)

    # Full chain material, all from Music: package, grant and licence by Alice.
    with tempfile.TemporaryDirectory(prefix="music-s2-vectors-") as td:
        root = Path(td)
        (root / "src.bin").write_bytes(b"S2 key-binding v2 synthetic content" * 3)
        manifest, content_key = music.create_package(root / "src.bin", root / "store", alice, chunk_size=32)
    x_pub = bob_x.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    with mock.patch("time.time", return_value=float(T0)):
        grant = cg.issue_content_grant(owner_signer=alice, owner_agent=ALICE, listener_agent=BOB,
                                       recipient_public=x_pub, signed_manifest=manifest,
                                       content_key=content_key, lifetime_seconds=1800)
        licence = cg.issue_personal_licence(owner_signer=alice, owner_agent=ALICE, listener_agent=BOB,
                                            recipient_public=x_pub, signed_manifest=manifest,
                                            content_key=content_key)

    for c in cases:
        accepted = c["python"]["verdict"] == "accepted"
        assert accepted == (c["expect"]["result"] == "accepted"), (c["name"], c["python"])
    vectors = {
        "schema": VECTOR_SCHEMA,
        "music_commit": PINNED_MUSIC_COMMIT,
        "dna_hash": DNA,
        "other_dna_hash": OTHER_DNA,
        "agents": {"alice": ALICE, "bob": BOB, "carol": CAROL, "mallory": MALLORY},
        "keys": {"alice_ed25519_public_hex": pub(alice).hex(), "carol_ed25519_public_hex": pub(carol).hex(),
                 "mallory_ed25519_public_hex": pub(mallory).hex(), "bob_x25519_public_hex": x_pub.hex()},
        "message_hex": hi.key_binding_v2_message(DNA, ALICE, O, pub(alice).hex()).hex(),
        "bindings": {"alice_owner": alice_owner, "alice_owner_second_key": alice_second,
                     "carol_host": carol_host, "mallory_owner": mallory_owner},
        "cases": cases,
        "chain": {"manifest_text": music.canonical(manifest).decode(),
                  "manifest_sha256": music.manifest_digest(manifest),
                  "file_id": manifest["body"]["file_id"],
                  "grant_text": music.canonical(grant).decode(),
                  "licence_text": music.canonical(licence).decode(),
                  "now": T0 + 10},
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(vectors, sort_keys=True, indent=1) + "\n", encoding="utf-8")
    print(f"Created {len(cases)} S2 key-binding v2 vectors from {commit}")


if __name__ == "__main__":
    main()
