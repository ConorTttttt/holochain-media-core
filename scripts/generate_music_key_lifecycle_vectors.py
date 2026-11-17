#!/usr/bin/env python3
"""S2 key lifecycle v2.1 and replica-receipt/v2 vectors from Holochain Music's
own Python code (``holochain_storage.key_lifecycle``) at a pinned commit.

Every transition, revocation and receipt is made by Music's functions; every
forged/malformed record is derived from those; Music's verdict for each query
comes from its own ``evaluate_key`` / ``resolve_key_lifecycle`` /
``verify_replica_receipt_v2``. The S1 packages, streaming grant and personal
licence come from Music's ``create_package`` / ``content_grants``. Nothing
here re-implements Music's signing. Media Core asserts the same verdicts.

Disposable synthetic identities only. Action hashes and chain positions are
synthetic (they model what a validating conductor returns).
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest import mock

PINNED_MUSIC_COMMIT = "64f57d4"
VECTOR_SCHEMA = "holochain-media-core/music-key-lifecycle-v21-vectors/v1"
T0 = 1_760_000_000
DNA = "uhC0kStorageV21DnaForS2LifecycleTestsOnly000000000"
OTHER_DNA = "uhC0kADifferentStorageDnaForS2V21TestsOnly00000000"
ALICE = "uhCAkAliceOwnerAgentForS2TestsOnly000000000000000000"
BOB = "uhCAkBobListenerAgentForS2TestsOnly00000000000000000"
CAROL = "uhCAkCarolHostAgentForS2TestsOnly0000000000000000000"
MALLORY = "uhCAkMalloryAgentForS2TestsOnly000000000000000000000"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--music-repo", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    music_root = args.music_repo.resolve()
    commit = subprocess.check_output(["git", "-C", str(music_root), "rev-parse", "HEAD"], text=True).strip()
    if not commit.startswith(PINNED_MUSIC_COMMIT):
        raise SystemExit(f"Wrong Music source version: {commit}; expected {PINNED_MUSIC_COMMIT}")
    sys.path.insert(0, str(music_root))

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    from holochain_storage import key_lifecycle as kl
    from holochain_storage import package as music
    from music_catalogue import content_grants as cg

    def key(byte: int) -> Ed25519PrivateKey:
        return Ed25519PrivateKey.from_private_bytes(bytes([byte]) * 32)

    pub = music.public_key_bytes
    a1, a2, a3, a4 = key(0x61), key(0x62), key(0x63), key(0x64)
    c1, c2 = key(0x71), key(0x72)
    m1 = key(0x7a)
    bob_x = X25519PrivateKey.from_private_bytes(bytes([0x7b]) * 32)
    O, H = "owner-manifest", "host-receipt"

    def rec(author, body, action, seq):
        return {"author": author, "action_hash": action, "action_seq": seq, "body": body}

    def srec(r):
        return kl.SequencedRecord(r["author"], r["action_hash"], r["action_seq"], r["body"])

    def incept(k, agent=ALICE, purpose=O, dna=DNA):
        return kl.make_inception(k, dna_hash=dna, agent=agent, purpose=purpose)

    def rotate(new, old, pred, agent=ALICE, purpose=O, dna=DNA):
        return kl.make_rotation(new, old, dna_hash=dna, agent=agent, purpose=purpose,
                                predecessor_action=pred["action_hash"],
                                predecessor_generation=pred["body"]["generation"])

    def recover(new, pred, agent=ALICE, purpose=O):
        return kl.make_recovery(new, dna_hash=DNA, agent=agent, purpose=purpose,
                                predecessor_action=pred["action_hash"],
                                predecessor_key_hex=pred["body"]["signing_key_hex"],
                                predecessor_generation=pred["body"]["generation"])

    def revoke(target, scope, agent=ALICE, purpose=O):
        return kl.make_revocation(dna_hash=DNA, agent=agent, purpose=purpose,
                                  generation=target["body"]["generation"],
                                  signing_key_hex=target["body"]["signing_key_hex"],
                                  target_action=target["action_hash"], scope=scope)

    # Alice's owner lifecycle and Carol's host lifecycle (chain positions model
    # each agent's source chain: genesis actions first, then app actions).
    g1 = rec(ALICE, incept(a1), "uhCkkAliceOwnerG1", 5)
    g2 = rec(ALICE, rotate(a2, a1, g1), "uhCkkAliceOwnerG2", 20)
    rv1 = rec(ALICE, revoke(g1, kl.SCOPE_NEW_OPERATIONS), "uhCkkAliceRevokeG1", 30)
    rc1 = rec(ALICE, revoke(g1, kl.SCOPE_COMPROMISED), "uhCkkAliceCompromiseG1", 31)
    h1 = rec(CAROL, incept(c1, CAROL, H), "uhCkkCarolHostG1", 5)
    h2 = rec(CAROL, rotate(c2, c1, h1, CAROL, H), "uhCkkCarolHostG2", 40)

    scenarios = []

    def scenario(name, agent, purpose, records, queries, note=""):
        srecs = [srec(r) for r in records]
        try:
            lc = kl.resolve_key_lifecycle(srecs, agent, purpose, DNA)
            try:
                active = lc.active().key.hex()
            except kl.LifecycleError:
                active = None
            resolved = {"result": "resolved", "active_key_hex": active,
                        "generations": [{"generation": g.generation, "key_hex": g.key.hex(),
                                         "action_hash": g.action_hash, "continuity": g.continuity,
                                         "revocations": list(g.revoked_scopes)} for g in lc.generations]}
        except kl.LifecycleError as exc:
            resolved = {"result": "error", "verdict": exc.verdict, "error": str(exc)}
        out = []
        for k_hex, use, anchor in queries:
            anchor_obj = kl.ChainAnchor(*anchor) if anchor else None
            verdict = kl.evaluate_key(srecs, agent, purpose, DNA, k_hex, use, anchor_obj)
            out.append({"key_hex": k_hex, "use": use,
                        "anchor": {"author": anchor[0], "action_seq": anchor[1]} if anchor else None,
                        "python": verdict})
        scenarios.append({"name": name, "note": note, "agent": agent, "purpose": purpose,
                          "records": records, "python": resolved, "queries": out})

    A1, A2, A3, A4 = (pub(k).hex() for k in (a1, a2, a3, a4))
    NEW, HIST = kl.NEW_OPERATION, kl.HISTORICAL

    def all_uses(*keys, anchors=()):
        q = []
        for k in keys:
            q += [(k, NEW, None), (k, HIST, None)]
            q += [(k, HIST, a) for a in anchors]
        return q

    # 1, 2: legitimate rotations (Alice owner, Carol host).
    scenario("alice_inception", ALICE, O, [g1], all_uses(A1, A2, anchors=[(ALICE, 3), (ALICE, 50)]))
    scenario("alice_rotation", ALICE, O, [g1, g2],
             all_uses(A1, A2, anchors=[(ALICE, 10), (ALICE, 25), (MALLORY, 10)]))
    scenario("carol_host_rotation", CAROL, H, [h1, h2],
             all_uses(pub(c1).hex(), pub(c2).hex(), anchors=[(CAROL, 30), (CAROL, 41)]))
    # 3, 4: Mallory cannot rotate Alice's key; a stolen media key alone cannot.
    forged = rotate(m1, a1, g1)
    scenario("mallory_authored_rotation_of_alice", ALICE, O,
             [g1, rec(MALLORY, forged, "uhCkkMalloryForged", 9)], all_uses(A1, pub(m1).hex()))
    stolen = rotate(m1, a1, g1, agent=MALLORY)
    scenario("stolen_media_key_rotation_relabelled", ALICE, O,
             [g1, rec(ALICE, dict(stolen, agent=ALICE), "uhCkkStolen", 9)], all_uses(A1, pub(m1).hex()))
    scenario("stolen_media_key_on_mallory_chain", MALLORY, O,
             [g1, rec(MALLORY, stolen, "uhCkkStolenM", 9)], all_uses(A1, pub(m1).hex()),
             "a rotation naming Alice's predecessor on Mallory's chain has no inception there")
    # 5, 6: no cross-purpose or cross-DNA reuse.
    scenario("rotation_relabelled_other_purpose", ALICE, H,
             [rec(ALICE, dict(incept(a1), purpose=H), "uhCkkPurpose1", 5),
              rec(ALICE, dict(g2["body"], purpose=H), "uhCkkPurpose2", 20)], all_uses(A1, A2))
    scenario("lifecycle_made_for_other_dna", ALICE, O,
             [rec(ALICE, incept(a1, dna=OTHER_DNA), "uhCkkOtherDna1", 5)], all_uses(A1))
    scenario("rotation_moved_to_this_dna", ALICE, O,
             [g1, rec(ALICE, dict(rotate(a2, a1, g1, dna=OTHER_DNA), dna_hash=DNA), "uhCkkMoved", 20)],
             all_uses(A1, A2))
    # 7: replay.
    scenario("same_action_delivered_twice", ALICE, O, [g1, g2, g2], all_uses(A1, A2))
    scenario("rotation_reauthored_as_new_action", ALICE, O,
             [g1, g2, rec(ALICE, g2["body"], "uhCkkReplay", 21)], all_uses(A1, A2))
    scenario("one_action_two_bodies", ALICE, O,
             [g1, g2, rec(ALICE, dict(g2["body"], kind="recovery", continuity_signature_hex=""),
                          g2["action_hash"], 20)], all_uses(A2))
    # 8: invalid predecessor references.
    scenario("unknown_predecessor", ALICE, O,
             [g1, rec(ALICE, rotate(a2, a1, {"action_hash": "uhCkkNowhere", "body": g1["body"]}),
                      "uhCkkOrphan", 20)], all_uses(A1, A2))
    scenario("skipped_generation", ALICE, O,
             [g1, rec(ALICE, kl.make_rotation(a2, a1, dna_hash=DNA, agent=ALICE, purpose=O,
                                               predecessor_action=g1["action_hash"],
                                               predecessor_generation="2"), "uhCkkSkip", 20)],
             all_uses(A1, A2))
    scenario("predecessor_key_mismatch", ALICE, O,
             [g1, rec(ALICE, rotate(a2, a3, g1), "uhCkkWrongPred", 20)], all_uses(A1, A2))
    scenario("successor_before_predecessor_on_chain", ALICE, O,
             [g1, rec(ALICE, g2["body"], "uhCkkEarly", 4)], all_uses(A1, A2))
    # 9: competing successors / second inception.
    scenario("competing_successors", ALICE, O,
             [g1, g2, rec(ALICE, rotate(a3, a1, g1), "uhCkkFork", 21)], all_uses(A1, A2, A3))
    scenario("second_inception", ALICE, O,
             [g1, rec(ALICE, incept(a3), "uhCkkSecondInception", 21)], all_uses(A1, A3))
    # Continuity and reactivation.
    g2_no_cont = rec(ALICE, dict(g2["body"], continuity_signature_hex=""), "uhCkkNoCont", 20)
    scenario("rotation_without_continuity", ALICE, O, [g1, g2_no_cont], all_uses(A2))
    scenario("rotation_with_foreign_continuity", ALICE, O,
             [g1, rec(ALICE, dict(rotate(a2, m1, g1), predecessor_key_hex=A1), "uhCkkForeign", 20)],
             all_uses(A2))
    scenario("old_key_reactivated", ALICE, O,
             [g1, g2, rec(ALICE, rotate(a1, a2, g2), "uhCkkReactivate", 25)], all_uses(A1, A2))
    rec_g2 = rec(ALICE, recover(a2, g1), "uhCkkRecover", 20)
    scenario("lost_key_recovery", ALICE, O, [g1, rec_g2], all_uses(A1, A2, anchors=[(ALICE, 10), (ALICE, 25)]))
    # 10, 11: revocation; historical verification policy.
    scenario("retired_key_revoked_for_new_operations", ALICE, O, [g1, g2, rv1],
             all_uses(A1, A2, anchors=[(ALICE, 10), (ALICE, 25), (ALICE, 35)]))
    scenario("compromised_key", ALICE, O, [g1, g2, rv1, rc1],
             all_uses(A1, A2, anchors=[(ALICE, 10), (ALICE, 25)]))
    tip_revoked = rec(ALICE, revoke(g2, kl.SCOPE_NEW_OPERATIONS), "uhCkkRevokeTip", 40)
    scenario("active_key_revoked", ALICE, O, [g1, g2, tip_revoked], all_uses(A1, A2, anchors=[(ALICE, 30)]))
    g3 = rec(ALICE, recover(a3, g2), "uhCkkRecoverAfterRevoke", 45)
    scenario("recovery_after_revoked_tip", ALICE, O, [g1, g2, tip_revoked, g3], all_uses(A2, A3))
    scenario("rotation_after_revoked_tip", ALICE, O,
             [g1, g2, tip_revoked, rec(ALICE, rotate(a4, a2, g2), "uhCkkRotateRevoked", 45)], all_uses(A2, A4))
    scenario("duplicate_revocation_scope", ALICE, O,
             [g1, g2, rv1, rec(ALICE, rv1["body"], "uhCkkRevokeAgain", 33)], all_uses(A1))
    scenario("revocation_of_unknown_transition", ALICE, O,
             [g1, rec(ALICE, dict(rv1["body"], target_action="uhCkkNowhere"), "uhCkkRevokeNowhere", 30)],
             all_uses(A1))
    scenario("revocation_wrong_key", ALICE, O,
             [g1, g2, rec(ALICE, dict(rv1["body"], signing_key_hex=A2), "uhCkkRevokeWrong", 30)], all_uses(A1))
    # 12: Mallory cannot revoke Alice's key.
    scenario("mallory_revokes_alice", ALICE, O,
             [g1, rec(MALLORY, revoke(g1, kl.SCOPE_COMPROMISED), "uhCkkMalloryRevoke", 9)], all_uses(A1))
    # Malformed.
    for name, change in [("bad_proof", {"proof_signature_hex": "00" * 64}),
                         ("uppercase_key", {"signing_key_hex": A1.upper()}),
                         ("generation_zero_padded", {"generation": "01"}),
                         ("extra_field", {"note": "x"}),
                         ("unknown_kind", {"kind": "reset"}),
                         ("numeric_generation", {"generation": 1})]:
        scenario(f"malformed_{name}", ALICE, O, [rec(ALICE, dict(g1["body"], **change), "uhCkkBad", 5)],
                 all_uses(A1))
    scenario("no_records", ALICE, O, [], all_uses(A1))
    scenario("missing_chain_position", ALICE, O,
             [{"author": ALICE, "action_hash": "uhCkkNoSeq", "action_seq": None, "body": g1["body"]}], [])

    # ---- Content, licences and host-attributed receipts --------------------
    with tempfile.TemporaryDirectory(prefix="music-s2v21-vectors-") as td:
        root = Path(td)
        (root / "old.bin").write_bytes(b"S2 v2.1 historical content signed by generation 1" * 3)
        (root / "new.bin").write_bytes(b"S2 v2.1 new content signed by generation 2!" * 3)
        old_manifest, old_ck = music.create_package(root / "old.bin", root / "store", a1, chunk_size=48)
        new_manifest, new_ck = music.create_package(root / "new.bin", root / "store", a2, chunk_size=48)
        x_pub = bob_x.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        with mock.patch("time.time", return_value=float(T0)):
            old_licence = cg.issue_personal_licence(owner_signer=a1, owner_agent=ALICE, listener_agent=BOB,
                                                    recipient_public=x_pub, signed_manifest=old_manifest,
                                                    content_key=old_ck)
            new_grant = cg.issue_content_grant(owner_signer=a2, owner_agent=ALICE, listener_agent=BOB,
                                               recipient_public=x_pub, signed_manifest=new_manifest,
                                               content_key=new_ck, lifetime_seconds=1800)
        carol_receipt = kl.replicate_package_v2(
            old_manifest, root / "store", root / "carol", pub(a1), c1, dna_hash=DNA, host_agent=CAROL,
            host_key_generation="1", host_key_action=h1["action_hash"], owner_agent=ALICE,
            received_at="2026-11-13T12:00:00Z")
        legacy_receipt = music.replicate_package(old_manifest, root / "store", root / "carol2", pub(a1), c1)
        m_lc = rec(MALLORY, incept(m1, MALLORY, H), "uhCkkMalloryHostG1", 5)
        mallory_claims_carol = kl.sign_replica_receipt_v2(
            old_manifest, node_key=m1, dna_hash=DNA, host_agent=CAROL, host_key_generation="1",
            host_key_action=h1["action_hash"], owner_agent=ALICE, trusted_artist=pub(a1),
            received_at="2026-11-13T12:00:00Z")

    receipt_cases = []
    carol_lc = [srec(h1)]

    def receipt_case(name, receipt, host_agent, host_records, use=HIST, anchor=None, note=""):
        lc = kl.resolve_key_lifecycle([srec(r) for r in host_records], host_agent, H, DNA)
        try:
            kl.verify_replica_receipt_v2(json.dumps(receipt).encode(), old_manifest, trusted_artist=pub(a1),
                                         dna_hash=DNA, host_agent=host_agent, owner_agent=ALICE,
                                         host_lifecycle=lc, use=use,
                                         anchor=kl.ChainAnchor(*anchor) if anchor else None)
            python = {"verdict": "accepted", "digest": kl.receipt_v2_digest(receipt)}
        except music.StorageError as exc:
            python = {"verdict": "rejected", "error": str(exc)}
        receipt_cases.append({"name": name, "note": note, "receipt": receipt, "host_agent": host_agent,
                              "host_records": host_records, "use": use,
                              "anchor": {"author": anchor[0], "action_seq": anchor[1]} if anchor else None,
                              "python": python})

    receipt_case("valid_host_attributed", carol_receipt, CAROL, [h1])
    receipt_case("valid_after_host_rotation_historical", carol_receipt, CAROL, [h1, h2])
    receipt_case("rotated_host_key_new_operation", carol_receipt, CAROL, [h1, h2], use=NEW)
    receipt_case("claim_anchored_after_rotation", carol_receipt, CAROL, [h1, h2], anchor=(CAROL, 41))
    receipt_case("claim_anchored_before_rotation", carol_receipt, CAROL, [h1, h2], anchor=(CAROL, 39))
    receipt_case("forged_signature",
                 dict(carol_receipt, signature_hex=m1.sign(kl.receipt_v2_message(carol_receipt)).hex()),
                 CAROL, [h1])
    receipt_case("mallory_receipt_claims_carol", mallory_claims_carol, CAROL, [h1])
    receipt_case("carol_receipt_presented_as_mallory", carol_receipt, MALLORY, [m_lc])
    for field, value in [("host_agent", MALLORY), ("owner_agent", BOB), ("dna_hash", OTHER_DNA),
                         ("chunk_count", "1"), ("host_key_generation", "2"), ("host_key_action", "uhCkkOther"),
                         ("context", "other"), ("received_at", "2026-11-13T12:00:00+00:00"),
                         ("received_at", "2026-13-40T12:00:00Z"), ("file_id", "00" * 32),
                         ("schema", "holochain-storage/replica-receipt/v1")]:
        receipt_case(f"tampered_{field}_{value[:8]}", dict(carol_receipt, **{field: value}), CAROL, [h1])
    receipt_case("extra_field", dict(carol_receipt, note="x"), CAROL, [h1])
    receipt_case("legacy_s1_receipt", legacy_receipt, CAROL, [h1],
                 note="S1 receipts are not v2 receipts; they stay readable only through the legacy path")
    receipt_case("compromised_host_key_unanchored", carol_receipt, CAROL,
                 [h1, h2, rec(CAROL, revoke(h1, kl.SCOPE_COMPROMISED, CAROL, H), "uhCkkCarolCompromise", 50)])
    receipt_case("compromised_host_key_anchored_before", carol_receipt, CAROL,
                 [h1, h2, rec(CAROL, revoke(h1, kl.SCOPE_COMPROMISED, CAROL, H), "uhCkkCarolCompromise", 50)],
                 anchor=(CAROL, 30))

    # ---- grant anchors (access-grant/v2 issuance authority) -----------------
    grant_message = b"holochain-music/access-grant/v2\x00{synthetic grant body for anchor vectors}"
    gid = "a5" * 16
    anchor_cases = []

    def anchor_case(name, lifecycle_records, record, *, grant_id=gid, message=grant_message,
                    action=None, policy="reject", note=""):
        action = action or record["body"].get("issuer_key_action", "")
        lc = kl.resolve_key_lifecycle([srec(r) for r in lifecycle_records], ALICE, O, DNA)
        try:
            g = kl.verify_grant_anchor(srec(record), lc, grant_id=grant_id, grant_message=message,
                                       issuer_key_action=action, recovered_policy=policy)
            python = {"verdict": "accepted", "generation": g.generation}
        except music.StorageError as exc:
            python = {"verdict": "rejected", "error": str(exc)}
        anchor_cases.append({"name": name, "note": note, "lifecycle": lifecycle_records, "record": record,
                             "claim": {"grant_id": grant_id, "grant_message_hex": message.hex(),
                                       "issuer_key_action": action},
                             "policy": policy, "python": python})

    def anchor(action, seq, author=ALICE, **changes):
        body = kl.make_grant_anchor(dna_hash=DNA, grant_id=gid, grant_message=grant_message,
                                    issuer_key_action=action)
        body.update(changes)
        return rec(author, body, f"uhCkkAnchor{seq}", seq)

    anchor_case("current_key", [g1, g2], anchor(g2["action_hash"], 25))
    anchor_case("g1_before_rotation", [g1, g2], anchor(g1["action_hash"], 10))
    anchor_case("g1_after_rotation", [g1, g2], anchor(g1["action_hash"], 25),
                note="obsolete key cannot authorise a new grant after its authority ended")
    anchor_case("g1_after_revocation", [g1, g2, rv1], anchor(g1["action_hash"], 35))
    tip_rev = rec(ALICE, revoke(g2, kl.SCOPE_COMPROMISED), "uhCkkRevokeG2Anchor", 40)
    anchor_case("g2_after_compromise", [g1, g2, tip_rev], anchor(g2["action_hash"], 45))
    anchor_case("g2_before_compromise", [g1, g2, tip_rev], anchor(g2["action_hash"], 30))
    anchor_case("mallory_authored", [g1, g2], anchor(g2["action_hash"], 25, author=MALLORY))
    anchor_case("other_dna", [g1, g2], anchor(g2["action_hash"], 25, dna_hash=OTHER_DNA))
    anchor_case("extra_field", [g1, g2], anchor(g2["action_hash"], 25, note="x"))
    anchor_case("wrong_commitment", [g1, g2], anchor(g2["action_hash"], 25), message=grant_message + b"!")
    anchor_case("wrong_grant_id", [g1, g2], anchor(g2["action_hash"], 25), grant_id="b6" * 16)
    anchor_case("claim_names_other_generation", [g1, g2], anchor(g2["action_hash"], 25),
                action=g1["action_hash"])
    anchor_case("precedes_issuer_key", [g1, g2], anchor(g2["action_hash"], 15))
    anchor_case("action_not_in_lifecycle", [g1, g2], anchor("uhCkkNowhere", 25))
    anchor_case("recovered_issuer_default", [g1, rec_g2], anchor(rec_g2["action_hash"], 25))
    anchor_case("recovered_issuer_accept_policy", [g1, rec_g2], anchor(rec_g2["action_hash"], 25),
                policy="accept")
    expected_anchor_accept = {"current_key", "g1_before_rotation", "g2_before_compromise",
                              "recovered_issuer_accept_policy"}
    for c in anchor_cases:
        assert (c["python"]["verdict"] == "accepted") == (c["name"] in expected_anchor_accept), (c["name"], c["python"])

    for s in scenarios:
        for q in s["queries"]:
            assert q["python"] in (kl.ACTIVE, kl.ROTATED, kl.REVOKED, kl.HISTORICAL_ONLY, kl.AMBIGUOUS,
                                   kl.INVALID), q
    expected_accept = {"valid_host_attributed", "valid_after_host_rotation_historical",
                       "claim_anchored_before_rotation", "compromised_host_key_anchored_before"}
    for c in receipt_cases:
        assert (c["python"]["verdict"] == "accepted") == (c["name"] in expected_accept), (c["name"], c["python"])

    vectors = {
        "schema": VECTOR_SCHEMA,
        "music_commit": commit,
        "dna_hash": DNA,
        "other_dna_hash": OTHER_DNA,
        "agents": {"alice": ALICE, "bob": BOB, "carol": CAROL, "mallory": MALLORY},
        "keys": {"alice_g1": A1, "alice_g2": A2, "alice_g3": A3, "carol_g1": pub(c1).hex(),
                 "carol_g2": pub(c2).hex(), "mallory": pub(m1).hex(), "bob_x25519": x_pub.hex()},
        "messages": {
            "rotation_successor_hex": kl._message_for(g2["body"], kl.ROLE_SUCCESSOR).hex(),
            "rotation_predecessor_hex": kl._message_for(g2["body"], kl.ROLE_PREDECESSOR).hex(),
            "receipt_v2_hex": kl.receipt_v2_message(carol_receipt).hex(),
            "receipt_v2_digest": kl.receipt_v2_digest(carol_receipt),
        },
        "lifecycle": {"alice_g1": g1, "alice_g2": g2, "alice_revoke_g1_new_operations": rv1,
                      "alice_revoke_g1_compromised": rc1, "carol_g1": h1, "carol_g2": h2},
        "scenarios": scenarios,
        "receipts": receipt_cases,
        "grant_anchors": anchor_cases,
        "content": {
            "old_manifest_text": music.canonical(old_manifest).decode(),
            "old_manifest_sha256": music.manifest_digest(old_manifest),
            "old_file_id": old_manifest["body"]["file_id"],
            "new_manifest_text": music.canonical(new_manifest).decode(),
            "new_manifest_sha256": music.manifest_digest(new_manifest),
            "new_file_id": new_manifest["body"]["file_id"],
            "old_licence_text": music.canonical(old_licence).decode(),
            "new_grant_text": music.canonical(new_grant).decode(),
            "carol_receipt_text": json.dumps(carol_receipt, sort_keys=True, separators=(",", ":")),
            "legacy_receipt_text": music.canonical(legacy_receipt).decode(),
            "now": T0 + 10,
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(vectors, sort_keys=True, indent=1) + "\n", encoding="utf-8")
    queries = sum(len(s["queries"]) for s in scenarios)
    print(f"Created {len(scenarios)} lifecycle scenarios ({queries} queries) and "
          f"{len(receipt_cases)} receipt cases and {len(anchor_cases)} grant-anchor cases from {commit}")


if __name__ == "__main__":
    main()
