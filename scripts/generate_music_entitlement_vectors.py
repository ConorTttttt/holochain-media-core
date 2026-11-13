#!/usr/bin/env python3
"""CORE-005: independent Music grant/licence vectors from the REAL pinned Music code.

Every signed grant and licence here is produced by Holochain Music's own
``music_catalogue.content_grants`` issuance functions (or, for deliberately
invalid-but-owner-signed bodies, Music's own ``holochain_storage.package._sign``
and ``canonical``). Every Python verdict is produced by Music's own
``unwrap_content_grant`` evaluated at the case's clock. Nothing here
re-implements Music's signing, canonical JSON, HKDF context or key wrapping.

Only ``time.time`` is patched, so that ``issued_at`` and each verdict use a
fixed, reproducible clock instead of the wall clock. Randomness (ephemeral
X25519 keys, salts, nonces, licence IDs, file IDs, content keys) comes from the
real OS RNG, so every run yields fresh bytes; the Rust tests are data-driven
and accept any run.

Identities and keys are disposable, synthetic, test-only material. Never put
user data, production keys or real media in these fixtures.

The Rust-side expectation for each case (``expect``) is written down here so
the vectors are self-describing. It is *our* classification of *why* the
evaluator must reject, checked against Python's independent verdict
(``python``); where the two deliberately differ, ``divergence`` names the
documented reason (see docs/CORE-005-entitlement-verification.md).
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

PINNED_MUSIC_COMMIT = "bd7aabc3e9ea1fef1e8e8f674301e1b5ffecb637"
VECTOR_SCHEMA = "holochain-media-core/music-entitlement-vectors/v1"

# Fixed synthetic clock (2025-10-09T08:53:20Z). All cases are relative to it.
T0 = 1_760_000_000
STREAM_LIFETIME = 1800

ALICE = "uhCAkAliceOwnerAgentForCore005TestsOnly0000000000000"
BOB = "uhCAkBobListenerAgentForCore005TestsOnly000000000000"
MALLORY = "uhCAkMalloryAgentForCore005TestsOnly00000000000000000"


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

    import cryptography
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    from holochain_storage import package as music
    from holochain_storage import grant as legacy
    from music_catalogue import content_grants as cg

    def x_public(private: X25519PrivateKey) -> bytes:
        return private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    # Disposable deterministic identities (test-only seeds).
    alice_ed = Ed25519PrivateKey.from_private_bytes(bytes([0x11]) * 32)
    mallory_ed = Ed25519PrivateKey.from_private_bytes(bytes([0x33]) * 32)
    bob_x = X25519PrivateKey.from_private_bytes(bytes([0x22]) * 32)
    mallory_x = X25519PrivateKey.from_private_bytes(bytes([0x44]) * 32)
    alice_pub = music.public_key_bytes(alice_ed)
    mallory_pub = music.public_key_bytes(mallory_ed)
    x_keys = {"bob": bob_x, "mallory": mallory_x}
    agents = {"alice": ALICE, "bob": BOB, "mallory": MALLORY}

    def at(now: int):
        return mock.patch("time.time", return_value=float(now))

    with tempfile.TemporaryDirectory(prefix="music-core005-vectors-") as td:
        root = Path(td)
        source = root / "source.bin"
        packages: dict[str, tuple[dict, bytes]] = {}
        for name, data, signer in (
            ("p", bytes(range(48)) + b"CORE-005 synthetic P", alice_ed),
            ("q", b"CORE-005 synthetic Q" * 3, alice_ed),
            ("m", b"CORE-005 synthetic Mallory package", mallory_ed),
        ):
            source.write_bytes(data)
            manifest, key = music.create_package(source, root / name, signer, chunk_size=16)
            music.verify_package(manifest, root / name, music.public_key_bytes(signer))
            packages[name] = (manifest, key)

    p_manifest, p_key = packages["p"]
    q_manifest, q_key = packages["q"]
    m_manifest, m_key = packages["m"]

    def stream(manifest=p_manifest, key=p_key, *, signer=alice_ed, owner=ALICE,
               listener=BOB, recipient=bob_x, issued=T0, lifetime=STREAM_LIFETIME):
        with at(issued):
            return cg.issue_content_grant(
                owner_signer=signer, owner_agent=owner, listener_agent=listener,
                recipient_public=x_public(recipient), signed_manifest=manifest,
                content_key=key, lifetime_seconds=lifetime)

    def licence(manifest=p_manifest, key=p_key, *, signer=alice_ed, owner=ALICE,
                listener=BOB, recipient=bob_x, issued=T0):
        with at(issued):
            return cg.issue_personal_licence(
                owner_signer=signer, owner_agent=owner, listener_agent=listener,
                recipient_public=x_public(recipient), signed_manifest=manifest,
                content_key=key)

    def resign(grant: dict, transform, signer=alice_ed) -> dict:
        """Owner-signed body that Music's issuer itself would never emit."""
        body = copy.deepcopy(grant["body"])
        transform(body)
        return music._sign(body, signer)

    def text(value) -> str:
        """Exact bytes handed to both implementations (Music's canonical form)."""
        return music.canonical(value).decode("utf-8")

    s_valid = stream()
    l_valid = licence()
    manifests = {"p": p_manifest, "q": q_manifest, "m": m_manifest}

    def python_verdict(grant_text: str, content: str, subject: dict, now: int, right: str) -> dict:
        """Music's own verdict: real json.loads + unwrap_content_grant at `now`.

        The right gate mirrors holochain_music/app.py at the pinned commit:
        `_session_for` (playback) accepts any grant that unwraps; `download`,
        `_offline_readiness_impl` and `_export_wav_impl` additionally require
        `grant_kind(grant) == "perpetual-personal"`.
        """
        try:
            grant = json.loads(grant_text)
        except ValueError as exc:
            return {"unwrap": "rejected", "error": f"json: {exc.__class__.__name__}",
                    "right_allowed": False}
        try:
            with at(now):
                key = cg.unwrap_content_grant(
                    grant, trusted_artist=alice_pub, owner_agent=ALICE,
                    listener_agent=subject["listener_agent"],
                    recipient_private=x_keys[subject["x25519"]],
                    signed_manifest=manifests[content])
        except (music.StorageError, ValueError, TypeError, KeyError, AttributeError) as exc:
            return {"unwrap": "rejected", "error": str(exc) or exc.__class__.__name__,
                    "right_allowed": False}
        assert len(key) == 32
        kind = cg.grant_kind(grant)
        allowed = right == "stream" or kind == "perpetual-personal"
        return {"unwrap": "ok", "kind": kind, "right_allowed": allowed,
                "unwrapped_key_matches_content_key": key == {"p": p_key, "q": q_key, "m": m_key}[content]}

    cases: list[dict] = []
    bob = {"listener_agent": BOB, "x25519": "bob"}

    def case(name: str, grant_or_text, expect: dict, *, now: int = T0 + 10, right: str = "stream",
             content: str = "p", subject: dict | None = None, divergence: str | None = None,
             note: str = "") -> None:
        subject = subject or bob
        grant_text = grant_or_text if isinstance(grant_or_text, str) else text(grant_or_text)
        entry = {
            "name": name, "note": note, "grant_text": grant_text, "content": content,
            "subject": {"listener_agent": subject["listener_agent"],
                        "recipient_key_hex": x_public(x_keys[subject["x25519"]]).hex()},
            "now": now, "right": right,
            "python": python_verdict(grant_text, content, subject, now, right),
            "expect": expect,
        }
        if divergence:
            entry["divergence"] = divergence
        # Music's HKDF/AES-GCM additional data for authorised grants, so Rust's
        # key-unwrap context can be compared byte-for-byte.
        if expect.get("decision") == "authorized":
            body = json.loads(grant_text)["body"]
            ctx = cg._licence_context(body) if body["schema"] == cg.LICENCE_SCHEMA else cg._context(body)
            entry["python_hkdf_context_hex"] = ctx.hex()
        cases.append(entry)

    ok = {"decision": "authorized"}

    def rej(category: str, reason: str) -> dict:
        return {"decision": "rejected", "category": category, "reason": reason}

    # ---- positive: temporary streaming grant ------------------------------
    case("stream_grant_valid_for_stream", s_valid, ok)
    case("stream_grant_valid_at_lower_skew_edge", s_valid, ok, now=T0 - cg.CLOCK_SKEW_SECONDS,
         note="issued_at == now + CLOCK_SKEW_SECONDS is accepted")
    case("stream_grant_valid_last_second", s_valid, ok, now=T0 + STREAM_LIFETIME - 1)
    case("stream_grant_maximum_lifetime", stream(lifetime=cg.MAX_LIFETIME_SECONDS), ok,
         now=T0 + cg.MAX_LIFETIME_SECONDS - 1)
    case("stream_grant_for_package_q", stream(q_manifest, q_key), ok, content="q")
    case("stream_grant_owner_is_listener", stream(listener=ALICE), ok,
         subject={"listener_agent": ALICE, "x25519": "bob"},
         note="owner and listener may be the same agent (Music self-licence pattern)")

    # ---- positive: permanent personal-use licence -------------------------
    for right in ("stream", "managed-offline", "export"):
        case(f"licence_valid_for_{right.replace('-', '_')}", l_valid, ok, right=right)
    case("licence_does_not_expire_a_century_later", l_valid, ok, now=T0 + 100 * 365 * 86400,
         right="export")
    case("licence_valid_at_lower_skew_edge", l_valid, ok, now=T0 - cg.CLOCK_SKEW_SECONDS)
    case("licence_epoch_issued_at_parity", licence(issued=0), ok,
         note="Music accepts any integer issued_at not in the future for licences; Rust matches")

    # ---- time policy -------------------------------------------------------
    case("stream_grant_expired_at_expires_at", s_valid, rej("validity", "Expired"),
         now=T0 + STREAM_LIFETIME)
    case("stream_grant_expired_long_ago", s_valid, rej("validity", "Expired"), now=T0 + 10 * 86400)
    case("stream_grant_issued_in_future_beyond_skew", s_valid, rej("validity", "NotYetValid"),
         now=T0 - cg.CLOCK_SKEW_SECONDS - 1)
    case("licence_issued_in_future_beyond_skew", l_valid, rej("validity", "NotYetValid"),
         now=T0 - cg.CLOCK_SKEW_SECONDS - 1, right="export")
    case("stream_grant_zero_lifetime", resign(s_valid, lambda b: b.update(expires_at=b["issued_at"])),
         rej("validity", "InvalidPeriod"), now=T0 - 60)
    case("stream_grant_negative_lifetime", resign(s_valid, lambda b: b.update(expires_at=b["issued_at"] - 5)),
         rej("validity", "InvalidPeriod"), now=T0 - 60)
    case("stream_grant_lifetime_exceeds_maximum",
         resign(s_valid, lambda b: b.update(expires_at=b["issued_at"] + cg.MAX_LIFETIME_SECONDS + 1)),
         rej("validity", "InvalidPeriod"))
    case("stream_grant_string_timestamp", resign(s_valid, lambda b: b.update(issued_at=str(T0))),
         rej("validity", "InvalidTimestamp"))
    case("stream_grant_boolean_timestamp", resign(s_valid, lambda b: b.update(expires_at=True)),
         rej("validity", "InvalidTimestamp"))
    case("stream_grant_null_timestamp", resign(s_valid, lambda b: b.update(expires_at=None)),
         rej("validity", "InvalidTimestamp"))
    case("stream_grant_float_timestamp", resign(s_valid, lambda b: b.update(issued_at=T0 + 0.5)),
         rej("malformed", "NonCanonicalNumber"),
         note="Music signs 1760000000.5; Rust refuses to canonicalise floats (CORE-002 rule)")
    case("licence_timestamp_beyond_i64", resign(l_valid, lambda b: b.update(issued_at=2**63)),
         rej("validity", "InvalidTimestamp"))
    case("licence_negative_timestamp_beyond_i64", licence(issued=-(10**19)),
         rej("malformed", "NonCanonicalNumber"),
         divergence="python-accepts-out-of-range-licence-issued-at",
         note="Music accepts any past integer; serde_json reads < i64::MIN as a float, "
              "which Rust refuses to canonicalise. Owner-signed only; Music never issues it.")

    # ---- issuer authentication ---------------------------------------------
    case("grant_signed_by_mallory_key", resign(s_valid, lambda b: None, signer=mallory_ed),
         rej("unauthenticated", "WrongIssuer"))
    case("mallory_substitutes_her_own_package_grant",
         stream(m_manifest, m_key, signer=mallory_ed, owner=MALLORY),
         rej("unauthenticated", "WrongIssuer"))

    def swap_signature(grant: dict, signature_b64: str) -> dict:
        forged = copy.deepcopy(grant)
        forged["signature"] = signature_b64
        return forged

    mallory_sig = music.b64(mallory_ed.sign(music.canonical(s_valid["body"])))
    case("forged_signature_under_alice_signer", swap_signature(s_valid, mallory_sig),
         rej("unauthenticated", "InvalidSignature"))
    case("all_zero_signature", swap_signature(s_valid, music.b64(bytes(64))),
         rej("unauthenticated", "InvalidSignature"))
    case("truncated_signature_63_bytes",
         swap_signature(s_valid, music.b64(music.from_b64(s_valid["signature"], 64)[:63])),
         rej("unauthenticated", "MalformedSignature"))
    case("signature_not_base64", swap_signature(s_valid, "!" * 88),
         rej("unauthenticated", "MalformedSignature"))
    bad_signer = copy.deepcopy(s_valid)
    bad_signer["signer"] = music.b64(alice_pub[:31])
    case("signer_field_wrong_length", bad_signer, rej("unauthenticated", "MalformedIssuerKey"))
    claimed_mallory = copy.deepcopy(s_valid)
    claimed_mallory["signer"] = music.b64(mallory_pub)
    case("signer_field_claims_mallory", claimed_mallory, rej("unauthenticated", "WrongIssuer"))
    # Non-canonical base64 (non-zero trailing bits) in the UNSIGNED signer field:
    # Python's b64decode(validate=True) accepts it; Rust matches for grants.
    nc_signer = copy.deepcopy(s_valid)
    sig_text = nc_signer["signer"]
    assert sig_text.endswith("=")
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    last = sig_text[-2]
    nc_signer["signer"] = sig_text[:-2] + alphabet[alphabet.index(last) | 1] + "="
    if nc_signer["signer"] != sig_text:
        case("signer_field_noncanonical_base64_parity", nc_signer, ok,
             note="decodes to Alice's key in both implementations")

    # ---- signed-body tampering (no re-signature) ----------------------------
    def tamper(grant: dict, transform) -> dict:
        altered = copy.deepcopy(grant)
        transform(altered["body"])
        return altered

    case("modified_listener_without_resign", tamper(s_valid, lambda b: b.update(listener_agent=MALLORY)),
         rej("unauthenticated", "InvalidSignature"),
         subject={"listener_agent": MALLORY, "x25519": "bob"})
    case("modified_expiry_without_resign",
         tamper(s_valid, lambda b: b.update(expires_at=b["expires_at"] + 3600)),
         rej("unauthenticated", "InvalidSignature"))
    case("modified_recipient_without_resign",
         tamper(s_valid, lambda b: b.update(recipient_key_hex=x_public(mallory_x).hex())),
         rej("unauthenticated", "InvalidSignature"),
         subject={"listener_agent": BOB, "x25519": "mallory"})
    def relabel(b: dict) -> None:
        del b["expires_at"]
        b.update(schema=cg.LICENCE_SCHEMA, licence_id="ab" * 16, terms=cg.LICENCE_TERMS)

    case("stream_grant_relabelled_as_licence", tamper(s_valid, relabel),
         rej("unauthenticated", "InvalidSignature"), right="export")

    # ---- owner / content binding -------------------------------------------
    case("wrong_owner_agent_in_alice_signed_grant", stream(owner=MALLORY),
         rej("denied", "OwnerMismatch"))
    case("replay_grant_for_other_package", stream(q_manifest, q_key), rej("denied", "FileMismatch"))
    case("replay_licence_for_other_package", licence(q_manifest, q_key), rej("denied", "FileMismatch"),
         right="export")
    case("wrong_file_id_resigned", resign(s_valid, lambda b: b.update(file_id="00" * 32)),
         rej("denied", "FileMismatch"))
    case("wrong_manifest_digest_resigned", resign(s_valid, lambda b: b.update(manifest_sha256="00" * 32)),
         rej("denied", "ManifestMismatch"))
    case("uppercase_manifest_digest_resigned",
         resign(s_valid, lambda b: b.update(manifest_sha256=b["manifest_sha256"].upper())),
         rej("denied", "ManifestMismatch"))

    # ---- listener / recipient binding --------------------------------------
    mallory_bob_key = {"listener_agent": MALLORY, "x25519": "bob"}
    mallory_own = {"listener_agent": MALLORY, "x25519": "mallory"}
    bob_mallory_key = {"listener_agent": BOB, "x25519": "mallory"}
    case("wrong_listener_agent", s_valid, rej("denied", "ListenerMismatch"), subject=mallory_bob_key)
    case("mallory_presents_bobs_grant", s_valid, rej("denied", "ListenerMismatch"), subject=mallory_own)
    case("mallory_presents_bobs_licence", l_valid, rej("denied", "ListenerMismatch"),
         subject=mallory_own, right="export")
    case("wrong_recipient_public_key", s_valid, rej("denied", "RecipientKeyMismatch"),
         subject=bob_mallory_key)
    case("grant_addressed_to_mallory_key", stream(recipient=mallory_x),
         rej("denied", "RecipientKeyMismatch"))
    case("uppercase_recipient_key_resigned",
         resign(s_valid, lambda b: b.update(recipient_key_hex=b["recipient_key_hex"].upper())),
         rej("malformed", "RecipientKey"))
    case("short_recipient_key_resigned",
         resign(s_valid, lambda b: b.update(recipient_key_hex=b["recipient_key_hex"][:62])),
         rej("malformed", "RecipientKey"))
    case("invalid_ephemeral_key_resigned",
         resign(s_valid, lambda b: b.update(ephemeral_key_hex="zz" * 32)),
         rej("malformed", "EphemeralKey"))

    # ---- requested rights ----------------------------------------------------
    case("stream_grant_does_not_confer_managed_offline", s_valid, rej("denied", "RightNotGranted"),
         right="managed-offline")
    case("stream_grant_does_not_confer_export", s_valid, rej("denied", "RightNotGranted"),
         right="export")
    case("max_lifetime_grant_does_not_confer_export",
         stream(lifetime=cg.MAX_LIFETIME_SECONDS), rej("denied", "RightNotGranted"), right="export")

    # ---- licence terms / schema / structure ----------------------------------
    case("licence_unknown_terms", resign(l_valid, lambda b: b.update(terms="commercial-use")),
         rej("unsupported", "LicenceTerms"), right="export")
    case("licence_uppercase_licence_id", resign(l_valid, lambda b: b.update(licence_id=b["licence_id"].upper())),
         rej("malformed", "LicenceId"))
    case("licence_short_licence_id", resign(l_valid, lambda b: b.update(licence_id="ab" * 15)),
         rej("malformed", "LicenceId"))
    case("unsupported_schema_version",
         resign(s_valid, lambda b: b.update(schema="holochain-music/content-grant/v2")),
         rej("unsupported", "UnknownSchema"))
    case("missing_schema", resign(s_valid, lambda b: b.pop("schema")),
         rej("malformed", "Structure"))
    with at(T0):
        legacy_grant = legacy.create_perpetual_grant(p_manifest, alice_pub, alice_ed, p_key, x_public(bob_x))
    case("legacy_personal_perpetual_grant_v1", legacy_grant, rej("unsupported", "LegacyPerpetualGrant"),
         right="export",
         note="holochain_storage/grant.py prototype schema: no owner/listener agent binding")
    case("unexpected_body_field", resign(s_valid, lambda b: b.update(note="hello")),
         rej("malformed", "Structure"))
    case("licence_with_expiry_field", resign(l_valid, lambda b: b.update(expires_at=T0 + 60)),
         rej("malformed", "Structure"))
    case("missing_body_field", resign(s_valid, lambda b: b.pop("nonce_b64")),
         rej("malformed", "Structure"))
    case("non_string_agent_resigned", resign(s_valid, lambda b: b.update(listener_agent=7)),
         rej("malformed", "Structure"))
    extra_envelope = copy.deepcopy(s_valid)
    extra_envelope["note"] = "unsigned"
    case("unexpected_envelope_field", extra_envelope, rej("malformed", "Structure"))
    missing_sig = copy.deepcopy(s_valid)
    del missing_sig["signature"]
    case("missing_signature_field", missing_sig, rej("malformed", "Structure"))
    valid_text = text(s_valid)
    case("truncated_envelope", valid_text[: len(valid_text) // 2], rej("malformed", "Json"))
    case("trailing_garbage", valid_text + "x", rej("malformed", "Json"))
    case("json_array_not_object", "[" + valid_text + "]", rej("malformed", "Structure"))
    case("empty_input", "", rej("malformed", "Json"))

    # Duplicate keys: Python's json.loads keeps the last value; Rust rejects the
    # ambiguity outright. With the signed value last, Music accepts.
    body_text = text(s_valid["body"])
    dup_last = valid_text.replace(
        '"listener_agent":"' + BOB + '"',
        '"listener_agent":"' + MALLORY + '","listener_agent":"' + BOB + '"', 1)
    assert dup_last != valid_text and body_text in valid_text
    case("duplicate_body_key_signed_value_last", dup_last, rej("malformed", "Structure"),
         divergence="rust-rejects-duplicate-json-keys")
    dup_first = valid_text.replace(
        '"listener_agent":"' + BOB + '"',
        '"listener_agent":"' + BOB + '","listener_agent":"' + MALLORY + '"', 1)
    case("duplicate_body_key_signed_value_first", dup_first, rej("malformed", "Structure"))
    dup_env = valid_text[:-1] + ',"signer":' + json.dumps(s_valid["signer"]) + "}"
    case("duplicate_envelope_key", dup_env, rej("malformed", "Structure"),
         divergence="rust-rejects-duplicate-json-keys")

    # ---- size limits ----------------------------------------------------------
    big = resign(s_valid, lambda b: b.update(owner_agent="A" * cg.MAX_GRANT_BYTES))
    case("oversized_canonical_grant", big, rej("malformed", "TooLarge"))
    padded = valid_text.replace(",", ", " + " " * 4096, 4)
    assert len(padded.encode()) > 16 * 1024
    case("oversized_raw_input_whitespace", padded, rej("malformed", "TooLarge"),
         divergence="rust-caps-raw-input-at-music-library-read-limit",
         note="Music's Library.grant() refuses files > 16 KiB; unwrap_content_grant alone accepts")

    # ---- wrapped-key envelope -----------------------------------------------
    case("wrapped_key_wrong_length_resigned",
         resign(s_valid, lambda b: b.update(wrapped_key_b64=music.b64(bytes(47)))),
         rej("malformed", "KeyEnvelope"))
    case("salt_not_base64_resigned", resign(s_valid, lambda b: b.update(salt_b64="***")),
         rej("malformed", "KeyEnvelope"))
    case("nonce_wrong_length_resigned", resign(s_valid, lambda b: b.update(nonce_b64=music.b64(bytes(11)))),
         rej("malformed", "KeyEnvelope"))

    def flip_wrapped(b: dict) -> None:
        raw = bytearray(music.from_b64(b["wrapped_key_b64"], 48))
        raw[0] ^= 1
        b["wrapped_key_b64"] = music.b64(bytes(raw))

    case("wrapped_key_corrupted_but_owner_signed", resign(s_valid, flip_wrapped), ok,
         divergence="key-unwrap-boundary",
         note="CORE-005 authorises the signed policy only; Music's AES-GCM unwrap then rejects")
    case("ephemeral_key_low_order_but_owner_signed",
         resign(s_valid, lambda b: b.update(ephemeral_key_hex="00" * 32)), ok,
         divergence="key-unwrap-boundary",
         note="X25519 exchange with a low-order point fails only at unwrap time")

    vectors = {
        "schema": VECTOR_SCHEMA,
        "music_commit": PINNED_MUSIC_COMMIT,
        "cryptography_version": cryptography.__version__,
        "clock_t0": T0,
        "constants": {
            "max_grant_bytes": cg.MAX_GRANT_BYTES,
            "max_lifetime_seconds": cg.MAX_LIFETIME_SECONDS,
            "clock_skew_seconds": cg.CLOCK_SKEW_SECONDS,
            "grant_schema": cg.GRANT_SCHEMA,
            "licence_schema": cg.LICENCE_SCHEMA,
            "licence_terms": cg.LICENCE_TERMS,
            "legacy_grant_schema": legacy.GRANT_SCHEMA,
        },
        "agents": agents,
        "keys": {
            "alice_ed25519_public_hex": alice_pub.hex(),
            "mallory_ed25519_public_hex": mallory_pub.hex(),
            "bob_x25519_public_hex": x_public(bob_x).hex(),
            "mallory_x25519_public_hex": x_public(mallory_x).hex(),
        },
        "content": {
            name: {"owner_agent": ALICE if name != "m" else MALLORY,
                   "manifest_text": text(manifests[name]),
                   "file_id": manifests[name]["body"]["file_id"],
                   "manifest_sha256": music.manifest_digest(manifests[name])}
            for name in ("p", "q")
        },
        "cases": cases,
    }

    names = [c["name"] for c in cases]
    assert len(names) == len(set(names)), "duplicate case names"
    # Self-check: Python's verdict agrees with the expectation except where a
    # divergence is documented.
    for c in cases:
        authorised = c["python"]["unwrap"] == "ok" and c["python"]["right_allowed"]
        expected = c["expect"]["decision"] == "authorized"
        divergence = c.get("divergence")
        if divergence == "key-unwrap-boundary":
            assert expected and not authorised, c["name"]
        elif divergence in ("rust-rejects-duplicate-json-keys",
                            "rust-caps-raw-input-at-music-library-read-limit",
                            "python-accepts-out-of-range-licence-issued-at"):
            assert authorised and not expected, c["name"]
        else:
            assert authorised == expected, (c["name"], c["python"])

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(vectors, sort_keys=True, indent=1) + "\n", encoding="utf-8")
    print(f"Created {len(cases)} non-sensitive Music entitlement vectors from {commit}")


if __name__ == "__main__":
    main()
