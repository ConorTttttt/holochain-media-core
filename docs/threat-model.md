# Threat model — initial security boundary

Status: CORE-001 draft. Threat analysis must be expanded and independently reviewed before production.

## Protected assets

- Plaintext media and per-package content keys.
- Listener recipient private keys and grants.
- Creator and host signing keys, Holochain identity/transport key bindings.
- Integrity and availability of encrypted content, versioned licence terms and publication records.
- User metadata, local cache paths and publication/quarantine status.

## Attacker capabilities to test

1. Malicious storage peer substitutes, truncates, reorders or withholds ciphertext objects.
2. An impostor publisher/host uses a valid but unbound signing key or a wrong TLS fingerprint.
3. Recipient replays, duplicates, forwards or fabricates grants; another recipient attempts to unwrap them.
4. Creator self-asserts copyright, reviewer authority or payment and attempts to release quarantined media.
5. Local or network attacker creates symlink/path traversal, exhaustion, oversized object or cancellation races.
6. A compromised/abandoned client changes its clock to extend an offline rental; already-exported files are copied.
7. A curious host, relay or DHT observer correlates content, participants, traffic sizes and timestamps.
8. Compromised keys require revocation, rotation and backup recovery; older signed artefacts remain a migration risk.

## Controls and fail-closed rules

- Every manifest and receipt must be verified against an independently trusted expected signer and exact manifest digest.
- AES-GCM authentication tags, per-chunk hashes and bounded read lengths must be checked before releasing plaintext; verification is separate from source authenticity.
- Public DHT must not include media payloads, private encrypted grants or plaintext keys.
- Grant evaluation requires cryptographic validity, issuer identity, recipient, content scope, explicit permissions and time/policy requirements.
- A signed reviewer finding is not a legal copyright judgement and is not equivalent to a release authorisation.
- A signed content grant is not proof of settlement; independent payment confirmation is required before issuing a paid grant.
- Security-sensitive caches and file paths must be bounded, symlink-safe and checked on every use.
- Offline rental enforcement is best-effort on untrusted devices; never claim unbreakable expiry without a trusted device/clock model.
- A perpetual exported copy cannot be remotely revoked.
- Receipt audit and repair are availability tools, not proofs of ongoing independent custody.
- Invalid schema versions, unknown rights bits, unexpected authors and unsupported values must be rejected rather than silently accepted.

## CORE-001 capabilities and limits (historical)

Only parser-level validation of two 32-byte hex identifier types and three rights bits is implemented. This is **not** cryptographic verification, grant evaluation, content security or media distribution.

## CORE-004 controls and open findings

Implemented and exercised against real conductors and MoQ hosts: authorship
checks on every S2 record; unique-selection (no first-match) for keys,
claims and endpoints; S1 signature with the Holochain-bound key and exact
committed digest; receipt signed by the bound host key and committed by the
host's claim; SHA-256 certificate pinning from a host-authored endpoint;
loopback-only endpoint policy by default; per-object length/SHA-256 before
any write; transport/metadata failures classified as unavailability, never
denial. Open: S2 key bindings are not proof of possession and receipts do not
name the host agent (spoofable availability/attribution; integrity
unaffected); Holochain 0.7.0 IPv6-less dual-bind; moq-transport buffering
before length checks. Details: docs/CORE-004-holochain-moq-integration.md.

## Security review gate

Before public use, add independent review of format/parser consensus, signed network inputs, resource bounds, local key custody, metadata leakage, private message abuse, host identity pinning and migration/key-rotation flows. Keep attack tests in CI.
