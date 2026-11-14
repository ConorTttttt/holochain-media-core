//! S2 key lifecycle v2.1: verified rotation, recovery and revocation of the
//! media signing keys bound to a Holochain agent (Music `dna-v21/`).
//!
//! Records are [`ConductorRecord`]s from a trusted, validating conductor that
//! carry their action's chain position ([`ConductorRecord::action_seq`]).
//! Every record for the agent and purpose is verified here independently of
//! the DNA (exact fields, DNA hash, Ed25519 proof of possession, continuity
//! signature) and the single lineage is rebuilt from predecessor references:
//!
//! * exactly one inception; a second one, or two successors of one
//!   generation, is [`KeyValidity::Ambiguous`] (fail closed, never
//!   first/latest-match, never timestamps);
//! * generations increase by exactly one; keys are never reused;
//! * a gap (a predecessor or revocation target that was not returned) is
//!   [`BindingError::LifecycleIncomplete`];
//! * any invalid record is an error, never skipped.
//!
//! Use policy (see docs/S2-KEY-LIFECYCLE-V21.md §6):
//! * **new operations** need the active (tip, unrevoked) generation;
//! * **historical** use of a superseded or `new-operations`-revoked key is
//!   [`KeyValidity::HistoricalOnly`]; a `compromised` key is only acceptable
//!   for an artifact anchored on the agent's chain before the key ended;
//! * an artifact anchored *after* its key ended is a new operation with a
//!   stale key ([`KeyValidity::Rotated`] / [`KeyValidity::Revoked`]).

use crate::binding::{
    BindingAssurance, BindingError, ConductorRecord, KeyPurpose, VerifiedKeyBinding,
};
use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::Value;

/// Lifecycle transition schema (inception, rotation, recovery).
pub const KEY_LIFECYCLE_V21: &str = "holochain-storage/key-lifecycle/v2.1";
/// Revocation schema.
pub const KEY_REVOCATION_V21: &str = "holochain-storage/key-revocation/v2.1";
/// Signing domain of lifecycle signatures (NUL-terminated).
pub const KEY_LIFECYCLE_DOMAIN_V21: &[u8] = b"holochain-storage/key-lifecycle/v2.1\0";
/// Role of the new key's proof of possession.
pub const ROLE_SUCCESSOR: &str = "successor-possession";
/// Role of the predecessor key's continuity signature.
pub const ROLE_PREDECESSOR: &str = "predecessor-continuity";
/// Only revocation authority defined by v2.1.
pub const REVOCATION_AUTHORITY_AGENT: &str = "holochain-agent";
/// Largest generation number.
pub const MAX_GENERATION: u32 = 1_000_000;
const MAX_TEXT: usize = 160;
const TRANSITION_FIELDS: [&str; 11] = [
    "schema",
    "dna_hash",
    "agent",
    "purpose",
    "generation",
    "kind",
    "signing_key_hex",
    "predecessor_action",
    "predecessor_key_hex",
    "proof_signature_hex",
    "continuity_signature_hex",
];
const REVOCATION_FIELDS: [&str; 9] = [
    "schema",
    "dna_hash",
    "agent",
    "purpose",
    "generation",
    "signing_key_hex",
    "target_action",
    "authority",
    "scope",
];

/// Explicit validity of a signing key for one use.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum KeyValidity {
    /// The current, unrevoked generation.
    Active,
    /// Superseded by a later generation; not valid for this use.
    Rotated,
    /// Revoked; not valid for this use.
    Revoked,
    /// Not valid for new operations, valid for this historical use.
    HistoricalOnly,
    /// The lifecycle forks (two inceptions or competing successors).
    Ambiguous,
    /// Invalid, incomplete or unrelated records, or an unknown key.
    Invalid,
}

/// How a generation was introduced.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum KeyContinuity {
    /// First generation (also v1/v2 bindings).
    Inception,
    /// Normal rotation: continuity signed by the predecessor key.
    Rotation,
    /// Recovery: authorised by the agent alone, no continuity signature.
    RecoveredWithoutContinuity,
}

/// Revocation scope.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RevocationScope {
    /// No new operations; historical signatures remain verifiable.
    NewOperations,
    /// No new operations; historical signatures only when anchored before
    /// the key ended.
    Compromised,
}

impl RevocationScope {
    /// On-DHT spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NewOperations => "new-operations",
            Self::Compromised => "compromised",
        }
    }
    fn parse(text: &str) -> Option<Self> {
        match text {
            "new-operations" => Some(Self::NewOperations),
            "compromised" => Some(Self::Compromised),
            _ => None,
        }
    }
}

/// Position of an agent-authored record (a file commitment, a replica claim)
/// on its author's chain. Only constructed from a [`ConductorRecord`] that
/// carries its chain position.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChainAnchor {
    author: String,
    action_seq: u32,
}

impl ChainAnchor {
    /// Anchor at `record`'s action. Fails if the conductor did not return
    /// the chain position.
    pub fn from_record(record: &ConductorRecord) -> Result<Self, BindingError> {
        Ok(Self {
            author: record.author().to_owned(),
            action_seq: record.action_seq().ok_or(BindingError::MissingRecord)?,
        })
    }
    /// The record's author.
    pub fn author(&self) -> &str {
        &self.author
    }
    /// The record's chain position.
    pub fn action_seq(&self) -> u32 {
        self.action_seq
    }
}

/// What a key is being used for.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum KeyUse {
    /// A new manifest, grant, receipt or other operation needing an active
    /// signing authority.
    NewOperation,
    /// Verifying a previously issued artifact, optionally anchored on the
    /// key owner's chain.
    Historical {
        /// The agent-authored record that published the artifact.
        anchor: Option<ChainAnchor>,
    },
}

/// One verified generation of a lifecycle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyGeneration {
    generation: u32,
    key: [u8; 32],
    action_hash: String,
    action_seq: u32,
    continuity: KeyContinuity,
    recovered_lineage: bool,
    end_seq: Option<u32>,
    compromised_seq: Option<u32>,
    revocations: Vec<RevocationScope>,
}

impl KeyGeneration {
    /// Generation number.
    pub fn generation(&self) -> u32 {
        self.generation
    }
    /// Ed25519 public key.
    pub fn key(&self) -> &[u8; 32] {
        &self.key
    }
    /// Action hash of the transition that introduced it.
    pub fn action_hash(&self) -> &str {
        &self.action_hash
    }
    /// Chain position of that transition.
    pub fn action_seq(&self) -> u32 {
        self.action_seq
    }
    /// How it was introduced.
    pub fn continuity(&self) -> KeyContinuity {
        self.continuity
    }
    /// Chain position after which it may not authorise new operations (its
    /// successor or first revocation), if any.
    pub fn end_seq(&self) -> Option<u32> {
        self.end_seq
    }
    /// Recorded revocation scopes, in chain order.
    pub fn revocations(&self) -> &[RevocationScope] {
        &self.revocations
    }
}

/// A verified, unambiguous lifecycle for one agent and purpose.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyLifecycle {
    agent: String,
    purpose: KeyPurpose,
    dna_hash: String,
    generations: Vec<KeyGeneration>,
}

impl KeyLifecycle {
    /// The Holochain agent.
    pub fn agent(&self) -> &str {
        &self.agent
    }
    /// The purpose.
    pub fn purpose(&self) -> KeyPurpose {
        self.purpose
    }
    /// The v2.1 DNA hash the records were verified for.
    pub fn dna_hash(&self) -> &str {
        &self.dna_hash
    }
    /// All generations, oldest first (never empty).
    pub fn generations(&self) -> &[KeyGeneration] {
        &self.generations
    }
    /// The latest generation (active unless revoked).
    pub fn tip(&self) -> &KeyGeneration {
        self.generations
            .last()
            .expect("a resolved lifecycle has an inception")
    }

    fn find(&self, key: &[u8; 32]) -> Option<&KeyGeneration> {
        self.generations.iter().find(|g| &g.key == key)
    }

    /// The tip generation as a binding, reporting its CURRENT status
    /// ([`KeyValidity::Active`], or [`KeyValidity::Revoked`] when the tip
    /// was revoked). Informational: authorise uses with [`Self::active`] or
    /// [`Self::authorize`].
    pub fn tip_binding(&self) -> VerifiedKeyBinding {
        let tip = self.tip();
        let validity = if tip.revocations.is_empty() {
            KeyValidity::Active
        } else {
            KeyValidity::Revoked
        };
        self.binding(tip, validity)
    }

    /// The key for new operations, or [`BindingError::KeyRevoked`].
    pub fn active(&self) -> Result<VerifiedKeyBinding, BindingError> {
        let tip = self.tip();
        if !tip.revocations.is_empty() {
            return Err(BindingError::KeyRevoked);
        }
        Ok(self.binding(tip, KeyValidity::Active))
    }

    /// Classify `key` for `key_use` (total; see the module docs).
    pub fn classify(&self, key: &[u8; 32], key_use: &KeyUse) -> KeyValidity {
        let Some(g) = self.find(key) else {
            return KeyValidity::Invalid;
        };
        let active_now = std::ptr::eq(g, self.tip()) && g.revocations.is_empty();
        let ended = || {
            if g.revocations.is_empty() {
                KeyValidity::Rotated
            } else {
                KeyValidity::Revoked
            }
        };
        let current = if active_now {
            KeyValidity::Active
        } else {
            KeyValidity::HistoricalOnly
        };
        match key_use {
            KeyUse::NewOperation => {
                if active_now {
                    KeyValidity::Active
                } else {
                    ended()
                }
            }
            KeyUse::Historical {
                anchor: Some(anchor),
            } => {
                if anchor.author != self.agent {
                    KeyValidity::Invalid
                } else if g.end_seq.is_some_and(|end| anchor.action_seq > end) {
                    ended()
                } else {
                    current
                }
            }
            KeyUse::Historical { anchor: None } => {
                if g.compromised_seq.is_some() {
                    KeyValidity::Revoked
                } else {
                    current
                }
            }
        }
    }

    /// A [`VerifiedKeyBinding`] for `key` when it is acceptable for
    /// `key_use` ([`KeyValidity::Active`] or [`KeyValidity::HistoricalOnly`]).
    pub fn authorize(
        &self,
        key: &[u8; 32],
        key_use: &KeyUse,
    ) -> Result<VerifiedKeyBinding, BindingError> {
        match self.classify(key, key_use) {
            validity @ (KeyValidity::Active | KeyValidity::HistoricalOnly) => {
                let g = self.find(key).expect("classified key exists");
                Ok(self.binding(g, validity))
            }
            KeyValidity::Rotated => Err(BindingError::KeyRotated),
            KeyValidity::Revoked => Err(BindingError::KeyRevoked),
            KeyValidity::Ambiguous => Err(BindingError::Ambiguous),
            KeyValidity::Invalid => Err(BindingError::KeyNotBound),
        }
    }

    /// The generation introduced by this transition action, if any.
    pub fn generation_by_action(&self, action_hash: &str) -> Option<&KeyGeneration> {
        self.generations
            .iter()
            .find(|g| g.action_hash == action_hash)
    }

    /// The generation with this exact transition action, generation and key.
    pub(crate) fn generation_at(
        &self,
        action_hash: &str,
        generation: u32,
        key: &[u8; 32],
    ) -> Option<&KeyGeneration> {
        self.generations
            .iter()
            .find(|g| g.action_hash == action_hash && g.generation == generation && &g.key == key)
    }

    pub(crate) fn binding(&self, g: &KeyGeneration, validity: KeyValidity) -> VerifiedKeyBinding {
        VerifiedKeyBinding {
            agent: self.agent.clone(),
            purpose: self.purpose,
            key: g.key,
            assurance: if g.recovered_lineage {
                BindingAssurance::KeyLifecycleRecoveredV21
            } else {
                BindingAssurance::KeyLifecycleV21
            },
            action_hash: g.action_hash.clone(),
            generation: g.generation,
            continuity: g.continuity,
            validity,
        }
    }
}

/// Exact signed bytes: `KEY_LIFECYCLE_DOMAIN_V21 || for f in [role, schema,
/// dna_hash, agent, purpose, generation, kind, signing_key_hex,
/// predecessor_action, predecessor_key_hex]: u32_be(len(f)) || f`.
#[allow(clippy::too_many_arguments)]
pub fn key_transition_v21_message(
    role: &str,
    dna_hash: &str,
    agent: &str,
    purpose: &str,
    generation: &str,
    kind: &str,
    signing_key_hex: &str,
    predecessor_action: &str,
    predecessor_key_hex: &str,
) -> Vec<u8> {
    let mut out = KEY_LIFECYCLE_DOMAIN_V21.to_vec();
    for field in [
        role,
        KEY_LIFECYCLE_V21,
        dna_hash,
        agent,
        purpose,
        generation,
        kind,
        signing_key_hex,
        predecessor_action,
        predecessor_key_hex,
    ] {
        out.extend_from_slice(&(field.len() as u32).to_be_bytes());
        out.extend_from_slice(field.as_bytes());
    }
    out
}

/// Canonical decimal generation in `1..=MAX_GENERATION`.
pub fn parse_generation(text: &str) -> Option<u32> {
    if text.is_empty()
        || text.len() > 7
        || !text.bytes().all(|b| b.is_ascii_digit())
        || text.starts_with('0')
    {
        return None;
    }
    text.parse::<u32>()
        .ok()
        .filter(|g| (1..=MAX_GENERATION).contains(g))
}

pub(crate) fn strict_hex<const N: usize>(text: &str) -> Option<[u8; N]> {
    let raw = text.as_bytes();
    if raw.len() != 2 * N {
        return None;
    }
    let nibble = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    let mut out = [0u8; N];
    for (i, pair) in raw.chunks_exact(2).enumerate() {
        out[i] = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Some(out)
}

pub(crate) fn verify_ed25519(key: &[u8; 32], signature: &[u8; 64], message: &[u8]) -> bool {
    VerifyingKey::from_bytes(key)
        .and_then(|k| k.verify_strict(message, &Signature::from_bytes(signature)))
        .is_ok()
}

fn exact_fields(record: &ConductorRecord, fields: &[&str]) -> bool {
    let body = record.body();
    body.len() == fields.len()
        && fields.iter().all(|f| body.contains_key(*f))
        && body.values().all(Value::is_string)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Kind {
    Inception,
    Rotation,
    Recovery,
}

struct Transition<'a> {
    record: &'a ConductorRecord,
    seq: u32,
    generation: u32,
    kind: Kind,
    key: [u8; 32],
    predecessor_action: &'a str,
    predecessor_key_hex: &'a str,
}

struct Revocation<'a> {
    seq: u32,
    generation: &'a str,
    key_hex: &'a str,
    target: &'a str,
    scope: RevocationScope,
}

enum Checked<'a> {
    T(Transition<'a>),
    R(Revocation<'a>),
}

fn check<'a>(
    r: &'a ConductorRecord,
    agent: &str,
    purpose: KeyPurpose,
    dna: &str,
) -> Result<Checked<'a>, BindingError> {
    let seq = r.action_seq().ok_or(BindingError::MissingRecord)?;
    if r.author() != agent {
        return Err(BindingError::AuthorMismatch);
    }
    let schema = r.schema();
    let fields: &[&str] = match schema {
        Some(KEY_LIFECYCLE_V21) => &TRANSITION_FIELDS,
        Some(KEY_REVOCATION_V21) => &REVOCATION_FIELDS,
        _ => return Err(BindingError::InvalidRecord),
    };
    if !exact_fields(r, fields) {
        return Err(BindingError::InvalidRecord);
    }
    if r.text("agent")? != agent || r.text("purpose")? != purpose.as_str() {
        return Err(BindingError::KeyNotBound);
    }
    if r.text("dna_hash")? != dna {
        return Err(BindingError::WrongDna);
    }
    let generation_text = r.text("generation")?;
    let generation = parse_generation(generation_text).ok_or(BindingError::InvalidRecord)?;
    let key_hex = r.text("signing_key_hex")?;
    let key = strict_hex::<32>(key_hex).ok_or(BindingError::InvalidRecord)?;
    if schema == Some(KEY_REVOCATION_V21) {
        let scope = RevocationScope::parse(r.text("scope")?).ok_or(BindingError::InvalidRecord)?;
        if r.text("authority")? != REVOCATION_AUTHORITY_AGENT {
            return Err(BindingError::InvalidRecord);
        }
        return Ok(Checked::R(Revocation {
            seq,
            generation: generation_text,
            key_hex,
            target: r.text("target_action")?,
            scope,
        }));
    }
    let proof =
        strict_hex::<64>(r.text("proof_signature_hex")?).ok_or(BindingError::InvalidProof)?;
    let predecessor_action = r.text("predecessor_action")?;
    let predecessor_key_hex = r.text("predecessor_key_hex")?;
    let continuity_hex = r.text("continuity_signature_hex")?;
    let kind_text = r.text("kind")?;
    let message = |role: &str| {
        key_transition_v21_message(
            role,
            dna,
            agent,
            purpose.as_str(),
            generation_text,
            kind_text,
            key_hex,
            predecessor_action,
            predecessor_key_hex,
        )
    };
    let kind = match kind_text {
        "inception" => {
            if generation != 1
                || !predecessor_action.is_empty()
                || !predecessor_key_hex.is_empty()
                || !continuity_hex.is_empty()
            {
                return Err(BindingError::InvalidRecord);
            }
            Kind::Inception
        }
        "rotation" | "recovery" => {
            if predecessor_action.is_empty() || predecessor_action.len() > MAX_TEXT {
                return Err(BindingError::InvalidRecord);
            }
            let predecessor =
                strict_hex::<32>(predecessor_key_hex).ok_or(BindingError::InvalidRecord)?;
            if kind_text == "rotation" {
                let continuity =
                    strict_hex::<64>(continuity_hex).ok_or(BindingError::InvalidProof)?;
                if !verify_ed25519(&predecessor, &continuity, &message(ROLE_PREDECESSOR)) {
                    return Err(BindingError::InvalidProof);
                }
                Kind::Rotation
            } else {
                if !continuity_hex.is_empty() {
                    return Err(BindingError::InvalidRecord);
                }
                Kind::Recovery
            }
        }
        _ => return Err(BindingError::InvalidRecord),
    };
    if !verify_ed25519(&key, &proof, &message(ROLE_SUCCESSOR)) {
        return Err(BindingError::InvalidProof);
    }
    Ok(Checked::T(Transition {
        record: r,
        seq,
        generation,
        kind,
        key,
        predecessor_action,
        predecessor_key_hex,
    }))
}

/// Verify every v2.1 record of `agent`/`purpose` in `records` (others are
/// ignored) and rebuild the single lineage. See the module docs.
pub fn resolve_key_lifecycle(
    records: &[ConductorRecord],
    agent: &str,
    purpose: KeyPurpose,
    dna_hash: &str,
) -> Result<KeyLifecycle, BindingError> {
    if agent.is_empty()
        || agent.len() > MAX_TEXT
        || dna_hash.is_empty()
        || dna_hash.len() > MAX_TEXT
    {
        return Err(BindingError::MissingRecord);
    }
    // Select, then de-duplicate by action hash (an identical record delivered
    // twice is one record; one action with two bodies is invalid input).
    let mut selected: Vec<&ConductorRecord> = Vec::new();
    for r in records {
        let text = |k: &str| r.body().get(k).and_then(Value::as_str);
        let relevant = matches!(r.schema(), Some(KEY_LIFECYCLE_V21 | KEY_REVOCATION_V21))
            && text("agent") == Some(agent)
            && text("purpose") == Some(purpose.as_str());
        if !relevant {
            continue;
        }
        match selected.iter().find(|s| s.action_hash() == r.action_hash()) {
            Some(prior) if *prior == r => {}
            Some(_) => return Err(BindingError::InvalidRecord),
            None => selected.push(r),
        }
    }
    if selected.is_empty() {
        return Err(BindingError::MissingRecord);
    }
    let mut transitions = Vec::new();
    let mut revocations = Vec::new();
    for r in &selected {
        match check(r, agent, purpose, dna_hash)? {
            Checked::T(t) => transitions.push(t),
            Checked::R(v) => revocations.push(v),
        }
    }
    let mut inceptions = transitions.iter().filter(|t| t.kind == Kind::Inception);
    let first = inceptions.next().ok_or(BindingError::LifecycleIncomplete)?;
    if inceptions.next().is_some() {
        return Err(BindingError::Ambiguous);
    }
    let mut generations = vec![KeyGeneration {
        generation: 1,
        key: first.key,
        action_hash: first.record.action_hash().to_owned(),
        action_seq: first.seq,
        continuity: KeyContinuity::Inception,
        recovered_lineage: false,
        end_seq: None,
        compromised_seq: None,
        revocations: Vec::new(),
    }];
    loop {
        let current = generations.last().expect("non-empty");
        let mut successors = transitions
            .iter()
            .filter(|t| t.predecessor_action == current.action_hash);
        let Some(next) = successors.next() else {
            break;
        };
        if successors.next().is_some() {
            return Err(BindingError::Ambiguous);
        }
        let current_key_hex: String = current.key.iter().map(|b| format!("{b:02x}")).collect();
        if next.generation != current.generation + 1
            || next.predecessor_key_hex != current_key_hex
            || generations.iter().any(|g| g.key == next.key)
            || next.seq <= current.action_seq
            || next.kind == Kind::Inception
        {
            return Err(BindingError::InvalidRecord);
        }
        let recovered = next.kind == Kind::Recovery;
        let lineage = current.recovered_lineage || recovered;
        generations.push(KeyGeneration {
            generation: next.generation,
            key: next.key,
            action_hash: next.record.action_hash().to_owned(),
            action_seq: next.seq,
            continuity: if recovered {
                KeyContinuity::RecoveredWithoutContinuity
            } else {
                KeyContinuity::Rotation
            },
            recovered_lineage: lineage,
            end_seq: None,
            compromised_seq: None,
            revocations: Vec::new(),
        });
    }
    if generations.len() != transitions.len() {
        return Err(BindingError::LifecycleIncomplete);
    }
    for i in 0..generations.len() - 1 {
        generations[i].end_seq = Some(generations[i + 1].action_seq);
    }
    revocations.sort_by_key(|r| r.seq);
    for r in &revocations {
        let target = generations
            .iter_mut()
            .find(|g| g.action_hash == r.target)
            .ok_or(BindingError::LifecycleIncomplete)?;
        let key_hex: String = target.key.iter().map(|b| format!("{b:02x}")).collect();
        if target.generation.to_string() != r.generation
            || key_hex != r.key_hex
            || r.seq <= target.action_seq
            || target.revocations.contains(&r.scope)
            || target.revocations.contains(&RevocationScope::Compromised)
        {
            return Err(BindingError::InvalidRecord);
        }
        target.revocations.push(r.scope);
        target.end_seq = Some(target.end_seq.map_or(r.seq, |e| e.min(r.seq)));
        if r.scope == RevocationScope::Compromised {
            target.compromised_seq = Some(r.seq);
        }
    }
    // A continuity rotation may not follow a revoked key (DNA rule; re-checked).
    for i in 1..generations.len() {
        let previous = &generations[i - 1];
        if generations[i].continuity == KeyContinuity::Rotation
            && !previous.revocations.is_empty()
            && previous
                .end_seq
                .is_some_and(|e| e < generations[i].action_seq)
        {
            return Err(BindingError::InvalidRecord);
        }
    }
    Ok(KeyLifecycle {
        agent: agent.to_owned(),
        purpose,
        dna_hash: dna_hash.to_owned(),
        generations,
    })
}

/// Total classifier over raw records: resolution errors become
/// [`KeyValidity::Ambiguous`] (forks) or [`KeyValidity::Invalid`].
pub fn evaluate_key(
    records: &[ConductorRecord],
    agent: &str,
    purpose: KeyPurpose,
    dna_hash: &str,
    key: &[u8; 32],
    key_use: &KeyUse,
) -> KeyValidity {
    match resolve_key_lifecycle(records, agent, purpose, dna_hash) {
        Ok(lifecycle) => lifecycle.classify(key, key_use),
        Err(BindingError::Ambiguous) => KeyValidity::Ambiguous,
        Err(_) => KeyValidity::Invalid,
    }
}
