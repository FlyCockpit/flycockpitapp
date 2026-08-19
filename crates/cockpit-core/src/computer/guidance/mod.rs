//! User-reviewed typed computer-use guidance proposals.
//!
//! Lets an active computer agent propose a small set of typed operating
//! preferences for future contexts without creating an agent-authored
//! persistent prompt-injection channel.
//!
//! # Security boundary
//!
//! Typed allowlisted data compiled by Cockpit is the security boundary; user
//! review alone does not make arbitrary agent-authored text safe to
//! persist/inject. Rules cannot carry free prompt text, JSON, URLs, selectors,
//! page labels/content, tool names, policy text, regexes, or templates. The
//! compiler emits only code-owned constant byte strings selected by the closed
//! enum or the eight-entry `max_actions` table — never proposal, rationale,
//! provider, model, project, page, or tool bytes.
//!
//! # Consequential predicate
//!
//! The consequential predicate used by `before_consequential_*` clauses is
//! code-owned and byte-identical to the audit contract: exactly
//! `pointer_button|pointer_drag|text_entry|key_input|scroll` are
//! consequential; `pointer_move|wait` are not; captures are observations
//! rather than actions.

#![allow(dead_code)] // Wired through the daemon coordinator in follow-up prompts.

use crate::computer::audit::ActionClass;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// The wire/storage schema version. Currently 1.
pub const SCHEMA_VERSION: u8 = 1;

/// The minimum number of rules in a proposal.
pub const MIN_RULES: usize = 1;

/// The maximum number of rules in a proposal.
pub const MAX_RULES: usize = 6;

/// The encoded length of a single rule: `schema_version:u8 | kind:u8 |
/// value:u8`.
pub const RULE_ENCODED_LEN: usize = 3;

/// The maximum number of Unicode scalar values in a rationale.
pub const RATIONALE_MAX_SCALARS: usize = 512;

/// The maximum number of UTF-8 bytes in a rationale.
pub const RATIONALE_MAX_BYTES: usize = 2048;

/// The proposal expiry duration in seconds (10 minutes).
pub const PROPOSAL_EXPIRY_SECS: i64 = 600;

/// The maximum number of proposals per delegation.
pub const MAX_PROPOSALS_PER_DELEGATION: u32 = 3;

/// The maximum number of proposals per session.
pub const MAX_PROPOSALS_PER_SESSION: u32 = 10;

/// The retention horizon (30 complete 24-hour periods) in seconds.
pub const RETENTION_HORIZON_SECS: i64 = 30 * 24 * 60 * 60;

// ---------------------------------------------------------------------------
// Rule kind discriminants (1..=6)
// ---------------------------------------------------------------------------

/// The six closed rule-kind discriminants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
#[repr(u8)]
pub enum RuleKind {
    /// `observation_cadence = 1`
    ObservationCadence = 1,
    /// `pointer_verification = 2`
    PointerVerification = 2,
    /// `fresh_dossier = 3`
    FreshDossier = 3,
    /// `unexpected_state_stop = 4`
    UnexpectedStateStop = 4,
    /// `max_reversible_batch = 5`
    MaxReversibleBatch = 5,
    /// `provider_workaround = 6`
    ProviderWorkaround = 6,
}

impl RuleKind {
    /// Convert from a raw byte. Returns `None` for codes outside 1..=6.
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            1 => Some(Self::ObservationCadence),
            2 => Some(Self::PointerVerification),
            3 => Some(Self::FreshDossier),
            4 => Some(Self::UnexpectedStateStop),
            5 => Some(Self::MaxReversibleBatch),
            6 => Some(Self::ProviderWorkaround),
            _ => None,
        }
    }

    /// The canonical byte code.
    pub fn as_byte(self) -> u8 {
        self as u8
    }

    /// The bit position in `rule_kind_bits` (0-indexed: kind 1 → bit 0,
    /// kind 6 → bit 5).
    pub fn bit_index(self) -> u8 {
        (self as u8) - 1
    }

    /// The bitmask for this kind in `rule_kind_bits`.
    pub fn bit_mask(self) -> u16 {
        1u16 << self.bit_index()
    }

    /// All six kinds in discriminant order.
    pub const ALL: [RuleKind; 6] = [
        RuleKind::ObservationCadence,
        RuleKind::PointerVerification,
        RuleKind::FreshDossier,
        RuleKind::UnexpectedStateStop,
        RuleKind::MaxReversibleBatch,
        RuleKind::ProviderWorkaround,
    ];
}

// ---------------------------------------------------------------------------
// Closed value enums
// ---------------------------------------------------------------------------

/// `observation_cadence` values: `before_each_action = 1 |
/// before_consequential_action = 2 | after_each_action = 3 |
/// after_navigation = 4`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ObservationCadence {
    BeforeEachAction = 1,
    BeforeConsequentialAction = 2,
    AfterEachAction = 3,
    AfterNavigation = 4,
}

impl ObservationCadence {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            1 => Some(Self::BeforeEachAction),
            2 => Some(Self::BeforeConsequentialAction),
            3 => Some(Self::AfterEachAction),
            4 => Some(Self::AfterNavigation),
            _ => None,
        }
    }
    pub fn as_byte(self) -> u8 {
        self as u8
    }
}

/// `pointer_verification` values: `before_every_pointer_action = 1 |
/// before_consequential_pointer_action = 2 | after_pointer_motion = 3`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum PointerVerification {
    BeforeEveryPointerAction = 1,
    BeforeConsequentialPointerAction = 2,
    AfterPointerMotion = 3,
}

impl PointerVerification {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            1 => Some(Self::BeforeEveryPointerAction),
            2 => Some(Self::BeforeConsequentialPointerAction),
            3 => Some(Self::AfterPointerMotion),
            _ => None,
        }
    }
    pub fn as_byte(self) -> u8 {
        self as u8
    }
}

/// `fresh_dossier` values: `before_each_action = 1 |
/// before_consequential_action = 2 | after_navigation = 3`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum FreshDossier {
    BeforeEachAction = 1,
    BeforeConsequentialAction = 2,
    AfterNavigation = 3,
}

impl FreshDossier {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            1 => Some(Self::BeforeEachAction),
            2 => Some(Self::BeforeConsequentialAction),
            3 => Some(Self::AfterNavigation),
            _ => None,
        }
    }
    pub fn as_byte(self) -> u8 {
        self as u8
    }
}

/// `unexpected_state_stop` values: `any_mismatch = 1 |
/// target_or_focus_mismatch = 2 | verification_mismatch = 3`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum UnexpectedStateStop {
    AnyMismatch = 1,
    TargetOrFocusMismatch = 2,
    VerificationMismatch = 3,
}

impl UnexpectedStateStop {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            1 => Some(Self::AnyMismatch),
            2 => Some(Self::TargetOrFocusMismatch),
            3 => Some(Self::VerificationMismatch),
            _ => None,
        }
    }
    pub fn as_byte(self) -> u8 {
        self as u8
    }
}

/// `provider_workaround` values: `refresh_observation_before_pointer = 1 |
/// one_pointer_action_per_observation = 2 | verify_after_scroll = 3`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ProviderWorkaround {
    RefreshObservationBeforePointer = 1,
    OnePointerActionPerObservation = 2,
    VerifyAfterScroll = 3,
}

impl ProviderWorkaround {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            1 => Some(Self::RefreshObservationBeforePointer),
            2 => Some(Self::OnePointerActionPerObservation),
            3 => Some(Self::VerifyAfterScroll),
            _ => None,
        }
    }
    pub fn as_byte(self) -> u8 {
        self as u8
    }
}

// ---------------------------------------------------------------------------
// ComputerGuidanceRuleV1 — the closed union
// ---------------------------------------------------------------------------

/// The closed union of typed guidance rules. The wire/storage form is
/// `{schema_version: 1, kind: <closed discriminant>, <the one field above>}`
/// with unknown keys rejected. The encoder is `schema_version:u8 | kind:u8 |
/// value:u8`; all six variants are exactly three bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ComputerGuidanceRuleV1 {
    ObservationCadence(ObservationCadence),
    PointerVerification(PointerVerification),
    FreshDossier(FreshDossier),
    UnexpectedStateStop(UnexpectedStateStop),
    MaxReversibleBatch { max_actions: u8 },
    ProviderWorkaround(ProviderWorkaround),
}

impl ComputerGuidanceRuleV1 {
    /// The discriminant kind of this rule.
    pub fn kind(&self) -> RuleKind {
        match self {
            Self::ObservationCadence(_) => RuleKind::ObservationCadence,
            Self::PointerVerification(_) => RuleKind::PointerVerification,
            Self::FreshDossier(_) => RuleKind::FreshDossier,
            Self::UnexpectedStateStop(_) => RuleKind::UnexpectedStateStop,
            Self::MaxReversibleBatch { .. } => RuleKind::MaxReversibleBatch,
            Self::ProviderWorkaround(_) => RuleKind::ProviderWorkaround,
        }
    }

    /// The single value byte.
    pub fn value_byte(&self) -> u8 {
        match self {
            Self::ObservationCadence(v) => v.as_byte(),
            Self::PointerVerification(v) => v.as_byte(),
            Self::FreshDossier(v) => v.as_byte(),
            Self::UnexpectedStateStop(v) => v.as_byte(),
            Self::MaxReversibleBatch { max_actions } => *max_actions,
            Self::ProviderWorkaround(v) => v.as_byte(),
        }
    }

    /// Encode to the exact 3-byte canonical form:
    /// `schema_version:u8 | kind:u8 | value:u8`.
    pub fn encode(&self) -> [u8; RULE_ENCODED_LEN] {
        [SCHEMA_VERSION, self.kind().as_byte(), self.value_byte()]
    }

    /// Decode from the exact 3-byte canonical form. Rejects unknown schema
    /// versions, unknown kinds, out-of-range values, and unknown fields.
    pub fn decode(buf: &[u8; RULE_ENCODED_LEN]) -> Result<Self, GuidanceDecodeError> {
        if buf[0] != SCHEMA_VERSION {
            return Err(GuidanceDecodeError::BadSchemaVersion(buf[0]));
        }
        let kind = RuleKind::from_byte(buf[1]).ok_or(GuidanceDecodeError::UnknownKind(buf[1]))?;
        let value = buf[2];
        match kind {
            RuleKind::ObservationCadence => {
                let v = ObservationCadence::from_byte(value)
                    .ok_or(GuidanceDecodeError::InvalidValue(kind, value))?;
                Ok(Self::ObservationCadence(v))
            }
            RuleKind::PointerVerification => {
                let v = PointerVerification::from_byte(value)
                    .ok_or(GuidanceDecodeError::InvalidValue(kind, value))?;
                Ok(Self::PointerVerification(v))
            }
            RuleKind::FreshDossier => {
                let v = FreshDossier::from_byte(value)
                    .ok_or(GuidanceDecodeError::InvalidValue(kind, value))?;
                Ok(Self::FreshDossier(v))
            }
            RuleKind::UnexpectedStateStop => {
                let v = UnexpectedStateStop::from_byte(value)
                    .ok_or(GuidanceDecodeError::InvalidValue(kind, value))?;
                Ok(Self::UnexpectedStateStop(v))
            }
            RuleKind::MaxReversibleBatch => {
                if !(1..=8).contains(&value) {
                    return Err(GuidanceDecodeError::InvalidValue(kind, value));
                }
                Ok(Self::MaxReversibleBatch { max_actions: value })
            }
            RuleKind::ProviderWorkaround => {
                let v = ProviderWorkaround::from_byte(value)
                    .ok_or(GuidanceDecodeError::InvalidValue(kind, value))?;
                Ok(Self::ProviderWorkaround(v))
            }
        }
    }

    /// Decode from a slice, rejecting wrong lengths and unknown keys. This
    /// is the wire/storage decoder: it rejects any extra bytes (unknown
    /// fields) beyond the exact 3-byte form.
    pub fn from_bytes(buf: &[u8]) -> Result<Self, GuidanceDecodeError> {
        if buf.len() != RULE_ENCODED_LEN {
            return Err(GuidanceDecodeError::BadLength {
                expected: RULE_ENCODED_LEN,
                actual: buf.len(),
            });
        }
        let arr: [u8; RULE_ENCODED_LEN] =
            buf.try_into().map_err(|_| GuidanceDecodeError::BadLength {
                expected: RULE_ENCODED_LEN,
                actual: buf.len(),
            })?;
        Self::decode(&arr)
    }
}

// ---------------------------------------------------------------------------
// Decode errors
// ---------------------------------------------------------------------------

/// Errors encountered when decoding or validating a guidance rule.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GuidanceDecodeError {
    #[error("guidance rule bad schema version: {0}")]
    BadSchemaVersion(u8),
    #[error("guidance rule unknown kind: {0}")]
    UnknownKind(u8),
    #[error("guidance rule invalid value for kind {0:?}: {1}")]
    InvalidValue(RuleKind, u8),
    #[error("guidance rule bad length: expected {expected}, actual {actual}")]
    BadLength { expected: usize, actual: usize },
    #[error("guidance proposal has {0} rules; must be {MIN_RULES}..={MAX_RULES}")]
    RuleCountOutOfRange(usize),
    #[error("guidance proposal has duplicate kind: {0:?}")]
    DuplicateKind(RuleKind),
}

// ---------------------------------------------------------------------------
// Proposal validation (1..=6 unique kinds)
// ---------------------------------------------------------------------------

/// Validate a slice of rules for the proposal constraints: 1..=6 rules,
/// all unique kinds. Returns the `rule_kind_bits` bitmask on success.
pub fn validate_proposal(rules: &[ComputerGuidanceRuleV1]) -> Result<u16, GuidanceDecodeError> {
    if rules.len() < MIN_RULES || rules.len() > MAX_RULES {
        return Err(GuidanceDecodeError::RuleCountOutOfRange(rules.len()));
    }
    let mut bits: u16 = 0;
    for rule in rules {
        let mask = rule.kind().bit_mask();
        if bits & mask != 0 {
            return Err(GuidanceDecodeError::DuplicateKind(rule.kind()));
        }
        bits |= mask;
    }
    Ok(bits)
}

// ---------------------------------------------------------------------------
// Rationale normalization (objective codec)
// ---------------------------------------------------------------------------

/// Errors encountered when validating rationale text.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RationaleError {
    #[error("rationale is not valid UTF-8")]
    InvalidUtf8,
    #[error("rationale contains NUL")]
    Nul,
    #[error("rationale contains disallowed C0/C1 control character: 0x{0:02x}")]
    DisallowedControl(u32),
    #[error("rationale contains Unicode noncharacter: U+{0:04X}")]
    Noncharacter(u32),
    #[error("rationale contains bidi override/isolate control: U+{0:04X}")]
    BidiControl(u32),
    #[error("rationale exceeds {RATIONALE_MAX_SCALARS} Unicode scalar values")]
    TooManyScalars,
    #[error("rationale exceeds {RATIONALE_MAX_BYTES} UTF-8 bytes")]
    TooManyBytes,
}

/// Normalize and validate an optional reviewer rationale.
///
/// The objective codec:
/// 1. Validate UTF-8.
/// 2. Normalize CRLF and CR to LF.
/// 3. Reject NUL, C0/C1 controls other than TAB/LF, Unicode noncharacters,
///    and bidi override/isolate controls.
/// 4. Trim only leading/trailing SP, TAB, and LF.
/// 5. Treat empty as absent (return `None`).
/// 6. Cap at both 512 Unicode scalar values and 2,048 UTF-8 bytes.
///
/// No semantic classifier tries to decide whether text is "safe," personal,
/// page-specific, or secret.
pub fn normalize_rationale(input: &str) -> Result<Option<String>, RationaleError> {
    // Step 1: input is already valid UTF-8 (&str).

    // Step 2: normalize CRLF and CR to LF.
    let normalized: String = input.replace("\r\n", "\n").replace('\r', "\n");

    // Step 3: reject disallowed characters.
    for ch in normalized.chars() {
        let cp = ch as u32;
        if cp == 0x00 {
            return Err(RationaleError::Nul);
        }
        // C0 controls (0x00..=0x1F) except TAB (0x09) and LF (0x0A).
        if (0x01..=0x08).contains(&cp) || (0x0B..=0x0C).contains(&cp) || (0x0E..=0x1F).contains(&cp)
        {
            return Err(RationaleError::DisallowedControl(cp));
        }
        // C1 controls (0x7F..=0x9F). 0x7F is DEL, 0x80..=0x9F are C1.
        if (0x7F..=0x9F).contains(&cp) {
            return Err(RationaleError::DisallowedControl(cp));
        }
        // Unicode noncharacters: U+FDD0..=U+FDEF, U+FFFE, U+FFFF, and
        // U+nFFFE/U+nFFFF for n in 1..=16 (i.e., last two code points of
        // each plane 1..=16).
        if (0xFDD0..=0xFDEF).contains(&cp) || (cp & 0xFFFE) == 0xFFFE {
            return Err(RationaleError::Noncharacter(cp));
        }
        // Bidi override/isolate controls:
        // U+202A..=U+202E (LRE/RLE/PDF/LRO/RLO),
        // U+2066..=U+2069 (LRI/RLI/FSI/PDI).
        if (0x202A..=0x202E).contains(&cp) || (0x2066..=0x2069).contains(&cp) {
            return Err(RationaleError::BidiControl(cp));
        }
    }

    // Step 4: trim only leading/trailing SP, TAB, and LF.
    let trimmed = normalized.trim_matches(|c| c == ' ' || c == '\t' || c == '\n');

    // Step 5: treat empty as absent.
    if trimmed.is_empty() {
        return Ok(None);
    }

    // Step 6: cap at 512 scalar values and 2048 UTF-8 bytes.
    let scalar_count = trimmed.chars().count();
    if scalar_count > RATIONALE_MAX_SCALARS {
        return Err(RationaleError::TooManyScalars);
    }
    let byte_len = trimmed.len();
    if byte_len > RATIONALE_MAX_BYTES {
        return Err(RationaleError::TooManyBytes);
    }

    Ok(Some(trimmed.to_string()))
}

// ---------------------------------------------------------------------------
// Compiler — literal byte lookup, concatenated in discriminant order
// ---------------------------------------------------------------------------

/// The 24 code-owned constant template byte strings, indexed by the closed
/// enum or the eight-entry `max_actions` table. They are not format strings,
/// cannot contain proposal/rationale/provider/model/project/page/tool bytes,
/// and are snapshot-tested byte-for-byte.
///
/// Index layout (matching `compiler_clause_bytes`):
/// - `[0]` = observation_cadence before_each_action
/// - `[1]` = observation_cadence before_consequential_action
/// - `[2]` = observation_cadence after_each_action
/// - `[3]` = observation_cadence after_navigation
/// - `[4]` = pointer_verification before_every_pointer_action
/// - `[5]` = pointer_verification before_consequential_pointer_action
/// - `[6]` = pointer_verification after_pointer_motion
/// - `[7]` = fresh_dossier before_each_action
/// - `[8]` = fresh_dossier before_consequential_action
/// - `[9]` = fresh_dossier after_navigation
/// - `[10]` = unexpected_state_stop any_mismatch
/// - `[11]` = unexpected_state_stop target_or_focus_mismatch
/// - `[12]` = unexpected_state_stop verification_mismatch
/// - `[13]` = max_reversible_batch 1
/// - `[14]` = max_reversible_batch 2
/// - `[15]` = max_reversible_batch 3
/// - `[16]` = max_reversible_batch 4
/// - `[17]` = max_reversible_batch 5
/// - `[18]` = max_reversible_batch 6
/// - `[19]` = max_reversible_batch 7
/// - `[20]` = max_reversible_batch 8
/// - `[21]` = provider_workaround refresh_observation_before_pointer
/// - `[22]` = provider_workaround one_pointer_action_per_observation
/// - `[23]` = provider_workaround verify_after_scroll
pub const COMPILER_TEMPLATES: [&[u8]; 24] = [
    b"Observe immediately before every computer action.",
    b"Observe immediately before every consequential computer action.",
    b"Observe immediately after every computer action.",
    b"Observe immediately after every navigation.",
    b"Verify the pointer target immediately before every pointer action.",
    b"Verify the pointer target immediately before every consequential pointer action.",
    b"Verify the pointer target immediately after every pointer movement.",
    b"Build a fresh transient dossier immediately before every computer action.",
    b"Build a fresh transient dossier immediately before every consequential computer action.",
    b"Build a fresh transient dossier immediately after every navigation.",
    b"Stop when any observed state differs from the expected state.",
    b"Stop when the physical target or focus differs from the expected state.",
    b"Stop when post-action verification differs from the expected state.",
    b"Execute at most one reversible computer action before observing again.",
    b"Execute at most two reversible computer actions before observing again.",
    b"Execute at most three reversible computer actions before observing again.",
    b"Execute at most four reversible computer actions before observing again.",
    b"Execute at most five reversible computer actions before observing again.",
    b"Execute at most six reversible computer actions before observing again.",
    b"Execute at most seven reversible computer actions before observing again.",
    b"Execute at most eight reversible computer actions before observing again.",
    b"Refresh the observation immediately before every pointer action.",
    b"Execute only one pointer action per observation.",
    b"Verify the observed state immediately after every scroll action.",
];

/// The single LF byte used between clauses.
pub const CLAUSE_SEPARATOR: u8 = 0x0A;

/// Map a single rule to its code-owned constant template bytes.
///
/// This is a literal byte lookup selected only by the closed enum or the
/// eight-entry `max_actions` table. It never injects proposal, rationale,
/// provider, model, project, page, or tool bytes.
pub fn compiler_clause_bytes(rule: &ComputerGuidanceRuleV1) -> &'static [u8] {
    match rule {
        ComputerGuidanceRuleV1::ObservationCadence(v) => match v {
            ObservationCadence::BeforeEachAction => COMPILER_TEMPLATES[0],
            ObservationCadence::BeforeConsequentialAction => COMPILER_TEMPLATES[1],
            ObservationCadence::AfterEachAction => COMPILER_TEMPLATES[2],
            ObservationCadence::AfterNavigation => COMPILER_TEMPLATES[3],
        },
        ComputerGuidanceRuleV1::PointerVerification(v) => match v {
            PointerVerification::BeforeEveryPointerAction => COMPILER_TEMPLATES[4],
            PointerVerification::BeforeConsequentialPointerAction => COMPILER_TEMPLATES[5],
            PointerVerification::AfterPointerMotion => COMPILER_TEMPLATES[6],
        },
        ComputerGuidanceRuleV1::FreshDossier(v) => match v {
            FreshDossier::BeforeEachAction => COMPILER_TEMPLATES[7],
            FreshDossier::BeforeConsequentialAction => COMPILER_TEMPLATES[8],
            FreshDossier::AfterNavigation => COMPILER_TEMPLATES[9],
        },
        ComputerGuidanceRuleV1::UnexpectedStateStop(v) => match v {
            UnexpectedStateStop::AnyMismatch => COMPILER_TEMPLATES[10],
            UnexpectedStateStop::TargetOrFocusMismatch => COMPILER_TEMPLATES[11],
            UnexpectedStateStop::VerificationMismatch => COMPILER_TEMPLATES[12],
        },
        ComputerGuidanceRuleV1::MaxReversibleBatch { max_actions } => {
            // max_actions is 1..=8, maps to templates[13..=20].
            let idx = 13 + (*max_actions as usize) - 1;
            COMPILER_TEMPLATES[idx]
        }
        ComputerGuidanceRuleV1::ProviderWorkaround(v) => match v {
            ProviderWorkaround::RefreshObservationBeforePointer => COMPILER_TEMPLATES[21],
            ProviderWorkaround::OnePointerActionPerObservation => COMPILER_TEMPLATES[22],
            ProviderWorkaround::VerifyAfterScroll => COMPILER_TEMPLATES[23],
        },
    }
}

/// Compile a set of rules into the guidance byte string.
///
/// Compilation is a literal byte lookup, concatenated in discriminant order
/// with exactly one LF (`0x0A`) between clauses and no final LF. The
/// compiler emits kinds in fixed code-owned order regardless of input order.
/// No creation order, map iteration order, or free-form conflict resolver
/// participates.
///
/// At composition time a session value replaces a persistent value of the
/// same kind; within one scope a newly accepted value replaces the existing
/// same kind. Distinct kinds form a union. No other precedence, conflict
/// resolver, or merge is permitted.
pub fn compile_guidance(rules: &[ComputerGuidanceRuleV1]) -> Vec<u8> {
    // Deduplicate by kind, keeping the last value for each kind (session
    // overrides persistent; later reviewed acceptance replaces earlier).
    // Then sort by discriminant order.
    let mut by_kind: [Option<ComputerGuidanceRuleV1>; 6] = [None, None, None, None, None, None];
    for rule in rules {
        let idx = rule.kind().bit_index() as usize;
        by_kind[idx] = Some(*rule);
    }

    let mut out = Vec::new();
    let mut first = true;
    for rule in by_kind.iter().flatten() {
        if !first {
            out.push(CLAUSE_SEPARATOR);
        }
        out.extend_from_slice(compiler_clause_bytes(rule));
        first = false;
    }
    out
}

// ---------------------------------------------------------------------------
// Enablement resolution — four-layer sticky-disable resolver
// ---------------------------------------------------------------------------

/// The four applicable layers for `allow_computer_guidance_proposals`.
/// Each layer is `absent | enabled | disabled`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum EnablementValue {
    /// No explicit value at this layer.
    #[default]
    Absent,
    /// Explicitly enabled at this layer.
    Enabled,
    /// Explicitly disabled at this layer (sticky safety veto).
    Disabled,
}

impl EnablementValue {
    pub fn from_bool(b: Option<bool>) -> Self {
        match b {
            None => Self::Absent,
            Some(true) => Self::Enabled,
            Some(false) => Self::Disabled,
        }
    }
}

/// The four applicable layers, in order from broadest to narrowest:
/// global, canonical machine-local project, provider, model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct EnablementLayers {
    /// Global layer.
    pub global: EnablementValue,
    /// Canonical machine-local project layer.
    pub project: EnablementValue,
    /// Provider layer.
    pub provider: EnablementValue,
    /// Model layer.
    pub model: EnablementValue,
}

/// The result of enablement resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnablementResolution {
    /// The effective boolean: with no explicit value the result is disabled;
    /// any explicit enable may opt in only when no applicable layer is
    /// explicitly disabled, and an explicit disable at any layer is a
    /// sticky safety veto that no narrower enable can lift.
    pub enabled: bool,
    /// Every contributing layer/value.
    pub layers: EnablementLayers,
    /// Whether any layer is an explicit disable (the sticky veto).
    pub has_disable_veto: bool,
}

/// Resolve the effective enablement across the four layers.
///
/// Rules:
/// - With no explicit value (all absent) the result is disabled.
/// - Any explicit enable may opt in only when no applicable layer is
///   explicitly disabled.
/// - An explicit disable at any layer is a sticky safety veto that no
///   narrower enable can lift.
pub fn resolve_enablement(layers: &EnablementLayers) -> EnablementResolution {
    let all_layers = [layers.global, layers.project, layers.provider, layers.model];

    // Any explicit disable at any layer is a sticky veto.
    let has_disable_veto = all_layers.contains(&EnablementValue::Disabled);

    // Any explicit enable.
    let has_explicit_enable = all_layers.contains(&EnablementValue::Enabled);

    // All absent → disabled.
    let all_absent = all_layers.iter().all(|l| *l == EnablementValue::Absent);

    let enabled = if all_absent {
        false
    } else if has_disable_veto {
        // Sticky veto: no narrower enable can lift it.
        false
    } else {
        // No disable veto; enabled if any layer explicitly enables.
        has_explicit_enable
    };

    EnablementResolution {
        enabled,
        layers: *layers,
        has_disable_veto,
    }
}

// ---------------------------------------------------------------------------
// Composition — session-over-persistent, fixed-order union
// ---------------------------------------------------------------------------

/// The two scopes for accepted rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RuleScope {
    /// Session scope: keyed by exact `(session, canonical project, provider,
    /// model, rule kind)`. Lives until session end.
    Session,
    /// Persistent scope: keyed by exact `(canonical machine-local project,
    /// provider, model, rule kind)`. Never roams through config
    /// export/sync/import.
    Persistent,
}

/// Compose accepted session and persistent rules into a single compiled
/// guidance byte string.
///
/// At composition time a session value replaces a persistent value of the
/// same kind; distinct kinds form a union. The compiler emits kinds in a
/// fixed code-owned order. No creation order, map iteration order, or
/// free-form conflict resolver participates.
///
/// Rules are keyed by exact `(scope, canonical project, provider, model,
/// rule kind)`; the caller is responsible for ensuring the supplied
/// session and persistent rule sets are already scoped to the same
/// `(canonical project, provider, model)`.
pub fn compose_and_compile(
    session_rules: &[ComputerGuidanceRuleV1],
    persistent_rules: &[ComputerGuidanceRuleV1],
) -> Vec<u8> {
    // Session overrides persistent for the same kind. Distinct kinds form
    // a union. Within each scope, a later value replaces an earlier value
    // of the same kind (the caller passes at most one per kind per scope,
    // but we handle duplicates defensively by last-wins).
    let mut by_kind: [Option<ComputerGuidanceRuleV1>; 6] = [None, None, None, None, None, None];

    // Persistent first, then session overrides.
    for rule in persistent_rules {
        let idx = rule.kind().bit_index() as usize;
        by_kind[idx] = Some(*rule);
    }
    for rule in session_rules {
        let idx = rule.kind().bit_index() as usize;
        by_kind[idx] = Some(*rule);
    }

    let mut out = Vec::new();
    let mut first = true;
    for rule in by_kind.iter().flatten() {
        if !first {
            out.push(CLAUSE_SEPARATOR);
        }
        out.extend_from_slice(compiler_clause_bytes(rule));
        first = false;
    }
    out
}

/// Apply a newly accepted proposal to an existing set of rules in one scope.
///
/// A later user-reviewed acceptance atomically replaces the earlier value
/// for only the rule kinds present in that accepted proposal; omitted kinds
/// remain unchanged. There is exactly one typed value per key.
pub fn apply_accepted(
    existing: &[ComputerGuidanceRuleV1],
    accepted: &[ComputerGuidanceRuleV1],
) -> Vec<ComputerGuidanceRuleV1> {
    let mut by_kind: [Option<ComputerGuidanceRuleV1>; 6] = [None, None, None, None, None, None];
    // Install existing.
    for rule in existing {
        let idx = rule.kind().bit_index() as usize;
        by_kind[idx] = Some(*rule);
    }
    // Replace only the kinds present in the accepted proposal.
    for rule in accepted {
        let idx = rule.kind().bit_index() as usize;
        by_kind[idx] = Some(*rule);
    }
    // Emit in fixed code-owned order.
    by_kind.iter().filter_map(|slot| *slot).collect()
}

// ---------------------------------------------------------------------------
// Consequential predicate — byte-identical to the audit contract
// ---------------------------------------------------------------------------

/// The consequential predicate used by `before_consequential_*` clauses.
///
/// This is code-owned and byte-identical to the audit contract: exactly
/// `pointer_button|pointer_drag|text_entry|key_input|scroll` are
/// consequential; `pointer_move|wait` are not; captures are observations
/// rather than actions.
///
/// This is a thin delegation to `audit::ActionClass::is_consequential` to
/// guarantee byte-identical semantics with the audit chain.
pub fn is_consequential_action(class: ActionClass) -> bool {
    class.is_consequential()
}

#[cfg(test)]
mod tests;
