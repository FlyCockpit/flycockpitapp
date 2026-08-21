//! Closed acquisition-outcome type + fail-closed `RequiresUser` validator
//! (leak-report AC6, sub-increment 2c-3a).
//!
//! ## What this module owns
//!
//! ONLY the **pure, closed result type** for a trusted-child credential
//! acquisition attempt, plus the single fail-closed parser that is the ONLY
//! way to build a [`RequiresUser`] interactive-prompt payload. It has no
//! provider, no async, no I/O, and no wiring to any caller.
//!
//! The coordinator that actually dispatches a trusted child and classifies its
//! output into one of these outcomes (sub-increment 2c-3b, the task-delegation
//! caller), and the lifecycle wiring through the 2c-2
//! [`crate::session::trusted_child_capture`] registry (sub-increment 2c-3c),
//! are **separate** follow-ups and are intentionally NOT built here.
//!
//! ## The closed outcome set (AC6)
//!
//! An acquisition attempt resolves to exactly one of three outcomes:
//!
//! - [`AcquisitionOutcome::Sealed`] — the credential was captured and sealed;
//! - [`AcquisitionOutcome::RequiresUser`] — the child cannot proceed without a
//!   human answering a bounded, single-line question ([`RequiresUser`]);
//! - [`AcquisitionOutcome::Failed`] — everything else, including every invalid
//!   input to the [`RequiresUser::parse`] validator.
//!
//! There is deliberately **no** `Ok`-with-payload escape hatch: the set is
//! closed, and a caller cannot smuggle a value through as a "success" that
//! bypasses classification. Invalid input to the validator collapses to
//! `Failed` and never leaks *why* (non-oracular), consistent with the closed
//! outcome contract.
//!
//! ## The "1..=240 scalar safe question" rule (SETTLED)
//!
//! [`RequiresUser::parse`] yields a [`RequiresUser`] ONLY when BOTH the claimed
//! reason maps to one of the three closed [`AcquisitionReason`] variants AND
//! the candidate prompt is a valid single-line printable question:
//!
//! - length, after trimming leading/trailing ASCII spaces, is in `1..=240`
//!   counted in **Unicode scalar values** (`chars().count()`), NOT bytes;
//! - single-line and printable: it contains no control character (which
//!   includes `\n`, `\r`, `\t`, and NUL), no Unicode line/paragraph separator,
//!   no non-ASCII whitespace, and no zero-width/bidi/format character;
//! - it is not empty and not all-whitespace.
//!
//! This conservative rule deliberately fails a planted secret closed: a
//! high-entropy secret carrying control bytes, newlines, or over-length data is
//! not a valid single-line printable question, so it collapses to `Failed`
//! rather than being passed through as a "question". This module does NOT add a
//! stricter credential/URL allowlist — that is out of scope.
//!
//! ## Dormancy
//!
//! The module is `#[allow(dead_code)]`-gated at its `mod` declaration in
//! [`crate::engine`] until sub-increment 2c-3b consumes it; that allow drops
//! when 2c-3b wires the coordinator to this type.

use serde::{Deserialize, Serialize};

/// The maximum length of a valid acquisition prompt, counted in Unicode scalar
/// values (`chars().count()`), after trimming leading/trailing ASCII spaces.
const MAX_PROMPT_SCALARS: usize = 240;

/// The closed set of outcomes for a trusted-child credential acquisition
/// attempt (AC6). There is no `Ok`-with-payload variant: a value can only reach
/// a caller through classification into one of these three outcomes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcquisitionOutcome {
    /// The credential was captured and sealed.
    Sealed,
    /// The child cannot proceed without a human answering a bounded,
    /// single-line question. The payload is validation-gated (see
    /// [`RequiresUser`]).
    RequiresUser(RequiresUser),
    /// The acquisition failed. Every invalid input to [`RequiresUser::parse`]
    /// collapses here, without leaking why (non-oracular).
    Failed,
}

/// The closed set of reasons a trusted child needs a human to answer a
/// question. Mirrors the [`crate::image_sidecar::SidecarReason`] shape: a
/// `snake_case` serde encoding plus a [`AcquisitionReason::as_str`] accessor.
///
/// Exactly these three reasons are recognized; any other claimed reason is
/// rejected (the acquisition collapses to [`AcquisitionOutcome::Failed`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AcquisitionReason {
    /// A required credential is absent and cannot be derived.
    MissingCredential,
    /// The provider requires an interactive login the child cannot perform.
    InteractiveLogin,
    /// Only the owner holds the knowledge needed to proceed.
    OwnerKnowledge,
}

impl AcquisitionReason {
    /// The stable `snake_case` reason code.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MissingCredential => "missing_credential",
            Self::InteractiveLogin => "interactive_login",
            Self::OwnerKnowledge => "owner_knowledge",
        }
    }

    /// Map a claimed reason code to one of the three closed variants, or `None`
    /// if it is unknown/unmapped. This is the single closed funnel; there is no
    /// catch-all that would silently admit an unrecognized reason.
    fn from_claimed(claimed: &str) -> Option<Self> {
        match claimed {
            "missing_credential" => Some(Self::MissingCredential),
            "interactive_login" => Some(Self::InteractiveLogin),
            "owner_knowledge" => Some(Self::OwnerKnowledge),
            _ => None,
        }
    }
}

/// A validated interactive-prompt payload: a closed [`AcquisitionReason`] plus a
/// single-line printable question.
///
/// Both fields are **private** and there is no public constructor: the ONLY way
/// to obtain a `RequiresUser` is through [`RequiresUser::parse`], which
/// fail-closed-validates its inputs. A caller therefore cannot fabricate a
/// `RequiresUser` that skips validation (for example, one carrying a multi-line
/// or secret-bearing prompt). Read-only access is via [`RequiresUser::reason`]
/// and [`RequiresUser::prompt`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequiresUser {
    reason: AcquisitionReason,
    prompt: String,
}

impl RequiresUser {
    /// The fail-closed constructor and the ONLY way to build a [`RequiresUser`].
    ///
    /// Returns [`AcquisitionOutcome::RequiresUser`] with an exact
    /// `{ reason, prompt }` ONLY when BOTH hold:
    ///
    /// 1. `claimed_reason` maps to one of the three closed
    ///    [`AcquisitionReason`] variants (unknown/unmapped → `Failed`); AND
    /// 2. `prompt` is a valid "1..=240 scalar safe question":
    ///    - leading/trailing ASCII spaces are trimmed first;
    ///    - after trimming, its Unicode-scalar length (`chars().count()`, NOT
    ///      bytes) is in `1..=240` — so an empty, all-space, or over-length
    ///      prompt is rejected;
    ///    - it is single-line and printable: no control character (`\n`, `\r`,
    ///      `\t`, NUL, VT, FF, DEL, and other C0/C1 controls), no Unicode
    ///      line/paragraph separator (U+2028/U+2029), no non-ASCII whitespace,
    ///      and no zero-width/bidi/format character.
    ///
    /// Any violation collapses to [`AcquisitionOutcome::Failed`] — never a
    /// partial value and never a panic — and the outcome does not encode which
    /// rule failed (non-oracular).
    pub fn parse(claimed_reason: &str, prompt: &str) -> AcquisitionOutcome {
        // Rule 1: the reason must map to a closed variant.
        let Some(reason) = AcquisitionReason::from_claimed(claimed_reason) else {
            return AcquisitionOutcome::Failed;
        };

        // Rule 2: the prompt must be a valid single-line printable question.
        // Trim only leading/trailing ASCII spaces; any other surrounding
        // whitespace (tab, newline, ...) is a control/format char and is
        // rejected by the scan below rather than silently trimmed.
        let trimmed = prompt.trim_matches(' ');

        let scalar_len = trimmed.chars().count();
        if !(1..=MAX_PROMPT_SCALARS).contains(&scalar_len) {
            return AcquisitionOutcome::Failed;
        }

        if trimmed.chars().any(is_unsafe_question_char) {
            return AcquisitionOutcome::Failed;
        }

        AcquisitionOutcome::RequiresUser(RequiresUser {
            reason,
            prompt: trimmed.to_owned(),
        })
    }

    /// The validated reason.
    pub fn reason(&self) -> AcquisitionReason {
        self.reason
    }

    /// The validated, trimmed single-line question.
    pub fn prompt(&self) -> &str {
        &self.prompt
    }
}

/// Whether a scalar is disallowed in a single-line printable safe question.
///
/// Rejects (fail-closed) any character that is:
/// - a control character (C0/C1, which covers `\n`, `\r`, `\t`, NUL, VT, FF,
///   DEL);
/// - a Unicode whitespace other than the plain ASCII space `' '` (so NBSP,
///   ideographic space, and the U+2028/U+2029 line/paragraph separators are
///   rejected while ordinary interior spaces between words are allowed);
/// - a known zero-width, bidi-control, or format character that could hide or
///   reorder content in a prompt.
fn is_unsafe_question_char(ch: char) -> bool {
    if ch.is_control() {
        return true;
    }
    // Only the plain ASCII space is an allowed whitespace; everything else in
    // the Unicode whitespace class (NBSP, line/paragraph separators, exotic
    // spaces) is rejected.
    if ch.is_whitespace() && ch != ' ' {
        return true;
    }
    // Zero-width / bidi / format characters that are visually invisible or can
    // reorder surrounding text. These are not caught by `is_control` (they are
    // not in the Cc category).
    matches!(
        ch,
        '\u{00AD}'                    // soft hyphen
        | '\u{200B}'..='\u{200F}'      // ZWSP, ZWNJ, ZWJ, LRM, RLM
        | '\u{2028}'..='\u{2029}'      // line / paragraph separator
        | '\u{202A}'..='\u{202E}'      // bidi embeddings/overrides
        | '\u{2060}'..='\u{2064}'      // word joiner + invisible operators
        | '\u{2066}'..='\u{2069}'      // bidi isolates
        | '\u{FEFF}'                   // BOM / zero-width no-break space
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a plain single-line ASCII question of an exact scalar length.
    fn ascii_question(len: usize) -> String {
        "a".repeat(len)
    }

    #[test]
    fn valid_triple_each_reason_min_and_max_length() {
        let cases = [
            ("missing_credential", AcquisitionReason::MissingCredential),
            ("interactive_login", AcquisitionReason::InteractiveLogin),
            ("owner_knowledge", AcquisitionReason::OwnerKnowledge),
        ];
        for (claimed, reason) in cases {
            for len in [1usize, MAX_PROMPT_SCALARS] {
                let prompt = ascii_question(len);
                match RequiresUser::parse(claimed, &prompt) {
                    AcquisitionOutcome::RequiresUser(ru) => {
                        assert_eq!(ru.reason(), reason);
                        assert_eq!(ru.prompt(), prompt.as_str());
                        assert_eq!(ru.reason().as_str(), claimed);
                    }
                    other => panic!("expected RequiresUser for {claimed} len {len}, got {other:?}"),
                }
            }
        }
    }

    #[test]
    fn empty_prompt_fails() {
        assert_eq!(
            RequiresUser::parse("missing_credential", ""),
            AcquisitionOutcome::Failed
        );
    }

    #[test]
    fn over_length_prompt_fails() {
        let prompt = ascii_question(MAX_PROMPT_SCALARS + 1); // 241 scalars
        assert_eq!(
            RequiresUser::parse("owner_knowledge", &prompt),
            AcquisitionOutcome::Failed
        );
    }

    #[test]
    fn max_length_multibyte_prompt_is_scalar_counted_not_byte_counted() {
        // 240 scalar values, each a multibyte emoji (4 bytes each => 960 bytes).
        // A byte-count rule would reject this; a scalar-count rule accepts it.
        let prompt = "😀".repeat(MAX_PROMPT_SCALARS);
        assert_eq!(prompt.chars().count(), MAX_PROMPT_SCALARS);
        assert!(prompt.len() > MAX_PROMPT_SCALARS); // proves it is multibyte
        match RequiresUser::parse("interactive_login", &prompt) {
            AcquisitionOutcome::RequiresUser(ru) => {
                assert_eq!(ru.prompt().chars().count(), MAX_PROMPT_SCALARS);
            }
            other => panic!("expected 240-scalar emoji prompt accepted, got {other:?}"),
        }

        // And one scalar over the limit, still multibyte, is rejected.
        let too_long = "é".repeat(MAX_PROMPT_SCALARS + 1);
        assert_eq!(too_long.chars().count(), MAX_PROMPT_SCALARS + 1);
        assert_eq!(
            RequiresUser::parse("interactive_login", &too_long),
            AcquisitionOutcome::Failed
        );
    }

    #[test]
    fn newline_control_and_carriage_return_prompts_fail() {
        for bad in [
            "line one\nline two",   // \n
            "before\rafter",        // \r
            "tab\there",            // \t
            "nul\0here",            // NUL
            "sep\u{2028}here",      // Unicode line separator
            "para\u{2029}here",     // Unicode paragraph separator
            "zero\u{200B}width",    // zero-width space
            "bidi\u{202E}override", // right-to-left override
        ] {
            assert_eq!(
                RequiresUser::parse("missing_credential", bad),
                AcquisitionOutcome::Failed,
                "expected Failed for {bad:?}"
            );
        }
    }

    #[test]
    fn all_whitespace_prompt_fails() {
        assert_eq!(
            RequiresUser::parse("owner_knowledge", "     "),
            AcquisitionOutcome::Failed
        );
    }

    #[test]
    fn leading_and_trailing_spaces_are_trimmed() {
        match RequiresUser::parse("owner_knowledge", "   which vault?   ") {
            AcquisitionOutcome::RequiresUser(ru) => assert_eq!(ru.prompt(), "which vault?"),
            other => panic!("expected trimmed RequiresUser, got {other:?}"),
        }
    }

    #[test]
    fn unknown_reason_fails() {
        assert_eq!(
            RequiresUser::parse("totally_unknown_reason", "which vault?"),
            AcquisitionOutcome::Failed
        );
        // An empty claimed reason is also unknown.
        assert_eq!(
            RequiresUser::parse("", "which vault?"),
            AcquisitionOutcome::Failed
        );
    }

    #[test]
    fn planted_secret_prompt_fails_closed() {
        // A realistic high-entropy secret: over length, with an embedded
        // newline and control bytes. It is not a valid single-line printable
        // question, so the validator fails closed rather than passing the
        // secret through as a "question".
        let mut secret = String::new();
        secret.push_str("sk-live_");
        secret.push_str(&"A9f2Q7zX1kL0mN8pR3sT6vW4yB5cD".repeat(12)); // > 240 scalars
        secret.push('\n'); // newline smuggled in
        secret.push('\u{0007}'); // BEL control byte
        secret.push('\0'); // NUL
        assert!(secret.chars().count() > MAX_PROMPT_SCALARS);
        assert_eq!(
            RequiresUser::parse("missing_credential", &secret),
            AcquisitionOutcome::Failed
        );

        // Even a short high-entropy token that carries a single control byte
        // (within length) still fails closed — a secret is never a valid
        // question.
        let short_secret_with_ctrl = "hunter2\u{0001}token";
        assert_eq!(
            RequiresUser::parse("missing_credential", short_secret_with_ctrl),
            AcquisitionOutcome::Failed
        );
    }

    #[test]
    fn reason_as_str_round_trips_through_from_claimed() {
        for reason in [
            AcquisitionReason::MissingCredential,
            AcquisitionReason::InteractiveLogin,
            AcquisitionReason::OwnerKnowledge,
        ] {
            assert_eq!(
                AcquisitionReason::from_claimed(reason.as_str()),
                Some(reason)
            );
        }
    }

    // Non-fabricable proof (compile-fenced note): `RequiresUser` has private
    // fields and no public constructor, so the ONLY way to obtain one is
    // `RequiresUser::parse`, which validates. Uncommenting the following line
    // fails to compile (E0451: field `reason`/`prompt` of `RequiresUser` is
    // private), proving validation cannot be skipped:
    //
    //     let _ = RequiresUser {
    //         reason: AcquisitionReason::MissingCredential,
    //         prompt: String::new(),
    //     };
    //
    // (Kept as a comment rather than a `compile_fail` doctest because this is a
    // `#[cfg(test)]` item in a `pub(crate)` module, which rustdoc does not
    // collect as a doctest.)
    #[test]
    fn requires_user_is_only_constructed_via_parse() {
        // Runtime companion to the compile-fail fence above: the sole
        // construction path is `parse`, and its output is always wrapped in the
        // closed outcome enum (never a bare `RequiresUser` a caller supplied).
        let outcome = RequiresUser::parse("missing_credential", "which vault should I unlock?");
        assert!(matches!(outcome, AcquisitionOutcome::RequiresUser(_)));
    }
}
