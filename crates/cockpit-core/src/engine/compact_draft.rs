//! Pure policy for reliable compaction-draft sampling and request fitting.
//!
//! This module deliberately owns no transport or driver state.  Preparation
//! can therefore classify and fit a request before inference without risking
//! a partial compaction commit.

use rig::message::Message;

use super::driver::wire_token_total;

pub(crate) const MIN_CLEAN_BRIEF_CHARS: usize = 500;
pub(crate) const MAX_DRAFT_NODES: usize = 64;
pub(crate) const MAX_WIRE_SAMPLES_PER_NODE: u8 = 2;
const DIAGNOSTIC_LIMIT: usize = 240;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CompactFitRung {
    Verbatim,
    HistorySelected,
    ToolResultTruncated,
    Emergency,
    ChunkedSynthesis,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CompactInputCoverage {
    Full,
    Partial,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CompactDraftSuccess {
    pub brief: String,
    pub fit_rung: CompactFitRung,
    pub input_coverage: CompactInputCoverage,
    pub attempts: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CompactDraftOutcome {
    Success(CompactDraftSuccess),
    Cancelled,
    ContextOverflow { diagnostic: String },
    Deterministic { diagnostic: String },
    TransientExhausted { diagnostic: String },
    Degenerate { non_whitespace_chars: usize },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CompactSampleClass {
    Cancelled,
    ContextOverflow,
    Deterministic,
    Transient,
}

pub(crate) fn is_context_overflow_text(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    [
        "too long for this model",
        "prompt is too long",
        "maximum prompt length",
        "maximum context length",
        "context_length_exceeded",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
        || (lower.contains("current message") && lower.contains("exceeds budget"))
}

/// Cancellation and overflow deliberately take precedence over HTTP status.
pub(crate) fn classify_sample_error(
    cancelled: bool,
    message: &str,
    status: Option<u16>,
    typed_timeout: bool,
) -> CompactSampleClass {
    let lower = message.to_ascii_lowercase();
    if cancelled {
        CompactSampleClass::Cancelled
    } else if is_context_overflow_text(message) {
        CompactSampleClass::ContextOverflow
    } else if [
        "authentication",
        "unauthorized",
        "invalid api key",
        "invalid request",
        "schema validation",
        "malformed request",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
    {
        CompactSampleClass::Deterministic
    } else if typed_timeout || status.is_none() {
        CompactSampleClass::Transient
    } else if matches!(status, Some(408 | 429 | 500..=599)) {
        CompactSampleClass::Transient
    } else {
        CompactSampleClass::Deterministic
    }
}

pub(crate) fn bounded_diagnostic(text: &str) -> String {
    let one_line = text.split_whitespace().collect::<Vec<_>>().join(" ");
    one_line.chars().take(DIAGNOSTIC_LIMIT).collect()
}

pub(crate) fn cleaned_brief_chars(text: &str) -> usize {
    text.chars().filter(|ch| !ch.is_whitespace()).count()
}

pub(crate) fn is_degenerate_brief(text: &str) -> bool {
    cleaned_brief_chars(text) < MIN_CLEAN_BRIEF_CHARS
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CompactRequestBudget {
    pub window: u64,
    pub reserve: u64,
    pub fixed_tokens: u64,
    pub history_tokens: u64,
}

impl CompactRequestBudget {
    pub(crate) fn new(window: u32, system: &str, instruction: &str, history: &[Message]) -> Self {
        let window = u64::from(window);
        let reserve = window.div_ceil(10);
        // Message serialization is the existing wire estimator. Represent the
        // system and final instruction as messages as well, retaining framing.
        let fixed_tokens = wire_token_total(&[
            Message::user(system.to_owned()),
            Message::user(instruction.to_owned()),
        ]);
        Self {
            window,
            reserve,
            fixed_tokens,
            history_tokens: wire_token_total(history),
        }
    }

    pub(crate) fn fits(self) -> bool {
        self.fixed_tokens
            .saturating_add(self.history_tokens)
            .saturating_add(self.reserve)
            <= self.window
    }

    pub(crate) fn history_allowance(self) -> u64 {
        self.window
            .saturating_sub(self.reserve)
            .saturating_sub(self.fixed_tokens)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct FittedCompactHistory {
    pub history: Vec<Message>,
    pub rung: CompactFitRung,
    pub coverage: CompactInputCoverage,
}

pub(crate) fn fit_compact_request(
    history: &[Message],
    system: &str,
    instruction: &str,
    context_window: Option<u32>,
) -> Result<FittedCompactHistory, String> {
    let Some(window) = context_window else {
        return Ok(FittedCompactHistory {
            history: history.to_vec(),
            rung: CompactFitRung::Verbatim,
            coverage: CompactInputCoverage::Full,
        });
    };
    if window == 0 {
        return Err("compact model declares a zero context window".to_string());
    }
    let budget = CompactRequestBudget::new(window, system, instruction, history);
    if budget.fixed_tokens.saturating_add(budget.reserve) >= budget.window {
        return Err("compact model window cannot fit system and draft instructions".to_string());
    }
    if budget.fits() {
        return Ok(FittedCompactHistory {
            history: history.to_vec(),
            rung: CompactFitRung::Verbatim,
            coverage: CompactInputCoverage::Full,
        });
    }
    fit_whole_exchange_suffix(history, budget.history_allowance())
        .ok_or_else(|| "newest complete exchange does not fit the compact model".to_string())
}

/// Select the richest provider-valid whole-exchange suffix that fits.  The
/// exchange definition is shared with post-compaction tail planning, so a
/// split can never begin at a tool result or separate a call from its result
/// run.
pub(crate) fn fit_whole_exchange_suffix(
    history: &[Message],
    allowance: u64,
) -> Option<FittedCompactHistory> {
    let ranges = super::compact::complete_exchange_ranges(history);
    let mut start = ranges.len();
    let mut tokens = 0_u64;
    for (index, range) in ranges.iter().enumerate().rev() {
        let candidate = wire_token_total(&history[range.clone()]);
        if tokens.saturating_add(candidate) > allowance {
            break;
        }
        tokens += candidate;
        start = index;
    }
    if start == ranges.len() {
        return None;
    }
    let first = ranges[start].start;
    Some(FittedCompactHistory {
        history: history[first..].to_vec(),
        rung: if first == 0 {
            CompactFitRung::Verbatim
        } else {
            CompactFitRung::HistorySelected
        },
        coverage: if first == 0 {
            CompactInputCoverage::Full
        } else {
            CompactInputCoverage::Partial
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_overflow_variants_are_narrow_and_case_insensitive() {
        for text in [
            "too long for this model",
            "Prompt is too long",
            "maximum prompt length reached",
            "MAXIMUM CONTEXT LENGTH",
            "code=context_length_exceeded",
            "The current message exceeds budget for the deployment",
        ] {
            assert!(is_context_overflow_text(text), "{text}");
        }
        assert!(!is_context_overflow_text("monthly budget exceeded"));
    }

    #[test]
    fn compact_draft_classification_obeys_precedence() {
        assert_eq!(
            classify_sample_error(true, "HTTP 401", Some(401), false),
            CompactSampleClass::Cancelled
        );
        assert_eq!(
            classify_sample_error(false, "context_length_exceeded", Some(400), false),
            CompactSampleClass::ContextOverflow
        );
        for status in [400, 401] {
            assert_eq!(
                classify_sample_error(false, "rejected", Some(status), false),
                CompactSampleClass::Deterministic
            );
        }
        for text in ["authentication failed", "invalid request schema"] {
            assert_eq!(
                classify_sample_error(false, text, None, false),
                CompactSampleClass::Deterministic
            );
        }
        for status in [408, 429, 500, 503] {
            assert_eq!(
                classify_sample_error(false, "failed", Some(status), false),
                CompactSampleClass::Transient
            );
        }
        assert_eq!(
            classify_sample_error(false, "timeout", None, true),
            CompactSampleClass::Transient
        );
    }

    #[test]
    fn request_budget_includes_fixed_input_and_ten_percent_reserve() {
        let history = vec![Message::user("history")];
        let budget = CompactRequestBudget::new(100, "system", "instruction", &history);
        assert_eq!(budget.reserve, 10);
        assert!(budget.fixed_tokens > 0);
        assert_eq!(budget.history_tokens, wire_token_total(&history));
    }

    #[test]
    fn compact_verbatim_request_accounts_for_system_prompt_instruction_and_headroom() {
        let history = vec![Message::user("h"), Message::assistant("a")];
        let raw_history = wire_token_total(&history);
        let fixed = CompactRequestBudget::new(10_000, "system", "instruction", &history);
        let window = u32::try_from(raw_history + fixed.fixed_tokens + 1).unwrap();
        let fitted = fit_compact_request(&history, "system", "instruction", Some(window));
        assert!(
            fitted.is_err(),
            "the ten-percent reserve must make the otherwise raw-fitting request fail"
        );
        let verbatim = fit_compact_request(&history, "system", "instruction", None).unwrap();
        assert_eq!(verbatim.history, history);
        assert_eq!(verbatim.rung, CompactFitRung::Verbatim);
    }

    #[test]
    fn compact_history_selected_never_orphans_tool_pairs() {
        let history = vec![
            Message::user("old user ".repeat(200)),
            Message::assistant("old answer ".repeat(200)),
            Message::user("new user"),
            Message::assistant("new answer"),
        ];
        let newest_tokens = wire_token_total(&history[2..]);
        let fitted = fit_whole_exchange_suffix(&history, newest_tokens).unwrap();
        assert_eq!(fitted.history, history[2..]);
        assert_eq!(fitted.rung, CompactFitRung::HistorySelected);
        assert_eq!(fitted.coverage, CompactInputCoverage::Partial);
    }

    #[test]
    fn compact_unknown_window_attempts_only_verbatim() {
        let history = vec![Message::user("history")];
        let fitted = fit_compact_request(&history, "system", "instruction", None).unwrap();
        assert_eq!(fitted.history, history);
        assert_eq!(fitted.rung, CompactFitRung::Verbatim);
        assert_eq!(fitted.coverage, CompactInputCoverage::Full);
    }
}
