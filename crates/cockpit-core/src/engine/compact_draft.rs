//! Pure policy for reliable compaction-draft sampling and request fitting.
//!
//! This module deliberately owns no transport or driver state.  Preparation
//! can therefore classify and fit a request before inference without risking
//! a partial compaction commit.

use rig::message::{Message, ToolResultContent, UserContent};

pub(crate) fn wire_token_total(history: &[Message]) -> u64 {
    history
        .iter()
        .map(|message| match serde_json::to_string(message) {
            Ok(serialized) => crate::tokens::count(&serialized) as u64,
            Err(_) => 0,
        })
        .sum()
}

pub(crate) const MIN_CLEAN_BRIEF_CHARS: usize = 500;
pub(crate) const MAX_WIRE_SAMPLES_PER_NODE: u8 = 2;
pub(crate) const MAX_DRAFT_NODES: usize = 64;
pub(crate) const MAX_COMPACTION_WIRE_SAMPLES: usize =
    MAX_DRAFT_NODES * MAX_WIRE_SAMPLES_PER_NODE as usize;
pub(crate) const DIAGNOSTIC_LIMIT: usize = 240;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompactFitRung {
    Verbatim,
    HistorySelected,
    ToolResultTruncated,
    Emergency,
    ChunkedSynthesis,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompactInputCoverage {
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
    } else if typed_timeout || status.is_none() || matches!(status, Some(408 | 429 | 500..=599)) {
        CompactSampleClass::Transient
    } else {
        CompactSampleClass::Deterministic
    }
}

pub(crate) fn bounded_diagnostic(text: &str) -> String {
    let one_line = text.split_whitespace().collect::<Vec<_>>().join(" ");
    one_line.chars().take(DIAGNOSTIC_LIMIT).collect()
}

pub(crate) fn bounded_model_diagnostic(model: &crate::engine::model::Model, text: &str) -> String {
    bounded_diagnostic(&model.scrub_diagnostic(text))
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
        .or_else(|| truncate_newest_exchange_to_fit(history, budget.history_allowance()))
        .or_else(|| emergency_history_to_fit(history, budget.history_allowance()))
        .ok_or_else(|| "newest complete exchange does not fit the compact model".to_string())
}

pub(crate) fn is_real_user_message(message: &Message) -> bool {
    matches!(message, Message::User { content } if content.iter().any(|part| !matches!(part, UserContent::ToolResult(_))))
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
    let fitted = FittedCompactHistory {
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
    };
    super::rehydrate::validate_pairing(&fitted.history).ok()?;
    Some(fitted)
}

/// Strictly reduce a provider-rejected request. This is used only after an
/// actual context-overflow verdict; transient failures stay on the same input.
pub(crate) fn next_smaller_fit(
    source_history: &[Message],
    current_history: &[Message],
    current_rung: CompactFitRung,
) -> Option<FittedCompactHistory> {
    if current_rung == CompactFitRung::Emergency {
        return None;
    }
    let allowance = wire_token_total(current_history).saturating_sub(1);
    // Every rung is derived from the immutable source history. In particular,
    // Emergency must not truncate the omission marker emitted by the previous
    // ToolResultTruncated attempt: that would report bytes omitted from a
    // synthetic marker rather than from the original tool result.
    if current_rung != CompactFitRung::ToolResultTruncated {
        if let Some(selected) =
            fit_whole_exchange_suffix(source_history, allowance).filter(|candidate| {
                wire_token_total(&candidate.history) < wire_token_total(current_history)
            })
        {
            return Some(selected);
        }
    }
    if current_rung != CompactFitRung::ToolResultTruncated {
        if let Some(truncated) =
            truncate_newest_exchange_to_fit(source_history, allowance).filter(|candidate| {
                wire_token_total(&candidate.history) < wire_token_total(current_history)
            })
        {
            return Some(truncated);
        }
    }
    emergency_history_to_fit(source_history, allowance).filter(|candidate| {
        wire_token_total(&candidate.history) < wire_token_total(current_history)
    })
}

fn utf8_prefix(text: &str, byte_cap: usize) -> &str {
    let mut end = byte_cap.min(text.len());
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

fn truncate_tool_payloads(history: &[Message], byte_cap: usize) -> (Vec<Message>, bool) {
    let mut output = history.to_vec();
    let mut changed = false;
    for message in &mut output {
        let Message::User { content } = message else {
            continue;
        };
        for part in content.iter_mut() {
            let UserContent::ToolResult(result) = part else {
                continue;
            };
            for payload in result.content.iter_mut() {
                let ToolResultContent::Text(text) = payload else {
                    continue;
                };
                if text.text.len() <= byte_cap {
                    continue;
                }
                let retained = utf8_prefix(&text.text, byte_cap);
                let omitted = text.text.len().saturating_sub(retained.len());
                text.text = format!(
                    "{retained}\n[compaction omitted {omitted} bytes from this tool result]"
                );
                changed = true;
            }
        }
    }
    (output, changed)
}

/// Fit only the newest complete exchange by shortening tool-result text.
/// Tool IDs, calls, arguments, ordering, and non-text content remain intact.
pub(crate) fn truncate_newest_exchange_to_fit(
    history: &[Message],
    allowance: u64,
) -> Option<FittedCompactHistory> {
    let range = super::compact::complete_exchange_ranges(history).pop()?;
    let exchange = &history[range];
    let max_payload = exchange
        .iter()
        .filter_map(|message| match message {
            Message::User { content } => Some(content),
            _ => None,
        })
        .flat_map(|content| content.iter())
        .filter_map(|part| match part {
            UserContent::ToolResult(result) => Some(&result.content),
            _ => None,
        })
        .flat_map(|content| content.iter())
        .filter_map(|payload| match payload {
            ToolResultContent::Text(text) => Some(text.text.len()),
            _ => None,
        })
        .max()?;

    let mut low = 0_usize;
    let mut high = max_payload;
    let mut best = None;
    while low <= high {
        let mid = low + (high - low) / 2;
        let (candidate, changed) = truncate_tool_payloads(exchange, mid);
        if changed && wire_token_total(&candidate) <= allowance {
            best = Some(candidate);
            low = mid.saturating_add(1);
        } else if mid == 0 {
            break;
        } else {
            high = mid - 1;
        }
    }
    best.and_then(|history| {
        super::rehydrate::validate_pairing(&history).ok()?;
        Some(FittedCompactHistory {
            history,
            rung: CompactFitRung::ToolResultTruncated,
            coverage: CompactInputCoverage::Partial,
        })
    })
}

/// Last-resort provider-valid request retaining the newest real user turn and
/// only its adjacent complete exchange context. Unlike ordinary selection,
/// this rung may shorten eligible tool-result payloads even when later
/// provider-only exchanges exist.
pub(crate) fn emergency_history_to_fit(
    history: &[Message],
    allowance: u64,
) -> Option<FittedCompactHistory> {
    let newest_user = history.iter().rposition(is_real_user_message)?;
    let range = super::compact::complete_exchange_ranges(history)
        .into_iter()
        .find(|range| range.contains(&newest_user))?;
    let exchange = &history[range];
    if wire_token_total(exchange) <= allowance {
        super::rehydrate::validate_pairing(exchange).ok()?;
        return Some(FittedCompactHistory {
            history: exchange.to_vec(),
            rung: CompactFitRung::Emergency,
            coverage: CompactInputCoverage::Partial,
        });
    }
    let max_payload = exchange
        .iter()
        .filter_map(|message| match message {
            Message::User { content } => Some(content),
            _ => None,
        })
        .flat_map(|content| content.iter())
        .filter_map(|part| match part {
            UserContent::ToolResult(result) => Some(&result.content),
            _ => None,
        })
        .flat_map(|content| content.iter())
        .filter_map(|payload| match payload {
            ToolResultContent::Text(text) => Some(text.text.len()),
            _ => None,
        })
        .max()?;
    let mut low = 0;
    let mut high = max_payload;
    let mut best = None;
    while low <= high {
        let mid = low + (high - low) / 2;
        let (candidate, changed) = truncate_tool_payloads(exchange, mid);
        if changed && wire_token_total(&candidate) <= allowance {
            best = Some(candidate);
            low = mid.saturating_add(1);
        } else if mid == 0 {
            break;
        } else {
            high = mid - 1;
        }
    }
    let history = best?;
    super::rehydrate::validate_pairing(&history).ok()?;
    Some(FittedCompactHistory {
        history,
        rung: CompactFitRung::Emergency,
        coverage: CompactInputCoverage::Partial,
    })
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ChunkedSynthesisPlan {
    pub chunks: Vec<Vec<Message>>,
    /// Number of recursive adjacent-merge layers after leaf drafting.
    pub merge_depth: usize,
    /// Leaves, recursive merges, and the final synthesis node.
    pub draft_nodes: usize,
    pub max_wire_samples: usize,
}

/// Partition all exchanges chronologically into provider-valid request-sized
/// leaves, then account for a balanced adjacent merge tree and final synthesis
/// under the fixed quota boundary. No source exchange is silently dropped.
pub(crate) fn plan_chunked_synthesis(
    history: &[Message],
    allowance: u64,
) -> Result<ChunkedSynthesisPlan, String> {
    let ranges = super::compact::complete_exchange_ranges(history);
    if ranges.is_empty() {
        return Err("no complete exchanges available for chunked synthesis".to_string());
    }
    let mut chunks: Vec<Vec<Message>> = Vec::new();
    for range in ranges {
        let exchange = &history[range];
        if wire_token_total(exchange) > allowance {
            return Err(
                "an exchange cannot fit a full-coverage chunk leaf without omitting source bytes"
                    .to_string(),
            );
        }
        let exchange = exchange.to_vec();
        super::rehydrate::validate_pairing(&exchange)
            .map_err(|error| format!("invalid chunk leaf: {error}"))?;
        if let Some(last) = chunks.last_mut() {
            let mut candidate = last.clone();
            candidate.extend(exchange.clone());
            if wire_token_total(&candidate) <= allowance {
                *last = candidate;
                continue;
            }
        }
        chunks.push(exchange);
    }
    let leaves = chunks.len();
    let recursive_merges = leaves.saturating_sub(1);
    let draft_nodes = leaves.saturating_add(recursive_merges).saturating_add(1);
    if draft_nodes > MAX_DRAFT_NODES {
        return Err(format!(
            "chunked synthesis requires {draft_nodes} draft nodes; limit is {MAX_DRAFT_NODES}"
        ));
    }
    let merge_depth = if leaves <= 1 {
        0
    } else {
        usize::BITS as usize - (leaves - 1).leading_zeros() as usize
    };
    Ok(ChunkedSynthesisPlan {
        chunks,
        merge_depth,
        draft_nodes,
        max_wire_samples: draft_nodes * MAX_WIRE_SAMPLES_PER_NODE as usize,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rig::message::{AssistantContent, ToolCall, ToolFunction, ToolResult};

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

    /// AC5: a fitted suffix containing multi-call assistant turns and
    /// multi-result runs must pass the provider-validity predicate.
    #[test]
    fn compact_history_selected_with_multi_call_and_multi_result_passes_pairing() {
        let call_a = Message::Assistant {
            id: None,
            content: vec![
                AssistantContent::ToolCall(ToolCall {
                    id: rig::message::ToolCallId::new_or_mint("call-a"),
                    provider: None,
                    function: ToolFunction {
                        name: "read".into(),
                        arguments: serde_json::json!({"path": "a.txt"}),
                    },
                    signature: None,
                    additional_params: None,
                }),
                AssistantContent::ToolCall(ToolCall {
                    id: rig::message::ToolCallId::new_or_mint("call-b"),
                    provider: None,
                    function: ToolFunction {
                        name: "read".into(),
                        arguments: serde_json::json!({"path": "b.txt"}),
                    },
                    signature: None,
                    additional_params: None,
                }),
            ],
        };
        let results_ab = Message::User {
            content: vec![
                UserContent::ToolResult(ToolResult {
                    call: rig::message::ToolCallId::new_or_mint("call-a"),
                    provider: None,
                    name: "read".into(),
                    content: vec![ToolResultContent::text("content a")],
                }),
                UserContent::ToolResult(ToolResult {
                    call: rig::message::ToolCallId::new_or_mint("call-b"),
                    provider: None,
                    name: "read".into(),
                    content: vec![ToolResultContent::text("content b")],
                }),
            ],
        };
        let history = vec![
            Message::user("old request ".repeat(200)),
            Message::assistant("old answer ".repeat(200)),
            Message::user("new request"),
            call_a,
            results_ab,
            Message::assistant("final answer"),
        ];
        // Fit only the newest exchange (user → assistant with tool calls).
        let newest_tokens = wire_token_total(&history[2..]);
        let fitted = fit_whole_exchange_suffix(&history, newest_tokens).unwrap();
        assert_eq!(fitted.rung, CompactFitRung::HistorySelected);
        // The fitted suffix must pass provider-valid tool pairing.
        crate::engine::rehydrate::validate_pairing(&fitted.history).unwrap();
        // The multi-call assistant turn and its multi-result run are intact.
        let serialized = serde_json::to_string(&fitted.history).unwrap();
        assert!(serialized.contains("call-a"));
        assert!(serialized.contains("call-b"));
        assert!(serialized.contains("content a"));
        assert!(serialized.contains("content b"));
    }

    /// AC5: a split candidate that would begin at a tool-result user
    /// message (without its owning assistant tool call) must be rejected
    /// by the pair-validity predicate — the suffix snaps to a whole
    /// exchange boundary instead.
    #[test]
    fn compact_history_selected_split_at_tool_result_is_rejected() {
        let call = Message::Assistant {
            id: None,
            content: vec![AssistantContent::ToolCall(ToolCall {
                id: rig::message::ToolCallId::new_or_mint("call-x"),
                provider: None,
                function: ToolFunction {
                    name: "bash".into(),
                    arguments: serde_json::json!({"command": "ls"}),
                },
                signature: None,
                additional_params: None,
            })],
        };
        let result = Message::User {
            content: vec![UserContent::ToolResult(ToolResult {
                call: rig::message::ToolCallId::new_or_mint("call-x"),
                provider: None,
                name: "bash".into(),
                content: vec![ToolResultContent::text("file1\nfile2")],
            })],
        };
        let history = vec![
            Message::user("old request ".repeat(200)),
            Message::assistant("old answer ".repeat(200)),
            call,
            result,
            Message::user("newest real request"),
            Message::assistant("newest response"),
        ];
        // An allowance that fits only the last two messages (user + assistant)
        // would tempt a raw split at the tool-result boundary (index 3).
        // The fitter must snap to a whole-exchange boundary instead.
        let last_exchange_tokens = wire_token_total(&history[4..]);
        let fitted = fit_whole_exchange_suffix(&history, last_exchange_tokens).unwrap();
        // The fitted suffix must pass pairing validation.
        crate::engine::rehydrate::validate_pairing(&fitted.history).unwrap();
        // It must not begin at the orphaned tool result.
        assert!(
            !fitted
                .history
                .iter()
                .any(|msg| { serde_json::to_string(msg).unwrap().contains("file1\nfile2") }),
            "a split beginning at an orphaned tool result must be rejected"
        );
    }

    #[test]
    fn compact_unknown_window_attempts_only_verbatim() {
        let history = vec![Message::user("history")];
        let fitted = fit_compact_request(&history, "system", "instruction", None).unwrap();
        assert_eq!(fitted.history, history);
        assert_eq!(fitted.rung, CompactFitRung::Verbatim);
        assert_eq!(fitted.coverage, CompactInputCoverage::Full);
    }

    #[test]
    fn compact_tool_result_truncation_preserves_pair_metadata() {
        let call = Message::Assistant {
            id: None,
            content: vec![AssistantContent::ToolCall(ToolCall {
                id: rig::message::ToolCallId::new_or_mint("call-1"),
                provider: rig::message::ProviderCallId::new("provider-call-1"),
                function: ToolFunction {
                    name: "read".into(),
                    arguments: serde_json::json!({"path": "large.json"}),
                },
                signature: None,
                additional_params: None,
            })],
        };
        let result = Message::User {
            content: vec![UserContent::ToolResult(ToolResult {
                call: rig::message::ToolCallId::new_or_mint("call-1"),
                provider: rig::message::ProviderCallId::new("provider-call-1"),
                name: "read".into(),
                content: vec![ToolResultContent::text("x".repeat(4_000))],
            })],
        };
        let history = vec![Message::user("inspect it"), call.clone(), result];
        let allowance = wire_token_total(&history).saturating_sub(100);
        let fitted = truncate_newest_exchange_to_fit(&history, allowance).unwrap();
        assert_eq!(fitted.rung, CompactFitRung::ToolResultTruncated);
        assert_eq!(fitted.history[1], call);
        let serialized = serde_json::to_string(&fitted.history).unwrap();
        assert!(serialized.contains("compaction omitted"));
        assert!(serialized.contains("call-1"));
        assert!(serialized.contains("provider-call-1"));
        assert!(serialized.contains("large.json"));
    }

    #[test]
    fn provider_overflow_reaches_tool_result_truncation_before_emergency() {
        let history = vec![
            Message::user("inspect it"),
            Message::Assistant {
                id: None,
                content: vec![AssistantContent::ToolCall(ToolCall {
                    id: rig::message::ToolCallId::new_or_mint("call-overflow-ladder"),
                    provider: None,
                    function: ToolFunction {
                        name: "read".into(),
                        arguments: serde_json::json!({"path": "large.json"}),
                    },
                    signature: None,
                    additional_params: None,
                })],
            },
            Message::User {
                content: vec![UserContent::ToolResult(ToolResult {
                    call: rig::message::ToolCallId::new_or_mint("call-overflow-ladder"),
                    provider: None,
                    name: "read".into(),
                    content: vec![ToolResultContent::text("x".repeat(4_000))],
                })],
            },
            Message::assistant("done"),
        ];

        let smaller = next_smaller_fit(&history, &history, CompactFitRung::Verbatim)
            .expect("overflowed single exchange with a tool result can be truncated");
        assert_eq!(smaller.rung, CompactFitRung::ToolResultTruncated);
        assert!(wire_token_total(&smaller.history) < wire_token_total(&history));
        crate::engine::rehydrate::validate_pairing(&smaller.history).unwrap();
    }

    #[test]
    fn provider_overflow_advances_truncated_single_exchange_to_emergency() {
        let history = vec![
            Message::user("inspect it"),
            Message::Assistant {
                id: None,
                content: vec![AssistantContent::ToolCall(ToolCall {
                    id: rig::message::ToolCallId::new_or_mint("call-overflow"),
                    provider: None,
                    function: ToolFunction {
                        name: "read".into(),
                        arguments: serde_json::json!({"path": "large.json"}),
                    },
                    signature: None,
                    additional_params: None,
                })],
            },
            Message::User {
                content: vec![UserContent::ToolResult(ToolResult {
                    call: rig::message::ToolCallId::new_or_mint("call-overflow"),
                    provider: None,
                    name: "read".into(),
                    content: vec![ToolResultContent::text("x".repeat(4_000))],
                })],
            },
            Message::assistant("done"),
        ];
        let truncated = truncate_newest_exchange_to_fit(
            &history,
            wire_token_total(&history).saturating_sub(100),
        )
        .expect("fixture must first reach ToolResultTruncated");
        let emergency = next_smaller_fit(&history, &truncated.history, truncated.rung)
            .expect("provider overflow must advance to Emergency");
        assert_eq!(emergency.rung, CompactFitRung::Emergency);
        assert!(wire_token_total(&emergency.history) < wire_token_total(&truncated.history));
        crate::engine::rehydrate::validate_pairing(&emergency.history).unwrap();
    }

    #[test]
    fn emergency_retruncation_uses_original_tool_result_without_nested_markers() {
        let source = "x".repeat(4_000);
        let history = vec![
            Message::user("inspect it"),
            Message::Assistant {
                id: None,
                content: vec![AssistantContent::ToolCall(ToolCall {
                    id: rig::message::ToolCallId::new_or_mint("call-original-source"),
                    provider: None,
                    function: ToolFunction {
                        name: "read".into(),
                        arguments: serde_json::json!({"path": "large.json"}),
                    },
                    signature: None,
                    additional_params: None,
                })],
            },
            Message::User {
                content: vec![UserContent::ToolResult(ToolResult {
                    call: rig::message::ToolCallId::new_or_mint("call-original-source"),
                    provider: None,
                    name: "read".into(),
                    content: vec![ToolResultContent::text(source.clone())],
                })],
            },
        ];
        let truncated = truncate_newest_exchange_to_fit(
            &history,
            wire_token_total(&history).saturating_sub(100),
        )
        .expect("first rung must truncate the tool result");
        let emergency = next_smaller_fit(&history, &truncated.history, truncated.rung)
            .expect("overflow must derive Emergency from original source");
        let serialized = serde_json::to_string(&emergency.history).unwrap();
        assert_eq!(serialized.matches("compaction omitted").count(), 1);
        assert!(
            !serialized.contains("compaction omitted 0 bytes from this tool result]\\n[compaction"),
            "a fresh Emergency candidate must not shorten a prior omission marker"
        );
        assert!(serialized.contains(&source[..64]));
        crate::engine::rehydrate::validate_pairing(&emergency.history).unwrap();
    }

    #[test]
    fn compact_fitting_keeps_newest_real_user_turn() {
        let history = vec![
            Message::user("old request ".repeat(100)),
            Message::assistant("old response ".repeat(100)),
            Message::user("newest real request"),
            Message::assistant("newest response"),
        ];
        let allowance = wire_token_total(&history[2..]);
        let fitted = fit_whole_exchange_suffix(&history, allowance).unwrap();
        assert!(fitted.history.iter().any(|message| {
            is_real_user_message(message)
                && serde_json::to_string(message)
                    .unwrap()
                    .contains("newest real request")
        }));
    }

    /// AC6: when the newest user message is a tool-result user message (not a
    /// real user turn), fitting must still preserve the newest *real* user
    /// request as the boundary — it must not choose the tool-result user
    /// message as the "newest real user turn".
    #[test]
    fn compact_fitting_keeps_newest_real_user_turn_not_tool_result() {
        let call = Message::Assistant {
            id: None,
            content: vec![AssistantContent::ToolCall(ToolCall {
                id: rig::message::ToolCallId::new_or_mint("call-tr"),
                provider: None,
                function: ToolFunction {
                    name: "bash".into(),
                    arguments: serde_json::json!({"command": "echo hi"}),
                },
                signature: None,
                additional_params: None,
            })],
        };
        let tool_result = Message::User {
            content: vec![UserContent::ToolResult(ToolResult {
                call: rig::message::ToolCallId::new_or_mint("call-tr"),
                provider: None,
                name: "bash".into(),
                content: vec![ToolResultContent::text("hi")],
            })],
        };
        let history = vec![
            Message::user("old request ".repeat(100)),
            Message::assistant("old response ".repeat(100)),
            Message::user("real user request"),
            Message::assistant("intermediate response"),
            call,
            tool_result,
            Message::assistant("tool-based answer"),
        ];
        // The tool-result user message at index 5 is NOT a real user turn.
        // `is_real_user_message` must return false for it.
        assert!(
            !is_real_user_message(&history[5]),
            "a tool-result-only user message is not a real user turn"
        );
        // The real user message at index 2 IS a real user turn.
        assert!(is_real_user_message(&history[2]));

        // Fit a suffix that includes the whole exchange starting from the
        // real user request.  The fitter must retain the real user message,
        // not the tool-result user message as the boundary.
        let suffix_tokens = wire_token_total(&history[2..]);
        let fitted = fit_whole_exchange_suffix(&history, suffix_tokens).unwrap();
        assert!(
            fitted.history.iter().any(|message| {
                is_real_user_message(message)
                    && serde_json::to_string(message)
                        .unwrap()
                        .contains("real user request")
            }),
            "fitting must preserve the newest real user turn, not the tool-result user message"
        );
    }

    #[test]
    fn compact_fitting_ladder_is_monotonic_and_bounded() {
        let history = vec![
            Message::user("old ".repeat(500)),
            Message::assistant("answer ".repeat(500)),
            Message::user("new request"),
            Message::assistant("new response"),
        ];
        let full = wire_token_total(&history);
        let selected = fit_whole_exchange_suffix(&history, full / 2).unwrap();
        assert!(wire_token_total(&selected.history) <= full);
        assert_eq!(selected.rung, CompactFitRung::HistorySelected);
        assert!(fit_compact_request(&history, "system", "instruction", Some(1)).is_err());
    }

    /// AC8: the full ladder (Verbatim → HistorySelected → ToolResultTruncated
    /// → Emergency) is monotonic with tool-call-bearing exchanges.  Each
    /// candidate is no larger than its predecessor, and an impossibly small
    /// known window fails without sending malformed or raw-sliced history.
    #[test]
    fn compact_fitting_ladder_with_tool_calls_is_monotonic_and_bounded() {
        let call = Message::Assistant {
            id: None,
            content: vec![AssistantContent::ToolCall(ToolCall {
                id: rig::message::ToolCallId::new_or_mint("call-ladder"),
                provider: None,
                function: ToolFunction {
                    name: "read".into(),
                    arguments: serde_json::json!({"path": "big.json"}),
                },
                signature: None,
                additional_params: None,
            })],
        };
        let result = Message::User {
            content: vec![UserContent::ToolResult(ToolResult {
                call: rig::message::ToolCallId::new_or_mint("call-ladder"),
                provider: None,
                name: "read".into(),
                content: vec![ToolResultContent::text("x".repeat(2_000))],
            })],
        };
        let history = vec![
            Message::user("old request ".repeat(300)),
            Message::assistant("old answer ".repeat(300)),
            Message::user("real request"),
            call,
            result,
            Message::assistant("response with tool data"),
        ];
        let full = wire_token_total(&history);

        // Verbatim: fits a generous window.
        let generous = fit_compact_request(&history, "s", "i", None).unwrap();
        assert_eq!(generous.rung, CompactFitRung::Verbatim);
        assert_eq!(generous.coverage, CompactInputCoverage::Full);
        assert_eq!(wire_token_total(&generous.history), full);

        // HistorySelected: a window that fits only the newest exchange.
        let newest_exchange = wire_token_total(&history[2..]);
        let selected = fit_compact_request(
            &history,
            "s",
            "i",
            Some(u32::try_from(newest_exchange + 100).unwrap()),
        )
        .unwrap();
        assert_eq!(selected.rung, CompactFitRung::HistorySelected);
        assert!(wire_token_total(&selected.history) <= full);
        // Tool pairing must survive the selection.
        crate::engine::rehydrate::validate_pairing(&selected.history).unwrap();

        // ToolResultTruncated: a window that fits only with truncated payloads.
        let truncated_allowance = newest_exchange / 2;
        let fitted = truncate_newest_exchange_to_fit(&history, truncated_allowance)
            .expect("the fixture must exercise ToolResultTruncated");
        assert_eq!(fitted.rung, CompactFitRung::ToolResultTruncated);
        let truncated_tokens = wire_token_total(&fitted.history);
        assert!(truncated_tokens <= truncated_allowance);
        crate::engine::rehydrate::validate_pairing(&fitted.history).unwrap();
        let serialized = serde_json::to_string(&fitted.history).unwrap();
        assert!(serialized.contains("compaction omitted"));
        assert!(serialized.contains("call-ladder"));
        assert!(serialized.contains("big.json"));

        // Emergency: an even smaller window.
        let newest_range = super::super::compact::complete_exchange_ranges(&history)
            .into_iter()
            .find(|range| range.contains(&2))
            .unwrap();
        let (minimal_emergency, changed) = truncate_tool_payloads(&history[newest_range], 0);
        assert!(changed);
        let emergency_allowance = wire_token_total(&minimal_emergency);
        let fitted = emergency_history_to_fit(&history, emergency_allowance)
            .expect("the fixture must exercise Emergency");
        assert_eq!(fitted.rung, CompactFitRung::Emergency);
        let emergency_tokens = wire_token_total(&fitted.history);
        assert!(emergency_tokens <= emergency_allowance);
        assert!(emergency_tokens <= truncated_tokens);
        crate::engine::rehydrate::validate_pairing(&fitted.history).unwrap();

        // Impossibly small known window fails without mutation.
        assert!(
            fit_compact_request(&history, "s", "i", Some(1)).is_err(),
            "an impossibly small known window must fail"
        );
    }

    #[test]
    fn compact_chunked_synthesis_covers_every_exchange_and_enforces_node_cap() {
        let history = (0..4)
            .flat_map(|index| {
                [
                    Message::user(format!("request-{index} {}", "x".repeat(200))),
                    Message::assistant(format!("response-{index} {}", "y".repeat(200))),
                ]
            })
            .collect::<Vec<_>>();
        let one_exchange = wire_token_total(&history[..2]);
        let plan = plan_chunked_synthesis(&history, one_exchange).unwrap();
        assert_eq!(plan.chunks.len(), 4);
        assert_eq!(plan.draft_nodes, 8);
        assert_eq!(
            plan.max_wire_samples,
            plan.draft_nodes * MAX_WIRE_SAMPLES_PER_NODE as usize
        );
        let flattened = plan.chunks.into_iter().flatten().collect::<Vec<_>>();
        assert_eq!(flattened, history);

        let oversized = (0..33)
            .flat_map(|index| {
                [
                    Message::user(format!("request-{index} {}", "x".repeat(200))),
                    Message::assistant(format!("response-{index} {}", "y".repeat(200))),
                ]
            })
            .collect::<Vec<_>>();
        assert!(plan_chunked_synthesis(&oversized, one_exchange).is_err());
    }

    #[test]
    fn compact_chunk_leaf_never_promotes_truncated_source_to_full_coverage() {
        let call = Message::Assistant {
            id: None,
            content: vec![AssistantContent::ToolCall(ToolCall {
                id: rig::message::ToolCallId::new_or_mint("call-large"),
                provider: rig::message::ProviderCallId::new("provider-large"),
                function: ToolFunction {
                    name: "read".into(),
                    arguments: serde_json::json!({"path": "large.json"}),
                },
                signature: None,
                additional_params: None,
            })],
        };
        let result = Message::User {
            content: vec![UserContent::ToolResult(ToolResult {
                call: rig::message::ToolCallId::new_or_mint("call-large"),
                provider: rig::message::ProviderCallId::new("provider-large"),
                name: "read".into(),
                content: vec![ToolResultContent::text("x".repeat(20_000))],
            })],
        };
        let history = vec![Message::user("inspect"), call, result];
        let truncated = truncate_newest_exchange_to_fit(
            &history,
            wire_token_total(&history).saturating_sub(100),
        )
        .expect("the partial ladder may truncate an intermediate input");
        assert_eq!(truncated.coverage, CompactInputCoverage::Partial);
        assert!(
            plan_chunked_synthesis(&history, wire_token_total(&truncated.history)).is_err(),
            "full-coverage synthesis must fail instead of relabeling omitted bytes as full"
        );
    }

    #[test]
    fn compact_diagnostic_is_bounded_to_240_chars_and_collapses_whitespace() {
        // A long multi-line diagnostic must be collapsed to one line and
        // truncated at exactly the 240-char diagnostic limit.
        let long = format!("{} ", "word".repeat(200));
        let bounded = bounded_diagnostic(&long);
        assert!(
            bounded.chars().count() <= DIAGNOSTIC_LIMIT,
            "bounded diagnostic must not exceed {} chars, got {}",
            DIAGNOSTIC_LIMIT,
            bounded.chars().count()
        );
        assert_eq!(bounded.chars().count(), DIAGNOSTIC_LIMIT);
        assert!(
            !bounded.contains('\n'),
            "bounded diagnostic must collapse whitespace to a single line"
        );

        // A short diagnostic passes through unchanged (modulo whitespace
        // normalization).
        let short = "compact model returned an error";
        assert_eq!(bounded_diagnostic(short), short);

        // A diagnostic with extra whitespace is normalized.
        let messy = "  compact   model\n\n  returned   an  error  ";
        assert_eq!(bounded_diagnostic(messy), "compact model returned an error");
    }

    #[test]
    fn compact_diagnostic_preserves_utf8_boundary_on_truncation() {
        // 240 ASCII chars + multi-byte UTF-8: the truncation must not split
        // a UTF-8 code point.  Using chars().take() naturally respects char
        // boundaries, so the result is always valid UTF-8.
        let mut input = String::from("x".repeat(DIAGNOSTIC_LIMIT));
        input.push_str("héllo wörld ☃ ");
        let bounded = bounded_diagnostic(&input);
        assert!(bounded.chars().count() <= DIAGNOSTIC_LIMIT);
        // The result must be valid UTF-8 (String guarantees this, but verify
        // the boundary case did not panic or produce mojibake).
        assert!(bounded.starts_with(&"x".repeat(DIAGNOSTIC_LIMIT)));
    }
}
