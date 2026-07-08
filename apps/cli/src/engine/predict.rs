//! Composer next-message prediction (implementation note).
//!
//! After each agent turn the TUI asks the utility model to predict what
//! the user is likely to type next, and offers the result as grey ghost
//! text in an empty composer. This module owns the *pure* pieces — turn
//! assembly, prompt construction, output bounding — and the one-shot
//! utility-model call that produces a prediction. The ghost-text
//! lifecycle / accept state machine lives on the composer (`src/tui/`);
//! this module never touches the UI.
//!
//! The call is a history-free, one-shot
//! [`Model::text_completion`](crate::engine::model::Model::text_completion)
//! against [`ExtendedConfig::utility_model`], mirroring the auto-titling
//! (§17d) and translation (`translate.rs`) utility-model paths. The
//! assembled prompt is **scrubbed through [`crate::redact::RedactionTable`]
//! before it leaves the process** — redaction is non-bypassable for every
//! outbound prompt (GOALS §7).
//!
//! Token economy (GOALS §10): the model sees only the **last 3 turns**,
//! each turn reduced to the user's input + the agent's final response —
//! no tool calls, no intermediate reasoning. The predicted output is
//! bounded to the mode (`short` ≈ one line; `long` a bounded full
//! response, never unbounded).

use std::time::Duration;

use crate::config::extended::{ExtendedConfig, PredictNextMessage};
use crate::config::providers::ProvidersConfig;
use crate::engine::message::{Message, extract_text, extract_user_text};

/// Timeout for one prediction call. Predictions are best-effort ghost
/// text; if the provider stalls we drop the prediction rather than tie up
/// a task.
pub const PREDICT_CALL_TIMEOUT: Duration = Duration::from_secs(20);

/// Hard character cap on a `short` prediction (one line). Belt-and-braces
/// over the prompt instruction so a misbehaving model can't blow the
/// single-line affordance.
pub const SHORT_MAX_CHARS: usize = 200;

/// Hard character cap on a `long` prediction. Bounds the full proposed
/// response so it never grows unbounded (token economy, GOALS §10).
pub const LONG_MAX_CHARS: usize = 2000;

/// One conversation turn reduced to what the predictor sees: the user's
/// input and the agent's final response. Tool calls and reasoning are
/// excluded by construction — the caller only ever populates these two
/// fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PredictionTurn {
    /// The user's message that opened the turn.
    pub user: String,
    /// The agent's final response text for the turn. Empty when the turn
    /// produced no final text (e.g. a tool-only turn) — still carried so
    /// the pairing with `user` is faithful.
    pub agent: String,
}

/// Number of most-recent turns fed to the predictor (token economy).
pub const PREDICTION_TURN_WINDOW: usize = 3;

/// Reduce a flat list of (user, agent-final-response) turns to the last
/// [`PREDICTION_TURN_WINDOW`] turns. The input is assumed already free of
/// tool calls / reasoning — callers build it from the user + agent-final
/// projections only. Returned oldest-first.
pub fn last_turns(turns: &[PredictionTurn]) -> Vec<PredictionTurn> {
    let start = turns.len().saturating_sub(PREDICTION_TURN_WINDOW);
    turns[start..].to_vec()
}

/// Project the engine's rig-[`Message`] history into [`PredictionTurn`]s —
/// the canonical engine-side turn assembly that mirrors the TUI's
/// `turns_from_history` shape (`src/tui/app/mod.rs`), but reads from the
/// driver's `Vec<Message>` rather than UI `HistoryEntry`s. Plain `User`
/// text opens a turn; the next `Assistant` final text closes it. Tool-call
/// rounds are excluded by construction: a tool-result `User` message
/// projects to empty text (and is skipped), and an `Assistant` message
/// carrying only tool calls contributes no final text. Consecutive user
/// messages (e.g. queued + folded) flatten into the open turn so the turn
/// count stays faithful; multiple agent finalizations in one round fold
/// into one final response. Returned oldest-first; callers pass the result
/// through [`last_turns`] to keep only the window.
pub fn turns_from_messages(history: &[Message]) -> Vec<PredictionTurn> {
    let mut turns: Vec<PredictionTurn> = Vec::new();
    // True when the last pushed turn is still awaiting its agent reply (so a
    // following user message folds rather than opening a new one).
    let mut open = false;
    for msg in history {
        match msg {
            Message::User { content } => {
                let text = extract_user_text(content);
                // Tool-result rounds carry no plain text → not a real user
                // turn; skip without disturbing the open turn's pairing.
                if text.trim().is_empty() {
                    continue;
                }
                if open {
                    if let Some(last) = turns.last_mut() {
                        last.user.push_str("\n\n");
                        last.user.push_str(&text);
                    }
                } else {
                    turns.push(PredictionTurn {
                        user: text,
                        agent: String::new(),
                    });
                    open = true;
                }
            }
            Message::Assistant { content, .. } => {
                let text = extract_text(content);
                // A tool-call-only assistant message produces no final text;
                // it neither opens nor closes a turn.
                if text.trim().is_empty() {
                    continue;
                }
                if let Some(last) = turns.last_mut() {
                    if last.agent.is_empty() {
                        last.agent = text;
                    } else {
                        last.agent.push('\n');
                        last.agent.push_str(&text);
                    }
                    open = false;
                }
            }
            // System messages aren't part of the user/agent turn pairing.
            _ => {}
        }
    }
    turns
}

/// Build the one-shot prediction prompt from the last-3-turns transcript.
/// Names the mode's length bound so the utility model self-limits, fences
/// the transcript so the model treats it as context (not instructions),
/// and asks for ONLY the predicted next user message.
///
/// `mode` must be a non-`off` mode; `off` short-circuits before any prompt
/// is built (no utility call at all).
pub fn build_prediction_prompt(turns: &[PredictionTurn], mode: PredictNextMessage) -> String {
    let length_instruction = match mode {
        PredictNextMessage::Short => {
            "Keep it to a single short line — one sentence or phrase, no line breaks."
        }
        PredictNextMessage::Long => {
            "Write the full message the user would likely send next; it may span multiple \
             lines, but keep it concise — a few short paragraphs at most."
        }
        // Unreachable: the caller gates on `is_enabled()`. Fall back to the
        // short bound rather than panic.
        PredictNextMessage::Off => "Keep it to a single short line.",
    };

    let mut transcript = String::new();
    for turn in turns {
        transcript.push_str("USER: ");
        transcript.push_str(turn.user.trim());
        transcript.push('\n');
        if !turn.agent.trim().is_empty() {
            transcript.push_str("AGENT: ");
            transcript.push_str(turn.agent.trim());
            transcript.push('\n');
        }
    }

    format!(
        "You are predicting the next message a user will type to a coding agent, given the \
         recent conversation. Respond AS the user, in the first person — write the message \
         they would most likely send next. {length_instruction} Return ONLY the predicted \
         message, with no preamble, no quotes, and no explanation.\n\n\
         <conversation>\n{transcript}</conversation>",
    )
}

/// Trim a raw model response to a usable prediction and enforce the mode's
/// bound. Any leading `<think>…</think>` reasoning block is **always**
/// stripped first (via the shared [`crate::engine::think::split_think`]
/// parser), independent of the display/context toggle: a suggested response
/// is text the user would send, where reasoning is never appropriate. This
/// is a no-op for non-reasoning models — `split_think` returns the input
/// unchanged as `body` when no closed `<think>` block is present — so they
/// are byte-for-byte unaffected. Stripping also ensures the Short-mode
/// first-line collapse below sees the answer, not a line from inside the
/// think block. `short` collapses to the first non-empty line and caps at
/// [`SHORT_MAX_CHARS`]; `long` keeps the whole response (trimmed) capped at
/// [`LONG_MAX_CHARS`]. Returns `None` when nothing usable survives (the
/// caller then shows no ghost) — including when the body is empty after
/// stripping a think-only response.
pub fn bound_prediction(raw: &str, mode: PredictNextMessage) -> Option<String> {
    let body = crate::engine::think::split_think(raw).0;
    let trimmed = body.trim();
    if trimmed.is_empty() {
        return None;
    }
    let bounded = match mode {
        PredictNextMessage::Short => {
            // Collapse to the first non-empty line, then char-cap.
            let line = trimmed.lines().find(|l| !l.trim().is_empty())?.trim();
            truncate_chars(line, SHORT_MAX_CHARS)
        }
        PredictNextMessage::Long => truncate_chars(trimmed, LONG_MAX_CHARS),
        PredictNextMessage::Off => return None,
    };
    if bounded.trim().is_empty() {
        None
    } else {
        Some(bounded)
    }
}

/// Truncate `s` to at most `max` characters on a char boundary, trimming
/// any trailing whitespace the cut may expose.
fn truncate_chars(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let truncated: String = s.chars().take(max).collect();
    truncated.trim_end().to_string()
}

/// Issue the prediction call for `turns` under `mode`. Returns the bounded
/// prediction, or `None` on every disabled/degrade path (mode `off`, no
/// utility model, empty transcript, build/send error, timeout, empty or
/// unusable response) so the caller simply shows no ghost text.
///
/// The assembled prompt is scrubbed through the model's non-bypassable
/// redaction chokepoint before the provider round-trip (GOALS §7,
/// `redaction-cover-all-llm-requests.md`); `redactor` is the session's
/// effective table, threaded into the model so the send path scrubs it.
pub async fn predict(
    turns: &[PredictionTurn],
    mode: PredictNextMessage,
    extended: &ExtendedConfig,
    providers: &ProvidersConfig,
    redactor: std::sync::Arc<crate::redact::RedactionTable>,
    trusted_only: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> Option<String> {
    if !mode.is_enabled() {
        return None;
    }
    let window = last_turns(turns);
    // No agent response yet (fresh session) → nothing to predict.
    if window.is_empty() || window.iter().all(|t| t.agent.trim().is_empty()) {
        return None;
    }

    let model_ref = extended.predict_next_message_model_ref()?;
    let model = match crate::engine::model::Model::from_ref_trusted_only(
        providers,
        model_ref,
        redactor,
        trusted_only,
    ) {
        Ok(m) => m,
        Err(e) => {
            tracing::debug!(error = %e, "predict: model build failed; no ghost text");
            return None;
        }
    };

    // The outbound prompt is scrubbed at the model send chokepoint
    // (`text_completion`), so no per-site scrub is needed here.
    let prompt = build_prediction_prompt(&window, mode);

    let response =
        match tokio::time::timeout(PREDICT_CALL_TIMEOUT, model.text_completion(&prompt)).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                tracing::debug!(error = %e, "predict: call failed; no ghost text");
                return None;
            }
            Err(_) => {
                tracing::debug!("predict: call timed out; no ghost text");
                return None;
            }
        };

    // A suggested response is always think-stripped, regardless of the
    // model's display/context toggle — reasoning is never part of a message
    // the user would send. `bound_prediction` strips unconditionally (a
    // no-op for non-reasoning models), so no per-model toggle lookup is
    // needed here.
    bound_prediction(&response, mode)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn turn(user: &str, agent: &str) -> PredictionTurn {
        PredictionTurn {
            user: user.to_string(),
            agent: agent.to_string(),
        }
    }

    #[test]
    fn turns_from_messages_pairs_user_and_agent_skipping_tool_rounds() {
        use rig::OneOrMany;
        use rig::message::{
            AssistantContent, ToolCall, ToolFunction, ToolResult, ToolResultContent, UserContent,
        };

        fn user(text: &str) -> Message {
            Message::user(text)
        }
        fn assistant_text(text: &str) -> Message {
            Message::Assistant {
                id: None,
                content: OneOrMany::one(AssistantContent::text(text)),
            }
        }
        fn assistant_call() -> Message {
            Message::Assistant {
                id: None,
                content: OneOrMany::one(AssistantContent::ToolCall(ToolCall::new(
                    "c1".into(),
                    ToolFunction {
                        name: "bash".into(),
                        arguments: serde_json::json!({}),
                    },
                ))),
            }
        }
        fn tool_result() -> Message {
            Message::User {
                content: OneOrMany::one(UserContent::ToolResult(ToolResult {
                    id: "c1".into(),
                    call_id: None,
                    content: OneOrMany::one(ToolResultContent::text("ran")),
                })),
            }
        }

        // Turn 1: user → tool-call → tool-result → final text.
        // Turn 2: user → final text.
        let history = vec![
            user("add a flag"),
            assistant_call(),
            tool_result(),
            assistant_text("Done, added the flag."),
            user("now test it"),
            assistant_text("Tests pass."),
        ];
        let turns = turns_from_messages(&history);
        assert_eq!(turns.len(), 2, "{turns:?}");
        assert_eq!(turns[0], turn("add a flag", "Done, added the flag."));
        assert_eq!(turns[1], turn("now test it", "Tests pass."));
    }

    #[test]
    fn turns_from_messages_folds_consecutive_user_messages() {
        let history = vec![Message::user("first"), Message::user("second")];
        let turns = turns_from_messages(&history);
        assert_eq!(turns.len(), 1);
        assert_eq!(turns[0].user, "first\n\nsecond");
        assert!(turns[0].agent.is_empty());
    }

    #[test]
    fn last_turns_keeps_only_the_most_recent_three() {
        let turns = vec![
            turn("t1", "a1"),
            turn("t2", "a2"),
            turn("t3", "a3"),
            turn("t4", "a4"),
        ];
        let last = last_turns(&turns);
        assert_eq!(last.len(), 3);
        assert_eq!(last[0], turn("t2", "a2"));
        assert_eq!(last[2], turn("t4", "a4"));
    }

    #[test]
    fn last_turns_handles_fewer_than_window() {
        let turns = vec![turn("only", "resp")];
        assert_eq!(last_turns(&turns), turns);
        assert!(last_turns(&[]).is_empty());
    }

    #[test]
    fn prompt_contains_user_and_agent_text_but_not_tool_noise() {
        // The transcript fed in only ever carries user + agent-final text;
        // this asserts the prompt reflects exactly that and never invents
        // tool/reasoning markers.
        let turns = vec![turn("add a flag", "I added the flag.")];
        let p = build_prediction_prompt(&turns, PredictNextMessage::Short);
        assert!(p.contains("USER: add a flag"), "{p}");
        assert!(p.contains("AGENT: I added the flag."), "{p}");
        assert!(p.contains("single short line"), "{p}");
        // No tool-call / reasoning vocabulary leaks into the prompt body.
        assert!(!p.contains("tool_call"), "{p}");
        assert!(!p.contains("<think>"), "{p}");
    }

    #[test]
    fn prompt_omits_agent_line_when_response_empty() {
        // A tool-only turn (no final text) still pairs faithfully: the
        // USER line is present, the AGENT line is omitted (no empty marker).
        let turns = vec![turn("run the tests", "")];
        let p = build_prediction_prompt(&turns, PredictNextMessage::Long);
        assert!(p.contains("USER: run the tests"), "{p}");
        assert!(!p.contains("AGENT:"), "{p}");
        // Long mode names the multi-line allowance.
        assert!(p.contains("multiple"), "{p}");
    }

    #[test]
    fn bound_short_collapses_to_first_line_and_caps() {
        // Multi-line model output in short mode → first non-empty line.
        let raw = "first line\nsecond line\nthird";
        assert_eq!(
            bound_prediction(raw, PredictNextMessage::Short).as_deref(),
            Some("first line")
        );
        // Over-length single line is char-capped.
        let long = "x".repeat(SHORT_MAX_CHARS + 50);
        let bounded = bound_prediction(&long, PredictNextMessage::Short).unwrap();
        assert!(bounded.chars().count() <= SHORT_MAX_CHARS);
    }

    #[test]
    fn bound_long_keeps_multiline_but_caps_total() {
        let raw = "line one\nline two\nline three";
        assert_eq!(
            bound_prediction(raw, PredictNextMessage::Long).as_deref(),
            Some("line one\nline two\nline three")
        );
        let long = "y".repeat(LONG_MAX_CHARS + 100);
        let bounded = bound_prediction(&long, PredictNextMessage::Long).unwrap();
        assert!(bounded.chars().count() <= LONG_MAX_CHARS);
    }

    #[test]
    fn bound_always_strips_think_block_in_short_mode() {
        // A reasoning model prefixes its predicted message with a think
        // block; only the answer's first line survives as the ghost text.
        // Stripping is unconditional — a suggested response never carries
        // reasoning, regardless of any toggle.
        let raw = "<think>Let me analyze this conversation and pick a reply.</think>\n\n\
                   Sure, go ahead and add those.\nExtra line that short mode drops.";
        assert_eq!(
            bound_prediction(raw, PredictNextMessage::Short).as_deref(),
            Some("Sure, go ahead and add those.")
        );
    }

    #[test]
    fn bound_always_strips_think_block_in_long_mode() {
        // Long mode keeps the full body (minus the think block).
        let raw = "<think>reasoning the model did</think>\nFirst answer line.\nSecond answer line.";
        assert_eq!(
            bound_prediction(raw, PredictNextMessage::Long).as_deref(),
            Some("First answer line.\nSecond answer line.")
        );
    }

    #[test]
    fn bound_returns_none_for_closed_think_only_response() {
        // Model emitted only a closed think block → empty body → no ghost.
        assert_eq!(
            bound_prediction(
                "<think>only reasoning, no answer</think>",
                PredictNextMessage::Short
            ),
            None
        );
        assert_eq!(
            bound_prediction(
                "<think>only reasoning, no answer</think>",
                PredictNextMessage::Long
            ),
            None
        );
    }

    #[test]
    fn bound_keeps_unterminated_think_as_body() {
        // An UNCLOSED `<think>` is no longer reasoning — the whole content
        // stays as body (priority #1: a missing close never swallows text).
        // It therefore survives as ghost text rather than collapsing to None.
        // Short mode takes the first line (the open-tag line here).
        assert_eq!(
            bound_prediction(
                "<think>still thinking, never closed",
                PredictNextMessage::Short
            )
            .as_deref(),
            Some("<think>still thinking, never closed")
        );
        // Unclosed think followed by a real answer keeps everything in long mode.
        let raw = "<think>weighing options\nLet's add the flag.";
        assert_eq!(
            bound_prediction(raw, PredictNextMessage::Long).as_deref(),
            Some(raw)
        );
    }

    #[test]
    fn bound_no_think_block_is_passthrough() {
        // Non-reasoning models (no `<think>` tag) behave exactly as before.
        assert_eq!(
            bound_prediction("plain answer", PredictNextMessage::Short).as_deref(),
            Some("plain answer")
        );
        let raw = "line one\nline two";
        assert_eq!(
            bound_prediction(raw, PredictNextMessage::Long).as_deref(),
            Some("line one\nline two")
        );
    }

    #[test]
    fn bound_returns_none_for_empty_or_whitespace() {
        assert_eq!(bound_prediction("", PredictNextMessage::Short), None);
        assert_eq!(bound_prediction("   \n  ", PredictNextMessage::Short), None);
        assert_eq!(bound_prediction("\n\n", PredictNextMessage::Long), None);
        // `off` never produces a prediction even from non-empty raw.
        assert_eq!(bound_prediction("hi", PredictNextMessage::Off), None);
    }
}
