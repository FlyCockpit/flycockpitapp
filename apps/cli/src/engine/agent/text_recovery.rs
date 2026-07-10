use super::*;

/// One-line italic disclosure prepended to the promoted text when the
/// reasoning-channel rescue fires (implementation note).
/// Markdown-italic so the existing renderer sets it off; kept to one short
/// sentence (token economy, GOALS §10).
const REASONING_RESCUE_CHIP: &str =
    "*(Model put its answer in the reasoning channel — surfacing it here.)*";

/// Whether the reasoning-channel rescue should fire for an assistant turn
/// (implementation note). All four conditions must
/// hold: (1) `is_root` and (2) `calls_empty` together are the terminal,
/// user-facing boundary — control returns to the user with this turn as the
/// visible message (a subagent turn returns to its parent, a tool-call turn is
/// the model acting, not answering); (3) `text` is empty/whitespace-only after
/// trimming; (4) `reasoning` carries ≥1 non-whitespace char. Pure so the
/// trigger matrix is unit-tested directly.
pub(super) fn reasoning_channel_rescue(
    is_root: bool,
    calls_empty: bool,
    text: &str,
    reasoning: &str,
) -> bool {
    is_root && calls_empty && text.trim().is_empty() && !reasoning.trim().is_empty()
}

/// Build the promoted, user-visible text from the verbatim reasoning: the
/// one-line italic chip, a blank line, then the reasoning unmodified (no
/// truncation, no stripping). This single string is what BOTH the user sees
/// and the model reads back in its own wire history (GOALS §14 — one version).
pub(super) fn promote_reasoning(reasoning: &str) -> String {
    format!("{REASONING_RESCUE_CHIP}\n\n{reasoning}")
}

pub(super) fn should_attempt_text_recovery(calls_empty: bool, reasoning_rescue: bool) -> bool {
    calls_empty && !reasoning_rescue
}

/// Harmony / ChatML special tokens a local chat-template parser bleeds into
/// assistant `text` (implementation note). Both
/// `<|x>` and `<|x|>` shapes — different fine-tunes emit one or the other.
/// Exact byte-string match; extend here if new templates surface.
const HARMONY_TOKENS: &[&str] = &[
    "<|channel>",
    "<|channel|>",
    "<|im_start>",
    "<|im_start|>",
    "<|im_end>",
    "<|im_end|>",
    "<|start>",
    "<|start|>",
    "<|end>",
    "<|end|>",
    "<|message>",
    "<|message|>",
    "<|return>",
    "<|return|>",
    "<|assistant>",
    "<|assistant|>",
    "<|system>",
    "<|system|>",
    "<|user>",
    "<|user|>",
];

/// The `data.recovery.stage` recorded when the Harmony sanitizer fires.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum HarmonyStrip {
    /// `text` was nothing but a leading special token (+ optional whitespace).
    WholePayload,
    /// A leading special token was stripped but real content followed it.
    LeadingMarker,
}

impl HarmonyStrip {
    pub(super) fn stage(self) -> &'static str {
        match self {
            HarmonyStrip::WholePayload => "whole_payload",
            HarmonyStrip::LeadingMarker => "leading_marker",
        }
    }
}

/// Conservatively strip a leading Harmony / ChatML special-token bleed artifact
/// from assistant `text` (implementation note). Returns
/// `Some((stripped, stage))` when a strip happened, `None` when `text` is left
/// untouched. Only an UNAMBIGUOUS parser-bleed artifact is stripped — a token
/// inside a fenced or inline code span, or anywhere other than position 0, is
/// preserved so prose/code that legitimately cites the token is never corrupted.
pub(super) fn sanitize_harmony_tokens(text: &str) -> Option<(String, HarmonyStrip)> {
    // Code-span exemption: if `text` opens a fenced block (```` ``` ````) or an
    // inline code span (`` ` ``), the leading token (if any) is quoted content,
    // not a bleed artifact — suppress entirely.
    let lead = text.trim_start();
    if lead.starts_with("```") || lead.starts_with('`') {
        return None;
    }

    // Rule 1 — whole-payload: `text` trims to exactly one registry token.
    let trimmed = text.trim();
    if HARMONY_TOKENS.contains(&trimmed) {
        return Some((String::new(), HarmonyStrip::WholePayload));
    }

    // Rules 2 & 3 — leading marker at byte 0. The longest matching token wins
    // (e.g. `<|channel|>` before `<|channel>`) so the trailing pipe isn't left
    // behind as stray content.
    let token = HARMONY_TOKENS
        .iter()
        .filter(|t| text.starts_with(**t))
        .max_by_key(|t| t.len())?;
    let rest = &text[token.len()..];
    if rest.trim().is_empty() {
        // Rule 2 — token followed by only whitespace to EOF.
        Some((String::new(), HarmonyStrip::WholePayload))
    } else {
        // Rule 3 — token + whitespace prefix + more content: drop the token and
        // the whitespace run that separates it from the surviving content.
        Some((rest.trim_start().to_string(), HarmonyStrip::LeadingMarker))
    }
}

// ---- text-embedded tool-call recovery (implementation note) ---

/// A synthesized tool call recovered from a text-embedded block, plus the
/// §14 wire-vs-user split metadata the dispatch loop records for it. The
/// loop dispatches `call` exactly as if it had arrived structured (validate-
/// then-repair + permission gate + execution); the `marker` overrides the
/// row's recorded recovery to [`Recovery::TextEmbedded`] and `original_text`
/// stands in for `original_input` so the user timeline shows the model's
/// text block with the recovery chip.
pub(super) struct RecoveredTextCall {
    /// The synthesized structured call (fresh id, name already fuzzy-repaired
    /// to a real advertised tool, args lifted from the extracted block). Both
    /// pushed into `calls` and injected into the just-stored assistant message
    /// so the provider sees a real tool_use that pairs with its tool_result.
    pub(super) call: ToolCall,
    /// The recovery marker recorded for this call's audit row + chip.
    pub(super) marker: Recovery,
}

/// The decision the recovery pipeline reaches for an assistant turn whose
/// structured `tool_calls` field came back empty
/// (implementation note). Computed once, after the structural
/// gate + format normalization + fuzzy name-repair, and acted on by the agent
/// loop.
pub(super) enum TextRecoveryDecision {
    /// Not a recovery candidate (mode `off`, the structural gate rejected it,
    /// the block wasn't tool-shaped, or — in `available` mode — the name didn't
    /// resolve and we instead nudge). The turn proceeds as today.
    None,
    /// A real advertised tool was resolved: dispatch the synthesized call.
    Recovered(RecoveredTextCall),
    /// `available` mode, the named tool does not resolve: surface the block to
    /// the user with a yellow warning chip and inject a model-side correction
    /// nudge for the next turn. Not executed, not a hard failure. `unknown` is
    /// the post-name-repair name; `available_tools` is the advertised set for
    /// the nudge text.
    UnknownAvailable {
        unknown: String,
        available_tools: Vec<String>,
    },
    /// `strict` mode, the named tool does not resolve: feed an
    /// `unknown tool X` tool_result back to the model, keeping it in the tool
    /// loop. The synthesized `call` is injected into history so the result
    /// pairs; `unknown` is the post-name-repair name.
    UnknownStrict { call: ToolCall, unknown: String },
}

/// The subagent names the `task` tool advertises (its `agent` enum) — the
/// authoritative "is this a known subagent" set for the gemma `"agent"`-keyed
/// recovery shape. Empty when the toolbox holds no `task` tool.
fn task_subagent_names(tools: &ToolBox) -> Vec<String> {
    let Some(task) = tools.get("task") else {
        return Vec::new();
    };
    task.parameters()
        .get("properties")
        .and_then(|p| p.get("payload"))
        .and_then(|d| d.get("properties"))
        .and_then(|p| p.get("agent"))
        .and_then(|a| a.get("enum"))
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// Lift the extracted block's raw args into a tool-call `arguments` object.
/// `raw_args` is always an object (possibly empty) from
/// [`crate::engine::text_call::extract_candidate`]; a non-object defensively
/// becomes `{}` so the synthesized call always has object arguments for the
/// §12 validate-then-repair pass.
fn lift_raw_args(raw_args: Value) -> Value {
    match raw_args {
        obj @ Value::Object(_) => obj,
        _ => Value::Object(serde_json::Map::new()),
    }
}

/// Run the text-embedded-recovery pipeline over the assistant `text` for an
/// empty-structured-`tool_calls` turn (implementation note).
///
/// Pipeline: structural gate + format normalization
/// ([`crate::engine::text_call::extract_candidate`]) → **fuzzy name-repair**
/// ([`repair::repair_tool_name`]) → existence check, branched on `mode`. The
/// `agent_keyed` shape's candidate is mapped to `task(agent=…)` when it names a
/// known subagent, dispatched directly when it names a known tool. The returned
/// [`RecoveredTextCall`]/[`TextRecoveryDecision::UnknownStrict`] carry a `call`
/// whose `id` the caller injects into the just-stored assistant message so the
/// provider sees a paired tool_use.
pub(super) fn decide_text_recovery(
    tools: &ToolBox,
    text: &str,
    mode: crate::config::extended::TextEmbeddedRecovery,
) -> TextRecoveryDecision {
    use crate::config::extended::TextEmbeddedRecovery as Mode;
    use crate::engine::text_call::{Convention, extract_candidate};

    if matches!(mode, Mode::Off) {
        return TextRecoveryDecision::None;
    }
    let Some(extracted) = extract_candidate(text) else {
        return TextRecoveryDecision::None;
    };

    let known: Vec<&str> = tools.names();
    let subagents = task_subagent_names(tools);

    // The gemma `"agent"`-keyed shape conflates `task` and a bare tool: if the
    // value names a known subagent, the tool is `task` and the value becomes
    // `arguments.agent`; otherwise it is treated as a tool name like the OpenAI
    // shape. Resolve that mapping FIRST, then fuzzy name-repair the resulting
    // tool name, then branch on existence (repair-before-existence, settled).
    let (mut tool_name, mut args) = match extracted.convention {
        Convention::AgentKeyed => {
            let lifted = lift_raw_args(extracted.raw_args.clone());
            if subagents.iter().any(|s| s == &extracted.candidate_name) {
                // Known subagent → a `task` delegation; the value is the agent.
                let mut map = match lifted {
                    Value::Object(m) => m,
                    _ => serde_json::Map::new(),
                };
                map.insert(
                    "agent".to_string(),
                    Value::String(extracted.candidate_name.clone()),
                );
                ("task".to_string(), Value::Object(map))
            } else {
                // Otherwise the value is itself the tool name.
                (extracted.candidate_name.clone(), lifted)
            }
        }
        Convention::OpenAI => (
            extracted.candidate_name.clone(),
            lift_raw_args(extracted.raw_args.clone()),
        ),
    };

    // Fuzzy name-repair BEFORE the existence check (a salvageable typo like
    // `read_file`→`read` must not bail to the user). `repair_tool_name` only
    // rebinds on an exact match after deterministic transforms — never a fuzzy
    // guess — so it can't invent a tool the model didn't mean.
    let name_repair = repair::repair_tool_name(&tool_name, &known);
    tool_name = name_repair.name;

    // Structural tools (`task`/`schedule`/`handoff`/`spawn`/`done`/`return`) are
    // registered in the toolbox, so `known.contains` resolves them too and they
    // route through their special-cases in the dispatch loop.
    let resolves = known.contains(&tool_name.as_str());

    if !resolves {
        return match mode {
            Mode::Available => TextRecoveryDecision::UnknownAvailable {
                unknown: tool_name,
                available_tools: known.iter().map(|s| s.to_string()).collect(),
            },
            Mode::Strict => {
                // Build a synthesized call that names the unknown tool so the
                // dispatch loop produces the standard `unknown tool` failure and
                // feeds it back as the tool_result, keeping the model in the
                // loop. We pre-build the call here (with a fresh id) so the
                // caller can inject it into the assistant message for pairing.
                let unknown = tool_name.clone();
                let call = synth_tool_call(&tool_name, args);
                TextRecoveryDecision::UnknownStrict { call, unknown }
            }
            // Handled above.
            Mode::Off => TextRecoveryDecision::None,
        };
    }

    // Resolved: synthesize the structured call. `args` is the lifted raw args;
    // the dispatch loop runs the §12 validate-then-repair + permission gate over
    // it exactly as for a structured call (no bypass).
    let call = synth_tool_call(&tool_name, std::mem::take(&mut args));
    let marker = Recovery::TextEmbedded {
        stage: extracted.convention.stage(),
        original: text.to_string(),
        dropped_trailing: extracted.dropped_trailing,
    };
    TextRecoveryDecision::Recovered(RecoveredTextCall { call, marker })
}

/// Build a synthesized [`ToolCall`] for a recovered text-embedded call. A fresh
/// `id` (with a `text-` prefix so it's distinguishable in traces) pairs the
/// injected assistant tool_use with its tool_result; `call_id` is `None` (the
/// recovered call has no provider-issued function-call id).
fn synth_tool_call(name: &str, arguments: Value) -> ToolCall {
    use rig::message::ToolFunction;
    ToolCall {
        id: format!("text-{}", Uuid::new_v4()),
        call_id: None,
        function: ToolFunction {
            name: name.to_string(),
            arguments,
        },
        signature: None,
        additional_params: None,
    }
}

/// Append a tool call to the most recent assistant message in `history` so the
/// provider sees a real tool_use that pairs with the tool_result the dispatch
/// loop pushes for a recovered text-embedded call. Walks backward to the last
/// assistant turn (the one just stored this turn) and pushes `tc` onto its
/// content. Silent no-op if there is no assistant message (defensive — the
/// recovery path only runs when `text` is non-empty, so one was stored).
pub(super) fn append_tool_call_to_last_assistant(history: &mut [Message], tc: &ToolCall) {
    use rig::message::AssistantContent;
    for msg in history.iter_mut().rev() {
        if let Message::Assistant { content, .. } = msg {
            content.push(AssistantContent::ToolCall(tc.clone()));
            return;
        }
    }
}

/// The model-side correction nudge injected after an `available`-mode
/// unrecovered text call (implementation note): tell the model
/// its previous output named an unknown tool and list the tools it can call, so
/// it self-corrects instead of looping. Terse (token economy §10); the
/// available-tool list is truncated to keep it bounded.
pub(super) fn unknown_tool_nudge(unknown: &str, available: &[String]) -> String {
    const MAX_LISTED: usize = 40;
    let listed: Vec<&str> = available
        .iter()
        .take(MAX_LISTED)
        .map(String::as_str)
        .collect();
    let mut list = listed.join(", ");
    if available.len() > MAX_LISTED {
        list.push_str(", …");
    }
    format!(
        "Your previous message looked like a tool call to `{unknown}`, which is not an available tool. Available tools: {list}. Re-emit the call using one of these, in the structured tool-call format."
    )
}

#[cfg(test)]
mod reasoning_rescue_tests {
    use super::*;

    /// Fires: terminal user-facing turn (`is_root`, no tool calls), empty
    /// `text`, non-empty `reasoning`. The promoted text leads with the chip and
    /// carries the reasoning verbatim, and is the single version recorded.
    #[test]
    fn fires_on_empty_text_nonempty_reasoning_no_tool_call() {
        assert!(reasoning_channel_rescue(true, true, "", "answer goes here"));
        let promoted = promote_reasoning("answer goes here");
        assert!(promoted.starts_with(REASONING_RESCUE_CHIP));
        assert!(promoted.ends_with("answer goes here"));
        // Reasoning is surfaced verbatim — no truncation/stripping.
        assert!(promoted.contains("answer goes here"));
    }

    /// Does not fire: a tool call is present (active turn — `calls_empty` is
    /// false), even with whitespace-only `text` and non-empty `reasoning`.
    #[test]
    fn does_not_fire_with_tool_call() {
        assert!(!reasoning_channel_rescue(true, false, " ", "x"));
    }

    /// Does not fire: `text` is already populated (the normal answering case),
    /// regardless of any reasoning alongside it.
    #[test]
    fn does_not_fire_when_text_present() {
        assert!(!reasoning_channel_rescue(true, true, "hello", "thinking"));
    }

    /// Does not fire: `reasoning` is whitespace-only — nothing to surface.
    #[test]
    fn does_not_fire_on_whitespace_only_reasoning() {
        assert!(!reasoning_channel_rescue(true, true, "", "   "));
    }

    /// Does not fire on a non-root (subagent) terminal turn: the turn returns
    /// to the parent, not the user — the user-facing boundary is not crossed.
    #[test]
    fn does_not_fire_on_non_root_turn() {
        assert!(!reasoning_channel_rescue(
            false,
            true,
            "",
            "answer goes here"
        ));
    }

    /// Does not reinterpret rescued reasoning as executable embedded tool-call text.
    #[test]
    fn promoted_tool_shaped_reasoning_skips_text_recovery() {
        use crate::config::extended::TextEmbeddedRecovery as Mode;

        let tools =
            crate::engine::tool::ToolBox::new().with(Arc::new(crate::tools::bash::BashTool::new()));
        let reasoning = r#"{"name":"bash","arguments":{"command":"echo should-not-run"}}"#;
        assert!(matches!(
            decide_text_recovery(&tools, reasoning, Mode::Available),
            TextRecoveryDecision::Recovered(_)
        ));

        let promoted = promote_reasoning(reasoning);
        let decision = if should_attempt_text_recovery(true, true) {
            decide_text_recovery(&tools, &promoted, Mode::Available)
        } else {
            TextRecoveryDecision::None
        };
        assert!(matches!(decision, TextRecoveryDecision::None));
    }
}

#[cfg(test)]
mod harmony_sanitizer_tests {
    use super::*;

    /// Rule 1 — whole payload is a bare special token: stripped to `""`,
    /// recorded as `whole_payload`.
    #[test]
    fn whole_payload_bare_token_strips_to_empty() {
        let (out, stage) = sanitize_harmony_tokens("<|channel>").expect("should strip");
        assert_eq!(out, "");
        assert_eq!(stage, HarmonyStrip::WholePayload);
        assert_eq!(stage.stage(), "whole_payload");
    }

    /// Rule 2 — leading token followed by only whitespace to EOF: stripped to
    /// `""`. Same outcome as rule 1, recorded as `whole_payload`.
    #[test]
    fn leading_token_empty_tail_strips_to_empty() {
        let (out, stage) = sanitize_harmony_tokens("<|im_start>\n").expect("should strip");
        assert_eq!(out, "");
        assert_eq!(stage, HarmonyStrip::WholePayload);
    }

    /// Rule 3 — leading token + whitespace + real content: strip the token and
    /// the whitespace prefix, keep the rest. Recorded as `leading_marker`.
    #[test]
    fn leading_token_with_content_keeps_tail() {
        let (out, stage) =
            sanitize_harmony_tokens("<|channel>\nHere is my answer.").expect("should strip");
        assert_eq!(out, "Here is my answer.");
        assert_eq!(stage, HarmonyStrip::LeadingMarker);
        assert_eq!(stage.stage(), "leading_marker");
    }

    /// The `<|x|>` shape (trailing pipe) strips fully — the longest matching
    /// token wins so no stray `>` is left behind.
    #[test]
    fn trailing_pipe_shape_strips_fully() {
        let (out, _) = sanitize_harmony_tokens("<|channel|>").expect("should strip");
        assert_eq!(out, "");
    }

    /// Non-fire: the token is cited mid-sentence (not at position 0) — prose
    /// discussing Harmony format must be untouched.
    #[test]
    fn token_in_prose_is_untouched() {
        assert!(sanitize_harmony_tokens("The <|channel> token marks the boundary.").is_none());
    }

    /// Non-fire: a fenced code block opening with a triple-backtick suppresses
    /// the strip even though a token sits inside the fence.
    #[test]
    fn token_in_fenced_code_block_is_untouched() {
        assert!(sanitize_harmony_tokens("```\n<|channel>\n```").is_none());
    }

    /// Non-fire: an inline code span opening with a backtick suppresses the
    /// strip.
    #[test]
    fn token_in_inline_code_span_is_untouched() {
        assert!(sanitize_harmony_tokens("`<|channel>` is a marker").is_none());
    }

    /// Non-fire: ordinary prose with no leading marker — no recovery.
    #[test]
    fn plain_answer_is_untouched() {
        assert!(sanitize_harmony_tokens("Plain answer.").is_none());
    }
}

#[cfg(test)]
mod text_recovery_tests {
    use super::*;
    use crate::config::extended::TextEmbeddedRecovery as Mode;

    /// A realistic write-capable tool surface: `task` (subagents
    /// `explore`/`builder`), `bash`, and `read`. This is the toolbox the
    /// recovery decision branches against.
    fn build_tools() -> crate::engine::tool::ToolBox {
        crate::engine::tool::ToolBox::new()
            .with(Arc::new(crate::tools::task::TaskTool::with_subagents(&[
                "explore", "builder",
            ])))
            .with(Arc::new(crate::tools::bash::BashTool::new()))
            .with(Arc::new(crate::tools::read::ReadTool))
    }

    /// `thrpz9`: the captured ```json `task`/`explore` block (function-wrapped,
    /// args flattened as siblings of `name`) recovers into a real
    /// `task(agent="explore", …)` call. The synthesized call routes through the
    /// `task` special-case (→ permission gate / subagent spawn), no bypass.
    #[test]
    fn thrpz9_recovers_task_explore() {
        let tools = build_tools();
        let text = "```json\n[{\"type\":\"function\",\"function\":{\"name\":\"task\",\"agent\":\"explore\",\"prompt\":\"Perform a thorough review\",\"mode\":\"subagent\"}}]\n```";
        match decide_text_recovery(&tools, text, Mode::Available) {
            TextRecoveryDecision::Recovered(rec) => {
                assert_eq!(rec.call.function.name, "task");
                assert_eq!(rec.call.function.arguments["agent"], json_str("explore"));
                assert_eq!(
                    rec.call.function.arguments["prompt"],
                    json_str("Perform a thorough review")
                );
                assert!(matches!(
                    rec.marker,
                    Recovery::TextEmbedded {
                        stage: "openai",
                        ..
                    }
                ));
            }
            other => panic!("expected Recovered, got {}", variant(&other)),
        }
    }

    /// `6n3381`: the `"agent"`-keyed `[{"agent":"explore",…}]` block recovers to
    /// `task(agent="explore", …)` (explore is a known subagent → `task`).
    #[test]
    fn n6n3381_agent_keyed_explore_recovers_task() {
        let tools = build_tools();
        let text = "[{\"agent\":\"explore\",\"prompt\":\"Review the repo\",\"why\":\"audit\"}]";
        match decide_text_recovery(&tools, text, Mode::Available) {
            TextRecoveryDecision::Recovered(rec) => {
                assert_eq!(rec.call.function.name, "task");
                assert_eq!(rec.call.function.arguments["agent"], json_str("explore"));
                assert_eq!(
                    rec.call.function.arguments["prompt"],
                    json_str("Review the repo")
                );
                assert!(matches!(
                    rec.marker,
                    Recovery::TextEmbedded {
                        stage: "agent_keyed",
                        ..
                    }
                ));
            }
            other => panic!("expected Recovered, got {}", variant(&other)),
        }
    }

    /// `6n3381`: the `"agent"`-keyed `[{"agent":"bash",…}]` block recovers to
    /// `bash(command=…)` (bash is a known TOOL, not a subagent → dispatch it).
    #[test]
    fn n6n3381_agent_keyed_bash_recovers_bash() {
        let tools = build_tools();
        let text = "[{\"agent\":\"bash\",\"command\":\"ls -la\"}]";
        match decide_text_recovery(&tools, text, Mode::Available) {
            TextRecoveryDecision::Recovered(rec) => {
                assert_eq!(rec.call.function.name, "bash");
                assert_eq!(rec.call.function.arguments["command"], json_str("ls -la"));
                // bash args carry no `agent` key.
                assert!(rec.call.function.arguments.get("agent").is_none());
            }
            other => panic!("expected Recovered, got {}", variant(&other)),
        }
    }

    /// Structural-gate negative: a docs answer that is prose PLUS a fenced JSON
    /// block naming a real tool is NOT recovered and NOT executed.
    #[test]
    fn prose_plus_block_is_not_recovered() {
        let tools = build_tools();
        let text = "To list files, run:\n```json\n{\"name\":\"bash\",\"arguments\":{\"command\":\"ls\"}}\n```";
        assert!(matches!(
            decide_text_recovery(&tools, text, Mode::Available),
            TextRecoveryDecision::None
        ));
        // Even in strict mode the gate rejects prose-around-a-block.
        assert!(matches!(
            decide_text_recovery(&tools, text, Mode::Strict),
            TextRecoveryDecision::None
        ));
    }

    /// `available` + unknown tool (post name-repair): surfaced for the warning
    /// chip + a model-side nudge — not executed, not a hard failure.
    #[test]
    fn available_unknown_tool_surfaces_and_nudges() {
        let tools = build_tools();
        let text = "{\"name\":\"frobnicate\",\"arguments\":{\"x\":1}}";
        match decide_text_recovery(&tools, text, Mode::Available) {
            TextRecoveryDecision::UnknownAvailable {
                unknown,
                available_tools,
            } => {
                assert_eq!(unknown, "frobnicate");
                // The nudge lists real tools.
                let nudge = unknown_tool_nudge(&unknown, &available_tools);
                assert!(nudge.contains("frobnicate"));
                assert!(nudge.contains("bash") || nudge.contains("read"));
            }
            other => panic!("expected UnknownAvailable, got {}", variant(&other)),
        }
    }

    /// `strict` + the same unknown tool: returns a synthesized call so the
    /// dispatch loop feeds back an `unknown tool` tool_result (keeps the model
    /// in the loop) — never a yellow-chip surface.
    #[test]
    fn strict_unknown_tool_feeds_back_unknown() {
        let tools = build_tools();
        let text = "{\"name\":\"frobnicate\",\"arguments\":{\"x\":1}}";
        match decide_text_recovery(&tools, text, Mode::Strict) {
            TextRecoveryDecision::UnknownStrict { call, unknown } => {
                assert_eq!(unknown, "frobnicate");
                assert_eq!(call.function.name, "frobnicate");
            }
            other => panic!("expected UnknownStrict, got {}", variant(&other)),
        }
    }

    /// `off`: no recovery — even a clean tool-shaped block stays plain text.
    #[test]
    fn off_mode_never_recovers() {
        let tools = build_tools();
        let text = "[{\"agent\":\"bash\",\"command\":\"ls\"}]";
        assert!(matches!(
            decide_text_recovery(&tools, text, Mode::Off),
            TextRecoveryDecision::None
        ));
    }

    /// No false positive: a plain prose answer with no tool-shaped block is not
    /// a candidate in any mode.
    #[test]
    fn plain_prose_is_never_a_candidate() {
        let tools = build_tools();
        let text = "The repository is a Rust CLI with a TUI, a daemon, and a session DB.";
        for mode in [Mode::Available, Mode::Strict, Mode::Off] {
            assert!(matches!(
                decide_text_recovery(&tools, text, mode),
                TextRecoveryDecision::None
            ));
        }
    }

    /// A salvageable name typo is name-repaired BEFORE the existence check, so
    /// `read_file` → `read` recovers instead of bailing to the user.
    #[test]
    fn name_repair_runs_before_existence_check() {
        let tools = build_tools();
        // `functions.read` normalizes+rebinds to `read` (a registered tool).
        let text = "{\"name\":\"functions.read\",\"arguments\":{\"path\":\"src/x.rs\"}}";
        match decide_text_recovery(&tools, text, Mode::Available) {
            TextRecoveryDecision::Recovered(rec) => {
                assert_eq!(rec.call.function.name, "read");
            }
            other => panic!(
                "expected Recovered after name-repair, got {}",
                variant(&other)
            ),
        }
    }

    fn json_str(s: &str) -> Value {
        Value::String(s.to_string())
    }

    fn variant(d: &TextRecoveryDecision) -> &'static str {
        match d {
            TextRecoveryDecision::None => "None",
            TextRecoveryDecision::Recovered(_) => "Recovered",
            TextRecoveryDecision::UnknownAvailable { .. } => "UnknownAvailable",
            TextRecoveryDecision::UnknownStrict { .. } => "UnknownStrict",
        }
    }
}
