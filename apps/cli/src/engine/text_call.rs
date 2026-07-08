//! Text-embedded tool-call recovery (implementation note).
//!
//! Some weak ~120k-context models (gemma-3 and its class) emit a tool call as
//! **text** — a fenced ```json code block or a bare JSON array/object in the
//! assistant message — instead of in the structured `tool_calls` response
//! field. The structured field comes back empty, so the agent loop treats the
//! blob as a final text answer and nothing dispatches. No tool-description or
//! prompt tuning fixes a model whose calls never reach the wire, so this is a
//! priority-#1 "defensive against weak models" recovery (project guidance): pull the
//! text-form call back into a real tool call through the normal
//! validate-then-repair + permission + dispatch path.
//!
//! This module owns the *structural gate* and the *format normalization*: it
//! decides whether the assistant text is a recovery candidate at all, and if
//! so extracts `(candidate_name, raw_args)` from the known conventions. The
//! name-repair → existence-check branch, the setting precedence, and the
//! actual dispatch live in the agent loop (`src/engine/agent.rs`), which owns
//! the toolbox + permission gate — this module never dispatches.
//!
//! ## Structural gate (kills false positives — settled with the user)
//!
//! Reasoning (`<think>…</think>`, via [`crate::engine::think::split_think`]) is
//! stripped first; the **remaining content must consist solely of the
//! tool-call payload** — a single fenced code block OR a bare JSON
//! array/object, with **no other prose**. Any surrounding prose ⇒ NOT a
//! recovery candidate: the model is explaining or illustrating a call (e.g. a
//! docs answer containing a `bash` example), never invoking one. This gate
//! matters most for `bash`/write tools.
//!
//! ## Format normalization → candidate extraction
//!
//! Across the known conventions, extract `(candidate_name, raw_args)`:
//!   - OpenAI shape `{"name":…,"arguments":{…}}`, and the wrapped/flattened
//!     `{"type":"function","function":{"name":…, …args}}` (the `thrpz9` shape,
//!     args flattened as siblings of `name`);
//!   - the gemma `"agent"`-keyed shape (`6n3381`): the candidate name comes
//!     from `agent`. The caller decides whether that names a subagent (→
//!     `task`, value becomes `arguments.agent`) or a tool (→ that tool);
//!   - a single bare object, or a one-element array wrapping any of the above;
//!   - multi-element arrays (gemma occasionally batches) recover the
//!     **first** — [`Extracted::dropped_trailing`] records that trailing
//!     entries were dropped (no silent truncation — surfaced in the chip).

use serde_json::{Map, Value};

use crate::engine::think::split_think;

/// A tool-call candidate extracted from a text-embedded block, before
/// name-repair / existence-check / argument lifting (which the caller does).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Extracted {
    /// The convention the candidate was extracted under (`openai` /
    /// `agent_keyed`) — recorded as the recovery stage for the §14 audit row.
    pub convention: Convention,
    /// The model's emitted tool/agent name, *before* fuzzy name-repair. For
    /// the `agent_keyed` convention this is the value of the `agent` key; the
    /// caller branches on whether it names a known subagent vs a known tool.
    pub candidate_name: String,
    /// The raw arguments for the call. For the OpenAI `arguments`-nested shape
    /// this is the inner object; for the flattened / `agent_keyed` shapes it is
    /// the sibling keys (with the name/type/agent keys removed). Always an
    /// object (possibly empty) — the caller lifts it into the resolved tool's
    /// arguments and runs validate-then-repair (§12) over it.
    pub raw_args: Value,
    /// True when the source was a multi-element array and trailing entries were
    /// dropped (we recover only the first). Surfaced in the recovery chip so
    /// the truncation is never silent.
    pub dropped_trailing: bool,
}

/// Which text-embedded convention a candidate was extracted under. Recorded as
/// the recovery *stage* for the §14 audit row + chip; round-tripped by the
/// audit reader via [`TEXT_RECOVERY_STAGES`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Convention {
    /// OpenAI `{"name":…,"arguments":{…}}` or the function-wrapped/flattened
    /// `{"type":"function","function":{"name":…, …args}}` (`thrpz9`).
    OpenAI,
    /// The gemma `"agent"`-keyed shape (`6n3381`): `{"agent":…, …args}` with no
    /// `name` field, where `agent` carries the tool/subagent name.
    AgentKeyed,
}

impl Convention {
    /// The stable stage name persisted on the audit row (`recovery_stage`).
    pub fn stage(self) -> &'static str {
        match self {
            Convention::OpenAI => "openai",
            Convention::AgentKeyed => "agent_keyed",
        }
    }
}

/// The text-recovery stage names, in convention order. Used by the audit-row
/// reader to round-trip `Recovery::TextEmbedded` the same way the shape /
/// cascade / name-repair stage lists are (implementation note).
pub const TEXT_RECOVERY_STAGES: &[&str] = &["openai", "agent_keyed"];

/// Run the structural gate over `content` (an assistant message's text) and, if
/// it passes, extract the tool-call candidate. Returns `None` when the content
/// is NOT a recovery candidate — either prose surrounds the payload (the
/// structural gate rejected it) or the payload is not a recognized tool-call
/// shape. The caller invokes this only when the structured `tool_calls` field
/// came back empty.
///
/// The gate: reasoning is stripped first; the remaining body, trimmed, must be
/// either a single fenced code block whose fence content is the whole payload,
/// or a bare JSON array/object — with nothing else around it. A bare value with
/// leading/trailing prose is rejected.
pub fn extract_candidate(content: &str) -> Option<Extracted> {
    // 1. Strip reasoning. The body is what the user/model would treat as the
    //    answer; an inline `<think>` block is not part of the payload.
    let (body, _reasoning) = split_think(content);
    let body = body.trim();
    if body.is_empty() {
        return None;
    }

    // 2. Structural gate: the body must be SOLELY the payload — a single fenced
    //    code block, or a bare JSON array/object. Any surrounding prose fails.
    let payload = unwrap_sole_payload(body)?;

    // 3. Parse the payload as JSON. A non-JSON fenced block (a shell snippet, a
    //    diff) is not a tool call — reject.
    let value: Value = serde_json::from_str(payload).ok()?;

    // 4. Normalize: unwrap a single-/multi-element array to its first element,
    //    noting any dropped trailing entries.
    let (object, dropped_trailing) = match value {
        Value::Array(arr) => {
            let mut it = arr.into_iter();
            let first = it.next()?;
            let dropped = it.next().is_some();
            (first, dropped)
        }
        other => (other, false),
    };
    let Value::Object(map) = object else {
        return None;
    };

    extract_from_object(map, dropped_trailing)
}

/// Decide whether `body` is *solely* a tool-call payload and return the inner
/// JSON text. Two accepted shapes:
///   - a single fenced code block (```… ```), optionally tagged (```json), whose
///     fence content is the entire body — no prose before the opening fence or
///     after the closing fence;
///   - a bare JSON array/object — the trimmed body starts with `[`/`{` and ends
///     with the matching `]`/`}` (a quick structural check; full validity is
///     decided by the JSON parse in the caller).
///
/// Any other shape (prose around the payload, multiple fenced blocks, a bare
/// scalar) returns `None` — the structural gate rejecting a non-candidate.
fn unwrap_sole_payload(body: &str) -> Option<&str> {
    let body = body.trim();
    if let Some(inner) = unwrap_sole_fence(body) {
        let inner = inner.trim();
        return is_bare_json_delimited(inner).then_some(inner);
    }
    is_bare_json_delimited(body).then_some(body)
}

/// If `body` is exactly one fenced code block and nothing else, return its
/// inner content (fence tag line stripped). The opening fence must be at the
/// very start (after trim) and the closing fence at the very end, with no text
/// outside — otherwise this is prose-with-a-block, not a sole payload.
fn unwrap_sole_fence(body: &str) -> Option<&str> {
    let rest = body.strip_prefix("```")?;
    // The opening fence may carry an info string (e.g. `json`) up to the first
    // newline; that line is not part of the payload.
    let nl = rest.find('\n')?;
    let info = rest[..nl].trim();
    // A fenced info string is a single token (a language tag) — reject a fence
    // whose "info" is actually prose (contains spaces / looks like a sentence),
    // which would mean this wasn't a sole code block.
    if info.contains(char::is_whitespace) {
        return None;
    }
    let after_info = &rest[nl + 1..];
    // The closing fence must end the body — no trailing prose after it.
    let close = after_info.rfind("```")?;
    // Everything after the closing fence (trimmed) must be empty.
    if !after_info[close + 3..].trim().is_empty() {
        return None;
    }
    Some(&after_info[..close])
}

/// A cheap structural check that `s` is delimited like a JSON array or object:
/// it starts with `[`/`{` and ends with the matching `]`/`}`. Full validity is
/// left to the JSON parser; this only screens out bare scalars and prose so the
/// gate stays a *structural* gate (the model emitting a sentence that happens to
/// contain a brace is not a candidate).
fn is_bare_json_delimited(s: &str) -> bool {
    let s = s.trim();
    matches!(
        (s.chars().next(), s.chars().last()),
        (Some('{'), Some('}')) | (Some('['), Some(']'))
    )
}

/// Extract `(candidate_name, raw_args)` from a single JSON object across the
/// known conventions. Returns `None` if the object matches no recognized
/// tool-call shape.
fn extract_from_object(map: Map<String, Value>, dropped_trailing: bool) -> Option<Extracted> {
    // The function-wrapped OpenAI shape: `{"type":"function","function":{…}}`.
    // Unwrap to the inner function object and recurse on it (the inner object is
    // itself either `{"name":…,"arguments":{…}}` or the flattened `thrpz9`
    // shape). The outer wrapper carries no args of its own.
    if let Some(Value::Object(func)) = map.get("function") {
        // `dropped_trailing` propagates from the array level above.
        return extract_openai_object(func.clone(), dropped_trailing);
    }

    // A bare object with a `name` key is the OpenAI shape (nested `arguments`
    // or flattened siblings).
    if map.contains_key("name") {
        return extract_openai_object(map, dropped_trailing);
    }

    // The gemma `"agent"`-keyed shape: no `name`, the tool/subagent name is the
    // value of `agent`. The remaining siblings are the args.
    if let Some(Value::String(agent)) = map.get("agent") {
        let candidate_name = agent.trim().to_string();
        if candidate_name.is_empty() {
            return None;
        }
        let mut raw_args = map;
        // `agent` itself is consumed as the name carrier; the rest are args.
        raw_args.remove("agent");
        // A wrapper `type:"function"` key (if a model mixes conventions) is not
        // an argument.
        raw_args.remove("type");
        return Some(Extracted {
            convention: Convention::AgentKeyed,
            candidate_name,
            raw_args: Value::Object(raw_args),
            dropped_trailing,
        });
    }

    None
}

/// Extract from an OpenAI-shaped object: `name` plus either a nested
/// `arguments` object or args flattened as siblings of `name` (`thrpz9`).
fn extract_openai_object(mut map: Map<String, Value>, dropped_trailing: bool) -> Option<Extracted> {
    let candidate_name = map.get("name").and_then(Value::as_str)?.trim().to_string();
    if candidate_name.is_empty() {
        return None;
    }
    // Nested `arguments` wins when present and an object (the canonical OpenAI
    // shape). `arguments` given as a JSON *string* is parsed (some providers
    // stringify it); a non-object/non-parseable `arguments` falls through to the
    // flattened path so a malformed wrapper never loses the sibling args.
    if let Some(args) = map.get("arguments") {
        if let Value::Object(_) = args {
            let inner = map.remove("arguments").unwrap();
            return Some(Extracted {
                convention: Convention::OpenAI,
                candidate_name,
                raw_args: inner,
                dropped_trailing,
            });
        }
        if let Value::String(s) = args
            && let Ok(Value::Object(parsed)) = serde_json::from_str::<Value>(s)
        {
            return Some(Extracted {
                convention: Convention::OpenAI,
                candidate_name,
                raw_args: Value::Object(parsed),
                dropped_trailing,
            });
        }
    }
    // Flattened (`thrpz9`): the args are the siblings of `name`. Remove the
    // structural keys (`name`, `type`, and any stray non-object `arguments`),
    // and treat the rest as the arguments object.
    map.remove("name");
    map.remove("type");
    map.remove("arguments");
    Some(Extracted {
        convention: Convention::OpenAI,
        candidate_name,
        raw_args: Value::Object(map),
        dropped_trailing,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn thrpz9_flattened_task_explore_block() {
        // The captured `thrpz9` block: a single ```json fenced array, one
        // element, OpenAI function-wrapped with args flattened as siblings of
        // `name`. Recovers to a `task`-named candidate with the agent/prompt/
        // mode as raw_args.
        let content = "```json\n[{\"type\":\"function\",\"function\":{\"name\":\"task\",\"agent\":\"explore\",\"prompt\":\"Perform a thorough review\",\"mode\":\"subagent\"}}]\n```";
        let e = extract_candidate(content).expect("recovers");
        assert_eq!(e.convention, Convention::OpenAI);
        assert_eq!(e.candidate_name, "task");
        assert_eq!(e.raw_args["agent"], json!("explore"));
        assert_eq!(e.raw_args["prompt"], json!("Perform a thorough review"));
        assert_eq!(e.raw_args["mode"], json!("subagent"));
        // `name`/`type` are stripped from the args.
        assert!(e.raw_args.get("name").is_none());
        assert!(e.raw_args.get("type").is_none());
        assert!(!e.dropped_trailing);
    }

    #[test]
    fn agent_keyed_explore_block() {
        // `6n3381`: `[{"agent":"explore", …}]` — no `name`, agent carries the
        // subagent name. The candidate name is `explore`; the caller maps it to
        // `task`.
        let content = "[{\"agent\":\"explore\",\"prompt\":\"Review the repo\",\"why\":\"audit\"}]";
        let e = extract_candidate(content).expect("recovers");
        assert_eq!(e.convention, Convention::AgentKeyed);
        assert_eq!(e.candidate_name, "explore");
        assert_eq!(e.raw_args["prompt"], json!("Review the repo"));
        assert_eq!(e.raw_args["why"], json!("audit"));
        assert!(e.raw_args.get("agent").is_none());
    }

    #[test]
    fn agent_keyed_bash_block() {
        // `6n3381`: `[{"agent":"bash", …}]` — agent carries a TOOL name. The
        // candidate name is `bash`; the caller dispatches it as the tool.
        let content = "[{\"agent\":\"bash\",\"command\":\"ls -la\"}]";
        let e = extract_candidate(content).expect("recovers");
        assert_eq!(e.convention, Convention::AgentKeyed);
        assert_eq!(e.candidate_name, "bash");
        assert_eq!(e.raw_args["command"], json!("ls -la"));
    }

    #[test]
    fn openai_nested_arguments() {
        let content = "{\"name\":\"read\",\"arguments\":{\"path\":\"src/main.rs\"}}";
        let e = extract_candidate(content).expect("recovers");
        assert_eq!(e.convention, Convention::OpenAI);
        assert_eq!(e.candidate_name, "read");
        assert_eq!(e.raw_args, json!({"path": "src/main.rs"}));
    }

    #[test]
    fn openai_stringified_arguments() {
        // Some providers stringify `arguments`. We parse it.
        let content = "{\"name\":\"read\",\"arguments\":\"{\\\"path\\\":\\\"x\\\"}\"}";
        let e = extract_candidate(content).expect("recovers");
        assert_eq!(e.raw_args, json!({"path": "x"}));
    }

    #[test]
    fn single_bare_object_no_fence() {
        let content = "{\"name\":\"tree\",\"arguments\":{}}";
        let e = extract_candidate(content).expect("recovers");
        assert_eq!(e.candidate_name, "tree");
        assert_eq!(e.raw_args, json!({}));
    }

    #[test]
    fn multi_element_array_recovers_first_and_flags_drop() {
        let content =
            "[{\"agent\":\"bash\",\"command\":\"a\"},{\"agent\":\"bash\",\"command\":\"b\"}]";
        let e = extract_candidate(content).expect("recovers");
        assert_eq!(e.candidate_name, "bash");
        assert_eq!(e.raw_args["command"], json!("a"));
        assert!(e.dropped_trailing, "trailing entries must be flagged");
    }

    #[test]
    fn think_block_stripped_before_gate() {
        // A leading `<think>` is reasoning, not prose: stripping it leaves a
        // sole bare-JSON payload, which recovers.
        let content =
            "<think>I should review the code</think>\n{\"name\":\"tree\",\"arguments\":{}}";
        let e = extract_candidate(content).expect("recovers after think-strip");
        assert_eq!(e.candidate_name, "tree");
    }

    #[test]
    fn prose_plus_fenced_block_is_rejected() {
        // The structural-gate negative: a docs answer illustrating a `bash`
        // call. Prose precedes the fenced block, so it is NOT a recovery
        // candidate and must not execute.
        let content = "To list files, run this command:\n```json\n{\"name\":\"bash\",\"arguments\":{\"command\":\"ls\"}}\n```";
        assert!(
            extract_candidate(content).is_none(),
            "prose around the block must reject recovery"
        );
    }

    #[test]
    fn prose_after_block_is_rejected() {
        let content = "```json\n{\"name\":\"bash\",\"arguments\":{\"command\":\"ls\"}}\n```\nThat lists the files.";
        assert!(extract_candidate(content).is_none());
    }

    #[test]
    fn bare_json_with_leading_prose_is_rejected() {
        let content = "Here is the call: {\"name\":\"bash\",\"arguments\":{\"command\":\"ls\"}}";
        assert!(extract_candidate(content).is_none());
    }

    #[test]
    fn plain_prose_answer_is_not_a_candidate() {
        let content = "The repository contains a Rust CLI with a TUI and a daemon.";
        assert!(extract_candidate(content).is_none());
    }

    #[test]
    fn non_json_fenced_block_is_not_a_candidate() {
        // A fenced shell snippet (not JSON) is not a tool call.
        let content = "```bash\nls -la\n```";
        assert!(extract_candidate(content).is_none());
    }

    #[test]
    fn empty_content_is_not_a_candidate() {
        assert!(extract_candidate("").is_none());
        assert!(extract_candidate("   \n  ").is_none());
    }

    #[test]
    fn object_without_name_or_agent_is_not_a_candidate() {
        // A bare object that isn't tool-shaped (no `name`, no `agent`).
        let content = "{\"foo\":1,\"bar\":2}";
        assert!(extract_candidate(content).is_none());
    }

    #[test]
    fn convention_stage_names_match_catalog() {
        assert_eq!(Convention::OpenAI.stage(), "openai");
        assert_eq!(Convention::AgentKeyed.stage(), "agent_keyed");
        assert!(TEXT_RECOVERY_STAGES.contains(&"openai"));
        assert!(TEXT_RECOVERY_STAGES.contains(&"agent_keyed"));
    }
}
