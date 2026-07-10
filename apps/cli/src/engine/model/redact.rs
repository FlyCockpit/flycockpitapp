use super::*;

const COCKPIT_OWNED_REQUEST_KEYS: &[&str] = &[
    "model",
    "messages",
    "temperature",
    "max_tokens",
    "tools",
    "tool_choice",
    "stream",
];

/// Strip [`COCKPIT_OWNED_REQUEST_KEYS`] from an extra-params fragment so a
/// merge into the outbound body supplies vendor keys only and can never
/// clobber the params cockpit already sets. Returns `None` when there are
/// no params, or nothing survives the strip (so no empty object is sent).
/// A non-object fragment is passed through untouched — rig's
/// `additional_params` only meaningfully flattens an object, and we don't
/// silently rewrite a shape the config author chose.
pub(crate) fn sanitized_extra_params(
    extra: Option<&serde_json::Value>,
) -> Option<serde_json::Value> {
    let extra = extra?;
    let serde_json::Value::Object(map) = extra else {
        return Some(extra.clone());
    };
    let kept: serde_json::Map<String, serde_json::Value> = map
        .iter()
        .filter(|(k, _)| !COCKPIT_OWNED_REQUEST_KEYS.contains(&k.as_str()))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    if kept.is_empty() {
        None
    } else {
        Some(serde_json::Value::Object(kept))
    }
}

/// Scrub every dynamic text field of one history/prompt [`Message`] through
/// `redact`, returning a rewritten copy (GOALS §7,
/// `redaction-cover-all-llm-requests.md`). Covers the system content, every
/// user/assistant `Text` part, the string content of every **tool result**,
/// and the stringified arguments of every assistant tool call. Static,
/// harness-defined tool *schemas* are not part of a message and are never
/// scrubbed here (they carry no user secrets). Opaque non-text parts (images,
/// audio, video, documents, encrypted/redacted reasoning) pass through
/// untouched.
///
/// `scrub` is deterministic + idempotent, so re-scrubbing already-scrubbed
/// cached history each turn yields byte-stable output — prompt caching is
/// unaffected (verified by the redact module's determinism test).
pub(super) fn scrub_message(redact: &RedactionTable, msg: &Message) -> Message {
    #[cfg(test)]
    SCRUB_MESSAGE_CALLS.with(|calls| calls.set(calls.get() + 1));
    match msg {
        Message::System { content } => Message::System {
            content: redact.scrub(content),
        },
        Message::User { content } => {
            let parts: Vec<UserContent> = content
                .iter()
                .map(|part| scrub_user_content(redact, part))
                .collect();
            // `parts` is rebuilt 1:1 from a non-empty `OneOrMany`, so it is
            // non-empty; `many` cannot fail. Fall back to the original on the
            // impossible empty case rather than panic.
            match OneOrMany::many(parts) {
                Ok(content) => Message::User { content },
                Err(_) => msg.clone(),
            }
        }
        Message::Assistant { id, content } => {
            let parts: Vec<AssistantContent> = content
                .iter()
                .map(|part| scrub_assistant_content(redact, part))
                .collect();
            match OneOrMany::many(parts) {
                Ok(content) => Message::Assistant {
                    id: id.clone(),
                    content,
                },
                Err(_) => msg.clone(),
            }
        }
    }
}

/// Scrub the text-bearing fields of one [`UserContent`] part. `Text` parts and
/// the `Text` content of a `ToolResult` are scrubbed; images/audio/video/
/// documents pass through.
fn scrub_user_content(redact: &RedactionTable, part: &UserContent) -> UserContent {
    match part {
        UserContent::Text(t) => UserContent::text(redact.scrub(&t.text)),
        UserContent::ToolResult(tr) => {
            let scrubbed: Vec<ToolResultContent> = tr
                .content
                .iter()
                .map(|c| match c {
                    ToolResultContent::Text(t) => ToolResultContent::text(redact.scrub(&t.text)),
                    other => other.clone(),
                })
                .collect();
            let content = OneOrMany::many(scrubbed).unwrap_or_else(|_| tr.content.clone());
            match &tr.call_id {
                Some(call_id) => {
                    UserContent::tool_result_with_call_id(tr.id.clone(), call_id.clone(), content)
                }
                None => UserContent::tool_result(tr.id.clone(), content),
            }
        }
        other => other.clone(),
    }
}

/// Scrub the text-bearing fields of one [`AssistantContent`] part. `Text`
/// parts and the (stringified JSON) arguments of a tool call are scrubbed so a
/// secret the model echoes into a tool argument can't leak on replay; text
/// reasoning is scrubbed while provider signatures and opaque encrypted /
/// redacted reasoning blocks pass through unchanged.
fn scrub_assistant_content(redact: &RedactionTable, part: &AssistantContent) -> AssistantContent {
    match part {
        AssistantContent::Text(t) => AssistantContent::text(redact.scrub(&t.text)),
        AssistantContent::ToolCall(tc) => {
            let mut tc = tc.clone();
            tc.function.arguments = scrub_json_strings(redact, &tc.function.arguments);
            AssistantContent::ToolCall(tc)
        }
        AssistantContent::Reasoning(reasoning) => {
            AssistantContent::Reasoning(scrub_reasoning(redact, reasoning))
        }
        other => other.clone(),
    }
}

fn scrub_reasoning(redact: &RedactionTable, reasoning: &Reasoning) -> Reasoning {
    let mut reasoning = reasoning.clone();
    reasoning.content = reasoning
        .content
        .into_iter()
        .map(|content| match content {
            ReasoningContent::Text { text, signature } => ReasoningContent::Text {
                text: redact.scrub(&text),
                signature,
            },
            ReasoningContent::Summary(text) => ReasoningContent::Summary(redact.scrub(&text)),
            other => other,
        })
        .collect();
    reasoning
}

fn scrub_json_strings(redact: &RedactionTable, value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::String(s) => serde_json::Value::String(redact.scrub(s)),
        serde_json::Value::Array(items) => serde_json::Value::Array(
            items
                .iter()
                .map(|v| scrub_json_strings(redact, v))
                .collect(),
        ),
        serde_json::Value::Object(map) => serde_json::Value::Object(
            map.iter()
                .map(|(k, v)| (k.clone(), scrub_json_strings(redact, v)))
                .collect(),
        ),
        other => other.clone(),
    }
}

/// Remove unsigned reasoning blocks before replaying history to native
/// Anthropic. Signed thinking blocks are provider-authenticated replay
/// material; unsigned reasoning may have come from another provider and can
/// trip Anthropic's signature validation when paired with tool use.
pub(super) fn strip_unsigned_reasoning(msg: &Message) -> Option<Message> {
    match msg {
        Message::Assistant { id, content } => {
            let kept: Vec<AssistantContent> = content
                .iter()
                .filter(|c| match c {
                    AssistantContent::Reasoning(reasoning) => reasoning_has_signature(reasoning),
                    _ => true,
                })
                .cloned()
                .collect();
            match OneOrMany::many(kept) {
                Ok(new_content) => Some(Message::Assistant {
                    id: id.clone(),
                    content: new_content,
                }),
                Err(_) => None,
            }
        }
        other => Some(other.clone()),
    }
}

fn reasoning_has_signature(reasoning: &Reasoning) -> bool {
    reasoning.content.iter().any(|content| {
        matches!(
            content,
            ReasoningContent::Text {
                signature: Some(signature),
                ..
            } if !signature.is_empty()
        )
    })
}

/// Remove `AssistantContent::Reasoning` items from a message's
/// content vector. Used to scrub past thinking blocks from the
/// history before each outbound request. Returns `None` when the
/// message must be dropped from the wire history entirely (a
/// reasoning-only assistant turn — see below); callers `filter_map`.
///
/// Safe for the Chat Completions variant (reasoning is never replayed
/// there). NOT safe as-is for a native Anthropic variant: stripping the
/// *latest* assistant turn's thinking — or any turn that pairs thinking
/// with `tool_use` — 400s the Messages API. Make this position-aware
/// before wiring native Anthropic. See `implementation notes` §10b.
pub(super) fn strip_reasoning(msg: &Message) -> Option<Message> {
    match msg {
        Message::Assistant { id, content } => {
            let kept: Vec<AssistantContent> = content
                .iter()
                .filter(|c| !matches!(c, AssistantContent::Reasoning(_)))
                .cloned()
                .collect();
            // `OneOrMany::many` errors on empty input: filtering reasoning
            // left no content, so this was a degenerate reasoning-only
            // assistant turn (no text, no tool call — e.g. a length-
            // truncated response that stopped mid-reasoning). Drop it
            // rather than ship the reasoning block verbatim, mirroring the
            // store-time policy that drops blank/body-less assistant turns
            // (`agent.rs:770`). A reasoning-only turn carries no tool_use
            // id, so dropping it can never orphan a tool_result.
            match OneOrMany::many(kept) {
                Ok(new_content) => Some(Message::Assistant {
                    id: id.clone(),
                    content: new_content,
                }),
                Err(_) => None,
            }
        }
        other => Some(other.clone()),
    }
}

/// Pull every `ReasoningContent::Text` chunk out of a complete
/// `Reasoning` block, joined with newlines. Empty for non-text
/// reasoning content (which rig models internally but we don't
/// display).
pub(super) fn collect_reasoning_text(r: &Reasoning) -> String {
    let mut seen = std::collections::HashSet::new();
    let mut parts = Vec::new();
    for content in r.content.iter() {
        let text = match content {
            ReasoningContent::Text { text, .. } | ReasoningContent::Summary(text) => text.as_str(),
            _ => continue,
        };
        if !text.is_empty() && seen.insert(text.to_string()) {
            parts.push(text.to_string());
        }
    }
    parts.join("\n")
}
