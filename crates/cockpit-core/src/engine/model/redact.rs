use super::*;
use rig::message::AdditionalParams;

const COCKPIT_OWNED_REQUEST_KEYS: &[&str] = &[
    "model",
    "messages",
    "temperature",
    "max_tokens",
    "tools",
    "tool_choice",
    "stream",
];

/// These controls are owned only by the generic OpenAI Responses wire. Other
/// wires may legitimately define identically named vendor parameters.
const RESPONSES_STATEFUL_REQUEST_KEYS: &[&str] = &[
    // Cockpit owns Responses statefulness. Every Responses request carries
    // the full transcript and explicitly disables server-side retention; a
    // provider fragment must not opt back into a stateful server session.
    "store",
    "previous_response_id",
    "background",
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
    sanitized_extra_params_with(extra, |key| COCKPIT_OWNED_REQUEST_KEYS.contains(&key))
}

/// Apply the generic collision guard plus the statelessness controls owned by
/// the generic OpenAI Responses wire. Keeping this separate from
/// [`sanitized_extra_params`] ensures a Chat Completions (or other) provider
/// can use an identically named vendor parameter.
pub(crate) fn sanitized_openai_responses_extra_params(
    extra: Option<&serde_json::Value>,
) -> Option<serde_json::Value> {
    sanitized_extra_params_with(extra, |key| {
        COCKPIT_OWNED_REQUEST_KEYS.contains(&key) || RESPONSES_STATEFUL_REQUEST_KEYS.contains(&key)
    })
}

fn sanitized_extra_params_with(
    extra: Option<&serde_json::Value>,
    is_owned: impl Fn(&str) -> bool,
) -> Option<serde_json::Value> {
    let extra = extra?;
    let serde_json::Value::Object(map) = extra else {
        return Some(extra.clone());
    };
    let kept: serde_json::Map<String, serde_json::Value> = map
        .iter()
        .filter(|(k, _)| !is_owned(k))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    if kept.is_empty() {
        None
    } else {
        Some(serde_json::Value::Object(kept))
    }
}

/// Protocol constant for the key-collision terminal object. When scrubbing the
/// keys of one JSON object produces a duplicate key, that entire object is
/// replaced by exactly `{"**REDACTED BY COCKPIT**":"**REDACTED BY COCKPIT**"}`
/// (parent-prompt spec — deliberately NOT the configurable placeholder). It is
/// terminal: it carries no source data, is syntactically valid, and re-scrubs
/// to itself (both key and value are protocol text, never a registered secret).
pub(super) const REDACTED_COLLISION_MARKER: &str = "**REDACTED BY COCKPIT**";

/// A wire field that has no renderer for a completion dispatch: a media
/// source that is not a scrubbable string channel (`Raw` bytes, a provider
/// `FileId`, `Unknown`, or a future rig variant). Rather than pass an
/// unscrubbable channel to a provider that may retain it, the prep step fails
/// closed and the three prep entry points map this into a typed
/// [`InferenceFailure`] with phase `prep` and class
/// [`InferenceErrorClass::UnrenderableWireField`]. Every completion route runs
/// the walk.
#[derive(Debug, Clone)]
pub(crate) struct UnrenderableWireField {
    /// The channel that could not be rendered, for the failure detail.
    pub(crate) channel: &'static str,
}

impl UnrenderableWireField {
    fn new(channel: &'static str) -> Self {
        Self { channel }
    }

    pub(crate) fn detail(&self) -> String {
        format!(
            "message wire field `{}` has no renderer for a completion dispatch",
            self.channel
        )
    }
}

impl std::fmt::Display for UnrenderableWireField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("message wire field `")?;
        f.write_str(self.channel)?;
        f.write_str("` has no renderer for a completion dispatch")
    }
}

/// Scrub every dynamic text field of one history/prompt [`Message`] through
/// `redact`, returning a rewritten copy (GOALS §7,
/// `redaction-cover-all-llm-requests.md`). This is the completion-egress wire
/// walk and it fails **closed** on any channel it cannot render.
///
/// The walk is a closed policy over every rig content variant — there is no
/// silent passthrough. Each string channel is scrubbed: the system content,
/// every user/assistant `Text` part (and its `additional_params`), every
/// **tool result** member (text, image data strings, and recursively every
/// value **and key** of a JSON member), every assistant tool call's function
/// **name**, arguments (recursively, values and keys), and `additional_params`,
/// reasoning text/summaries, and the `data` string channels
/// (`Url`/`Base64`/`String`) plus `additional_params` of every image / audio /
/// video / document part. Non-string scalars, media-type enums, provider
/// signatures, and opaque encrypted/redacted reasoning blocks are
/// enumerated-safe passthroughs. A media `data` channel with no renderer
/// (`Raw`/`FileId`/`Unknown`) returns [`UnrenderableWireField`]. Static,
/// harness-defined tool *schemas* are not part of a message and are never
/// scrubbed here.
///
/// `scrub` is deterministic + idempotent, so re-scrubbing already-scrubbed
/// cached history each turn yields byte-stable output — prompt caching is
/// unaffected (verified by the redact module's determinism test).
pub(crate) fn scrub_message(
    redact: &RedactionTable,
    msg: &Message,
) -> Result<Message, UnrenderableWireField> {
    #[cfg(test)]
    SCRUB_MESSAGE_CALLS.with(|calls| calls.set(calls.get() + 1));
    match msg {
        Message::System { content } => Ok(Message::System {
            content: redact.scrub(content),
        }),
        Message::User { content } => {
            let mut parts: Vec<UserContent> = Vec::with_capacity(content.len());
            for part in content.iter() {
                parts.push(scrub_user_content(redact, part)?);
            }
            Ok(Message::User { content: parts })
        }
        Message::Assistant { id, content } => {
            let mut parts: Vec<AssistantContent> = Vec::with_capacity(content.len());
            for part in content.iter() {
                parts.push(scrub_assistant_content(redact, part)?);
            }
            Ok(Message::Assistant {
                id: id.clone(),
                content: parts,
            })
        }
    }
}

/// Scrub one optional provider-params object (present on `Text` and every
/// media part). `None` stays `None`. `AdditionalParams` is non-empty by
/// construction; scrubbing preserves every key/value pair (or replaces only a
/// colliding nested object with the terminal redaction marker), so the result
/// remains non-empty as well.
fn scrub_additional_params(
    redact: &RedactionTable,
    params: &Option<AdditionalParams>,
) -> Option<AdditionalParams> {
    params.as_ref().map(|params| {
        let serde_json::Value::Object(map) = scrub_json_object(redact, params.as_map()) else {
            unreachable!("scrubbing an additional-params object always returns an object")
        };
        AdditionalParams::new(map)
            .expect("scrubbing a non-empty additional-params object preserves content")
    })
}

/// Tool calls still use Rig's unconstrained JSON extra-params field. Preserve
/// its configured shape while recursively redacting every string channel.
fn scrub_tool_call_additional_params(
    redact: &RedactionTable,
    params: &Option<serde_json::Value>,
) -> Option<serde_json::Value> {
    params.as_ref().map(|value| scrub_json_value(redact, value))
}

/// The single recursive JSON renderer for both tool-result `Json` values and
/// tool-call arguments. Every string leaf (array element, object value) **and
/// every object key** is scrubbed. When scrubbing an object's keys collides two
/// rendered keys, that innermost object collapses to the terminal collision
/// object. Non-string scalars (numbers/bools/null) are enumerated-safe and pass
/// through. `serde_json::Value` is not a rig content enum, so its scalar
/// passthrough is not a wire-inventory hole.
fn scrub_json_value(redact: &RedactionTable, value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::String(s) => serde_json::Value::String(redact.scrub(s)),
        serde_json::Value::Array(items) => {
            serde_json::Value::Array(items.iter().map(|v| scrub_json_value(redact, v)).collect())
        }
        serde_json::Value::Object(map) => scrub_json_object(redact, map),
        // Numbers, bools, and null carry no string channel.
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => {
            value.clone()
        }
    }
}

/// Scrub the keys and values of one JSON object. Values are rendered first
/// (so nested/inner collisions collapse before this level is checked —
/// innermost first). If two rendered keys collide, the whole object collapses
/// to the terminal collision object.
fn scrub_json_object(
    redact: &RedactionTable,
    map: &serde_json::Map<String, serde_json::Value>,
) -> serde_json::Value {
    let mut out = serde_json::Map::with_capacity(map.len());
    for (key, value) in map {
        let scrubbed_key = redact.scrub(key);
        let scrubbed_value = scrub_json_value(redact, value);
        if out.contains_key(&scrubbed_key) {
            // Two rendered keys are equal: the object cannot be represented
            // without dropping a member, so it collapses to the terminal
            // collision object at this innermost colliding level only.
            return redacted_collision_object();
        }
        out.insert(scrubbed_key, scrubbed_value);
    }
    serde_json::Value::Object(out)
}

/// `{"**REDACTED BY COCKPIT**":"**REDACTED BY COCKPIT**"}` — the fixed,
/// terminal, source-data-free replacement for a key-collided object.
fn redacted_collision_object() -> serde_json::Value {
    let mut map = serde_json::Map::with_capacity(1);
    map.insert(
        REDACTED_COLLISION_MARKER.to_string(),
        serde_json::Value::String(REDACTED_COLLISION_MARKER.to_string()),
    );
    serde_json::Value::Object(map)
}

/// Render one media `data` source. The three string channels
/// (`Url`/`Base64`/`String`) are scrubbed against the table; the non-string
/// channels (`Raw`/`FileId`/`Unknown`, or a future rig variant) have no
/// renderer and fail closed on an untrusted dispatch. This match is over the
/// `#[non_exhaustive]` `DocumentSourceKind`, so the compiler requires a final
/// arm — it fails **closed** (never a silent passthrough).
fn scrub_media_source(
    redact: &RedactionTable,
    data: &DocumentSourceKind,
    channel: &'static str,
) -> Result<DocumentSourceKind, UnrenderableWireField> {
    match data {
        DocumentSourceKind::Url(s) => Ok(DocumentSourceKind::Url(redact.scrub(s))),
        DocumentSourceKind::Base64(s) => Ok(DocumentSourceKind::Base64(redact.scrub(s))),
        DocumentSourceKind::String(s) => Ok(DocumentSourceKind::String(redact.scrub(s))),
        // `DocumentSourceKind` is `#[non_exhaustive]` in rig, so this crate
        // (external to rig) CANNOT write a compile-forced exhaustive match over
        // it — the wildcard arm is unavoidable, not a lazy `_`. It is therefore
        // deliberately fail-CLOSED: the non-string channels (`Raw` bytes, a
        // provider `FileId`, `Unknown`) have no renderer, and any future rig
        // source kind lands here too, so every one errors on an untrusted
        // dispatch rather than reaching a provider unscrubbed. AC6's variant
        // walk asserts each of these arms returns `UnrenderableWireField`.
        _ => Err(UnrenderableWireField::new(channel)),
    }
}

/// Scrub one [`UserContent`] part. Exhaustive over every rig `UserContent`
/// variant with no silent-passthrough arm, so a new rig variant is a compile
/// error rather than a leak.
pub(crate) fn scrub_user_content(
    redact: &RedactionTable,
    part: &UserContent,
) -> Result<UserContent, UnrenderableWireField> {
    match part {
        UserContent::Text(t) => {
            let mut t = t.clone();
            t.text = redact.scrub(&t.text);
            t.additional_params = scrub_additional_params(redact, &t.additional_params);
            Ok(UserContent::Text(t))
        }
        UserContent::ToolResult(tr) => {
            let mut scrubbed: Vec<ToolResultContent> = Vec::with_capacity(tr.content.len());
            for c in tr.content.iter() {
                scrubbed.push(scrub_tool_result_content(redact, c)?);
            }
            let mut result = tr.clone();
            result.content = scrubbed;
            Ok(UserContent::ToolResult(result))
        }
        UserContent::Image(image) => {
            let mut image = image.clone();
            image.data = scrub_media_source(redact, &image.data, "user.image.data")?;
            image.additional_params = scrub_additional_params(redact, &image.additional_params);
            Ok(UserContent::Image(image))
        }
        UserContent::Audio(audio) => {
            let mut audio = audio.clone();
            audio.data = scrub_media_source(redact, &audio.data, "user.audio.data")?;
            audio.additional_params = scrub_additional_params(redact, &audio.additional_params);
            Ok(UserContent::Audio(audio))
        }
        UserContent::Video(video) => {
            let mut video = video.clone();
            video.data = scrub_media_source(redact, &video.data, "user.video.data")?;
            video.additional_params = scrub_additional_params(redact, &video.additional_params);
            Ok(UserContent::Video(video))
        }
        UserContent::Document(document) => {
            let mut document = document.clone();
            document.data = scrub_media_source(redact, &document.data, "user.document.data")?;
            document.additional_params =
                scrub_additional_params(redact, &document.additional_params);
            Ok(UserContent::Document(document))
        }
    }
}

/// Scrub one tool-result member. Exhaustive over `ToolResultContent` — text is
/// scrubbed, image data string channels are scrubbed (fail closed on
/// non-renderable), and JSON members run the recursive value+key renderer.
fn scrub_tool_result_content(
    redact: &RedactionTable,
    content: &ToolResultContent,
) -> Result<ToolResultContent, UnrenderableWireField> {
    match content {
        ToolResultContent::Text(t) => {
            let mut t = t.clone();
            t.text = redact.scrub(&t.text);
            t.additional_params = scrub_additional_params(redact, &t.additional_params);
            Ok(ToolResultContent::Text(t))
        }
        ToolResultContent::Image(image) => {
            let mut image = image.clone();
            image.data = scrub_media_source(redact, &image.data, "tool_result.image.data")?;
            image.additional_params = scrub_additional_params(redact, &image.additional_params);
            Ok(ToolResultContent::Image(image))
        }
        ToolResultContent::Json { value } => Ok(ToolResultContent::Json {
            value: scrub_json_value(redact, value),
        }),
    }
}

/// Scrub one [`AssistantContent`] part. Exhaustive over every rig
/// `AssistantContent` variant. `Text` and the tool call's function **name** +
/// arguments (values and keys) + `additional_params` are scrubbed; text
/// reasoning is scrubbed while provider signatures and opaque encrypted /
/// redacted reasoning blocks are enumerated-safe passthroughs. The tool call's
/// correlation identifiers (`id`, `call_id`) and provider `signature` are
/// structural and preserved so tool-result correlation and provider
/// authentication survive.
fn scrub_assistant_content(
    redact: &RedactionTable,
    part: &AssistantContent,
) -> Result<AssistantContent, UnrenderableWireField> {
    match part {
        AssistantContent::Text(t) => {
            let mut t = t.clone();
            t.text = redact.scrub(&t.text);
            t.additional_params = scrub_additional_params(redact, &t.additional_params);
            Ok(AssistantContent::Text(t))
        }
        AssistantContent::ToolCall(tc) => {
            let mut tc = tc.clone();
            tc.function.name = redact.scrub(&tc.function.name);
            tc.function.arguments = scrub_json_value(redact, &tc.function.arguments);
            tc.additional_params = scrub_tool_call_additional_params(redact, &tc.additional_params);
            Ok(AssistantContent::ToolCall(tc))
        }
        AssistantContent::Reasoning(reasoning) => Ok(AssistantContent::Reasoning(scrub_reasoning(
            redact, reasoning,
        ))),
        AssistantContent::Image(image) => {
            let mut image = image.clone();
            image.data = scrub_media_source(redact, &image.data, "assistant.image.data")?;
            image.additional_params = scrub_additional_params(redact, &image.additional_params);
            Ok(AssistantContent::Image(image))
        }
    }
}

fn scrub_reasoning(redact: &RedactionTable, reasoning: &Reasoning) -> Reasoning {
    let mut out = reasoning.clone();
    let mut content = Vec::with_capacity(out.content.len());
    for block in out.content.into_iter() {
        content.push(match block {
            ReasoningContent::Text { text, signature } => ReasoningContent::Text {
                text: redact.scrub(&text),
                signature,
            },
            ReasoningContent::Summary(text) => ReasoningContent::Summary(redact.scrub(&text)),
            // Opaque provider-authenticated / provider-redacted reasoning blobs
            // are enumerated-safe: they carry no user free text we can render.
            ReasoningContent::Encrypted(data) => ReasoningContent::Encrypted(data),
            ReasoningContent::Redacted { data } => ReasoningContent::Redacted { data },
        });
    }
    out.content = content;
    out
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
            (!kept.is_empty()).then_some(Message::Assistant {
                id: id.clone(),
                content: kept,
            })
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
            // Filtering reasoning can leave no content, so this was a degenerate reasoning-only
            // assistant turn (no text, no tool call — e.g. a length-
            // truncated response that stopped mid-reasoning). Drop it
            // rather than ship the reasoning block verbatim, mirroring the
            // store-time policy that drops blank/body-less assistant turns
            // (`agent.rs:770`). A reasoning-only turn carries no tool_use
            // id, so dropping it can never orphan a tool_result.
            (!kept.is_empty()).then_some(Message::Assistant {
                id: id.clone(),
                content: kept,
            })
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
