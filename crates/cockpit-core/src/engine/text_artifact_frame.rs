//! The single deterministic model-facing frame for retained text artifacts.

use anyhow::{Result, anyhow, bail, ensure};
use rig::message::UserContent;
use uuid::Uuid;

pub const ARTIFACT_FRAME_GUIDANCE: &str =
    "Use artifact_read or artifact_search with artifact_id to inspect this retained text.";

#[derive(Debug, Clone)]
pub struct ArtifactFrame<'a> {
    pub status: &'a str,
    pub reason: Option<&'a str>,
    pub artifact_id: Option<Uuid>,
    pub kind: &'a str,
    pub capture_reason: &'a str,
    /// A prevalidated compact JSON object in the kind-specific fixed order.
    pub provenance_json: &'a str,
    pub host_captured_bytes: usize,
    pub host_original_bytes: usize,
    pub host_dropped_bytes: usize,
    pub stored_source_bytes: usize,
    pub content_bytes: usize,
    pub line_count: usize,
    pub preview_head: &'a str,
    pub preview_tail: &'a str,
}

pub fn render_artifact_frame(frame: &ArtifactFrame<'_>) -> String {
    // Persisted provenance is trusted only as a validated object, not as an
    // already-canonical JSON string. Re-render it in the closed kind-specific
    // key order so imported archives cannot perturb a model-visible frame by
    // changing JSON member order or embedding sentinel-shaped punctuation.
    let provenance_json = canonical_provenance_json(frame.kind, frame.provenance_json);
    let payload = format!(
        "{{\"version\":1,\"status\":{},\"reason\":{},\"artifact_id\":{},\"kind\":{},\"capture_reason\":{},\"provenance\":{},\"host_captured_bytes\":{},\"host_original_bytes\":{},\"host_dropped_bytes\":{},\"stored_source_bytes\":{},\"content_bytes\":{},\"line_count\":{},\"preview_head\":{},\"preview_tail\":{},\"guidance\":{}}}",
        json_string(frame.status),
        nullable_string(frame.reason),
        nullable_uuid(frame.artifact_id),
        json_string(frame.kind),
        json_string(frame.capture_reason),
        provenance_json,
        frame.host_captured_bytes,
        frame.host_original_bytes,
        frame.host_dropped_bytes,
        frame.stored_source_bytes,
        frame.content_bytes,
        frame.line_count,
        json_string(frame.preview_head),
        json_string(frame.preview_tail),
        if frame.artifact_id.is_some() {
            json_string(ARTIFACT_FRAME_GUIDANCE)
        } else {
            "null".to_owned()
        },
    );
    format!(
        "<cockpit_artifact_v1 payload_utf8_bytes={}>\n{}\n</cockpit_artifact_v1>",
        payload.len(),
        payload
    )
}

/// Render a persisted accepted-submission envelope by replacing its one
/// authored slot.  Both immediate dispatch and session rehydration must call
/// this function; no caller may parse an artifact frame back into identity.
pub fn render_accepted_user_envelope(
    envelope_json: &str,
    artifact_frame: &str,
) -> Result<Vec<UserContent>> {
    let envelope: serde_json::Value = serde_json::from_str(envelope_json)
        .map_err(|_| anyhow!("invalid accepted user envelope"))?;
    let parts = envelope
        .get("parts")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| anyhow!("accepted user envelope lacks parts"))?;
    let mut rendered = Vec::with_capacity(parts.len());
    let mut slots = 0usize;
    for part in parts {
        let object = part
            .as_object()
            .ok_or_else(|| anyhow!("accepted user envelope part is invalid"))?;
        match object.get("type").and_then(serde_json::Value::as_str) {
            Some("authored_text_slot") => {
                slots += 1;
                rendered.push(UserContent::text(artifact_frame));
            }
            Some("text") => rendered.push(UserContent::text(
                object
                    .get("text")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| anyhow!("accepted text part lacks text"))?,
            )),
            Some(kind @ ("image" | "audio" | "video" | "document" | "tool_result")) => {
                let payload = object
                    .get("payload")
                    .cloned()
                    .ok_or_else(|| anyhow!("accepted typed envelope part lacks payload"))?;
                let content: UserContent = serde_json::from_value(payload)
                    .map_err(|_| anyhow!("accepted typed envelope payload is invalid"))?;
                let matches_kind = matches!(
                    (&content, kind),
                    (UserContent::Image(_), "image")
                        | (UserContent::Audio(_), "audio")
                        | (UserContent::Video(_), "video")
                        | (UserContent::Document(_), "document")
                        | (UserContent::ToolResult(_), "tool_result")
                );
                ensure!(
                    matches_kind,
                    "accepted typed envelope payload has the wrong codec"
                );
                rendered.push(content);
            }
            _ => bail!("accepted user envelope has an unknown part"),
        }
    }
    ensure!(
        slots == 1,
        "accepted user envelope must have one authored slot"
    );
    Ok(rendered)
}

/// The durable accepted composition. Prelude entries are host-synthesized
/// native tool pairs that must precede the rendered user content on both live
/// dispatch and restart; keeping them in the phase-two envelope closes the
/// crash window without duplicating their body as a text guidance part.
pub struct AcceptedUserComposition {
    pub leading: Vec<crate::engine::message::Message>,
    pub content: Vec<UserContent>,
}

pub fn render_accepted_user_composition(
    envelope_json: &str,
    artifact_frame: &str,
) -> Result<AcceptedUserComposition> {
    let value: serde_json::Value = serde_json::from_str(envelope_json)
        .map_err(|_| anyhow!("invalid accepted user envelope"))?;
    let mut leading = Vec::new();
    if let Some(prelude) = value.get("prelude").and_then(serde_json::Value::as_array) {
        for entry in prelude {
            let object = entry
                .as_object()
                .ok_or_else(|| anyhow!("invalid accepted envelope prelude"))?;
            ensure!(
                object.get("type").and_then(serde_json::Value::as_str) == Some("forced_skill"),
                "unknown accepted envelope prelude"
            );
            let call_id = object
                .get("call_id")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| anyhow!("forced prelude lacks call id"))?;
            let _skill_name = object
                .get("name")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| anyhow!("forced prelude lacks name"))?;
            let args = object
                .get("args")
                .and_then(serde_json::Value::as_object)
                .ok_or_else(|| anyhow!("forced prelude args must be an object"))?;
            ensure!(args.len() == 1, "forced prelude args have unknown fields");
            ensure!(
                args.get("name").and_then(serde_json::Value::as_str) == Some(_skill_name),
                "forced prelude args name is invalid"
            );
            let args = serde_json::Value::Object(args.clone());
            let body = object
                .get("body")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| anyhow!("forced prelude lacks body"))?;
            let id = rig::message::ToolCallId::new_or_mint(call_id.to_owned());
            let provider = rig::message::ProviderCallId::new(call_id.to_owned());
            leading.push(crate::engine::message::Message::Assistant {
                id: None,
                content: vec![crate::engine::message::AssistantContent::ToolCall(
                    crate::engine::message::ToolCall {
                        id: id.clone(),
                        provider: provider.clone(),
                        function: rig::message::ToolFunction {
                            name: "skill".to_owned(),
                            arguments: args,
                        },
                        signature: None,
                        additional_params: None,
                    },
                )],
            });
            leading.push(crate::engine::message::Message::User {
                content: vec![UserContent::ToolResult(rig::message::ToolResult {
                    call: id,
                    provider,
                    name: "skill".to_owned(),
                    content: vec![rig::message::ToolResultContent::text(body)],
                })],
            });
        }
    }
    Ok(AcceptedUserComposition {
        leading,
        content: render_accepted_user_envelope(envelope_json, artifact_frame)?,
    })
}

pub fn render_accepted_user_composition_with_redaction(
    envelope_json: &str,
    artifact_frame: &str,
    redaction: &crate::redact::RedactionTable,
) -> Result<AcceptedUserComposition> {
    let mut composition = render_accepted_user_composition(envelope_json, artifact_frame)?;
    composition.leading = composition
        .leading
        .iter()
        .map(|message| {
            crate::engine::model::redact::scrub_message(redaction, message).map_err(|error| {
                anyhow!("accepted envelope prelude has unrenderable outbound content: {error}")
            })
        })
        .collect::<Result<Vec<_>>>()?;
    composition.content = composition
        .content
        .iter()
        .map(|part| {
            crate::engine::model::redact::scrub_user_content(redaction, part).map_err(|error| {
                anyhow!("accepted user envelope has unrenderable outbound content: {error}")
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(composition)
}

/// The sole model-bound rendering path for accepted envelopes. Both live
/// dispatch and resume apply the current outbound redaction at this boundary.
pub fn render_accepted_user_envelope_with_redaction(
    envelope_json: &str,
    artifact_frame: &str,
    redaction: &crate::redact::RedactionTable,
) -> Result<Vec<UserContent>> {
    render_accepted_user_envelope(envelope_json, artifact_frame)?
        .iter()
        .map(|part| {
            crate::engine::model::redact::scrub_user_content(redaction, part).map_err(|error| {
                anyhow!("accepted user envelope has unrenderable outbound content: {error}")
            })
        })
        .collect()
}

/// Build the closed v3 composition for an accepted oversized text submission.
/// The caller supplies only already-resolved non-authored guidance; the source
/// body is deliberately absent and can therefore never be persisted twice.
pub fn accepted_user_envelope_with_guidance(guidance: &str) -> String {
    accepted_user_envelope_with_composition(None, guidance)
}

pub fn accepted_user_envelope_with_composition(
    prelude: Option<serde_json::Value>,
    guidance: &str,
) -> String {
    let mut parts = Vec::new();
    if !guidance.is_empty() {
        parts.push(serde_json::json!({"type":"text","text":guidance}));
    }
    parts.push(serde_json::json!({"type":"authored_text_slot"}));
    let mut envelope = serde_json::json!({"version":3,"parts":parts});
    if let Some(prelude) = prelude {
        envelope["prelude"] = serde_json::json!([prelude]);
    }
    envelope.to_string()
}

/// Persist the actual ordered user-content assembly, replacing only its one
/// authored text contribution.  This preserves any closed media/tool parts
/// around that contribution for resume instead of reconstructing them from a
/// lossy guidance string.
pub fn accepted_user_envelope_from_parts(
    prelude: Option<serde_json::Value>,
    parts: &[UserContent],
    authored_text: &str,
) -> Result<String> {
    let mut encoded = Vec::with_capacity(parts.len());
    let mut slots = 0usize;
    for part in parts {
        match part {
            UserContent::Text(text) if text.text == authored_text => {
                slots += 1;
                encoded.push(serde_json::json!({"type":"authored_text_slot"}));
            }
            UserContent::Text(text) => {
                encoded.push(serde_json::json!({"type":"text","text":text.text}))
            }
            UserContent::Image(_) => encoded
                .push(serde_json::json!({"type":"image","payload":serde_json::to_value(part)?})),
            UserContent::Audio(_) => encoded
                .push(serde_json::json!({"type":"audio","payload":serde_json::to_value(part)?})),
            UserContent::Video(_) => encoded
                .push(serde_json::json!({"type":"video","payload":serde_json::to_value(part)?})),
            UserContent::Document(_) => encoded
                .push(serde_json::json!({"type":"document","payload":serde_json::to_value(part)?})),
            UserContent::ToolResult(_) => encoded.push(
                serde_json::json!({"type":"tool_result","payload":serde_json::to_value(part)?}),
            ),
        }
    }
    ensure!(
        slots == 1,
        "accepted user composition must have exactly one authored text part"
    );
    let mut envelope = serde_json::json!({"version":3,"parts":encoded});
    if let Some(prelude) = prelude {
        envelope["prelude"] = serde_json::json!([prelude]);
    }
    Ok(envelope.to_string())
}

pub fn utf8_preview_pair(value: &str) -> (&str, &str) {
    const EACH: usize = 2 * 1024;
    if value.len() <= EACH * 2 {
        return (value, "");
    }
    let head = bounded_utf8_prefix(value, EACH);
    let tail_start = value.len().saturating_sub(EACH);
    let mut start = tail_start;
    while !value.is_char_boundary(start) {
        start += 1;
    }
    (head, &value[start..])
}

/// Render the model-only projection for one joined oversized-user owner. The
/// source/projection relation is authoritative; callers pass the selected
/// effective artifact and never parse a stored marker to recover identity.
pub fn render_user_input_artifact_frame(
    artifact: &crate::db::text_artifacts::TextArtifact,
) -> anyhow::Result<String> {
    render_user_input_artifact_frame_with_outbound_content(artifact, &artifact.content)
}

/// Render a user frame from a joined immutable owner while taking previews
/// from a value that already crossed the current outbound-safety boundary.
/// Immutable accounting still describes the artifact itself; the supplied
/// value controls model-visible preview text only.
pub fn render_user_input_artifact_frame_with_outbound_content(
    artifact: &crate::db::text_artifacts::TextArtifact,
    outbound_content: &str,
) -> anyhow::Result<String> {
    use crate::db::text_artifacts::{CaptureReason, TextArtifactKind, TextArtifactRelation};

    anyhow::ensure!(
        artifact.capture_reason == CaptureReason::OversizedUserInput,
        "user artifact has an invalid capture reason"
    );
    match (artifact.kind, artifact.relation, artifact.projection_slot) {
        (TextArtifactKind::UserInputSource, TextArtifactRelation::SourceUserInput, None)
        | (
            TextArtifactKind::UserInputProjection,
            TextArtifactRelation::ModelUserInputProjection,
            Some(0),
        ) => {}
        _ => anyhow::bail!("user artifact has an invalid owner relation"),
    }
    let (preview_head, preview_tail) = utf8_preview_pair(outbound_content);
    // User-frame provenance is intentionally independent of the derived
    // artifact's source UUID. A model sees only the effective artifact id.
    let provenance = format!(
        "{{\"event_seq\":{},\"projection_slot\":0}}",
        artifact.event_seq
    );
    Ok(render_artifact_frame(&ArtifactFrame {
        status: "available",
        reason: None,
        artifact_id: Some(artifact.artifact_id),
        kind: "user_input",
        capture_reason: "oversized_user_input",
        provenance_json: &provenance,
        host_captured_bytes: artifact.host_captured_bytes,
        host_original_bytes: artifact.host_original_bytes,
        host_dropped_bytes: artifact.host_dropped_bytes,
        stored_source_bytes: artifact.stored_source_bytes,
        content_bytes: artifact.content_bytes,
        line_count: artifact.content.lines().count(),
        preview_head,
        preview_tail,
    }))
}

/// Return a UTF-8-safe prefix measured in bytes. Callers use this before a
/// utility/provider boundary; it does not normalize or otherwise alter the
/// authored source.
pub fn bounded_utf8_prefix(value: &str, bytes: usize) -> &str {
    if value.len() <= bytes {
        return value;
    }
    let mut end = bytes;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

fn json_string(value: &str) -> String {
    serde_json::to_string(value)
        .expect("serializing a string cannot fail")
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026")
}

fn canonical_provenance_json(kind: &str, raw: &str) -> String {
    let Some(object) = serde_json::from_str::<serde_json::Value>(raw)
        .ok()
        .and_then(|value| value.as_object().cloned())
    else {
        // All production call sites validate provenance before rendering. A
        // defensive malformed value still must not make the surrounding
        // payload invalid or leak through a raw frame fragment.
        return "{}".to_owned();
    };
    match kind {
        "user_input" => {
            let event_seq = object
                .get("event_seq")
                .and_then(serde_json::Value::as_i64)
                .unwrap_or_default();
            let projection_slot = object
                .get("projection_slot")
                .and_then(serde_json::Value::as_i64)
                .unwrap_or_default();
            format!("{{\"event_seq\":{event_seq},\"projection_slot\":{projection_slot}}}")
        }
        "tool_result" => {
            let agent_id = match object.get("agent_id") {
                Some(serde_json::Value::String(value)) => json_string(value),
                _ => "null".to_owned(),
            };
            let tool = object
                .get("tool")
                .and_then(serde_json::Value::as_str)
                .map(json_string)
                .unwrap_or_else(|| json_string(""));
            let call_id = object
                .get("call_id")
                .and_then(serde_json::Value::as_str)
                .map(json_string)
                .unwrap_or_else(|| json_string(""));
            format!("{{\"agent_id\":{agent_id},\"tool\":{tool},\"call_id\":{call_id}}}")
        }
        _ => "{}".to_owned(),
    }
}
fn nullable_string(value: Option<&str>) -> String {
    value.map(json_string).unwrap_or_else(|| "null".to_owned())
}
fn nullable_uuid(value: Option<Uuid>) -> String {
    value
        .map(|id| json_string(&id.to_string()))
        .unwrap_or_else(|| "null".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_has_fixed_key_order_byte_count_and_escaped_nested_provenance() {
        let frame = render_artifact_frame(&ArtifactFrame {
            status: "available",
            reason: None,
            artifact_id: Some(Uuid::from_u128(1)),
            kind: "tool_result",
            capture_reason: "display_truncation",
            provenance_json: r#"{"call_id":"call-\u003c1\u003e","tool":"tool\u0026name","agent_id":"Build"}"#,
            host_captured_bytes: 9,
            host_original_bytes: 11,
            host_dropped_bytes: 2,
            stored_source_bytes: 9,
            content_bytes: 9,
            line_count: 1,
            preview_head: "quote \" slash \\ <tag>&",
            preview_tail: "tail",
        });
        let payload = frame
            .strip_prefix("<cockpit_artifact_v1 payload_utf8_bytes=")
            .and_then(|rest| rest.split_once(">\n"))
            .map(|(declared, rest)| {
                let payload = rest.strip_suffix("\n</cockpit_artifact_v1>").unwrap();
                (declared.parse::<usize>().unwrap(), payload)
            })
            .unwrap();
        assert_eq!(payload.0, payload.1.len());
        assert_eq!(
            payload.1,
            r#"{"version":1,"status":"available","reason":null,"artifact_id":"00000000-0000-0000-0000-000000000001","kind":"tool_result","capture_reason":"display_truncation","provenance":{"agent_id":"Build","tool":"tool\u0026name","call_id":"call-\u003c1\u003e"},"host_captured_bytes":9,"host_original_bytes":11,"host_dropped_bytes":2,"stored_source_bytes":9,"content_bytes":9,"line_count":1,"preview_head":"quote \" slash \\ \u003ctag\u003e\u0026","preview_tail":"tail","guidance":"Use artifact_read or artifact_search with artifact_id to inspect this retained text."}"#
        );
    }

    #[test]
    fn preview_pair_is_utf8_safe_and_uses_two_kibibytes_per_side() {
        let value = format!("{}{}", "é".repeat(2_049), "z".repeat(4_096));
        let (head, tail) = utf8_preview_pair(&value);
        assert!(head.len() <= 2 * 1024);
        assert!(tail.len() <= 2 * 1024);
        assert!(value.starts_with(head));
        assert!(value.ends_with(tail));
        assert!(head.is_char_boundary(head.len()));
        assert!(tail.is_char_boundary(0));
    }

    #[test]
    fn accepted_envelope_preserves_guidance_and_closed_typed_parts_in_order() {
        let image =
            UserContent::image_base64("YWJj", Some(rig::message::ImageMediaType::PNG), None);
        let envelope = serde_json::json!({
            "version": 3,
            "parts": [
                {"type":"text","text":"auto skill\n"},
                {"type":"image","payload": serde_json::to_value(&image).unwrap()},
                {"type":"authored_text_slot"},
                {"type":"text","text":"context tag"}
            ]
        });
        let rendered = render_accepted_user_envelope(&envelope.to_string(), "<frame>").unwrap();
        assert_eq!(
            rendered,
            vec![
                UserContent::text("auto skill\n"),
                image,
                UserContent::text("<frame>"),
                UserContent::text("context tag")
            ]
        );
    }

    #[test]
    fn accepted_composition_keeps_forced_prelude_once_and_parts_ordered() {
        let image =
            UserContent::image_base64("YWJj", Some(rig::message::ImageMediaType::PNG), None);
        let envelope = serde_json::json!({
            "version": 3,
            "prelude": [{"type":"forced_skill","call_id":"fc-skillslash-test","name":"skill","args":{"name":"skill"},"body":"FORCED","hard_fail":false}],
            "parts": [
                {"type":"text","text":"AUTO"},
                {"type":"image","payload":serde_json::to_value(&image).unwrap()},
                {"type":"authored_text_slot"},
                {"type":"text","text":"TAG"}
            ]
        });
        let composition =
            render_accepted_user_composition(&envelope.to_string(), "<frame>").unwrap();
        assert_eq!(composition.leading.len(), 2);
        assert_eq!(
            composition.content,
            vec![
                UserContent::text("AUTO"),
                image,
                UserContent::text("<frame>"),
                UserContent::text("TAG")
            ]
        );
    }

    #[test]
    fn accepted_composition_rejects_malformed_forced_prelude_args() {
        for args in [
            serde_json::json!(["skill"]),
            serde_json::json!("skill"),
            serde_json::json!({"name":"other"}),
            serde_json::json!({"name":"skill","extra":true}),
        ] {
            let envelope = serde_json::json!({"version":3,"prelude":[{"type":"forced_skill","call_id":"call","name":"skill","args":args,"body":"body","hard_fail":false}],"parts":[{"type":"authored_text_slot"}]});
            assert!(render_accepted_user_composition(&envelope.to_string(), "<frame>").is_err());
        }
    }
}
