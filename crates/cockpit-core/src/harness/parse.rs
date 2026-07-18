//! Lenient JSON-metadata extraction from harness stdout.
//!
//! Different harnesses emit metadata differently (a single trailing JSON
//! object, a stream of JSONL events, or prose with a JSON tail). We try
//! whole-stdout JSON first, then scan trailing lines for a JSON object
//! carrying a known key. Adapted from ralph-rs `parse_harness_json`;
//! cockpit recognizes a slightly wider key vocabulary so claude/codex/
//! opencode metadata all land.

use serde_json::Value;

/// Structured metadata a harness may report in JSON output. All fields
/// optional — a harness that emits none leaves them `None`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct HarnessMetadata {
    /// Cost in USD, if reported.
    pub cost_usd: Option<f64>,
    /// Input/prompt tokens.
    pub input_tokens: Option<i64>,
    /// Output/completion tokens.
    pub output_tokens: Option<i64>,
    /// Total tokens, if the harness reports a combined figure.
    pub total_tokens: Option<i64>,
    /// The harness's own session id (claude `session_id`, codex thread,
    /// etc.), useful for the user to resume the external session.
    pub session_id: Option<String>,
}

impl HarnessMetadata {
    /// Whether any field is populated.
    pub fn is_empty(&self) -> bool {
        *self == HarnessMetadata::default()
    }

    /// A terse one-line summary for inclusion in the structured result,
    /// or `None` when no metadata was parsed (so the caller omits the
    /// line — token economy).
    pub fn summary_line(&self) -> Option<String> {
        if self.is_empty() {
            return None;
        }
        let mut parts = Vec::new();
        if let Some(c) = self.cost_usd {
            parts.push(format!("cost=${c:.4}"));
        }
        match (self.input_tokens, self.output_tokens) {
            (Some(i), Some(o)) => parts.push(format!("tokens={}in/{}out", i, o)),
            _ => {
                if let Some(t) = self.total_tokens {
                    parts.push(format!("tokens={t}"));
                }
            }
        }
        if let Some(s) = &self.session_id {
            parts.push(format!("session={s}"));
        }
        if parts.is_empty() {
            None
        } else {
            Some(parts.join(" "))
        }
    }
}

/// Extract [`HarnessMetadata`] from `stdout`, leniently. Tries the whole
/// string as JSON first, then scans lines in reverse (structured output
/// is usually at the end), accepting the first JSON object carrying a
/// recognized key.
pub fn parse_harness_json(stdout: &str) -> HarnessMetadata {
    if let Some(m) = try_parse(stdout) {
        return m;
    }
    for line in stdout.lines().rev() {
        let trimmed = line.trim();
        if trimmed.starts_with('{')
            && let Some(m) = try_parse(trimmed)
        {
            return m;
        }
    }
    HarnessMetadata::default()
}

/// Parse `text` as a JSON object and pull known keys, including a couple
/// of nested shapes (`usage.{input,output}_tokens`,
/// `usage.{prompt,completion}_tokens`) that claude/codex emit. Returns
/// `None` unless at least one recognized key is present.
fn try_parse(text: &str) -> Option<HarnessMetadata> {
    let val: Value = serde_json::from_str(text).ok()?;
    let obj = val.as_object()?;

    let usage = obj.get("usage").and_then(Value::as_object);

    let input_tokens = obj
        .get("input_tokens")
        .and_then(Value::as_i64)
        .or_else(|| usage.and_then(|u| u.get("input_tokens").and_then(Value::as_i64)))
        .or_else(|| usage.and_then(|u| u.get("prompt_tokens").and_then(Value::as_i64)));
    let output_tokens = obj
        .get("output_tokens")
        .and_then(Value::as_i64)
        .or_else(|| usage.and_then(|u| u.get("output_tokens").and_then(Value::as_i64)))
        .or_else(|| usage.and_then(|u| u.get("completion_tokens").and_then(Value::as_i64)));
    let total_tokens = obj
        .get("total_tokens")
        .and_then(Value::as_i64)
        .or_else(|| usage.and_then(|u| u.get("total_tokens").and_then(Value::as_i64)));
    let cost_usd = obj
        .get("cost_usd")
        .and_then(Value::as_f64)
        .or_else(|| obj.get("total_cost_usd").and_then(Value::as_f64));
    let session_id = obj
        .get("session_id")
        .and_then(Value::as_str)
        .or_else(|| obj.get("sessionId").and_then(Value::as_str))
        .or_else(|| obj.get("thread_id").and_then(Value::as_str))
        .map(str::to_string);

    let m = HarnessMetadata {
        cost_usd,
        input_tokens,
        output_tokens,
        total_tokens,
        session_id,
    };
    if m.is_empty() { None } else { Some(m) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn whole_stdout_json() {
        let s = r#"{"cost_usd":0.05,"input_tokens":1000,"output_tokens":500,"session_id":"s1"}"#;
        let m = parse_harness_json(s);
        assert_eq!(m.cost_usd, Some(0.05));
        assert_eq!(m.input_tokens, Some(1000));
        assert_eq!(m.output_tokens, Some(500));
        assert_eq!(m.session_id.as_deref(), Some("s1"));
    }

    #[test]
    fn trailing_json_after_prose() {
        let s = "some output\nprocessing...\n{\"cost_usd\":0.03,\"session_id\":\"abc\"}\n";
        let m = parse_harness_json(s);
        assert_eq!(m.cost_usd, Some(0.03));
        assert_eq!(m.session_id.as_deref(), Some("abc"));
    }

    #[test]
    fn nested_usage_shape() {
        // claude-style result object with a nested usage block.
        let s =
            r#"{"type":"result","session_id":"x","usage":{"input_tokens":12,"output_tokens":7}}"#;
        let m = parse_harness_json(s);
        assert_eq!(m.input_tokens, Some(12));
        assert_eq!(m.output_tokens, Some(7));
        assert_eq!(m.session_id.as_deref(), Some("x"));
    }

    #[test]
    fn openai_usage_aliases() {
        let s = r#"{"usage":{"prompt_tokens":3,"completion_tokens":9,"total_tokens":12}}"#;
        let m = parse_harness_json(s);
        assert_eq!(m.input_tokens, Some(3));
        assert_eq!(m.output_tokens, Some(9));
        assert_eq!(m.total_tokens, Some(12));
    }

    #[test]
    fn grok_camel_case_session_id() {
        let s = r#"{"text":"OK.","stopReason":"EndTurn","sessionId":"s-grok","requestId":"r1"}"#;
        let m = parse_harness_json(s);
        assert_eq!(m.session_id.as_deref(), Some("s-grok"));
    }

    #[test]
    fn no_json_yields_empty() {
        let m = parse_harness_json("just prose, no metadata here");
        assert!(m.is_empty());
        assert!(m.summary_line().is_none());
    }

    #[test]
    fn unrelated_json_ignored() {
        // A JSON object with no recognized key is not metadata.
        let m = parse_harness_json(r#"{"foo":"bar"}"#);
        assert!(m.is_empty());
    }

    #[test]
    fn jsonl_last_event_wins() {
        let s = "{\"type\":\"start\"}\n{\"input_tokens\":5,\"output_tokens\":6}\n";
        let m = parse_harness_json(s);
        assert_eq!(m.input_tokens, Some(5));
        assert_eq!(m.output_tokens, Some(6));
    }

    #[test]
    fn summary_line_formats() {
        let m = HarnessMetadata {
            cost_usd: Some(0.12),
            input_tokens: Some(100),
            output_tokens: Some(50),
            total_tokens: None,
            session_id: Some("abc".to_string()),
        };
        let line = m.summary_line().unwrap();
        assert!(line.contains("cost=$0.1200"));
        assert!(line.contains("tokens=100in/50out"));
        assert!(line.contains("session=abc"));
    }
}
