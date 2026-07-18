//! Structured subagent return envelope (`structured-subagent-return
//! -summary.md`).
//!
//! Every delegated subagent (`builder`/`explore` + custom
//! subagents — **not** the `docs` Q&A pipeline, which is exempt) ends its run
//! by returning a *structured summary* rather than free prose, so the caller
//! (especially `Build`) can decide its next step without re-deriving it from
//! text. The summary has two kinds of field:
//!
//! - **Model-authored** (`accomplished`/`decisions_made`/`context_for_next`/
//!   `remaining`): filled by the subagent via the structural `return` tool
//!   ([`crate::tools::return_tool`]). These share the subagent-report token cap
//!   and are dropped/truncated deterministically across the combined set.
//! - **Host-authored** `files_changed`: the paths the child wrote/edited,
//!   derived deterministically from the child's own write/edit/unlock tool
//!   calls in its frame — **never** the model. It reuses the `compact.rs`
//!   file-edit ledger ([`super::compact::FileEdit`]) and self-empties for a
//!   read-only subagent (e.g. `explore`).
//!
//! Weak-model robustness (priority #1): a subagent that ends WITHOUT calling
//! `return` still yields a valid envelope — its final text is wrapped as
//! `accomplished` and the other model-authored fields are left empty
//! ([`Envelope::from_final_text`]). The host-authored `files_changed` is always
//! attached either way.

use serde_json::Value;

use super::compact::FileEdit;
use super::message::{AssistantContent, Message};
use crate::intel::budget::BudgetedWriter;

/// Combined token cap for the **model-authored** fields of the envelope — the
/// established subagent-report budget (§10). The host-authored `files_changed`
/// ledger is deterministic and rides outside this cap (it is a factual record,
/// not model prose).
pub const RETURN_MODEL_FIELDS_TOKEN_CAP: usize = crate::engine::schedule::ASYNC_RESULT_TOKEN_CAP;

/// The structured summary a delegated subagent returns to its caller. The
/// model-authored fields are filled by the `return` tool (or, on the fallback
/// path, `accomplished` carries the subagent's final text); `files_changed` is
/// always host-derived.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Envelope {
    /// What the subagent did. The one required model-authored field; also the
    /// fallback slot for a subagent that ended without calling `return`.
    pub accomplished: String,
    /// Decisions taken while doing it, so the caller doesn't re-litigate them.
    pub decisions_made: String,
    /// Anything the caller needs to guide its next step.
    pub context_for_next: String,
    /// What was deliberately not done / follow-ups.
    pub remaining: String,
    /// Host-derived: the paths the child wrote/edited (with content hash when
    /// known). Empty for a read-only subagent.
    pub files_changed: Vec<FileEdit>,
}

impl Envelope {
    /// Build the envelope from a (already validate-then-repaired) `return`
    /// tool-call argument object. Missing/blank fields default to empty —
    /// the schema only requires `accomplished`, and the repair layer (§12)
    /// guarantees it is a string. `files_changed` is attached separately by
    /// the caller (it is host-authored, never in `args`).
    pub fn from_return_args(args: &Value) -> Self {
        Self {
            accomplished: string_field(args, "accomplished"),
            decisions_made: string_field(args, "decisions_made"),
            context_for_next: string_field(args, "context_for_next"),
            remaining: string_field(args, "remaining"),
            files_changed: Vec::new(),
        }
    }

    /// Fallback envelope for a subagent that finished WITHOUT calling `return`
    /// (priority #1: the delegation must still yield a valid envelope, never
    /// fail). The final text becomes `accomplished`; the other model-authored
    /// fields stay empty. `files_changed` is attached separately.
    pub fn from_final_text(final_text: impl Into<String>) -> Self {
        Self {
            accomplished: final_text.into(),
            ..Self::default()
        }
    }

    /// Attach the host-derived `files_changed` ledger (consuming `files`).
    pub fn with_files_changed(mut self, files: Vec<FileEdit>) -> Self {
        self.files_changed = files;
        self
    }

    /// Render the envelope to the report string the caller ingests as this
    /// delegation's tool result. The model-authored fields are written through
    /// a [`BudgetedWriter`] capped at [`RETURN_MODEL_FIELDS_TOKEN_CAP`] —
    /// whole fields are dropped (and a terse truncation note appended) the
    /// moment the next field would push past the cap, deterministically,
    /// preserving the tool-result pairing. The host-authored `files_changed`
    /// section is appended *after* the cap (it is a factual ledger).
    pub fn render(&self) -> String {
        let mut writer = BudgetedWriter::new(RETURN_MODEL_FIELDS_TOKEN_CAP);

        // `accomplished` always leads. An empty `accomplished` (a subagent that
        // emitted neither final text nor a filled field) still renders the
        // header so the caller sees a well-formed, non-empty envelope.
        let accomplished = if self.accomplished.trim().is_empty() {
            "(none reported)"
        } else {
            self.accomplished.trim()
        };
        let truncated = !writer.write(&format!("## Accomplished\n{accomplished}\n"));

        let mut truncated = truncated;
        for (heading, body) in [
            ("Decisions made", self.decisions_made.trim()),
            ("Context for next step", self.context_for_next.trim()),
            ("Remaining / follow-ups", self.remaining.trim()),
        ] {
            if body.is_empty() {
                continue;
            }
            if !writer.write(&format!("\n## {heading}\n{body}\n")) {
                truncated = true;
            }
        }

        let mut out = writer.into_string();
        if truncated {
            out.push_str("\n[note: some fields were truncated to stay within the report budget]\n");
        }

        // Host-authored ledger — deterministic, outside the model-field cap.
        if !self.files_changed.is_empty() {
            out.push_str("\n## Files changed\n");
            for f in &self.files_changed {
                match &f.hash {
                    Some(h) => out.push_str(&format!("- `{}` (hash {})\n", f.path, h)),
                    None => out.push_str(&format!("- `{}`\n", f.path)),
                }
            }
        }
        out
    }
}

/// Derive the host-authored `files_changed` ledger from a subagent's own
/// in-memory frame (`history`) — the precise, frame-scoped source of truth,
/// independent of DB write timing. Walks the child's assistant turns for
/// `writeunlock`/`editunlock`/`unlock` tool calls (the single-writer mutate
/// set), pulls the path from each call's arguments, and the content hash from
/// the call's arguments or its matching tool-result output header. Reuses the
/// `compact.rs` file-edit ledger ([`super::compact::record_edit`]) so the
/// edited set is derived exactly as the `/compact` appendix derives it. Empty
/// for a read-only subagent that issued no such calls.
pub fn files_changed_from_history(history: &[Message]) -> Vec<FileEdit> {
    // Index tool-result output by the tool-call id it answers, so a call's
    // hash can fall back to its result's output header.
    let outputs = tool_result_outputs(history);

    let mut edited: Vec<FileEdit> = Vec::new();
    for msg in history {
        let Message::Assistant { content, .. } = msg else {
            continue;
        };
        for part in content.iter() {
            let AssistantContent::ToolCall(tc) = part else {
                continue;
            };
            if !matches!(
                tc.function.name.as_str(),
                "writeunlock" | "editunlock" | "unlock"
            ) {
                continue;
            }
            let Some(path) = super::compact::arg_path(&tc.function.arguments) else {
                continue;
            };
            let hash = super::compact::arg_hash(&tc.function.arguments).or_else(|| {
                outputs
                    .get(&tc.id)
                    .and_then(|o| super::compact::hash_from_output(o))
            });
            super::compact::record_edit(&mut edited, path, hash);
        }
    }
    edited
}

/// Map tool-call id → concatenated text output of the tool-result message that
/// answers it (for the hash fallback in [`files_changed_from_history`]).
fn tool_result_outputs(history: &[Message]) -> std::collections::HashMap<String, String> {
    use rig::message::{ToolResultContent, UserContent};

    let mut out = std::collections::HashMap::new();
    for msg in history {
        let Message::User { content } = msg else {
            continue;
        };
        for part in content.iter() {
            if let UserContent::ToolResult(tr) = part {
                let text: String = tr
                    .content
                    .iter()
                    .filter_map(|c| match c {
                        ToolResultContent::Text(t) => Some(t.text.clone()),
                        _ => None,
                    })
                    .collect::<Vec<_>>()
                    .join("");
                out.insert(tr.id.clone(), text);
            }
        }
    }
    out
}

fn string_field(args: &Value, key: &str) -> String {
    args.get(key)
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rig::OneOrMany;
    use rig::message::{ToolCall, ToolFunction};
    use serde_json::json;

    fn assistant_write(id: &str, path: &str) -> Message {
        Message::Assistant {
            id: None,
            content: OneOrMany::one(AssistantContent::ToolCall(ToolCall {
                id: id.to_string(),
                call_id: None,
                function: ToolFunction {
                    name: "writeunlock".to_string(),
                    arguments: json!({ "path": path }),
                },
                signature: None,
                additional_params: None,
            })),
        }
    }

    fn tool_result(id: &str, output: &str) -> Message {
        Message::tool_result_with_call_id(id.to_string(), None, output.to_string())
    }

    fn assistant_text(text: &str) -> Message {
        Message::Assistant {
            id: None,
            content: OneOrMany::one(AssistantContent::text(text)),
        }
    }

    #[test]
    fn files_changed_derived_from_write_calls_with_hash_from_output() {
        let history = vec![
            assistant_write("c1", "/a.rs"),
            tool_result("c1", "[hash=abc123 ok] wrote /a.rs"),
            // Same path written again — later call wins; no new hash here, so
            // the earlier hash is retained.
            assistant_write("c2", "/a.rs"),
            tool_result("c2", "ok"),
            assistant_write("c3", "/b.rs"),
            tool_result("c3", "[hash=def456 ok]"),
        ];
        let files = files_changed_from_history(&history);
        assert_eq!(files.len(), 2);
        let a = files.iter().find(|f| f.path == "/a.rs").unwrap();
        assert_eq!(a.hash.as_deref(), Some("abc123"));
        let b = files.iter().find(|f| f.path == "/b.rs").unwrap();
        assert_eq!(b.hash.as_deref(), Some("def456"));
    }

    #[test]
    fn read_only_history_yields_empty_files_changed() {
        // An `explore`-style frame: only text + (hypothetical) read calls, no
        // write/edit/unlock → empty ledger.
        let history = vec![assistant_text("I looked and found the bug in foo.rs")];
        assert!(files_changed_from_history(&history).is_empty());
    }

    #[test]
    fn from_return_args_fills_model_fields_and_trims() {
        let env = Envelope::from_return_args(&json!({
            "accomplished": "  added the flag  ",
            "decisions_made": "used u32",
            "context_for_next": "",
        }));
        assert_eq!(env.accomplished, "added the flag");
        assert_eq!(env.decisions_made, "used u32");
        assert_eq!(env.context_for_next, "");
        assert_eq!(env.remaining, "");
    }

    #[test]
    fn from_final_text_wraps_as_accomplished() {
        let env = Envelope::from_final_text("did the thing");
        assert_eq!(env.accomplished, "did the thing");
        assert!(env.decisions_made.is_empty());
        assert!(env.context_for_next.is_empty());
        assert!(env.remaining.is_empty());
    }

    #[test]
    fn render_includes_files_changed_section() {
        let env = Envelope::from_return_args(&json!({ "accomplished": "wrote it" }))
            .with_files_changed(vec![FileEdit {
                path: "/a.rs".into(),
                hash: Some("abc123".into()),
            }]);
        let r = env.render();
        assert!(r.contains("## Accomplished"));
        assert!(r.contains("wrote it"));
        assert!(r.contains("## Files changed"));
        assert!(r.contains("/a.rs"));
        assert!(r.contains("abc123"));
    }

    #[test]
    fn render_omits_empty_model_fields_and_files_section() {
        let env = Envelope::from_final_text("just text");
        let r = env.render();
        assert!(r.contains("## Accomplished"));
        assert!(r.contains("just text"));
        assert!(!r.contains("## Decisions made"));
        assert!(!r.contains("## Files changed"));
    }

    #[test]
    fn render_caps_combined_model_fields() {
        // A huge field blows the model-field cap; the truncation note fires and
        // the host-authored files section still renders after the cap.
        let big = "word ".repeat(RETURN_MODEL_FIELDS_TOKEN_CAP * 2);
        let env = Envelope {
            accomplished: "ok".into(),
            decisions_made: big,
            context_for_next: String::new(),
            remaining: String::new(),
            files_changed: vec![FileEdit {
                path: "/a.rs".into(),
                hash: None,
            }],
        };
        let r = env.render();
        assert!(r.contains("## Accomplished"));
        assert!(r.contains("truncated to stay within the report budget"));
        // The dropped field is absent; the deterministic files section survives.
        assert!(!r.contains("## Decisions made"));
        assert!(r.contains("## Files changed"));
        assert!(r.contains("/a.rs"));
    }
}
