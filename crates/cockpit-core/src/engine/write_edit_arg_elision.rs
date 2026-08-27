//! Elide applied `write`/`edit` arguments from model-visible history.
//!
//! After a `write` or `edit` succeeds, the call arguments (file content,
//! `old_string`/`new_string`) duplicate information the model already has:
//! the tool result carries the diff, and the file is on disk. Large args
//! dominate context, so this pass stubs those values out of the **model-bound**
//! assistant tool-call — in memory only, never the durable audit row.
//!
//! This is the sibling of [`super::delegation_prompt_prune`]: a pure
//! projection, idempotent, applied identically on the live path and in
//! [`super::rehydrate`].
//!
//! ## Model-recall cost
//!
//! A later `edit` `old_string` must match the file. After elision the model
//! reconstructs that text from the result diff or re-reads the file. The
//! size floor plus the diff-carrying result are the mitigation: small edits
//! stay verbatim because recall value exceeds savings.
//!
//! ## Cache
//!
//! Eliding a *settled* call diverges the prefix at that call. Done
//! consistently from the moment a call settles, the divergence is always
//! near the tail (a few messages of re-tokenization). Retroactive elision
//! of old calls outside this rule is forbidden.
//!
//! ## Signed-thinking tripwire
//!
//! Anthropic 400s if the latest assistant message carries signed reasoning
//! and any sibling block is rewritten. Elide unsigned settled calls as soon
//! as the matching successful result is available. Skip the latest assistant
//! message while it still carries signed reasoning; once a newer assistant
//! message exists the prior turn is settled and may be rewritten.

use std::collections::HashSet;

use rig::message::UserContent;
use serde_json::Value;

use crate::engine::message::{AssistantContent, Message, ToolCall};

const MIN_TOKENS_SAVED: usize = 96;

/// Distinct from `/prune`'s `[elided:` prefix so [`crate::engine::prune::Elision`]
/// ledger capture never classifies an applied-arg stub as a pruned result body.
pub const APPLIED_MARKER_PREFIX: &str = "[applied:";

pub fn applied_marker(byte_len: usize) -> String {
    format!(
        "[applied: {n} bytes — see result diff]",
        n = format_byte_count(byte_len)
    )
}

pub fn is_applied_marker(value: &str) -> bool {
    value.starts_with(APPLIED_MARKER_PREFIX)
}

pub fn elide_applied_write_edit_args(history: &mut [Message]) -> usize {
    elide_applied_write_edit_args_with_upcoming(history, None)
}

pub fn elide_applied_write_edit_args_with_upcoming(
    history: &mut [Message],
    upcoming_result: Option<&Message>,
) -> usize {
    let successful = successful_write_edit_ids(history, upcoming_result);
    if successful.is_empty() {
        return 0;
    }

    let last_assistant = history
        .iter()
        .rposition(|msg| matches!(msg, Message::Assistant { .. }));

    let mut changed = 0;
    for (idx, msg) in history.iter_mut().enumerate() {
        let Message::Assistant { content, .. } = msg else {
            continue;
        };
        if last_assistant == Some(idx) && assistant_has_signed_reasoning(content) {
            continue;
        }
        for part in content.iter_mut() {
            let AssistantContent::ToolCall(tc) = part else {
                continue;
            };
            if !successful.contains(tc.id.as_str()) {
                continue;
            }
            changed += elide_tool_call(tc);
        }
    }
    changed
}

/// Project `write`/`edit` args to the same stubbed form used in history so
/// [`crate::approval::store::GrantStore::loop_signature`] agrees on both the
/// current call (still full) and a historical call (already elided).
pub fn args_for_loop_hash(tool: &str, args: &Value) -> Value {
    if !matches!(tool, "write" | "edit") {
        return args.clone();
    }
    let mut projected = args.clone();
    stub_large_string_fields(&mut projected);
    projected
}

fn elide_tool_call(tc: &mut ToolCall) -> usize {
    if !matches!(tc.function.name.as_str(), "write" | "edit") {
        return 0;
    }
    if stub_large_string_fields(&mut tc.function.arguments) > 0 {
        1
    } else {
        0
    }
}

fn stub_large_string_fields(args: &mut Value) -> usize {
    let Some(obj) = args.as_object_mut() else {
        return 0;
    };
    let keys: Vec<String> = obj.keys().cloned().collect();
    let mut changed = 0;
    for key in keys {
        if key == "path" {
            continue;
        }
        let Some(original) = obj.get(&key).and_then(Value::as_str).map(str::to_string) else {
            continue;
        };
        if is_applied_marker(&original) {
            continue;
        }
        let replacement = applied_marker(original.len());
        if original == replacement {
            continue;
        }
        let before = crate::tokens::count(&original);
        let after = crate::tokens::count(&replacement);
        if before.saturating_sub(after) < MIN_TOKENS_SAVED {
            continue;
        }
        obj.insert(key, Value::String(replacement));
        changed += 1;
    }
    changed
}

fn successful_write_edit_ids(
    history: &[Message],
    upcoming_result: Option<&Message>,
) -> HashSet<String> {
    let mut out = HashSet::new();
    for msg in history {
        collect_successful_write_edit_ids(msg, &mut out);
    }
    if let Some(msg) = upcoming_result {
        collect_successful_write_edit_ids(msg, &mut out);
    }
    out
}

fn collect_successful_write_edit_ids(msg: &Message, out: &mut HashSet<String>) {
    let Message::User { content } = msg else {
        return;
    };
    for part in content.iter() {
        let UserContent::ToolResult(tr) = part else {
            continue;
        };
        if !matches!(tr.name.as_str(), "write" | "edit") {
            continue;
        }
        let body = tool_result_text(&tr.content);
        if result_indicates_applied(&tr.name, &body) {
            out.insert(tr.call.to_string());
        }
    }
}

fn result_indicates_applied(tool: &str, body: &str) -> bool {
    if body.starts_with("Error:") {
        return false;
    }
    match tool {
        "write" => body.starts_with("wrote `"),
        "edit" => body.starts_with("edited `"),
        _ => false,
    }
}

fn tool_result_text(content: &[rig::message::ToolResultContent]) -> String {
    content
        .iter()
        .filter_map(|part| match part {
            rig::message::ToolResultContent::Text(text) => Some(text.text.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("")
}

fn assistant_has_signed_reasoning(content: &[AssistantContent]) -> bool {
    content.iter().any(|part| {
        matches!(
            part,
            AssistantContent::Reasoning(reasoning)
                if reasoning.content.iter().any(|item| {
                    matches!(
                        item,
                        rig::message::ReasoningContent::Text {
                            signature: Some(signature),
                            ..
                        } if !signature.is_empty()
                    )
                })
        )
    })
}

fn format_byte_count(n: usize) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, ch) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(ch);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rig::message::ToolFunction;
    use serde_json::json;

    fn long_payload() -> String {
        let mut s = String::new();
        while crate::tokens::count(&s) < 140 {
            s.push_str(
                "fn example() { let value = expensive_computation(); println!(\"{value}\"); }\n",
            );
        }
        s
    }

    fn short_payload() -> String {
        "tiny".to_string()
    }

    fn assistant_call(id: &str, name: &str, arguments: Value) -> Message {
        Message::Assistant {
            id: None,
            content: vec![AssistantContent::ToolCall(ToolCall {
                id: rig::message::ToolCallId::new_or_mint(id.to_string()),
                provider: None,
                function: ToolFunction {
                    name: name.to_string(),
                    arguments,
                },
                signature: None,
                additional_params: None,
            })],
        }
    }

    fn signed_assistant_call(id: &str, name: &str, arguments: Value) -> Message {
        Message::Assistant {
            id: None,
            content: vec![
                AssistantContent::Reasoning(rig::message::Reasoning::new_with_signature(
                    "provider signed thinking",
                    Some("sig-native".into()),
                )),
                AssistantContent::ToolCall(ToolCall {
                    id: rig::message::ToolCallId::new_or_mint(id.to_string()),
                    provider: None,
                    function: ToolFunction {
                        name: name.to_string(),
                        arguments,
                    },
                    signature: None,
                    additional_params: None,
                }),
            ],
        }
    }

    fn write_result(id: &str, body: &str) -> Message {
        crate::engine::message::synthetic_tool_result_message_with_provider_identity(
            id.to_string(),
            None,
            None,
            "write",
            body.to_string(),
        )
    }

    fn edit_result(id: &str, body: &str) -> Message {
        crate::engine::message::synthetic_tool_result_message_with_provider_identity(
            id.to_string(),
            None,
            None,
            "edit",
            body.to_string(),
        )
    }

    fn first_call_args(msg: &Message) -> Value {
        let Message::Assistant { content, .. } = msg else {
            panic!("assistant");
        };
        let AssistantContent::ToolCall(tc) = content
            .iter()
            .find(|part| matches!(part, AssistantContent::ToolCall(_)))
            .unwrap()
        else {
            panic!("tool call");
        };
        tc.function.arguments.clone()
    }

    fn object_keys(args: &Value) -> Vec<String> {
        args.as_object()
            .expect("tool_use.input must remain an object")
            .keys()
            .cloned()
            .collect()
    }

    #[test]
    fn applied_marker_uses_distinct_prefix_and_thousands_separators() {
        let marker = applied_marker(41_213);
        assert_eq!(marker, "[applied: 41,213 bytes — see result diff]");
        assert!(is_applied_marker(&marker));
        assert!(!marker.starts_with("[elided:"));
        assert!(!crate::engine::prune::Elision::is_marker(&marker));
        assert!(!crate::engine::prune::Elision::contains_marker(&marker));
    }

    #[test]
    fn elides_completed_long_write_content_and_is_idempotent() {
        let content = long_payload();
        let mut history = vec![
            assistant_call(
                "w1",
                "write",
                json!({ "path": "src/lib.rs", "content": content }),
            ),
            write_result("w1", "wrote `src/lib.rs` (1200 bytes, LF)"),
        ];

        assert_eq!(elide_applied_write_edit_args(&mut history), 1);
        let args = first_call_args(&history[0]);
        assert_eq!(args["path"], json!("src/lib.rs"));
        assert_eq!(args["content"], json!(applied_marker(content.len())));
        assert_eq!(
            object_keys(&args),
            vec!["path".to_string(), "content".to_string()]
        );
        assert_eq!(elide_applied_write_edit_args(&mut history), 0);
    }

    #[test]
    fn elides_completed_long_edit_strings_preserving_key_set() {
        let old = long_payload();
        let new = long_payload();
        let mut history = vec![
            assistant_call(
                "e1",
                "edit",
                json!({
                    "path": "src/main.rs",
                    "old_string": old,
                    "new_string": new,
                    "replace_all": false
                }),
            ),
            edit_result("e1", "edited `src/main.rs` (exact; 800 bytes)"),
        ];

        assert_eq!(elide_applied_write_edit_args(&mut history), 1);
        let args = first_call_args(&history[0]);
        assert_eq!(args["path"], json!("src/main.rs"));
        assert_eq!(args["replace_all"], json!(false));
        assert_eq!(args["old_string"], json!(applied_marker(old.len())));
        assert_eq!(args["new_string"], json!(applied_marker(new.len())));
        let mut keys = object_keys(&args);
        keys.sort();
        assert_eq!(
            keys,
            vec![
                "new_string".to_string(),
                "old_string".to_string(),
                "path".to_string(),
                "replace_all".to_string()
            ]
        );
    }

    #[test]
    fn leaves_short_write_content_unchanged() {
        let mut history = vec![
            assistant_call(
                "w1",
                "write",
                json!({ "path": "n.txt", "content": short_payload() }),
            ),
            write_result("w1", "wrote `n.txt` (4 bytes, LF)"),
        ];

        assert_eq!(elide_applied_write_edit_args(&mut history), 0);
        assert_eq!(
            first_call_args(&history[0])["content"],
            json!(short_payload())
        );
    }

    #[test]
    fn path_is_never_elided_even_when_huge() {
        let huge_path = long_payload();
        let content = long_payload();
        let mut history = vec![
            assistant_call(
                "w1",
                "write",
                json!({ "path": huge_path, "content": content }),
            ),
            write_result("w1", "wrote `long/path` (1200 bytes, LF)"),
        ];

        assert_eq!(elide_applied_write_edit_args(&mut history), 1);
        let args = first_call_args(&history[0]);
        assert_eq!(args["path"], json!(huge_path));
        assert_eq!(
            crate::engine::compact::arg_path(&args).as_deref(),
            Some(huge_path.as_str())
        );
        assert!(is_applied_marker(args["content"].as_str().unwrap()));
    }

    #[test]
    fn failed_calls_are_never_elided() {
        let content = long_payload();
        let mut history = vec![
            assistant_call(
                "w1",
                "write",
                json!({ "path": "blocked/file.md", "content": content }),
            ),
            write_result("w1", "Error: `blocked/file.md` is not a directory"),
        ];

        assert_eq!(elide_applied_write_edit_args(&mut history), 0);
        assert_eq!(first_call_args(&history[0])["content"], json!(content));
    }

    #[test]
    fn identity_refusal_is_not_treated_as_applied() {
        let content = long_payload();
        let mut history = vec![
            assistant_call(
                "w1",
                "write",
                json!({ "path": "SOUL.md", "content": content }),
            ),
            write_result(
                "w1",
                "Refused: `SOUL.md` is an assistant identity file (SOUL.md); soul_edit_mode=human_only requires the human to edit SOUL.md/USER.md outside model tools.",
            ),
        ];

        assert_eq!(elide_applied_write_edit_args(&mut history), 0);
        assert_eq!(first_call_args(&history[0])["content"], json!(content));
    }

    #[test]
    fn pending_call_without_result_is_not_elided() {
        let mut history = vec![assistant_call(
            "w1",
            "write",
            json!({ "path": "src/lib.rs", "content": long_payload() }),
        )];

        assert_eq!(elide_applied_write_edit_args(&mut history), 0);
        assert!(!is_applied_marker(
            first_call_args(&history[0])["content"].as_str().unwrap()
        ));
    }

    #[test]
    fn upcoming_successful_result_settles_the_call() {
        let content = long_payload();
        let mut history = vec![assistant_call(
            "w1",
            "write",
            json!({ "path": "src/lib.rs", "content": content.clone() }),
        )];
        let upcoming = write_result("w1", "wrote `src/lib.rs` (1200 bytes, LF)");

        assert_eq!(
            elide_applied_write_edit_args_with_upcoming(&mut history, Some(&upcoming)),
            1
        );
        assert_eq!(
            first_call_args(&history[0])["content"],
            json!(applied_marker(content.len()))
        );
    }

    #[test]
    fn signed_reasoning_latest_assistant_is_untouched_until_settled() {
        let content = long_payload();
        let mut history = vec![
            signed_assistant_call(
                "w1",
                "write",
                json!({ "path": "src/lib.rs", "content": content.clone() }),
            ),
            write_result("w1", "wrote `src/lib.rs` (1200 bytes, LF)"),
        ];

        assert_eq!(elide_applied_write_edit_args(&mut history), 0);
        assert_eq!(first_call_args(&history[0])["content"], json!(content));

        history.push(assistant_call(
            "r1",
            "read",
            json!({ "path": "src/lib.rs" }),
        ));

        assert_eq!(elide_applied_write_edit_args(&mut history), 1);
        assert_eq!(
            first_call_args(&history[0])["content"],
            json!(applied_marker(content.len()))
        );
    }

    #[test]
    fn unsigned_latest_assistant_is_elided_once_the_result_exists() {
        let content = long_payload();
        let mut history = vec![
            assistant_call(
                "w1",
                "write",
                json!({ "path": "src/lib.rs", "content": content.clone() }),
            ),
            write_result("w1", "wrote `src/lib.rs` (1200 bytes, LF)"),
        ];

        assert_eq!(elide_applied_write_edit_args(&mut history), 1);
        assert_eq!(
            first_call_args(&history[0])["content"],
            json!(applied_marker(content.len()))
        );
    }

    #[test]
    fn non_object_args_are_left_untouched() {
        let mut history = vec![
            assistant_call("w1", "write", json!("not-an-object")),
            write_result("w1", "wrote `x` (1 bytes, LF)"),
        ];

        assert_eq!(elide_applied_write_edit_args(&mut history), 0);
        assert_eq!(first_call_args(&history[0]), json!("not-an-object"));
    }

    #[test]
    fn loop_hash_projection_is_idempotent_with_elided_history_args() {
        let content = long_payload();
        let full = json!({ "path": "src/x.rs", "content": content });
        let mut history = vec![
            assistant_call("w1", "write", full.clone()),
            write_result("w1", "wrote `src/x.rs` (1200 bytes, LF)"),
        ];
        assert_eq!(elide_applied_write_edit_args(&mut history), 1);
        let elided = first_call_args(&history[0]);

        let from_full = args_for_loop_hash("write", &full);
        let from_elided = args_for_loop_hash("write", &elided);
        assert_eq!(from_full, from_elided);
        assert_eq!(
            crate::approval::store::GrantStore::loop_signature("write", &from_full),
            crate::approval::store::GrantStore::loop_signature("write", &from_elided)
        );
        assert_ne!(
            crate::approval::store::GrantStore::loop_signature("write", &full),
            crate::approval::store::GrantStore::loop_signature("write", &elided),
            "hashing unprojected full args against already-elided history would miss the loop"
        );
    }

    #[test]
    fn read_and_other_tools_are_untouched() {
        let mut history = vec![
            assistant_call("r1", "read", json!({ "path": "src/lib.rs" })),
            crate::engine::message::synthetic_tool_result_message_with_provider_identity(
                "r1".to_string(),
                None,
                None,
                "read",
                long_payload(),
            ),
        ];
        assert_eq!(elide_applied_write_edit_args(&mut history), 0);
        assert_eq!(first_call_args(&history[0])["path"], json!("src/lib.rs"));
    }

    #[test]
    fn stubs_only_fields_above_the_floor() {
        let old = long_payload();
        let mut history = vec![
            assistant_call(
                "e1",
                "edit",
                json!({
                    "path": "src/main.rs",
                    "old_string": old,
                    "new_string": "x"
                }),
            ),
            edit_result("e1", "edited `src/main.rs` (exact; 10 bytes)"),
        ];

        assert_eq!(elide_applied_write_edit_args(&mut history), 1);
        let args = first_call_args(&history[0]);
        assert!(is_applied_marker(args["old_string"].as_str().unwrap()));
        assert_eq!(args["new_string"], json!("x"));
        assert_eq!(args["path"], json!("src/main.rs"));
    }
}
