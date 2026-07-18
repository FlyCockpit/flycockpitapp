//! Model-history pruning for completed structural delegations.
//!
//! Durable events retain the original brief; this pass rewrites only the
//! model-bound assistant tool-call arguments after the matching tool result is
//! available, keeping provider tool-call/result pairing intact.

use std::collections::HashSet;

use rig::message::UserContent;
use serde_json::Value;

use crate::engine::message::{AssistantContent, Message, ToolCall};

const MIN_TOKENS_SAVED: usize = 96;

pub fn marker(call_id: &str) -> String {
    format!("[pruned after subagent returned; see paired tool_result {call_id}]")
}

pub fn prune_completed_delegation_prompts(history: &mut [Message]) -> usize {
    prune_completed_delegation_prompts_with_upcoming(history, None)
}

pub fn prune_completed_delegation_prompts_with_upcoming(
    history: &mut [Message],
    upcoming_result: Option<&Message>,
) -> usize {
    let mut completed = HashSet::new();
    for msg in history.iter() {
        collect_tool_result_ids(msg, &mut completed);
    }
    if let Some(msg) = upcoming_result {
        collect_tool_result_ids(msg, &mut completed);
    }
    if completed.is_empty() {
        return 0;
    }

    let mut changed = 0;
    for msg in history {
        let Message::Assistant { content, .. } = msg else {
            continue;
        };
        for part in content.iter_mut() {
            let AssistantContent::ToolCall(tc) = part else {
                continue;
            };
            if !completed.contains(&tc.id) {
                continue;
            }
            changed += prune_tool_call(tc);
        }
    }
    changed
}

fn collect_tool_result_ids(msg: &Message, out: &mut HashSet<String>) {
    let Message::User { content } = msg else {
        return;
    };
    for part in content.iter() {
        if let UserContent::ToolResult(tr) = part {
            out.insert(tr.id.clone());
        }
    }
}

fn prune_tool_call(tc: &mut ToolCall) -> usize {
    match tc.function.name.as_str() {
        "task" => prune_task_call(tc),
        "spawn" => prune_single_prompt_call(tc),
        _ => 0,
    }
}

fn prune_task_call(tc: &mut ToolCall) -> usize {
    if let Some(payload) = tc.function.arguments.get_mut("payload") {
        if payload.is_object() {
            return prune_prompt_value(payload, &tc.id);
        }
        if let Some(items) = payload.as_array_mut() {
            return items
                .iter_mut()
                .map(|entry| prune_prompt_value(entry, &tc.id))
                .sum();
        }
    }
    if let Some(delegate) = tc
        .function
        .arguments
        .get_mut("delegate")
        .filter(|value| value.is_object())
    {
        return prune_prompt_value(delegate, &tc.id);
    }
    if let Some(items) = tc
        .function
        .arguments
        .get_mut("batch")
        .and_then(Value::as_array_mut)
    {
        return items
            .iter_mut()
            .map(|entry| prune_prompt_value(entry, &tc.id))
            .sum();
    }
    if let Some(items) = tc
        .function
        .arguments
        .get_mut("parallel")
        .and_then(Value::as_array_mut)
    {
        return items
            .iter_mut()
            .map(|entry| prune_prompt_value(entry, &tc.id))
            .sum();
    }
    prune_single_prompt_call(tc)
}

fn prune_single_prompt_call(tc: &mut ToolCall) -> usize {
    prune_prompt_value(&mut tc.function.arguments, &tc.id)
}

fn prune_prompt_value(args: &mut Value, call_id: &str) -> usize {
    let Some(obj) = args.as_object_mut() else {
        return 0;
    };
    let Some(prompt) = obj.get("prompt").and_then(Value::as_str) else {
        return 0;
    };
    let replacement = marker(call_id);
    if prompt == replacement {
        return 0;
    }
    let before = crate::tokens::count(prompt);
    let after = crate::tokens::count(&replacement);
    if before.saturating_sub(after) < MIN_TOKENS_SAVED {
        return 0;
    }
    obj.insert("prompt".to_string(), Value::String(replacement));
    1
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::message::OneOrMany;
    use rig::message::ToolFunction;
    use serde_json::json;

    fn long_prompt() -> String {
        let mut s = String::new();
        while crate::tokens::count(&s) < 140 {
            s.push_str("Inspect the implementation carefully, compare live and resume paths, preserve provider-valid pairing, and report concrete file references. ");
        }
        s
    }

    fn assistant_call(id: &str, name: &str, arguments: Value) -> Message {
        Message::Assistant {
            id: None,
            content: OneOrMany::one(AssistantContent::ToolCall(ToolCall {
                id: id.to_string(),
                call_id: None,
                function: ToolFunction {
                    name: name.to_string(),
                    arguments,
                },
                signature: None,
                additional_params: None,
            })),
        }
    }

    fn result(id: &str) -> Message {
        Message::tool_result_with_call_id(id.to_string(), None, "done".to_string())
    }

    fn first_call_args(msg: &Message) -> Value {
        let Message::Assistant { content, .. } = msg else {
            panic!("assistant");
        };
        let AssistantContent::ToolCall(tc) = content.iter().next().unwrap() else {
            panic!("tool call");
        };
        tc.function.arguments.clone()
    }

    #[test]
    fn prunes_completed_long_task_prompt_and_is_idempotent() {
        let mut history = vec![
            assistant_call(
                "task-1",
                "task",
                json!({ "agent": "explore", "prompt": long_prompt(), "mode": "subagent" }),
            ),
            result("task-1"),
        ];

        assert_eq!(prune_completed_delegation_prompts(&mut history), 1);
        let args = first_call_args(&history[0]);
        assert_eq!(
            args["prompt"],
            json!("[pruned after subagent returned; see paired tool_result task-1]")
        );
        assert_eq!(args["agent"], json!("explore"));
        assert_eq!(args["mode"], json!("subagent"));
        assert_eq!(prune_completed_delegation_prompts(&mut history), 0);
    }

    #[test]
    fn prunes_completed_envelope_delegate_prompt_and_is_idempotent() {
        let mut history = vec![
            assistant_call(
                "task-1",
                "task",
                json!({
                    "intent": "delegate",
                    "delegate": { "agent": "explore", "prompt": long_prompt(), "mode": "subagent" }
                }),
            ),
            result("task-1"),
        ];

        assert_eq!(prune_completed_delegation_prompts(&mut history), 1);
        let args = first_call_args(&history[0]);
        assert_eq!(
            args["delegate"]["prompt"],
            json!("[pruned after subagent returned; see paired tool_result task-1]")
        );
        assert_eq!(args["delegate"]["agent"], json!("explore"));
        assert_eq!(args["delegate"]["mode"], json!("subagent"));
        assert_eq!(prune_completed_delegation_prompts(&mut history), 0);
    }

    #[test]
    fn prunes_completed_canonical_payload_delegate_prompt_and_is_idempotent() {
        let mut history = vec![
            assistant_call(
                "task-1",
                "task",
                json!({
                    "intent": "delegate",
                    "payload": { "agent": "explore", "prompt": long_prompt(), "mode": "subagent" }
                }),
            ),
            result("task-1"),
        ];

        assert_eq!(prune_completed_delegation_prompts(&mut history), 1);
        let args = first_call_args(&history[0]);
        assert_eq!(
            args["payload"]["prompt"],
            json!("[pruned after subagent returned; see paired tool_result task-1]")
        );
        assert_eq!(args["payload"]["agent"], json!("explore"));
        assert_eq!(args["payload"]["mode"], json!("subagent"));
        assert_eq!(prune_completed_delegation_prompts(&mut history), 0);
    }

    #[test]
    fn prunes_completed_deepthink_prompt_but_keeps_structured_response() {
        let report = "summary:\n- done\nrecommendation:\n- keep result\nrisks:\nnone\nassumptions:\nnone\nopen_questions:\nnone";
        let mut history = vec![
            assistant_call(
                "task-1",
                "task",
                json!({
                    "intent": "delegate",
                    "payload": {
                        "agent": "deepthink",
                        "prompt": long_prompt(),
                        "model": { "kind": "category", "category": "reasoning" }
                    }
                }),
            ),
            Message::tool_result_with_call_id("task-1".to_string(), None, report.to_string()),
        ];

        assert_eq!(prune_completed_delegation_prompts(&mut history), 1);
        let args = first_call_args(&history[0]);
        assert_eq!(
            args["payload"]["prompt"],
            json!("[pruned after subagent returned; see paired tool_result task-1]")
        );
        assert_eq!(args["payload"]["agent"], json!("deepthink"));
        let Message::User { content } = &history[1] else {
            panic!("tool result");
        };
        let UserContent::ToolResult(result) = content.iter().next().unwrap() else {
            panic!("tool result content");
        };
        let rig::message::ToolResultContent::Text(text) = result.content.iter().next().unwrap()
        else {
            panic!("tool result text");
        };
        assert_eq!(text.text, report);
    }

    #[test]
    fn leaves_short_task_prompt_unchanged() {
        let mut history = vec![
            assistant_call(
                "task-1",
                "task",
                json!({ "agent": "explore", "prompt": "look around" }),
            ),
            result("task-1"),
        ];

        assert_eq!(prune_completed_delegation_prompts(&mut history), 0);
        assert_eq!(first_call_args(&history[0])["prompt"], json!("look around"));
    }

    #[test]
    fn does_not_prune_pending_delegation() {
        let mut history = vec![assistant_call(
            "task-1",
            "task",
            json!({ "agent": "explore", "prompt": long_prompt() }),
        )];

        assert_eq!(prune_completed_delegation_prompts(&mut history), 0);
        assert_ne!(
            first_call_args(&history[0])["prompt"],
            json!("[pruned after subagent returned; see paired tool_result task-1]")
        );
    }

    #[test]
    fn prunes_completed_parallel_entries_individually() {
        let mut history = vec![
            assistant_call(
                "task-1",
                "task",
                json!({
                    "parallel": [
                        { "label": "a", "agent": "explore", "prompt": long_prompt(), "model": "slow" },
                        { "label": "b", "agent": "explore", "prompt": "short brief" }
                    ]
                }),
            ),
            result("task-1"),
        ];

        assert_eq!(prune_completed_delegation_prompts(&mut history), 1);
        let args = first_call_args(&history[0]);
        assert_eq!(
            args["parallel"][0]["prompt"],
            json!("[pruned after subagent returned; see paired tool_result task-1]")
        );
        assert_eq!(args["parallel"][0]["model"], json!("slow"));
        assert_eq!(args["parallel"][1]["prompt"], json!("short brief"));
    }

    #[test]
    fn prunes_completed_envelope_batch_entries_individually() {
        let mut history = vec![
            assistant_call(
                "task-1",
                "task",
                json!({
                    "intent": "batch",
                    "batch": [
                        { "label": "a", "agent": "explore", "prompt": long_prompt(), "model": "slow" },
                        { "label": "b", "agent": "explore", "prompt": "short brief" }
                    ]
                }),
            ),
            result("task-1"),
        ];

        assert_eq!(prune_completed_delegation_prompts(&mut history), 1);
        let args = first_call_args(&history[0]);
        assert_eq!(
            args["batch"][0]["prompt"],
            json!("[pruned after subagent returned; see paired tool_result task-1]")
        );
        assert_eq!(args["batch"][0]["model"], json!("slow"));
        assert_eq!(args["batch"][1]["prompt"], json!("short brief"));
    }

    #[test]
    fn prunes_completed_canonical_payload_batch_entries_individually() {
        let mut history = vec![
            assistant_call(
                "task-1",
                "task",
                json!({
                    "intent": "batch",
                    "payload": [
                        { "label": "a", "agent": "explore", "prompt": long_prompt(), "model": "slow" },
                        { "label": "b", "agent": "explore", "prompt": "short brief" }
                    ]
                }),
            ),
            result("task-1"),
        ];

        assert_eq!(prune_completed_delegation_prompts(&mut history), 1);
        let args = first_call_args(&history[0]);
        assert_eq!(
            args["payload"][0]["prompt"],
            json!("[pruned after subagent returned; see paired tool_result task-1]")
        );
        assert_eq!(args["payload"][0]["model"], json!("slow"));
        assert_eq!(args["payload"][1]["prompt"], json!("short brief"));
    }
}
