//! One stable system block on every provider wire.
//!
//! Local chat templates (LM Studio / llama.cpp / vLLM / Ollama serving
//! Qwen/Llama/Mistral families) raise "System message must be at the
//! beginning" for any system message after index 0 or for a second system
//! message. Rig's Anthropic and Codex Responses conversions hoist history
//! system text into the cached top-level system/instructions instead. Cockpit
//! history carries host-authored `Message::System` entries (conversation
//! rules, turn-start notices, nudges, the time prelude, tool-availability
//! changes). These tests pin the request JSON each wire actually sends: the
//! stable agent contract is the only system content and is byte-identical
//! across turns, and every history system entry is replayed in place as
//! `<system-reminder>` user text.

use super::*;

const PREAMBLE: &str = "stable agent system contract";
const NOTICE: &str = "notice between turns";

fn reminder(text: &str) -> String {
    format!("<system-reminder>\n{text}\n</system-reminder>")
}

/// JSON-escaped reminder, for substring checks on serialized elements.
fn reminder_json(text: &str) -> String {
    serde_json::to_string(&reminder(text))
        .unwrap()
        .trim_matches('"')
        .to_string()
}

/// Multi-turn history: conversation rules at index 0, a tool round-trip with
/// a notice right after the tool result, a compaction handoff (a user
/// message), and positional system notices mid-conversation and trailing.
fn mixed_history() -> Vec<Message> {
    vec![
        Message::System {
            content: "conversation rules".into(),
        },
        Message::user("first user turn"),
        assistant(vec![responses_tool_call("call-1", Some("call-1"))]),
        tool_result_message("call-1", Some("call-1")),
        Message::System {
            content: "after tool notice".into(),
        },
        Message::assistant("first answer"),
        Message::System {
            content: "mid-conversation nudge".into(),
        },
        Message::user("compaction handoff summary"),
        Message::assistant("second answer"),
        Message::System {
            content: "trailing tool availability notice".into(),
        },
    ]
}

async fn text_provider(dialect: WireDialect) -> ScriptedProvider {
    ScriptedProvider::builder()
        .dialect(dialect)
        .turn(Turn::Text("ok".into()))
        .repeat_last()
        .start()
        .await
}

async fn send(model: &Model, history: &[Message], prompt: &str) {
    let prepared = model
        .prepare_completion_request(
            AgentPromptParts::new(PREAMBLE, history),
            &Message::user(prompt),
            &[simple_tool()],
            &ModelParams::default(),
            false,
            None,
        )
        .unwrap();
    // The captured/debug body already shows the normalized shape.
    assert!(
        prepared.captured["history"]
            .as_array()
            .expect("captured history")
            .iter()
            .all(|message| message["role"] != "system"),
        "captured history still carries a system-role message"
    );
    let _ = model
        .complete_prepared_with_pre_drain(
            prepared,
            &[simple_tool()],
            ModelParams::default(),
            "Build",
            None,
            &CancellationToken::new(),
            None,
            None,
            false,
            None,
        )
        .await;
}

fn role_of(message: &serde_json::Value) -> &str {
    message["role"].as_str().unwrap_or("")
}

fn text_of(message: &serde_json::Value) -> String {
    match &message["content"] {
        serde_json::Value::String(text) => text.clone(),
        serde_json::Value::Array(parts) => parts
            .iter()
            .filter_map(|part| part["text"].as_str())
            .collect::<Vec<_>>()
            .join("|"),
        _ => String::new(),
    }
}

#[derive(Clone, Copy)]
enum Wire {
    ChatCompletions,
    Responses,
    ChatGptCodex,
    Anthropic,
}

async fn wire_model(wire: Wire) -> (ScriptedProvider, Model) {
    match wire {
        Wire::ChatCompletions => {
            let provider = text_provider(WireDialect::ChatCompletions).await;
            let model = openai_model_at_with_wire(&provider.base_url(), WireApi::Completions, true);
            (provider, model)
        }
        Wire::Responses => {
            let provider = text_provider(WireDialect::Responses).await;
            let model = openai_model_at_with_wire(&provider.base_url(), WireApi::Responses, true);
            (provider, model)
        }
        Wire::ChatGptCodex => {
            use crate::providers::models_fetch::{ResolvedHeader, ResolvedRequest};
            let provider = text_provider(WireDialect::Responses).await;
            let url =
                provider.base_url().trim_end_matches("/v1").to_string() + "/backend-api/codex";
            let resolved = ResolvedRequest {
                base_url: url,
                headers: vec![
                    ResolvedHeader {
                        name: "Authorization".to_string(),
                        value: "Bearer codex-access-token".to_string(),
                    },
                    ResolvedHeader {
                        name: "chatgpt-account-id".to_string(),
                        value: "acc_123".to_string(),
                    },
                ],
                is_codex_credential: true,
            };
            let model = build_chatgpt_model(
                "codex-oauth",
                &resolved,
                "gpt-5-codex",
                &crate::config::providers::TimeoutConfig::default(),
                false,
                false,
                None,
                0,
                0,
                false,
                TestArc::new(RedactionTable::empty()),
                TestArc::new(RedactionTable::empty()),
            )
            .expect("native ChatGPT model must build");
            (provider, model)
        }
        Wire::Anthropic => {
            let provider = text_provider(WireDialect::Anthropic).await;
            let model = native_anthropic_model_at(
                TestArc::new(RedactionTable::empty()),
                provider.base_url(),
                8_192,
            );
            (provider, model)
        }
    }
}

/// The stable system content of a request body, per wire.
fn stable_system(wire: Wire, body: &serde_json::Value) -> serde_json::Value {
    match wire {
        Wire::ChatCompletions => body["messages"][0].clone(),
        Wire::Responses | Wire::ChatGptCodex => match body.get("instructions") {
            Some(instructions) if !instructions.is_null() => instructions.clone(),
            _ => body["input"][0].clone(),
        },
        Wire::Anthropic => body["system"].clone(),
    }
}

/// The ordered conversation elements of a request body, per wire.
fn elements(wire: Wire, body: &serde_json::Value) -> Vec<serde_json::Value> {
    let key = match wire {
        Wire::ChatCompletions | Wire::Anthropic => "messages",
        Wire::Responses | Wire::ChatGptCodex => "input",
    };
    body[key].as_array().expect("conversation array").clone()
}

fn assert_no_extra_system(wire: Wire, body: &serde_json::Value) {
    let elements = elements(wire, body);
    let system_positions: Vec<usize> = elements
        .iter()
        .enumerate()
        .filter(|(_, element)| matches!(role_of(element), "system" | "developer"))
        .map(|(index, _)| index)
        .collect();
    match wire {
        Wire::ChatCompletions => assert_eq!(system_positions, vec![0], "{body:#?}"),
        Wire::Responses | Wire::ChatGptCodex => {
            let has_instructions = body
                .get("instructions")
                .is_some_and(|instructions| !instructions.is_null());
            let allowed: Vec<usize> = if has_instructions { vec![] } else { vec![0] };
            assert_eq!(system_positions, allowed, "{body:#?}");
        }
        Wire::Anthropic => assert!(system_positions.is_empty(), "{body:#?}"),
    }
    let system = serde_json::to_string(&stable_system(wire, body)).unwrap();
    assert!(system.contains(PREAMBLE), "{system}");
    assert!(
        !system.contains("system-reminder") && !system.contains(NOTICE),
        "a positional notice reached the stable system block: {system}"
    );
}

/// Two turns with a host notice injected between them: the stable system
/// content is byte-identical, and the notice is replayed in place (after the
/// first answer) as user `<system-reminder>` text.
async fn assert_two_turn_shape(wire: Wire) {
    let (mut provider, model) = wire_model(wire).await;
    send(&model, &[], "first prompt").await;
    let first = provider.next_request().await.body;
    let second_history = vec![
        Message::user("first prompt"),
        Message::assistant("first answer"),
        Message::System {
            content: NOTICE.into(),
        },
    ];
    send(&model, &second_history, "second prompt").await;
    let second = provider.next_request().await.body;

    for body in [&first, &second] {
        assert_no_extra_system(wire, body);
    }
    assert_eq!(
        serde_json::to_vec(&stable_system(wire, &first)).unwrap(),
        serde_json::to_vec(&stable_system(wire, &second)).unwrap(),
        "stable system block changed across turns"
    );

    let elements = elements(wire, &second);
    let serialized: Vec<String> = elements
        .iter()
        .map(|element| serde_json::to_string(element).unwrap())
        .collect();
    let answer_at = serialized
        .iter()
        .position(|element| element.contains("first answer"))
        .expect("first answer replayed");
    let notice_at = serialized
        .iter()
        .position(|element| element.contains(&reminder_json(NOTICE)))
        .unwrap_or_else(|| panic!("notice replayed as a reminder: {second:#?}"));
    assert!(notice_at > answer_at, "{second:#?}");
    assert_eq!(role_of(&elements[notice_at]), "user", "{second:#?}");
    let prompt_at = serialized
        .iter()
        .rposition(|element| element.contains("second prompt"))
        .expect("prompt sent");
    assert!(prompt_at >= notice_at, "{second:#?}");
}

#[tokio::test]
async fn chat_completions_two_turns_keep_one_stable_leading_system_message() {
    assert_two_turn_shape(Wire::ChatCompletions).await;
}

#[tokio::test]
async fn responses_two_turns_keep_stable_instructions_and_inline_reminders() {
    assert_two_turn_shape(Wire::Responses).await;
}

#[tokio::test]
async fn chatgpt_codex_two_turns_keep_stable_instructions_and_inline_reminders() {
    assert_two_turn_shape(Wire::ChatGptCodex).await;
}

#[tokio::test]
async fn anthropic_two_turns_keep_stable_system_and_inline_reminders() {
    assert_two_turn_shape(Wire::Anthropic).await;
}

#[tokio::test]
async fn chat_completions_mixed_history_shape() {
    let (mut provider, model) = wire_model(Wire::ChatCompletions).await;
    send(&model, &mixed_history(), "current prompt").await;
    let body = provider.next_request().await.body;
    assert_no_extra_system(Wire::ChatCompletions, &body);
    let messages = body["messages"].as_array().unwrap();
    assert_eq!(text_of(&messages[0]), PREAMBLE);
    let roles: Vec<&str> = messages.iter().map(role_of).collect();
    assert_eq!(
        roles,
        vec![
            "system",    // stable preamble
            "user",      // rules reminder + first user turn
            "assistant", // tool call
            "tool",      // tool result
            "user",      // after-tool reminder (trails the tool result)
            "assistant", // first answer
            "user",      // nudge reminder + compaction handoff
            "assistant", // second answer
            "user",      // trailing reminder + current prompt
        ],
        "{messages:#?}"
    );
    assert_eq!(
        text_of(&messages[1]),
        format!("{}|first user turn", reminder("conversation rules"))
    );
    assert_eq!(text_of(&messages[4]), reminder("after tool notice"));
    assert_eq!(
        text_of(&messages[6]),
        format!(
            "{}|compaction handoff summary",
            reminder("mid-conversation nudge")
        )
    );
    assert_eq!(
        text_of(&messages[8]),
        format!(
            "{}|current prompt",
            reminder("trailing tool availability notice")
        )
    );
}

#[tokio::test]
async fn anthropic_mixed_history_alternates_and_keeps_system_stable() {
    let (mut provider, model) = wire_model(Wire::Anthropic).await;
    send(&model, &mixed_history(), "current prompt").await;
    let body = provider.next_request().await.body;
    assert_no_extra_system(Wire::Anthropic, &body);
    let system = serde_json::to_string(&body["system"]).unwrap();
    for volatile in [
        "conversation rules",
        "after tool notice",
        "mid-conversation nudge",
        "trailing tool availability notice",
    ] {
        assert!(
            !system.contains(volatile),
            "positional notice `{volatile}` was hoisted into the cached system prefix: {system}"
        );
    }
    let messages = body["messages"].as_array().unwrap();
    let roles: Vec<&str> = messages.iter().map(role_of).collect();
    assert_eq!(
        roles,
        vec![
            "user",
            "assistant",
            "user",
            "assistant",
            "user",
            "assistant",
            "user"
        ],
        "strict user/assistant alternation: {messages:#?}"
    );
    // The after-tool reminder rides as a text block after the tool_result.
    let tool_turn = &messages[2]["content"];
    assert_eq!(tool_turn[0]["type"], "tool_result", "{tool_turn:#?}");
    assert_eq!(
        tool_turn[1]["text"].as_str(),
        Some(reminder("after tool notice").as_str()),
        "{tool_turn:#?}"
    );
}

#[tokio::test]
async fn responses_mixed_history_has_no_system_input_items() {
    let (mut provider, model) = wire_model(Wire::Responses).await;
    send(&model, &mixed_history(), "current prompt").await;
    let body = provider.next_request().await.body;
    assert_no_extra_system(Wire::Responses, &body);
    let serialized = serde_json::to_string(&body).unwrap();
    for notice in [
        "conversation rules",
        "after tool notice",
        "mid-conversation nudge",
        "trailing tool availability notice",
    ] {
        assert!(serialized.contains(&reminder_json(notice)), "{body:#?}");
    }
}

#[test]
fn normalize_system_roles_is_idempotent_and_covers_the_prompt() {
    let mut history = mixed_history();
    let mut prompt = Message::System {
        content: "prompt-level notice".into(),
    };
    normalize_system_roles_for_wire(&mut history, &mut prompt);
    let once = (history.clone(), prompt.clone());
    normalize_system_roles_for_wire(&mut history, &mut prompt);
    assert_eq!(
        serde_json::to_value(&once).unwrap(),
        serde_json::to_value((&history, &prompt)).unwrap()
    );
    assert!(
        history
            .iter()
            .chain(std::iter::once(&prompt))
            .all(|message| !matches!(message, Message::System { .. }))
    );
    // Non-system messages keep their order; reminders merge into adjacent
    // user turns. The trailing reminder follows an assistant turn and the
    // prompt is itself a reminder (which must stay the final message), so it
    // is the one reminder that stands alone.
    let non_system = mixed_history()
        .into_iter()
        .filter(|message| !matches!(message, Message::System { .. }))
        .count();
    assert_eq!(history.len(), non_system + 1);
    assert!(
        matches!(history.last(), Some(Message::User { content }) if content.len() == 1),
        "{history:#?}"
    );
}

#[test]
fn reminder_between_two_assistant_turns_stands_alone() {
    let mut history = vec![
        Message::assistant("a"),
        Message::System {
            content: "between".into(),
        },
        Message::assistant("b"),
    ];
    let mut prompt = Message::user("p");
    normalize_system_roles_for_wire(&mut history, &mut prompt);
    assert_eq!(history.len(), 3);
    assert!(
        matches!(&history[1], Message::User { content } if content.len() == 1),
        "{history:#?}"
    );
}
