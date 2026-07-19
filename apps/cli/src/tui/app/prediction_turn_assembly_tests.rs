use super::turns_from_history;
use crate::tui::history::{HistoryEntry, ToolCall, ToolCallState};

fn user(text: &str) -> HistoryEntry {
    HistoryEntry::User {
        text: text.into(),
        cleaned: None,
        expanded: false,
        timestamp: chrono::Local::now(),
        seq: None,
        preflight_pending: false,
        persist_failed: false,
    }
}

fn agent(text: &str, reasoning: &str) -> HistoryEntry {
    HistoryEntry::Agent {
        name: "Build".into(),
        text: text.into(),
        reasoning: reasoning.into(),
        timestamp: chrono::Local::now(),
        expanded: false,
        reasoning_offset: 0,
        think_duration: None,
        seq: None,
    }
}

fn tool_box() -> HistoryEntry {
    HistoryEntry::ToolBox {
        calls: vec![ToolCall {
            call_id: "c1".into(),
            tool: "bash".into(),
            summary: "ls".into(),
            full_input: "ls".into(),
            output: "file.txt".into(),
            expanded: false,
            result_offset: 0,
            state: ToolCallState::Success,
            hint: None,
            mcp_child: None,
        }],
        view_offset: 0,
        follow: true,
    }
}

/// One pair per turn: the user message + the agent's final response,
/// with tool calls and reasoning skipped entirely.
#[test]
fn pairs_user_with_agent_final_response_only() {
    let history = vec![
        user("add a flag"),
        tool_box(),
        agent("Done, added the flag.", "let me think about this"),
    ];
    let turns = turns_from_history(&history);
    assert_eq!(turns.len(), 1);
    assert_eq!(turns[0].user, "add a flag");
    // The agent FINAL TEXT carries; reasoning never does.
    assert_eq!(turns[0].agent, "Done, added the flag.");
    assert!(!turns[0].agent.contains("think"));
}

/// More than three turns: assembly keeps every turn (the last-3 window
/// is applied by `engine::predict::last_turns`), but each is faithful.
#[test]
fn assembles_every_turn_faithfully() {
    let history = vec![
        user("q1"),
        agent("a1", ""),
        user("q2"),
        tool_box(),
        agent("a2", ""),
        user("q3"),
        agent("a3", ""),
        user("q4"),
        agent("a4", ""),
    ];
    let turns = turns_from_history(&history);
    assert_eq!(turns.len(), 4);
    let last3 = crate::engine::predict::last_turns(&turns);
    assert_eq!(last3.len(), 3);
    assert_eq!(last3[0].user, "q2");
    assert_eq!(last3[2].user, "q4");
    assert_eq!(last3[2].agent, "a4");
}

/// A user message arriving before the agent reply (queued + folded)
/// folds into the open turn rather than opening a phantom turn.
#[test]
fn consecutive_user_messages_fold_into_open_turn() {
    let history = vec![user("first part"), user("second part"), agent("ok", "")];
    let turns = turns_from_history(&history);
    assert_eq!(turns.len(), 1);
    assert!(turns[0].user.contains("first part"));
    assert!(turns[0].user.contains("second part"));
    assert_eq!(turns[0].agent, "ok");
}

/// A trailing user message with no agent reply yet stays an open turn
/// with an empty agent response — never paired with the wrong reply.
#[test]
fn trailing_open_turn_has_empty_agent() {
    let history = vec![user("q1"), agent("a1", ""), user("q2")];
    let turns = turns_from_history(&history);
    assert_eq!(turns.len(), 2);
    assert_eq!(turns[1].user, "q2");
    assert!(turns[1].agent.is_empty());
}

/// A fresh session (no agent response yet) yields a window that
/// `engine::predict` treats as "nothing to predict".
#[test]
fn fresh_session_has_no_agent_response() {
    let history = vec![user("first message")];
    let turns = turns_from_history(&history);
    let window = crate::engine::predict::last_turns(&turns);
    assert!(window.iter().all(|t| t.agent.trim().is_empty()));
}
