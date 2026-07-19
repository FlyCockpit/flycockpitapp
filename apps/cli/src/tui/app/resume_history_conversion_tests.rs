use super::wire_history_to_entries;
use crate::daemon::proto::HistoryEntry as Wire;
use crate::tui::history::{HistoryEntry, ToolCallState};
use serde_json::json;

#[test]
fn replayed_user_row_uses_display_text() {
    let entries = wire_history_to_entries(vec![Wire::User {
        text: "<file path=\"src/lib.rs\">expanded</file>".into(),
        display_text: Some("review @src/lib.rs".into()),
        tag_expansions: Vec::new(),
        ts_ms: 1_700_000_000_000,
        seq: 1,
        origin_principal: None,
    }]);
    assert!(matches!(
        &entries[0],
        HistoryEntry::User { text, .. } if text == "review @src/lib.rs"
    ));

    let legacy = wire_history_to_entries(vec![Wire::User {
        text: "legacy wire".into(),
        display_text: None,
        tag_expansions: Vec::new(),
        ts_ms: 1_700_000_000_000,
        seq: 2,
        origin_principal: None,
    }]);
    assert!(matches!(
        &legacy[0],
        HistoryEntry::User { text, .. } if text == "legacy wire"
    ));

    let empty_display = wire_history_to_entries(vec![Wire::User {
        text: "wire fallback".into(),
        display_text: Some(String::new()),
        tag_expansions: Vec::new(),
        ts_ms: 1_700_000_000_000,
        seq: 3,
        origin_principal: None,
    }]);
    assert!(matches!(
        &empty_display[0],
        HistoryEntry::User { text, .. } if text == "wire fallback"
    ));
}

#[test]
fn replayed_user_row_renders_tag_entries() {
    let entries = wire_history_to_entries(vec![Wire::User {
        text: "expanded wire".into(),
        display_text: Some("review @src/lib.rs".into()),
        tag_expansions: vec![crate::daemon::proto::TagExpansionMeta {
            tool: "read".into(),
            path: "src/lib.rs".into(),
            detail: "142 lines".into(),
            ok: true,
        }],
        ts_ms: 1_700_000_000_000,
        seq: 1,
        origin_principal: None,
    }]);
    assert_eq!(entries.len(), 2);
    assert!(matches!(
        &entries[1],
        HistoryEntry::Plain { line } if line == "  → read(src/lib.rs) ✓ 142 lines"
    ));
}

/// REGRESSION (implementation note): the wire→TUI
/// conversion a `/sessions` resume runs must yield matching `User` / `Agent`
/// / `ToolBox` entries in order — a resumed transcript renders like a live
/// one. Before the fix this conversion didn't exist (the runner discarded
/// the snapshot and the resume handler only cleared history).
#[test]
fn converts_user_assistant_tool_call_to_tui_entries() {
    let wire = vec![
        Wire::User {
            text: "read the file".into(),
            display_text: None,
            tag_expansions: Vec::new(),
            ts_ms: 1_700_000_000_000,
            seq: 1,
            origin_principal: None,
        },
        Wire::Assistant {
            agent: "Build".into(),
            text: "let me read it".into(),
            reasoning: "thinking".into(),
            ts_ms: 1_700_000_001_000,
            seq: 2,
        },
        Wire::ToolCall {
            seq: 3,
            agent: "Build".into(),
            call_id: "tc-1".into(),
            parent_call_id: None,
            parent_child_index: None,
            tool: "read".into(),
            mcp_server: None,
            mcp_builtin: None,
            mcp_kind: None,
            original_input: json!({ "path": "src/main.rs" }),
            wire_input: json!({ "path": "src/main.rs" }),
            recovery_kind: None,
            recovery_stage: None,
            output: "fn main() {}".into(),
            hard_fail: false,
            truncated: false,
            hint: None,
        },
    ];

    let entries = wire_history_to_entries(wire);
    assert_eq!(entries.len(), 3);

    match &entries[0] {
        HistoryEntry::User { text, seq, .. } => {
            assert_eq!(text, "read the file");
            assert_eq!(*seq, Some(1), "seq carries so the row stays pinnable");
        }
        other => panic!("entries[0] should be User, got {other:?}"),
    }
    match &entries[1] {
        HistoryEntry::Agent {
            name,
            text,
            reasoning,
            seq,
            ..
        } => {
            assert_eq!(name, "Build");
            assert_eq!(text, "let me read it");
            assert_eq!(reasoning, "thinking");
            assert_eq!(*seq, Some(2));
        }
        other => panic!("entries[1] should be Agent, got {other:?}"),
    }
    match &entries[2] {
        HistoryEntry::ToolBox { calls, .. } => {
            assert_eq!(calls.len(), 1);
            assert_eq!(calls[0].tool, "read");
            assert_eq!(calls[0].summary, "src/main.rs");
            assert_eq!(calls[0].output, "fn main() {}");
            assert_eq!(calls[0].state, ToolCallState::Success);
        }
        other => panic!("entries[2] should be ToolBox, got {other:?}"),
    }
}

#[test]
fn converts_interrupt_decision_to_dedicated_tui_entry() {
    let entries = wire_history_to_entries(vec![Wire::InterruptDecision {
        decision: crate::daemon::proto::InterruptDecision {
            permission: true,
            cancelled: false,
            lines: vec![crate::daemon::proto::InterruptDecisionLine {
                prompt: "Run command?".into(),
                answer: "Allow".into(),
            }],
        },
        seq: 42,
    }]);

    match &entries[..] {
        [HistoryEntry::InterruptDecision { decision }] => {
            assert!(decision.permission);
            assert!(!decision.cancelled);
            assert_eq!(decision.lines[0].prompt, "Run command?");
            assert_eq!(decision.lines[0].answer, "Allow");
        }
        other => panic!("expected dedicated interrupt decision entry, got {other:?}"),
    }
}

/// Consecutive boxable tool calls coalesce into ONE `ToolBox`, matching the
/// live grouping (not a separate read-only path).
#[test]
fn consecutive_tool_calls_coalesce_into_one_box() {
    let tc = |id: &str| Wire::ToolCall {
        seq: 1,
        agent: "Build".into(),
        call_id: id.into(),
        parent_call_id: None,
        parent_child_index: None,
        tool: "bash".into(),
        mcp_server: None,
        mcp_builtin: None,
        mcp_kind: None,
        original_input: json!({ "command": "ls" }),
        wire_input: json!({ "command": "ls" }),
        recovery_kind: None,
        recovery_stage: None,
        output: "out".into(),
        hard_fail: false,
        truncated: false,
        hint: None,
    };
    let entries = wire_history_to_entries(vec![tc("a"), tc("b"), tc("c")]);
    assert_eq!(entries.len(), 1, "one box holds all three calls");
    match &entries[0] {
        HistoryEntry::ToolBox { calls, .. } => assert_eq!(calls.len(), 3),
        other => panic!("should be a single ToolBox, got {other:?}"),
    }
}

/// An empty snapshot converts to no entries (the brand-new / empty session
/// edge case — empty transcript, no error).
#[test]
fn empty_snapshot_yields_no_entries() {
    assert!(wire_history_to_entries(Vec::new()).is_empty());
}

/// Inference failures are display-only rows in attach history and should
/// preserve ordering across surrounding user rows.
#[test]
fn inference_error_snapshot_converts_in_order_collapsed() {
    let entries = wire_history_to_entries(vec![
        Wire::User {
            text: "before".into(),
            display_text: None,
            tag_expansions: Vec::new(),
            ts_ms: 1_700_000_000_000,
            seq: 1,
            origin_principal: None,
        },
        Wire::InferenceError {
            seq: 2,
            summary: "Inference failed (p/m): network: first line".into(),
            detail: "first line\nsecond line".into(),
        },
        Wire::User {
            text: "after".into(),
            display_text: None,
            tag_expansions: Vec::new(),
            ts_ms: 1_700_000_001_000,
            seq: 2,
            origin_principal: None,
        },
    ]);
    assert_eq!(entries.len(), 3);
    assert!(matches!(entries[0], HistoryEntry::User { .. }));
    match &entries[1] {
        HistoryEntry::InferenceError {
            summary,
            detail,
            expanded,
        } => {
            assert_eq!(summary, "Inference failed (p/m): network: first line");
            assert_eq!(detail, "first line\nsecond line");
            assert!(!expanded);
        }
        other => panic!("entries[1] should be InferenceError, got {other:?}"),
    }
    assert!(matches!(entries[2], HistoryEntry::User { .. }));
}

#[test]
fn steer_user_snapshot_converts_to_provenance_row() {
    let entries = wire_history_to_entries(vec![Wire::User {
        text: "please adjust".into(),
        display_text: None,
        tag_expansions: Vec::new(),
        ts_ms: 1_700_000_000_000,
        seq: 7,
        origin_principal: Some("local:tester".into()),
    }]);

    assert_eq!(entries.len(), 1);
    match &entries[0] {
        HistoryEntry::Plain { line } => {
            assert!(line.contains("local:tester"));
            assert!(line.contains("please adjust"));
        }
        other => panic!("entries[0] should be steer provenance, got {other:?}"),
    }
}

#[test]
fn active_subagent_snapshot_converts_to_running_row() {
    let entries = wire_history_to_entries(vec![
        Wire::User {
            text: "build it".into(),
            display_text: None,
            tag_expansions: Vec::new(),
            ts_ms: 1_700_000_000_000,
            seq: 1,
            origin_principal: None,
        },
        Wire::Subagent {
            seq: 2,
            parent: "Build".into(),
            child: "builder".into(),
            task_call_id: "task-1".into(),
            label: "default".into(),
        },
        Wire::Assistant {
            agent: "builder".into(),
            text: "working".into(),
            reasoning: String::new(),
            ts_ms: 1_700_000_001_000,
            seq: 2,
        },
    ]);

    assert_eq!(entries.len(), 3);
    match &entries[1] {
        HistoryEntry::Subagent {
            parent,
            child,
            task_call_id,
            label,
            outcome,
            ..
        } => {
            assert_eq!(parent, "Build");
            assert_eq!(child, "builder");
            assert_eq!(task_call_id, "task-1");
            assert_eq!(label, "default");
            assert!(outcome.is_none(), "attach row must remain running");
        }
        other => panic!("entries[1] should be running Subagent, got {other:?}"),
    }
    match &entries[2] {
        HistoryEntry::Agent { name, text, .. } => {
            assert_eq!(name, "builder");
            assert_eq!(text, "working");
        }
        other => panic!("entries[2] should be child Agent, got {other:?}"),
    }
}
