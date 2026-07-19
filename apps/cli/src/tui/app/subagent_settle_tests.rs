use super::{
    SubagentReportUpdate, SubagentRoutingUpdate, amend_subagent_routing_in, settle_subagent_in,
};
use crate::tui::history::{HistoryEntry, SubagentRoutingChips};

fn running(parent: &str, child: &str) -> HistoryEntry {
    HistoryEntry::Subagent {
        parent: parent.into(),
        child: child.into(),
        task_call_id: "task".into(),
        label: "default".into(),
        trusted_only: false,
        model_trusted: false,
        routing: SubagentRoutingChips::default(),
        spawned_at: std::time::Instant::now(),
        outcome: None,
        expanded: false,
    }
}

fn running_labeled(parent: &str, child: &str, task_call_id: &str, label: &str) -> HistoryEntry {
    HistoryEntry::Subagent {
        parent: parent.into(),
        child: child.into(),
        task_call_id: task_call_id.into(),
        label: label.into(),
        trusted_only: false,
        model_trusted: false,
        routing: SubagentRoutingChips::default(),
        spawned_at: std::time::Instant::now(),
        outcome: None,
        expanded: false,
    }
}

fn report_update(report: impl Into<String>) -> SubagentReportUpdate {
    SubagentReportUpdate {
        report: report.into(),
        trusted_only: false,
        model_trusted: false,
        routing: SubagentRoutingChips::default(),
    }
}

fn routing_update(model: &str) -> SubagentRoutingUpdate {
    SubagentRoutingUpdate {
        trusted_only: true,
        model_trusted: true,
        routing: SubagentRoutingChips {
            model: Some(model.into()),
            location: Some("private_remote".into()),
            fallback: Some("backup".into()),
        },
    }
}

fn outcome(entry: &HistoryEntry) -> Option<(&str, bool)> {
    match entry {
        HistoryEntry::Subagent {
            outcome: Some(o), ..
        } => Some((o.report.as_str(), o.failed)),
        _ => None,
    }
}

fn routing_model(entry: &HistoryEntry) -> Option<&str> {
    match entry {
        HistoryEntry::Subagent { routing, .. } => routing.model.as_deref(),
        _ => None,
    }
}

fn outcome_status(entry: &HistoryEntry) -> Option<&str> {
    match entry {
        HistoryEntry::Subagent {
            outcome: Some(o), ..
        } => o.status.as_deref(),
        _ => None,
    }
}

fn expanded(entry: &HistoryEntry) -> bool {
    match entry {
        HistoryEntry::Subagent { expanded, .. } => *expanded,
        _ => false,
    }
}

fn trust_flags(entry: &HistoryEntry) -> Option<(bool, bool)> {
    match entry {
        HistoryEntry::Subagent {
            trusted_only,
            model_trusted,
            ..
        } => Some((*trusted_only, *model_trusted)),
        _ => None,
    }
}

/// Spawn → report transition settles the running entry in place
/// (no new entry pushed) with the report and failed=false.
#[test]
fn report_settles_running_entry_in_place() {
    let mut history = vec![running("Build", "explore")];
    settle_subagent_in(
        &mut history,
        "explore",
        "task",
        "default",
        report_update("all done"),
    );
    assert_eq!(history.len(), 1);
    assert_eq!(outcome(&history[0]), Some(("all done", false)));
    assert_eq!(outcome_status(&history[0]), None);
    assert!(!expanded(&history[0]));
}

#[test]
fn report_updates_subagent_trust_metadata() {
    let mut history = vec![running("Build", "explore")];
    settle_subagent_in(
        &mut history,
        "explore",
        "task",
        "default",
        SubagentReportUpdate {
            report: "all done".into(),
            trusted_only: true,
            model_trusted: true,
            routing: SubagentRoutingChips {
                model: Some("claude-sonnet-4-6".into()),
                location: Some("private_remote".into()),
                fallback: Some("none".into()),
            },
        },
    );
    assert_eq!(trust_flags(&history[0]), Some((true, true)));
    match &history[0] {
        HistoryEntry::Subagent { routing, .. } => {
            assert_eq!(routing.model.as_deref(), Some("claude-sonnet-4-6"));
            assert_eq!(routing.location.as_deref(), Some("private_remote"));
        }
        other => panic!("expected subagent, got {other:?}"),
    }
}

#[test]
fn routing_amend_updates_inflight_subagent_chips() {
    let mut history = vec![running("Build", "explore")];

    assert!(amend_subagent_routing_in(
        &mut history,
        "explore",
        "task",
        "default",
        routing_update("child-model"),
    ));

    assert_eq!(history.len(), 1);
    assert_eq!(routing_model(&history[0]), Some("child-model"));
    assert_eq!(trust_flags(&history[0]), Some((true, true)));
}

#[test]
fn routing_amend_without_entry_is_dropped() {
    let mut history = vec![running("Build", "explore")];

    assert!(!amend_subagent_routing_in(
        &mut history,
        "builder",
        "missing-task",
        "default",
        routing_update("child-model"),
    ));

    assert_eq!(history.len(), 1);
    assert_eq!(routing_model(&history[0]), None);
}

#[test]
fn routing_amend_after_report_updates_settled_entry() {
    let mut history = vec![running("Build", "explore")];
    settle_subagent_in(
        &mut history,
        "explore",
        "task",
        "default",
        report_update("all done"),
    );

    assert!(amend_subagent_routing_in(
        &mut history,
        "explore",
        "task",
        "default",
        routing_update("child-model"),
    ));

    assert_eq!(history.len(), 1);
    assert_eq!(outcome(&history[0]), Some(("all done", false)));
    assert_eq!(routing_model(&history[0]), Some("child-model"));
}

/// A report whose text is the driver's `Error: ` failure encoding
/// settles as a failure (failed=true) rather than a normal report.
#[test]
fn error_prefixed_report_settles_as_failure() {
    let mut history = vec![running("Build", "explore")];
    settle_subagent_in(
        &mut history,
        "explore",
        "task",
        "default",
        report_update("Error: it broke"),
    );
    assert_eq!(outcome(&history[0]), Some(("Error: it broke", true)));
    assert_eq!(
        outcome_status(&history[0]),
        Some("explore stopped with an error")
    );
    assert!(expanded(&history[0]));
}

#[test]
fn partial_builder_report_sets_status_and_auto_expands() {
    let mut history = vec![running("Build", "builder")];
    settle_subagent_in(
        &mut history,
        "builder",
        "task",
        "default",
        report_update("Edited src/lib.rs and src/main.rs. Validation not run yet."),
    );
    assert_eq!(
        outcome_status(&history[0]),
        Some("builder stopped after writing files; validation not run yet")
    );
    assert!(expanded(&history[0]));
}

/// An empty report still settles the entry (the renderer shows a
/// bare header) — it doesn't leave a dangling running line.
#[test]
fn empty_report_settles_running_entry() {
    let mut history = vec![running("Build", "explore")];
    settle_subagent_in(
        &mut history,
        "explore",
        "task",
        "default",
        report_update(String::new()),
    );
    assert_eq!(outcome(&history[0]), Some(("", false)));
}

/// Each report settles the most-recent still-running entry for the
/// child (the just-spawned one), leaving already-settled entries
/// untouched. With two running entries, the first report settles the
/// newer (last) one, the second report settles the older.
#[test]
fn settles_most_recent_running_for_child() {
    let mut history = vec![running("Build", "explore"), running("Build", "explore")];
    settle_subagent_in(
        &mut history,
        "explore",
        "task",
        "default",
        report_update("first"),
    );
    settle_subagent_in(
        &mut history,
        "explore",
        "task",
        "default",
        report_update("second"),
    );
    assert_eq!(outcome(&history[1]), Some(("first", false)));
    assert_eq!(outcome(&history[0]), Some(("second", false)));
}

#[test]
fn settles_same_agent_by_task_call_and_label() {
    let mut history = vec![
        running_labeled("Build", "explore", "task-1", "auth"),
        running_labeled("Build", "explore", "task-1", "db"),
    ];
    settle_subagent_in(
        &mut history,
        "explore",
        "task-1",
        "auth",
        report_update("auth done"),
    );
    assert_eq!(outcome(&history[0]), Some(("auth done", false)));
    assert_eq!(outcome(&history[1]), None);
    settle_subagent_in(
        &mut history,
        "explore",
        "task-1",
        "db",
        report_update("db done"),
    );
    assert_eq!(outcome(&history[1]), Some(("db done", false)));
}

/// A report with no matching running entry pushes a settled entry
/// (defensive) so the report is never lost.
#[test]
fn orphan_report_pushes_settled_entry() {
    let mut history: Vec<HistoryEntry> = Vec::new();
    settle_subagent_in(
        &mut history,
        "explore",
        "task",
        "default",
        report_update("orphan"),
    );
    assert_eq!(history.len(), 1);
    assert_eq!(outcome(&history[0]), Some(("orphan", false)));
}
