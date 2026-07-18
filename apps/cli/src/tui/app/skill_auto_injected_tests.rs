use super::App;
use crate::engine::TurnEvent;
use crate::tui::history::HistoryEntry;

/// Push the optimistic user row exactly as a fresh send does: original
/// text, no cleaned form, unstamped `seq` (the auto-inject events arrive
/// while this row is still unstamped, mid-turn).
fn push_optimistic(app: &mut App, text: &str) {
    app.history.push(HistoryEntry::User {
        text: text.to_string(),
        cleaned: None,
        expanded: false,
        timestamp: chrono::Local::now(),
        seq: None,
        preflight_pending: false,
        persist_failed: false,
    });
}

fn render(entry: &HistoryEntry) -> crate::tui::history::Rendered {
    crate::tui::history::render_entry(
        entry,
        80,
        crate::config::extended::ThinkingDisplay::Condensed,
        crate::tui::history::MarkdownOpts::default(),
        crate::config::extended::DiffStyle::default(),
        false,
        &std::collections::HashSet::new(),
        0,
        None,
    )
}

/// Flatten one rendered `Line` to its plain text (span contents joined).
fn line_text(line: &ratatui::text::Line<'_>) -> String {
    line.spans.iter().map(|s| s.content.to_string()).collect()
}

fn render_line(entry: &HistoryEntry) -> String {
    render(entry)
        .lines
        .iter()
        .map(line_text)
        .collect::<Vec<_>>()
        .join("")
}

/// Auto-select injecting `firecrawl` produces a `/firecrawl · injected by
/// agent` row on the turn, ahead of the user's message.
#[test]
fn injection_renders_a_labeled_row_ahead_of_the_user_message() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    push_optimistic(&mut app, "scrape example.com please");

    app.apply_event(TurnEvent::SkillAutoInjected {
        name: "firecrawl".to_string(),
        reason: None,
    });

    // Exactly one auto-injected row, and it sits AHEAD of the user row.
    let inj_idx = app
        .history
        .iter()
        .position(|e| matches!(e, HistoryEntry::SkillAutoInjected { .. }))
        .expect("an auto-injected row");
    let user_idx = app
        .history
        .iter()
        .position(|e| matches!(e, HistoryEntry::User { .. }))
        .expect("the user row");
    assert!(inj_idx < user_idx, "the injected row precedes the message");

    // The row carries the skill id AND the discriminating label.
    let line = render_line(&app.history[inj_idx]);
    assert!(line.contains("/firecrawl"), "names the skill: {line}");
    assert!(
        line.contains("injected by agent"),
        "labeled as auto-injected: {line}"
    );
}

/// Multiple skills in one turn → one row each, in injection order, all
/// ahead of the user's message.
#[test]
fn multiple_injections_render_one_row_each_in_order() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    push_optimistic(&mut app, "research and deploy");

    app.apply_event(TurnEvent::SkillAutoInjected {
        name: "firecrawl".to_string(),
        reason: None,
    });
    app.apply_event(TurnEvent::SkillAutoInjected {
        name: "deploy".to_string(),
        reason: None,
    });

    let rows: Vec<String> = app
        .history
        .iter()
        .filter_map(|e| match e {
            HistoryEntry::SkillAutoInjected { name, .. } => Some(name.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(
        rows,
        vec!["firecrawl".to_string(), "deploy".to_string()],
        "one row per skill, in injection order"
    );
    // Both precede the user message.
    let user_idx = app
        .history
        .iter()
        .position(|e| matches!(e, HistoryEntry::User { .. }))
        .unwrap();
    let last_inj = app
        .history
        .iter()
        .rposition(|e| matches!(e, HistoryEntry::SkillAutoInjected { .. }))
        .unwrap();
    assert!(last_inj < user_idx, "all injected rows precede the message");
}

/// No injection → no row (the `Selection::None` case never emits the event,
/// so the history holds only the user's message).
#[test]
fn no_injection_means_no_row() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    push_optimistic(&mut app, "what time is it");
    // No `SkillAutoInjected` applied.
    assert!(
        !app.history
            .iter()
            .any(|e| matches!(e, HistoryEntry::SkillAutoInjected { .. })),
        "no auto-injected row without an injection event"
    );
}

/// A user-typed `/{name}` is visually DISTINCT: it renders as a `skill`
/// tool-call row (glyph/label + summary), never the auto-injected label.
/// The two surfaces are unmistakable.
#[test]
fn user_typed_skill_row_is_distinct_no_injected_label() {
    // The auto-injected row carries the discriminator.
    let injected = HistoryEntry::SkillAutoInjected {
        name: "firecrawl".to_string(),
        reason: None,
    };
    let injected_line = render_line(&injected);
    assert!(injected_line.contains("injected by agent"));

    // A user-typed `/firecrawl` flows through the `skill` tool call
    // (`seed_forced_skill`), rendered as a tool-call row — never the
    // "injected by agent" label.
    let user_typed = HistoryEntry::ToolBox {
        calls: vec![crate::tui::history::ToolCall {
            call_id: "skillslash-1".to_string(),
            tool: "skill".to_string(),
            summary: "firecrawl".to_string(),
            full_input: "firecrawl".to_string(),
            output: "Skill `firecrawl`:\n\n…".to_string(),
            expanded: false,
            result_offset: 0,
            state: crate::tui::history::ToolCallState::Success,
            hint: None,
        }],
        view_offset: 0,
        follow: true,
    };
    let user_line = render_line(&user_typed);
    assert!(
        !user_line.contains("injected by agent"),
        "a user-typed skill carries NO auto-injected label: {user_line}"
    );
    assert!(
        user_line.contains("skill"),
        "a user-typed skill renders as a `skill` tool-call row: {user_line}"
    );
}

/// An entry WITH a reason renders two lines: the `/{name} · injected by
/// agent` row (name span bold) and a muted `└ <reason>` sub-line
/// (implementation note).
#[test]
fn reason_renders_a_bold_name_and_a_muted_sub_line() {
    use ratatui::style::Modifier;

    let entry = HistoryEntry::SkillAutoInjected {
        name: "analyze-session-logs".to_string(),
        reason: Some("because you asked about tool-call effectiveness".to_string()),
    };
    let r = render(&entry);
    assert_eq!(r.lines.len(), 2, "two lines: the row + the reason sub-line");

    // First line: the row, with the `/{name}` span bold.
    let first = line_text(&r.lines[0]);
    assert!(
        first.contains("/analyze-session-logs"),
        "names the skill: {first}"
    );
    assert!(first.contains("injected by agent"), "the label: {first}");
    let name_span = r.lines[0]
        .spans
        .iter()
        .find(|s| s.content.contains("/analyze-session-logs"))
        .expect("a name span");
    assert!(
        name_span.style.add_modifier.contains(Modifier::BOLD),
        "the skill name is bold"
    );

    // Second line: the muted tree-style reason sub-line.
    let second = line_text(&r.lines[1]);
    assert!(second.contains('└'), "tree-style sub-line: {second}");
    assert!(
        second.contains("because you asked about tool-call effectiveness"),
        "carries the reason: {second}"
    );
    // The sub-line row is flagged as a continuation of the logical row.
    assert_eq!(r.continuations.len(), r.lines.len());
    assert!(r.continuations[1], "reason row is a continuation");
}

/// An entry WITHOUT a reason renders exactly one line, identical to
/// today's behavior (the plain-row edge).
#[test]
fn no_reason_renders_a_single_unchanged_line() {
    let entry = HistoryEntry::SkillAutoInjected {
        name: "firecrawl".to_string(),
        reason: None,
    };
    let r = render(&entry);
    assert_eq!(r.lines.len(), 1, "exactly one line when no reason");
    let line = line_text(&r.lines[0]);
    assert_eq!(line, "/firecrawl · injected by agent");
}

/// The JSON export round-trips the `reason` field.
#[test]
fn json_export_round_trips_reason() {
    let history = vec![
        HistoryEntry::SkillAutoInjected {
            name: "firecrawl".to_string(),
            reason: Some("matches: scrape, content".to_string()),
        },
        HistoryEntry::SkillAutoInjected {
            name: "deploy".to_string(),
            reason: None,
        },
    ];
    let exported = crate::tui::history::export_transcript(&history);
    let turns = exported.as_array().expect("an array of turns");

    assert_eq!(turns[0]["type"], "skill_auto_injected");
    assert_eq!(turns[0]["name"], "firecrawl");
    assert_eq!(turns[0]["reason"], "matches: scrape, content");

    // No reason → the field is present and null.
    assert!(
        turns[1]["reason"].is_null(),
        "absent reason exports as null"
    );
}
