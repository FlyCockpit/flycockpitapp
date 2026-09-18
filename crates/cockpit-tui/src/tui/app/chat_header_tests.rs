//! Tests for the three-row chat header: state assembly from real sources,
//! footer-replacement parity, pill drill-ins (mouse + keyboard), the
//! collapsed-pill popover, and narrow-width geometry.

use super::{
    App, AttentionInterruptKind, AttentionInterruptState, HistoryEntry, Overlay,
    StartupWorkspaceTrust, TranscriptFind,
};
use crate::tui::chat_header::{CHAT_HEADER_HEIGHT, HEADER_COLLAPSE_PROBE_WIDTHS, HeaderPillKind};
use crate::tui::pins_overlay::{CopyPick, ForkPick, PinPick, PinsReview};
use crate::tui::rules_overlay::RulesReview;
use cockpit_proto::{
    ConversationRule, ConversationRuleCreatedBy, ConversationRuleSourceTrust, PinnedMessage,
    RepoStatus,
};
use crossterm::event::{
    KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers, MouseButton, MouseEvent,
    MouseEventKind,
};
use ratatui::{Terminal, backend::TestBackend};
use std::time::Instant;
use uuid::Uuid;

fn press(code: KeyCode) -> KeyEvent {
    KeyEvent {
        code,
        modifiers: KeyModifiers::empty(),
        kind: KeyEventKind::Press,
        state: KeyEventState::empty(),
    }
}

fn click(kind: MouseEventKind, column: u16, row: u16) -> MouseEvent {
    MouseEvent {
        kind,
        column,
        row,
        modifiers: KeyModifiers::empty(),
    }
}

fn app(tmp: &tempfile::TempDir) -> App {
    let mut app =
        App::new_with_workspace_trust(Some(tmp.path()), false, StartupWorkspaceTrust::Decided);
    app.dialog = crate::tui::settings::Dialog::None;
    app.launch.banner_enabled = false;
    app.mouse_capture = true;
    app
}

fn repo(branch: &str, staged: u32, unstaged: u32, unpushed: u32) -> RepoStatus {
    RepoStatus {
        branch: branch.to_string(),
        staged,
        unstaged,
        unpushed,
    }
}

fn render(app: &mut App, width: u16, height: u16) -> ratatui::buffer::Buffer {
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).expect("test backend");
    terminal.draw(|frame| app.render(frame)).expect("draw");
    terminal.backend().buffer().clone()
}

fn row_text(buf: &ratatui::buffer::Buffer, y: u16) -> String {
    (0..buf.area.width)
        .map(|x| buf[(x, y)].symbol().to_string())
        .collect()
}

fn schedule(app: &mut App, job_id: &str, kind: &str) {
    app.active_schedules.insert(
        job_id.to_string(),
        super::ActiveSchedule {
            session_id: Uuid::new_v4(),
            label: format!("{kind} job"),
            kind: kind.to_string(),
            iteration: 1,
            last_activity: Instant::now(),
        },
    );
}

fn plain_lines(app: &App) -> Vec<String> {
    app.history
        .iter()
        .filter_map(|entry| match entry {
            HistoryEntry::Plain { line } => Some(line.clone()),
            _ => None,
        })
        .collect()
}

fn agent_entry(text: &str) -> HistoryEntry {
    HistoryEntry::Agent {
        name: "Build".to_string(),
        text: text.to_string(),
        reasoning: String::new(),
        timestamp: chrono::Local::now(),
        expanded: false,
        reasoning_offset: 0,
        think_duration: None,
        seq: Some(7),
        performance: None,
        performance_expanded: false,
    }
}

fn user_entry(text: &str) -> HistoryEntry {
    HistoryEntry::User {
        text: text.to_string(),
        cleaned: None,
        expanded: false,
        timestamp: chrono::Local::now(),
        seq: Some(6),
        optimistic_submission_id: None,
        preflight_pending: false,
        persist_failed: false,
    }
}

/// The header owns the one path/git summary; the footer no longer repeats
/// it, and the git-pending (unknown) state renders no slot.
#[test]
fn header_meta_row_replaces_footer_path_and_git() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = app(&tmp);
    app.launch.cwd_display = "/fly/repo".to_string();
    app.launch.repo_status = Some(repo("main", 1, 2, 0));

    let buf = render(&mut app, 100, 30);
    let layout = app
        .chat_header_layout
        .clone()
        .expect("header rendered in the chat shell");
    let meta = row_text(&buf, layout.area.y + 1);
    assert!(meta.contains("/fly/repo"), "path on the meta row: {meta:?}");
    assert!(
        meta.contains("main"),
        "branch badge on the meta row: {meta:?}"
    );
    assert!(
        meta.contains("+1 ~2"),
        "dirty counts on the meta row: {meta:?}"
    );

    let footer = row_text(&buf, 29);
    assert!(
        !footer.contains("/fly/repo") && !footer.contains("+1 ~2"),
        "footer must not duplicate the header summary: {footer:?}"
    );

    // Unknown git (probe pending / no repo): neutral state, no badge slot.
    app.launch.repo_status = None;
    let buf = render(&mut app, 100, 30);
    let layout = app.chat_header_layout.clone().expect("header rendered");
    let meta = row_text(&buf, layout.area.y + 1);
    assert!(meta.contains("/fly/repo"), "{meta:?}");
    assert!(
        !meta.contains('▐'),
        "no git slot while unresolved: {meta:?}"
    );
}

/// Every pill derives from established state; unknown/empty states omit the
/// pill rather than render a placeholder. The async-schedule strip summary
/// (task/timer) moved from the footer to pills.
#[test]
fn header_pills_draw_only_from_real_state() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = app(&tmp);

    let _ = render(&mut app, 100, 30);
    let layout = app.chat_header_layout.clone().expect("header rendered");
    assert!(
        layout.pill_buttons.is_empty(),
        "an idle session renders no activity pills"
    );

    // One timer job: exactly one timer pill, no `more` chip.
    schedule(&mut app, "t1", "timer");
    let buf = render(&mut app, 100, 30);
    let layout = app.chat_header_layout.clone().expect("header rendered");
    let kinds: Vec<_> = layout.pill_buttons.iter().map(|(k, _)| *k).collect();
    assert_eq!(kinds, vec![HeaderPillKind::Timer], "{kinds:?}");
    assert!(layout.more_button.is_none());
    let meta = row_text(&buf, layout.area.y + 1);
    assert!(meta.contains("[timer 1]"), "timer pill label: {meta:?}");

    // The footer no longer renders the schedule strip glyphs.
    let footer = row_text(&buf, 29);
    assert!(
        !footer.contains('⏲') && !footer.contains('⟳') && !footer.contains('⤓'),
        "footer must not duplicate the task/timer summary: {footer:?}"
    );

    // Two more task-kind jobs (background + loop) count into one task pill.
    schedule(&mut app, "b1", "background");
    schedule(&mut app, "l1", "loop");
    let buf = render(&mut app, 100, 30);
    let layout = app.chat_header_layout.clone().expect("header rendered");
    let kinds: Vec<_> = layout.pill_buttons.iter().map(|(k, _)| *k).collect();
    assert_eq!(kinds, vec![HeaderPillKind::Task, HeaderPillKind::Timer]);
    let meta = row_text(&buf, layout.area.y + 1);
    assert!(meta.contains("[task 2]"), "counted task label: {meta:?}");

    // An in-flight tool call surfaces the tool pill with the tool's name.
    app.history.push(HistoryEntry::ToolLine {
        call_id: "c1".to_string(),
        tool: "edit".to_string(),
        summary: "src/lib.rs".to_string(),
        icon_path: None,
        state: crate::tui::history::ToolCallState::Processing,
    });
    let _ = render(&mut app, 100, 30);
    let layout = app.chat_header_layout.clone().expect("header rendered");
    let kinds: Vec<_> = layout.pill_buttons.iter().map(|(k, _)| *k).collect();
    assert!(kinds.contains(&HeaderPillKind::Tool), "{kinds:?}");

    // A settled tool (ToolEnd applied) drops the pill again.
    if let Some(HistoryEntry::ToolLine { state, .. }) = app.history.get_mut(0) {
        *state = crate::tui::history::ToolCallState::Success;
    }
    let _ = render(&mut app, 100, 30);
    let layout = app.chat_header_layout.clone().expect("header rendered");
    let kinds: Vec<_> = layout.pill_buttons.iter().map(|(k, _)| *k).collect();
    assert!(!kinds.contains(&HeaderPillKind::Tool), "{kinds:?}");
}

/// Session status on the title row tracks real state: attention pending,
/// busy working, idle.
#[test]
fn header_session_status_tracks_real_state() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = app(&tmp);
    let buf = render(&mut app, 100, 30);
    let layout = app.chat_header_layout.clone().expect("header rendered");
    let title = row_text(&buf, layout.area.y);
    assert!(title.contains("Idle"), "idle by default: {title:?}");

    app.busy = true;
    let buf = render(&mut app, 100, 30);
    let title = row_text(&buf, 0);
    assert!(title.contains("Working"), "busy span: {title:?}");
    app.attention_interrupt = Some(AttentionInterruptState {
        interrupt_id: Uuid::new_v4(),
        kind: AttentionInterruptKind::Question,
        pending: true,
        pending_count: 1,
        next_renudge_at: Instant::now(),
    });
    let buf = render(&mut app, 100, 30);
    let title = row_text(&buf, 0);
    assert!(
        title.contains("Waiting"),
        "attention outranks busy: {title:?}"
    );
}

#[test]
fn agent_pill_opens_agent_tree() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = app(&tmp);
    app.busy = true;
    let _ = render(&mut app, 100, 30);
    app.activate_header_pill(HeaderPillKind::Agent);
    assert!(
        matches!(app.overlay, Overlay::AgentTree(_)),
        "agent pill opens the authoritative agent-tree overlay"
    );
}

#[test]
fn attention_pill_opens_agent_tree() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = app(&tmp);
    app.attention_interrupt = Some(AttentionInterruptState {
        interrupt_id: Uuid::new_v4(),
        kind: AttentionInterruptKind::Approval,
        pending: true,
        pending_count: 1,
        next_renudge_at: Instant::now(),
    });
    let _ = render(&mut app, 100, 30);
    app.activate_header_pill(HeaderPillKind::Attention);
    assert!(
        matches!(app.overlay, Overlay::AgentTree(_)),
        "attention pill opens the tree+attention surface"
    );
}

#[test]
fn tool_pill_opens_tools_pane() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = app(&tmp);
    app.agent_path = vec!["Build".to_string()];
    let _ = render(&mut app, 100, 30);
    app.activate_header_pill(HeaderPillKind::Tool);
    assert!(
        matches!(app.overlay, Overlay::Tools(_)),
        "tool pill opens the tools detail surface (same path as /tools)"
    );
}

#[test]
fn skill_pill_opens_skills_pane() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = app(&tmp);
    app.history.push(HistoryEntry::SkillAutoInjected {
        name: "firecrawl".to_string(),
        reason: None,
    });
    let _ = render(&mut app, 100, 30);
    app.activate_header_pill(HeaderPillKind::Skill);
    assert!(
        matches!(app.overlay, Overlay::Skills(_)),
        "skill pill opens the skills pane (same path as /skills)"
    );
}

#[test]
fn task_and_timer_pills_open_schedule_listing() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = app(&tmp);
    schedule(&mut app, "t1", "timer");
    schedule(&mut app, "b1", "background");
    let _ = render(&mut app, 100, 30);

    app.activate_header_pill(HeaderPillKind::Timer);
    let lines = plain_lines(&app);
    assert!(
        lines.iter().any(|l| l.contains("/schedule: active")),
        "timer pill routes through the /schedule command path: {lines:?}"
    );

    let before = plain_lines(&app).len();
    app.activate_header_pill(HeaderPillKind::Task);
    let lines = plain_lines(&app);
    assert!(
        lines.len() > before,
        "task pill routes through the /schedule command path: {lines:?}"
    );
}

/// Keyboard drill-in: ←/→ cycle the selection across this frame's active
/// pills, Enter opens the same surface a click opens, Esc clears, and any
/// other ordinary key releases the selection to the composer.
#[test]
fn header_pill_keyboard_cycles_and_enter_opens() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = app(&tmp);
    schedule(&mut app, "t1", "timer");
    schedule(&mut app, "b1", "background");
    let _ = render(&mut app, 100, 30);
    let layout = app.chat_header_layout.clone().expect("header rendered");
    let kinds = layout.active_kinds();
    assert_eq!(
        kinds,
        vec![HeaderPillKind::Task, HeaderPillKind::Timer],
        "cycling follows priority order"
    );

    app.header_pill_selection = Some(HeaderPillKind::Task);
    app.handle_key(press(KeyCode::Right));
    assert_eq!(app.header_pill_selection, Some(HeaderPillKind::Timer));
    app.handle_key(press(KeyCode::Right));
    assert_eq!(
        app.header_pill_selection,
        Some(HeaderPillKind::Task),
        "cycling wraps"
    );
    app.handle_key(press(KeyCode::Left));
    assert_eq!(app.header_pill_selection, Some(HeaderPillKind::Timer));

    app.handle_key(press(KeyCode::Enter));
    assert!(
        !matches!(app.overlay, Overlay::AgentTree(_)),
        "timer opens the schedule listing, not the tree"
    );
    assert!(
        plain_lines(&app)
            .iter()
            .any(|l| l.contains("/schedule: active")),
        "Enter on the timer pill routes through /schedule"
    );

    app.overlay = Overlay::None;
    app.header_pill_selection = Some(HeaderPillKind::Task);
    app.handle_key(press(KeyCode::Esc));
    assert_eq!(app.header_pill_selection, None);

    app.header_pill_selection = Some(HeaderPillKind::Task);
    app.handle_key(press(KeyCode::Char('x')));
    assert_eq!(
        app.header_pill_selection, None,
        "ordinary typing releases the pill selection"
    );
}

/// The collapsed-pill `more` popover opens from the counted chip, floats
/// over the transcript, activates a collapsed pill on click, and closes on
/// an outside press.
#[test]
fn header_more_popover_lists_and_activates_collapsed_pills() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = app(&tmp);
    app.busy = true;
    app.attention_interrupt = Some(AttentionInterruptState {
        interrupt_id: Uuid::new_v4(),
        kind: AttentionInterruptKind::Question,
        pending: true,
        pending_count: 1,
        next_renudge_at: Instant::now(),
    });
    app.history.push(HistoryEntry::SkillAutoInjected {
        name: "firecrawl".to_string(),
        reason: None,
    });
    schedule(&mut app, "t1", "timer");
    schedule(&mut app, "b1", "background");

    let _ = render(&mut app, 40, 30);
    let layout = app.chat_header_layout.clone().expect("header rendered");
    let (collapsed_count, _more_rect) = layout
        .more_button
        .expect("40 columns collapse lower-priority pills");
    assert_eq!(collapsed_count, layout.collapsed.len());
    assert!(collapsed_count >= 1);

    // Toggle open via the chip's dispatch path.
    app.dispatch_button(crate::tui::button::ButtonDispatch::HeaderMore);
    assert!(app.chat_header_more_open);
    let buf = render(&mut app, 40, 30);
    let popover = app.chat_header_more_rect.expect("popover painted");
    assert!(popover.y > layout.area.y, "popover floats below the header");
    let popover_text: String = (popover.y..popover.y + popover.height)
        .map(|y| row_text(&buf, y))
        .collect();
    assert!(
        popover_text.contains("skill firecrawl"),
        "collapsed pill labels list in the popover: {popover_text:?}"
    );

    // A click on a popover row activates that pill's surface.
    let skill_kind = HeaderPillKind::Skill;
    let skill_row = layout
        .collapsed
        .iter()
        .position(|p| p.kind == skill_kind)
        .expect("skill pill is collapsed at 40 columns");
    let row_y = popover.y + 1 + skill_row as u16; // rows live inside the border
    app.handle_mouse(click(
        MouseEventKind::Down(MouseButton::Left),
        popover.x + 2,
        row_y,
    ));
    app.handle_mouse(click(
        MouseEventKind::Up(MouseButton::Left),
        popover.x + 2,
        row_y,
    ));
    assert!(
        matches!(app.overlay, Overlay::Skills(_)),
        "popover row click opens the skills pane"
    );
    assert!(!app.chat_header_more_open, "activation closes the popover");

    // An outside press closes the popover without consuming the click.
    app.overlay = Overlay::None;
    app.dispatch_button(crate::tui::button::ButtonDispatch::HeaderMore);
    assert!(app.chat_header_more_open);
    let _ = render(&mut app, 40, 30);
    app.handle_mouse(click(MouseEventKind::Down(MouseButton::Left), 0, 29));
    assert!(
        !app.chat_header_more_open,
        "outside press closes the popover"
    );

    // Esc closes it too.
    app.dispatch_button(crate::tui::button::ButtonDispatch::HeaderMore);
    assert!(app.chat_header_more_open);
    app.handle_key(press(KeyCode::Esc));
    assert!(!app.chat_header_more_open);
}

/// A mouse click on a visible pill opens its surface directly.
#[test]
fn header_pill_click_opens_surface() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = app(&tmp);
    schedule(&mut app, "t1", "timer");
    let _ = render(&mut app, 100, 30);
    let layout = app.chat_header_layout.clone().expect("header rendered");
    let (_, rect) = layout
        .pill_buttons
        .iter()
        .find(|(kind, _)| *kind == HeaderPillKind::Timer)
        .expect("timer pill visible")
        .clone();
    let (x, y) = (rect.x + rect.width / 2, rect.y);
    app.handle_mouse(click(MouseEventKind::Down(MouseButton::Left), x, y));
    app.handle_mouse(click(MouseEventKind::Up(MouseButton::Left), x, y));
    assert!(
        plain_lines(&app)
            .iter()
            .any(|l| l.contains("/schedule: active")),
        "pill click routes through the schedule listing"
    );
    assert_eq!(app.header_pill_selection, Some(HeaderPillKind::Timer));
}

/// At 80, 56, and 40 columns the header keeps deterministic priority
/// collapse and the transcript keeps its reserved timestamp/control columns
/// without overlapping text.
#[test]
fn header_and_transcript_hold_reserved_columns_at_probe_widths() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = app(&tmp);
    app.busy = true;
    app.attention_interrupt = Some(AttentionInterruptState {
        interrupt_id: Uuid::new_v4(),
        kind: AttentionInterruptKind::Question,
        pending: true,
        pending_count: 1,
        next_renudge_at: Instant::now(),
    });
    app.history
        .push(user_entry("hello header this is the user message"));
    app.history.push(agent_entry(
        "agent reply that is long enough to wrap at narrow widths repeatedly",
    ));
    schedule(&mut app, "t1", "timer");
    schedule(&mut app, "b1", "background");

    for width in HEADER_COLLAPSE_PROBE_WIDTHS {
        let buf = render(&mut app, width, 30);
        let layout = app.chat_header_layout.clone().expect("header rendered");
        // The header renders beside the rail (wide layouts) or across the
        // chat (narrow); either way it stays inside the frame.
        assert!(layout.area.width <= width, "header spans the chat width");
        assert!(layout.area.right() <= width);

        // Rule row is a literal horizontal rule across the header's width
        // (the rail's border may share the row to its left).
        let full_rule = row_text(&buf, layout.area.y + 2);
        let rule: String = full_rule
            .chars()
            .skip(layout.area.x as usize)
            .take(layout.area.width as usize)
            .collect();
        assert!(
            !rule.is_empty() && rule.chars().all(|c| c == '─'),
            "row 3 is a rule at {width}: {rule:?}"
        );

        // The highest-priority pill survives; visible pills are a priority
        // prefix; collapse (when present) is counted.
        let visible: Vec<_> = layout.pill_buttons.iter().map(|(k, _)| *k).collect();
        assert_eq!(visible.first().copied(), Some(HeaderPillKind::Attention));
        if !layout.collapsed.is_empty() {
            let (n, _) = layout.more_button.expect("counted more chip");
            assert_eq!(n, layout.collapsed.len());
        }

        // No header row overflows the width.
        for y in layout.area.y..layout.area.y + 3 {
            let text = row_text(&buf, y);
            assert!(text.chars().count() <= width as usize);
        }

        // Transcript: the agent row keeps its right-aligned HH:MM timestamp
        // on the entry's first rendered row, and nothing overflows.
        let chat = app.chat_area.expect("history area");
        assert!(chat.y >= layout.area.y + 3);
        let ts = chrono::Local::now().format("%H:%M").to_string();
        let agent_first_row = (chat.y..chat.bottom())
            .map(|y| row_text(&buf, y))
            .find(|text| text.contains("agent reply"))
            .unwrap_or_else(|| {
                panic!(
                    "agent text visible at {width}: {:?}",
                    (chat.y..chat.bottom())
                        .map(|y| row_text(&buf, y))
                        .collect::<Vec<_>>()
                )
            });
        assert!(
            agent_first_row.contains(&ts) || agent_first_row.trim_end().ends_with(&ts),
            "timestamp reserved at {width}: {agent_first_row:?}"
        );
        for y in chat.y..chat.bottom() {
            let text = row_text(&buf, y);
            assert!(text.chars().count() <= width as usize, "row {y} overflows");
        }

        // Pin/fork controls keep their reserved columns beside the entries
        // they belong to: every recorded hit region parses back to exactly
        // its control glyphs (body text never renders under them), and each
        // fixture entry retains its controls after the header carve.
        let mut user_control_rows = 0usize;
        let mut agent_control_rows = 0usize;
        for (row, meta) in app.chat_row_meta.iter().enumerate() {
            let y = chat.y + row as u16;
            let region = |start: u16, end: u16| -> String {
                (start..end)
                    .map(|col| buf[(chat.x + col, y)].symbol().to_string())
                    .collect()
            };
            if let Some(hit) = meta.fork_hit {
                assert_eq!(
                    region(hit.col_start, hit.col_end),
                    "[fork]",
                    "fork columns reserved at {width}"
                );
            }
            if let Some(hit) = meta.pin_hit {
                let text = region(hit.col_start, hit.col_end);
                assert!(
                    text == "[pin]" || text == "[unpin]",
                    "pin columns reserved at {width}: {text:?}"
                );
            }
            match meta.history_index {
                Some(0) if meta.pin_hit.is_some() => user_control_rows += 1,
                Some(1) if meta.pin_hit.is_some() || meta.fork_hit.is_some() => {
                    agent_control_rows += 1
                }
                _ => {}
            }
        }
        assert!(
            user_control_rows >= 1,
            "user entry retains its pin/fork columns at {width}"
        );
        assert!(
            agent_control_rows >= 1,
            "agent entry retains its pin/fork columns at {width}"
        );
    }
}

/// Every moved control names its retained surface and a proof that is a
/// declared `#[test]` in this module — the app-level behavior suite that
/// builds the real App and renders — so a row cannot point at an unrelated
/// helper or a layout unit test that never exercises the replacement.
#[test]
fn header_parity_table_names_retained_surfaces_and_proofs() {
    let behavior_suite = include_str!("chat_header_tests.rs");
    let mut declared_tests = std::collections::HashSet::new();
    let mut lines = behavior_suite.lines();
    while let Some(line) = lines.next() {
        if line.trim() != "#[test]" {
            continue;
        }
        // rustfmt keeps the attribute directly above the item; the next
        // non-empty line is the `fn name(` declaration.
        let Some(declaration) = lines.by_ref().find(|l| !l.trim().is_empty()) else {
            break;
        };
        if let Some(name) = declaration.trim().strip_prefix("fn ")
            && let Some(name) = name.split('(').next()
        {
            declared_tests.insert(name.to_string());
        }
    }
    assert!(
        !declared_tests.is_empty(),
        "the behavior-suite scan must find the tests it validates"
    );
    for row in crate::tui::chat_header::capability_parity_table() {
        assert!(
            declared_tests.contains(row.proof),
            "parity proof {} for {} must be a declared #[test] in the app behavior suite",
            row.proof,
            row.control
        );
    }
}

/// A too-short chat pane skips the header rather than crowding out
/// history — the pane passes through unchanged, no layout is recorded (so
/// nothing in the header is activatable), and stale selection/popover
/// state is released.
#[test]
fn header_skips_when_pane_cannot_hold_history() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = app(&tmp);
    let backend = TestBackend::new(60, 8);
    let mut terminal = Terminal::new(backend).expect("test backend");
    schedule(&mut app, "t1", "timer");

    terminal
        .draw(|frame| {
            let pane = ratatui::layout::Rect::new(0, 0, 60, CHAT_HEADER_HEIGHT);
            let rest = app.render_chat_header(frame, pane);
            assert_eq!(rest, pane, "an unholdable pane passes through unchanged");
        })
        .expect("draw");
    assert!(app.chat_header_layout.is_none());
    assert!(!app.chat_header_more_open);
    assert!(app.chat_header_more_rect.is_none());

    // Stale selection/popover state from a previous frame is released.
    app.header_pill_selection = Some(HeaderPillKind::Timer);
    app.chat_header_more_open = true;
    terminal
        .draw(|frame| {
            let pane = ratatui::layout::Rect::new(0, 0, 60, CHAT_HEADER_HEIGHT);
            let _ = app.render_chat_header(frame, pane);
        })
        .expect("draw");
    assert_eq!(app.header_pill_selection, None);
    assert!(!app.chat_header_more_open);

    // A pane that can hold history renders the header and carves it.
    terminal
        .draw(|frame| {
            let pane = ratatui::layout::Rect::new(0, 0, 60, 8);
            let rest = app.render_chat_header(frame, pane);
            assert_eq!(rest, ratatui::layout::Rect::new(0, 3, 60, 5));
            assert!(app.chat_header_layout.is_some());
        })
        .expect("draw");
}

/// Header chrome never preempts a body-owning modal: with the approval
/// question dialog on top, pill keys reach the dialog, pill activation is
/// refused, and the collapsed-pill popover closes instead of floating
/// above the dialog's compact slot.
#[test]
fn header_pills_yield_to_the_question_dialog() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = app(&tmp);
    app.attention_interrupt = Some(AttentionInterruptState {
        interrupt_id: Uuid::new_v4(),
        kind: AttentionInterruptKind::Question,
        pending: true,
        pending_count: 1,
        next_renudge_at: Instant::now(),
    });
    schedule(&mut app, "t1", "timer");
    let _ = render(&mut app, 100, 30);
    assert!(
        app.chat_header_layout.is_some(),
        "the header renders behind the dialog"
    );

    app.question_dialog = Some(question_dialog());
    app.header_pill_selection = Some(HeaderPillKind::Timer);
    app.chat_header_more_open = true;

    // The mouse funnel (a pill click) is refused while the modal is up.
    app.activate_header_pill(HeaderPillKind::Attention);
    assert!(
        matches!(app.overlay, Overlay::None),
        "no surface opens over the dialog"
    );
    assert_eq!(app.header_pill_selection, None);

    // The popover closes instead of floating above the dialog.
    app.chat_header_more_open = true;
    let _ = render(&mut app, 100, 30);
    assert!(!app.chat_header_more_open);
    assert!(app.chat_header_more_rect.is_none());

    // Arrow keys cycle only when the header owns input; here they must
    // pass through to the dialog and release the stale selection.
    app.header_pill_selection = Some(HeaderPillKind::Timer);
    app.handle_key(press(KeyCode::Right));
    assert_eq!(
        app.header_pill_selection, None,
        "the dialog owns the key, not the pill cycler"
    );

    // Enter belongs to the dialog: the pill must not fire /schedule.
    // (Enter may resolve the dialog; only the pill side is asserted.)
    app.header_pill_selection = Some(HeaderPillKind::Timer);
    app.handle_key(press(KeyCode::Enter));
    assert!(
        !plain_lines(&app)
            .iter()
            .any(|l| l.contains("/schedule: active")),
        "Enter must reach the question dialog, not the timer pill"
    );
    assert_eq!(app.header_pill_selection, None);
}

/// Header chrome never preempts a body-owning keyboard modal: while any
/// pick/review mode is open, the mouse funnel (pill activation) is
/// refused, the collapsed-pill popover closes instead of floating above
/// the modal, and pill keys are swallowed by the modal rather than
/// cycling pills. The pick/review modes route ahead of the header in
/// `handle_key`, so the keyboard side is ordering-protected; these
/// assertions lock the mouse path to the same invariant. The fixture
/// keeps pills collapsed at 40 columns so the popover close can only come
/// from the gate, not from a missing `more` chip.
#[test]
fn header_pills_yield_to_pick_and_review_modals() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = app(&tmp);
    app.busy = true;
    app.attention_interrupt = Some(AttentionInterruptState {
        interrupt_id: Uuid::new_v4(),
        kind: AttentionInterruptKind::Approval,
        pending: true,
        pending_count: 1,
        next_renudge_at: Instant::now(),
    });
    app.history.push(HistoryEntry::SkillAutoInjected {
        name: "firecrawl".to_string(),
        reason: None,
    });
    schedule(&mut app, "t1", "timer");
    schedule(&mut app, "b1", "background");
    let _ = render(&mut app, 40, 30);
    let layout = app.chat_header_layout.clone().expect("header rendered");
    assert!(
        layout.more_button.is_some(),
        "fixture keeps pills collapsed so the popover close is meaningful"
    );

    let modes: Vec<(&str, Box<dyn Fn(&mut App)>)> = vec![
        (
            "/pin pick",
            Box::new(|app: &mut App| {
                app.pin_pick = PinPick::enter(vec![0]);
            }),
        ),
        (
            "/fork pick",
            Box::new(|app: &mut App| {
                app.fork_pick = ForkPick::enter(vec![0]);
            }),
        ),
        (
            "/copy-pick",
            Box::new(|app: &mut App| {
                app.copy_pick = CopyPick::enter(vec![0]);
            }),
        ),
        (
            "/pins review",
            Box::new(|app: &mut App| {
                app.pins_review = PinsReview::enter(vec![PinnedMessage {
                    seq: 1,
                    is_assistant: false,
                    text: "pinned".to_string(),
                }]);
            }),
        ),
        (
            "/rules review",
            Box::new(|app: &mut App| {
                app.rules_review = RulesReview::enter(vec![ConversationRule {
                    rule_id: Uuid::new_v4(),
                    lineage_id: Uuid::new_v4(),
                    text: "cite the spec".to_string(),
                    created_by: ConversationRuleCreatedBy::User,
                    source_trust: ConversationRuleSourceTrust::Trusted,
                    created_at_unix_ms: 0,
                }]);
            }),
        ),
    ];

    for (name, open) in modes {
        open(&mut app);

        // The mouse funnel (a pill click) is refused while the modal is
        // up: no surface opens, the task pill never fires /schedule, and
        // any selection is released.
        app.header_pill_selection = Some(HeaderPillKind::Timer);
        app.activate_header_pill(HeaderPillKind::Task);
        assert!(
            matches!(app.overlay, Overlay::None),
            "{name}: no surface opens over the modal"
        );
        assert!(
            !plain_lines(&app)
                .iter()
                .any(|l| l.contains("/schedule: active")),
            "{name}: the task pill must not fire /schedule over the modal"
        );
        assert_eq!(
            app.header_pill_selection, None,
            "{name}: refused activation releases the selection"
        );

        // The collapsed-pill popover closes instead of floating above the
        // modal.
        app.chat_header_more_open = true;
        let _ = render(&mut app, 40, 30);
        assert!(!app.chat_header_more_open, "{name}: popover closes");
        assert!(app.chat_header_more_rect.is_none(), "{name}: no popover");

        // The modal swallows the key: the pill cycler never runs, so the
        // selection cannot move (and Enter-style activation is unreachable
        // the same way).
        app.header_pill_selection = Some(HeaderPillKind::Timer);
        app.handle_key(press(KeyCode::Right));
        assert_eq!(
            app.header_pill_selection,
            Some(HeaderPillKind::Timer),
            "{name}: the modal owns the key, not the pill cycler"
        );

        // Reset every modal state before the next mode.
        app.pin_pick = None;
        app.fork_pick = None;
        app.copy_pick = None;
        app.pins_review = None;
        app.rules_review = None;
        app.transcript_find = None;
    }
}

/// The transcript-find bar is the same body-owning keyboard-modal class:
/// it paints over the transcript and swallows every key, but unlike the
/// pick/review modes its key routing sits *below* the header's, so the
/// gate must also refuse pill activation and release a stale selection —
/// otherwise a click could open an overlay over the find bar and the
/// click-set selection would outrank the bar's keys once the overlay
/// closes.
#[test]
fn header_pills_yield_to_the_transcript_find_bar() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = app(&tmp);
    app.busy = true;
    app.attention_interrupt = Some(AttentionInterruptState {
        interrupt_id: Uuid::new_v4(),
        kind: AttentionInterruptKind::Approval,
        pending: true,
        pending_count: 1,
        next_renudge_at: Instant::now(),
    });
    app.history.push(HistoryEntry::SkillAutoInjected {
        name: "firecrawl".to_string(),
        reason: None,
    });
    schedule(&mut app, "t1", "timer");
    schedule(&mut app, "b1", "background");
    let _ = render(&mut app, 40, 30);
    let layout = app.chat_header_layout.clone().expect("header rendered");
    assert!(
        layout.more_button.is_some(),
        "fixture keeps pills collapsed so the popover close is meaningful"
    );
    app.transcript_find = Some(TranscriptFind::default());

    // The mouse funnel (a pill click) is refused while the find bar owns
    // the keyboard.
    app.header_pill_selection = Some(HeaderPillKind::Timer);
    app.activate_header_pill(HeaderPillKind::Task);
    assert!(
        matches!(app.overlay, Overlay::None),
        "no surface opens over the find bar"
    );
    assert!(
        !plain_lines(&app)
            .iter()
            .any(|l| l.contains("/schedule: active")),
        "the task pill must not fire /schedule over the find bar"
    );
    assert_eq!(
        app.header_pill_selection, None,
        "refused activation releases the selection"
    );

    // The popover closes instead of floating above the find bar.
    app.chat_header_more_open = true;
    let _ = render(&mut app, 40, 30);
    assert!(!app.chat_header_more_open);
    assert!(app.chat_header_more_rect.is_none());

    // A stale selection releases its keys to the find bar instead of
    // cycling pills (the pill handler sits ahead of find routing, so only
    // the gate can hand the key back).
    app.header_pill_selection = Some(HeaderPillKind::Timer);
    app.handle_key(press(KeyCode::Right));
    assert_eq!(
        app.header_pill_selection, None,
        "the find bar owns the key, not the pill cycler"
    );
    assert!(
        app.transcript_find.is_some(),
        "the find bar stays open and keeps the key"
    );
}

/// While an overlay owns the body (the header did not render that frame),
/// a stale pill selection never swallows the overlay's keys.
#[test]
fn header_pill_selection_releases_keys_to_open_overlays() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = app(&tmp);
    app.history.push(HistoryEntry::SkillAutoInjected {
        name: "firecrawl".to_string(),
        reason: None,
    });
    let _ = render(&mut app, 100, 30);
    app.activate_header_pill(HeaderPillKind::Skill);
    assert!(matches!(app.overlay, Overlay::Skills(_)));

    app.header_pill_selection = Some(HeaderPillKind::Skill);
    assert!(
        !app.handle_header_pill_key(&press(KeyCode::Enter)),
        "the key falls through to the overlay"
    );
    assert_eq!(app.header_pill_selection, None);

    // Full key path: Esc reaches the skills pane and closes it instead of
    // being eaten by the pill selection handler.
    app.header_pill_selection = Some(HeaderPillKind::Skill);
    app.handle_key(press(KeyCode::Esc));
    assert!(
        matches!(app.overlay, Overlay::None),
        "Esc closes the skills pane"
    );
}

fn question_dialog() -> crate::tui::dialog::question::QuestionDialog {
    use cockpit_proto::{InterruptOption, InterruptQuestion, InterruptQuestionSet};
    crate::tui::dialog::question::QuestionDialog::new(
        Uuid::new_v4(),
        String::new(),
        InterruptQuestionSet {
            questions: vec![InterruptQuestion::Single {
                prompt: "Proceed?".to_string(),
                options: vec![
                    InterruptOption {
                        id: "yes".to_string(),
                        label: "Yes".to_string(),
                        description: None,
                        secondary: false,
                    },
                    InterruptOption {
                        id: "no".to_string(),
                        label: "No".to_string(),
                        description: None,
                        secondary: false,
                    },
                ],
                allow_freetext: false,
                command_detail: None,
                permission: false,
                approval_class: None,
                sandbox_escalation: None,
            }],
        },
        std::time::Duration::ZERO,
    )
}
