use super::*;
use cockpit_proto::MessageRole;
use crossterm::event::{KeyEventKind, KeyEventState, MouseButton, MouseEvent, MouseEventKind};
use ratatui::{Terminal, backend::TestBackend};
use std::collections::HashMap;

fn press(code: KeyCode) -> KeyEvent {
    KeyEvent {
        code,
        modifiers: KeyModifiers::empty(),
        kind: KeyEventKind::Press,
        state: KeyEventState::empty(),
    }
}

fn summary(id: Uuid, last_active: i64) -> SessionSummary {
    SessionSummary {
        session_id: id,
        session_entry_mode: "code".into(),
        short_id: Some("abc123".into()),
        project_root: "/proj/alpha".into(),
        project_id: "pid".into(),
        started_at_unix_ms: 0,
        last_active_at_unix_ms: last_active,
        turns: 0,
        active_agent: "builder".into(),
        title: Some(format!("session-{id}")),
        description: None,
        parent_session_id: None,
        fork_point_turn_id: None,
        is_assistant_thread: false,
        fork_count: 0,
        descendant_count: 0,
        last_viewed_at_unix_ms: None,
        latest_activity_at_unix_ms: None,
        open_interrupts: 0,
        activity_state: None,
        archived_at_unix_ms: None,
        favorite: false,
        created_by_principal: None,
        shared_with_collaborators: false,
        pin_count: 0,
        assistant_inbox_unread: 0,
        assistant_inbox_latest_source_session_id: None,
        compaction_predecessor_session_id: None,
        compaction_lineage_root_id: None,
        lineage_window_count: 1,
    }
}

fn test_rail(cards: Vec<(SessionSummary, Tier)>) -> SessionRail {
    let mut rail = SessionRail::new(None, std::path::Path::new("/project"), true, false);
    rail.loading = false;
    rail.list_generation = 1;
    rail.levels = vec![Level::with_cards(None, cards)];
    rail.project_id = Some("pid".into());
    rail.focus();
    rail
}

fn apply_list(rail: &mut SessionRail, sessions: Vec<SessionSummary>) {
    assert!(rail.begin_list());
    let generation = rail.list_generation;
    let attachment = rail.attachment_generation;
    rail.apply_sessions_result(generation, attachment, Ok(sessions));
}

fn start_archive(rail: &mut SessionRail) -> SessionsMutationEffect {
    rail.handle_key(press(KeyCode::Char('d')));
    rail.handle_key(press(KeyCode::Right));
    match rail.handle_key(press(KeyCode::Enter)) {
        Some(RailOutcome::Mutate(effect)) => *effect,
        other => panic!("expected archive mutate, got {other:?}"),
    }
}

fn ack_completion(effect: &SessionsMutationEffect) -> SessionsMutationCompletion {
    SessionsMutationCompletion {
        rail_id: effect.rail_id,
        operation_id: effect.operation_id,
        generation: effect.generation,
        attachment_generation: effect.attachment_generation,
        target: effect.target.clone(),
        response: Ok(cockpit_proto::Response::Ack),
    }
}

fn message(seq: i64, text: &str) -> SessionMessage {
    SessionMessage {
        seq,
        ts_ms: seq,
        role: MessageRole::User,
        text: text.into(),
    }
}

fn golden_rail(selected: bool, hovered: Option<usize>, visible: bool) -> ratatui::buffer::Buffer {
    let mut first = summary(Uuid::from_u128(1), 1_725_582_480_000);
    first.title = Some("Build session rail".into());
    first.favorite = true;
    first.pin_count = 2;
    let mut second = summary(Uuid::from_u128(2), 1_725_496_800_000);
    second.title = Some("Waiting for approval".into());
    second.open_interrupts = 1;
    let mut rail = test_rail(vec![
        (first, Tier::Processing),
        (second, Tier::PendingQuestion),
    ]);
    rail.current_mut().selected_session_id = if selected {
        Some(Uuid::from_u128(1))
    } else {
        None
    };
    rail.hovered_card = hovered;
    rail.set_visible(visible);
    crate::tui::golden::render_frame(120, 40, |frame| {
        let persistent = visible.then_some(Rect::new(0, 0, 30, 40));
        rail.render(frame, persistent, None, None, 120);
    })
}

#[test]
fn golden_rail_region_matches_excoc_paint_rules_120x40() {
    let _pins = crate::tui::golden::GoldenPins::install().allow_hover();
    let buffer = golden_rail(true, None, true);
    let rendered = crate::tui::golden::buffer_text(&buffer);
    let rail_width = 30usize;
    let crop = crop_buffer_width(&rendered, rail_width);
    let lines: Vec<_> = crop.lines().collect();
    assert!(
        lines
            .iter()
            .any(|line| line.contains('◆') && line.contains("Cockpit")),
        "excoc header uses the Do 6 ◆ Cockpit title"
    );
    assert!(
        lines.iter().any(|line| line.contains("[Hide]")),
        "open rail shows the excoc Hide chip"
    );
    assert!(
        lines.iter().any(|line| line.contains("+ New session")),
        "excoc new-session chip"
    );
    assert!(
        lines
            .iter()
            .any(|line| line.trim_start().starts_with("SESSIONS")),
        "excoc sessions label row"
    );
    assert!(
        lines.iter().any(|line| line.contains('▌')),
        "selected row uses excoc repeat-highlight"
    );
    assert!(
        lines
            .iter()
            .any(|line| line.contains('●') && line.contains("working")),
        "excoc legend names the working dot tier"
    );
    // Product-only selected-row metadata (third line) is allowed; excoc has no
    // equivalent, so this is not part of the excoc parity check.
    assert!(
        lines.iter().any(|line| line.contains("pin 2")),
        "selected-row product metadata remains a bounded extension"
    );
}

fn crop_buffer_width(text: &str, width: usize) -> String {
    text.lines()
        .map(|line| {
            let mut out = String::new();
            let mut cols = 0usize;
            for ch in line.chars() {
                let w = unicode_width::UnicodeWidthChar::width(ch).unwrap_or(0);
                if cols + w > width {
                    break;
                }
                out.push(ch);
                cols += w;
            }
            out
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}

#[test]
fn wheel_over_rail_steps_one_session_window() {
    let cards: Vec<_> = (0..20)
        .map(|i| {
            (
                summary(Uuid::from_u128(i as u128 + 1), 1000 - i),
                Tier::Idle,
            )
        })
        .collect();
    let mut rail = test_rail(cards);
    let backend = TestBackend::new(36, 14);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal
        .draw(|frame| {
            rail.render(frame, Some(Rect::new(0, 0, 36, 14)), None, None, 80);
        })
        .unwrap();
    assert!(
        20 > rail.session_viewport_for_test(),
        "sessions must overflow the viewport"
    );
    let before = rail.session_scroll_for_test();
    let list = rail.list_area_for_test().expect("list area");
    rail.handle_mouse(MouseEvent {
        kind: MouseEventKind::ScrollDown,
        column: list.x + 1,
        row: list.y + 1,
        modifiers: KeyModifiers::empty(),
    });
    assert_eq!(
        rail.session_scroll_for_test(),
        before + 1,
        "wheel down over the rail advances the session window by one"
    );
}

#[test]
fn sessions_keybindings_include_open_preview_and_switch_actions() {
    let group = SessionRail::keybindings();
    let actions: Vec<_> = group.bindings.iter().map(|b| b.action).collect();
    for required in ["open", "preview", "switch", "forks", "windows"] {
        assert!(
            actions.contains(&required),
            "missing Sessions which-key action: {required}"
        );
    }
}

#[test]
fn hover_archive_mutates_without_confirm_popover() {
    let id = Uuid::from_u128(1);
    let mut rail = test_rail(vec![(summary(id, 10), Tier::Idle)]);
    rail.action_hits = vec![ActionHit {
        index: 0,
        action: CardAction::Archive,
        rect: Rect::new(10, 1, 8, 1),
    }];
    let outcome = rail.handle_mouse(MouseEvent {
        kind: MouseEventKind::Down(MouseButton::Left),
        column: 11,
        row: 1,
        modifiers: KeyModifiers::empty(),
    });
    assert!(matches!(
        outcome,
        Some(RailOutcome::Mutate(effect))
            if matches!(effect.request, cockpit_proto::Request::ArchiveSession { cascade: true, .. })
    ));
    assert!(matches!(rail.step, Step::Browse));
}

#[test]
fn golden_session_rail_open_hidden_hovered_and_selected_120x40() {
    let _pins = crate::tui::golden::GoldenPins::install().allow_hover();
    for (name, selected, hovered, visible) in [
        ("open", false, None, true),
        ("hidden-show", false, None, false),
        ("hovered-row", false, Some(1), true),
        ("selected-row", true, None, true),
    ] {
        let buffer = golden_rail(selected, hovered, visible);
        crate::tui::golden::assert_golden("session-rail", name, 120, 40, &buffer);
    }
}

#[test]
fn named_width_tests_80_79_56_55() {
    assert!(matches!(
        RailLayoutMode::from_width(80),
        RailLayoutMode::Wide { .. }
    ));
    assert_eq!(RailLayoutMode::from_width(79), RailLayoutMode::Compact);
    assert_eq!(RailLayoutMode::from_width(56), RailLayoutMode::Compact);
    assert_eq!(
        RailLayoutMode::from_width(55),
        RailLayoutMode::HiddenUntilFocused
    );
    assert_eq!(
        RailLayoutMode::from_width_and_preference(120, false),
        RailLayoutMode::HiddenByPreference
    );
}

#[test]
fn wide_shell_keeps_persistent_cards_and_chat_remainder() {
    let rail = SessionRail::new(None, std::path::Path::new("/project"), true, false);
    let body = Rect::new(0, 0, 80, 24);
    let (persistent, chat) = rail.split_body(body, 80);
    let persistent = persistent.expect("wide layout has a persistent rail");
    assert!((RAIL_MIN_WIDTH..=RAIL_MAX_WIDTH).contains(&persistent.width));
    assert_eq!(persistent.width + chat.width, 80);
    assert!(chat.width > 0);
    assert!(rail.overlay_rail_rect(body, 80).is_none());
}

#[test]
fn compact_79_hides_cards_and_shows_affordance() {
    let mut rail = SessionRail::new(None, std::path::Path::new("/project"), true, false);
    let body = Rect::new(0, 0, 79, 24);
    let (persistent, chat) = rail.split_body(body, 79);
    let persistent = persistent.expect("compact unfocused affordance");
    assert_eq!(persistent.width, COMPACT_AFFORDANCE_WIDTH);
    assert_eq!(chat.width, 79 - COMPACT_AFFORDANCE_WIDTH);
    assert!(!RailLayoutMode::from_width(79).shows_persistent_cards());
    rail.focus();
    let (persistent_focused, chat_focused) = rail.split_body(body, 79);
    assert!(persistent_focused.is_none());
    assert_eq!(chat_focused.width, 79);
    let overlay = rail.overlay_rail_rect(body, 79).expect("focused overlay");
    assert!((RAIL_MIN_WIDTH..=RAIL_MAX_WIDTH).contains(&overlay.width));
}

#[test]
fn hidden_55_has_no_persistent_column_until_focused() {
    let mut rail = SessionRail::new(None, std::path::Path::new("/project"), true, false);
    let body = Rect::new(0, 0, 55, 24);
    let (persistent, chat) = rail.split_body(body, 55);
    assert!(persistent.is_none());
    assert_eq!(chat.width, 55);
    assert!(rail.overlay_rail_rect(body, 55).is_none());
    rail.focus();
    let overlay = rail.overlay_rail_rect(body, 55).expect("focused overlay");
    assert!(overlay.width > 0);
}

fn card_text(summary: &SessionSummary, tier: Tier) -> String {
    super::render::card_lines(summary, tier, true, true, 80, false)
        .iter()
        .flat_map(|line| line.spans.iter().map(|span| span.content.as_ref()))
        .collect()
}

#[test]
fn cards_render_only_daemon_confirmed_fields() {
    let mut favorite = summary(Uuid::from_u128(1), 10);
    favorite.favorite = true;
    assert!(card_text(&favorite, Tier::Idle).contains('★'));

    let mut archived = summary(Uuid::from_u128(2), 10);
    archived.archived_at_unix_ms = Some(5);
    assert!(card_text(&archived, Tier::Idle).contains("archived"));

    let mut pinned = summary(Uuid::from_u128(3), 10);
    pinned.pin_count = 2;
    assert!(card_text(&pinned, Tier::Idle).contains("pin 2"));

    let mut forked = summary(Uuid::from_u128(4), 10);
    forked.fork_count = 3;
    assert!(card_text(&forked, Tier::Idle).contains("3 forks"));

    let mut windows = summary(Uuid::from_u128(5), 10);
    windows.lineage_window_count = 4;
    assert!(card_text(&windows, Tier::Idle).contains("4 windows"));

    let mut inbox = summary(Uuid::from_u128(6), 10);
    inbox.assistant_inbox_unread = 1;
    inbox.assistant_inbox_latest_source_session_id = Some(Uuid::from_u128(7));
    assert!(card_text(&inbox, Tier::Idle).contains("inbox 1"));

    let mut pending = summary(Uuid::from_u128(8), 10);
    pending.open_interrupts = 2;
    assert!(card_text(&pending, Tier::PendingQuestion).contains("2 pending"));
    assert!(!card_text(&pending, Tier::PendingQuestion).contains("unknown metric"));
    assert!(!card_text(&pending, Tier::PendingQuestion).contains("fabricated"));
}

#[test]
fn unknown_metrics_are_omitted() {
    let s = summary(Uuid::from_u128(1), 10);
    let lines = super::render::card_lines(&s, Tier::Idle, false, false, 36, false);
    let text: String = lines
        .iter()
        .flat_map(|line| line.spans.iter().map(|span| span.content.as_ref()))
        .collect();
    assert!(!text.contains("pin"));
    assert!(!text.contains("fork"));
    assert!(!text.contains("inbox"));
    assert!(!text.contains("archived"));
    assert!(!text.contains('★'));
}

#[test]
fn rows_are_two_lines_with_a_bounded_selected_metadata_extension() {
    let mut s = summary(Uuid::from_u128(1), 10);
    s.pin_count = 2;
    let plain = super::render::card_lines(&s, Tier::ToolRunning, false, true, 80, false);
    let selected = super::render::card_lines(&s, Tier::ToolRunning, true, true, 80, false);
    assert_eq!(plain.len(), 2);
    assert_eq!(selected.len(), 3);
    let meta: String = selected[2]
        .spans
        .iter()
        .map(|span| span.content.as_ref())
        .collect();
    assert!(meta.contains("tool running"));
    assert!(meta.contains("[alpha]"));
    assert!(meta.contains("pin 2"));
    assert!(selected[0].spans[0].content.contains('▌'));
    assert!(selected[1].spans[0].content.contains('▌'));
}

#[test]
fn activity_tiers_collapse_to_four_reference_dot_colours() {
    for tier in [
        Tier::ActiveSchedules,
        Tier::ToolRunning,
        Tier::InferenceInProgress,
        Tier::Processing,
    ] {
        assert_eq!(tier.color(), crate::tui::theme::YELLOW);
    }
    for tier in [Tier::Interrupted, Tier::PendingQuestion, Tier::Unread] {
        assert_eq!(tier.color(), crate::tui::theme::RED);
    }
    assert_eq!(Tier::Done.color(), crate::tui::theme::GOOD);
    assert_eq!(Tier::Idle.color(), crate::tui::theme::DISABLED);
}

#[test]
fn list_scopes_send_existing_request_shapes() {
    let mut rail = test_rail(vec![(summary(Uuid::from_u128(1), 10), Tier::Idle)]);
    rail.project_id = Some("pid".into());
    rail.scope = Scope::Project;
    let (project, parent, lineage) = rail.root_request();
    assert_eq!(project.as_deref(), Some("pid"));
    assert!(parent.is_none());
    assert!(lineage.is_none());

    rail.scope = Scope::All;
    let (project, _, _) = rail.root_request();
    assert!(project.is_none());

    let mut parent_summary = summary(Uuid::from_u128(2), 10);
    parent_summary.fork_count = 1;
    rail.levels = vec![Level::with_cards(
        None,
        vec![(parent_summary.clone(), Tier::Idle)],
    )];
    rail.focus();
    assert!(rail.drill_in());
    let (_, parent, lineage) = rail.root_request();
    assert_eq!(parent, Some(parent_summary.session_id));
    assert!(lineage.is_none());

    let mut window = summary(Uuid::from_u128(3), 10);
    window.lineage_window_count = 2;
    window.compaction_lineage_root_id = Some(Uuid::from_u128(9));
    rail.levels = vec![Level::with_cards(None, vec![(window.clone(), Tier::Idle)])];
    assert!(rail.drill_in_lineage());
    let (_, parent, lineage) = rail.root_request();
    assert!(parent.is_none());
    assert_eq!(lineage, Some(Uuid::from_u128(9)));
}

#[test]
fn selection_uuid_survives_refresh_when_still_present() {
    let keep = Uuid::from_u128(1);
    let drop = Uuid::from_u128(2);
    let mut rail = test_rail(vec![
        (summary(keep, 20), Tier::Idle),
        (summary(drop, 10), Tier::Idle),
    ]);
    rail.current_mut().selected_session_id = Some(keep);
    apply_list(
        &mut rail,
        vec![summary(keep, 30), summary(Uuid::from_u128(3), 5)],
    );
    assert_eq!(rail.selected_id(), Some(keep));
}

#[test]
fn selection_clears_when_uuid_leaves_projection() {
    let gone = Uuid::from_u128(1);
    let mut rail = test_rail(vec![(summary(gone, 20), Tier::Idle)]);
    rail.current_mut().selected_session_id = Some(gone);
    apply_list(&mut rail, vec![summary(Uuid::from_u128(2), 10)]);
    assert_ne!(rail.selected_id(), Some(gone));
}

#[test]
fn late_list_does_not_change_membership() {
    let mut rail = test_rail(vec![]);
    assert!(rail.begin_list());
    let stale_gen = rail.list_generation;
    let attach = rail.attachment_generation;
    assert!(rail.begin_list());
    let fresh_gen = rail.list_generation;
    rail.apply_sessions_result(stale_gen, attach, Ok(vec![summary(Uuid::from_u128(99), 1)]));
    assert!(rail.current().cards.is_empty());
    rail.apply_sessions_result(fresh_gen, attach, Ok(vec![summary(Uuid::from_u128(1), 1)]));
    assert_eq!(rail.current().cards.len(), 1);
    assert_eq!(rail.current().cards[0].0.session_id, Uuid::from_u128(1));
}

#[test]
fn late_preview_cannot_overwrite_new_selection() {
    let first = Uuid::from_u128(1);
    let second = Uuid::from_u128(2);
    let mut rail = test_rail(vec![
        (summary(first, 20), Tier::Idle),
        (summary(second, 10), Tier::Idle),
    ]);
    rail.current_mut().selected_session_id = Some(first);
    let started = rail.begin_preview(None).expect("preview");
    assert_eq!(started.0, first);
    rail.current_mut().selected_session_id = Some(second);
    rail.preview = Some(PreviewState::new(
        second,
        rail.list_generation,
        rail.attachment_generation,
    ));
    rail.apply_preview_result(
        rail.list_generation,
        rail.attachment_generation,
        first,
        None,
        Ok((
            vec![SessionMessage {
                seq: 1,
                ts_ms: 1,
                role: MessageRole::User,
                text: "stale".into(),
            }],
            false,
        )),
    );
    assert_eq!(rail.preview_session_id(), Some(second));
    assert_eq!(rail.preview_message_count(), 0);
}

#[test]
fn late_live_status_is_generation_fenced() {
    let id = Uuid::from_u128(1);
    let mut rail = test_rail(vec![(summary(id, 10), Tier::Idle)]);
    apply_list(&mut rail, vec![summary(id, 10)]);
    let ids = rail.begin_live(vec![id]).expect("live");
    assert_eq!(ids.len(), 1);
    let list_gen = rail.list_generation;
    let attach = rail.attachment_generation;
    rail.apply_live_status(
        list_gen.wrapping_add(1),
        attach,
        Ok(HashMap::from([(id, (true, true))])),
    );
    assert_eq!(rail.current().cards[0].1, Tier::Idle);
    rail.apply_live_status(list_gen, attach, Ok(HashMap::from([(id, (true, true))])));
    assert_eq!(rail.current().cards[0].1, Tier::ActiveSchedules);
}

#[test]
fn favorite_result_uses_captured_generation() {
    let id = Uuid::from_u128(1);
    let mut rail = test_rail(vec![(summary(id, 10), Tier::Idle)]);
    let list_gen = rail.list_generation;
    let attach = rail.attachment_generation;
    let started = rail.begin_favorite(id, true).expect("favorite");
    assert!(rail.begin_list());
    rail.apply_sessions_result(rail.list_generation, attach, Ok(vec![]));
    rail.apply_favorite_result(list_gen, attach, started.1, id, Ok((started.1, true)));
    assert!(
        rail.current().cards.is_empty(),
        "stale favorite must not restore a deleted card"
    );
}

#[test]
fn archive_and_delete_use_cascade_confirm() {
    let id = Uuid::from_u128(1);
    let mut s = summary(id, 10);
    s.descendant_count = 4;
    let mut rail = test_rail(vec![(s, Tier::Idle)]);
    rail.handle_key(press(KeyCode::Char('d')));
    assert!(matches!(
        rail.step,
        Step::Confirm {
            descendants: 4,
            choice: ConfirmChoice::Cancel,
            ..
        }
    ));
    rail.handle_key(press(KeyCode::Right));
    let outcome = rail.handle_key(press(KeyCode::Enter));
    assert!(matches!(
        outcome,
        Some(RailOutcome::Mutate(effect))
            if matches!(effect.request, cockpit_proto::Request::ArchiveSession { cascade: true, .. })
    ));
}

#[test]
fn card_click_outside_action_hits_does_not_mutate() {
    let id = Uuid::from_u128(1);
    let mut rail = test_rail(vec![(summary(id, 10), Tier::Idle)]);
    rail.card_hits = vec![CardHit {
        index: 0,
        rect: Rect::new(0, 0, 20, 4),
    }];
    rail.action_hits.clear();
    let outcome = rail.handle_mouse(MouseEvent {
        kind: MouseEventKind::Down(MouseButton::Left),
        column: 2,
        row: 1,
        modifiers: KeyModifiers::empty(),
    });
    assert!(!matches!(outcome, Some(RailOutcome::Mutate(_))));
    assert!(!matches!(outcome, Some(RailOutcome::Resume(_))));
}

#[test]
fn filtered_title_click_selects_the_visible_row() {
    let beta_id = Uuid::from_u128(2);
    let mut alpha = summary(Uuid::from_u128(1), 100);
    alpha.title = Some("alpha".into());
    let mut beta = summary(beta_id, 90);
    beta.title = Some("beta".into());
    let mut rail = test_rail(vec![(alpha, Tier::Idle), (beta, Tier::Idle)]);
    rail.current_mut().selected_session_id = Some(Uuid::from_u128(1));
    rail.search = "beta".into();
    rail.card_hits = vec![CardHit {
        index: 0,
        rect: Rect::new(0, 5, 20, 2),
    }];
    rail.handle_mouse(MouseEvent {
        kind: MouseEventKind::Down(MouseButton::Left),
        column: 2,
        row: 5,
        modifiers: KeyModifiers::empty(),
    });
    assert_eq!(
        rail.selected_id(),
        Some(beta_id),
        "title click indices follow filtered_cards(), not the raw card list"
    );
}

#[test]
fn open_hit_resumes_and_favorite_hit_does_not() {
    let id = Uuid::from_u128(1);
    let mut rail = test_rail(vec![(summary(id, 10), Tier::Idle)]);
    rail.action_hits = vec![
        ActionHit {
            index: 0,
            action: CardAction::Open,
            rect: Rect::new(0, 0, 6, 1),
        },
        ActionHit {
            index: 0,
            action: CardAction::Favorite,
            rect: Rect::new(8, 0, 4, 1),
        },
    ];
    let open = rail.handle_mouse(MouseEvent {
        kind: MouseEventKind::Down(MouseButton::Left),
        column: 1,
        row: 0,
        modifiers: KeyModifiers::empty(),
    });
    assert!(matches!(open, Some(RailOutcome::Resume(got)) if got == id));
    let fav = rail.handle_mouse(MouseEvent {
        kind: MouseEventKind::Down(MouseButton::Left),
        column: 9,
        row: 0,
        modifiers: KeyModifiers::empty(),
    });
    assert!(matches!(fav, Some(RailOutcome::SetFavorite { .. })));
}

#[test]
fn escape_returns_focus_to_composer() {
    let mut rail = test_rail(vec![(summary(Uuid::from_u128(1), 10), Tier::Idle)]);
    assert!(rail.is_focused());
    assert!(matches!(
        rail.handle_key(press(KeyCode::Esc)),
        Some(RailOutcome::Unfocus)
    ));
    assert!(!rail.is_focused());
}

#[test]
fn slash_starts_search_while_focused() {
    let mut rail = test_rail(vec![(summary(Uuid::from_u128(1), 10), Tier::Idle)]);
    rail.handle_key(press(KeyCode::Char('/')));
    assert!(rail.is_search_focused());
    rail.handle_key(press(KeyCode::Char('s')));
    assert_eq!(rail.search_query(), "s");
}

#[test]
fn unfocused_rail_ignores_navigation_keys() {
    let mut rail = test_rail(vec![(summary(Uuid::from_u128(1), 10), Tier::Idle)]);
    rail.unfocus();
    assert!(rail.handle_key(press(KeyCode::Down)).is_none());
    assert!(rail.handle_key(press(KeyCode::Enter)).is_none());
}

#[test]
fn card_storage_is_bounded_by_list_limit() {
    let sessions: Vec<_> = (0..150)
        .map(|i| summary(Uuid::from_u128(i + 1), i as i64))
        .collect();
    let mut rail = test_rail(vec![]);
    apply_list(&mut rail, sessions);
    assert!(rail.card_count() <= LIST_LIMIT);
    assert!(rail.stored_card_bound_ok());
}

#[test]
fn churn_keeps_one_in_flight_list_live_preview_and_coalesced_favorite() {
    let root = Uuid::from_u128(7);
    let mut a = summary(Uuid::from_u128(1), 20);
    a.compaction_lineage_root_id = Some(root);
    let b = summary(Uuid::from_u128(2), 10);
    let mut rail = test_rail(vec![(a.clone(), Tier::Idle), (b.clone(), Tier::Idle)]);
    rail.list_generation = 0;
    rail.counts = RailRequestCounts::default();
    assert!(rail.begin_list());
    assert_eq!(rail.request_counts().list_in_flight, 1);
    assert!(rail.begin_list());
    assert_eq!(rail.request_counts().list_in_flight, 1);
    assert_eq!(rail.request_counts().list_started, 2);
    let list_gen = rail.list_generation;
    let attach = rail.attachment_generation;
    rail.apply_sessions_result(list_gen, attach, Ok(vec![a.clone(), b.clone()]));
    assert_eq!(rail.request_counts().list_in_flight, 0);

    let ids = rail.begin_live(vec![a.session_id, b.session_id]).unwrap();
    assert!(ids.len() <= LIST_LIMIT);
    assert_eq!(rail.request_counts().live_in_flight, 1);
    rail.begin_live(vec![a.session_id, b.session_id]);
    assert_eq!(rail.request_counts().live_in_flight, 1);

    rail.current_mut().selected_session_id = Some(a.session_id);
    rail.begin_preview(None);
    rail.begin_preview(None);
    assert_eq!(rail.request_counts().preview_in_flight, 1);
    let stale_preview = (
        rail.list_generation,
        rail.attachment_generation,
        a.session_id,
    );
    assert!(
        rail.handle_key(press(KeyCode::Down)).is_some(),
        "selection change must replace the pending preview"
    );
    assert_eq!(rail.selected_id(), Some(b.session_id));
    assert_eq!(rail.request_counts().preview_in_flight, 1);
    rail.apply_preview_result(
        stale_preview.0,
        stale_preview.1,
        stale_preview.2,
        None,
        Ok((vec![message(1, "stale")], false)),
    );
    assert_eq!(
        rail.request_counts().preview_in_flight,
        1,
        "stale preview for the previous selection must not consume the replacement in-flight slot"
    );
    assert_eq!(rail.preview_session_id(), Some(b.session_id));
    assert_eq!(rail.preview_message_count(), 0);

    rail.begin_favorite(a.session_id, true);
    rail.begin_favorite(a.session_id, false);
    rail.begin_favorite(a.session_id, true);
    assert_eq!(rail.request_counts().favorite_in_flight, 1);
    let counts = rail.request_counts();
    assert!(counts.list_in_flight <= 1);
    assert!(counts.live_in_flight <= 1);
    assert!(counts.preview_in_flight <= 1);
    assert!(counts.favorite_in_flight <= 1);
}

#[test]
fn attachment_change_discards_generations_and_favorite_intent() {
    let id = Uuid::from_u128(1);
    let mut rail = test_rail(vec![(summary(id, 10), Tier::Idle)]);
    rail.begin_list();
    rail.begin_favorite(id, true);
    let mutation = start_archive(&mut rail);
    rail.discard_for_attachment_change();
    assert_eq!(rail.request_counts().list_in_flight, 0);
    assert_eq!(rail.request_counts().favorite_in_flight, 0);
    assert!(!rail.has_unsettled_local_authority());
    assert!(rail.current().cards.is_empty());
    assert_eq!(rail.list_generation(), 0);
    assert!(
        !rail.apply_mutation_completion(ack_completion(&mutation)),
        "pre-attachment archive must not commit"
    );
    assert_ne!(rail.notice(), Some("archive committed"));
}

#[test]
fn comparator_orders_favorite_tier_recency_uuid() {
    let mut fav_idle = summary(Uuid::from_u128(10), 40);
    fav_idle.favorite = true;
    let mut fav_live = summary(Uuid::from_u128(11), 30);
    fav_live.favorite = true;
    let unfav_idle = summary(Uuid::from_u128(20), 90);
    let unfav_live = summary(Uuid::from_u128(21), 80);
    let sorted = tier_sort(vec![
        (unfav_idle.clone(), None),
        (fav_idle.clone(), None),
        (unfav_live.clone(), Some((false, true))),
        (fav_live.clone(), Some((false, true))),
    ]);
    assert_eq!(
        sorted.iter().map(|(s, _)| s.session_id).collect::<Vec<_>>(),
        vec![
            fav_live.session_id,
            fav_idle.session_id,
            unfav_live.session_id,
            unfav_idle.session_id,
        ]
    );
}

#[test]
fn comparator_equal_timestamps_order_uuid_ascending() {
    let a = summary(Uuid::from_u128(2), 50);
    let b = summary(Uuid::from_u128(1), 50);
    let sorted = tier_sort(vec![(a.clone(), None), (b.clone(), None)]);
    assert_eq!(sorted[0].0.session_id, b.session_id);
}

#[test]
fn comparator_does_not_reconstruct_eligibility() {
    // Assistant-filtered / restricted-peer favorites beyond a pre-filter cap
    // arrive already in the daemon projection. The rail only reorders.
    let mut far_favorite = summary(Uuid::from_u128(1000), 1);
    far_favorite.favorite = true;
    far_favorite.created_by_principal = Some("peer".into());
    far_favorite.shared_with_collaborators = true;
    let recent = summary(Uuid::from_u128(1), 9_999);
    let sorted = tier_sort(vec![(recent.clone(), None), (far_favorite.clone(), None)]);
    assert!(sorted[0].0.favorite);
    assert_eq!(sorted[0].0.session_id, far_favorite.session_id);
    assert_eq!(sorted.len(), 2);
}

#[test]
fn capability_parity_table_covers_sessions_pane_operations() {
    let names: Vec<_> = capability_parity_table()
        .iter()
        .map(|row| row.operation)
        .collect();
    for required in [
        "project/all scope",
        "root list",
        "fork drill-in",
        "compaction lineage",
        "active/archived filter",
        "search/clear",
        "selected preview pagination",
        "resume",
        "fork",
        "compaction drill-in",
        "attention/unread/live",
        "favorite",
        "archive",
        "unarchive",
        "delete",
        "inbox source",
        "assistant inbox",
        "mouse confirm",
    ] {
        assert!(names.contains(&required), "missing parity row: {required}");
    }
}

#[test]
fn skeleton_has_no_fabricated_counts() {
    let mut rail = SessionRail::new(None, std::path::Path::new("/project"), true, false);
    assert!(rail.is_loading());
    let backend = TestBackend::new(36, 20);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal
        .draw(|frame| {
            rail.render(frame, Some(Rect::new(0, 0, 36, 20)), None, None, 80);
        })
        .unwrap();
    let buffer = terminal.backend().buffer();
    let text: String = buffer
        .content()
        .iter()
        .map(|cell| cell.symbol().to_string())
        .collect();
    assert!(!text.contains("unread"));
    assert!(!text.contains("jobs running"));
    assert!(!text.contains("pin "));
}

#[test]
fn empty_search_scope_is_truthful() {
    let mut rail = test_rail(vec![(summary(Uuid::from_u128(1), 10), Tier::Idle)]);
    rail.search = "no-such-session".into();
    assert!(rail.visible_cards().is_empty());
    let backend = TestBackend::new(36, 16);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal
        .draw(|frame| {
            rail.render(frame, Some(Rect::new(0, 0, 36, 16)), None, None, 80);
        })
        .unwrap();
    let buffer = terminal.backend().buffer();
    let text: String = buffer
        .content()
        .iter()
        .map(|cell| cell.symbol().to_string())
        .collect();
    assert!(text.contains("no active sessions") || text.contains("matching"));
}

#[test]
fn disconnected_preserves_stale_cards() {
    let id = Uuid::from_u128(1);
    let mut rail = test_rail(vec![(summary(id, 10), Tier::Idle)]);
    rail.set_daemon_connected(false);
    assert!(rail.is_stale());
    assert_eq!(rail.card_count(), 1);
    assert!(rail.begin_favorite(id, true).is_none());
}

#[test]
fn enter_resumes_selected_session() {
    let id = Uuid::from_u128(1);
    let mut rail = test_rail(vec![(summary(id, 10), Tier::Idle)]);
    assert!(matches!(
        rail.handle_key(press(KeyCode::Enter)),
        Some(RailOutcome::Resume(got)) if got == id
    ));
}

#[test]
fn fork_and_lineage_are_named_rail_actions() {
    let mut parent = summary(Uuid::from_u128(1), 10);
    parent.fork_count = 2;
    let mut rail = test_rail(vec![(parent, Tier::Idle)]);
    assert!(matches!(
        rail.handle_key(press(KeyCode::Right)),
        Some(RailOutcome::LoadList)
    ));

    let mut window = summary(Uuid::from_u128(2), 10);
    window.lineage_window_count = 3;
    let mut rail = test_rail(vec![(window, Tier::Idle)]);
    assert!(matches!(
        rail.handle_key(press(KeyCode::Char('e'))),
        Some(RailOutcome::LoadList)
    ));
}

#[test]
fn unarchive_is_a_named_rail_action() {
    let mut archived = summary(Uuid::from_u128(1), 10);
    archived.archived_at_unix_ms = Some(4);
    let mut rail = test_rail(vec![(archived, Tier::Idle)]);
    rail.show_archived = true;
    assert!(matches!(
        rail.handle_key(press(KeyCode::Char('u'))),
        Some(RailOutcome::Mutate(effect))
            if matches!(effect.request, cockpit_proto::Request::UnarchiveSession { .. })
    ));
}

#[test]
fn archived_filter_reloads_list() {
    let mut rail = test_rail(vec![(summary(Uuid::from_u128(1), 10), Tier::Idle)]);
    assert!(!rail.include_archived());
    assert!(matches!(
        rail.handle_key(press(KeyCode::Char('a'))),
        Some(RailOutcome::LoadList)
    ));
    assert!(rail.include_archived());
}

#[test]
fn inbox_source_resumes_source_session() {
    let source = Uuid::from_u128(9);
    let mut card = summary(Uuid::from_u128(1), 10);
    card.assistant_inbox_latest_source_session_id = Some(source);
    let mut rail = test_rail(vec![(card, Tier::Idle)]);
    assert!(matches!(
        rail.handle_key(press(KeyCode::Char('i'))),
        Some(RailOutcome::Resume(got)) if got == source
    ));
}

#[test]
fn assistant_inbox_loads_inbox() {
    let id = Uuid::from_u128(1);
    let mut rail = test_rail(vec![(summary(id, 10), Tier::Idle)]);
    assert!(matches!(
        rail.handle_key(press(KeyCode::Char('n'))),
        Some(RailOutcome::LoadInbox { main_session_id }) if main_session_id == id
    ));
}

#[test]
fn mouse_confirm_archive_dispatches_existing_mutation() {
    let id = Uuid::from_u128(1);
    let mut rail = test_rail(vec![(summary(id, 10), Tier::Idle)]);
    rail.handle_key(press(KeyCode::Char('d')));
    let outcome =
        rail.pointer_activate_confirm(crate::tui::button::ButtonDispatch::SessionsConfirmArchive);
    assert!(matches!(
        outcome,
        Some(RailOutcome::Mutate(effect))
            if matches!(effect.request, cockpit_proto::Request::ArchiveSession { cascade: true, .. })
    ));
}

#[test]
fn preview_pagination_is_fenced_and_capped() {
    let id = Uuid::from_u128(1);
    let mut rail = test_rail(vec![(summary(id, 10), Tier::Idle)]);
    rail.current_mut().selected_session_id = Some(id);
    rail.begin_preview(None);
    let list_gen = rail.list_generation;
    let attach = rail.attachment_generation;
    rail.apply_preview_result(
        list_gen,
        attach,
        id,
        None,
        Ok((vec![message(100, "newest")], true)),
    );
    assert_eq!(rail.preview_message_count(), 1);

    rail.begin_preview(Some(100));
    rail.apply_preview_result(
        list_gen,
        attach,
        id,
        None,
        Ok((vec![message(1, "stale-first-page")], false)),
    );
    assert_eq!(rail.preview_message_count(), 1);
    assert_eq!(rail.preview.as_ref().unwrap().messages[0].text, "newest");

    rail.apply_preview_result(
        list_gen,
        attach,
        id,
        Some(100),
        Ok((vec![message(50, "older")], true)),
    );
    assert_eq!(rail.preview_message_count(), 2);
    assert_eq!(rail.preview.as_ref().unwrap().messages[0].text, "older");

    let mut older_pages = Vec::new();
    for seq in 0..PREVIEW_MAX_MESSAGES as i64 {
        older_pages.push(message(seq, "page"));
    }
    rail.begin_preview(Some(50));
    rail.apply_preview_result(list_gen, attach, id, Some(50), Ok((older_pages, true)));
    assert!(rail.preview_message_count() <= PREVIEW_MAX_MESSAGES);
    assert!(rail.stored_card_bound_ok());
    assert!(
        rail.begin_preview(Some(0)).is_none(),
        "pagination must stop at the preview window cap"
    );
}

#[test]
fn stale_preview_error_does_not_poison_current_preview() {
    let id = Uuid::from_u128(1);
    let mut rail = test_rail(vec![(summary(id, 10), Tier::Idle)]);
    rail.current_mut().selected_session_id = Some(id);
    rail.begin_preview(None);
    let first_gen = rail.list_generation;
    let attach = rail.attachment_generation;
    rail.invalidate_for_search();
    rail.begin_preview(None);
    let second_gen = rail.list_generation;
    assert_ne!(first_gen, second_gen);
    rail.apply_preview_result(
        first_gen,
        attach,
        id,
        None,
        Err("stale preview failed".into()),
    );
    assert!(rail.preview_error().is_none());
    rail.apply_preview_result(
        second_gen,
        attach,
        id,
        None,
        Err("current preview failed".into()),
    );
    assert_eq!(rail.preview_error(), Some("current preview failed"));
}

#[test]
fn search_invalidates_in_flight_projection_reads() {
    let keep = Uuid::from_u128(1);
    let mut rail = test_rail(vec![(summary(keep, 10), Tier::Idle)]);
    assert!(rail.begin_list());
    let stale_gen = rail.list_generation;
    let attach = rail.attachment_generation;
    rail.handle_key(press(KeyCode::Char('/')));
    rail.handle_key(press(KeyCode::Char('s')));
    assert_eq!(rail.search_query(), "s");
    assert_eq!(rail.request_counts().list_in_flight, 0);
    rail.apply_sessions_result(stale_gen, attach, Ok(vec![summary(Uuid::from_u128(99), 1)]));
    assert_eq!(rail.current().cards[0].0.session_id, keep);
}

#[test]
fn reconnect_invalidates_pending_intents() {
    let id = Uuid::from_u128(1);
    let mut rail = test_rail(vec![(summary(id, 10), Tier::Idle)]);
    assert!(rail.begin_list());
    rail.begin_favorite(id, true);
    let mutation = start_archive(&mut rail);
    let stale_gen = rail.list_generation;
    let stale_attach = rail.attachment_generation;
    rail.invalidate_for_reconnect();
    assert_eq!(rail.request_counts().list_in_flight, 0);
    assert_eq!(rail.request_counts().favorite_in_flight, 0);
    assert!(!rail.has_unsettled_local_authority());
    assert!(rail.is_stale());
    rail.apply_sessions_result(stale_gen, stale_attach, Ok(vec![summary(id, 99)]));
    assert_ne!(
        rail.current().cards[0].0.last_active_at_unix_ms,
        99,
        "pre-reconnect list must not land"
    );
    assert!(
        !rail.apply_mutation_completion(ack_completion(&mutation)),
        "pre-reconnect archive must not commit"
    );
    assert_ne!(rail.notice(), Some("archive committed"));
}

#[test]
fn disconnect_keeps_favorite_intent_paired() {
    let id = Uuid::from_u128(1);
    let mut rail = test_rail(vec![(summary(id, 10), Tier::Idle)]);
    let started = rail.begin_favorite(id, true).expect("favorite");
    let list_gen = rail.list_generation;
    let attach = rail.attachment_generation;
    rail.set_daemon_connected(false);
    assert!(rail.has_unsettled_local_authority());
    rail.apply_favorite_result(list_gen, attach, started.1, id, Ok((started.1, true)));
    assert!(!rail.has_unsettled_local_authority());
    assert!(rail.current().cards[0].0.favorite);
}

#[test]
fn attachment_change_does_not_apply_stale_favorite() {
    let id = Uuid::from_u128(1);
    let mut rail = test_rail(vec![(summary(id, 10), Tier::Idle)]);
    let started = rail.begin_favorite(id, true).expect("favorite");
    let list_gen = rail.list_generation;
    let attach = rail.attachment_generation;
    rail.discard_for_attachment_change();
    assert!(!rail.has_unsettled_local_authority());
    assert!(
        rail.apply_favorite_result(list_gen, attach, started.1, id, Ok((started.1, true)))
            .is_none()
    );
    assert!(!rail.has_unsettled_local_authority());
}

#[test]
fn replacement_mutation_after_attachment_change_is_not_wedged_by_stale_receipt() {
    let id = Uuid::from_u128(1);
    let mut rail = test_rail(vec![(summary(id, 10), Tier::Idle)]);
    let stale = start_archive(&mut rail);
    rail.discard_for_attachment_change();
    rail.set_daemon_connected(true);
    apply_list(&mut rail, vec![summary(id, 10)]);
    let fresh = start_archive(&mut rail);
    assert!(rail.has_unsettled_local_authority());
    assert!(!rail.apply_mutation_completion(ack_completion(&stale)));
    assert!(rail.has_unsettled_local_authority());
    assert!(rail.apply_mutation_completion(ack_completion(&fresh)));
    assert!(!rail.has_unsettled_local_authority());
    assert_eq!(rail.notice(), Some("archive committed"));
}

#[test]
fn disconnect_keeps_mutation_intent_paired() {
    let id = Uuid::from_u128(1);
    let mut rail = test_rail(vec![(summary(id, 10), Tier::Idle)]);
    let effect = start_archive(&mut rail);
    rail.set_daemon_connected(false);
    assert!(rail.has_unsettled_local_authority());
    assert!(rail.apply_mutation_completion(ack_completion(&effect)));
    assert!(!rail.has_unsettled_local_authority());
    assert_eq!(rail.notice(), Some("archive committed"));
}

#[test]
fn search_keeps_mutation_intent_paired() {
    let id = Uuid::from_u128(1);
    let mut rail = test_rail(vec![(summary(id, 10), Tier::Idle)]);
    let effect = start_archive(&mut rail);
    rail.invalidate_for_search();
    assert!(rail.has_unsettled_local_authority());
    assert!(rail.apply_mutation_completion(ack_completion(&effect)));
    assert!(!rail.has_unsettled_local_authority());
    assert_eq!(rail.notice(), Some("archive committed"));
}

#[test]
fn unarchive_is_generation_and_attachment_fenced() {
    let mut archived = summary(Uuid::from_u128(1), 10);
    archived.archived_at_unix_ms = Some(4);
    let mut rail = test_rail(vec![(archived, Tier::Idle)]);
    rail.show_archived = true;
    let effect = match rail.handle_key(press(KeyCode::Char('u'))) {
        Some(RailOutcome::Mutate(effect)) => *effect,
        other => panic!("expected unarchive mutate, got {other:?}"),
    };
    assert_eq!(effect.generation, rail.list_generation());
    assert_eq!(effect.attachment_generation, rail.attachment_generation());
    rail.invalidate_for_reconnect();
    assert!(!rail.apply_mutation_completion(ack_completion(&effect)));
    assert_ne!(rail.notice(), Some("unarchive committed"));
}

#[test]
fn replacement_favorite_after_attachment_change_is_not_wedged_by_stale_receipt() {
    let id = Uuid::from_u128(1);
    let mut rail = test_rail(vec![(summary(id, 10), Tier::Idle)]);
    let stale = rail.begin_favorite(id, true).expect("favorite");
    let stale_gen = rail.list_generation;
    let stale_attach = rail.attachment_generation;
    rail.discard_for_attachment_change();
    rail.set_daemon_connected(true);
    apply_list(&mut rail, vec![summary(id, 10)]);
    let fresh = rail
        .begin_favorite(id, false)
        .expect("replacement favorite");
    let fresh_gen = rail.list_generation;
    let fresh_attach = rail.attachment_generation;
    assert!(rail.has_unsettled_local_authority());
    assert!(
        rail.apply_favorite_result(stale_gen, stale_attach, stale.1, id, Ok((stale.1, true)))
            .is_none()
    );
    assert!(rail.has_unsettled_local_authority());
    rail.apply_favorite_result(fresh_gen, fresh_attach, fresh.1, id, Ok((fresh.1, false)));
    assert!(!rail.has_unsettled_local_authority());
    assert!(!rail.current().cards[0].0.favorite);
}

#[test]
fn hover_actions_belong_only_to_the_hovered_row() {
    let selected = Uuid::from_u128(1);
    let other = Uuid::from_u128(2);
    let mut rail = test_rail(vec![
        (summary(selected, 20), Tier::Idle),
        (summary(other, 10), Tier::Idle),
    ]);
    rail.current_mut().selected_session_id = Some(selected);
    let backend = TestBackend::new(36, 24);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal
        .draw(|frame| {
            rail.render(frame, Some(Rect::new(0, 0, 36, 24)), None, None, 80);
        })
        .unwrap();
    let other_card = rail
        .card_hits
        .iter()
        .find(|hit| hit.index == 1)
        .expect("unselected card hit");
    rail.handle_mouse(MouseEvent {
        kind: MouseEventKind::Moved,
        column: other_card.rect.x.saturating_add(2),
        row: other_card.rect.y,
        modifiers: KeyModifiers::empty(),
    });
    terminal
        .draw(|frame| {
            rail.render(frame, Some(Rect::new(0, 0, 36, 24)), None, None, 80);
        })
        .unwrap();
    assert!(
        !rail.action_hits.is_empty(),
        "hovered card must expose action hits"
    );
    assert!(
        rail.action_hits.iter().all(|hit| hit.index == 1),
        "action hits must only cover the hovered card"
    );
    let other_card = rail.card_hits.iter().find(|hit| hit.index == 1).unwrap();
    let outcome = rail.handle_mouse(MouseEvent {
        kind: MouseEventKind::Down(MouseButton::Left),
        column: other_card.rect.x.saturating_add(2),
        row: other_card.rect.y,
        modifiers: KeyModifiers::empty(),
    });
    assert!(!matches!(outcome, Some(RailOutcome::Resume(_))));
    assert!(!matches!(outcome, Some(RailOutcome::SetFavorite { .. })));
    assert!(!matches!(outcome, Some(RailOutcome::Mutate(_))));

    let delete = rail
        .action_hits
        .iter()
        .find(|hit| hit.action == CardAction::Delete)
        .expect("hovered row delete chip")
        .rect;
    let outcome = rail.handle_mouse(MouseEvent {
        kind: MouseEventKind::Down(MouseButton::Left),
        column: delete.x,
        row: delete.y,
        modifiers: KeyModifiers::empty(),
    });
    assert!(outcome.is_none());
    assert!(
        matches!(rail.step, Step::Confirm { session_id, .. } if session_id == other),
        "the × chip must enter the existing confirm-delete flow"
    );
}

#[test]
fn header_chips_route_visibility_and_new_session_outcomes() {
    let mut rail = test_rail(vec![(summary(Uuid::from_u128(1), 10), Tier::Idle)]);
    let backend = TestBackend::new(36, 24);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal
        .draw(|frame| {
            rail.render(frame, Some(Rect::new(0, 0, 36, 24)), None, None, 80);
        })
        .unwrap();

    let toggle = rail.toggle_area.expect("hide chip hit area");
    let new_session = rail.new_session_area.expect("new-session chip hit area");
    assert!(matches!(
        rail.handle_mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: toggle.x,
            row: toggle.y,
            modifiers: KeyModifiers::empty(),
        }),
        Some(RailOutcome::ToggleVisibility)
    ));

    assert!(matches!(
        rail.handle_mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: new_session.x,
            row: new_session.y,
            modifiers: KeyModifiers::empty(),
        }),
        Some(RailOutcome::NewSession)
    ));

    rail.set_visible(false);
    terminal
        .draw(|frame| rail.render(frame, None, None, None, 80))
        .unwrap();
    let show = rail.toggle_area.expect("show chip hit area");
    assert_eq!(show.x, 0);
    assert_eq!(show.y, 0);
    assert!(matches!(
        rail.handle_mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: show.x,
            row: show.y,
            modifiers: KeyModifiers::empty(),
        }),
        Some(RailOutcome::ToggleVisibility)
    ));
}
