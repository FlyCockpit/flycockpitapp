use super::*;
use cockpit_proto::MessageRole;
use crossterm::event::{KeyEventKind, KeyEventState};
use ratatui::{Terminal, backend::TestBackend};

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
        HashMap::from([(id, (true, true))]),
    );
    assert_eq!(rail.current().cards[0].1, Tier::Idle);
    rail.apply_live_status(list_gen, attach, HashMap::from([(id, (true, true))]));
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
    let mut a = summary(Uuid::from_u128(1), 10);
    a.compaction_lineage_root_id = Some(root);
    let mut rail = test_rail(vec![(a.clone(), Tier::Idle)]);
    rail.list_generation = 0;
    rail.counts = RailRequestCounts::default();
    assert!(rail.begin_list());
    assert_eq!(rail.request_counts().list_in_flight, 1);
    assert!(rail.begin_list());
    assert_eq!(rail.request_counts().list_in_flight, 1);
    assert_eq!(rail.request_counts().list_started, 2);
    let list_gen = rail.list_generation;
    let attach = rail.attachment_generation;
    rail.apply_sessions_result(list_gen, attach, Ok(vec![a.clone()]));
    assert_eq!(rail.request_counts().list_in_flight, 0);

    let ids = rail.begin_live(vec![a.session_id]).unwrap();
    assert!(ids.len() <= LIST_LIMIT);
    assert_eq!(rail.request_counts().live_in_flight, 1);
    rail.begin_live(vec![a.session_id]);
    assert_eq!(rail.request_counts().live_in_flight, 1);

    rail.current_mut().selected_session_id = Some(a.session_id);
    rail.begin_preview(None);
    rail.begin_preview(None);
    assert_eq!(rail.request_counts().preview_in_flight, 1);

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
    rail.discard_for_attachment_change();
    assert_eq!(rail.request_counts().list_in_flight, 0);
    assert_eq!(rail.request_counts().favorite_in_flight, 0);
    assert!(rail.current().cards.is_empty());
    assert_eq!(rail.list_generation(), 0);
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
        .map(|(name, _)| *name)
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
