//! Reducer, render, and pointer tests for the full-screen onboarding shell.

use super::search::{ProviderSearchScreen, filter_catalog, onboarding_catalog};
use super::*;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
use ratatui::Terminal;
use ratatui::backend::TestBackend;

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

fn click(column: u16, row: u16) -> MouseEvent {
    MouseEvent {
        kind: MouseEventKind::Down(MouseButton::Left),
        column,
        row,
        modifiers: KeyModifiers::NONE,
    }
}

fn wheel_down(column: u16, row: u16) -> MouseEvent {
    MouseEvent {
        kind: MouseEventKind::ScrollDown,
        column,
        row,
        modifiers: KeyModifiers::NONE,
    }
}

fn wheel_up(column: u16, row: u16) -> MouseEvent {
    MouseEvent {
        kind: MouseEventKind::ScrollUp,
        column,
        row,
        modifiers: KeyModifiers::NONE,
    }
}

fn snapshot(stage: OnboardingStage) -> OnboardingBootstrapSnapshot {
    OnboardingBootstrapSnapshot {
        run_id: uuid::Uuid::from_u128(1),
        attempt_id: uuid::Uuid::from_u128(2),
        revision: 3,
        stage,
        bootstrap_state: cockpit_proto::OnboardingBootstrapState::AwaitingChoice,
        limited_mode: false,
        lifetime_selection: None,
        host_capabilities: cockpit_proto::HostCapabilitySnapshot::unpublished(),
        last_receipt: None,
    }
}

fn secure_store_capabilities(
    keyring_state: cockpit_proto::FeatureCapabilityState,
) -> cockpit_proto::HostCapabilitySnapshot {
    let mut capabilities = cockpit_proto::HostCapabilitySnapshot::unpublished();
    capabilities.features = vec![
        cockpit_proto::FeatureCapabilityRow {
            id: "secret_store.keyring".into(),
            state: keyring_state,
            reason: "keyring is locked".into(),
            fix_command: Some("unlock-keyring".into()),
            remedy_text: Some("Unlock the platform keyring".into()),
            dependency_ids: Vec::new(),
        },
        cockpit_proto::FeatureCapabilityRow {
            id: "secret_store.file".into(),
            state: cockpit_proto::FeatureCapabilityState::Available,
            reason: "encrypted file vault is available".into(),
            fix_command: None,
            remedy_text: None,
            dependency_ids: Vec::new(),
        },
    ];
    capabilities
}

fn shell_at(stage: OnboardingStage) -> OnboardingShell {
    OnboardingShell::new(&snapshot(stage), false)
}

fn render_string(shell: &mut OnboardingShell, width: u16, height: u16, engine: &Dialog) -> String {
    let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
    let mut links = crate::tui::links::LinkRegistry::default();
    terminal
        .draw(|frame| shell.render(frame, frame.area(), engine, &mut links))
        .unwrap();
    terminal
        .backend()
        .buffer()
        .content
        .iter()
        .map(|cell| cell.symbol())
        .collect()
}

// ── Welcome ──────────────────────────────────────────────────────────────

#[test]
fn welcome_any_key_requests_advance_only_on_welcome_stage() {
    let mut shell = shell_at(OnboardingStage::Welcome);
    let mut engine = Dialog::None;
    assert!(matches!(
        shell.handle_key(key(KeyCode::Char(' ')), &mut engine),
        Some(OnboardingShellAction::Transition(
            cockpit_proto::OnboardingTransitionKind::Advance,
            None
        ))
    ));
}

#[test]
fn welcome_screen_never_advances_a_later_stage() {
    // A Welcome screen paired with a later stage can only happen when the
    // profile engine failed to mount; a key there must not skip Profile.
    let mut shell = shell_at(OnboardingStage::Profile);
    let mut engine = Dialog::None;
    assert!(shell.handle_key(key(KeyCode::Enter), &mut engine).is_none());
}

#[test]
fn welcome_animation_is_tick_driven_and_settles() {
    let mut shell = shell_at(OnboardingStage::Welcome);
    let engine = Dialog::None;
    let frame_zero = render_string(&mut shell, 80, 24, &engine);
    // Every intermediate frame reports a change until the window closes.
    for _ in 0..WELCOME_ANIMATION_FRAMES {
        assert!(shell.tick());
    }
    assert!(!shell.tick(), "the fly-in must settle, not loop forever");
    let settled = render_string(&mut shell, 80, 24, &engine);
    assert_ne!(frame_zero, settled);
    assert!(settled.contains("Press any key"));
}

#[test]
fn reduced_motion_welcome_is_deterministic_and_static() {
    let snapshot = snapshot(OnboardingStage::Welcome);
    let mut shell = OnboardingShell::new(&snapshot, true);
    let engine = Dialog::None;
    let first = render_string(&mut shell, 80, 24, &engine);
    assert!(!shell.tick(), "reduced motion must not animate");
    let second = render_string(&mut shell, 80, 24, &engine);
    assert_eq!(first, second);
    assert!(first.contains("Press any key"));
    assert!(first.contains("✈"));
}

#[test]
fn reduced_motion_controls_cover_no_color_dumb_terminal_and_explicit_flags() {
    assert!(reduced_motion_for(false, Some("dumb"), [None, None]));
    assert!(reduced_motion_for(
        true,
        Some("xterm-256color"),
        [None, None]
    ));
    assert!(reduced_motion_for(
        false,
        Some("xterm-256color"),
        [Some("1".into()), None]
    ));
    assert!(!reduced_motion_for(
        false,
        Some("xterm-256color"),
        [Some("0".into()), Some("0".into())]
    ));
}

// ── Escape semantics ─────────────────────────────────────────────────────

#[test]
fn escape_offers_visible_choices_and_never_defers_silently() {
    let mut shell = shell_at(OnboardingStage::Provider);
    let mut engine = Dialog::None;
    // Plain Escape opens the menu without emitting any transition.
    assert!(shell.handle_key(key(KeyCode::Esc), &mut engine).is_none());
    // The daemon never accepts Back from Provider (the committed
    // secure-store choice cannot be reopened through onboarding), so the
    // menu offers only Defer and Cancel.
    let rendered = render_string(&mut shell, 80, 24, &engine);
    assert!(rendered.contains("Leave setup?"));
    assert!(!rendered.contains("Back to the previous step"));
    assert!(rendered.contains("Defer provider setup (limited mode)"));
    assert!(rendered.contains("Cancel setup for now"));
    // Escape again dismisses without effect.
    assert!(shell.handle_key(key(KeyCode::Esc), &mut engine).is_none());
    let dismissed = render_string(&mut shell, 80, 24, &engine);
    assert!(!dismissed.contains("Leave setup?"));
}

#[test]
fn escape_menu_choices_differ_by_stage() {
    let cases: [(OnboardingStage, &[&str]); 4] = [
        // Welcome has nowhere to go back to and nothing to defer.
        (OnboardingStage::Welcome, &["Cancel setup for now"]),
        (
            OnboardingStage::SecureStore,
            &["Back to the previous step", "Cancel setup for now"],
        ),
        (
            // Back from Provider would reopen the committed secure-store
            // choice; the daemon rejects that transition, so it is never
            // offered.
            OnboardingStage::Provider,
            &[
                "Defer provider setup (limited mode)",
                "Cancel setup for now",
            ],
        ),
        (
            OnboardingStage::Model,
            &["Back to the previous step", "Cancel setup for now"],
        ),
    ];
    let mut engine = Dialog::None;
    for (stage, expected) in cases {
        let mut shell = shell_at(stage);
        assert!(
            shell.handle_key(key(KeyCode::Esc), &mut engine).is_none(),
            "escape only opens the menu"
        );
        let rendered = render_string(&mut shell, 100, 30, &engine);
        for label in expected {
            assert!(
                rendered.contains(label),
                "{stage:?} menu must offer {label}"
            );
        }
        if stage != OnboardingStage::Provider {
            assert!(
                !rendered.contains("Defer provider setup"),
                "{stage:?} must not offer defer"
            );
        }
        if matches!(
            stage,
            OnboardingStage::Welcome | OnboardingStage::Profile | OnboardingStage::Provider
        ) {
            assert!(
                !rendered.contains("Back to the previous step"),
                "{stage:?} must not offer an illegal Back transition"
            );
        }
    }
}

#[test]
fn escape_menu_selection_emits_distinct_actions() {
    let mut engine = Dialog::None;

    // Back is offered where the daemon accepts it (from Model).
    let mut shell = shell_at(OnboardingStage::Model);
    shell.handle_key(key(KeyCode::Esc), &mut engine);
    assert!(matches!(
        shell.handle_key(key(KeyCode::Enter), &mut engine),
        Some(OnboardingShellAction::Transition(
            cockpit_proto::OnboardingTransitionKind::Back,
            None
        ))
    ));

    // Defer (first row) on the provider stage, where Back is withheld.
    let mut shell = shell_at(OnboardingStage::Provider);
    shell.handle_key(key(KeyCode::Esc), &mut engine);
    assert!(matches!(
        shell.handle_key(key(KeyCode::Enter), &mut engine),
        Some(OnboardingShellAction::Transition(
            cockpit_proto::OnboardingTransitionKind::DeferProvider,
            None
        ))
    ));

    // Cancel (second row) closes the shell without a transition.
    let mut shell = shell_at(OnboardingStage::Provider);
    shell.handle_key(key(KeyCode::Esc), &mut engine);
    shell.handle_key(key(KeyCode::Down), &mut engine);
    assert!(matches!(
        shell.handle_key(key(KeyCode::Enter), &mut engine),
        Some(OnboardingShellAction::Close)
    ));
}

#[test]
fn escape_menu_pointer_selection_chooses_the_clicked_row() {
    let mut shell = shell_at(OnboardingStage::Provider);
    let mut engine = Dialog::None;
    shell.handle_key(key(KeyCode::Esc), &mut engine);
    // Render first so the menu records its row rects.
    let rendered = render_string(&mut shell, 100, 30, &engine);
    assert!(rendered.contains("Defer provider setup"));
    let defer_row = shell.escape.as_ref().unwrap().row_rects[0];
    let outcome = shell.handle_mouse(click(defer_row.x, defer_row.y));
    assert!(outcome.consumed);
    assert!(matches!(
        outcome.action,
        Some(OnboardingShellAction::Transition(
            cockpit_proto::OnboardingTransitionKind::DeferProvider,
            None
        ))
    ));
}

// ── Secure store ─────────────────────────────────────────────────────────

#[test]
fn unavailable_automatic_secure_store_never_silently_falls_back_to_file() {
    let mut snap = snapshot(OnboardingStage::SecureStore);
    snap.host_capabilities =
        secure_store_capabilities(cockpit_proto::FeatureCapabilityState::Missing);
    let mut shell = OnboardingShell::new(&snap, false);
    let mut engine = Dialog::None;
    shell.handle_key(key(KeyCode::Enter), &mut engine);
    let action = shell.handle_key(key(KeyCode::Enter), &mut engine);
    assert!(
        action.is_none(),
        "an unavailable keyring must not submit a placement"
    );
    let rendered = render_string(&mut shell, 80, 24, &engine);
    assert!(rendered.contains("unlock-keyring"));

    // An explicit machine-bound selection still submits.
    shell.handle_key(key(KeyCode::Down), &mut engine);
    shell.handle_key(key(KeyCode::Down), &mut engine);
    match shell.handle_key(key(KeyCode::Enter), &mut engine) {
        Some(OnboardingShellAction::SecureIntent(submission)) => {
            assert_eq!(
                submission.placement,
                cockpit_proto::OnboardingSecurePlacement::MachineBoundFile
            );
            assert!(submission.passphrase.is_none());
        }
        other => panic!("expected machine-bound submission, got {other:?}"),
    }
}

#[test]
fn passphrase_secure_store_requires_matching_confirmation() {
    let mut snap = snapshot(OnboardingStage::SecureStore);
    snap.host_capabilities =
        secure_store_capabilities(cockpit_proto::FeatureCapabilityState::Available);
    let mut shell = OnboardingShell::new(&snap, false);
    let mut engine = Dialog::None;
    shell.handle_key(key(KeyCode::Down), &mut engine);
    shell.handle_key(key(KeyCode::Enter), &mut engine);
    for ch in "first-canary".chars() {
        shell.handle_key(key(KeyCode::Char(ch)), &mut engine);
    }
    shell.handle_key(key(KeyCode::Enter), &mut engine);
    for ch in "second-canary".chars() {
        shell.handle_key(key(KeyCode::Char(ch)), &mut engine);
    }
    let action = shell.handle_key(key(KeyCode::Enter), &mut engine);
    assert!(
        action.is_none(),
        "mismatched confirmation must not submit a passphrase"
    );
    let rendered = render_string(&mut shell, 80, 24, &engine);
    assert!(rendered.contains("confirmation does not match"));
    assert!(
        !rendered.contains("first-canary") && !rendered.contains("second-canary"),
        "passphrase bytes must never render"
    );

    // Correcting the passphrase submits through the sensitive ingress only.
    for ch in "first-canary".chars() {
        shell.handle_key(key(KeyCode::Char(ch)), &mut engine);
    }
    shell.handle_key(key(KeyCode::Enter), &mut engine);
    for ch in "first-canary".chars() {
        shell.handle_key(key(KeyCode::Char(ch)), &mut engine);
    }
    match shell.handle_key(key(KeyCode::Enter), &mut engine) {
        Some(OnboardingShellAction::SecureIntent(submission)) => {
            assert_eq!(
                submission.placement,
                cockpit_proto::OnboardingSecurePlacement::PassphraseFile
            );
            assert!(submission.passphrase.is_some());
        }
        other => panic!("expected passphrase submission, got {other:?}"),
    }
}

#[test]
fn secure_store_pointer_selects_placement_row() {
    let mut snap = snapshot(OnboardingStage::SecureStore);
    snap.host_capabilities =
        secure_store_capabilities(cockpit_proto::FeatureCapabilityState::Available);
    let mut shell = OnboardingShell::new(&snap, false);
    let engine = Dialog::None;
    // Render to record row rects (intro 3 lines, then three rows).
    render_string(&mut shell, 80, 24, &engine);
    // The machine-bound row is the third placement row: border(1) +
    // progress(1) + intro(3) + 2 = row 7.
    let outcome = shell.handle_mouse(click(10, 7));
    assert!(outcome.consumed);
    match outcome.action {
        Some(OnboardingShellAction::SecureIntent(submission)) => {
            assert_eq!(
                submission.placement,
                cockpit_proto::OnboardingSecurePlacement::MachineBoundFile
            );
        }
        other => panic!("expected machine-bound pointer selection, got {other:?}"),
    }
}

#[test]
fn secure_store_pointer_activation_emits_the_selected_daemon_intent() {
    let mut snapshot = snapshot(OnboardingStage::SecureStore);
    snapshot.host_capabilities =
        secure_store_capabilities(cockpit_proto::FeatureCapabilityState::Available);
    let mut shell = OnboardingShell::new(&snapshot, true);
    let engine = Dialog::None;
    let _ = render_string(&mut shell, 100, 24, &engine);

    let outcome = shell.handle_mouse(click(5, 5));
    assert!(outcome.consumed);
    assert!(matches!(
        outcome.action,
        Some(OnboardingShellAction::SecureIntent(SecureStoreSubmission {
            placement: cockpit_proto::OnboardingSecurePlacement::Automatic,
            passphrase: None,
        }))
    ));
}

// ── Provider search ──────────────────────────────────────────────────────

#[test]
fn search_filters_by_label_and_id_case_insensitively() {
    let catalog = onboarding_catalog();
    let grok = filter_catalog(&catalog, "GRok");
    let ids: Vec<_> = grok.iter().map(|template| template.id).collect();
    assert!(ids.contains(&"grok"), "label match: {ids:?}");
    let by_id = filter_catalog(&catalog, "codex-oauth");
    assert_eq!(by_id.len(), 1);
    assert_eq!(by_id[0].id, "codex-oauth");
    assert_eq!(filter_catalog(&catalog, "").len(), catalog.len());
}

#[test]
fn search_unicode_query_and_cursor_edits_round_trip() {
    let mut shell = shell_at(OnboardingStage::Provider);
    let mut engine = Dialog::None;
    for ch in "grk".chars() {
        shell.handle_key(key(KeyCode::Char(ch)), &mut engine);
    }
    // Cursor edit in the middle of the query with a wide character.
    shell.handle_key(key(KeyCode::Left), &mut engine);
    shell.handle_key(key(KeyCode::Char('o')), &mut engine);
    let query = match &shell.screen {
        OnboardingScreen::ProviderSearch(screen) => screen.query().to_string(),
        _other => panic!("expected search screen, got {_other:?}"),
    };
    assert_eq!(query, "grok");
    let filtered = match &shell.screen {
        OnboardingScreen::ProviderSearch(screen) => screen.filtered(),
        _other => panic!("expected search screen"),
    };
    assert!(
        filtered.iter().any(|template| template.id == "grok"),
        "grok must still match after the edit"
    );

    // A non-matching Unicode query empties the list and Enter is inert
    // with an explanatory status.
    shell.handle_key(key(KeyCode::End), &mut engine);
    for ch in "日本".chars() {
        shell.handle_key(key(KeyCode::Char(ch)), &mut engine);
    }
    let action = shell.handle_key(key(KeyCode::Enter), &mut engine);
    assert!(action.is_none(), "no template may resolve for a dead query");
    let rendered = render_string(&mut shell, 80, 24, &engine);
    assert!(rendered.contains("No provider matches this search."));
}

#[test]
fn search_text_field_accepts_j_and_k_instead_of_treating_them_as_navigation() {
    let mut screen = ProviderSearchScreen::new();
    for ch in "j-k".chars() {
        screen.handle_key(key(KeyCode::Char(ch)));
    }
    assert_eq!(screen.query(), "j-k");
    assert!(screen.filtered().is_empty());
}

#[test]
fn search_disabled_template_surfaces_reason_and_blocks_selection() {
    let mut shell = shell_at(OnboardingStage::Provider);
    let mut engine = Dialog::None;
    for ch in "grok-oauth".chars() {
        shell.handle_key(key(KeyCode::Char(ch)), &mut engine);
    }
    let filtered = match &shell.screen {
        OnboardingScreen::ProviderSearch(screen) => screen.filtered(),
        _other => panic!("expected search screen"),
    };
    let disabled = filtered
        .iter()
        .find(|template| template.id == "grok-oauth")
        .expect("grok-oauth stays visible for discoverability");
    assert!(disabled.is_disabled());
    let action = shell.handle_key(key(KeyCode::Enter), &mut engine);
    assert!(
        action.is_none(),
        "a disabled template must never produce a selection"
    );
    let reason = disabled.disabled_reason().unwrap();
    let visible_prefix = reason
        .split_whitespace()
        .take(6)
        .collect::<Vec<_>>()
        .join(" ");
    let rendered = render_string(&mut shell, 100, 30, &engine);
    assert!(rendered.contains(&visible_prefix), "{rendered}");
}

#[test]
fn search_keyboard_select_after_filtering_resolves_canonical_template() {
    let mut shell = shell_at(OnboardingStage::Provider);
    let mut engine = Dialog::None;
    // Filter to the anthropic label, then move and select.
    for ch in "anthropic".chars() {
        shell.handle_key(key(KeyCode::Char(ch)), &mut engine);
    }
    shell.handle_key(key(KeyCode::Down), &mut engine);
    match shell.handle_key(key(KeyCode::Enter), &mut engine) {
        Some(OnboardingShellAction::SelectTemplate(template)) => {
            assert_eq!(template.id, "anthropic");
            assert_eq!(template.display, "Anthropic (Claude API)");
        }
        other => panic!("expected a canonical template selection, got {other:?}"),
    }
}

#[test]
fn filtering_never_changes_selected_template_identity() {
    let mut screen = ProviderSearchScreen::new();
    screen.observe_viewport(8);
    // Move to a mid-catalog entry with the full list, then filter down to a
    // single entry that includes it.
    let before = screen.selected_template().expect("catalog is non-empty");
    for ch in before.id.chars() {
        screen.handle_key(key(KeyCode::Char(ch)));
    }
    let after = screen
        .selected_template()
        .expect("the id query still matches");
    assert_eq!(
        before.id, after.id,
        "filtering must resolve the same canonical template id"
    );

    // A filter that keeps several entries — including, but not isolating,
    // the selection — must keep the same canonical selection identity
    // instead of silently snapping to a different row. Find an entry whose
    // id prefix is shared by at least one other row (e.g. `openai` and
    // `openai-compatible`) so the fixture does not depend on exact
    // registry ordering.
    screen = ProviderSearchScreen::new();
    screen.observe_viewport(onboarding_catalog().len().max(8));
    let mut shared_prefix = None;
    for _ in 0..onboarding_catalog().len() {
        let selected = screen.selected_template().expect("cursor in catalog");
        let prefix: String = selected.id.chars().take(3).collect();
        let kept = filter_catalog(&onboarding_catalog(), &prefix);
        if kept.len() > 1 && kept.iter().any(|t| t.id == selected.id) {
            shared_prefix = Some((prefix, selected));
            break;
        }
        screen.handle_key(key(KeyCode::Down));
    }
    let (prefix, selected) =
        shared_prefix.expect("the registry contains shared-prefix entries (openai)");
    for ch in prefix.chars() {
        screen.handle_key(key(KeyCode::Char(ch)));
    }
    let filtered = screen.filtered();
    assert!(
        filtered.len() > 1,
        "fixture must keep a set containing the selection: {:?}",
        filtered.iter().map(|t| t.id).collect::<Vec<_>>()
    );
    assert!(filtered.iter().any(|t| t.id == selected.id));
    assert_eq!(
        screen.selected_template().expect("selection survives").id,
        selected.id,
        "a query that keeps the selection must not change which template is selected"
    );

    // A filter that excludes the entry clamps to the remaining list and
    // still resolves an original template id.
    screen.handle_key(key(KeyCode::End));
    for ch in "zzz-no-match".chars() {
        screen.handle_key(key(KeyCode::Char(ch)));
    }
    assert!(screen.selected_template().is_none());
    assert!(screen.filtered().is_empty());
}

#[test]
fn search_pointer_hit_selects_the_clicked_row() {
    let mut shell = shell_at(OnboardingStage::Provider);
    let mut engine = Dialog::None;
    // Type a query so row 0 is a known template, then render to record
    // rects and click the first row.
    for ch in "openai".chars() {
        shell.handle_key(key(KeyCode::Char(ch)), &mut engine);
    }
    let expected_id = match &shell.screen {
        OnboardingScreen::ProviderSearch(screen) => screen.filtered()[0].id,
        _ => unreachable!(),
    };
    render_string(&mut shell, 80, 24, &engine);
    let first_row = shell.list_row_rects[0];
    let outcome = shell.handle_mouse(click(first_row.x, first_row.y));
    match outcome.action {
        Some(OnboardingShellAction::SelectTemplate(template)) => {
            assert_eq!(template.id, expected_id);
        }
        other => panic!("expected pointer selection, got {other:?}"),
    }
    assert!(outcome.consumed);
}

#[test]
fn search_wheel_scrolls_the_viewport() {
    let mut shell = shell_at(OnboardingStage::Provider);
    let engine = Dialog::None;
    // Small viewport so scrolling is observable.
    render_string(&mut shell, 80, 12, &engine);
    let offset_before = match &shell.screen {
        OnboardingScreen::ProviderSearch(screen) => screen.offset(),
        _other => panic!("expected search screen, got {_other:?}"),
    };
    assert_eq!(offset_before, 0);
    let outcome = shell.handle_mouse(wheel_down(10, 6));
    assert!(outcome.consumed);
    let offset_after = match &shell.screen {
        OnboardingScreen::ProviderSearch(screen) => screen.offset(),
        _other => panic!("expected search screen"),
    };
    assert!(
        offset_after > offset_before,
        "wheel must scroll the viewport"
    );

    // Scrolling back up clamps at zero.
    shell.handle_mouse(wheel_up(10, 6));
    let offset_up = match &shell.screen {
        OnboardingScreen::ProviderSearch(screen) => screen.offset(),
        _other => panic!("expected search screen"),
    };
    assert_eq!(offset_up, offset_after - 1);
    shell.handle_mouse(wheel_up(10, 6));
    let offset_clamped = match &shell.screen {
        OnboardingScreen::ProviderSearch(screen) => screen.offset(),
        _other => panic!("expected search screen"),
    };
    assert!(offset_clamped <= offset_up);
}

#[test]
fn search_resize_clamps_cursor_and_viewport() {
    let mut screen = ProviderSearchScreen::new();
    let total = screen.filtered().len();
    screen.observe_viewport(total + 10);
    // Park the cursor deep in the list, then shrink the viewport hard.
    screen.handle_key(key(KeyCode::Down));
    let deep_cursor = screen.cursor();
    assert!(deep_cursor > 0);
    screen.observe_viewport(2);
    // The cursor survives (it indexes the filtered list, not the viewport),
    // but the viewport keeps it visible and within bounds.
    assert!(screen.cursor() <= deep_cursor);
    let capacity = 2;
    assert!(screen.offset() + capacity > screen.cursor());
    // The visible window never exceeds the list.
    assert!(screen.offset() <= total.saturating_sub(capacity));
}

// ── Engine pairing ───────────────────────────────────────────────────────

#[test]
fn provider_engine_abandoning_add_returns_to_search() {
    let mut shell = shell_at(OnboardingStage::Provider);
    let mut engine = Dialog::None;
    shell.present_engine(EngineStage::Provider);
    // Dialog::None is not the add page: the pairing check must send the
    // shell back to the searchable catalog rather than a settings list.
    let action = shell.handle_key(key(KeyCode::Down), &mut engine);
    assert!(action.is_none());
    assert!(
        shell.screen_kind() == OnboardingScreenKind::ProviderSearch,
        "an abandoned provider engine returns to the catalog"
    );
}

#[test]
fn escape_during_engine_authority_work_reaches_the_engine() {
    // When the engine owns an unsettled authority operation the shell must
    // not open its Back/Defer/Cancel menu; Escape flows to the engine's
    // correlated cancellation. Dialog::None never reports pending
    // authority, so the menu opens — the pairing under test is that the
    // shell consults the engine rather than deciding alone.
    let mut shell = shell_at(OnboardingStage::Provider);
    let mut engine = Dialog::None;
    shell.present_engine(EngineStage::Provider);
    assert!(shell.handle_key(key(KeyCode::Esc), &mut engine).is_none());
    let rendered = render_string(&mut shell, 80, 24, &engine);
    // The abandon check sends us back to search first; Escape there opens
    // the menu (no engine authority pending).
    assert!(rendered.contains("Leave setup?"));
}

// ── Completion ───────────────────────────────────────────────────────────

#[test]
fn completion_screen_choices_are_distinct() {
    let mut shell = shell_at(OnboardingStage::Lifetime);
    let mut engine = Dialog::None;
    shell.present_completion("Configured p/m as the default model.".into());
    let rendered = render_string(&mut shell, 90, 24, &engine);
    assert!(rendered.contains("Cockpit is ready."));
    assert!(rendered.contains("Add another provider"));
    assert!(rendered.contains("Start coding"));
    // The completion copy keeps pointing at the post-onboarding surfaces.
    assert!(rendered.contains("/setup security"));
    assert!(rendered.contains("/help"));

    // "Add another provider" is a shell-local detour (the daemon stage is
    // already Complete): the searchable catalog returns, and Escape offers
    // a local return to the stored summary instead of a daemon transition.
    shell.handle_key(key(KeyCode::Up), &mut engine);
    assert!(
        shell.handle_key(key(KeyCode::Enter), &mut engine).is_none(),
        "adding another provider is shell-local"
    );
    assert_eq!(shell.screen_kind(), OnboardingScreenKind::ProviderSearch);
    shell.handle_key(key(KeyCode::Esc), &mut engine);
    let detour_menu = render_string(&mut shell, 90, 24, &engine);
    assert!(detour_menu.contains("Return to the setup summary"));
    assert!(matches!(
        shell.handle_key(key(KeyCode::Enter), &mut engine),
        Some(OnboardingShellAction::ReturnToCompletion)
    ));
    assert_eq!(shell.screen_kind(), OnboardingScreenKind::Complete);

    // "Start coding" is a local close: the terminal Complete transition was
    // already committed when the lifetime stage settled.
    shell.present_completion("again".into());
    shell.handle_key(key(KeyCode::Down), &mut engine);
    assert!(matches!(
        shell.handle_key(key(KeyCode::Enter), &mut engine),
        Some(OnboardingShellAction::Close)
    ));
}

#[test]
fn completion_detour_escape_replaces_back_and_cancel() {
    let mut shell = shell_at(OnboardingStage::Lifetime);
    let mut engine = Dialog::None;
    shell.present_completion("summary".into());
    shell.begin_completion_provider_detour(Some("status".into()));
    shell.handle_key(key(KeyCode::Esc), &mut engine);
    let rendered = render_string(&mut shell, 90, 24, &engine);
    assert!(rendered.contains("Return to the setup summary"));
    assert!(!rendered.contains("Cancel setup for now"));
    assert!(!rendered.contains("Back to the previous step"));
    assert!(!rendered.contains("Defer provider setup"));
}

// ── Snapshot authority ───────────────────────────────────────────────────

#[test]
fn sync_snapshot_rebuilds_native_screens_on_stage_change() {
    let mut shell = shell_at(OnboardingStage::Welcome);
    let mut next = snapshot(OnboardingStage::SecureStore);
    next.host_capabilities =
        secure_store_capabilities(cockpit_proto::FeatureCapabilityState::Available);
    assert!(shell.sync_snapshot(&next));
    assert!(matches!(shell.screen, OnboardingScreen::SecureStore(_)));

    let provider = snapshot(OnboardingStage::Provider);
    assert!(shell.sync_snapshot(&provider));
    assert!(matches!(shell.screen, OnboardingScreen::ProviderSearch(_)));
}

#[test]
fn latched_transition_clears_only_when_revision_advances() {
    let mut shell = shell_at(OnboardingStage::Welcome);
    shell.latch_transition(3, cockpit_proto::OnboardingTransitionKind::Advance);
    assert!(shell.transition_pending());
    // Same revision: still latched (duplicate snapshot refresh).
    let same = snapshot(OnboardingStage::Welcome);
    assert!(!shell.sync_snapshot(&same));
    assert!(shell.transition_pending());
    // Advanced revision: the latch clears.
    let mut advanced = snapshot(OnboardingStage::Profile);
    advanced.revision = 4;
    assert!(shell.sync_snapshot(&advanced));
    assert!(!shell.transition_pending());
}

#[test]
fn superseding_same_stage_revision_discards_stale_local_search_state() {
    let mut shell = shell_at(OnboardingStage::Provider);
    shell.paste("openai");
    let engine = Dialog::None;
    assert!(render_string(&mut shell, 90, 24, &engine).contains("openai│"));

    let mut superseding = snapshot(OnboardingStage::Provider);
    superseding.revision += 1;
    assert!(shell.sync_snapshot(&superseding));

    let rendered = render_string(&mut shell, 90, 24, &engine);
    assert!(rendered.contains("Search providers: │"), "{rendered}");
    assert!(!rendered.contains("openai│"), "{rendered}");
}

// ── Chrome ───────────────────────────────────────────────────────────────

#[test]
fn chrome_shows_progress_and_limited_mode_at_both_sizes() {
    for (width, height) in [(60u16, 20u16), (120, 40)] {
        let mut shell = shell_at(OnboardingStage::SecureStore);
        let mut engine = Dialog::None;
        let rendered = render_string(&mut shell, width, height, &engine);
        assert!(rendered.contains("Cockpit setup"), "{width}x{height}");
        assert!(rendered.contains("Welcome"), "{width}x{height}");
        assert!(rendered.contains("Provider"), "{width}x{height}");
        assert!(rendered.contains("Secure store"), "{width}x{height}");

        let mut limited = snapshot(OnboardingStage::Provider);
        limited.limited_mode = true;
        let mut limited_shell = OnboardingShell::new(&limited, false);
        let limited_rendered = render_string(&mut limited_shell, width, height, &engine);
        assert!(
            limited_rendered.contains("limited mode"),
            "{width}x{height} must show the limited-mode badge"
        );
    }
}

#[test]
fn provider_auth_engine_renders_inside_full_screen_chrome_at_narrow_and_wide_sizes() {
    let home = tempfile::tempdir().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(home.path());
    let template = cockpit_core::providers::template_by_id("openai").unwrap();
    let mut engine = Dialog::onboarding_provider_engine(home.path(), None);
    engine.seed_provider_template(template);
    let mut shell = shell_at(OnboardingStage::Provider);
    shell.present_engine(EngineStage::Provider);

    for (width, height) in [(48, 18), (110, 32)] {
        let rendered = render_string(&mut shell, width, height, &engine);
        assert!(rendered.contains("Cockpit setup"), "{rendered}");
        assert!(rendered.contains("Template: OpenAI"), "{rendered}");
        assert!(rendered.contains("Provider"), "{rendered}");
        assert!(rendered.contains("esc: options"), "{rendered}");
    }
}

#[test]
fn setup_engine_stages_share_shell_chrome_at_narrow_and_wide_sizes() {
    let home = tempfile::tempdir().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(home.path());
    let cases = [
        (
            OnboardingStage::Profile,
            cockpit_core::wizard::ONBOARDING_PROFILE_WIZARD_ID,
        ),
        (
            OnboardingStage::Lifetime,
            cockpit_core::wizard::ONBOARDING_LIFETIME_WIZARD_ID,
        ),
    ];

    for (stage, wizard_id) in cases {
        let engine = Dialog::onboarding_wizard_engine(wizard_id, None, None).unwrap();
        let mut shell = shell_at(stage);
        shell.present_engine(EngineStage::for_stage(stage).unwrap());
        for (width, height) in [(48, 18), (110, 32)] {
            let rendered = render_string(&mut shell, width, height, &engine);
            assert!(rendered.contains("Cockpit setup"), "{rendered}");
            assert!(rendered.contains("Setup —"), "{rendered}");
            assert!(rendered.contains("esc: options"), "{rendered}");
        }
    }
}

#[test]
fn failed_bootstrap_state_is_surfaced() {
    let mut snap = snapshot(OnboardingStage::SecureStore);
    snap.bootstrap_state = cockpit_proto::OnboardingBootstrapState::Failed;
    let mut shell = OnboardingShell::new(&snap, false);
    let mut engine = Dialog::None;
    let rendered = render_string(&mut shell, 80, 24, &engine);
    assert!(rendered.contains("Onboarding bootstrap failed"));
}

#[test]
fn materializing_bootstrap_state_is_surfaced() {
    let mut snap = snapshot(OnboardingStage::SecureStore);
    snap.bootstrap_state = cockpit_proto::OnboardingBootstrapState::Materializing;
    let mut shell = OnboardingShell::new(&snap, false);
    let mut engine = Dialog::None;
    let rendered = render_string(&mut shell, 80, 24, &engine);
    assert!(rendered.contains("Preparing the secure store"));
}
