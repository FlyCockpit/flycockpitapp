//! Reducer, render, and pointer tests for the full-screen onboarding shell.

use super::search::{ProviderSearchScreen, filter_catalog, onboarding_catalog};
use super::*;
use crate::tui::onboarding::auth::AuthPhase;
use crate::tui::settings::{OAuthBeginResult, OAuthFlowRequest, OAuthPublicBegin};
use cockpit_config::providers::ProvidersConfig;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
use ratatui::Terminal;
use ratatui::backend::TestBackend;
use ratatui::layout::Position;

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

fn drag_left(column: u16, row: u16) -> MouseEvent {
    MouseEvent {
        kind: MouseEventKind::Drag(MouseButton::Left),
        column,
        row,
        modifiers: KeyModifiers::NONE,
    }
}

fn release_left(column: u16, row: u16) -> MouseEvent {
    MouseEvent {
        kind: MouseEventKind::Up(MouseButton::Left),
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

fn click_action(
    shell: &mut OnboardingShell,
    action_index: usize,
    width: u16,
    height: u16,
    engine: &mut Dialog,
) -> PointerOutcome {
    let position = (0..height)
        .flat_map(|row| (0..width).map(move |column| Position::new(column, row)))
        .find(|position| shell.actions.clicked(*position) == Some(action_index))
        .unwrap_or_else(|| panic!("action {action_index} must have a rendered hit target"));
    shell.handle_mouse(click(position.x, position.y), engine)
}

// ── Welcome ──────────────────────────────────────────────────────────────

#[test]
fn welcome_any_key_requests_advance_only_on_welcome_stage() {
    let mut shell = shell_at(OnboardingStage::Welcome);
    let mut engine = Dialog::None;
    assert!(
        shell
            .handle_key(key(KeyCode::Char(' ')), &mut engine)
            .is_none()
    );
    shell.set_frame_for_golden(WELCOME_ANIMATION_FRAMES);
    assert!(matches!(
        shell.handle_key(key(KeyCode::Char(' ')), &mut engine),
        Some(OnboardingShellAction::Transition(
            cockpit_proto::OnboardingTransitionKind::Advance,
            None
        ))
    ));
}

#[test]
fn welcome_ignores_early_clicks_but_escape_opens_options() {
    let mut shell = shell_at(OnboardingStage::Welcome);
    let mut engine = Dialog::None;
    let outcome = shell.handle_mouse(click(40, 12), &mut engine);
    assert!(outcome.action.is_none());
    assert!(shell.handle_key(key(KeyCode::Esc), &mut engine).is_none());
    let rendered = render_string(&mut shell, 80, 24, &engine);
    assert!(rendered.contains("Leave setup?"), "{rendered}");
}

#[test]
fn mouse_only_walkthrough_reaches_the_provider_catalog() {
    const WIDTH: u16 = 100;
    const HEIGHT: u16 = 30;

    let mut shell = shell_at(OnboardingStage::Welcome);
    let mut engine = Dialog::None;
    shell.set_frame_for_golden(WELCOME_ANIMATION_FRAMES);
    render_string(&mut shell, WIDTH, HEIGHT, &engine);
    let welcome = shell.handle_mouse(click(WIDTH / 2, HEIGHT / 2), &mut engine);
    assert!(matches!(
        welcome.action,
        Some(OnboardingShellAction::Transition(
            cockpit_proto::OnboardingTransitionKind::Advance,
            None
        ))
    ));

    assert!(shell.sync_snapshot(&snapshot(OnboardingStage::Profile)));
    shell.paste("Ada");
    render_string(&mut shell, WIDTH, HEIGHT, &engine);
    let profile = click_action(&mut shell, 0, WIDTH, HEIGHT, &mut engine);
    assert!(
        matches!(
            profile.action,
            Some(OnboardingShellAction::ApplyProfile(ref name)) if name.ends_with("Ada")
        ),
        "the rendered Continue button must submit the typed profile"
    );

    let mut secure = snapshot(OnboardingStage::SecureStore);
    secure.host_capabilities =
        secure_store_capabilities(cockpit_proto::FeatureCapabilityState::Available);
    assert!(shell.sync_snapshot(&secure));
    render_string(&mut shell, WIDTH, HEIGHT, &engine);
    let machine = shell.list_row_rects[2];
    let first = shell.handle_mouse(click(machine.x, machine.y), &mut engine);
    assert!(first.consumed && first.action.is_none());
    let second = shell.handle_mouse(click(machine.x, machine.y), &mut engine);
    assert!(matches!(
        second.action,
        Some(OnboardingShellAction::SecureIntent(SecureStoreSubmission {
            placement: cockpit_proto::OnboardingSecurePlacement::MachineBoundFile,
            passphrase: None,
        }))
    ));

    assert!(shell.sync_snapshot(&snapshot(OnboardingStage::Provider)));
    let provider = render_string(&mut shell, WIDTH, HEIGHT, &engine);
    assert_eq!(shell.screen_kind(), OnboardingScreenKind::ProviderSearch);
    assert!(provider.contains("Filter"), "{provider}");
    assert!(provider.contains("filter by name"), "{provider}");
    assert!(provider.contains("Providers  ·  "), "{provider}");
}

#[test]
fn profile_stage_presents_its_native_screen_and_step() {
    assert_eq!(
        PROGRESS_STEPS,
        [
            "Welcome",
            "Name",
            "Secure store",
            "Provider",
            "Model",
            "Agent",
            "Lifetime",
            "Ready",
        ]
    );
    let mut shell = shell_at(OnboardingStage::Profile);
    let mut engine = Dialog::None;
    assert_eq!(shell.screen_kind(), OnboardingScreenKind::Profile);
    let rendered = render_string(&mut shell, 110, 32, &engine);
    assert!(rendered.contains("step 2/8"), "{rendered}");
    assert!(
        rendered.contains("What should Cockpit call you?"),
        "{rendered}"
    );
    assert!(matches!(
        shell.handle_key(key(KeyCode::Enter), &mut engine),
        Some(OnboardingShellAction::ApplyProfile(_))
    ));
    assert!(shell.handle_key(key(KeyCode::Esc), &mut engine).is_none());
    let rendered = render_string(&mut shell, 110, 32, &engine);
    assert!(rendered.contains("Leave setup?"), "{rendered}");
}

#[test]
fn profile_validation_errors_are_visible_and_do_not_submit() {
    let mut engine = Dialog::None;
    let mut too_long = shell_at(OnboardingStage::Profile);
    too_long.paste(&"x".repeat(81));
    assert!(
        too_long
            .handle_key(key(KeyCode::Enter), &mut engine)
            .is_none()
    );
    let rendered = render_string(&mut too_long, 110, 32, &engine);
    assert!(
        rendered.contains("name must be 80 characters or fewer"),
        "{rendered}"
    );

    let mut control = shell_at(OnboardingStage::Profile);
    control.paste("name\u{7}");
    assert!(
        control
            .handle_key(key(KeyCode::Enter), &mut engine)
            .is_none()
    );
    let rendered = render_string(&mut control, 110, 32, &engine);
    assert!(
        rendered.contains("name cannot contain control characters"),
        "{rendered}"
    );
}

#[test]
fn welcome_animation_is_tick_driven_and_settles() {
    let mut shell = shell_at(OnboardingStage::Welcome);
    let engine = Dialog::None;
    let frame_zero = render_string(&mut shell, 80, 24, &engine);
    // Every intermediate frame reports a change until the fly-in lands.
    for _ in 0..WELCOME_ANIMATION_FRAMES {
        assert!(shell.tick());
    }
    let landed = render_string(&mut shell, 80, 24, &engine);
    assert_ne!(frame_zero, landed);
    assert!(landed.contains("[press any button to continue]"));
    // Landing is not a freeze: the same tick keeps advancing the ambient
    // prop bob and cloud drift past the prompt frame.
    for _ in 0..4 {
        assert!(
            shell.tick(),
            "ambient motion must keep ticking after landing"
        );
    }
    let ambient = render_string(&mut shell, 80, 24, &engine);
    assert!(ambient.contains("[press any button to continue]"));
    assert_ne!(
        landed, ambient,
        "prop bob and cloud drift must continue past the prompt frame"
    );
}

#[test]
fn welcome_animation_keeps_the_animation_tick_alive_until_navigation() {
    let mut shell = shell_at(OnboardingStage::Welcome);
    assert!(shell.welcome_animation_active());
    for _ in 0..WELCOME_ANIMATION_FRAMES {
        shell.tick();
    }
    assert!(
        shell.welcome_animation_active(),
        "the post-landing ambient motion still needs the animation tick"
    );
    let reduced = OnboardingShell::new(&snapshot(OnboardingStage::Welcome), true);
    assert!(!reduced.welcome_animation_active());
    let other_stage = shell_at(OnboardingStage::SecureStore);
    assert!(!other_stage.welcome_animation_active());
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
    assert!(first.contains("[press any button to continue]"));
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
    let outcome = shell.handle_mouse(click(defer_row.x, defer_row.y), &mut engine);
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
    let OnboardingScreen::SecureStore(screen) = &mut shell.screen else {
        panic!("expected secure-store screen");
    };
    assert_eq!(
        screen.cursor, 1,
        "a missing keyring must start on the first selectable row"
    );
    screen.cursor = 0;
    let action = shell.handle_key(key(KeyCode::Enter), &mut engine);
    assert!(
        action.is_none(),
        "an unavailable keyring must not submit a placement"
    );
    let rendered = render_string(&mut shell, 80, 24, &engine);
    assert!(rendered.contains("unlock-keyring"));
    assert!(rendered.contains("Platform keyring  —  unavailable"));
    assert!(rendered.contains("Passphrase-protected file  —  recommended"));

    // An explicit machine-bound selection still submits.
    shell.handle_key(key(KeyCode::Up), &mut engine);
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
fn secure_store_wheel_skips_disabled_rows_and_stops_on_password_step() {
    let mut snapshot = snapshot(OnboardingStage::SecureStore);
    snapshot.host_capabilities =
        secure_store_capabilities(cockpit_proto::FeatureCapabilityState::Missing);
    let mut shell = OnboardingShell::new(&snapshot, false);
    let mut engine = Dialog::None;
    render_string(&mut shell, 80, 24, &engine);
    let list = shell.list_area;

    let up = shell.handle_mouse(wheel_up(list.x, list.y), &mut engine);
    assert!(up.consumed);
    let OnboardingScreen::SecureStore(screen) = &shell.screen else {
        panic!("expected secure-store screen");
    };
    assert_eq!(screen.cursor, 2, "wheel must skip the disabled keyring row");

    let down = shell.handle_mouse(wheel_down(list.x, list.y), &mut engine);
    assert!(down.consumed);
    let OnboardingScreen::SecureStore(screen) = &shell.screen else {
        panic!("expected secure-store screen");
    };
    assert_eq!(screen.cursor, 1);

    shell.handle_key(key(KeyCode::Enter), &mut engine);
    let ignored = shell.handle_mouse(wheel_down(list.x, list.y), &mut engine);
    assert!(
        !ignored.consumed,
        "password fields must not route wheel events to the hidden choice list"
    );
    let OnboardingScreen::SecureStore(screen) = &shell.screen else {
        panic!("expected secure-store screen");
    };
    assert_eq!(screen.cursor, 1);
    assert_eq!(
        screen.phase,
        secure_store::SecureStoreInputPhase::Passphrase
    );
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
    let mut engine = Dialog::None;
    // Render to record row rects (intro 3 lines, then three rows).
    render_string(&mut shell, 80, 24, &engine);
    let machine = shell.list_row_rects[2];
    // First click on a non-selected row only moves the cursor.
    let first = shell.handle_mouse(click(machine.x, machine.y), &mut engine);
    assert!(first.consumed);
    assert!(first.action.is_none());
    let outcome = shell.handle_mouse(click(machine.x, machine.y), &mut engine);
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
    let mut engine = Dialog::None;
    let _ = render_string(&mut shell, 100, 24, &engine);
    let first_row = shell.list_row_rects[0];

    // The default cursor is already on the first row; a click confirms.
    let outcome = shell.handle_mouse(click(first_row.x, first_row.y), &mut engine);
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
    shell.handle_key(key(KeyCode::Down), &mut engine);
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
    let first = shell.handle_mouse(click(first_row.x, first_row.y), &mut engine);
    assert!(first.consumed);
    assert!(first.action.is_none(), "first click only selects");
    let outcome = shell.handle_mouse(click(first_row.x, first_row.y), &mut engine);
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
    let list = shell.list_area;
    let outcome = shell.handle_mouse(wheel_down(list.x, list.y), &mut Dialog::None);
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
    shell.handle_mouse(wheel_up(list.x, list.y), &mut Dialog::None);
    let offset_up = match &shell.screen {
        OnboardingScreen::ProviderSearch(screen) => screen.offset(),
        _other => panic!("expected search screen"),
    };
    assert_eq!(offset_up, offset_after - 1);
    shell.handle_mouse(wheel_up(list.x, list.y), &mut Dialog::None);
    let offset_clamped = match &shell.screen {
        OnboardingScreen::ProviderSearch(screen) => screen.offset(),
        _other => panic!("expected search screen"),
    };
    assert!(offset_clamped <= offset_up);
}

#[test]
fn provider_catalog_scrollbar_drag_changes_the_viewport_and_consumes_gesture() {
    let mut shell = shell_at(OnboardingStage::Provider);
    let mut engine = Dialog::None;
    render_string(&mut shell, 80, 12, &engine);
    let scrollbar = match &shell.screen {
        OnboardingScreen::ProviderSearch(screen) => screen.scrollbar_area(),
        _other => panic!("expected search screen"),
    };
    assert!(!scrollbar.is_empty(), "small provider list must overflow");

    let down = shell.handle_mouse(click(scrollbar.x, scrollbar.y), &mut engine);
    assert!(down.consumed);
    let OnboardingScreen::ProviderSearch(screen) = &shell.screen else {
        panic!("expected search screen");
    };
    assert!(screen.dragging_scrollbar());
    assert_eq!(screen.offset(), 0);

    let bottom = scrollbar.bottom().saturating_sub(1);
    let drag = shell.handle_mouse(drag_left(scrollbar.x, bottom), &mut engine);
    assert!(drag.consumed);
    let OnboardingScreen::ProviderSearch(screen) = &shell.screen else {
        panic!("expected search screen");
    };
    assert!(
        screen.offset() > 0,
        "dragging down must change the viewport"
    );
    let dragged_offset = screen.offset();

    let release = shell.handle_mouse(release_left(scrollbar.x, bottom), &mut engine);
    assert!(release.consumed);
    let after_release = shell.handle_mouse(drag_left(scrollbar.x, scrollbar.y), &mut engine);
    assert!(!after_release.consumed);
    let OnboardingScreen::ProviderSearch(screen) = &shell.screen else {
        panic!("expected search screen");
    };
    assert!(!screen.dragging_scrollbar());
    assert_eq!(screen.offset(), dragged_offset);
}

#[test]
fn provider_catalog_hides_scrollbar_without_overflow() {
    let mut shell = shell_at(OnboardingStage::Provider);
    render_string(&mut shell, 120, 40, &Dialog::None);
    let OnboardingScreen::ProviderSearch(screen) = &shell.screen else {
        panic!("expected search screen");
    };
    assert!(
        screen.scrollbar_area().is_empty(),
        "a catalog that fits must not expose a scrollbar hit target"
    );
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

// ── Native provider sub-phases ───────────────────────────────────────────

#[test]
fn authenticate_escape_returns_to_search() {
    let mut shell = shell_at(OnboardingStage::Provider);
    let mut engine = Dialog::None;
    shell.present_authenticate(cockpit_core::providers::template_by_id("openai").unwrap());
    let action = shell.handle_key(key(KeyCode::Esc), &mut engine);
    assert!(action.is_none());
    assert_eq!(shell.screen_kind(), OnboardingScreenKind::ProviderSearch);
}

#[test]
fn authenticate_oauth_device_idle_escape_cancels_and_returns_to_search() {
    let mut shell = shell_at(OnboardingStage::Provider);
    let mut engine = Dialog::None;
    shell.present_authenticate(cockpit_core::providers::template_by_id("codex-oauth").unwrap());
    shell.set_auth_phase_for_golden(AuthPhase::DeviceIdle);
    let action = shell.handle_key(key(KeyCode::Esc), &mut engine);
    assert!(matches!(action, Some(OnboardingShellAction::OAuth(_))));
    assert_eq!(shell.screen_kind(), OnboardingScreenKind::ProviderSearch);
}

#[test]
fn authenticate_oauth_paste_callback_escape_cancels_and_returns_to_search() {
    let mut shell = shell_at(OnboardingStage::Provider);
    let mut engine = Dialog::None;
    shell.present_authenticate(cockpit_core::providers::template_by_id("grok-oauth").unwrap());
    shell.set_auth_phase_for_golden(AuthPhase::PasteCallback);
    let action = shell.handle_key(key(KeyCode::Esc), &mut engine);
    assert!(matches!(action, Some(OnboardingShellAction::OAuth(_))));
    assert_eq!(shell.screen_kind(), OnboardingScreenKind::ProviderSearch);
}

#[test]
fn authenticate_oauth_device_polling_escape_stays_on_authenticate() {
    let mut shell = shell_at(OnboardingStage::Provider);
    let mut engine = Dialog::None;
    shell.present_authenticate(cockpit_core::providers::template_by_id("codex-oauth").unwrap());
    shell.set_auth_phase_for_golden(AuthPhase::DevicePolling);
    let action = shell.handle_key(key(KeyCode::Esc), &mut engine);
    assert!(matches!(action, Some(OnboardingShellAction::OAuth(_))));
    assert_eq!(shell.screen_kind(), OnboardingScreenKind::Authenticate);
}

#[test]
fn authenticate_oauth_acknowledge_then_begin_enters_device_idle_without_waiting_copy() {
    let mut shell = shell_at(OnboardingStage::Provider);
    let mut engine = Dialog::None;
    shell.present_authenticate(cockpit_core::providers::template_by_id("codex-oauth").unwrap());
    let OAuthFlowRequest {
        client_flow_id,
        operation_id,
        ..
    } = match shell.handle_key(key(KeyCode::Enter), &mut engine) {
        Some(OnboardingShellAction::OAuth(request)) => request,
        other => panic!("acknowledge must queue OAuth, got {other:?}"),
    };
    let begin = shell
        .apply_onboarding_oauth_acknowledgement(client_flow_id, operation_id, Ok(()))
        .expect("successful acknowledgement must queue begin");
    shell.apply_onboarding_oauth_begin(
        begin.client_flow_id,
        begin.operation_id,
        OAuthBeginResult::Public(Ok(OAuthPublicBegin {
            flow_id: "remote-flow".into(),
            authorize_url: "https://auth.openai.com/codex/device".into(),
            user_code: Some("WXYZ-1234".into()),
        })),
    );
    assert!(matches!(
        &shell.screen,
        OnboardingScreen::Authenticate(screen) if screen.auth_phase() == AuthPhase::DeviceIdle
    ));
    let rendered = render_string(&mut shell, 80, 24, &engine);
    assert!(!rendered.contains("Waiting for approval"), "{rendered}");
}

#[test]
fn verify_no_endpoint_renders_full_configured_models_sentence_at_80x24() {
    let mut shell = shell_at(OnboardingStage::Provider);
    let engine = Dialog::None;
    shell.present_verify("no-catalog".into());
    shell.apply_provider_verification("no-catalog", VerifyOutcome::NoEndpoint, None);
    let rendered = render_string(&mut shell, 80, 24, &engine);
    let body = rendered.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(
        body.contains(
            "The credential is stored. This provider does not publish a model catalog, so Cockpit will use configured models."
        ),
        "{rendered}"
    );
}

#[test]
fn verify_retry_reprobes_the_same_provider() {
    let mut shell = shell_at(OnboardingStage::Provider);
    let mut engine = Dialog::None;
    shell.present_verify("localtest".into());
    shell.apply_provider_verification("localtest", VerifyOutcome::Unauthorized(401), None);
    let action = shell.handle_key(key(KeyCode::Char('r')), &mut engine);
    assert!(matches!(
        action,
        Some(OnboardingShellAction::RetryProviderVerification { provider_id })
            if provider_id == "localtest"
    ));
    assert!(matches!(
        &shell.screen,
        OnboardingScreen::Verify(screen)
            if matches!(screen.phase(), verify::VerifyPhase::Fetching)
    ));
}

#[test]
fn verify_renders_each_daemon_failure_class_with_retry() {
    let engine = Dialog::None;
    for (outcome, expected) in [
        (
            VerifyOutcome::Unauthorized(401),
            "Credential rejected (401)",
        ),
        (VerifyOutcome::NotFound, "Wrong base URL (404)"),
        (
            VerifyOutcome::HttpStatus {
                status: 429,
                snippet: "rate limited".into(),
            },
            "Provider returned HTTP 429",
        ),
        (
            VerifyOutcome::Network("DNS lookup failed".into()),
            "Couldn't reach the provider",
        ),
        (
            VerifyOutcome::Parse("invalid model JSON".into()),
            "Couldn't parse the model list",
        ),
    ] {
        let mut shell = shell_at(OnboardingStage::Provider);
        shell.present_verify("fake".into());
        shell.apply_provider_verification("fake", outcome, None);
        let rendered = render_string(&mut shell, 80, 24, &engine);
        assert!(rendered.contains(expected), "{rendered}");
        assert!(rendered.contains("[ Retry ]"), "{rendered}");
    }
}

#[test]
fn verify_add_another_keeps_provider_stage_during_completion_detour() {
    let mut shell = shell_at(OnboardingStage::Complete);
    let mut engine = Dialog::None;
    shell.present_completion("summary".into());
    shell.begin_completion_provider_detour(None);
    shell.present_verify("openai".into());
    shell.apply_provider_verification(
        "openai",
        VerifyOutcome::Models(vec!["gpt-4o".into()]),
        Some(ProviderSettlementEvidence {
            operation_id: "op".into(),
            mutation_intent_hash: "00".repeat(32),
            mutation_config_generation: 1,
            config_generation: 1,
        }),
    );
    let action = shell.handle_key(key(KeyCode::Char('a')), &mut engine);
    assert!(matches!(
        action,
        Some(OnboardingShellAction::FinishProvider {
            add_another: true,
            ..
        })
    ));
    shell.present_provider_search(Some(
        "Provider connected. Add another, or finish from Verify.".into(),
    ));
    assert_eq!(shell.screen_kind(), OnboardingScreenKind::ProviderSearch);
    assert_eq!(shell.stage(), OnboardingStage::Complete);
    assert!(shell.completion_detour_active());
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
    let buttons = OnboardingShell::action_buttons(&shell.screen);
    assert!(!buttons[0].primary);
    assert!(buttons[1].primary);

    // "Add another provider" is a shell-local detour (the daemon stage is
    // already Complete): the searchable catalog returns, and Escape offers
    // a local return to the stored summary instead of a daemon transition.
    shell.handle_key(key(KeyCode::Up), &mut engine);
    let buttons = OnboardingShell::action_buttons(&shell.screen);
    assert!(buttons[0].primary);
    assert!(!buttons[1].primary);
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
    assert!(render_string(&mut shell, 90, 24, &engine).contains("openai"));

    let mut superseding = snapshot(OnboardingStage::Provider);
    superseding.revision += 1;
    assert!(shell.sync_snapshot(&superseding));

    let rendered = render_string(&mut shell, 90, 24, &engine);
    assert!(rendered.contains("Filter"), "{rendered}");
    assert!(!rendered.contains("openai"), "{rendered}");
}

// ── Chrome ───────────────────────────────────────────────────────────────

#[test]
fn chrome_shows_progress_and_limited_mode_at_both_sizes() {
    for (width, height) in [(60u16, 20u16), (120, 40)] {
        let mut shell = shell_at(OnboardingStage::SecureStore);
        let engine = Dialog::None;
        let rendered = render_string(&mut shell, width, height, &engine);
        assert!(rendered.contains("Secure your secrets"), "{width}x{height}");
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
fn provider_authenticate_renders_inside_full_screen_chrome_at_narrow_and_wide_sizes() {
    let template = cockpit_core::providers::template_by_id("openai").unwrap();
    let engine = Dialog::None;
    let mut shell = shell_at(OnboardingStage::Provider);
    shell.present_authenticate(template);

    for (width, height) in [(48, 18), (110, 32)] {
        let rendered = render_string(&mut shell, width, height, &engine);
        assert!(rendered.contains("Add your API key"), "{rendered}");
        assert!(rendered.contains("API key"), "{rendered}");
        assert!(rendered.contains("[ Reveal ]"), "{rendered}");
        assert!(rendered.contains("[ Continue ]"), "{rendered}");
        assert!(rendered.contains("◐Provider"), "{rendered}");
    }
}

#[test]
fn lifetime_continue_submits_the_recorded_choice_by_keyboard_and_pointer() {
    let mut engine = Dialog::None;

    // Cursor 0 is the persistent default: Enter submits true without any
    // cursor motion.
    let mut shell = shell_at(OnboardingStage::Lifetime);
    assert_eq!(shell.screen_kind(), OnboardingScreenKind::Lifetime);
    assert!(matches!(
        shell.handle_key(key(KeyCode::Enter), &mut engine),
        Some(OnboardingShellAction::ApplyLifetime(true))
    ));

    // Down moves to the ephemeral row; Enter submits false.
    let mut shell = shell_at(OnboardingStage::Lifetime);
    shell.handle_key(key(KeyCode::Down), &mut engine);
    assert!(matches!(
        shell.handle_key(key(KeyCode::Enter), &mut engine),
        Some(OnboardingShellAction::ApplyLifetime(false))
    ));

    // Pointer: a row click only records the choice (#426 — the answer is
    // applied when it is submitted, never when it is picked); the rendered
    // Continue button then submits the clicked row.
    const WIDTH: u16 = 100;
    const HEIGHT: u16 = 30;
    let mut shell = shell_at(OnboardingStage::Lifetime);
    render_string(&mut shell, WIDTH, HEIGHT, &engine);
    let ephemeral_row = shell.list_row_rects[1];
    let choose = shell.handle_mouse(click(ephemeral_row.x, ephemeral_row.y), &mut engine);
    assert!(choose.consumed);
    assert!(
        choose.action.is_none(),
        "a row click must choose, not submit"
    );
    let submit = click_action(&mut shell, 0, WIDTH, HEIGHT, &mut engine);
    assert!(matches!(
        submit.action,
        Some(OnboardingShellAction::ApplyLifetime(false))
    ));
}

fn model_catalog_with_distinct_policies() -> ProvidersConfig {
    use cockpit_config::providers::{
        CapabilityStatus, ModelCapabilities, ModelEntry, ModelTrust, ProviderEntry, ThinkingMode,
    };

    let mut config = ProvidersConfig::default();
    let provider = ProviderEntry {
        models: vec![
            ModelEntry {
                id: "model-a".into(),
                trust: Some(ModelTrust::Untrusted),
                capabilities: ModelCapabilities {
                    image_input: CapabilityStatus::Supported,
                    reasoning: CapabilityStatus::Supported,
                    context_tokens: Some(4096),
                    max_output_tokens: Some(512),
                    ..Default::default()
                },
                default_thinking_mode: Some(ThinkingMode::High),
                subagent_invokable: Some(false),
                can_delegate: Some(true),
                ..Default::default()
            },
            ModelEntry {
                id: "model-b".into(),
                trust: Some(ModelTrust::Trusted),
                capabilities: ModelCapabilities {
                    tool_calling: CapabilityStatus::Supported,
                    structured_outputs: CapabilityStatus::Supported,
                    ..Default::default()
                },
                default_thinking_mode: Some(ThinkingMode::Off),
                subagent_invokable: Some(true),
                can_delegate: Some(false),
                ..Default::default()
            },
        ],
        ..Default::default()
    };
    config.providers.insert("provider".into(), provider);
    config
}

#[test]
fn model_continue_commits_focus_reseeds_policy_and_submits_by_pointer() {
    const WIDTH: u16 = 100;
    const HEIGHT: u16 = 30;
    let mut shell = shell_at(OnboardingStage::Model);
    shell.present_model(
        &model_catalog_with_distinct_policies(),
        Some(("provider", "model-a")),
    );
    let mut engine = Dialog::None;

    let default = render_string(&mut shell, WIDTH, HEIGHT, &engine);
    assert!(default.contains("◉ ★ model-a"), "{default}");
    assert!(default.contains("○   model-b"), "{default}");
    assert!(default.contains("esc options"), "{default}");

    // Arrow focus plus Continue commits model-b and reseeds every policy field.
    shell.handle_key(key(KeyCode::Down), &mut engine);
    shell.handle_key(key(KeyCode::Enter), &mut engine);
    assert_eq!(shell.model_phase(), Some(ModelPhase::Trust));
    assert_eq!(shell.model_selection(), Some(("provider", "model-b")));
    let trust = render_string(&mut shell, WIDTH, HEIGHT, &engine);
    assert!(trust.contains("◉ trusted"), "{trust}");

    // Focus differs from the reseeded trusted value; Enter must commit focus.
    shell.handle_key(key(KeyCode::Up), &mut engine);
    shell.handle_key(key(KeyCode::Enter), &mut engine);
    assert_eq!(shell.model_phase(), Some(ModelPhase::Capabilities));

    // model-b starts with tools + structured outputs. Keyboard toggles tools;
    // a first click focuses reasoning and the second click toggles it.
    shell.handle_key(key(KeyCode::Down), &mut engine);
    shell.handle_key(key(KeyCode::Char(' ')), &mut engine);
    render_string(&mut shell, WIDTH, HEIGHT, &engine);
    let reasoning = shell.model_row_rects()[2];
    shell.handle_mouse(click(reasoning.x, reasoning.y), &mut engine);
    shell.handle_mouse(click(reasoning.x, reasoning.y), &mut engine);
    shell.handle_key(key(KeyCode::Enter), &mut engine);
    assert_eq!(shell.model_phase(), Some(ModelPhase::Limits));

    for ch in "8192".chars() {
        shell.handle_key(key(KeyCode::Char(ch)), &mut engine);
    }
    shell.handle_key(key(KeyCode::Tab), &mut engine);
    for ch in "1024".chars() {
        shell.handle_key(key(KeyCode::Char(ch)), &mut engine);
    }
    let limits = render_string(&mut shell, WIDTH, HEIGHT, &engine);
    assert!(limits.contains("Context window tokens"), "{limits}");
    assert!(limits.contains("8192"), "{limits}");
    assert!(limits.contains("Max output tokens"), "{limits}");
    assert!(limits.contains("1024"), "{limits}");
    shell.handle_key(key(KeyCode::Enter), &mut engine);

    // model-b reseeded thinking to off (row 1); Down + Enter commits low.
    shell.handle_key(key(KeyCode::Down), &mut engine);
    shell.handle_key(key(KeyCode::Enter), &mut engine);
    assert_eq!(shell.model_phase(), Some(ModelPhase::Delegation));

    // model-b reseeded delegation to [true, false]. The second click toggles
    // can_delegate, then pointer Continue returns the complete submission.
    render_string(&mut shell, WIDTH, HEIGHT, &engine);
    let can_delegate = shell.model_row_rects()[1];
    shell.handle_mouse(click(can_delegate.x, can_delegate.y), &mut engine);
    shell.handle_mouse(click(can_delegate.x, can_delegate.y), &mut engine);
    let submit = click_action(&mut shell, 0, WIDTH, HEIGHT, &mut engine);
    let Some(OnboardingShellAction::ApplyModel(submission)) = submit.action else {
        panic!("pointer Continue must submit the native model form");
    };
    assert_eq!(submission.provider_id, "provider");
    assert_eq!(submission.model_id, "model-b");
    assert_eq!(submission.trust, "untrusted");
    assert_eq!(
        submission.capabilities,
        vec!["reasoning", "structured_outputs"]
    );
    assert_eq!(submission.context_tokens, "8192");
    assert_eq!(submission.max_output_tokens, "1024");
    assert_eq!(submission.thinking, "low");
    assert_eq!(
        submission.subagent_flags,
        vec!["subagent_invokable", "can_delegate"]
    );
}

#[test]
fn model_back_walks_substeps_then_escape_opens_options() {
    const WIDTH: u16 = 100;
    const HEIGHT: u16 = 30;
    let mut shell = shell_at(OnboardingStage::Model);
    shell.present_model(
        &model_catalog_with_distinct_policies(),
        Some(("provider", "model-a")),
    );
    let mut engine = Dialog::None;

    shell.handle_key(key(KeyCode::Enter), &mut engine);
    shell.handle_key(key(KeyCode::Enter), &mut engine);
    assert_eq!(shell.model_phase(), Some(ModelPhase::Capabilities));
    shell.handle_key(key(KeyCode::Esc), &mut engine);
    assert_eq!(shell.model_phase(), Some(ModelPhase::Trust));

    render_string(&mut shell, WIDTH, HEIGHT, &engine);
    let back = shell.back_rect;
    shell.handle_mouse(click(back.x, back.y), &mut engine);
    assert_eq!(shell.model_phase(), Some(ModelPhase::DefaultModel));
    shell.handle_key(key(KeyCode::Esc), &mut engine);
    let options = render_string(&mut shell, WIDTH, HEIGHT, &engine);
    assert!(options.contains("Leave setup?"), "{options}");
}

#[test]
fn agent_authoring_back_stays_inside_the_editor_until_the_root_name_phase() {
    const WIDTH: u16 = 100;
    const HEIGHT: u16 = 30;
    let mut shell = shell_at(OnboardingStage::Agent);
    shell.present_agent_authoring(agent::golden_sample_projection(), "agent-back".into());
    let mut engine = Dialog::None;

    shell.handle_key(key(KeyCode::Enter), &mut engine);
    assert_eq!(
        shell.test_agent_authoring_phase(),
        Some(agent::Phase::ModelGrants)
    );
    shell.handle_key(key(KeyCode::Esc), &mut engine);
    assert_eq!(
        shell.test_agent_authoring_phase(),
        Some(agent::Phase::SourceIdentity),
        "Escape must use authoring phase-back before opening shell options"
    );
    let root = render_string(&mut shell, WIDTH, HEIGHT, &engine);
    assert!(
        !root.contains("Leave setup?"),
        "phase back must not open options"
    );

    shell.handle_key(key(KeyCode::Enter), &mut engine);
    assert_eq!(
        shell.test_agent_authoring_phase(),
        Some(agent::Phase::ModelGrants)
    );
    render_string(&mut shell, WIDTH, HEIGHT, &engine);
    let back = shell.back_rect;
    let outcome = shell.handle_mouse(click(back.x, back.y), &mut engine);
    assert!(
        outcome.action.is_none(),
        "authoring Back must not leave the stage"
    );
    assert_eq!(
        shell.test_agent_authoring_phase(),
        Some(agent::Phase::SourceIdentity)
    );

    shell.handle_key(key(KeyCode::Esc), &mut engine);
    let options = render_string(&mut shell, WIDTH, HEIGHT, &engine);
    assert!(
        options.contains("Leave setup?"),
        "only root-name Escape may open shell options: {options}"
    );
}

#[test]
fn model_same_default_after_back_preserves_every_policy_edit() {
    let mut shell = shell_at(OnboardingStage::Model);
    shell.present_model(
        &model_catalog_with_distinct_policies(),
        Some(("provider", "model-b")),
    );
    let mut engine = Dialog::None;

    // Change every policy group seeded by the selected catalog model.
    shell.handle_key(key(KeyCode::Enter), &mut engine);
    shell.handle_key(key(KeyCode::Up), &mut engine);
    shell.handle_key(key(KeyCode::Enter), &mut engine);
    shell.handle_key(key(KeyCode::Down), &mut engine);
    shell.handle_key(key(KeyCode::Char(' ')), &mut engine);
    shell.handle_key(key(KeyCode::Down), &mut engine);
    shell.handle_key(key(KeyCode::Char(' ')), &mut engine);
    shell.handle_key(key(KeyCode::Enter), &mut engine);
    for ch in "8192".chars() {
        shell.handle_key(key(KeyCode::Char(ch)), &mut engine);
    }
    shell.handle_key(key(KeyCode::Tab), &mut engine);
    for ch in "1024".chars() {
        shell.handle_key(key(KeyCode::Char(ch)), &mut engine);
    }
    shell.handle_key(key(KeyCode::Enter), &mut engine);
    shell.handle_key(key(KeyCode::Down), &mut engine);
    shell.handle_key(key(KeyCode::Enter), &mut engine);
    shell.handle_key(key(KeyCode::Char(' ')), &mut engine);
    shell.handle_key(key(KeyCode::Down), &mut engine);
    shell.handle_key(key(KeyCode::Char(' ')), &mut engine);

    // Walk back to Default Model, then continue without changing the pair.
    for expected in [
        ModelPhase::Thinking,
        ModelPhase::Limits,
        ModelPhase::Capabilities,
        ModelPhase::Trust,
        ModelPhase::DefaultModel,
    ] {
        shell.handle_key(key(KeyCode::Esc), &mut engine);
        assert_eq!(shell.model_phase(), Some(expected));
    }
    shell.handle_key(key(KeyCode::Enter), &mut engine);
    for _ in 0..4 {
        shell.handle_key(key(KeyCode::Enter), &mut engine);
    }
    let Some(OnboardingShellAction::ApplyModel(submission)) =
        shell.handle_key(key(KeyCode::Enter), &mut engine)
    else {
        panic!("same-model Continue must preserve edits and submit");
    };

    assert_eq!(submission.provider_id, "provider");
    assert_eq!(submission.model_id, "model-b");
    assert_eq!(submission.trust, "untrusted");
    assert_eq!(
        submission.capabilities,
        vec!["reasoning", "structured_outputs"]
    );
    assert_eq!(submission.context_tokens, "8192");
    assert_eq!(submission.max_output_tokens, "1024");
    assert_eq!(submission.thinking, "low");
    assert_eq!(submission.subagent_flags, vec!["can_delegate"]);
}

#[test]
fn model_empty_catalog_shows_error_accepts_id_and_submits() {
    const WIDTH: u16 = 100;
    const HEIGHT: u16 = 30;
    let mut config = ProvidersConfig::default();
    config.providers.insert("manual".into(), Default::default());
    let mut shell = shell_at(OnboardingStage::Model);
    shell.present_model(&config, Some(("manual", "")));
    let mut engine = Dialog::None;

    shell.handle_key(key(KeyCode::Enter), &mut engine);
    let error = render_string(&mut shell, WIDTH, HEIGHT, &engine);
    assert!(
        error.contains("Choose a provider and enter a model ID."),
        "{error}"
    );
    assert!(error.contains("type model id"), "{error}");

    shell.paste("manual-model");
    let next = click_action(&mut shell, 0, WIDTH, HEIGHT, &mut engine);
    assert!(next.action.is_none());
    assert_eq!(shell.model_phase(), Some(ModelPhase::Trust));
    assert_eq!(shell.model_selection(), Some(("manual", "manual-model")));
    for _ in 0..4 {
        shell.handle_key(key(KeyCode::Enter), &mut engine);
    }
    assert_eq!(shell.model_phase(), Some(ModelPhase::Delegation));
    let Some(OnboardingShellAction::ApplyModel(submission)) =
        shell.handle_key(key(KeyCode::Enter), &mut engine)
    else {
        panic!("manual model entry must submit after all native substeps");
    };
    assert_eq!(submission.provider_id, "manual");
    assert_eq!(submission.model_id, "manual-model");
}

#[test]
fn lifetime_native_screen_renders_inside_full_screen_chrome_at_narrow_and_wide_sizes() {
    let mut shell = shell_at(OnboardingStage::Lifetime);
    let engine = Dialog::None;
    for (width, height) in [(48, 18), (110, 32)] {
        let rendered = render_string(&mut shell, width, height, &engine);
        assert!(rendered.contains("Background agents"), "{rendered}");
        assert!(
            rendered.contains("Keep agents running in the background"),
            "{rendered}"
        );
        assert!(rendered.contains("‹ Back"), "{rendered}");
        assert!(rendered.contains("[ Continue ]"), "{rendered}");
        assert!(!rendered.contains("Setup —"), "{rendered}");
    }
}

#[test]
fn failed_bootstrap_state_is_surfaced() {
    let mut snap = snapshot(OnboardingStage::SecureStore);
    snap.bootstrap_state = cockpit_proto::OnboardingBootstrapState::Failed;
    let mut shell = OnboardingShell::new(&snap, false);
    let engine = Dialog::None;
    let rendered = render_string(&mut shell, 80, 24, &engine);
    assert!(rendered.contains("Onboarding bootstrap failed"));
}

#[test]
fn materializing_bootstrap_state_is_surfaced() {
    let mut snap = snapshot(OnboardingStage::SecureStore);
    snap.bootstrap_state = cockpit_proto::OnboardingBootstrapState::Materializing;
    let mut shell = OnboardingShell::new(&snap, false);
    let engine = Dialog::None;
    let rendered = render_string(&mut shell, 80, 24, &engine);
    assert!(rendered.contains("Preparing the secure store"));
}

#[test]
fn chrome_paints_back_and_action_bar_on_every_settled_screen() {
    let engine = Dialog::None;
    for stage in [
        OnboardingStage::Profile,
        OnboardingStage::Lifetime,
        OnboardingStage::SecureStore,
        OnboardingStage::Provider,
        OnboardingStage::Model,
    ] {
        let mut shell = shell_at(stage);
        shell.set_frame_for_golden(WELCOME_ANIMATION_FRAMES);
        let rendered = render_string(&mut shell, 80, 24, &engine);
        match stage {
            OnboardingStage::SecureStore => {
                assert!(
                    !rendered.contains("‹ Back"),
                    "{stage:?} must withhold Back on the choice screen: {rendered}"
                );
            }
            _ => {
                assert!(
                    rendered.contains("‹ Back"),
                    "{stage:?} must paint ‹ Back: {rendered}"
                );
            }
        }
        assert!(
            rendered.contains("[ Continue ]") || rendered.contains("[ Choose ]"),
            "{stage:?} must paint an action bar: {rendered}"
        );
        assert!(
            !rendered.contains("┌") && !rendered.contains("└"),
            "{stage:?} must not use Borders::ALL box drawing: {rendered}"
        );
    }

    let mut welcome = shell_at(OnboardingStage::Welcome);
    welcome.set_frame_for_golden(WELCOME_ANIMATION_FRAMES);
    let rendered = render_string(&mut welcome, 80, 24, &engine);
    assert!(!rendered.contains("‹ Back"), "{rendered}");
    assert!(!rendered.contains("[ Continue ]"), "{rendered}");

    let mut secure_store = shell_at(OnboardingStage::SecureStore);
    secure_store.set_frame_for_golden(WELCOME_ANIMATION_FRAMES);
    if let OnboardingScreen::SecureStore(screen) = &mut secure_store.screen {
        screen.phase = secure_store::SecureStoreInputPhase::Passphrase;
    }
    let rendered = render_string(&mut secure_store, 80, 24, &engine);
    assert!(
        rendered.contains("‹ Back"),
        "secure-store password sub-step must paint ‹ Back: {rendered}"
    );
    assert!(
        rendered.contains("[ Reveal ]") && rendered.contains("[ Save ]"),
        "secure-store password sub-step must paint Reveal/Save: {rendered}"
    );
}

#[test]
fn welcome_fly_in_has_no_back_button() {
    let mut shell = shell_at(OnboardingStage::Welcome);
    let engine = Dialog::None;
    let rendered = render_string(&mut shell, 80, 24, &engine);
    assert!(!rendered.contains("‹ Back"), "{rendered}");
}

#[test]
fn back_is_unclickable_on_welcome_and_provider() {
    let mut engine = Dialog::None;
    for stage in [OnboardingStage::Welcome, OnboardingStage::Provider] {
        let mut shell = shell_at(stage);
        shell.set_frame_for_golden(WELCOME_ANIMATION_FRAMES);
        render_string(&mut shell, 80, 24, &engine);
        let outcome = shell.handle_mouse(click(1, 0), &mut engine);
        assert!(
            !matches!(
                outcome.action,
                Some(OnboardingShellAction::Transition(
                    cockpit_proto::OnboardingTransitionKind::Back,
                    None
                ))
            ),
            "{stage:?} must not emit Back"
        );
    }
}

#[test]
fn ctrl_c_quits_from_anywhere() {
    let mut engine = Dialog::None;
    let mut shell = shell_at(OnboardingStage::SecureStore);
    let mut key = key(KeyCode::Char('c'));
    key.modifiers = KeyModifiers::CONTROL;
    assert!(matches!(
        shell.handle_key(key, &mut engine),
        Some(OnboardingShellAction::Close)
    ));
}

#[test]
fn key_release_is_ignored() {
    let mut engine = Dialog::None;
    let mut shell = shell_at(OnboardingStage::Welcome);
    shell.set_frame_for_golden(WELCOME_ANIMATION_FRAMES);
    let mut release = key(KeyCode::Char(' '));
    release.kind = crossterm::event::KeyEventKind::Release;
    assert!(shell.handle_key(release, &mut engine).is_none());
}

#[test]
fn click_after_prompt_advances_welcome() {
    let mut engine = Dialog::None;
    let mut shell = shell_at(OnboardingStage::Welcome);
    shell.set_frame_for_golden(WELCOME_ANIMATION_FRAMES);
    render_string(&mut shell, 80, 24, &engine);
    let outcome = shell.handle_mouse(click(40, 23), &mut engine);
    assert!(matches!(
        outcome.action,
        Some(OnboardingShellAction::Transition(
            cockpit_proto::OnboardingTransitionKind::Advance,
            None
        ))
    ));
}
