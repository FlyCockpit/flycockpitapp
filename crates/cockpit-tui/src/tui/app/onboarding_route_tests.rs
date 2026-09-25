//! Entry-point convergence tests: every onboarding route uses the shell adapter.

use super::*;
use cockpit_test_support::TestEnvGuard;

fn snapshot(stage: cockpit_proto::OnboardingStage) -> cockpit_proto::OnboardingBootstrapSnapshot {
    cockpit_proto::OnboardingBootstrapSnapshot {
        run_id: uuid::Uuid::from_u128(1),
        attempt_id: uuid::Uuid::from_u128(2),
        revision: 3,
        stage,
        bootstrap_state: cockpit_proto::OnboardingBootstrapState::Ready,
        limited_mode: false,
        lifetime_selection: None,
        host_capabilities: cockpit_proto::HostCapabilitySnapshot::unpublished(),
        last_receipt: None,
    }
}

#[test]
fn named_setup_wizard_table_is_exhaustive() {
    let tmp = tempfile::tempdir().unwrap();
    let _home = TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    for wizard_id in cockpit_core::wizard::named_setup_wizard_ids() {
        let mut app = App::new(Some(tmp.path()), false);
        app.apply_onboarding_bootstrap_snapshot(Some(snapshot(
            cockpit_proto::OnboardingStage::Complete,
        )));
        app.onboarding_shell = None;
        app.dialog = Dialog::None;
        app.open_onboarding_setup(Some(wizard_id));
        assert!(
            app.onboarding_shell.is_some(),
            "open_onboarding_setup must handle named wizard `{wizard_id}`"
        );
    }
}

#[test]
fn unknown_named_setup_wizard_does_not_mount() {
    let tmp = tempfile::tempdir().unwrap();
    let _home = TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let mut app = App::new(Some(tmp.path()), false);
    app.apply_onboarding_bootstrap_snapshot(Some(snapshot(
        cockpit_proto::OnboardingStage::Complete,
    )));
    app.open_onboarding_setup(Some("not-a-real-wizard"));
    assert!(
        app.onboarding_shell.is_none(),
        "unknown setup wizards must not mount the onboarding shell"
    );
    assert_ne!(app.dialog.test_page_name(), Some("wizard_menu"));
}

#[test]
fn post_onboarding_setup_wizards_mount_embedded_settings() {
    let tmp = tempfile::tempdir().unwrap();
    let _home = TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    for wizard_id in [
        cockpit_core::wizard::SECURITY_WIZARD_ID,
        cockpit_core::wizard::MODEL_WIZARD_ID,
    ] {
        let mut app = App::new(Some(tmp.path()), false);
        app.apply_onboarding_bootstrap_snapshot(Some(snapshot(
            cockpit_proto::OnboardingStage::Complete,
        )));
        app.open_onboarding_setup(Some(wizard_id));
        assert!(
            app.onboarding_shell.is_some(),
            "wizard `{wizard_id}` must mount the full-screen onboarding shell"
        );
        assert_eq!(
            app.onboarding_shell
                .as_ref()
                .map(|shell| shell.screen_kind()),
            Some(crate::tui::onboarding::OnboardingScreenKind::EmbeddedSettings),
            "post-onboarding setup wizards embed the settings engine in the shell"
        );
        assert_eq!(app.dialog.test_page_name(), Some(wizard_id));
    }
}

#[test]
fn post_onboarding_wizards_reject_active_onboarding_stages() {
    let tmp = tempfile::tempdir().unwrap();
    let _home = TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    for wizard_id in [
        cockpit_core::wizard::SECURITY_WIZARD_ID,
        cockpit_core::wizard::MODEL_WIZARD_ID,
    ] {
        for stage in [
            cockpit_proto::OnboardingStage::Welcome,
            cockpit_proto::OnboardingStage::Profile,
            cockpit_proto::OnboardingStage::SecureStore,
            cockpit_proto::OnboardingStage::Provider,
            cockpit_proto::OnboardingStage::Model,
            cockpit_proto::OnboardingStage::Lifetime,
            cockpit_proto::OnboardingStage::Agent,
        ] {
            let mut app = App::new(Some(tmp.path()), false);
            app.apply_onboarding_bootstrap_snapshot(Some(snapshot(stage)));
            app.open_onboarding_setup(Some(wizard_id));
            assert_ne!(
                app.dialog.test_page_name(),
                Some(wizard_id),
                "wizard `{wizard_id}` must not mount during active onboarding stage `{stage:?}`"
            );
        }
    }
}

#[test]
fn setup_slash_opens_onboarding_shell_not_wizard_menu() {
    let tmp = tempfile::tempdir().unwrap();
    let _home = TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let mut app = App::new(Some(tmp.path()), false);
    app.apply_onboarding_bootstrap_snapshot(Some(snapshot(
        cockpit_proto::OnboardingStage::Provider,
    )));
    let cmd = *super::slash::slash_command_by_name("setup").expect("setup command");
    app.composer.set("/setup".to_string());
    app.execute_slash(cmd);
    assert!(app.onboarding_shell.is_some());
    assert_ne!(app.dialog.test_page_name(), Some("wizard_menu"));
}

#[test]
fn setup_provider_slash_mounts_provider_search_in_shell() {
    let tmp = tempfile::tempdir().unwrap();
    let _home = TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let mut app = App::new(Some(tmp.path()), false);
    app.apply_onboarding_bootstrap_snapshot(Some(snapshot(
        cockpit_proto::OnboardingStage::Complete,
    )));
    let cmd = *super::slash::slash_command_by_name("setup").expect("setup command");
    app.composer.set("/setup provider".to_string());
    app.execute_slash(cmd);
    assert_eq!(
        app.onboarding_shell
            .as_ref()
            .map(|shell| shell.screen_kind()),
        Some(crate::tui::onboarding::OnboardingScreenKind::ProviderSearch)
    );
}

#[test]
fn setup_security_slash_mounts_embedded_settings_in_shell() {
    let tmp = tempfile::tempdir().unwrap();
    let _home = TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let mut app = App::new(Some(tmp.path()), false);
    app.apply_onboarding_bootstrap_snapshot(Some(snapshot(
        cockpit_proto::OnboardingStage::Complete,
    )));
    let cmd = *super::slash::slash_command_by_name("setup").expect("setup command");
    app.composer.set("/setup security".to_string());
    app.execute_slash(cmd);
    assert!(app.onboarding_shell.is_some());
    assert_eq!(
        app.onboarding_shell
            .as_ref()
            .map(|shell| shell.screen_kind()),
        Some(crate::tui::onboarding::OnboardingScreenKind::EmbeddedSettings)
    );
    assert_eq!(app.dialog.test_page_name(), Some("security"));
}

#[test]
fn skip_setup_launch_disposes_onboarding_projection() {
    let tmp = tempfile::tempdir().unwrap();
    let _home = TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let mut app = App::new(Some(tmp.path()), false);
    app.apply_onboarding_bootstrap_snapshot(Some(snapshot(
        cockpit_proto::OnboardingStage::Provider,
    )));
    app.configure_onboarding_launch(true, false);
    app.open_onboarding_setup(None);
    assert!(app.onboarding_shell.is_none());
    assert!(app.onboarding_snapshot.is_none());
}

#[test]
fn agent_stage_mounts_authoring_not_setup_wizard() {
    let tmp = tempfile::tempdir().unwrap();
    let _home = TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let mut app = App::new(Some(tmp.path()), false);
    app.apply_onboarding_bootstrap_snapshot(Some(snapshot(cockpit_proto::OnboardingStage::Agent)));
    assert!(
        app.onboarding_shell.is_some(),
        "agent stage must present through the onboarding shell"
    );
    assert!(
        app.onboarding_agent_operation_id.is_some(),
        "agent stage must start nested authoring, not the setup-wizard engine"
    );
    assert!(
        !app.dialog.is_active(),
        "agent stage must not mount a settings-dialog wizard"
    );
}

#[test]
fn setup_slash_adapter_does_not_open_legacy_menu() {
    let tmp = tempfile::tempdir().unwrap();
    let _home = TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let mut app = App::new(Some(tmp.path()), false);
    app.apply_onboarding_bootstrap_snapshot(Some(snapshot(
        cockpit_proto::OnboardingStage::Complete,
    )));
    let cmd = *super::slash::slash_command_by_name("setup").expect("setup command");
    app.composer.set("/setup not-a-wizard".to_string());
    app.execute_slash(cmd);
    assert!(
        app.onboarding_shell.is_none(),
        "unknown /setup targets must not mount a shell"
    );
    assert_ne!(app.dialog.test_page_name(), Some("wizard_menu"));
}

#[test]
fn reopen_onboarding_from_deferred_snapshot_uses_provider_search() {
    let tmp = tempfile::tempdir().unwrap();
    let _home = TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let mut app = App::new(Some(tmp.path()), false);
    let mut deferred = snapshot(cockpit_proto::OnboardingStage::Provider);
    deferred.limited_mode = true;
    app.apply_onboarding_bootstrap_snapshot(Some(deferred));
    app.composer.set("resume".to_string());
    assert!(!app.submit_input());
    assert_eq!(
        app.onboarding_shell
            .as_ref()
            .map(|shell| shell.screen_kind()),
        Some(crate::tui::onboarding::OnboardingScreenKind::ProviderSearch)
    );
}

#[test]
fn provider_add_named_route_uses_shell_adapter() {
    let tmp = tempfile::tempdir().unwrap();
    let _home = TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let mut app = App::new(Some(tmp.path()), false);
    app.apply_onboarding_bootstrap_snapshot(Some(snapshot(
        cockpit_proto::OnboardingStage::Complete,
    )));
    app.open_onboarding_setup(Some(cockpit_core::wizard::PROVIDER_WIZARD_ID));
    assert_eq!(
        app.onboarding_shell
            .as_ref()
            .map(|shell| shell.screen_kind()),
        Some(crate::tui::onboarding::OnboardingScreenKind::ProviderSearch),
        "provider add must mount the full-screen provider stage"
    );
    assert_ne!(app.dialog.test_page_name(), Some("wizard_menu"));
}

#[test]
fn force_setup_flag_is_stored_for_bootstrap_reentry() {
    let tmp = tempfile::tempdir().unwrap();
    let _home = TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let mut app = App::new(Some(tmp.path()), false);
    app.configure_onboarding_launch(false, true);
    app.open_onboarding_setup(None);
    assert!(app.onboarding_force);
}

#[test]
fn welcome_fly_in_drives_the_animation_tick() {
    let tmp = tempfile::tempdir().unwrap();
    let _home = TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let mut app = App::new(Some(tmp.path()), false);
    assert!(!app.animation_tick_active());
    app.onboarding_shell = Some(Box::new(crate::tui::onboarding::OnboardingShell::new(
        &snapshot(cockpit_proto::OnboardingStage::Welcome),
        false,
    )));
    assert!(
        app.animation_tick_active(),
        "the welcome fly-in must keep the 100ms animation tick alive instead of stranding at frame 0"
    );
    app.onboarding_shell = Some(Box::new(crate::tui::onboarding::OnboardingShell::new(
        &snapshot(cockpit_proto::OnboardingStage::Welcome),
        true,
    )));
    assert!(
        !app.animation_tick_active(),
        "reduced-motion welcome must not hold the animation tick"
    );
}

fn app_dragging_onboarding_scrollbar(tmp: &std::path::Path) -> App {
    let mut app = App::new(Some(tmp), false);
    let mut shell = crate::tui::onboarding::OnboardingShell::new(
        &snapshot(cockpit_proto::OnboardingStage::Provider),
        false,
    );
    let engine = crate::tui::settings::Dialog::None;
    let mut links = crate::tui::links::LinkRegistry::default();
    crate::tui::golden::render_frame(80, 20, |frame| {
        shell.render(frame, frame.area(), &engine, &mut links);
    });
    let scrollbar = shell.test_provider_scrollbar().expect("provider screen");
    assert!(!scrollbar.is_empty(), "the 80x20 catalog must overflow");
    let down = crossterm::event::MouseEvent {
        kind: crossterm::event::MouseEventKind::Down(crossterm::event::MouseButton::Left),
        column: scrollbar.x,
        row: scrollbar.y,
        modifiers: crossterm::event::KeyModifiers::NONE,
    };
    let mut pointer_engine = crate::tui::settings::Dialog::None;
    shell.handle_mouse(down, &mut pointer_engine);
    assert!(shell.test_pointer_captured());
    app.onboarding_shell = Some(Box::new(shell));
    app
}

fn arm_every_capture(app: &mut App) {
    app.dragging_divider = true;
    app.composer_controls.picker_scroll_drag = true;
    app.handle_mouse(crossterm::event::MouseEvent {
        kind: crossterm::event::MouseEventKind::Moved,
        column: 10,
        row: 5,
        modifiers: crossterm::event::KeyModifiers::NONE,
    });
    assert!(
        app.onboarding_shell
            .as_ref()
            .unwrap()
            .test_pointer()
            .is_some()
    );
    assert!(
        app.onboarding_shell
            .as_ref()
            .unwrap()
            .test_pointer_captured()
    );
}

fn assert_every_capture_ended(app: &App, context: &str) {
    let shell = app.onboarding_shell.as_ref().unwrap();
    assert!(
        !shell.test_pointer_captured(),
        "{context}: onboarding scrollbar drag"
    );
    assert!(!app.dragging_divider, "{context}: divider drag");
    assert!(
        !app.composer_controls.picker_scroll_drag,
        "{context}: composer picker scrollbar drag"
    );
}

#[test]
fn resize_and_focus_loss_end_captures_and_forget_the_pointer_by_their_own_reason() {
    let tmp = tempfile::tempdir().unwrap();
    let _home = TestEnvGuard::isolate_cockpit_home_at(tmp.path());

    // Resize: a view change — the transcript gesture's view generation moves.
    let mut app = app_dragging_onboarding_scrollbar(tmp.path());
    arm_every_capture(&mut app);
    let view = app.mouse_gesture_state.view_generation;
    app.handle_terminal_event(crossterm::event::Event::Resize(100, 30));
    assert_every_capture_ended(&app, "Resize");
    assert!(
        app.onboarding_shell
            .as_ref()
            .unwrap()
            .test_pointer()
            .is_none()
    );
    assert_eq!(
        app.mouse_gesture_state.view_generation,
        view.wrapping_add(1)
    );

    // Focus loss: a cancel — no view change.
    let mut app = app_dragging_onboarding_scrollbar(tmp.path());
    arm_every_capture(&mut app);
    let view = app.mouse_gesture_state.view_generation;
    app.handle_terminal_event(crossterm::event::Event::FocusLost);
    assert_every_capture_ended(&app, "FocusLost");
    assert!(
        app.onboarding_shell
            .as_ref()
            .unwrap()
            .test_pointer()
            .is_none()
    );
    assert_eq!(app.mouse_gesture_state.view_generation, view);
}

#[test]
fn opening_the_daemon_restart_prompt_ends_every_capture_and_takes_hover() {
    let tmp = tempfile::tempdir().unwrap();
    let _home = TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let mut app = app_dragging_onboarding_scrollbar(tmp.path());
    arm_every_capture(&mut app);
    app.open_daemon_restart_prompt();
    assert_every_capture_ended(&app, "daemon restart prompt");
    assert_eq!(
        app.pointer_owner(),
        super::PointerOwner::DaemonRestartPrompt
    );
    app.distribute_pointer_ownership();
    // The shell keeps the reported position but does not own the pointer, so
    // it paints no hover (see onboarding's
    // `an_app_modal_over_the_shell_owns_the_pointer`).
    let shell = app.onboarding_shell.as_ref().unwrap();
    assert!(shell.test_pointer().is_some());
    assert!(!shell.test_pointer_owned());

    app.daemon_restart_prompt = None;
    app.distribute_pointer_ownership();
    assert!(app.onboarding_shell.as_ref().unwrap().test_pointer_owned());
}
