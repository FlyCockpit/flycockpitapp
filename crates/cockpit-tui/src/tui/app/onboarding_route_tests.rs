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

/// The user's report: a secure-store transport failure showed the specific
/// "Onboarding transition unavailable: …" toast, then the recovery refresh it
/// triggered failed too and replaced it with a generic "Onboarding authority
/// unavailable", hiding the cause. A follow-up refresh failure must keep a
/// still-visible specific error on screen.
#[tokio::test(flavor = "current_thread")]
async fn onboarding_refresh_failure_keeps_the_specific_transition_error_toast() {
    let tmp = tempfile::tempdir().unwrap();
    let _home = TestEnvGuard::isolate_cockpit_home_at_async(tmp.path()).await;
    let mut app = App::new(Some(tmp.path()), false);
    app.apply_onboarding_bootstrap_snapshot(Some(snapshot(
        cockpit_proto::OnboardingStage::SecureStore,
    )));
    let transition_id = crate::tui::async_action::AsyncActionId::from_raw_for_test(901);
    app.pending_startup_onboarding_operations
        .insert(transition_id, "secure-intent-request".into());
    app.apply_async_action_result(crate::tui::async_action::AsyncActionResult {
        id: transition_id,
        kind: crate::tui::async_action::AsyncActionKind::DaemonRpc("onboarding.secure_intent"),
        presentation_stale: false,
        payload: Err(
            "connecting to /home/u/.cockpit/cockpit.sock: No such file or directory (os error 2)"
                .into(),
        ),
    });
    let specific = app
        .toast
        .as_ref()
        .expect("transition error toast")
        .text
        .clone();
    assert!(
        specific.starts_with("Onboarding transition unavailable:")
            && specific.contains("No such file or directory"),
        "{specific}"
    );

    app.apply_async_action_result(crate::tui::async_action::AsyncActionResult {
        id: crate::tui::async_action::AsyncActionId::from_raw_for_test(902),
        kind: crate::tui::async_action::AsyncActionKind::DaemonRpc("onboarding.bootstrap_refresh"),
        presentation_stale: false,
        payload: Err("daemon hello timed out".into()),
    });
    assert_eq!(
        app.toast.as_ref().map(|toast| toast.text.as_str()),
        Some(specific.as_str()),
        "the follow-up refresh failure must not replace the specific cause"
    );

    // Once the specific error has expired, a later refresh failure shows.
    app.toast.as_mut().expect("toast").expires_at = Instant::now() - Duration::from_millis(1);
    app.apply_async_action_result(crate::tui::async_action::AsyncActionResult {
        id: crate::tui::async_action::AsyncActionId::from_raw_for_test(903),
        kind: crate::tui::async_action::AsyncActionKind::DaemonRpc("onboarding.bootstrap_refresh"),
        presentation_stale: false,
        payload: Err("daemon hello timed out".into()),
    });
    assert!(
        app.toast
            .as_ref()
            .is_some_and(|toast| toast.text.starts_with("Onboarding authority unavailable:")),
    );
}

/// The in-flight secure-store submission's handoff progress is mirrored onto
/// the secure-store screen and cleared once the submission settles.
#[tokio::test(flavor = "current_thread")]
async fn secure_store_screen_shows_and_clears_the_submission_progress() {
    let tmp = tempfile::tempdir().unwrap();
    let _home = TestEnvGuard::isolate_cockpit_home_at_async(tmp.path()).await;
    let mut app = App::new(Some(tmp.path()), false);
    app.apply_onboarding_bootstrap_snapshot(Some(snapshot(
        cockpit_proto::OnboardingStage::SecureStore,
    )));
    let progress = super::startup_layout::OnboardingHandoffProgress::default();
    progress.set(super::startup_layout::OnboardingHandoffPhase::PreparingServices);
    app.onboarding_secure_intent_progress = Some((Instant::now(), progress));
    app.sync_onboarding_secure_intent_progress();
    let shown = app
        .onboarding_shell
        .as_ref()
        .and_then(|shell| shell.test_secure_store_progress())
        .expect("progress line on the secure-store screen");
    assert!(
        shown.starts_with("Secure store ready. Preparing Cockpit services…"),
        "{shown}"
    );

    let id = crate::tui::async_action::AsyncActionId::from_raw_for_test(904);
    app.pending_startup_onboarding_operations
        .insert(id, "secure-intent-request".into());
    app.apply_async_action_result(crate::tui::async_action::AsyncActionResult {
        id,
        kind: crate::tui::async_action::AsyncActionKind::DaemonRpc("onboarding.secure_intent"),
        presentation_stale: false,
        payload: Err("secure store rejected".into()),
    });
    assert!(app.onboarding_secure_intent_progress.is_none());
    app.sync_onboarding_secure_intent_progress();
    assert!(
        app.onboarding_shell
            .as_ref()
            .and_then(|shell| shell.test_secure_store_progress())
            .is_none()
    );
}
