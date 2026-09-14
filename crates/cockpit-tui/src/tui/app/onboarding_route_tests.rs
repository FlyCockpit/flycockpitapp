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

fn snapshot_for_named_wizard(wizard_id: &str) -> cockpit_proto::OnboardingBootstrapSnapshot {
    let stage = cockpit_core::wizard::named_setup_wizard_authoritative_stage(wizard_id)
        .unwrap_or(cockpit_proto::OnboardingStage::Complete);
    snapshot(stage)
}

#[test]
fn named_setup_wizards_mount_inside_onboarding_shell() {
    let tmp = tempfile::tempdir().unwrap();
    let _home = TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    for wizard_id in cockpit_core::wizard::named_setup_wizard_ids() {
        let mut app = App::new(Some(tmp.path()), false);
        app.apply_onboarding_bootstrap_snapshot(Some(snapshot_for_named_wizard(wizard_id)));
        app.open_onboarding_setup(Some(wizard_id));
        assert!(
            app.onboarding_shell.is_some(),
            "wizard `{wizard_id}` must mount the full-screen onboarding shell"
        );
        if wizard_id == cockpit_core::wizard::PROVIDER_WIZARD_ID {
            assert_eq!(
                app.onboarding_shell
                    .as_ref()
                    .map(|shell| shell.screen_kind()),
                Some(crate::tui::onboarding::OnboardingScreenKind::ProviderSearch)
            );
        } else if wizard_id == cockpit_core::wizard::ONBOARDING_AGENT_WIZARD_ID {
            // Agent authoring mounts asynchronously after the projection RPC.
        } else {
            assert_eq!(
                app.onboarding_shell
                    .as_ref()
                    .map(|shell| shell.screen_kind()),
                Some(crate::tui::onboarding::OnboardingScreenKind::Engine),
                "wizard `{wizard_id}` must present through the shell engine"
            );
        }
    }
}

#[test]
fn named_setup_wizard_rejects_stale_complete_stage_for_first_run_wizards() {
    let tmp = tempfile::tempdir().unwrap();
    let _home = TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    for wizard_id in [
        cockpit_core::wizard::ONBOARDING_AGENT_WIZARD_ID,
        cockpit_core::wizard::ONBOARDING_MODEL_WIZARD_ID,
        cockpit_core::wizard::ONBOARDING_PROFILE_WIZARD_ID,
        cockpit_core::wizard::ONBOARDING_LIFETIME_WIZARD_ID,
    ] {
        let mut app = App::new(Some(tmp.path()), false);
        app.apply_onboarding_bootstrap_snapshot(Some(snapshot(
            cockpit_proto::OnboardingStage::Complete,
        )));
        app.open_onboarding_setup(Some(wizard_id));
        assert!(
            app.onboarding_shell.is_none(),
            "wizard `{wizard_id}` must not mount against a Complete snapshot"
        );
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
fn setup_security_slash_mounts_engine_inside_shell() {
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
fn onboarding_agent_engine_rejects_legacy_wizard_descriptor() {
    let err = match Dialog::onboarding_wizard_engine(
        cockpit_core::wizard::ONBOARDING_AGENT_WIZARD_ID,
        None,
        None,
    ) {
        Err(err) => err,
        Ok(_) => panic!("agent onboarding must not mount the legacy wizard descriptor"),
    };
    assert!(err.contains("nested agent authoring editor"));
}

#[test]
fn agent_stage_mounts_authoring_not_setup_wizard() {
    let startup = include_str!("startup_layout.rs");
    let mount = startup
        .split("OnboardingStage::Agent =>")
        .nth(1)
        .and_then(|tail| tail.split("OnboardingStage::Lifetime").next())
        .expect("agent stage mount");
    assert!(mount.contains("mount_onboarding_agent_authoring"));
    assert!(!mount.contains("ONBOARDING_AGENT_WIZARD_ID"));
}

#[test]
fn setup_slash_adapter_does_not_open_legacy_menu() {
    let slash = include_str!("slash.rs");
    let run_setup = slash
        .split("fn run_setup")
        .nth(1)
        .and_then(|tail| tail.split("fn run_gitignore_allow").next())
        .expect("run_setup");
    assert!(run_setup.contains("open_onboarding_setup"));
    assert!(!run_setup.contains("Dialog::open_setup("));
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
fn provider_add_cli_dispatch_routes_through_shell_adapter() {
    let lib = include_str!("../../../../../apps/cli/src/lib.rs");
    assert!(
        lib.contains("Command::Provider(crate::cli::ProvidersCommand::Add(args))"),
        "provider add must have an interactive shell adapter"
    );
    assert!(
        lib.contains("cockpit_core::wizard::PROVIDER_WIZARD_ID"),
        "provider add must mount the full-screen provider stage"
    );
    let providers = include_str!("../../../../../apps/cli/src/commands/providers.rs");
    assert!(
        providers.contains("InteractiveOnboardingRequired::provider_add()"),
        "non-interactive provider add must fail before any mutation"
    );
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
