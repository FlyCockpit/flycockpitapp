//! Real-daemon first-run integration tests.
//!
//! `first_run_tests` synthesizes authoritative snapshots to focus the shell
//! reducers. These tests instead drive the *real* in-process daemon end to
//! end: the bootstrap fetch runs `BeginOrReopenOnboarding`, every stage
//! change is a real `ApplyOnboardingTransition` against the real revision
//! CAS, and the profile / model settlements are real `ApplySetupWizard`
//! operations whose receipts the daemon validates before the stage may
//! advance. The provider stage runs the real offline path: the save is a
//! real `apply_provider_mutation`, the validation probe really fails
//! against an unreachable endpoint, and the explicit manual-model key
//! commits the failed-validation checkpoint that the settled advance is
//! validated against.
//!
//! The chain stops at the agent stage's first screen: installing an agent
//! offline requires a bundled agent whose hard model-slot requirements
//! (a host-issued computer-use contract) a manually entered model cannot
//! satisfy, and a live install fetches a pinned third-party source. That
//! boundary is asserted, not papered over with a fixture.
//!
//! The only test-side substitution is the event-loop pump, which drains
//! async actions, ticks the dialog, and services the onboarding shell in
//! the same order as `service_event_loop_wake`.

use super::*;
use cockpit_config::providers::{ConfigDoc, ProvidersConfig};
use cockpit_proto::OnboardingStage;
use cockpit_test_support::TestEnvGuard;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

fn press(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

fn shell_key(app: &mut App, code: KeyCode) -> bool {
    app.handle_onboarding_shell_key(press(code))
}

fn shell_kind(app: &App) -> Option<crate::tui::onboarding::OnboardingScreenKind> {
    app.onboarding_shell
        .as_ref()
        .map(|shell| shell.screen_kind())
}

fn stage(app: &App) -> Option<OnboardingStage> {
    app.onboarding_snapshot
        .as_ref()
        .map(|snapshot| snapshot.stage)
}

fn capability_available(app: &App, id: &str) -> bool {
    app.onboarding_snapshot
        .as_ref()
        .and_then(|snapshot| snapshot.host_capabilities.feature(id))
        .is_some_and(|row| row.state.is_available())
}

/// One event-loop wake: start/apply async actions, apply fetch results,
/// then service the onboarding shell.
fn pump_once(app: &mut App) {
    app.drain_async_actions();
    app.dialog.tick();
    let _ = app.service_onboarding_shell();
}

fn pump_onboarding(app: &mut App, mut ready: impl FnMut(&App) -> bool, context: &str) {
    for _ in 0..900 {
        pump_once(app);
        if ready(app) {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    panic!("onboarding pump timed out waiting for {context}");
}

struct RealDaemonOnboarding {
    _env: TestEnvGuard,
    _daemon: cockpit_core::daemon::InProcessAutoPromoteGuard,
    runtime: tokio::runtime::Runtime,
}

fn real_daemon_onboarding(cwd: &std::path::Path) -> RealDaemonOnboarding {
    let env = TestEnvGuard::isolate_cockpit_home_at(cwd);
    let daemon = cockpit_core::daemon::enable_in_process_auto_promote_with_production_config();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("onboarding daemon test runtime");
    RealDaemonOnboarding {
        _env: env,
        _daemon: daemon,
        runtime,
    }
}

fn seed_workspace_trust(root: &std::path::Path) {
    tokio::runtime::Handle::current().block_on(async {
        let lifecycle = crate::tui::settings::test_lifecycle_client();
        let client = crate::tui::settings::settings_daemon_client(&lifecycle)
            .await
            .expect("onboarding fixture daemon client");
        let project_root = root.display().to_string();
        let expected_config_generation = match client
            .request(cockpit_proto::Request::GetWorkspaceTrust {
                project_root: project_root.clone(),
            })
            .await
            .expect("onboarding fixture trust read transport")
            .expect("onboarding fixture trust read response")
        {
            cockpit_proto::Response::WorkspaceTrust {
                config_generation, ..
            } => config_generation,
            other => panic!("unexpected onboarding fixture trust read: {other:?}"),
        };
        match client
            .request(cockpit_proto::Request::SetWorkspaceTrust {
                project_root,
                mode: cockpit_proto::WorkspaceTrustMode::Trust,
                expected_config_generation,
            })
            .await
            .expect("onboarding fixture trust set transport")
            .expect("onboarding fixture trust set response")
        {
            cockpit_proto::Response::WorkspaceTrustSet { .. } => {}
            other => panic!("unexpected onboarding fixture trust set: {other:?}"),
        }
    });
}

fn real_first_run_app(cwd: &std::path::Path) -> App {
    let mut app = App::new_composed(
        Some(cwd),
        false,
        SessionMode::Code,
        StartupWorkspaceTrust::Decided,
        None,
        crate::tui::settings::test_lifecycle_client(),
    );
    app.start_onboarding_bootstrap_fetch();
    app
}

/// Drive the real first run from the bootstrap fetch to the searchable
/// provider catalog: Welcome key → real advance → profile wizard through
/// the real ApplySetupWizard → real secure-store placement → the Provider
/// stage's catalog.
fn advance_real_first_run_to_provider(app: &mut App) {
    pump_onboarding(
        app,
        |app| shell_kind(app) == Some(crate::tui::onboarding::OnboardingScreenKind::Welcome),
        "the real bootstrap snapshot to open the Welcome shell",
    );

    shell_key(app, KeyCode::Char(' '));
    pump_onboarding(
        app,
        |app| {
            stage(app) == Some(OnboardingStage::Profile)
                && app.dialog.test_page_name()
                    == Some(cockpit_core::wizard::ONBOARDING_PROFILE_WIZARD_ID)
        },
        "the real Welcome→Profile advance",
    );

    // Profile: type a name and save through the real ApplySetupWizard.
    for ch in "Ada".chars() {
        shell_key(app, KeyCode::Char(ch));
    }
    shell_key(app, KeyCode::Enter);
    assert_eq!(
        app.dialog.test_setup_step(),
        Some("profile-save"),
        "the profile wizard must reach its daemon-save action step"
    );
    shell_key(app, KeyCode::Enter);
    pump_onboarding(
        app,
        |app| {
            stage(app) == Some(OnboardingStage::SecureStore)
                && shell_kind(app)
                    == Some(crate::tui::onboarding::OnboardingScreenKind::SecureStore)
        },
        "the real profile settlement and SecureStore advance",
    );
    let global = cockpit_config::dirs::global_config_file().expect("isolated global config path");
    let raw = std::fs::read_to_string(&global).unwrap_or_default();
    assert!(
        raw.contains("Ada"),
        "the profile settlement must publish the name to the global layer: {raw}"
    );

    // Secure store: choose a placement the daemon actually reports as
    // available (keyring availability is host-dependent). Prefer the
    // passphrase-free machine-bound file vault for determinism.
    let keyring = capability_available(app, "secret_store.keyring");
    let file = capability_available(app, "secret_store.file");
    assert!(
        keyring || file,
        "the daemon must expose at least one secure-store placement"
    );
    if file {
        shell_key(app, KeyCode::Down);
        shell_key(app, KeyCode::Down);
    }
    shell_key(app, KeyCode::Enter);
    pump_onboarding(
        app,
        |app| {
            stage(app) == Some(OnboardingStage::Provider)
                && shell_kind(app)
                    == Some(crate::tui::onboarding::OnboardingScreenKind::ProviderSearch)
        },
        "the real secure-store placement to reach the provider catalog",
    );
}

#[test]
fn first_run_settles_stages_against_the_real_daemon_offline() {
    let tmp = tempfile::tempdir().unwrap();
    let fixture = real_daemon_onboarding(tmp.path());
    let _enter = fixture.runtime.enter();
    let cockpit = tmp.path().join(".cockpit");
    std::fs::create_dir_all(&cockpit).unwrap();
    ConfigDoc::load(&cockpit.join("config.json"))
        .unwrap()
        .write(&ProvidersConfig::default())
        .unwrap();
    seed_workspace_trust(tmp.path());

    let mut app = real_first_run_app(tmp.path());
    advance_real_first_run_to_provider(&mut app);

    // Pick the generic OpenAI-compatible template (no vendor network
    // endpoint is contacted) and drive the real add wizard.
    for ch in "compat".chars() {
        shell_key(&mut app, KeyCode::Char(ch));
    }
    shell_key(&mut app, KeyCode::Enter);
    pump_onboarding(
        &mut app,
        |app| {
            app.dialog.is_provider_add() && app.dialog.test_provider_add_step() == Some("wire-api")
        },
        "the seeded provider engine",
    );

    shell_key(&mut app, KeyCode::Enter);
    assert_eq!(app.dialog.test_provider_add_step(), Some("id"));
    for ch in "localtest".chars() {
        shell_key(&mut app, KeyCode::Char(ch));
    }
    shell_key(&mut app, KeyCode::Enter);
    assert_eq!(app.dialog.test_provider_add_step(), Some("url"));
    for ch in "http://127.0.0.1:9/v1".chars() {
        shell_key(&mut app, KeyCode::Char(ch));
    }
    shell_key(&mut app, KeyCode::Enter);
    // Auth method: the env-var row keeps every secret out of the fixture.
    assert_eq!(app.dialog.test_provider_add_step(), Some("auth-method"));
    shell_key(&mut app, KeyCode::Down);
    shell_key(&mut app, KeyCode::Enter);
    assert_eq!(app.dialog.test_provider_add_step(), Some("env-var"));
    // The prefilled variable name is accepted as-is; Enter commits the
    // provider through the real apply_provider_mutation.
    shell_key(&mut app, KeyCode::Enter);

    pump_onboarding(
        &mut app,
        |app| {
            app.dialog.test_provider_add_step() == Some("test-key")
                && !app.dialog.test_provider_add_fetch_pending()
        },
        "the offline validation attempt to finish against the unreachable endpoint",
    );

    // Offline: the save committed and the live probe failed. The explicit
    // manual-model key commits the failed-validation checkpoint (retrying
    // while the post-failure catalog refresh settles).
    let mut committed = false;
    for _ in 0..150 {
        pump_once(&mut app);
        if app.dialog.test_provider_add_step() == Some("done") {
            committed = true;
            break;
        }
        if app.dialog.test_provider_add_step() == Some("test-key") {
            shell_key(&mut app, KeyCode::Char('m'));
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert!(
        committed,
        "manual model entry must commit the offline checkpoint; status: {:?}",
        app.dialog.test_provider_add_status()
    );

    // The settled advance validates against the daemon-recorded terminal
    // provider mutation before the stage may leave Provider.
    pump_onboarding(
        &mut app,
        |app| {
            stage(app) == Some(OnboardingStage::Model)
                && app.dialog.test_page_name()
                    == Some(cockpit_core::wizard::ONBOARDING_MODEL_WIZARD_ID)
        },
        "the settled Provider→Model advance",
    );
    assert!(
        app.config_snapshot
            .providers
            .providers
            .contains_key("localtest"),
        "the daemon-committed provider must be visible in the refreshed config"
    );

    // Model wizard, manual path: the only configured provider, a fresh
    // model id, smart defaults (which skip the advanced steps).
    assert_eq!(app.dialog.test_setup_step(), Some("provider"));
    shell_key(&mut app, KeyCode::Enter);
    assert_eq!(app.dialog.test_setup_step(), Some("model"));
    for ch in "manual-model".chars() {
        shell_key(&mut app, KeyCode::Char(ch));
    }
    shell_key(&mut app, KeyCode::Enter);
    assert_eq!(app.dialog.test_setup_step(), Some("configuration"));
    shell_key(&mut app, KeyCode::Enter);
    assert_eq!(app.dialog.test_setup_step(), Some("model-save"));
    shell_key(&mut app, KeyCode::Enter);

    pump_onboarding(
        &mut app,
        |app| {
            stage(app) == Some(OnboardingStage::Agent)
                && app.dialog.test_page_name()
                    == Some(cockpit_core::wizard::ONBOARDING_AGENT_WIZARD_ID)
        },
        "the settled Model→Agent advance",
    );
    // The real catalog discovery (live fetch with the bundled offline
    // snapshot as fallback) mounts the agent wizard on its first step.
    assert_eq!(app.dialog.test_setup_step(), Some("agent"));
}

#[test]
fn real_daemon_rejects_stale_revision_transitions() {
    let tmp = tempfile::tempdir().unwrap();
    let fixture = real_daemon_onboarding(tmp.path());
    let _enter = fixture.runtime.enter();
    seed_workspace_trust(tmp.path());

    tokio::runtime::Handle::current().block_on(async {
        let lifecycle = crate::tui::settings::test_lifecycle_client();
        let client = crate::tui::settings::settings_daemon_client(&lifecycle)
            .await
            .expect("revision fixture daemon client");
        let begin = match client
            .request(cockpit_proto::Request::BeginOrReopenOnboarding {
                expected_revision: None,
                client_operation_id: uuid::Uuid::new_v4().to_string(),
                reentry: false,
            })
            .await
            .expect("revision fixture begin transport")
            .expect("revision fixture begin response")
        {
            cockpit_proto::Response::OnboardingTransition(result) => result.snapshot,
            other => panic!("unexpected revision fixture begin: {other:?}"),
        };
        assert_eq!(begin.stage, OnboardingStage::Welcome);

        let transition = |expected_revision, run_id, attempt_id| {
            cockpit_proto::Request::ApplyOnboardingTransition {
                run_id,
                attempt_id,
                expected_revision,
                client_operation_id: uuid::Uuid::new_v4().to_string(),
                transition: cockpit_proto::OnboardingTransitionKind::Advance,
                settlement: None,
            }
        };

        // The first advance with the current revision commits.
        match client
            .request(transition(begin.revision, begin.run_id, begin.attempt_id))
            .await
            .expect("revision fixture advance transport")
            .expect("the current revision must advance")
        {
            cockpit_proto::Response::OnboardingTransition(result) => {
                assert_eq!(result.snapshot.stage, OnboardingStage::Profile);
            }
            other => panic!("unexpected revision fixture advance: {other:?}"),
        }

        // Replaying the consumed revision must be rejected by the CAS: a
        // superseded client operation can never advance the checkpoint
        // again. (The TUI's Replace transition policy and error-path
        // refresh exist precisely because this failure mode is real.)
        let replay = client
            .request(transition(begin.revision, begin.run_id, begin.attempt_id))
            .await
            .expect("revision fixture replay transport");
        assert!(
            replay.is_err(),
            "a stale revision must be rejected, got {replay:?}"
        );
    });
}

#[test]
fn concurrent_client_defer_is_followed_by_the_read_only_refresh() {
    let tmp = tempfile::tempdir().unwrap();
    let fixture = real_daemon_onboarding(tmp.path());
    let _enter = fixture.runtime.enter();
    let cockpit = tmp.path().join(".cockpit");
    std::fs::create_dir_all(&cockpit).unwrap();
    ConfigDoc::load(&cockpit.join("config.json"))
        .unwrap()
        .write(&ProvidersConfig::default())
        .unwrap();
    seed_workspace_trust(tmp.path());

    let mut app = real_first_run_app(tmp.path());
    advance_real_first_run_to_provider(&mut app);

    // A second client defers onboarding directly through the daemon.
    tokio::runtime::Handle::current().block_on(async {
        let lifecycle = crate::tui::settings::test_lifecycle_client();
        let client = crate::tui::settings::settings_daemon_client(&lifecycle)
            .await
            .expect("defer fixture daemon client");
        let snapshot = match client
            .request(cockpit_proto::Request::GetOnboardingBootstrapSnapshot)
            .await
            .expect("defer fixture snapshot transport")
            .expect("defer fixture snapshot response")
        {
            cockpit_proto::Response::OnboardingBootstrapSnapshot(Some(snapshot)) => snapshot,
            other => panic!("unexpected defer fixture snapshot: {other:?}"),
        };
        assert_eq!(snapshot.stage, OnboardingStage::Provider);
        match client
            .request(cockpit_proto::Request::ApplyOnboardingTransition {
                run_id: snapshot.run_id,
                attempt_id: snapshot.attempt_id,
                expected_revision: snapshot.revision,
                client_operation_id: uuid::Uuid::new_v4().to_string(),
                transition: cockpit_proto::OnboardingTransitionKind::DeferProvider,
                settlement: None,
            })
            .await
            .expect("defer fixture transition transport")
            .expect("defer fixture transition response")
        {
            cockpit_proto::Response::OnboardingTransition(result) => {
                assert!(result.snapshot.limited_mode);
            }
            other => panic!("unexpected defer fixture transition: {other:?}"),
        }
    });

    // The app under test never receives BeginOrReopen here: the read-only
    // refresh re-reads the authority and the shell follows the deferral.
    app.refresh_onboarding_bootstrap_snapshot();
    pump_onboarding(
        &mut app,
        |app| {
            app.onboarding_snapshot
                .as_ref()
                .is_some_and(|snapshot| snapshot.limited_mode)
                && app.onboarding_shell.is_none()
        },
        "the deferred authority through the read-only refresh",
    );
}
