//! Real-daemon first-run integration tests.
//!
//! `first_run_tests` synthesizes authoritative snapshots to focus the shell
//! reducers. These tests instead drive the *real* in-process daemon end to
//! end through the production first-run boot: a fresh home boots the locked
//! bootstrap (no vault authority), the bootstrap fetch runs
//! `BeginOrReopenOnboarding` against the locked allowlist, Welcome advances
//! through a real locked `ApplyOnboardingTransition`, and the secure-store
//! choice is the real sensitive intent that materializes a real vault and
//! hands the daemon off to its ready services. From Provider onward every
//! stage change is a real `ApplyOnboardingTransition` against the real
//! revision CAS, and the model / agent / lifetime settlements are real
//! `ApplySetupWizard` operations whose receipts — including the published
//! config generation — the daemon validates before the stage may advance.
//! The provider stage runs the real offline path: the save is a real
//! `apply_provider_mutation`, the validation probe really fails against an
//! unreachable endpoint, and the explicit manual-model key commits the
//! failed-validation checkpoint that the settled advance is validated
//! against.
//!
//! One stage crossing is driven outside the keystroke path, deliberately.
//! The profile wizard's save is an ordinary config mutation, and the locked
//! bootstrap allowlist (#388) rejects every ordinary config mutation until a
//! vault exists — the test proves that denial, then commits the
//! Profile→SecureStore crossing through the same locked-admitted
//! `ApplyOnboardingTransition` the shell's settled advance issues, and the
//! app follows the committed authority through the read-only refresh
//! exactly as it follows the daemon-global broadcast on the ready path.
//! Workspace trust is likewise a ready-service RPC, so the fixture seeds it
//! only after the secure-store handoff.
//!
//! The agent settlement crosses the real bundled-catalog install (catalog
//! resolution, installation service, publication journal, default
//! selection). One fixture substitution is deliberate: the provider and
//! validation flows cannot mint computer-use contract evidence by design
//! (a configured concrete route must carry a host-issued contract before an
//! authored hard requirement can select it), so the test seeds that catalog
//! capability metadata onto the committed provider's model — the same way
//! `first_run_tests` seeds provider configs — and every later authority
//! operation (model apply, agent apply, settlement fences) runs for real.
//!
//! The only test-side substitution beyond that seed is the event-loop pump,
//! which drains async actions, ticks the dialog, and services the onboarding
//! shell in the same order as `service_event_loop_wake`.

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
    let daemon = cockpit_core::daemon::enable_in_process_auto_promote_production_first_run();
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

/// Seed the committed provider's manual model with the catalog capability
/// metadata a real computer-use-capable catalog entry carries (context
/// window, tool calling, a host-issued computer-use contract, and the
/// frontier agent's remote locality). The provider/validation flows
/// deliberately cannot mint contract evidence themselves, so this stands in
/// for that authority the same way the other fixtures seed provider config;
/// every later daemon operation still runs for real.
fn seed_computer_use_catalog_capabilities() {
    use cockpit_config::providers::{
        CapabilityStatus, ComputerUseCapability, ComputerUseContract, ModelCapabilities,
        ModelEntry, ModelLocation,
    };
    let global = cockpit_config::dirs::global_config_file().expect("isolated global config path");
    let model_target =
        cockpit_config::providers::provider_file_path_for_config(&global, "localtest")
            .expect("committed provider file path");
    let mut doc = ConfigDoc::load(&model_target).expect("committed provider config file");
    let mut providers = doc.providers();
    let entry = providers
        .providers
        .get_mut("localtest")
        .expect("the committed provider owns its model file");
    assert!(
        entry.models.iter().all(|model| model.id != "manual-model"),
        "the fixture seeds catalog capability metadata onto a fresh model entry"
    );
    entry.models.push(ModelEntry {
        id: "manual-model".to_string(),
        manual: true,
        location: Some(ModelLocation::Remote),
        capabilities: ModelCapabilities {
            context_tokens: Some(200_000),
            tool_calling: CapabilityStatus::Supported,
            computer_use: Some(ComputerUseCapability {
                contract: Some(ComputerUseContract::OpenAiResponses),
                ..ComputerUseCapability::default()
            }),
            ..ModelCapabilities::default()
        },
        ..ModelEntry::default()
    });
    doc.write(&providers)
        .expect("seeding catalog capability metadata onto the provider file");
}

/// Commit the Profile stage through the same locked-admitted
/// `ApplyOnboardingTransition` the shell's settled advance issues, then have
/// the app follow the committed authority through the read-only refresh.
///
/// The profile wizard's save is an ordinary config mutation, and the locked
/// bootstrap allowlist (#388) rejects those until a vault exists — callers
/// must first prove the wizard's save was denied, so the stage crossing is
/// committed the way the locked allowlist intends: a plain revision-CAS
/// advance, exactly the request `request_onboarding_transition` sends once
/// the wizard settles.
fn commit_locked_profile_stage(app: &mut App) {
    let snapshot = app
        .onboarding_snapshot
        .clone()
        .expect("the locked bootstrap snapshot at the Profile stage");
    assert_eq!(snapshot.stage, OnboardingStage::Profile);
    let run_id = snapshot.run_id;
    let attempt_id = snapshot.attempt_id;
    let expected_revision = snapshot.revision;
    tokio::runtime::Handle::current().block_on(async {
        let lifecycle = crate::tui::settings::test_lifecycle_client();
        let client = crate::tui::settings::settings_daemon_client(&lifecycle)
            .await
            .expect("locked profile crossing daemon client");
        match client
            .request(cockpit_proto::Request::ApplyOnboardingTransition {
                run_id,
                attempt_id,
                expected_revision,
                client_operation_id: uuid::Uuid::new_v4().to_string(),
                transition: cockpit_proto::OnboardingTransitionKind::Advance,
                settlement: None,
            })
            .await
            .expect("locked profile crossing transport")
            .expect("the locked-admitted Profile→SecureStore advance")
        {
            cockpit_proto::Response::OnboardingTransition(result) => {
                assert_eq!(result.snapshot.stage, OnboardingStage::SecureStore);
            }
            other => panic!("unexpected locked profile crossing: {other:?}"),
        }
    });
    // Follow the committed authority exactly as the live event loop follows
    // the daemon-global broadcast: the read-only refresh, never a reopen.
    app.refresh_onboarding_bootstrap_snapshot();
    pump_onboarding(
        app,
        |app| {
            stage(app) == Some(OnboardingStage::SecureStore)
                && shell_kind(app)
                    == Some(crate::tui::onboarding::OnboardingScreenKind::SecureStore)
        },
        "the committed Profile→SecureStore crossing through the read-only refresh",
    );
}

/// Drive the real first run from the bootstrap fetch to the searchable
/// provider catalog: Welcome key → real locked advance → the profile stage
/// (its wizard save denied by the locked allowlist, the crossing committed
/// through the same locked transition the settled advance issues) → the real
/// sensitive secure-store intent that materializes the vault and hands the
/// daemon off to ready services → the Provider stage's catalog.
fn advance_real_first_run_to_provider(app: &mut App, root: &std::path::Path) {
    pump_onboarding(
        app,
        |app| shell_kind(app) == Some(crate::tui::onboarding::OnboardingScreenKind::Welcome),
        "the locked bootstrap snapshot to open the Welcome shell",
    );

    shell_key(app, KeyCode::Char(' '));
    pump_onboarding(
        app,
        |app| {
            stage(app) == Some(OnboardingStage::Profile)
                && app.dialog.test_page_name()
                    == Some(cockpit_core::wizard::ONBOARDING_PROFILE_WIZARD_ID)
        },
        "the real locked Welcome→Profile advance",
    );

    // Profile: type a name and submit the wizard's daemon save. The daemon
    // is still locked — no vault authority exists yet — so the ordinary
    // config mutation is denied and the wizard cannot settle. That denial is
    // the designed locked-bootstrap behavior; the stage crossing below
    // commits through the locked-admitted transition instead.
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
            app.dialog
                .test_setup_wizard_status()
                .is_some_and(|status| status.contains("bootstrap is locked"))
        },
        "the locked daemon to deny the profile wizard's ordinary config mutation",
    );
    assert!(
        !app.dialog
            .setup_wizard_is_complete(cockpit_core::wizard::ONBOARDING_PROFILE_WIZARD_ID),
        "a denied wizard save must never settle the profile stage"
    );
    assert_eq!(
        stage(app),
        Some(OnboardingStage::Profile),
        "the authority must still hold the Profile stage after the denied save"
    );
    commit_locked_profile_stage(app);

    // Secure store: choose a placement the daemon actually reports as
    // available (keyring availability is host-dependent). Prefer the
    // passphrase-free machine-bound file vault for determinism. The
    // submission is the real sensitive intent: the locked daemon
    // materializes a real vault for the chosen placement and hands itself
    // off to its ready services before replying.
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
        "the real secure-store placement to materialize the vault and reach the provider catalog",
    );

    // The vault exists and the daemon is ready: ordinary RPCs (workspace
    // trust, provider mutations, wizard applies) are servicable from here.
    seed_workspace_trust(root);
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

    let mut app = real_first_run_app(tmp.path());
    advance_real_first_run_to_provider(&mut app, tmp.path());

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

    // Seed the committed provider's model with the catalog capability
    // metadata (context window, tool calling, host-issued computer-use
    // contract) that the offline provider flow cannot mint itself; the
    // model and agent settlements below still run entirely through the
    // daemon's real ApplySetupWizard + settlement fences.
    seed_computer_use_catalog_capabilities();

    // Model wizard, manual path: the only configured provider, a fresh
    // model id, smart defaults (which imply the default-model commitment).
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

    // A bundled catalog agent whose primary slot the seeded model satisfies
    // is offered; third-party requires a pinned network fetch, so it can
    // never be the only offline option once a contract-capable model exists.
    let agent_options = app.dialog.test_setup_step_option_ids();
    let agent_index = agent_options
        .iter()
        .position(|id| id != "third-party")
        .expect("a bundled catalog agent compatible with the seeded model");
    for _ in 0..agent_index {
        shell_key(&mut app, KeyCode::Down);
    }
    shell_key(&mut app, KeyCode::Enter);
    // Model trust (untrusted), the compatible default model, explicit trust
    // confirmation, author tool tiers, the monty-package notice, no image
    // sidecar, and make-default so the settlement's default installation
    // lands.
    assert_eq!(app.dialog.test_setup_step(), Some("model-trust"));
    shell_key(&mut app, KeyCode::Enter);
    assert_eq!(app.dialog.test_setup_step(), Some("default-model"));
    assert_eq!(app.dialog.test_setup_step_options(), 1);
    shell_key(&mut app, KeyCode::Enter);
    assert_eq!(app.dialog.test_setup_step(), Some("model-trust-confirm"));
    shell_key(&mut app, KeyCode::Char('y'));
    assert_eq!(app.dialog.test_setup_step(), Some("tool-configuration"));
    shell_key(&mut app, KeyCode::Enter);
    assert_eq!(app.dialog.test_setup_step(), Some("monty-packages"));
    shell_key(&mut app, KeyCode::Enter);
    assert_eq!(app.dialog.test_setup_step(), Some("sidecar"));
    shell_key(&mut app, KeyCode::Enter);
    assert_eq!(app.dialog.test_setup_step(), Some("make-default"));
    shell_key(&mut app, KeyCode::Char('y'));
    assert_eq!(app.dialog.test_setup_step(), Some("agent-install"));
    shell_key(&mut app, KeyCode::Enter);

    // The real agent apply: bundled catalog resolution, the installation
    // service, the publication journal, and the settlement fence that
    // proves the receipt's published generation advances the stage.
    pump_onboarding(
        &mut app,
        |app| {
            stage(app) == Some(OnboardingStage::Lifetime)
                && app.dialog.test_page_name()
                    == Some(cockpit_core::wizard::ONBOARDING_LIFETIME_WIZARD_ID)
        },
        "the settled Agent→Lifetime advance through the real installation",
    );

    // Lifetime: commit an explicit choice through the real apply; the
    // terminal Complete transition is requested once the stage settles.
    assert_eq!(app.dialog.test_setup_step(), Some("background-agents"));
    shell_key(&mut app, KeyCode::Enter);
    assert_eq!(app.dialog.test_setup_step(), Some("lifetime-save"));
    shell_key(&mut app, KeyCode::Enter);
    pump_onboarding(
        &mut app,
        |app| {
            stage(app) == Some(OnboardingStage::Complete)
                && app
                    .onboarding_shell
                    .as_ref()
                    .is_some_and(|shell| shell.screen_is_complete())
        },
        "the authoritative Complete revision to present the summary",
    );

    // "Start coding" is a local close: the terminal transition committed,
    // so the summary's action just closes the shell behind the occupancy
    // fence.
    shell_key(&mut app, KeyCode::Enter);
    assert!(app.onboarding_shell.is_none());
    assert!(app.onboarding_dismissed);

    // Ready session: a fresh launch at the completed authority never opens
    // the onboarding surface and lands on the ordinary composer.
    let mut ready = real_first_run_app(tmp.path());
    pump_onboarding(
        &mut ready,
        |app| {
            app.onboarding_snapshot
                .as_ref()
                .is_some_and(|snapshot| snapshot.stage == OnboardingStage::Complete)
                && app.onboarding_shell.is_none()
                && !app.dialog.is_active()
        },
        "a fresh launch at the completed authority to reach the ready session",
    );
}

#[test]
fn real_daemon_rejects_stale_revision_transitions() {
    let tmp = tempfile::tempdir().unwrap();
    let fixture = real_daemon_onboarding(tmp.path());
    let _enter = fixture.runtime.enter();

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

    let mut app = real_first_run_app(tmp.path());
    advance_real_first_run_to_provider(&mut app, tmp.path());

    // A second client defers onboarding directly through the daemon.
    let deferred_authority = tokio::runtime::Handle::current().block_on(async {
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
                (
                    result.snapshot.run_id,
                    result.snapshot.attempt_id,
                    result.snapshot.revision,
                )
            }
            other => panic!("unexpected defer fixture transition: {other:?}"),
        }
    });

    // The app under test never receives BeginOrReopen here: it follows the
    // daemon-global OnboardingBootstrap broadcast exactly as the live event
    // loop would (proto event → turn event → the read-only refresh), and
    // the shell then follows the deferral.
    let (run_id, attempt_id, revision) = deferred_authority;
    let broadcast =
        cockpit_proto::Event::OnboardingBootstrap(cockpit_proto::OnboardingBootstrapEvent {
            run_id,
            attempt_id,
            revision,
            state: cockpit_proto::OnboardingBootstrapState::Ready,
        });
    let turn_event = crate::tui::agent_runner::proto_event_to_turn_event(broadcast)
        .expect("the daemon-global onboarding broadcast maps to the refresh turn event");
    app.apply_event(turn_event);
    pump_onboarding(
        &mut app,
        |app| {
            app.onboarding_snapshot
                .as_ref()
                .is_some_and(|snapshot| snapshot.limited_mode)
                && app.onboarding_shell.is_none()
        },
        "the deferred authority through the broadcast-driven refresh",
    );
}
