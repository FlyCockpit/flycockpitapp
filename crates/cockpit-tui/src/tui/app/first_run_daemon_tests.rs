//! Real-daemon first-run integration tests.
//!
//! `first_run_tests` synthesizes authoritative snapshots to focus the shell
//! reducers. These tests instead drive the *real* in-process daemon end to
//! end through the production first-run boot: a fresh home boots the locked
//! bootstrap (no vault authority), the bootstrap fetch runs
//! `BeginOrReopenOnboarding` against the locked allowlist, Welcome advances
//! through a real locked `ApplyOnboardingTransition`, the profile wizard's
//! save runs through the locked bootstrap's one scoped config admission and
//! is followed by an ordinary revision-checked Profile advance, and the
//! secure-store choice is the real sensitive intent that
//! materializes a real vault and hands the daemon off to its ready services.
//! From Provider onward every stage change is a real
//! `ApplyOnboardingTransition` against the real revision CAS, and the
//! model settlements are real `ApplySetupWizard` operations and agent
//! settlement is a real `ApplyAuthoredAgentPackage` receipt whose published
//! the daemon validates before the stage may advance. The provider stage
//! runs the real offline path: the save is a real `apply_provider_mutation`,
//! the validation probe really fails against an unreachable endpoint, and
//! the explicit manual-model key commits the failed-validation checkpoint
//! that the settled advance is validated against.
//!
//! Every stage crossing is driven by the shell's own keystroke path. The
//! profile wizard's save is the one config mutation the locked bootstrap
//! admits: the ordered screens put Profile before the secure-store choice
//! (#391), so the settlement RPC would otherwise have no legal moment, and
//! the locked allowlist scopes it to the onboarding profile wizard at the
//! Profile stage (#388 deny-by-default otherwise) under the same
//! publication gates the ready daemon enforces. The profile job waits for the
//! wizard apply, then issues the locked-admitted ordinary Advance; the name is
//! durable in the global config before the vault exists.
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
use std::sync::Arc;

struct InProcessSettingsDaemonEffect;

impl crate::tui::settings::SettingsDaemonEffect for InProcessSettingsDaemonEffect {
    fn request(&self, request: cockpit_proto::Request) -> Result<cockpit_proto::Response, String> {
        let request = async move {
            let lifecycle = crate::tui::settings::test_lifecycle_client();
            let client = crate::tui::settings::settings_daemon_client(&lifecycle)
                .await
                .map_err(|error| error.to_string())?;
            client
                .request(request)
                .await
                .map_err(|error| error.to_string())?
                .map_err(|error| error.to_string())
        };
        tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(request))
    }
}

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
    panic!(
        "onboarding pump timed out waiting for {context}; retry={:?}, snapshot={:?}, shell={}, pending={}, setup_step={:?}, setup_status={:?}",
        app.startup_background.retry,
        app.onboarding_snapshot
            .as_ref()
            .map(|snapshot| (snapshot.stage, snapshot.revision)),
        app.onboarding_shell.is_some(),
        app.pending_startup_onboarding_operations.len(),
        app.dialog.test_setup_step(),
        app.dialog.test_setup_status(),
    );
}

struct RealDaemonOnboarding {
    _env: TestEnvGuard,
    _daemon: cockpit_core::daemon::InProcessAutoPromoteGuard,
    runtime: tokio::runtime::Runtime,
}

fn real_daemon_onboarding(cwd: &std::path::Path) -> RealDaemonOnboarding {
    let env = TestEnvGuard::isolate_cockpit_home_at(cwd);
    // The profile wizard prefills its name field from USER/USERNAME; clear
    // both so the typed "Ada" is exactly the committed name (the guard
    // snapshots and restores them on drop).
    env.remove_var("USER");
    env.remove_var("USERNAME");
    let daemon = cockpit_core::daemon::enable_in_process_auto_promote_production_first_run();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("onboarding daemon test runtime");
    runtime.block_on(async {
        let lifecycle = crate::tui::settings::test_lifecycle_client();
        let resolved = lifecycle
            .resolve_default()
            .await
            .expect("boot production first-run daemon fixture");
        cockpit_client::DaemonClient::connect_endpoint(&resolved.endpoint)
            .await
            .expect("connect production first-run daemon fixture");
    });
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
            computer_use: ComputerUseCapability {
                contract: Some(ComputerUseContract::OpenAiResponses),
                ..ComputerUseCapability::default()
            },
            ..ModelCapabilities::default()
        },
        ..ModelEntry::default()
    });
    doc.write(&providers)
        .expect("seeding catalog capability metadata onto the provider file");
}

fn agent_authoring_phase(app: &App) -> Option<crate::tui::onboarding::agent::Phase> {
    app.onboarding_shell
        .as_ref()
        .and_then(|shell| shell.test_agent_authoring_phase())
}

fn sync_config_generation_after_agent_apply(app: &mut App, generation: u64) {
    app.sync_config_generation_after_authored_agent_apply(generation);
}

fn settle_agent_via_real_daemon_rpc(app: &mut App) {
    use cockpit_core::authoring_draft::{AgentAuthoringDraft, build_package_draft};
    use cockpit_proto::{ApplyAuthoredAgentPackageRequest, AuthoredAgentOnboardingCorrelation};

    pump_onboarding(
        app,
        |app| {
            stage(app) == Some(OnboardingStage::Agent)
                && shell_kind(app)
                    == Some(crate::tui::onboarding::OnboardingScreenKind::AgentAuthoring)
        },
        "the settled Model→Agent advance and agent authoring projection",
    );

    let snapshot = app
        .onboarding_snapshot
        .clone()
        .expect("agent stage snapshot");
    let operation_id = app
        .onboarding_agent_operation_id
        .clone()
        .unwrap_or_else(|| format!("first-run-agent-{}", uuid::Uuid::new_v4()));
    app.onboarding_agent_operation_id = Some(operation_id.clone());

    use crate::tui::settings::SettingsDaemonEffect;
    let effect = InProcessSettingsDaemonEffect;
    let projection = match SettingsDaemonEffect::request(
        &effect,
        cockpit_proto::Request::GetAgentAuthoringProjection,
    ) {
        Ok(cockpit_proto::Response::AgentAuthoringProjection(projection)) => projection,
        Ok(other) => panic!("unexpected agent projection response: {other:?}"),
        Err(error) => panic!("agent projection unavailable: {error}"),
    };
    if let Some(shell) = app.onboarding_shell.as_mut() {
        shell.present_agent_authoring(projection.clone(), operation_id.clone());
    }

    let draft = AgentAuthoringDraft::from_projection(&projection);
    for (index, _) in draft
        .pending_trust_route_indices(&projection)
        .into_iter()
        .enumerate()
    {
        let _ = index;
        // Real routes that require explicit trust confirmation must be acknowledged
        // before the canonical package builder will validate.
    }
    let mut draft = draft;
    for index in draft.pending_trust_route_indices(&projection) {
        draft.trust_confirmations[index] = true;
    }
    let package = build_package_draft(&projection, &draft).unwrap_or_else(|error| {
        panic!("canonical package construction failed: {error}");
    });
    let correlation = AuthoredAgentOnboardingCorrelation {
        run_id: snapshot.run_id,
        attempt_id: snapshot.attempt_id,
        stage_revision: snapshot.revision,
    };
    let preview_request = ApplyAuthoredAgentPackageRequest {
        client_operation_id: format!("{operation_id}-preview"),
        expected_policy_revision: package.policy_revision.clone(),
        package: package.clone(),
        onboarding: Some(correlation.clone()),
        validate_only: true,
    };
    let preview = match SettingsDaemonEffect::request(
        &effect,
        cockpit_proto::Request::ApplyAuthoredAgentPackage(preview_request),
    ) {
        Ok(cockpit_proto::Response::AuthoredAgentPackage(outcome)) => outcome,
        Ok(other) => panic!("unexpected preview response: {other:?}"),
        Err(error) => panic!("preview failed: {error}"),
    };
    if let Some(shell) = app.onboarding_shell.as_mut() {
        shell.apply_agent_authoring_outcome(preview);
    }
    let apply_request = ApplyAuthoredAgentPackageRequest {
        client_operation_id: operation_id,
        expected_policy_revision: package.policy_revision.clone(),
        package,
        onboarding: Some(correlation),
        validate_only: false,
    };
    let apply = match SettingsDaemonEffect::request(
        &effect,
        cockpit_proto::Request::ApplyAuthoredAgentPackage(apply_request),
    ) {
        Ok(cockpit_proto::Response::AuthoredAgentPackage(outcome)) => outcome,
        Ok(other) => panic!("unexpected apply response: {other:?}"),
        Err(error) => panic!("apply failed: {error}"),
    };
    let generation = match &apply {
        cockpit_proto::ApplyAuthoredAgentPackageOutcome::Receipt(receipt)
            if receipt.status == cockpit_proto::AuthoredAgentReceiptStatus::Committed =>
        {
            receipt.result_config_generation
        }
        other => panic!("apply did not commit: {other:?}"),
    };
    if let Some(shell) = app.onboarding_shell.as_mut() {
        shell.apply_agent_authoring_outcome(apply);
    }
    sync_config_generation_after_agent_apply(app, generation);
    pump_onboarding(
        app,
        |app| agent_authoring_phase(app) == Some(crate::tui::onboarding::agent::Phase::Success),
        "authored-agent receipt applied to the nested editor",
    );
    pump_onboarding(
        app,
        |app| stage(app) == Some(OnboardingStage::Lifetime),
        "agent stage settlement advancing to lifetime",
    );
}

fn complete_real_first_run_lifetime(app: &mut App, persistent_background_agents: bool) {
    pump_onboarding(
        app,
        |app| {
            stage(app) == Some(OnboardingStage::Lifetime)
                && shell_kind(app) == Some(crate::tui::onboarding::OnboardingScreenKind::Lifetime)
        },
        "the settled Agent→Lifetime advance through the real installation",
    );

    if !persistent_background_agents {
        shell_key(app, KeyCode::Down);
    }
    shell_key(app, KeyCode::Enter);
    pump_onboarding(
        app,
        |app| {
            stage(app) == Some(OnboardingStage::Complete)
                && app
                    .onboarding_shell
                    .as_ref()
                    .is_some_and(|shell| shell.screen_is_complete())
        },
        "the authoritative Complete revision to present the summary",
    );

    let global = cockpit_config::dirs::global_config_file().expect("isolated global config path");
    let cfg = cockpit_config::extended::ExtendedConfigDoc::load(&global)
        .expect("lifetime settlement wrote global config")
        .config();
    assert_eq!(
        cfg.daemon.background_agents, persistent_background_agents,
        "lifetime settlement must persist the explicit background_agents choice"
    );
}

/// Drive the real first run from the bootstrap fetch to the searchable
/// provider catalog: Welcome key → real locked advance → the profile stage
/// (its wizard save is admitted by the locked bootstrap's one scoped config
/// admission, followed by an ordinary stage advance in the same job) → the real
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
                && shell_kind(app) == Some(crate::tui::onboarding::OnboardingScreenKind::Profile)
        },
        "the real locked Welcome→Profile advance",
    );

    // Profile: type a name and submit the wizard's daemon save. The daemon
    // is still locked — no vault authority exists yet — and the profile
    // save is the one config mutation the locked bootstrap admits (scoped to
    // this wizard at this stage). The same async job waits for that apply and
    // then issues an ordinary locked-admitted Advance.
    for ch in "Ada".chars() {
        shell_key(app, KeyCode::Char(ch));
    }
    shell_key(app, KeyCode::Enter);
    pump_onboarding(
        app,
        |app| {
            stage(app) == Some(OnboardingStage::SecureStore)
                && shell_kind(app)
                    == Some(crate::tui::onboarding::OnboardingScreenKind::SecureStore)
        },
        "the locked profile save and ordinary Advance to cross Profile",
    );
    let profile_config_path = cockpit_config::dirs::global_config_dir()
        .expect("isolated global config dir")
        .join(cockpit_config::dirs::CONFIG_FILE);
    let profile_config = cockpit_config::extended::ExtendedConfigDoc::load(&profile_config_path)
        .expect("the locked profile settlement wrote the global config")
        .config();
    assert_eq!(
        profile_config.name.as_deref(),
        Some("Ada"),
        "the locked-admitted profile save must publish the name before the vault exists"
    );

    // Escape on the secure-store choice offers Back (AC5). The crossing is a
    // real locked transition back to Profile; the return trip re-saves the
    // name through the same admitted settlement and advances again, proving
    // both directions of the pre-vault stage are completable by keystroke.
    shell_key(app, KeyCode::Esc);
    shell_key(app, KeyCode::Enter);
    pump_onboarding(
        app,
        |app| {
            stage(app) == Some(OnboardingStage::Profile)
                && shell_kind(app) == Some(crate::tui::onboarding::OnboardingScreenKind::Profile)
        },
        "the locked Back transition from the secure-store choice to remount the profile screen",
    );
    for ch in "Ada".chars() {
        shell_key(app, KeyCode::Char(ch));
    }
    shell_key(app, KeyCode::Enter);
    pump_onboarding(
        app,
        |app| {
            stage(app) == Some(OnboardingStage::SecureStore)
                && shell_kind(app)
                    == Some(crate::tui::onboarding::OnboardingScreenKind::SecureStore)
        },
        "the repeated profile save and ordinary Advance to return to the secure-store choice",
    );

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

fn advance_real_first_run_from_provider_search_to_agent(app: &mut App) {
    for ch in "compat".chars() {
        shell_key(app, KeyCode::Char(ch));
    }
    shell_key(app, KeyCode::Down);
    shell_key(app, KeyCode::Enter);
    pump_onboarding(
        app,
        |app| {
            app.dialog.is_provider_add() && app.dialog.test_provider_add_step() == Some("wire-api")
        },
        "the seeded provider engine",
    );

    shell_key(app, KeyCode::Enter);
    assert_eq!(app.dialog.test_provider_add_step(), Some("id"));
    for ch in "localtest".chars() {
        shell_key(app, KeyCode::Char(ch));
    }
    shell_key(app, KeyCode::Enter);
    assert_eq!(app.dialog.test_provider_add_step(), Some("url"));
    for ch in "http://127.0.0.1:9/v1".chars() {
        shell_key(app, KeyCode::Char(ch));
    }
    shell_key(app, KeyCode::Enter);
    assert_eq!(app.dialog.test_provider_add_step(), Some("auth-method"));
    shell_key(app, KeyCode::Down);
    shell_key(app, KeyCode::Enter);
    assert_eq!(app.dialog.test_provider_add_step(), Some("env-var"));
    shell_key(app, KeyCode::Enter);

    pump_onboarding(
        app,
        |app| {
            app.dialog.test_provider_add_step() == Some("test-key")
                && !app.dialog.test_provider_add_fetch_pending()
        },
        "the offline validation attempt to finish against the unreachable endpoint",
    );

    let mut committed = false;
    for _ in 0..150 {
        pump_once(app);
        if app.dialog.test_provider_add_step() == Some("done") {
            committed = true;
            break;
        }
        if app.dialog.test_provider_add_step() == Some("test-key") {
            shell_key(app, KeyCode::Char('m'));
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert!(
        committed,
        "manual model entry must commit the offline checkpoint; status: {:?}",
        app.dialog.test_provider_add_status()
    );

    pump_onboarding(
        app,
        |app| {
            stage(app) == Some(OnboardingStage::Model)
                && shell_kind(app) == Some(crate::tui::onboarding::OnboardingScreenKind::Model)
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

    seed_computer_use_catalog_capabilities();

    for ch in "manual-model".chars() {
        shell_key(app, KeyCode::Char(ch));
    }
    for expected in crate::tui::onboarding::ModelPhase::ALL {
        assert_eq!(
            app.onboarding_shell
                .as_ref()
                .and_then(|shell| shell.model_phase()),
            Some(expected),
            "real first run must visit every native Model sub-step"
        );
        shell_key(app, KeyCode::Enter);
    }
    pump_onboarding(
        app,
        |app| {
            stage(app) == Some(OnboardingStage::Agent)
                && shell_kind(app)
                    == Some(crate::tui::onboarding::OnboardingScreenKind::AgentAuthoring)
        },
        "the settled Model→Agent advance through the real model wizard",
    );
    let global = ConfigDoc::load(
        &cockpit_config::dirs::global_config_file().expect("isolated global config path"),
    )
    .expect("native model settlement wrote global config")
    .providers();
    let active = global
        .active_model
        .expect("native model settlement selected a default model");
    assert_eq!(active.provider, "localtest");
    assert_eq!(active.model, "manual-model");

    settle_agent_via_real_daemon_rpc(app);
}

#[test]
fn real_daemon_profile_continue_advances_to_secure_store_and_persists_name() {
    let tmp = cockpit_test_support::latency_isolated_tempdir();
    let fixture = real_daemon_onboarding(tmp.path());
    let _enter = fixture.runtime.enter();
    crate::tui::settings::with_settings_daemon_effect(
        Arc::new(InProcessSettingsDaemonEffect),
        || {
            let cockpit = tmp.path().join(".cockpit");
            std::fs::create_dir_all(&cockpit).unwrap();
            ConfigDoc::load(&cockpit.join("config.json"))
                .unwrap()
                .write(&ProvidersConfig::default())
                .unwrap();

            let mut app = real_first_run_app(tmp.path());
            pump_onboarding(
                &mut app,
                |app| {
                    shell_kind(app) == Some(crate::tui::onboarding::OnboardingScreenKind::Welcome)
                },
                "the locked bootstrap snapshot to open Welcome",
            );
            shell_key(&mut app, KeyCode::Enter);
            pump_onboarding(
                &mut app,
                |app| {
                    stage(app) == Some(OnboardingStage::Profile)
                        && shell_kind(app)
                            == Some(crate::tui::onboarding::OnboardingScreenKind::Profile)
                },
                "the ordinary Welcome advance to Profile",
            );
            for ch in "Ada".chars() {
                shell_key(&mut app, KeyCode::Char(ch));
            }
            shell_key(&mut app, KeyCode::Enter);
            pump_onboarding(
                &mut app,
                |app| {
                    stage(app) == Some(OnboardingStage::SecureStore)
                        && shell_kind(app)
                            == Some(crate::tui::onboarding::OnboardingScreenKind::SecureStore)
                },
                "the profile wizard apply followed by an ordinary Profile advance",
            );

            let config = cockpit_config::extended::ExtendedConfigDoc::load(
                &cockpit_config::dirs::global_config_file().expect("isolated global config path"),
            )
            .expect("profile Continue wrote the global config")
            .config();
            assert_eq!(config.name.as_deref(), Some("Ada"));
        },
    );
}

#[test]
fn first_run_settles_stages_against_the_real_daemon_offline() {
    let tmp = cockpit_test_support::latency_isolated_tempdir();
    let fixture = real_daemon_onboarding(tmp.path());
    let _enter = fixture.runtime.enter();
    crate::tui::settings::with_settings_daemon_effect(
        Arc::new(InProcessSettingsDaemonEffect),
        || {
            let cockpit = tmp.path().join(".cockpit");
            std::fs::create_dir_all(&cockpit).unwrap();
            ConfigDoc::load(&cockpit.join("config.json"))
                .unwrap()
                .write(&ProvidersConfig::default())
                .unwrap();

            let mut app = real_first_run_app(tmp.path());
            advance_real_first_run_to_provider(&mut app, tmp.path());
            advance_real_first_run_from_provider_search_to_agent(&mut app);

            complete_real_first_run_lifetime(&mut app, true);

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
        },
    );
}

#[test]
fn real_daemon_first_run_ephemeral_lifetime_persists_background_agents_false() {
    let tmp = cockpit_test_support::latency_isolated_tempdir();
    let fixture = real_daemon_onboarding(tmp.path());
    let _enter = fixture.runtime.enter();
    crate::tui::settings::with_settings_daemon_effect(
        Arc::new(InProcessSettingsDaemonEffect),
        || {
            let cockpit = tmp.path().join(".cockpit");
            std::fs::create_dir_all(&cockpit).unwrap();
            ConfigDoc::load(&cockpit.join("config.json"))
                .unwrap()
                .write(&ProvidersConfig::default())
                .unwrap();

            let mut app = real_first_run_app(tmp.path());
            advance_real_first_run_to_provider(&mut app, tmp.path());
            advance_real_first_run_from_provider_search_to_agent(&mut app);
            complete_real_first_run_lifetime(&mut app, false);
        },
    );
}

#[test]
fn real_daemon_rejects_stale_revision_transitions() {
    let tmp = cockpit_test_support::latency_isolated_tempdir();
    let fixture = real_daemon_onboarding(tmp.path());
    let _enter = fixture.runtime.enter();

    tokio::runtime::Handle::current().block_on(async {
        let lifecycle = crate::tui::settings::test_lifecycle_client();
        let client = crate::tui::settings::settings_daemon_client(&lifecycle)
            .await
            .expect("revision fixture daemon client");
        let begin = match client
            .request(cockpit_proto::Request::BeginOrReopenOnboarding(
                cockpit_proto::BeginOrReopenOnboarding {
                    expected_revision: None,
                    client_operation_id: uuid::Uuid::new_v4().to_string(),
                    reentry: false,
                },
            ))
            .await
            .expect("revision fixture begin transport")
            .expect("revision fixture begin response")
        {
            cockpit_proto::Response::OnboardingTransition(result) => result.snapshot,
            other => panic!("unexpected revision fixture begin: {other:?}"),
        };
        assert_eq!(begin.stage, OnboardingStage::Welcome);

        let transition = |expected_revision, run_id, attempt_id| {
            cockpit_proto::Request::ApplyOnboardingTransition(
                cockpit_proto::ApplyOnboardingTransition {
                    run_id,
                    attempt_id,
                    expected_revision,
                    client_operation_id: uuid::Uuid::new_v4().to_string(),
                    transition: cockpit_proto::OnboardingTransitionKind::Advance,
                    settlement: None,
                },
            )
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
    let tmp = cockpit_test_support::latency_isolated_tempdir();
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
            .request(cockpit_proto::Request::ApplyOnboardingTransition(
                cockpit_proto::ApplyOnboardingTransition {
                    run_id: snapshot.run_id,
                    attempt_id: snapshot.attempt_id,
                    expected_revision: snapshot.revision,
                    client_operation_id: uuid::Uuid::new_v4().to_string(),
                    transition: cockpit_proto::OnboardingTransitionKind::DeferProvider,
                    settlement: None,
                },
            ))
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
