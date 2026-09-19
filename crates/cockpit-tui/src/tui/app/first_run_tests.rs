//! Full-screen onboarding shell integration tests.
//!
//! These drive the real `App` surface: shell keys route through
//! `handle_onboarding_shell_key`, stage engines are the embedded settings
//! dialogs, and stage changes are simulated by applying the authoritative
//! daemon snapshot (the transition RPC itself is a background async action,
//! exactly as in production).

use super::*;
use crate::tui::agent_runner::AgentRunner;
use cockpit_config::providers::{ConfigDoc, ModelEntry, ProviderEntry, ProvidersConfig};
use cockpit_proto::OnboardingStage;
use cockpit_test_support::TestEnvGuard;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::Terminal;
use ratatui::backend::TestBackend;
use tokio::sync::mpsc;

fn write_config(cwd: &std::path::Path, cfg: &ProvidersConfig) {
    let cockpit = cwd.join(".cockpit");
    std::fs::create_dir_all(&cockpit).unwrap();
    write_providers_at(&cockpit.join("config.json"), cfg);
}

fn write_global_config(cfg: &ProvidersConfig) {
    let path = cockpit_config::dirs::global_config_file().unwrap();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    write_providers_at(&path, cfg);
}

fn write_providers_at(path: &std::path::Path, cfg: &ProvidersConfig) {
    let mut doc = ConfigDoc::load(path).unwrap();
    doc.write(cfg).unwrap();
    // `active_model` is layer-wide default policy: an ordinary provider save
    // can no longer carry it, and only the authoritative effective-default
    // operation writes it. Seed it directly so this fixture still describes
    // the on-disk layer it claims to.
    if let Some(active) = cfg.active_model.as_ref() {
        let mut raw: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        raw["active_model"] = serde_json::to_value(active).unwrap();
        std::fs::write(
            &path,
            format!("{}\n", serde_json::to_string_pretty(&raw).unwrap()),
        )
        .unwrap();
    }
}

fn with_trusted_workspace<T>(cwd: &std::path::Path, f: impl FnOnce() -> T) -> T {
    let policy = cockpit_config::trust::WorkspaceTrustPolicy {
        root: cockpit_config::trust::resolve_trust_root(cwd).unwrap(),
        mode: cockpit_config::WorkspaceTrustMode::Trust,
    };
    cockpit_config::trust::with_workspace_trust_policy(policy, f)
}

fn with_untrusted_workspace<T>(cwd: &std::path::Path, f: impl FnOnce() -> T) -> T {
    let policy = cockpit_config::trust::WorkspaceTrustPolicy {
        root: cockpit_config::trust::resolve_trust_root(cwd).unwrap(),
        mode: cockpit_config::WorkspaceTrustMode::IgnoreConfig,
    };
    cockpit_config::trust::with_workspace_trust_policy(policy, f)
}

fn open_startup_trust_modal_from_daemon(app: &mut App, cwd: &std::path::Path) {
    let root = cockpit_config::trust::resolve_trust_root(cwd).unwrap();
    app.first_paint_completed = true;
    app.apply_startup_workspace_completion(super::StartupWorkspaceCompletion {
        generation: app.startup_background.generation,
        opened: cwd.to_path_buf(),
        root,
        mode: None,
        config_generation: 0,
        snapshot: None,
    });
}

fn config_with_provider(provider_id: &str, model_id: &str) -> ProvidersConfig {
    let mut cfg = ProvidersConfig::default();
    let mut provider = ProviderEntry {
        url: "http://localhost:1/v1".to_string(),
        ..Default::default()
    };
    provider.models.push(ModelEntry {
        id: model_id.to_string(),
        ..Default::default()
    });
    cfg.providers.insert(provider_id.to_string(), provider);
    cfg
}

fn onboarding_snapshot(stage: OnboardingStage) -> cockpit_proto::OnboardingBootstrapSnapshot {
    cockpit_proto::OnboardingBootstrapSnapshot {
        run_id: uuid::Uuid::from_u128(1),
        attempt_id: uuid::Uuid::from_u128(2),
        revision: stage as u64,
        stage,
        bootstrap_state: if matches!(
            stage,
            OnboardingStage::Welcome | OnboardingStage::Profile | OnboardingStage::SecureStore
        ) {
            cockpit_proto::OnboardingBootstrapState::AwaitingChoice
        } else {
            cockpit_proto::OnboardingBootstrapState::Ready
        },
        limited_mode: false,
        lifetime_selection: None,
        host_capabilities: secure_store_ready_capabilities(),
        last_receipt: None,
    }
}

fn secure_store_ready_capabilities() -> cockpit_proto::HostCapabilitySnapshot {
    let mut capabilities = cockpit_proto::HostCapabilitySnapshot::unpublished();
    capabilities.features = vec![
        cockpit_proto::FeatureCapabilityRow {
            id: "secret_store.keyring".into(),
            state: cockpit_proto::FeatureCapabilityState::Available,
            reason: "platform keyring is available".into(),
            fix_command: None,
            remedy_text: None,
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

fn set_onboarding_stage(app: &mut App, stage: OnboardingStage) {
    // Every post-secure-store checkpoint is reached through a committed
    // config mutation. Preserve that daemon settlement evidence when these
    // focused UI tests synthesize the authoritative checkpoint directly.
    if !matches!(
        stage,
        OnboardingStage::Welcome | OnboardingStage::Profile | OnboardingStage::SecureStore
    ) {
        app.config_snapshot.generation = 1;
        app.config_snapshot.providers.set_resolution_generation(1);
    }
    app.apply_onboarding_bootstrap_snapshot(Some(onboarding_snapshot(stage)));
}

fn shell_key(app: &mut App, code: KeyCode) -> bool {
    app.handle_onboarding_shell_key(KeyEvent::new(code, KeyModifiers::NONE))
}

fn shell_screen_kind(app: &App) -> Option<crate::tui::onboarding::OnboardingScreenKind> {
    app.onboarding_shell
        .as_ref()
        .map(|shell| shell.screen_kind())
}

fn submit_onboarding_lifetime(app: &mut App) {
    assert_eq!(
        shell_screen_kind(app),
        Some(crate::tui::onboarding::OnboardingScreenKind::Lifetime)
    );
    if let Some(shell) = app.onboarding_shell.as_mut() {
        shell.clear_pending_transition();
    }
    shell_key(app, KeyCode::Enter);
}

fn complete_native_model(app: &mut App) {
    use crate::tui::onboarding::ModelPhase;
    assert_eq!(
        shell_screen_kind(app),
        Some(crate::tui::onboarding::OnboardingScreenKind::Model)
    );
    for phase in ModelPhase::ALL {
        assert_eq!(
            app.onboarding_shell
                .as_ref()
                .and_then(|shell| shell.model_phase()),
            Some(phase)
        );
        shell_key(app, KeyCode::Enter);
    }
    assert!(
        app.onboarding_shell
            .as_ref()
            .is_some_and(|shell| shell.transition_pending())
    );
}

fn land_onboarding_complete_after_lifetime(app: &mut App) {
    submit_onboarding_lifetime(app);
    set_onboarding_stage(app, OnboardingStage::Complete);
}

/// Simulate the authoritative completion of the lifetime settlement RPC
/// added after `before` was captured (earlier stages leave stale pending
/// entries in these tests because their actions never drain): the daemon
/// committed the `ApplySetupWizard` write and the terminal Advance, and
/// the correlated receipt lands on the event loop. The client-side
/// adoption (config re-read, summary, held draft) runs only here — never
/// at latch time (#426).
fn land_onboarding_lifetime_completion(
    app: &mut App,
    before: &[crate::tui::async_action::AsyncActionId],
) {
    let (action_id, request_id) = app
        .pending_startup_onboarding_operations
        .iter()
        .find(|(id, _)| !before.contains(id))
        .map(|(id, request)| (*id, request.clone()))
        .expect("the lifetime settlement RPC is pending");
    let snapshot = app
        .onboarding_snapshot
        .clone()
        .expect("lifetime stage snapshot");
    let receipt = cockpit_proto::OnboardingTransitionReceipt {
        run_id: snapshot.run_id,
        attempt_id: snapshot.attempt_id,
        consumed_revision: snapshot.revision,
        receipt_id: uuid::Uuid::from_u128(31),
        status: cockpit_proto::OnboardingReceiptStatus::Committed,
    };
    let mut complete = onboarding_snapshot(OnboardingStage::Complete);
    complete.revision = snapshot.revision + 1;
    complete.last_receipt = Some(receipt.clone());
    app.apply_async_action_result(crate::tui::async_action::AsyncActionResult {
        id: action_id,
        kind: crate::tui::async_action::AsyncActionKind::DaemonRpc("onboarding.lifetime"),
        presentation_stale: false,
        payload: Ok(
            crate::tui::async_action::AsyncActionPayload::StartupOnboardingTransition(
                super::StartupOnboardingCompletion {
                    generation: app.startup_background.generation,
                    run_id: snapshot.run_id,
                    attempt_id: snapshot.attempt_id,
                    expected_revision: snapshot.revision,
                    request_id,
                    receipt: Some(receipt),
                    snapshot: Some(complete),
                },
            ),
        ),
    });
}

fn settle_onboarding_agent_stage(app: &mut App) {
    use cockpit_proto::{
        AGENT_AUTHORING_DTO_VERSION, AgentAuthoringCatalogOrigin, AgentAuthoringCompatibleRoute,
        AgentAuthoringProjection, AgentAuthoringSource, AgentAuthoringSourceKind, AgentPolicyRoute,
        AgentPolicySnapshot, AgentPolicyTrustClassification, ApplyAuthoredAgentPackageOutcome,
        ApplyAuthoredAgentPackageReceipt, AuthoredAgentReceiptStatus, AuthoredAgentReview,
        AuthoredAgentReviewGrant,
    };
    let operation_id = "first-run-agent-op".to_string();
    app.onboarding_agent_operation_id = Some(operation_id.clone());
    let projection = AgentAuthoringProjection {
        dto_version: AGENT_AUTHORING_DTO_VERSION,
        policy: AgentPolicySnapshot {
            policy_revision: "agent-policy-rev".into(),
            routes: vec![AgentPolicyRoute {
                provider_id: "p".into(),
                model_id: "m".into(),
                trust: AgentPolicyTrustClassification::Trusted,
                confirmation_required: false,
                trust_is_shared: true,
                capabilities: vec!["text_generation".into()],
                location: Some("remote".into()),
                auto_prune: false,
                sidecar_eligible: false,
                remote_sidecar_egress_required: false,
            }],
            catalog_origin: AgentAuthoringCatalogOrigin::Cached,
            catalog_revision: "catalog-rev".into(),
            bundled_frontier_slug: "frontier".into(),
        },
        sources: vec![AgentAuthoringSource {
            kind: AgentAuthoringSourceKind::BundledFrontier,
            slug: Some("navigator".into()),
            display_name: "Navigator".into(),
            source_locator: Some("catalog/frontier@rev".into()),
            compatible_routes: vec![AgentAuthoringCompatibleRoute {
                provider_id: "p".into(),
                model_id: "m".into(),
            }],
            definition_frontmatter_yaml: None,
        }],
        review_trust_disclosure: "Trust classification is shared global provider/model policy."
            .into(),
    };
    let review = AuthoredAgentReview {
        agent_name: "navigator".into(),
        grants: vec![AuthoredAgentReviewGrant {
            provider_id: "p".into(),
            model_id: "m".into(),
            is_default: true,
            trust: AgentPolicyTrustClassification::Trusted,
            trust_is_shared: true,
        }],
        tool_tier_preferences: vec![("read".into(), "enabled".into())],
        verification_label: None,
        interactive_subagents: true,
        goal_skeptics_label: "off".into(),
        children: vec![],
        sidecars: vec![],
        source: "catalog/frontier@rev".into(),
        make_default: true,
        trust_is_shared: true,
        trust_disclosure: "Trust classification is shared global provider/model policy.".into(),
    };
    if let Some(shell) = app.onboarding_shell.as_mut() {
        shell.present_agent_authoring(projection, operation_id.clone());
        shell.apply_agent_authoring_outcome(ApplyAuthoredAgentPackageOutcome::Receipt(
            ApplyAuthoredAgentPackageReceipt {
                client_operation_id: operation_id,
                receipt_id: uuid::Uuid::from_u128(9),
                status: AuthoredAgentReceiptStatus::Committed,
                package_digest: "digest".into(),
                policy_revision: "agent-policy-rev".into(),
                installation_id: Some("install-1".into()),
                default_selected: true,
                result_config_generation: 1,
                review,
            },
        ));
    }
    app.config_snapshot.generation = 1;
}

fn type_into_search(app: &mut App, text: &str) {
    for ch in text.chars() {
        shell_key(app, KeyCode::Char(ch));
    }
}

/// Walk Welcome → Profile → SecureStore → (Provider handled by the caller).
fn advance_through_secure_store(app: &mut App, _cwd: &std::path::Path) {
    set_onboarding_stage(app, OnboardingStage::Welcome);
    assert_eq!(
        shell_screen_kind(app),
        Some(crate::tui::onboarding::OnboardingScreenKind::Welcome)
    );
    shell_key(app, KeyCode::Char(' '));

    set_onboarding_stage(app, OnboardingStage::Profile);
    assert_eq!(
        shell_screen_kind(app),
        Some(crate::tui::onboarding::OnboardingScreenKind::Profile)
    );
    assert!(matches!(app.dialog, crate::tui::settings::Dialog::None));

    set_onboarding_stage(app, OnboardingStage::SecureStore);
    assert_eq!(
        shell_screen_kind(app),
        Some(crate::tui::onboarding::OnboardingScreenKind::SecureStore)
    );
    // Cursor 0 is the platform keyring; Enter submits the placement.
    shell_key(app, KeyCode::Enter);

    set_onboarding_stage(app, OnboardingStage::Provider);
    assert_eq!(
        shell_screen_kind(app),
        Some(crate::tui::onboarding::OnboardingScreenKind::ProviderSearch)
    );
}

/// Select a template from the searchable catalog, which mounts and seeds
/// the provider engine.
fn select_provider_template(app: &mut App, query: &str) {
    type_into_search(app, query);
    shell_key(app, KeyCode::Down);
    shell_key(app, KeyCode::Enter);
    assert!(
        app.dialog.is_provider_add(),
        "selecting a search row must mount the provider add engine"
    );
}

#[test]
fn first_run_chains_provider_then_model() {
    let tmp = tempfile::tempdir().unwrap();
    let _home = TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    write_config(tmp.path(), &ProvidersConfig::default());
    let mut app = App::new(Some(tmp.path()), false);
    advance_through_secure_store(&mut app, tmp.path());
    select_provider_template(&mut app, "openai");
    write_global_config(&config_with_provider("p", "m"));
    app.dialog.test_mark_provider_add_done("p");

    assert!(with_trusted_workspace(tmp.path(), || app.service_onboarding_shell()));
    set_onboarding_stage(&mut app, OnboardingStage::Model);

    assert_eq!(
        shell_screen_kind(&app),
        Some(crate::tui::onboarding::OnboardingScreenKind::Model)
    );
    assert!(!app.dialog.is_active());
}

#[test]
fn first_run_provider_without_catalog_offers_manual_model_entry() {
    let tmp = tempfile::tempdir().unwrap();
    let _home = TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    write_config(tmp.path(), &ProvidersConfig::default());
    let mut app = App::new(Some(tmp.path()), false);
    advance_through_secure_store(&mut app, tmp.path());
    select_provider_template(&mut app, "openai");
    // No catalog: the provider was saved without a validated model list.
    write_global_config(&config_with_provider("p", ""));
    let mut empty_catalog = config_with_provider("p", "");
    empty_catalog.providers.get_mut("p").unwrap().models.clear();
    write_global_config(&empty_catalog);
    app.dialog.test_mark_provider_add_done("p");

    assert!(with_trusted_workspace(tmp.path(), || app.service_onboarding_shell()));
    set_onboarding_stage(&mut app, OnboardingStage::Model);
    assert_eq!(
        shell_screen_kind(&app),
        Some(crate::tui::onboarding::OnboardingScreenKind::Model)
    );
    assert!(!app.dialog.is_active());
}

#[test]
fn first_run_flow_completes_end_to_end() {
    let tmp = tempfile::tempdir().unwrap();
    let _home = TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    write_config(tmp.path(), &ProvidersConfig::default());
    let mut app = App::new(Some(tmp.path()), false);
    advance_through_secure_store(&mut app, tmp.path());
    select_provider_template(&mut app, "openai");
    write_global_config(&config_with_provider("p", "m"));
    app.dialog.test_mark_provider_add_done("p");

    assert!(with_trusted_workspace(tmp.path(), || app.service_onboarding_shell()));
    set_onboarding_stage(&mut app, OnboardingStage::Model);
    complete_native_model(&mut app);
    set_onboarding_stage(&mut app, OnboardingStage::Agent);
    settle_onboarding_agent_stage(&mut app);
    assert_eq!(
        shell_screen_kind(&app),
        Some(crate::tui::onboarding::OnboardingScreenKind::AgentAuthoring)
    );
    assert!(with_trusted_workspace(tmp.path(), || app.service_onboarding_shell()));
    set_onboarding_stage(&mut app, OnboardingStage::Lifetime);
    assert_eq!(
        shell_screen_kind(&app),
        Some(crate::tui::onboarding::OnboardingScreenKind::Lifetime)
    );
    submit_onboarding_lifetime(&mut app);
    assert!(
        app.onboarding_shell
            .as_ref()
            .is_some_and(|shell| shell.transition_pending()),
        "the lifetime settlement must request the terminal transition"
    );

    set_onboarding_stage(&mut app, OnboardingStage::Complete);
    assert_eq!(
        shell_screen_kind(&app),
        Some(crate::tui::onboarding::OnboardingScreenKind::Complete),
        "the authoritative Complete revision presents the stored summary"
    );
    assert!(!app.dialog.is_active());

    // "Start coding" is a local close: the terminal transition already
    // committed, so leaving the summary just closes the shell behind the
    // occupancy fence.
    shell_key(&mut app, KeyCode::Enter);
    assert!(app.onboarding_shell.is_none());
    assert!(!app.dialog.is_active());
    assert!(app.onboarding_dismissed);

    // A late authority result must not reopen the closed shell.
    set_onboarding_stage(&mut app, OnboardingStage::Complete);
    assert!(app.onboarding_shell.is_none());
}

#[test]
fn completion_detour_ends_when_the_added_provider_settles() {
    let tmp = tempfile::tempdir().unwrap();
    let _home = TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    write_config(tmp.path(), &ProvidersConfig::default());
    let mut app = App::new(Some(tmp.path()), false);
    advance_through_secure_store(&mut app, tmp.path());
    select_provider_template(&mut app, "openai");
    write_global_config(&config_with_provider("p", "m"));
    app.dialog.test_mark_provider_add_done("p");
    assert!(with_trusted_workspace(tmp.path(), || app.service_onboarding_shell()));
    set_onboarding_stage(&mut app, OnboardingStage::Model);
    complete_native_model(&mut app);
    set_onboarding_stage(&mut app, OnboardingStage::Agent);
    settle_onboarding_agent_stage(&mut app);
    assert!(with_trusted_workspace(tmp.path(), || app.service_onboarding_shell()));
    set_onboarding_stage(&mut app, OnboardingStage::Lifetime);
    land_onboarding_complete_after_lifetime(&mut app);
    assert_eq!(
        shell_screen_kind(&app),
        Some(crate::tui::onboarding::OnboardingScreenKind::Complete)
    );

    // "Add another provider" opens the local detour: the searchable catalog
    // mounts without any daemon transition, and Escape offers a local
    // return to the stored summary.
    shell_key(&mut app, KeyCode::Up);
    shell_key(&mut app, KeyCode::Enter);
    assert_eq!(
        shell_screen_kind(&app),
        Some(crate::tui::onboarding::OnboardingScreenKind::ProviderSearch)
    );
    assert!(
        app.onboarding_shell
            .as_ref()
            .is_some_and(|shell| shell.completion_detour_active())
    );
    shell_key(&mut app, KeyCode::Esc);
    shell_key(&mut app, KeyCode::Enter);
    assert_eq!(
        shell_screen_kind(&app),
        Some(crate::tui::onboarding::OnboardingScreenKind::Complete)
    );

    // A second detour that adds a provider ends when the provider engine
    // reaches its done page: the stored summary is presented again and the
    // engine unmounts.
    shell_key(&mut app, KeyCode::Up);
    shell_key(&mut app, KeyCode::Enter);
    select_provider_template(&mut app, "openai");
    app.dialog.test_mark_provider_add_done("p2");
    assert!(with_trusted_workspace(tmp.path(), || app.service_onboarding_shell()));
    assert_eq!(
        shell_screen_kind(&app),
        Some(crate::tui::onboarding::OnboardingScreenKind::Complete)
    );
    assert!(!app.dialog.is_active());
}

#[test]
fn first_run_completes_under_an_untrusted_workspace() {
    // Provider saves are global and trust-independent: the whole
    // provider→model chain must settle with IgnoreConfig in force.
    let tmp = tempfile::tempdir().unwrap();
    let _home = TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    write_config(tmp.path(), &ProvidersConfig::default());
    let mut app = App::new(Some(tmp.path()), false);
    advance_through_secure_store(&mut app, tmp.path());
    select_provider_template(&mut app, "openai");
    write_global_config(&config_with_provider("p", "m"));
    app.dialog.test_mark_provider_add_done("p");

    assert!(with_untrusted_workspace(tmp.path(), || app.service_onboarding_shell()));
    set_onboarding_stage(&mut app, OnboardingStage::Model);
    assert_eq!(
        shell_screen_kind(&app),
        Some(crate::tui::onboarding::OnboardingScreenKind::Model)
    );
}

#[test]
fn complete_authority_refresh_preserves_the_local_provider_detour() {
    // Detour occupancy gates the Complete-snapshot apply the same way a
    // user dismissal gates reopen: a concurrent client's committed
    // transition (or any read-only refresh of the same authority) must
    // never unmount an in-flight "add another provider" engine.
    let tmp = tempfile::tempdir().unwrap();
    let _home = TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    write_config(tmp.path(), &ProvidersConfig::default());
    let mut app = App::new(Some(tmp.path()), false);
    advance_through_secure_store(&mut app, tmp.path());
    select_provider_template(&mut app, "openai");
    write_global_config(&config_with_provider("p", "m"));
    app.dialog.test_mark_provider_add_done("p");
    assert!(with_trusted_workspace(tmp.path(), || app.service_onboarding_shell()));
    set_onboarding_stage(&mut app, OnboardingStage::Model);
    complete_native_model(&mut app);
    set_onboarding_stage(&mut app, OnboardingStage::Agent);
    settle_onboarding_agent_stage(&mut app);
    assert!(with_trusted_workspace(tmp.path(), || app.service_onboarding_shell()));
    set_onboarding_stage(&mut app, OnboardingStage::Lifetime);
    land_onboarding_complete_after_lifetime(&mut app);

    // Open the detour and mount its provider engine.
    shell_key(&mut app, KeyCode::Up);
    shell_key(&mut app, KeyCode::Enter);
    select_provider_template(&mut app, "compat");
    assert!(
        app.dialog.is_provider_add(),
        "the detour's provider engine must be mounted"
    );

    // A Complete authority refresh landing mid-detour (the daemon-global
    // broadcast from a concurrent client, or this client's own refresh)
    // adopts the correlation fields but keeps the detour's occupancy: the
    // engine stays mounted and the stored summary is not re-presented.
    let mut refreshed = onboarding_snapshot(OnboardingStage::Complete);
    refreshed.revision += 1;
    app.apply_onboarding_bootstrap_snapshot(Some(refreshed));
    assert_ne!(
        shell_screen_kind(&app),
        Some(crate::tui::onboarding::OnboardingScreenKind::Complete),
        "a Complete refresh must not re-present the summary over the detour"
    );
    assert!(
        app.dialog.is_provider_add(),
        "the detour's engine must survive the Complete refresh"
    );
    assert!(
        app.onboarding_shell
            .as_ref()
            .is_some_and(|shell| shell.completion_detour_active())
    );

    // The detour still ends through its own local path: once the added
    // provider settles, the stored summary is presented again.
    app.dialog.test_mark_provider_add_done("p2");
    assert!(with_trusted_workspace(tmp.path(), || app.service_onboarding_shell()));
    assert_eq!(
        shell_screen_kind(&app),
        Some(crate::tui::onboarding::OnboardingScreenKind::Complete)
    );
    assert!(!app.dialog.is_active());
}

#[test]
fn first_run_configuration_queues_held_draft_behind_selected_model() {
    let tmp = tempfile::tempdir().unwrap();
    let _home = TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    write_config(tmp.path(), &ProvidersConfig::default());
    let mut app = App::new(Some(tmp.path()), false);
    app.composer.set("draft from first run".to_string());

    assert!(!app.submit_input());
    assert_eq!(app.composer.text(), "draft from first run");
    assert!(matches!(app.dialog, Dialog::None));
    set_onboarding_stage(&mut app, OnboardingStage::Provider);
    assert_eq!(
        shell_screen_kind(&app),
        Some(crate::tui::onboarding::OnboardingScreenKind::ProviderSearch)
    );

    let mut cfg = config_with_provider("p", "m");
    cfg.active_model = Some(cockpit_config::providers::ActiveModelRef {
        provider: "p".to_string(),
        model: "m".to_string(),
        reasoning_effort: None,
        thinking_mode: None,
        prompt_cache_retention: None,
    });
    write_config(tmp.path(), &cfg);
    write_global_config(&cfg);
    select_provider_template(&mut app, "openai");
    app.dialog.test_mark_provider_add_done("p");
    assert!(with_trusted_workspace(tmp.path(), || app.service_onboarding_shell()));
    set_onboarding_stage(&mut app, OnboardingStage::Model);
    complete_native_model(&mut app);
    set_onboarding_stage(&mut app, OnboardingStage::Agent);
    settle_onboarding_agent_stage(&mut app);
    assert!(with_trusted_workspace(tmp.path(), || app.service_onboarding_shell()));
    set_onboarding_stage(&mut app, OnboardingStage::Lifetime);
    with_trusted_workspace(tmp.path(), || app.refresh_bootstrap_config_snapshot());
    assert!(
        app.config_snapshot.providers.active_model.is_some(),
        "lifetime settlement needs a configured default model"
    );
    assert!(app.submit_after_model_selection);
    let (control_tx, mut control_rx) = mpsc::channel(4);
    app.agent_runner = Some(Ok(AgentRunner::stub_with_control_tx(control_tx)));
    let before = app
        .pending_startup_onboarding_operations
        .keys()
        .copied()
        .collect::<Vec<_>>();
    submit_onboarding_lifetime(&mut app);
    assert!(
        app.pending_model_selection.is_none(),
        "the held draft must not release before the wizard apply commits"
    );
    assert!(
        app.submit_after_model_selection,
        "a failed or in-flight apply must leave the draft held for retry"
    );

    // The wizard apply commits and the terminal Advance lands: only the
    // correlated completion releases the draft behind the selected model.
    land_onboarding_lifetime_completion(&mut app, &before);
    assert!(
        app.pending_model_selection.is_some(),
        "lifetime settlement must queue model selection while a draft is held"
    );

    let request = control_rx.try_recv().expect("model request queued").request;
    let selection_id = match request {
        cockpit_proto::Request::SetActiveModel { selection_id, .. } => selection_id,
        other => panic!("expected model request, got {other:?}"),
    };
    let pending = app
        .pending_model_selection
        .as_ref()
        .expect("selection pending");
    assert_eq!(pending.selection_id, selection_id);
    let queued = pending.queued_submission.as_ref().expect("draft held");
    assert_eq!(queued.submission.text, "draft from first run");
    assert_eq!(app.composer.text(), "draft from first run");
}

#[test]
fn lifetime_settlement_adopts_the_committed_choice_only_after_the_daemon_commit() {
    let tmp = tempfile::tempdir().unwrap();
    let _home = TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    write_config(tmp.path(), &ProvidersConfig::default());
    let mut app = App::new(Some(tmp.path()), false);
    advance_through_secure_store(&mut app, tmp.path());
    select_provider_template(&mut app, "openai");
    write_global_config(&config_with_provider("p", "m"));
    app.dialog.test_mark_provider_add_done("p");
    assert!(with_trusted_workspace(tmp.path(), || app.service_onboarding_shell()));
    set_onboarding_stage(&mut app, OnboardingStage::Model);
    complete_native_model(&mut app);
    set_onboarding_stage(&mut app, OnboardingStage::Agent);
    settle_onboarding_agent_stage(&mut app);
    assert!(with_trusted_workspace(tmp.path(), || app.service_onboarding_shell()));
    set_onboarding_stage(&mut app, OnboardingStage::Lifetime);
    assert_eq!(
        shell_screen_kind(&app),
        Some(crate::tui::onboarding::OnboardingScreenKind::Lifetime)
    );

    // Disk still carries the `background_agents: true` default, so this
    // process holds the persistent owner intent before the choice.
    assert!(!app.ephemeral_preference);

    // Choose "Stop the daemon when the last client leaves" and Continue:
    // latching the settlement must not adopt the choice ahead of the
    // daemon commit — the apply can still fail and be retried.
    if let Some(shell) = app.onboarding_shell.as_mut() {
        shell.clear_pending_transition();
    }
    let before = app
        .pending_startup_onboarding_operations
        .keys()
        .copied()
        .collect::<Vec<_>>();
    shell_key(&mut app, KeyCode::Down);
    shell_key(&mut app, KeyCode::Enter);
    assert!(
        app.onboarding_shell
            .as_ref()
            .is_some_and(|shell| shell.transition_pending()),
        "the lifetime settlement must latch the terminal transition"
    );
    assert!(
        !app.ephemeral_preference,
        "the process must keep the pre-choice intent until the wizard apply commits"
    );

    // The correlated completion lands: the committed choice now owns this
    // process's lifetime preference and default acquisition intent, so
    // closing the last client stops the owner as the screen promised. The
    // fabricated receipt stands in for the daemon, so the fixture also
    // performs the daemon's committed write of the choice to the global
    // config — the completion refresh reads that disk state.
    let global = cockpit_config::dirs::global_config_file().unwrap();
    let mut doc = cockpit_config::extended::ExtendedConfigDoc::load(&global).unwrap();
    let mut extended = doc.config();
    extended.daemon.background_agents = false;
    doc.write(&extended).unwrap();
    land_onboarding_lifetime_completion(&mut app, &before);
    assert!(
        app.ephemeral_preference,
        "the committed ephemeral choice must flip the process lifetime preference"
    );
    assert_eq!(
        app.lifecycle_intent(),
        cockpit_client::LifecycleIntent::AttachOrEphemeral
    );
}

#[test]
fn no_provider_status_is_surfaced_and_draft_preserved() {
    let tmp = tempfile::tempdir().unwrap();
    let _home = TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    write_config(tmp.path(), &ProvidersConfig::default());
    let mut app = App::new(Some(tmp.path()), false);
    set_onboarding_stage(&mut app, OnboardingStage::Provider);
    app.composer.set("draft message".to_string());

    assert!(!app.submit_input());
    assert_eq!(app.composer.text(), "draft message");
    assert!(app.queue.is_empty());
    assert!(app.history.is_empty());
    assert!(app.submit_after_model_selection);
    assert_eq!(
        shell_screen_kind(&app),
        Some(crate::tui::onboarding::OnboardingScreenKind::ProviderSearch)
    );
    // The full-screen shell renders the provider catalog; the composer
    // draft survives underneath it.
    let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
    terminal.draw(|frame| app.render(frame)).unwrap();
    let rendered: String = terminal
        .backend()
        .buffer()
        .content
        .iter()
        .map(|cell| cell.symbol())
        .collect();
    assert!(rendered.contains("Let's add a provider"), "{rendered}");
    assert!(rendered.contains("Filter"), "{rendered}");
    assert!(
        !rendered.contains("draft message"),
        "the shell replaces the chat surface; the draft lives on in state"
    );
}

#[test]
fn send_before_onboarding_projection_never_opens_the_legacy_provider_modal() {
    let tmp = tempfile::tempdir().unwrap();
    let _home = TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    write_config(tmp.path(), &ProvidersConfig::default());
    let mut app = App::new(Some(tmp.path()), false);
    app.composer.set("early draft".to_string());

    assert!(!app.submit_input());
    assert_eq!(app.composer.text(), "early draft");
    assert!(app.onboarding_shell.is_none());
    assert!(!app.dialog.is_active());
    assert!(app.history.iter().any(|item| matches!(
        item,
        HistoryEntry::Plain { line }
            if line.contains("Waiting for the daemon onboarding checkpoint")
    )));

    set_onboarding_stage(&mut app, OnboardingStage::Provider);
    assert_eq!(
        shell_screen_kind(&app),
        Some(crate::tui::onboarding::OnboardingScreenKind::ProviderSearch)
    );
    assert_eq!(app.composer.text(), "early draft");
}

#[test]
fn defer_provider_closes_shell_and_limited_resume_reopens_it() {
    let tmp = tempfile::tempdir().unwrap();
    let _home = TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    write_config(tmp.path(), &ProvidersConfig::default());
    let mut app = App::new(Some(tmp.path()), false);
    advance_through_secure_store(&mut app, tmp.path());

    // Escape → Defer: an explicit, visible choice — never a silent
    // key-to-defer mapping. Defer is the first row on the provider stage
    // (Back is withheld: the daemon rejects reopening the committed
    // secure-store choice).
    shell_key(&mut app, KeyCode::Esc);
    shell_key(&mut app, KeyCode::Enter);

    // The DeferProvider transition commits limited mode; the authoritative
    // deferred snapshot it produces closes the shell (limited-mode chat is
    // now the surface).
    let mut deferred = onboarding_snapshot(OnboardingStage::Provider);
    deferred.limited_mode = true;
    deferred.revision += 10;
    app.apply_onboarding_bootstrap_snapshot(Some(deferred.clone()));
    assert!(
        app.onboarding_shell.is_none(),
        "a committed deferral hands the surface to limited mode"
    );

    // A later launch applying the same deferred snapshot does not auto-open
    // the shell either; the no-provider send guard reopens it explicitly.
    let mut resumed = App::new(Some(tmp.path()), false);
    resumed.apply_onboarding_bootstrap_snapshot(Some(deferred));
    assert!(resumed.onboarding_shell.is_none());
    resumed.composer.set("deferred, still typing".to_string());
    assert!(!resumed.submit_input());
    assert_eq!(resumed.composer.text(), "deferred, still typing");
    assert!(resumed.onboarding_shell.is_some());
    assert_eq!(
        resumed
            .onboarding_shell
            .as_ref()
            .map(|shell| shell.screen_kind()),
        Some(crate::tui::onboarding::OnboardingScreenKind::ProviderSearch)
    );

    // The limited-mode badge is visible on the reopened shell.
    let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
    terminal.draw(|frame| resumed.render(frame)).unwrap();
    let rendered: String = terminal
        .backend()
        .buffer()
        .content
        .iter()
        .map(|cell| cell.symbol())
        .collect();
    assert!(rendered.contains("limited mode"), "{rendered}");
}

#[test]
fn cancel_preserves_progress_and_reopen_uses_authoritative_stage() {
    let tmp = tempfile::tempdir().unwrap();
    let _home = TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    write_config(tmp.path(), &ProvidersConfig::default());
    let mut app = App::new(Some(tmp.path()), false);
    advance_through_secure_store(&mut app, tmp.path());

    // Escape → Cancel: closes the shell; committed daemon progress (the
    // snapshot) is untouched. On the provider stage the menu is
    // [Defer, Cancel] (Back would reopen the committed secure-store
    // choice), so Cancel is one Down away.
    shell_key(&mut app, KeyCode::Esc);
    shell_key(&mut app, KeyCode::Down);
    shell_key(&mut app, KeyCode::Enter);
    assert!(app.onboarding_shell.is_none());
    assert!(!app.dialog.is_active());
    assert!(app.onboarding_dismissed);
    assert_eq!(
        app.onboarding_snapshot
            .as_ref()
            .map(|snapshot| snapshot.stage),
        Some(OnboardingStage::Provider),
        "cancel must not erase the committed stage"
    );

    // A snapshot alone must not reopen a dismissed shell — not even the
    // authoritative transition result of work that was in flight when the
    // user cancelled. Only explicit re-entry clears the fence.
    set_onboarding_stage(&mut app, OnboardingStage::Provider);
    assert!(
        app.onboarding_shell.is_none(),
        "the occupancy fence keeps a dismissed shell closed"
    );

    // Explicit re-entry (the no-provider send guard) reopens at the
    // authoritative stage — the provider catalog, not a stale settings page.
    app.composer.set("resume after cancel".to_string());
    assert!(!app.submit_input());
    assert!(!app.onboarding_dismissed);
    assert!(app.onboarding_shell.is_some());
    assert_eq!(
        shell_screen_kind(&app),
        Some(crate::tui::onboarding::OnboardingScreenKind::ProviderSearch)
    );
}

#[test]
fn duplicate_engine_completion_advances_exactly_once() {
    let tmp = tempfile::tempdir().unwrap();
    let _home = TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    write_config(tmp.path(), &ProvidersConfig::default());
    let mut app = App::new(Some(tmp.path()), false);
    advance_through_secure_store(&mut app, tmp.path());
    select_provider_template(&mut app, "openai");
    write_global_config(&config_with_provider("p", "m"));
    app.dialog.test_mark_provider_add_done("p");

    assert!(with_trusted_workspace(tmp.path(), || app.service_onboarding_shell()));
    // The latch holds until the authoritative revision lands: repeated
    // wakes must not request a second advance for the same completion.
    assert!(!with_trusted_workspace(tmp.path(), || app.service_onboarding_shell()));
    assert!(!with_trusted_workspace(tmp.path(), || app.service_onboarding_shell()));

    // The advanced snapshot clears the latch and mounts the model engine.
    set_onboarding_stage(&mut app, OnboardingStage::Model);
    assert_eq!(
        shell_screen_kind(&app),
        Some(crate::tui::onboarding::OnboardingScreenKind::Model)
    );
}

#[test]
fn late_engine_completion_after_close_is_inert() {
    let tmp = tempfile::tempdir().unwrap();
    let _home = TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    write_config(tmp.path(), &ProvidersConfig::default());
    let mut app = App::new(Some(tmp.path()), false);
    advance_through_secure_store(&mut app, tmp.path());
    select_provider_template(&mut app, "openai");

    // Cancel mid-flight, then deliver a settlement for the dropped engine.
    shell_key(&mut app, KeyCode::Esc);
    shell_key(&mut app, KeyCode::Down);
    shell_key(&mut app, KeyCode::Down);
    shell_key(&mut app, KeyCode::Enter);
    assert!(app.onboarding_shell.is_none());

    let completion = crate::tui::settings::SettingsDaemonEffectCompletion {
        dialog_id: uuid::Uuid::new_v4(),
        operation_id: uuid::Uuid::new_v4(),
        target: crate::tui::settings::SettingsEffectTarget {
            surface: "settings.providers".into(),
            owner: "provider-add".into(),
            revision: None,
        },
        response: Err("daemon gone".to_string()),
        authoritative_rejection: false,
        committed_refresh_needed: None,
    };
    app.dialog.apply_settings_daemon_completion(completion);
    assert!(app.onboarding_shell.is_none());
    assert!(!app.dialog.is_active());
}

#[test]
fn provider_engine_escape_never_offers_an_illegal_back() {
    let tmp = tempfile::tempdir().unwrap();
    let _home = TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    write_config(tmp.path(), &ProvidersConfig::default());
    let mut app = App::new(Some(tmp.path()), false);
    advance_through_secure_store(&mut app, tmp.path());
    select_provider_template(&mut app, "openai");
    assert!(app.dialog.is_provider_add());

    // The engine's Escape is intercepted by the shell. The visible menu
    // from the provider engine offers only what the daemon accepts for the
    // stage: Defer and Cancel — Back from Provider would reopen the
    // committed secure-store choice, so it is never offered.
    let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
    shell_key(&mut app, KeyCode::Esc);
    terminal.draw(|frame| app.render(frame)).unwrap();
    let rendered: String = terminal
        .backend()
        .buffer()
        .content
        .iter()
        .map(|cell| cell.symbol())
        .collect();
    assert!(rendered.contains("Leave setup?"), "{rendered}");
    assert!(
        !rendered.contains("Back to the previous step"),
        "{rendered}"
    );
    assert!(rendered.contains("Defer provider setup"), "{rendered}");

    // Defer is an explicit daemon transition, not a silent key mapping.
    shell_key(&mut app, KeyCode::Enter);
    assert!(app.async_actions.has_pending_kind(
        &crate::tui::async_action::AsyncActionKind::DaemonRpc("onboarding.transition")
    ));

    // The committed deferral hands the surface to limited mode.
    let mut deferred = onboarding_snapshot(OnboardingStage::Provider);
    deferred.limited_mode = true;
    deferred.revision += 10;
    app.apply_onboarding_bootstrap_snapshot(Some(deferred));
    assert!(app.onboarding_shell.is_none());
}

#[test]
fn stacked_modal_focus_matches_render_order() {
    let tmp = tempfile::tempdir().unwrap();
    let _home = TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let mut app = App::new_with_bootstrap_config(Some(tmp.path()), false);
    open_startup_trust_modal_from_daemon(&mut app, tmp.path());

    assert_eq!(
        app.startup_modal_on_top(),
        Some(StartupModal::WorkspaceTrust)
    );
    let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
    terminal.draw(|frame| app.render(frame)).unwrap();
    let rendered: String = terminal
        .backend()
        .buffer()
        .content
        .iter()
        .map(|cell| cell.symbol())
        .collect();
    assert!(rendered.contains("workspace trust"), "{rendered}");
    assert!(!rendered.contains("cockpit daemon"), "{rendered}");
}

#[tokio::test]
async fn keypress_does_not_record_hidden_trust_decision() {
    let tmp = tempfile::tempdir().unwrap();
    let _home = TestEnvGuard::isolate_cockpit_home_at_async(tmp.path()).await;
    let mut app = App::new_with_bootstrap_config(Some(tmp.path()), false);
    open_startup_trust_modal_from_daemon(&mut app, tmp.path());

    assert_eq!(
        app.startup_modal_on_top(),
        Some(StartupModal::WorkspaceTrust)
    );
    assert!(!app.handle_key(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE)));
    cockpit_config::trust::clear_runtime_policy_for_tests();
}

#[tokio::test]
async fn onboarding_never_auto_trusts() {
    let tmp = tempfile::tempdir().unwrap();
    let _home = TestEnvGuard::isolate_cockpit_home_at_async(tmp.path()).await;
    let mut app = App::new_with_bootstrap_config(Some(tmp.path()), false);
    open_startup_trust_modal_from_daemon(&mut app, tmp.path());

    app.service_onboarding_shell();
    assert_eq!(app.dialog.test_page_name(), Some("workspace_trust"));
    cockpit_config::trust::clear_runtime_policy_for_tests();
}

// ── #425: silent drop sites ──────────────────────────────────────────────

#[test]
fn onboarding_shell_disables_structured_paste_intake() {
    // Root cause of the cold-run Welcome wedge: while the full-screen shell
    // owns every key, ordinary keystrokes must not be intake-buffered as
    // rapid-paste candidates — the classifier replays those through the
    // frozen-composer route and the shell never sees them.
    let tmp = tempfile::tempdir().unwrap();
    let _home = TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let mut app = App::new(Some(tmp.path()), false);
    assert!(
        app.structured_paste_composer_eligible(),
        "composer owns paste intake when no shell is open"
    );
    set_onboarding_stage(&mut app, OnboardingStage::Welcome);
    assert!(
        !app.structured_paste_composer_eligible(),
        "the onboarding shell must own its own keys"
    );
}

#[test]
fn duplicate_transition_intent_while_pending_is_visible_not_silent() {
    let tmp = tempfile::tempdir().unwrap();
    let _home = TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let mut app = App::new(Some(tmp.path()), false);
    set_onboarding_stage(&mut app, OnboardingStage::Welcome);

    shell_key(&mut app, KeyCode::Char(' '));
    assert!(
        app.onboarding_shell
            .as_ref()
            .is_some_and(|shell| shell.transition_pending()),
        "the first intent latches the in-flight transition"
    );
    assert_eq!(app.pending_startup_onboarding_operations.len(), 1);

    shell_key(&mut app, KeyCode::Char(' '));
    assert_eq!(
        app.toast.as_ref().map(|toast| toast.text.as_str()),
        Some("Still applying the previous step…"),
        "a duplicate intent while the transition is pending must be visible"
    );
    assert_eq!(
        app.pending_startup_onboarding_operations.len(),
        1,
        "the duplicate intent must not abort and resend the RPC"
    );
}

#[test]
fn transition_correlation_failure_clears_latch_and_surfaces_retryable_error() {
    let tmp = tempfile::tempdir().unwrap();
    let _home = TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let mut app = App::new(Some(tmp.path()), false);
    set_onboarding_stage(&mut app, OnboardingStage::Welcome);
    let snapshot = app.onboarding_snapshot.clone().expect("welcome snapshot");

    shell_key(&mut app, KeyCode::Char(' '));
    let (action_id, request_id) = app
        .pending_startup_onboarding_operations
        .iter()
        .next()
        .map(|(id, request)| (*id, request.clone()))
        .expect("the transition RPC is pending");
    // A corrupt receipt: every identity field correlates, but the consumed
    // revision does not match the transition the client believes it sent.
    let receipt = cockpit_proto::OnboardingTransitionReceipt {
        run_id: snapshot.run_id,
        attempt_id: snapshot.attempt_id,
        consumed_revision: snapshot.revision + 1,
        receipt_id: uuid::Uuid::from_u128(77),
        status: cockpit_proto::OnboardingReceiptStatus::Committed,
    };
    app.apply_async_action_result(crate::tui::async_action::AsyncActionResult {
        id: action_id,
        kind: crate::tui::async_action::AsyncActionKind::DaemonRpc("onboarding.transition"),
        presentation_stale: false,
        payload: Ok(
            crate::tui::async_action::AsyncActionPayload::StartupOnboardingTransition(
                super::StartupOnboardingCompletion {
                    generation: app.startup_background.generation,
                    run_id: snapshot.run_id,
                    attempt_id: snapshot.attempt_id,
                    expected_revision: snapshot.revision,
                    request_id,
                    receipt: Some(receipt),
                    snapshot: None,
                },
            ),
        ),
    });

    assert!(
        !app.onboarding_shell
            .as_ref()
            .is_some_and(|shell| shell.transition_pending()),
        "a rejected correlation must clear the pending-transition latch"
    );
    let toast = app.toast.as_ref().expect("the rejection is visible");
    assert!(
        toast.text.contains("receipt revision mismatch"),
        "{}",
        toast.text
    );
    assert!(
        app.async_actions
            .has_pending_kind(&crate::tui::async_action::AsyncActionKind::DaemonRpc(
                "onboarding.bootstrap_refresh"
            )),
        "the rejection re-reads the authority so the stage can retry"
    );
}

#[test]
fn stale_generation_transition_completion_is_inert_not_erroring() {
    let tmp = tempfile::tempdir().unwrap();
    let _home = TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let mut app = App::new(Some(tmp.path()), false);
    set_onboarding_stage(&mut app, OnboardingStage::Welcome);

    shell_key(&mut app, KeyCode::Char(' '));
    let (action_id, request_id) = app
        .pending_startup_onboarding_operations
        .iter()
        .next()
        .map(|(id, request)| (*id, request.clone()))
        .expect("the transition RPC is pending");
    app.apply_async_action_result(crate::tui::async_action::AsyncActionResult {
        id: action_id,
        kind: crate::tui::async_action::AsyncActionKind::DaemonRpc("onboarding.transition"),
        presentation_stale: false,
        payload: Ok(
            crate::tui::async_action::AsyncActionPayload::StartupOnboardingTransition(
                super::StartupOnboardingCompletion {
                    generation: app.startup_background.generation + 1,
                    run_id: uuid::Uuid::from_u128(1),
                    attempt_id: uuid::Uuid::from_u128(2),
                    expected_revision: 0,
                    request_id,
                    receipt: None,
                    snapshot: None,
                },
            ),
        ),
    });

    assert!(
        app.toast.is_none(),
        "a replaced-generation completion is presentation-inert, not an error"
    );
    assert!(
        !app.async_actions
            .has_pending_kind(&crate::tui::async_action::AsyncActionKind::DaemonRpc(
                "onboarding.bootstrap_refresh"
            )),
        "an inert completion must not trigger an authority refresh"
    );
}

#[test]
fn workspace_resolution_waits_for_the_onboarding_run_to_complete() {
    // The bootstrap-locked daemon denies `GetWorkspaceTrust`; resolving it
    // while the wizard is open can only produce the cold-run red toast.
    // The ride-along must defer until the authoritative run completes.
    let tmp = tempfile::tempdir().unwrap();
    let _home = TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let mut app = App::new(Some(tmp.path()), false);
    assert!(!app.startup_background.workspace_ready);

    app.apply_onboarding_bootstrap_snapshot(Some(onboarding_snapshot(OnboardingStage::Welcome)));
    let workspace_kind = crate::tui::async_action::AsyncActionKind::DaemonRpc("startup.workspace");
    assert!(
        !app.async_actions.has_pending_kind(&workspace_kind),
        "no workspace RPC while the onboarding run is open"
    );

    app.apply_onboarding_bootstrap_snapshot(Some(onboarding_snapshot(OnboardingStage::Complete)));
    assert!(
        app.async_actions.has_pending_kind(&workspace_kind),
        "the deferred workspace resolution starts once the run completes"
    );
}
