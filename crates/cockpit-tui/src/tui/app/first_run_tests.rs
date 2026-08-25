use super::*;
use crate::tui::agent_runner::AgentRunner;
use cockpit_config::providers::{ConfigDoc, ModelEntry, ProviderEntry, ProvidersConfig};
use cockpit_test_support::TestEnvGuard;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::Terminal;
use ratatui::backend::TestBackend;
use tokio::sync::mpsc;

fn daemon_paths(tmp: &tempfile::TempDir) -> cockpit_core::daemon::DaemonPaths {
    cockpit_core::daemon::DaemonPaths {
        pid_file: tmp.path().join("daemon.pid"),
        socket: tmp.path().join("daemon.sock"),
        ephemeral: false,
    }
}

fn write_config(cwd: &std::path::Path, cfg: &ProvidersConfig) {
    let cockpit = cwd.join(".cockpit");
    std::fs::create_dir_all(&cockpit).unwrap();
    let path = cockpit.join("config.json");
    let mut doc = ConfigDoc::load(&path).unwrap();
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

#[test]
fn daemon_autostart_ask_shows_modal() {
    let tmp = tempfile::tempdir().unwrap();
    let state = daemon_not_running_state_with_spawn(
        cockpit_core::daemon::DaemonStatus::NotRunning,
        daemon_paths(&tmp),
        cockpit_config::extended::DaemonAutostart::Ask,
        false,
        || panic!("ask mode must not spawn"),
    );

    assert!(state.prompt.is_some());
    assert!(!state.connected);
    assert!(!state.daemonless);
}

#[test]
fn daemon_autostart_failure_falls_back_to_modal() {
    let tmp = tempfile::tempdir().unwrap();
    let state = daemon_not_running_state_with_spawn(
        cockpit_core::daemon::DaemonStatus::NotRunning,
        daemon_paths(&tmp),
        cockpit_config::extended::DaemonAutostart::Shared,
        false,
        || anyhow::bail!("boom"),
    );

    assert!(state.prompt.is_some());
    assert!(!state.connected);
    assert!(state.notice.is_none());
}

#[test]
fn first_run_chains_provider_then_model() {
    let tmp = tempfile::tempdir().unwrap();
    let _home = TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    write_config(tmp.path(), &ProvidersConfig::default());
    let mut app = App::new(Some(tmp.path()), false);
    app.daemon_prompt = None;
    app.dialog = crate::tui::settings::Dialog::open_providers_add(tmp.path());
    write_config(tmp.path(), &config_with_provider("p", "m"));
    app.dialog.test_mark_provider_add_done("p");

    assert!(with_trusted_workspace(tmp.path(), || app.service_first_run_flow()));

    assert_eq!(
        app.dialog.test_page_name(),
        Some(cockpit_core::wizard::MODEL_WIZARD_ID)
    );
    assert_eq!(
        app.dialog.test_setup_prefill(),
        Some(cockpit_core::wizard::WizardAnswer::Select("p".to_string()))
    );
    app.dialog
        .handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    assert_eq!(
        app.dialog.test_setup_answer("provider"),
        Some(cockpit_core::wizard::WizardAnswer::Select("p".to_string()))
    );
    assert_eq!(
        app.dialog.test_setup_prefill(),
        Some(cockpit_core::wizard::WizardAnswer::Select(
            "p:m".to_string()
        ))
    );
}

#[test]
fn first_run_flow_completes_end_to_end() {
    let tmp = tempfile::tempdir().unwrap();
    let _home = TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    write_config(tmp.path(), &ProvidersConfig::default());
    let mut app = App::new(Some(tmp.path()), false);
    app.daemon_prompt = None;
    app.dialog = crate::tui::settings::Dialog::open_providers_add(tmp.path());
    write_config(tmp.path(), &config_with_provider("p", "m"));
    app.dialog.test_mark_provider_add_done("p");

    assert!(with_trusted_workspace(tmp.path(), || app.service_first_run_flow()));
    assert_eq!(
        app.dialog.test_page_name(),
        Some(cockpit_core::wizard::MODEL_WIZARD_ID)
    );
    app.dialog.test_mark_setup_complete("model-save");
    assert!(with_trusted_workspace(tmp.path(), || app.service_first_run_flow()));
    assert_eq!(app.dialog.test_page_name(), Some("first_run_complete"));
}

#[test]
fn first_run_configuration_queues_held_draft_behind_selected_model() {
    let tmp = tempfile::tempdir().unwrap();
    let _home = TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    write_config(tmp.path(), &ProvidersConfig::default());
    let mut app = App::new(Some(tmp.path()), false);
    app.daemon_prompt = None;
    app.dialog = crate::tui::settings::Dialog::None;
    app.composer.set("draft from first run".to_string());

    assert!(!app.submit_input());
    assert!(app.dialog.test_provider_is_add());

    let mut cfg = config_with_provider("p", "m");
    cfg.active_model = Some(cockpit_config::providers::ActiveModelRef {
        provider: "p".to_string(),
        model: "m".to_string(),
        reasoning_effort: None,
        thinking_mode: None,
        prompt_cache_retention: None,
    });
    write_config(tmp.path(), &cfg);
    app.dialog.test_mark_provider_add_done("p");
    assert!(with_trusted_workspace(tmp.path(), || app.service_first_run_flow()));
    app.dialog.test_mark_setup_complete("model-save");

    let (control_tx, mut control_rx) = mpsc::channel(4);
    app.agent_runner = Some(Ok(AgentRunner::stub_with_control_tx(control_tx)));
    assert!(with_trusted_workspace(tmp.path(), || app.service_first_run_flow()));

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
fn no_provider_status_is_surfaced_and_draft_preserved() {
    let tmp = tempfile::tempdir().unwrap();
    let _home = TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    write_config(tmp.path(), &ProvidersConfig::default());
    let mut app = App::new(Some(tmp.path()), false);
    app.daemon_prompt = None;
    app.dialog = crate::tui::settings::Dialog::None;
    app.composer.set("draft message".to_string());

    assert!(!app.submit_input());
    assert_eq!(app.composer.text(), "draft message");
    assert!(app.queue.is_empty());
    assert!(app.history.is_empty());
    assert!(app.submit_after_model_selection);
    assert!(app.dialog.test_provider_is_add());
    assert_eq!(
        app.dialog.test_provider_add_status(),
        Some(
            "No provider is configured yet. Add one before sending; your message is still in the composer."
        )
    );
}

#[test]
fn no_provider_send_opens_provider_setup_preserves_input() {
    let tmp = tempfile::tempdir().unwrap();
    let _home = TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    write_config(tmp.path(), &ProvidersConfig::default());
    let mut app = App::new(Some(tmp.path()), false);
    app.daemon_prompt = None;
    app.dialog = crate::tui::settings::Dialog::None;
    app.composer.set("draft message".to_string());

    assert!(!app.submit_input());

    assert_eq!(app.composer.text(), "draft message");
    assert!(app.queue.is_empty());
    assert!(app.history.is_empty());
    assert!(app.submit_after_model_selection);
    assert!(app.dialog.test_provider_is_add());
}

fn daemon_prompt(tmp: &tempfile::TempDir) -> crate::tui::daemon_prompt::DaemonPromptDialog {
    crate::tui::daemon_prompt::DaemonPromptDialog::new(
        cockpit_core::daemon::DaemonStatus::NotRunning,
        daemon_paths(tmp),
    )
}

#[test]
fn stacked_modal_focus_matches_render_order() {
    let tmp = tempfile::tempdir().unwrap();
    let _home = TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let root = cockpit_config::trust::resolve_trust_root(tmp.path()).unwrap();
    let mut app = App::new_with_workspace_trust(
        Some(tmp.path()),
        false,
        StartupWorkspaceTrust::Pending(root),
    );
    app.daemon_prompt = Some(daemon_prompt(&tmp));

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
    let root = cockpit_config::trust::resolve_trust_root(tmp.path()).unwrap();
    let mut app = App::new_with_workspace_trust(
        Some(tmp.path()),
        false,
        StartupWorkspaceTrust::Pending(root.clone()),
    );
    app.daemon_prompt = Some(daemon_prompt(&tmp));

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
    let root = cockpit_config::trust::resolve_trust_root(tmp.path()).unwrap();
    let mut app = App::new_with_workspace_trust(
        Some(tmp.path()),
        false,
        StartupWorkspaceTrust::Pending(root.clone()),
    );

    app.service_first_run_flow();
    assert_eq!(app.dialog.test_page_name(), Some("workspace_trust"));
    cockpit_config::trust::clear_runtime_policy_for_tests();
}
