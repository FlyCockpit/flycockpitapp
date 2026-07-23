//! Tests for the daemon-pushed config snapshot the TUI renders from
//! (`tui-config-single-source`).
//!
//! `config_snapshot_values_match_previous_resolution` is a **characterization
//! test**: the fixtures below were captured against the *client-side*
//! resolution (`load_for_cwd` / `ordered_model_choices`) before any call site
//! was converted to read from the held snapshot (see the fixture-capture
//! commit). After conversion the same fixtures must resolve identically off the
//! held snapshot — this pins behavior parity (criterion 8).

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use cockpit_config::extended::LlmMode;
use tokio::sync::mpsc;

use super::App;
use crate::tui::agent_runner::{AgentRunner, ClientTasks, UsageCounts};

// ---- Fixed config tree + committed fixtures --------------------------------

/// The fixed config tree the characterization test resolves against.
fn write_fixture_tree(root: &Path) {
    let cockpit = root.join(".cockpit");
    std::fs::create_dir_all(&cockpit).unwrap();
    std::fs::write(
        cockpit.join("config.json"),
        r#"{"llm_mode":"normal","dialog":{"lockout_ms":2500},"tui":{"use_emojis":false}}"#,
    )
    .unwrap();
    let provider_path =
        cockpit_config::providers::provider_file_path_for_config(&cockpit.join("config.json"), "p")
            .unwrap();
    std::fs::create_dir_all(provider_path.parent().unwrap()).unwrap();
    std::fs::write(
        &provider_path,
        r#"{"url":"https://example.test","models":[{"id":"a","favorite":true},{"id":"b"}]}"#,
    )
    .unwrap();
}

/// `load_for_cwd(cwd).llm_mode`
const FIXTURE_GLOBAL_LLM_MODE: LlmMode = LlmMode::Normal;
/// `load_for_cwd(cwd).dialog.lockout_ms`
const FIXTURE_DIALOG_LOCKOUT_MS: u64 = 2500;
/// `load_for_cwd(cwd).tui.use_emojis`
const FIXTURE_USE_EMOJIS: bool = false;
/// `ordered_model_choices(cwd, &counts)` → `(provider_id, model_id, is_favorite, mode)`
fn fixture_model_ordering() -> Vec<(String, String, bool, LlmMode)> {
    vec![
        ("p".to_string(), "a".to_string(), true, LlmMode::Normal),
        ("p".to_string(), "b".to_string(), false, LlmMode::Normal),
    ]
}

// ---- Test helpers ----------------------------------------------------------

fn reset_config_counters() {
    cockpit_config::extended::reset_load_for_cwd_call_count();
    cockpit_config::providers::reset_load_effective_call_count();
}

fn load_for_cwd_count() -> usize {
    cockpit_config::extended::load_for_cwd_call_count()
}

fn load_effective_count() -> usize {
    cockpit_config::providers::load_effective_call_count()
}

/// Build the wire snapshot the daemon would push for a config tree: the
/// resolved `ExtendedConfig` plus the redacted provider projection.
fn snapshot_from_tree(cwd: &Path, generation: u64) -> cockpit_core::daemon::proto::ConfigSnapshot {
    let extended = cockpit_config::extended::load_for_cwd(cwd);
    let paths = cockpit_config::dirs::config_file_paths_for_load(cwd);
    let providers = cockpit_config::providers::ConfigDoc::providers_from_paths(&paths);
    cockpit_core::daemon::proto::ConfigSnapshot {
        session_id: uuid::Uuid::new_v4(),
        generation,
        extended,
        providers: cockpit_core::secret_ref::redact_provider_view(&providers),
    }
}

/// A minimal attached runner so `resync_config_after_local_write` takes the
/// daemon-signal path (no disk read) instead of the detached bootstrap refresh.
fn stub_runner() -> AgentRunner {
    let (input_tx, _r0) = mpsc::channel(1);
    let (record_tx, _r1) = mpsc::channel(1);
    let (control_tx, _r2) = mpsc::channel(1);
    let (attached_request_tx, _r3) = mpsc::channel(1);
    AgentRunner {
        input_tx,
        record_tx,
        control_tx,
        attached_request_tx,
        events: Arc::new(Mutex::new(Vec::new())),
        event_notify: Arc::new(tokio::sync::Notify::new()),
        active_agent: Arc::new(Mutex::new("Build".to_string())),
        active_agent_path: Arc::new(Mutex::new(vec!["Build".to_string()])),
        skill_inventory_names: Arc::new(Mutex::new(None)),
        foreground_target: Some(cockpit_core::engine::message::QueueTarget::root("Build")),
        active_model_state: None,
        session_id_state: Arc::new(Mutex::new(uuid::Uuid::new_v4())),
        short_id: "abc123".to_string(),
        project_id: "project".to_string(),
        usage: UsageCounts::default(),
        owns_daemon: false,
        socket: PathBuf::from("/tmp/cockpit-test.sock"),
        history: Vec::new(),
        paused_work: Vec::new(),
        repair_required: None,
        btw_fork: None,
        daemon_version: "test".to_string(),
        daemon_compatible: true,
        current_client: None,
        attach_context: None,
        last_applied_seq: Some(Arc::new(Mutex::new(Some(0)))),
        client_tasks: ClientTasks::default(),
    }
}

fn app_for_tree(tree: &Path) -> App {
    App::new_with_db(Some(tree), false, cockpit_db::Db::open_in_memory().unwrap())
}

// ---- Criterion 8: behavior parity ------------------------------------------

#[test]
fn config_snapshot_values_match_previous_resolution() {
    let tmp = tempfile::tempdir().unwrap();
    let _home = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    write_fixture_tree(tmp.path());
    let cwd = tmp.path();

    // Post-conversion: resolve the five values off the held daemon snapshot
    // instead of the client-side path. The committed fixtures are unchanged.
    let mut app = app_for_tree(cwd);
    app.apply_config_snapshot(snapshot_from_tree(cwd, 1));

    assert_eq!(
        app.config_snapshot.extended.llm_mode,
        FIXTURE_GLOBAL_LLM_MODE
    );
    assert_eq!(
        app.config_snapshot.extended.dialog.lockout_ms,
        FIXTURE_DIALOG_LOCKOUT_MS
    );
    assert_eq!(
        app.config_snapshot.extended.tui.use_emojis,
        FIXTURE_USE_EMOJIS
    );
    // Model-picker ordering: the global LLM mode is now threaded from the held
    // snapshot (the provider list read is owned by `tui-inventory-from-daemon`).
    let choices = crate::tui::model_picker::ordered_model_choices(
        cwd,
        app.config_snapshot.extended.llm_mode,
        &std::collections::HashMap::new(),
    )
    .unwrap();
    let ordering: Vec<(String, String, bool, LlmMode)> = choices
        .into_iter()
        .map(|c| (c.provider_id, c.model_id, c.is_favorite, c.mode))
        .collect();
    assert_eq!(ordering, fixture_model_ordering());
}

// ---- Criterion 1: no client-side config resolution remains -----------------

#[test]
fn tui_has_no_config_disk_reads_outside_bootstrap() {
    fn visit(dir: &Path, hits: &mut Vec<(String, usize, String)>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if path.is_dir() {
                visit(&path, hits);
                continue;
            }
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            if !name.ends_with(".rs") || name.ends_with("_tests.rs") {
                continue;
            }
            let text = std::fs::read_to_string(&path).unwrap();
            for (i, line) in text.lines().enumerate() {
                if line.trim_start().starts_with("//") {
                    continue;
                }
                if line.contains("secret_ref::load_effective(")
                    || line.contains("extended::load_for_cwd(")
                {
                    hits.push((name.clone(), i + 1, line.trim().to_string()));
                }
            }
        }
    }

    let tui_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/tui");
    let mut hits = Vec::new();
    visit(&tui_dir, &mut hits);

    // The only surviving client-side provider read is `model_picker.rs`: the
    // provider list inside `ordered_model_choices` is owned by
    // `tui-inventory-from-daemon`, and its `#[cfg(test)] open` helper reuses it.
    // Every other consumer renders from the held daemon snapshot.
    for (file, line, text) in &hits {
        assert_eq!(
            file, "model_picker.rs",
            "unexpected client-side config resolution at {file}:{line}: {text}"
        );
    }
    assert_eq!(
        hits.len(),
        2,
        "model_picker.rs should retain exactly the sibling-owned provider read \
         and its test helper; found: {hits:?}"
    );
}

// ---- Criterion 2: bootstrap resolves once; credential resolution stops ------

#[test]
fn tui_bootstrap_config_load_happens_once() {
    let tmp = tempfile::tempdir().unwrap();
    let _home = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    write_fixture_tree(tmp.path());
    reset_config_counters();

    let _app = app_for_tree(tmp.path());

    assert_eq!(
        load_for_cwd_count(),
        1,
        "bootstrap performs exactly one ExtendedConfig resolution"
    );
    assert_eq!(
        load_effective_count(),
        0,
        "credential/provider resolution moved daemon-side; bootstrap resolves none"
    );
}

#[test]
fn tui_config_count_stable_across_interactions() {
    let tmp = tempfile::tempdir().unwrap();
    let _home = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    write_fixture_tree(tmp.path());
    let mut app = app_for_tree(tmp.path());
    // Attached: `resync` signals the daemon instead of reading disk.
    app.agent_runner = Some(Ok(stub_runner()));
    // Build the pushed snapshot (daemon-side scaffolding) BEFORE the measured
    // window — its construction reads disk exactly as the daemon would.
    let pushed = snapshot_from_tree(tmp.path(), 1);
    reset_config_counters();

    // attach: apply a pushed snapshot.
    app.apply_event(cockpit_core::engine::TurnEvent::ConfigSnapshot {
        snapshot: Box::new(pushed),
    });
    // /model change: apply an active-model state.
    app.apply_active_model_state("p".to_string(), "a".to_string(), None, None, false, 1);
    // turn-event application: a foreground-target event re-runs skill discovery.
    app.apply_event(cockpit_core::engine::TurnEvent::ForegroundInputTarget {
        target: cockpit_core::engine::message::QueueTarget::root("Build"),
    });
    // /settings close and /new both funnel through `resync`; attached, it must
    // not read disk.
    app.resync_config_after_local_write();
    app.resync_config_after_local_write();

    assert_eq!(
        load_for_cwd_count(),
        0,
        "no ExtendedConfig disk read on any interaction (attached)"
    );
    assert_eq!(
        load_effective_count(),
        0,
        "no provider/credential resolution on any interaction"
    );
}

// ---- Criterion 3: attach seeds the snapshot --------------------------------

#[test]
fn attach_seeds_tui_config_snapshot() {
    let tmp = tempfile::tempdir().unwrap();
    let _home = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    write_fixture_tree(tmp.path());
    let mut app = app_for_tree(tmp.path());
    assert!(
        !app.config_snapshot.from_daemon,
        "starts on the bootstrap seed"
    );

    let snapshot = snapshot_from_tree(tmp.path(), 7);
    app.apply_event(cockpit_core::engine::TurnEvent::ConfigSnapshot {
        snapshot: Box::new(snapshot),
    });

    assert!(app.config_snapshot.from_daemon);
    assert_eq!(app.config_snapshot.generation, 7);
    assert!(app.config_snapshot.providers.providers.contains_key("p"));
}

// ---- Criterion 4: pushes replace the held snapshot -------------------------

#[test]
fn pushed_config_snapshot_replaces_held_snapshot() {
    let tmp = tempfile::tempdir().unwrap();
    let _home = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    write_fixture_tree(tmp.path());
    let mut app = app_for_tree(tmp.path());
    app.apply_config_snapshot(snapshot_from_tree(tmp.path(), 3));

    // A newer generation with a distinct extended value replaces the held one.
    let mut newer = snapshot_from_tree(tmp.path(), 4);
    newer.extended.dialog.lockout_ms = 9999;
    app.apply_config_snapshot(newer);

    assert_eq!(app.config_snapshot.generation, 4);
    assert_eq!(app.config_snapshot.extended.dialog.lockout_ms, 9999);
}

// ---- Criterion 5: stale pushes are dropped ---------------------------------

#[test]
fn stale_config_snapshot_push_is_ignored() {
    let tmp = tempfile::tempdir().unwrap();
    let _home = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    write_fixture_tree(tmp.path());
    let mut app = app_for_tree(tmp.path());
    app.apply_config_snapshot(snapshot_from_tree(tmp.path(), 5));

    let mut stale = snapshot_from_tree(tmp.path(), 4);
    stale.extended.dialog.lockout_ms = 12345;
    app.apply_config_snapshot(stale);

    assert_eq!(
        app.config_snapshot.generation, 5,
        "held generation unchanged"
    );
    assert_ne!(
        app.config_snapshot.extended.dialog.lockout_ms, 12345,
        "stale value must not be applied"
    );
}

// ---- Criterion 6: no optimistic self-write render --------------------------

#[test]
fn settings_write_does_not_optimistically_render() {
    let tmp = tempfile::tempdir().unwrap();
    let _home = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    write_fixture_tree(tmp.path());
    let mut app = app_for_tree(tmp.path());
    // Seed a known held snapshot, then attach so `resync` signals the daemon.
    app.apply_config_snapshot(snapshot_from_tree(tmp.path(), 1));
    app.agent_runner = Some(Ok(stub_runner()));
    let before = app.config_snapshot.extended.dialog.lockout_ms;

    // Simulate the user editing config on disk, then closing `/settings`.
    std::fs::write(
        tmp.path().join(".cockpit/config.json"),
        r#"{"llm_mode":"normal","dialog":{"lockout_ms":8888},"tui":{"use_emojis":false}}"#,
    )
    .unwrap();
    app.resync_config_after_local_write();

    // The UI still shows the old value until the daemon's snapshot arrives.
    assert_eq!(
        app.config_snapshot.extended.dialog.lockout_ms, before,
        "attached write must not optimistically render the self-written value"
    );

    // Once the daemon re-resolves and pushes, the UI updates.
    app.apply_config_snapshot(snapshot_from_tree(tmp.path(), 2));
    assert_eq!(app.config_snapshot.extended.dialog.lockout_ms, 8888);
}

// ---- Criterion 7: detached rendering uses the bootstrap, no disk reads ------

#[test]
fn detached_tui_renders_from_bootstrap_without_disk_reads() {
    let tmp = tempfile::tempdir().unwrap();
    let _home = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    write_fixture_tree(tmp.path());
    let app = app_for_tree(tmp.path());
    // Detached: no runner attached.
    assert!(app.agent_runner.is_none());
    // The bootstrap seed carries the redacted provider projection so the TUI
    // renders provider-dependent chrome before any daemon push.
    assert!(!app.config_snapshot.from_daemon);
    assert!(app.config_snapshot.providers.providers.contains_key("p"));
    assert_eq!(app.config_snapshot.extended.dialog.lockout_ms, 2500);

    reset_config_counters();
    // Reading rendered config off the held snapshot must not touch disk.
    let _ = app.visible_skills();
    let _ = app.config_snapshot.extended.tui.use_emojis;
    assert_eq!(load_for_cwd_count(), 0);
    assert_eq!(load_effective_count(), 0);
}
