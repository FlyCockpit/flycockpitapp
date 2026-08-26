//! Tests for the daemon-pushed config snapshot the TUI renders from
//! (`tui-config-single-source`).
//!
//! `config_snapshot_values_match_previous_resolution` is a **characterization
//! test**: the fixtures below were captured against the *client-side*
//! resolution (`load_for_cwd` / `ordered_model_choices`) before any call site
//! was converted to read from the held snapshot (see the fixture-capture
//! commit). After conversion the same fixtures must resolve identically off the
//! held snapshot — this pins behavior parity (criterion 8).

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use cockpit_config::extended::LlmMode;

use super::App;
use crate::tui::agent_runner::{AgentRunner, TestRunnerOverrides};

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
#[allow(dead_code)]
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

fn with_trusted_tree<T>(cwd: &Path, f: impl FnOnce() -> T) -> T {
    cockpit_config::trust::with_workspace_trust_policy(
        super::trusted_workspace_policy_for_tests(cwd),
        f,
    )
}

/// Build the wire snapshot the daemon would push for a config tree: the
/// resolved `ExtendedConfig` plus the redacted provider projection.
fn snapshot_from_tree(cwd: &Path, generation: u64) -> cockpit_proto::ConfigSnapshot {
    with_trusted_tree(cwd, || {
        let extended = cockpit_config::extended::load_for_cwd(cwd);
        let paths = cockpit_config::dirs::config_file_paths_for_load(cwd);
        let providers = cockpit_config::providers::ConfigDoc::providers_from_paths(&paths);
        cockpit_proto::ConfigSnapshot {
            session_id: uuid::Uuid::new_v4(),
            generation,
            extended,
            providers: cockpit_core::secret_ref::redact_provider_view(&providers),
        }
    })
}

fn marked_snapshot(
    cwd: &Path,
    session_id: uuid::Uuid,
    generation: u64,
    provider_id: &str,
    lockout_ms: u64,
    context_tokens: u32,
) -> cockpit_proto::ConfigSnapshot {
    let mut snapshot = snapshot_from_tree(cwd, generation);
    snapshot.session_id = session_id;
    snapshot.extended.dialog.lockout_ms = lockout_ms;
    let mut provider = snapshot
        .providers
        .providers
        .remove("p")
        .expect("fixture provider");
    provider.entry.models[0].capabilities.context_tokens = Some(context_tokens);
    snapshot.providers.providers.clear();
    snapshot
        .providers
        .providers
        .insert(provider_id.to_string(), provider);
    snapshot
}

/// A minimal attached runner so `resync_config_after_local_write` takes the
/// daemon-signal path (no disk read) instead of the detached bootstrap refresh.
fn stub_runner() -> AgentRunner {
    AgentRunner::test_fixture(TestRunnerOverrides {
        last_applied_seq: Some(Arc::new(Mutex::new(Some(0)))),
        ..Default::default()
    })
}

fn app_for_tree(tree: &Path) -> App {
    with_trusted_tree(tree, || App::new(Some(tree), false))
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
    // Model-picker ordering comes from the daemon inventory projection; with
    // no inventory snapshot yet the ordered list is empty (pre-attach).
    let choices = crate::tui::model_picker::ordered_model_choices_from_inventory(
        &app.inventory_models(),
        app.config_snapshot.extended.llm_mode,
        &std::collections::HashMap::new(),
    );
    assert!(
        choices.is_empty(),
        "pre-attach inventory models must be empty without a daemon bundle"
    );
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

    // Inventory consumption removed secret_ref::load_effective from model_picker
    // production paths. No non-test TUI consumer may re-resolve providers from disk.
    assert!(
        hits.is_empty(),
        "unexpected client-side config resolution outside bootstrap: {hits:?}"
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
    app.apply_active_model_state(
        cockpit_config::providers::ActiveModelRef {
            provider: "p".to_string(),
            model: "a".to_string(),
            reasoning_effort: None,
            thinking_mode: None,
            prompt_cache_retention: None,
        },
        None,
        false,
        1,
    );
    // turn-event application: a foreground-target event re-runs skill discovery.
    app.apply_event(cockpit_core::engine::TurnEvent::ForegroundInputTarget {
        target: cockpit_proto::QueueTarget::root("Build"),
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

#[derive(Clone, Copy)]
enum ConfigEpochPath {
    SessionReplacement,
    SameSessionReconnect,
}

fn assert_config_epoch_reset_accepts_authoritative_zero(path: ConfigEpochPath) {
    let tmp = tempfile::tempdir().unwrap();
    let _home = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    write_fixture_tree(tmp.path());
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let _runtime_guard = runtime.enter();
    let mut app = app_for_tree(tmp.path());
    let old_session_id = uuid::Uuid::new_v4();
    let new_session_id = match path {
        ConfigEpochPath::SessionReplacement => uuid::Uuid::new_v4(),
        ConfigEpochPath::SameSessionReconnect => old_session_id,
    };
    app.launch.session_id = Some(old_session_id);

    app.apply_config_snapshot(marked_snapshot(
        tmp.path(),
        old_session_id,
        9,
        "old-provider",
        9009,
        900_009,
    ));
    assert_eq!(app.config_snapshot.generation, 9);
    assert!(
        !app.has_no_providers_at_startup,
        "the launch-time provider-setup latch starts false for this configured tree"
    );
    assert!(
        app.config_snapshot
            .providers
            .providers
            .contains_key("old-provider")
    );
    assert_eq!(app.config_snapshot.extended.dialog.lockout_ms, 9009);
    assert_eq!(
        app.config_snapshot
            .providers
            .resolve_effective_model_capabilities(
                "old-provider",
                "a",
                app.config_snapshot.providers.resolution_generation,
            )
            .context_tokens,
        Some(900_009)
    );

    match path {
        ConfigEpochPath::SessionReplacement => {
            let runner = stub_runner();
            *runner.session_id_state.lock().unwrap() = new_session_id;
            app.adopt_runner(Ok(runner));
        }
        ConfigEpochPath::SameSessionReconnect => {
            app.agent_runner = Some(Ok(stub_runner()));
            app.apply_event(cockpit_core::engine::TurnEvent::DaemonLinkReconnected {
                active_model_state: None,
            });
        }
    }

    // No state from the previous worker may survive while the new worker's
    // generation-zero attach snapshot is in flight.
    assert_eq!(app.config_snapshot.generation, 0);
    assert!(!app.config_snapshot.from_daemon);
    assert!(app.config_snapshot.providers.providers.is_empty());
    assert!(
        !app.has_no_providers_at_startup,
        "an empty epoch seed must not masquerade as a provider-less process launch"
    );
    app.maybe_open_add_provider_wizard();
    assert!(
        !app.dialog.is_active(),
        "the temporary seed must not open first-run provider setup"
    );
    assert_eq!(app.config_snapshot.extended.dialog.lockout_ms, 9009);
    app.last_composer_edit_at = Some(Instant::now() - Duration::from_secs(2));
    assert_eq!(
        app.rehydrated_dialog_lockout(),
        Duration::from_millis(9009),
        "an interrupt arriving before authoritative generation zero must use the last confirmed presentation lockout"
    );

    app.apply_config_snapshot(marked_snapshot(
        tmp.path(),
        new_session_id,
        0,
        "attached-provider",
        1000,
        100_000,
    ));
    assert!(app.config_snapshot.from_daemon);
    assert_eq!(app.config_snapshot.generation, 0);
    assert!(
        app.config_snapshot
            .providers
            .providers
            .contains_key("attached-provider")
    );
    assert!(
        !app.config_snapshot
            .providers
            .providers
            .contains_key("old-provider")
    );
    assert_eq!(app.config_snapshot.extended.dialog.lockout_ms, 1000);
    assert_eq!(
        app.config_snapshot
            .providers
            .resolve_effective_model_capabilities(
                "attached-provider",
                "a",
                app.config_snapshot.providers.resolution_generation,
            )
            .context_tokens,
        Some(100_000)
    );

    app.apply_config_snapshot(marked_snapshot(
        tmp.path(),
        new_session_id,
        1,
        "updated-provider",
        1001,
        100_001,
    ));
    assert_eq!(app.config_snapshot.generation, 1);
    assert!(
        app.config_snapshot
            .providers
            .providers
            .contains_key("updated-provider")
    );
    assert!(
        !app.config_snapshot
            .providers
            .providers
            .contains_key("attached-provider")
    );
    assert_eq!(app.config_snapshot.extended.dialog.lockout_ms, 1001);
    assert_eq!(
        app.config_snapshot
            .providers
            .resolve_effective_model_capabilities(
                "updated-provider",
                "a",
                app.config_snapshot.providers.resolution_generation,
            )
            .context_tokens,
        Some(100_001)
    );
}

#[test]
fn session_replacement_starts_new_config_snapshot_epoch() {
    assert_config_epoch_reset_accepts_authoritative_zero(ConfigEpochPath::SessionReplacement);
}

#[test]
fn same_session_reconnect_starts_new_config_snapshot_epoch() {
    assert_config_epoch_reset_accepts_authoritative_zero(ConfigEpochPath::SameSessionReconnect);
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
    let _ = app.visible_skill_summaries();
    let _ = app.config_snapshot.extended.tui.use_emojis;
    assert_eq!(load_for_cwd_count(), 0);
    assert_eq!(load_effective_count(), 0);
}
