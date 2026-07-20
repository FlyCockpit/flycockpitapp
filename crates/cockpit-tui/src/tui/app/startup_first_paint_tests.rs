use super::App;
use crate::tui::agent_runner::GuidanceEstimate;

fn reset_startup_counters() {
    crate::config::extended::reset_load_for_cwd_call_count();
    crate::config::providers::reset_load_effective_call_count();
    crate::container::reset_detect_runtime_call_count();
    crate::daemon::reset_blocking_probe_call_count();
    crate::db::reset_open_default_call_count();
    crate::tokens::reset_count_call_count();
}

#[test]
fn app_new_loads_launch_config_once_and_defers_first_paint_work() {
    let tmp = tempfile::tempdir().unwrap();
    let db = crate::db::Db::open_in_memory().unwrap();
    reset_startup_counters();

    let app = App::new_with_db(Some(tmp.path()), false, db);

    assert_eq!(crate::config::extended::load_for_cwd_call_count(), 1);
    assert_eq!(crate::config::providers::load_effective_call_count(), 1);
    assert_eq!(crate::daemon::blocking_probe_call_count(), 1);
    assert_eq!(crate::db::open_default_call_count(), 0);
    assert_eq!(crate::container::detect_runtime_call_count(), 0);
    assert_eq!(crate::tokens::count_call_count(), 0);
    assert!(app.guidance_estimate.is_none());
    assert!(!app.startup_background.started);
}

#[test]
fn startup_guidance_backfill_discards_stale_session_or_model() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new_with_db(
        Some(tmp.path()),
        false,
        crate::db::Db::open_in_memory().unwrap(),
    );
    app.launch.active_model = Some(("provider".to_string(), "model-a".to_string()));
    let estimate = GuidanceEstimate {
        file: Some("AGENTS.md".to_string()),
        guidance_tokens: 10,
        system_tokens: 20,
        model_instruction_tokens: 0,
    };

    app.apply_startup_guidance_estimate(
        app.launch.cwd.clone(),
        Some(("provider".to_string(), "model-b".to_string())),
        estimate.clone(),
    );
    assert!(app.guidance_estimate.is_none());

    app.apply_startup_guidance_estimate(
        app.launch.cwd.join("other"),
        app.launch.active_model.clone(),
        estimate.clone(),
    );
    assert!(app.guidance_estimate.is_none());

    app.apply_startup_guidance_estimate(
        app.launch.cwd.clone(),
        app.launch.active_model.clone(),
        estimate,
    );
    assert_eq!(
        app.guidance_estimate.as_ref().map(|e| e.system_tokens),
        Some(20)
    );
}

#[tokio::test]
async fn startup_background_tasks_are_explicitly_started_after_construction() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new_with_db(
        Some(tmp.path()),
        false,
        crate::db::Db::open_in_memory().unwrap(),
    );
    assert!(!app.startup_background.started);
    assert_eq!(app.async_actions.pending_count(), 0);

    app.start_startup_background_tasks();

    assert!(app.startup_background.started);
    assert!(app.async_actions.pending_count() >= 2);
}
