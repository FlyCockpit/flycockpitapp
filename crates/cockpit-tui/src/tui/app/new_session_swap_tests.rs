use super::App;

#[test]
fn new_session_swap_loads_extended_config_once() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new_with_db(
        Some(tmp.path()),
        false,
        cockpit_db::Db::open_in_memory().unwrap(),
    );
    cockpit_config::extended::reset_load_for_cwd_call_count();

    app.pending_new_session = true;
    let serviced = app
        .maybe_service_new_session_with_clear(|| Ok(()))
        .expect("/new should be serviced");

    assert!(serviced);
    assert_eq!(cockpit_config::extended::load_for_cwd_call_count(), 1);
}
