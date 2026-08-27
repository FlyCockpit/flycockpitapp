use crate::support::{IsolatedHome, SpawnedDaemon, assert_success, output_text};

#[test]
fn reports_unopenable_database() {
    let mut home = IsolatedHome::new();
    home.set_env("XDG_DATA_HOME", "/dev/null");

    let output = home
        .cockpit()
        .args(["--no-sandbox", "doctor", "--offline"])
        .output()
        .unwrap();
    let text = output_text(&output);
    assert_eq!(output.status.code(), Some(1), "{text}");
    assert!(text.contains("database:"), "{text}");
    assert!(text.contains("openability: FAILED"), "{text}");
    assert!(text.contains("schema: unavailable"), "{text}");
}

#[tokio::test]
async fn reports_amended_migration() {
    // Doctor is read-only and never materializes SQLite. Boot (then stop) a
    // real daemon so the ledger exists, then amend it and re-run doctor.
    let daemon = SpawnedDaemon::start().await;
    let stop = daemon
        .command()
        .args(["daemon", "stop", "--grace", "0"])
        .output()
        .unwrap();
    assert_success(
        "stop daemon before amending migration ledger",
        &stop,
        daemon.home(),
    );

    let conn = rusqlite::Connection::open(daemon.db_path()).unwrap();
    conn.execute(
        "UPDATE schema_version SET sha256 = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' WHERE version = 1",
        [],
    )
    .unwrap();
    drop(conn);

    let output = daemon
        .command()
        .args(["--no-sandbox", "doctor", "--offline"])
        .output()
        .unwrap();
    let text = output_text(&output);
    assert_eq!(output.status.code(), Some(1), "{text}");
    assert!(text.contains("openability: ok (SQLite opened"), "{text}");
    assert!(text.contains("schema: FAILED"), "{text}");
    assert!(text.contains("migration checksum mismatch"), "{text}");
    assert!(text.contains("applied migration was amended"), "{text}");
}

#[test]
fn reports_daemon_status_without_starting_it() {
    let home = IsolatedHome::new();
    home.write_local_provider_config("http://127.0.0.1:9/v1");
    assert!(!home.socket_path().exists());
    assert!(!home.pid_file().exists());

    let output = home
        .cockpit()
        .args(["--no-sandbox", "doctor", "--offline"])
        .output()
        .unwrap();
    let text = output_text(&output);
    assert_eq!(output.status.code(), Some(0), "{text}");
    assert!(text.contains("daemon:"), "{text}");
    assert!(text.contains("status: informational"), "{text}");
    assert!(
        !home.socket_path().exists(),
        "doctor must not start a daemon"
    );
    assert!(!home.pid_file().exists(), "doctor must not start a daemon");
}

#[test]
fn no_providers_exits_one() {
    let home = IsolatedHome::new();
    let output = home
        .cockpit()
        .args(["doctor", "--offline"])
        .output()
        .unwrap();
    let text = output_text(&output);
    assert_eq!(output.status.code(), Some(1), "{text}");
    assert!(text.contains("no providers configured"), "{text}");
}

#[test]
fn output_is_secret_free() {
    let home = IsolatedHome::new();
    home.write_local_provider_config("http://127.0.0.1:9/v1");
    let config = home.config_dir();
    let provider_path = config.join("providers/local.json");
    let mut provider: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&provider_path).unwrap()).unwrap();
    provider
        .as_object_mut()
        .expect("local provider fixture must be an object")
        .remove("auth");
    provider["headers"] = serde_json::json!([
        {"name": "authorization", "value": "Bearer doctor-secret-value-12345"}
    ]);
    std::fs::write(provider_path, serde_json::to_vec(&provider).unwrap()).unwrap();

    let output = home
        .cockpit()
        .args(["doctor", "--offline"])
        .output()
        .unwrap();
    let text = output_text(&output);
    assert!(
        text.contains("local credentials: ok (literal header)"),
        "{text}"
    );
    assert!(!text.contains("doctor-secret-value-12345"), "{text}");
}

#[tokio::test]
async fn exit_codes() {
    let clean_home = IsolatedHome::new();
    clean_home.write_local_provider_config("http://127.0.0.1:9/v1");
    let daemon = SpawnedDaemon::start_with_home(clean_home).await;
    let clean = daemon
        .command()
        .args(["--no-sandbox", "doctor", "--offline"])
        .output()
        .unwrap();
    assert_eq!(clean.status.code(), Some(0), "{}", output_text(&clean));

    let problem = IsolatedHome::new()
        .cockpit()
        .args(["doctor", "--offline"])
        .output()
        .unwrap();
    assert_eq!(problem.status.code(), Some(1), "{}", output_text(&problem));

    let mut unable_home = IsolatedHome::new();
    unable_home.set_env("COCKPIT_TEST_DOCTOR_FORCE_FAILURE", "1");
    let unable = unable_home
        .cockpit()
        .args(["doctor", "--offline"])
        .output()
        .unwrap();
    let text = output_text(&unable);
    assert_eq!(unable.status.code(), Some(2), "{text}");
    assert!(text.contains("doctor itself could not run"), "{text}");
    assert!(
        !unable_home.socket_path().exists(),
        "an execution failure must not start a daemon"
    );
    assert!(
        !unable_home.pid_file().exists(),
        "an execution failure must not create a daemon pid file"
    );
}
