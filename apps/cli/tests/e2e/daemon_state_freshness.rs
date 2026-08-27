use std::process::Stdio;
use std::time::Duration;

use crate::support::{IsolatedHome, SpawnedDaemon, assert_failure, assert_success, output_text};
use cockpit_cli::integration::{DaemonClient, DaemonEvent};
use cockpit_test_support::provider::{ScriptedProvider, Turn};
use rusqlite::{Connection, params};

async fn text_provider() -> ScriptedProvider {
    ScriptedProvider::builder()
        .turn(Turn::Text("ephemeral history intact".into()))
        .repeat_last()
        .start()
        .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn daemon_trust_read_through() {
    // Keep the provider alive for the daemon lifetime; dropping it closes the listener.
    let provider = text_provider().await;
    let home = IsolatedHome::new();
    home.write_local_provider_config(&provider.base_url());
    let daemon = SpawnedDaemon::start_with_home(home).await;
    let client = daemon.client().await;

    let refusal = client
        .attach(daemon.project_path(), None, None, false)
        .await
        .expect_err("unset trust must fail closed")
        .to_string();
    assert!(refusal.contains("workspace trust is not set"), "{refusal}");
    assert!(!refusal.contains("internal:"), "{refusal}");

    let trust = daemon
        .command()
        .args([
            "trust",
            "set",
            &daemon.project_path().display().to_string(),
            "--mode",
            "trust",
        ])
        .output()
        .expect("set trust in separate process");
    assert!(trust.status.success(), "{}", output_text(&trust));

    client
        .attach(daemon.project_path(), None, None, false)
        .await
        .expect("same live daemon reads newly committed trust");

    let status = daemon
        .command()
        .args(["daemon", "status", "--json"])
        .output()
        .expect("daemon JSON status");
    assert!(status.status.success(), "{}", output_text(&status));
    let json: serde_json::Value = serde_json::from_slice(&status.stdout).expect("status JSON");
    assert_eq!(
        json["database_path"],
        daemon.db_path().display().to_string()
    );
    assert_eq!(
        json["schema_version"],
        cockpit_cli::db::EXPECTED_SCHEMA_VERSION
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ephemeral_session_resumes_on_shared_daemon() {
    // Keep the provider alive for the daemon lifetime; dropping it closes the listener.
    let provider = text_provider().await;
    let home = IsolatedHome::new();
    home.write_local_provider_config(&provider.base_url());
    home.trust_project();
    // `trust set` starts a persistent daemon that holds the exclusive boot
    // lock. Ephemeral and persistent cannot share that lock; stop the
    // trust-started process before the explicit ephemeral daemon boots.
    let stop_trust_daemon = home
        .cockpit()
        .args(["daemon", "stop", "--grace", "0"])
        .output()
        .expect("stop trust-started persistent daemon");
    assert_success(
        "stop trust-started persistent daemon",
        &stop_trust_daemon,
        &home,
    );

    let ephemeral_socket = home
        .socket_path()
        .with_file_name("cockpit-freshness-ephemeral.sock");
    let ephemeral_pid = home
        .pid_file()
        .with_file_name("cockpit-freshness-ephemeral.pid");
    std::fs::create_dir_all(ephemeral_pid.parent().expect("ephemeral pid parent"))
        .expect("create ephemeral pid parent");
    let mut daemon_command = home.cockpit();
    daemon_command
        .args(["daemon", "start", "--foreground"])
        .env("COCKPIT_EPHEMERAL_SOCKET", &ephemeral_socket)
        .env("COCKPIT_EPHEMERAL_PID_FILE", &ephemeral_pid)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut ephemeral_process = daemon_command
        .spawn()
        .expect("spawn explicit ephemeral daemon process");
    let socket_deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !ephemeral_socket.exists() {
        if let Some(status) = ephemeral_process
            .try_wait()
            .expect("probe ephemeral daemon")
        {
            let output = ephemeral_process
                .wait_with_output()
                .expect("collect failed ephemeral daemon output");
            panic!(
                "ephemeral daemon exited before binding ({status}): {}",
                output_text(&output)
            );
        }
        assert!(
            tokio::time::Instant::now() < socket_deadline,
            "timed out waiting for ephemeral daemon socket"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let ephemeral_client = DaemonClient::connect(&ephemeral_socket)
        .await
        .expect("connect explicit ephemeral daemon");
    let attached = ephemeral_client
        .attach(home.project_path(), None, None, false)
        .await
        .expect("attach ephemeral session");
    let session_id = attached.session_id;
    let attached_row_count: i64 = Connection::open(home.db_path())
        .expect("open DB after ephemeral attach")
        .query_row(
            "SELECT COUNT(*) FROM sessions WHERE session_id = ?1",
            params![session_id.to_string()],
            |row| row.get(0),
        )
        .expect("query attached session row");
    assert_eq!(
        attached_row_count, 1,
        "ephemeral attach returned before its session row was durable"
    );
    ephemeral_client
        .send_user_message("remember this across daemon processes")
        .await
        .expect("send ephemeral message");
    loop {
        match ephemeral_client
            .next_event(Duration::from_secs(20))
            .await
            .expect("ephemeral daemon event")
        {
            DaemonEvent::AssistantText {
                session_id: got,
                text,
            } if got == session_id && text.contains("ephemeral history intact") => break,
            _ => {}
        }
    }
    ephemeral_client
        .stop()
        .await
        .expect("gracefully stop ephemeral daemon");
    drop(ephemeral_client);
    let ephemeral_output = ephemeral_process
        .wait_with_output()
        .expect("wait for ephemeral daemon exit");
    assert_success(
        "ephemeral daemon foreground process",
        &ephemeral_output,
        &home,
    );

    let conn = Connection::open(home.db_path()).expect("open session DB after ephemeral run");
    let durable_user_message: String = conn
        .query_row(
            "SELECT data_json FROM session_events \
             WHERE session_id = ?1 AND type = 'user_message' ORDER BY seq LIMIT 1",
            params![session_id.to_string()],
            |row| row.get(0),
        )
        .expect("durable ephemeral user message");
    assert!(
        durable_user_message.contains("remember this across daemon processes"),
        "{durable_user_message}"
    );
    let durable_assistant_message: String = conn
        .query_row(
            "SELECT data_json FROM session_events \
             WHERE session_id = ?1 AND type = 'assistant_message' ORDER BY seq LIMIT 1",
            params![session_id.to_string()],
            |row| row.get(0),
        )
        .expect("durable ephemeral assistant message");
    assert!(
        durable_assistant_message.contains("ephemeral history intact"),
        "{durable_assistant_message}"
    );
    drop(conn);

    let list = home
        .cockpit()
        .args(["session", "list"])
        .output()
        .expect("list sessions after ephemeral exit");
    assert_success("cockpit session list", &list, &home);
    assert!(output_text(&list).contains(&session_id.to_string()));

    let shared = SpawnedDaemon::start_with_home(home).await;
    let resumed = shared
        .client()
        .await
        .attach(shared.project_path(), Some(session_id), None, false)
        .await
        .expect("shared daemon rehydrates ephemeral-born session");
    assert_eq!(resumed.session_id, session_id);
    assert!(
        resumed.history_len >= 2,
        "history was not rehydrated: {resumed:?}"
    );
}

#[tokio::test]
async fn daemon_refuses_newer_migration_ledger() {
    // Doctor is read-only and never materializes SQLite. Boot (then stop) a
    // real daemon so the ledger exists before we seed a future migration row.
    let daemon = SpawnedDaemon::start().await;
    let stop = daemon
        .command()
        .args(["daemon", "stop", "--grace", "0"])
        .output()
        .expect("stop daemon before seeding newer migration ledger");
    assert_success(
        "stop daemon before seeding newer migration ledger",
        &stop,
        daemon.home(),
    );

    let conn = Connection::open(daemon.db_path()).expect("open current DB");
    let fingerprint: String = conn
        .query_row(
            "SELECT schema_fingerprint FROM schema_version WHERE version = ?1",
            [cockpit_cli::db::EXPECTED_SCHEMA_VERSION],
            |row| row.get(0),
        )
        .expect("read current schema fingerprint");
    conn.execute(
        "INSERT INTO schema_version (version, name, sha256, schema_fingerprint, schema_profile, applied_at) \
         VALUES (?1, 'future', ?2, ?3, 'local-v0.1', CURRENT_TIMESTAMP)",
        rusqlite::params![
            cockpit_cli::db::EXPECTED_SCHEMA_VERSION + 1,
            "0".repeat(64),
            fingerprint
        ],
    )
    .expect("seed newer migration ledger");
    drop(conn);

    let output = daemon
        .command()
        .args(["daemon", "start", "--foreground"])
        .output()
        .expect("start daemon against newer migration ledger");
    assert_failure("newer-ledger daemon start", &output, daemon.home());
    let text = output_text(&output);
    assert!(
        text.contains("incompatible prerelease database schema v2")
            && text.contains("Restore a compatible migration backup or move the database aside"),
        "{text}"
    );
    assert!(
        !daemon.home().pid_file().exists(),
        "newer-ledger daemon pid file survived"
    );
    assert!(
        !daemon.socket_path().exists(),
        "newer-ledger daemon socket survived"
    );
    let endpoint = daemon
        .home()
        .pid_file()
        .parent()
        .expect("daemon state dir")
        .join("daemon-endpoint.json");
    assert!(!endpoint.exists(), "newer-ledger daemon endpoint survived");
}
