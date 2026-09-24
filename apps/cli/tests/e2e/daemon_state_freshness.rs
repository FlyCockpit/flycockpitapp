use std::process::Stdio;
use std::time::Duration;

use crate::support::{
    DAEMON_START_HANDSHAKE_TIMEOUT, EphemeralDaemonGuard, IsolatedHome, SpawnedDaemon,
    assert_failure, assert_success, output_text, wait_for_daemon_handshake_on_socket,
};
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
async fn one_shot_run_seeds_trust_in_never_trusted_home() {
    let provider = text_provider().await;
    let home = IsolatedHome::new();
    home.write_local_provider_config(&provider.base_url());
    let output = home
        .cockpit()
        .args(["--no-sandbox", "run", "--format", "json", "hello"])
        .output()
        .expect("one-shot run in a never-trusted home");
    assert_success("one-shot run without prior trust set", &output, &home);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("session_attached") || stdout.contains("assistant"),
        "one-shot run must complete a turn: {}",
        output_text(&output)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ephemeral_session_resumes_on_shared_daemon() {
    // Keep the provider alive for the daemon lifetime; dropping it closes the listener.
    let provider = text_provider().await;
    let home = IsolatedHome::new();
    home.write_local_provider_config(&provider.base_url());

    // Ephemeral ownership is a lifetime policy on the canonical ledger
    // endpoint. A shared follow-up daemon must discover the exact same socket
    // and durable session after this owner exits.
    let ephemeral_socket = home.socket_path();
    let launch_ticket = format!(
        "{:032x}{:032x}",
        uuid::Uuid::new_v4().as_u128(),
        uuid::Uuid::new_v4().as_u128()
    );
    let mut daemon_command = home.cockpit();
    daemon_command
        .args(["daemon", "start", "--foreground"])
        .env("COCKPIT_DAEMON_LIFETIME", "ephemeral")
        .env("COCKPIT_DAEMON_LAUNCH_TICKET", launch_ticket)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let child = daemon_command
        .spawn()
        .expect("spawn explicit ephemeral daemon process");
    let ephemeral_guard = EphemeralDaemonGuard::new(child, home.rendezvous_files());
    wait_for_daemon_handshake_on_socket(
        &ephemeral_socket,
        &home.pid_file(),
        DAEMON_START_HANDSHAKE_TIMEOUT,
        || {
            if let Ok(Some(status)) = ephemeral_guard.try_wait() {
                panic!(
                    "ephemeral daemon exited before handshake ({status}): socket={}",
                    ephemeral_socket.display()
                );
            }
            None
        },
    )
    .await;
    // Establish trust through the already-published exact child. Starting
    // trust first would auto-spawn an unowned persistent daemon.
    home.trust_project();
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
    let ephemeral_output = ephemeral_guard
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ephemeral_supervisor_exits_after_last_lifetime_client_disconnects() {
    let home = IsolatedHome::new();
    let socket = home.socket_path();
    let pid_file = home.pid_file();
    let mut daemon_command = home.cockpit();
    daemon_command
        .args(["daemon", "start", "--foreground"])
        .env("COCKPIT_DAEMON_LIFETIME", "ephemeral")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let child = daemon_command
        .spawn()
        .expect("spawn foreground ephemeral supervisor");
    let supervisor = EphemeralDaemonGuard::new(child, home.rendezvous_files());
    wait_for_daemon_handshake_on_socket(&socket, &pid_file, DAEMON_START_HANDSHAKE_TIMEOUT, || {
        if let Ok(Some(status)) = supervisor.try_wait() {
            panic!("ephemeral supervisor exited before handshake: {status}");
        }
        None
    })
    .await;

    let client = DaemonClient::connect(&socket)
        .await
        .expect("connect lifetime client before any transient command disconnects");
    let rendezvous: serde_json::Value = serde_json::from_slice(
        &std::fs::read(home.rendezvous_files().rendezvous)
            .expect("read ephemeral supervisor rendezvous"),
    )
    .expect("decode ephemeral supervisor rendezvous");
    assert_eq!(rendezvous["ephemeral"], true);
    assert!(rendezvous["worker_pid"].as_u64().is_some());

    drop(client);
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        if supervisor
            .try_wait()
            .expect("poll ephemeral supervisor exit")
            .is_some()
        {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "ephemeral supervisor must exit after its final lifetime client disconnects"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let output = supervisor
        .wait_with_output()
        .expect("reap exited ephemeral supervisor");
    assert_success("ephemeral supervisor natural reap", &output, &home);
    assert!(
        !pid_file.exists(),
        "supervisor must retract its pid metadata"
    );
    assert!(!socket.exists(), "supervisor must retract its endpoint");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ephemeral_supervisor_suppresses_reaping_during_worker_roll() {
    let home = IsolatedHome::new();
    let socket = home.socket_path();
    let pid_file = home.pid_file();
    let mut daemon_command = home.cockpit();
    daemon_command
        .args(["daemon", "start", "--foreground"])
        .env("COCKPIT_DAEMON_LIFETIME", "ephemeral")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let child = daemon_command
        .spawn()
        .expect("spawn foreground ephemeral supervisor");
    let supervisor = EphemeralDaemonGuard::new(child, home.rendezvous_files());
    wait_for_daemon_handshake_on_socket(&socket, &pid_file, DAEMON_START_HANDSHAKE_TIMEOUT, || {
        if let Ok(Some(status)) = supervisor.try_wait() {
            panic!("ephemeral supervisor exited before handshake: {status}");
        }
        None
    })
    .await;

    let client = DaemonClient::connect(&socket)
        .await
        .expect("connect lifetime client before roll");
    let before: serde_json::Value = serde_json::from_slice(
        &std::fs::read(home.rendezvous_files().rendezvous).expect("read pre-roll rendezvous"),
    )
    .expect("decode pre-roll rendezvous");
    let output = home
        .cockpit()
        .args(["daemon", "restart", "--grace", "0"])
        .output()
        .expect("roll ephemeral worker");
    assert_success("roll ephemeral worker", &output, &home);

    assert_eq!(
        supervisor.try_wait().expect("poll supervisor after roll"),
        None,
        "the ephemeral supervisor must survive the roll reconnect gap"
    );
    let replacement = DaemonClient::connect(&socket)
        .await
        .expect("connect to rolled ephemeral worker");
    let after: serde_json::Value = serde_json::from_slice(
        &std::fs::read(home.rendezvous_files().rendezvous).expect("read post-roll rendezvous"),
    )
    .expect("decode post-roll rendezvous");
    assert_eq!(before["pid"], after["pid"]);
    assert_eq!(before["opened_at_unix_ms"], after["opened_at_unix_ms"]);
    assert_ne!(before["worker_pid"], after["worker_pid"]);
    assert!(after["generation"].as_u64() > before["generation"].as_u64());

    drop(client);
    drop(replacement);
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while supervisor
        .try_wait()
        .expect("poll ephemeral supervisor exit")
        .is_none()
    {
        assert!(
            std::time::Instant::now() < deadline,
            "ephemeral supervisor must reap after rolled worker loses its final lifetime client"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let output = supervisor
        .wait_with_output()
        .expect("reap rolled ephemeral supervisor");
    assert_success("rolled ephemeral supervisor natural reap", &output, &home);
}

#[tokio::test]
async fn daemon_refuses_newer_migration_ledger() {
    // Doctor is read-only and never materializes SQLite. Boot (then stop) a
    // real daemon so the ledger exists before we seed a future migration row.
    let daemon = SpawnedDaemon::start().await;
    let stop = daemon.stop_via_command(0);
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
    let endpoint = daemon.home().rendezvous_files().rendezvous;
    assert!(!endpoint.exists(), "newer-ledger daemon endpoint survived");
}
