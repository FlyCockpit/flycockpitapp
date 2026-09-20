use std::cell::Cell;
use std::path::Path;
use std::time::{Duration, Instant};

use crate::support::{COMPOSER_PLACEHOLDER, HermeticCockpit, HermeticProfile};
use rusqlite::{Connection, params};
use uuid::Uuid;

const HISTORY_MARKER: &str = "watchdog-history-marker-437";
const SECOND_HISTORY_MARKER: &str = "watchdog-second-marker-437";

fn session_id_with_durable_marker(db_path: &Path, marker: &str) -> Uuid {
    let session_id: String = Connection::open(db_path)
        .expect("open hermetic session db")
        .query_row(
            "SELECT session_id FROM session_events \
             WHERE type = 'user_message' AND data_json LIKE ?1 \
             ORDER BY seq DESC LIMIT 1",
            params![format!("%{marker}%")],
            |row| row.get(0),
        )
        .expect("durable user message with history marker");
    Uuid::parse_str(&session_id).expect("session id in sqlite")
}

fn session_has_durable_user_message(db_path: &Path, session_id: Uuid, marker: &str) -> bool {
    Connection::open(db_path)
        .expect("open hermetic session db")
        .query_row(
            "SELECT 1 FROM session_events \
             WHERE session_id = ?1 AND type = 'user_message' AND data_json LIKE ?2 LIMIT 1",
            params![session_id.to_string(), format!("%{marker}%")],
            |_| Ok(()),
        )
        .is_ok()
}

fn assert_session_retains_markers(db_path: &Path, session_id: Uuid, markers: &[&str]) {
    for marker in markers {
        assert!(
            session_has_durable_user_message(db_path, session_id, marker),
            "session {session_id} must retain durable user message {marker}"
        );
    }
}

fn submit_durable_marker(session: &mut HermeticCockpit, marker: &str) {
    session.write_str(marker);
    session
        .wait_until_screen("marker draft", Duration::from_secs(5), |screen| {
            screen.contains(marker)
        })
        .expect("marker must reach the composer before submit");
    session.send_enter();
}

fn wait_until_durable_marker(db_path: &Path, session_id: Uuid, marker: &str, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if session_has_durable_user_message(db_path, session_id, marker) {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let actual = session_id_with_durable_marker(db_path, marker);
    panic!(
        "session {session_id} must retain durable user message {marker} within {timeout:?}; \
         marker is stored under {actual}"
    );
}

fn attach_with_durable_history() -> HermeticCockpit {
    let mut session = HermeticCockpit::launch_ready(HermeticProfile::Default);
    submit_durable_marker(&mut session, HISTORY_MARKER);
    session
        .wait_until_screen(
            "durable history marker",
            Duration::from_secs(10),
            |screen| screen.contains(HISTORY_MARKER) && screen.contains(COMPOSER_PLACEHOLDER),
        )
        .expect("submitted history is visible before daemon replacement");
    std::thread::sleep(Duration::from_millis(500));
    session
}

fn wait_for_replacement_rendezvous(
    session: &HermeticCockpit,
    old_worker_pid: u32,
) -> serde_json::Value {
    let path = session.home().pid_file().with_file_name("daemon.json");
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(bytes) = std::fs::read(&path)
            && let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes)
            && value["worker_pid"].as_u64() != Some(u64::from(old_worker_pid))
        {
            return value;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "supervisor must publish a replacement worker within 10s"
        );
        std::thread::sleep(Duration::from_millis(25));
    }
}

#[test]
fn sigkill_worker_reconnects_without_prompt_and_replays_same_session() {
    let mut session = attach_with_durable_history();
    let session_id = session_id_with_durable_marker(&session.home().db_path(), HISTORY_MARKER);
    let status_before = session.daemon_status_json();
    let old_worker_pid = session.sigkill_worker();
    session
        .wait_until_screen(
            "supervised reconnect blip",
            Duration::from_secs(10),
            |screen| {
                screen.contains("Reconnecting")
                    && !screen.contains("The daemon stopped unexpectedly. Restart it?")
            },
        )
        .expect("worker replacement must show a reconnecting blip without a modal");
    session
        .wait_until_screen(
            "same session reattached with history",
            Duration::from_secs(30),
            |screen| {
                screen.contains(COMPOSER_PLACEHOLDER)
                    && screen.contains(HISTORY_MARKER)
                    && !screen.contains("The daemon stopped unexpectedly")
                    && !screen.contains("Loading session setup")
            },
        )
        .expect("supervisor respawn must reattach and replay SQLite history");
    let rendezvous = wait_for_replacement_rendezvous(&session, old_worker_pid);
    assert_ne!(
        rendezvous["worker_pid"].as_u64(),
        Some(u64::from(old_worker_pid)),
        "supervisor must publish a new worker pid"
    );
    assert!(
        rendezvous["generation"]
            .as_u64()
            .is_some_and(|value| value > 1),
        "supervisor must advance generation"
    );
    let status_after = session.daemon_status_json();
    assert_eq!(status_after["worker_pid"], rendezvous["worker_pid"]);
    assert!(
        status_after["generation"].as_u64().unwrap()
            > status_before["generation"].as_u64().unwrap()
    );
    assert!(
        status_after["uptime_ms"].as_u64().unwrap() >= status_before["uptime_ms"].as_u64().unwrap()
    );
    session
        .wait_until_screen(
            "composer ready after crash restart",
            Duration::from_secs(30),
            |screen| screen.contains(COMPOSER_PLACEHOLDER),
        )
        .expect("crash restart must return to an idle composer");
    submit_durable_marker(&mut session, SECOND_HISTORY_MARKER);
    wait_until_durable_marker(
        &session.home().db_path(),
        session_id,
        SECOND_HISTORY_MARKER,
        Duration::from_secs(20),
    );
    assert_session_retains_markers(
        &session.home().db_path(),
        session_id,
        &[HISTORY_MARKER, SECOND_HISTORY_MARKER],
    );
    session.reap();
    session.assert_reaped();
}

#[test]
fn supervisor_reexec_keeps_attached_session_and_listener() {
    let mut session = attach_with_durable_history();
    let before = session.daemon_status_json();
    session.reexec_daemon_supervisor();
    session
        .wait_until_screen(
            "session remains attached after reexec",
            Duration::from_secs(10),
            |screen| {
                screen.contains(HISTORY_MARKER)
                    && screen.contains(COMPOSER_PLACEHOLDER)
                    && !screen.contains("The daemon stopped unexpectedly. Restart it?")
            },
        )
        .expect("supervisor reexec must preserve the attached worker connection");
    let after = session.daemon_status_json();
    assert_eq!(after["worker_pid"], before["worker_pid"]);
    assert_eq!(after["generation"], before["generation"]);
    assert!(after["uptime_ms"].as_u64().unwrap() >= before["uptime_ms"].as_u64().unwrap());
    session.reap();
    session.assert_reaped();
}

#[test]
fn daemon_restart_reconnects_attached_tui_without_prompt() {
    let mut session = attach_with_durable_history();
    let session_id = session_id_with_durable_marker(&session.home().db_path(), HISTORY_MARKER);
    let output = session.restart_daemon();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("attached clients will reconnect"),
        "restart output must describe attached-client behavior: {stdout}"
    );
    let saw_reconnect_chrome = Cell::new(false);
    let _ = session.wait_until_screen(
        "trusted restart reconnecting",
        Duration::from_secs(10),
        |screen| screen.contains("daemon restarting") || screen.contains("daemon connection lost"),
    );
    session
        .wait_until_screen(
            "trusted restart reattached",
            Duration::from_secs(30),
            |screen| {
                if screen.contains("daemon reconnected") {
                    saw_reconnect_chrome.set(true);
                }
                screen.contains(COMPOSER_PLACEHOLDER)
                    && screen.contains(HISTORY_MARKER)
                    && !screen.contains("The daemon stopped unexpectedly")
                    && !screen.contains("Loading session setup")
                    && !screen.contains("daemon restarting")
                    && !screen.contains("daemon connection lost")
            },
        )
        .expect("trusted restart must reconnect without user input");
    assert!(
        saw_reconnect_chrome.get(),
        "trusted restart must surface the daemon reconnected toast during reattach"
    );
    session
        .wait_until_screen(
            "composer ready after trusted restart",
            Duration::from_secs(30),
            |screen| screen.contains(COMPOSER_PLACEHOLDER),
        )
        .expect("trusted restart must return to an idle composer");
    submit_durable_marker(&mut session, SECOND_HISTORY_MARKER);
    wait_until_durable_marker(
        &session.home().db_path(),
        session_id,
        SECOND_HISTORY_MARKER,
        Duration::from_secs(30),
    );
    assert_session_retains_markers(
        &session.home().db_path(),
        session_id,
        &[HISTORY_MARKER, SECOND_HISTORY_MARKER],
    );
    session.reap();
    session.assert_reaped();
}
