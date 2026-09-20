use std::path::Path;
use std::time::{Duration, Instant};

use crate::support::{COMPOSER_PLACEHOLDER, HermeticCockpit, HermeticProfile, sgr_left_click};
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

#[test]
fn sigkill_prompts_within_one_second_and_restart_replays_same_session() {
    let mut session = attach_with_durable_history();
    let session_id = session_id_with_durable_marker(&session.home().db_path(), HISTORY_MARKER);
    let killed_at = Instant::now();
    session.sigkill_daemon();
    session
        .wait_until_screen("daemon restart prompt", Duration::from_secs(1), |screen| {
            screen.contains("The daemon stopped unexpectedly. Restart it?")
                && screen.contains("[ Restart ]")
                && screen.contains("[ Quit ]")
        })
        .expect("receipt watch or socket EOF must raise the prompt within one second");
    assert!(killed_at.elapsed() <= Duration::from_secs(1));

    // Exercise the actual modal action. The lifecycle host reclaims the stale
    // endpoint, spawns, and the runner attaches the same durable session id.
    let restart = session
        .snapshot()
        .find_text("[ Restart ]")
        .expect("restart action geometry");
    session.write_bytes(&sgr_left_click(restart.sgr_x(), restart.sgr_y()));
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
        .expect("restart must reattach and replay SQLite history");
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
    session.adopt_current_daemon_generation();
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
    session
        .wait_until_screen(
            "trusted restart reattached",
            Duration::from_secs(30),
            |screen| {
                screen.contains(COMPOSER_PLACEHOLDER)
                    && screen.contains(HISTORY_MARKER)
                    && !screen.contains("The daemon stopped unexpectedly")
                    && !screen.contains("Loading session setup")
            },
        )
        .expect("trusted restart must reconnect without user input");
    assert_eq!(
        session_id,
        session_id_with_durable_marker(&session.home().db_path(), HISTORY_MARKER),
        "trusted restart must keep the durable session id for the history marker"
    );
    session.reap();
    session.assert_reaped();
}
