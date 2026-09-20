use std::path::Path;
use std::time::{Duration, Instant};

use crate::support::{COMPOSER_PLACEHOLDER, HermeticCockpit, HermeticProfile, sgr_left_click};
use rusqlite::{Connection, params};
use uuid::Uuid;

const HISTORY_MARKER: &str = "watchdog-history-marker-437";

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

fn durable_user_message_contains(db_path: &Path, session_id: Uuid, marker: &str) -> bool {
    Connection::open(db_path)
        .expect("open hermetic session db")
        .query_row(
            "SELECT data_json FROM session_events \
             WHERE session_id = ?1 AND type = 'user_message' ORDER BY seq LIMIT 1",
            params![session_id.to_string()],
            |row| row.get::<_, String>(0),
        )
        .map(|json| json.contains(marker))
        .unwrap_or(false)
}

fn attach_with_durable_history() -> HermeticCockpit {
    let mut session = HermeticCockpit::launch_ready(HermeticProfile::Default);
    // Wait for the PTY paste to reach the composer before sending Enter. The
    // input source acknowledges paste asynchronously, so back-to-back bytes
    // can otherwise make the test assert against an unsubmitted draft.
    session.write_str(HISTORY_MARKER);
    session
        .wait_until_screen("history marker draft", Duration::from_secs(5), |screen| {
            screen.contains(HISTORY_MARKER)
        })
        .expect("history marker must reach the composer before submit");
    session.send_enter();
    session
        .wait_until_screen(
            "durable history marker",
            Duration::from_secs(10),
            |screen| screen.contains(HISTORY_MARKER) && screen.contains(COMPOSER_PLACEHOLDER),
        )
        .expect("submitted history is visible before daemon replacement");
    // The user event is persisted before model execution; allow its daemon
    // response to cross the PTY without requiring the animated screen to be
    // byte-stable.
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
    assert!(
        durable_user_message_contains(&session.home().db_path(), session_id, HISTORY_MARKER),
        "reattach must keep the durable transcript for the original session id"
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
    assert!(
        durable_user_message_contains(&session.home().db_path(), session_id, HISTORY_MARKER),
        "trusted restart must preserve the durable session id and transcript"
    );
    session.reap();
    session.assert_reaped();
}
