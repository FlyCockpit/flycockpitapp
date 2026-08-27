//! Daemon lifecycle replay e2e (`daemon-lifecycle-replay-e2e.md`).
//!
//! Timing-budget policy (`daemon-lifecycle-replay-timing-robustness.md`,
//! criterion 6): every `wait_until`/`next_event` below is a legitimate
//! condition-poll for something asynchronous *from the client's point of view*
//! — an out-of-process daemon the test does not control finishing its boot,
//! rehydration, crash-reconciliation, or replay — never a "wait long enough"
//! window, and none of these budgets is widened here. The three former
//! `sleep(100ms)` negative-assertion windows have been replaced with the
//! deterministic [`wait_for_duplicate_resolve_processed`] happens-before
//! barrier. The drain/restart park-commit race the three `create_parked_session_
//! with_shutdown_park_delay` tests exercise is forced deterministically via an
//! injected debug-build pause, not by host CPU contention.

use std::future::Future;
use std::path::Path;
use std::sync::{LazyLock, Mutex};
use std::time::Duration;

use crate::support::{IsolatedHome, SpawnedDaemon, log_tail, output_text, wait_until};
use cockpit_cli::integration::{AttachedSession, DaemonEvent};
use cockpit_test_support::provider::{ScriptedProvider, Turn};
use rusqlite::{Connection, params};
use uuid::Uuid;

const TOOL_CALL_ID: &str = "call_lifecycle_bash";
const COMMAND: &str = "cat /tmp";

static DAEMON_REPLAY_TEST_MUTEX: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

fn run_daemon_replay_test(test: impl Future<Output = ()>) {
    let _guard = DAEMON_REPLAY_TEST_MUTEX
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("daemon replay test runtime")
        .block_on(test);
}

async fn lifecycle_provider() -> ScriptedProvider {
    ScriptedProvider::builder()
        .turn(Turn::ToolCall {
            id: TOOL_CALL_ID.into(),
            name: "bash".into(),
            arguments: serde_json::json!({ "command": COMMAND }),
        })
        .turn(Turn::Text("lifecycle complete".into()))
        .repeat_last()
        .start()
        .await
}

#[derive(Debug, Clone)]
struct InterruptRow {
    state: String,
    parked_tool: Option<String>,
    parked_args_json: Option<String>,
    parked_call_id: Option<String>,
    parked_gate_json: Option<String>,
    response_json: Option<String>,
}

fn open_db(path: &Path) -> Connection {
    Connection::open(path).unwrap_or_else(|err| panic!("open db {}: {err}", path.display()))
}

fn interrupt_row(db_path: &Path, interrupt_id: Uuid) -> InterruptRow {
    let conn = open_db(db_path);
    conn.query_row(
        "SELECT state, parked_tool, parked_args_json, parked_call_id, parked_gate_json,
                response_json
           FROM needs_attention
          WHERE interrupt_id = ?1",
        params![interrupt_id.to_string()],
        |row| {
            Ok(InterruptRow {
                state: row.get(0)?,
                parked_tool: row.get(1)?,
                parked_args_json: row.get(2)?,
                parked_call_id: row.get(3)?,
                parked_gate_json: row.get(4)?,
                response_json: row.get(5)?,
            })
        },
    )
    .expect("interrupt row")
}

fn paused_work_status(db_path: &Path, session_id: Uuid) -> Option<String> {
    let conn = open_db(db_path);
    conn.query_row(
        "SELECT status FROM paused_session_work WHERE session_id = ?1",
        params![session_id.to_string()],
        |row| row.get(0),
    )
    .ok()
}

fn tool_call_count(db_path: &Path, session_id: Uuid) -> i64 {
    let conn = open_db(db_path);
    conn.query_row(
        "SELECT COUNT(*) FROM tool_call_events WHERE session_id = ?1 AND call_id = ?2",
        params![session_id.to_string(), TOOL_CALL_ID],
        |row| row.get(0),
    )
    .expect("tool call count")
}

fn session_event_rows(db_path: &Path, session_id: Uuid) -> Vec<(i64, String)> {
    let conn = open_db(db_path);
    let mut stmt = conn
        .prepare(
            "SELECT seq, type
               FROM session_events
              WHERE session_id = ?1
                AND type IN ('user_message', 'assistant_message', 'tool_call', 'interrupt_decision')
              ORDER BY seq",
        )
        .expect("prepare session event rows");
    stmt.query_map(params![session_id.to_string()], |row| {
        Ok((row.get(0)?, row.get(1)?))
    })
    .expect("query session event rows")
    .map(|row| row.expect("session event row"))
    .collect()
}

fn tool_call_command(db_path: &Path, session_id: Uuid) -> String {
    let conn = open_db(db_path);
    let raw: String = conn
        .query_row(
            "SELECT original_input_json FROM tool_call_events WHERE session_id = ?1 AND call_id = ?2",
            params![session_id.to_string(), TOOL_CALL_ID],
            |row| row.get(0),
        )
        .expect("tool call input");
    serde_json::from_str::<serde_json::Value>(&raw).expect("tool call json")["command"]
        .as_str()
        .expect("tool command")
        .to_string()
}

fn tool_call_output(db_path: &Path, session_id: Uuid) -> String {
    let conn = open_db(db_path);
    conn.query_row(
        "SELECT output FROM tool_call_events WHERE session_id = ?1 AND call_id = ?2",
        params![session_id.to_string(), TOOL_CALL_ID],
        |row| row.get(0),
    )
    .expect("tool call output")
}

fn assert_replay_payload(row: &InterruptRow) {
    assert_eq!(row.parked_tool.as_deref(), Some("bash"));
    assert_eq!(row.parked_call_id.as_deref(), Some(TOOL_CALL_ID));
    assert_eq!(
        row.parked_args_json
            .as_deref()
            .and_then(|raw| serde_json::from_str::<serde_json::Value>(raw).ok())
            .and_then(|json| json["command"].as_str().map(str::to_string))
            .as_deref(),
        Some(COMMAND)
    );
}

async fn wait_for_interrupt(
    client: &cockpit_cli::integration::DaemonClient,
    daemon: &SpawnedDaemon,
    session_id: Uuid,
    reason: Option<&str>,
) -> Uuid {
    loop {
        match client
            .next_event(Duration::from_secs(20))
            .await
            .unwrap_or_else(|err| {
                let status = daemon
                    .command()
                    .args(["daemon", "status"])
                    .output()
                    .map(|output| output_text(&output))
                    .unwrap_or_else(|status_err| format!("status probe failed: {status_err}"));
                panic!(
                    "daemon event while waiting for interrupt: {err}\nstatus:\n{status}\nlog tail:\n{}",
                    log_tail(daemon.home())
                )
            }) {
            DaemonEvent::InterruptRaised {
                session_id: got,
                interrupt_id,
                reason: got_reason,
            } if got == session_id && reason.is_none_or(|expected| expected == got_reason) => {
                return interrupt_id;
            }
            _ => {}
        }
    }
}

async fn wait_for_resolved(
    client: &cockpit_cli::integration::DaemonClient,
    session_id: Uuid,
    interrupt_id: Uuid,
) {
    let mut seen = Vec::new();
    loop {
        let event = client
            .next_event(Duration::from_secs(20))
            .await
            .unwrap_or_else(|err| {
                panic!("daemon event while waiting for resolution: {err}; seen: {seen:#?}")
            });
        seen.push(format!("{event:?}"));
        match event {
            DaemonEvent::InterruptResolved {
                session_id: got_session,
                interrupt_id: got_interrupt,
            } if got_session == session_id && got_interrupt == interrupt_id => return,
            _ => {}
        }
    }
}

async fn wait_for_replay(
    client: &cockpit_cli::integration::DaemonClient,
    session_id: Uuid,
) -> (i64, Vec<(i64, &'static str)>) {
    loop {
        match client
            .next_event(Duration::from_secs(20))
            .await
            .expect("daemon event")
        {
            DaemonEvent::HistoryReplay {
                session_id: got,
                max_seq,
                entries,
            } if got == session_id => {
                return (
                    max_seq,
                    entries
                        .into_iter()
                        .map(|entry| (entry.seq, entry.kind))
                        .collect(),
                );
            }
            _ => {}
        }
    }
}

async fn drive_auto_replay_to_tool_call(
    client: &cockpit_cli::integration::DaemonClient,
    daemon: &SpawnedDaemon,
    session_id: Uuid,
) {
    let mut seen = Vec::new();
    for _ in 0..32 {
        if tool_call_count(&daemon.db_path(), session_id) == 1 {
            return;
        }
        let event = client
            .next_event(Duration::from_secs(20))
            .await
            .unwrap_or_else(|err| {
                panic!(
                    "daemon event while driving auto replay: {err}; seen: {seen:#?}\nlog tail:\n{}",
                    log_tail(daemon.home())
                )
            });
        seen.push(format!("{event:?}"));
        match event {
            DaemonEvent::Notice { text, .. } if text.contains("safety gate unavailable") => {
                panic!("replay re-raised the memoized safety gate: {text}");
            }
            DaemonEvent::InterruptRaised {
                session_id: got,
                interrupt_id,
                ..
            } if got == session_id => {
                client
                    .approve_interrupt_project(interrupt_id)
                    .await
                    .expect("approve follow-up replay interrupt");
            }
            _ => {}
        }
    }
    panic!("auto replay did not reach tool call; seen: {seen:#?}");
}

async fn create_parked_session_with_hook(
    pause_replay_executing: bool,
) -> (ScriptedProvider, SpawnedDaemon, AttachedSession, Uuid) {
    // Keep the provider alive for the daemon lifetime; dropping it closes the listener.
    let provider = lifecycle_provider().await;
    let mut home = IsolatedHome::new();
    if pause_replay_executing {
        home.set_env("COCKPIT_TEST_PAUSE_PARKED_REPLAY_EXECUTING", "1");
    }
    home.write_local_provider_config(&provider.base_url());
    home.trust_project();
    let daemon = SpawnedDaemon::start_with_home(home).await;
    let client = daemon.client().await;
    let attached = client
        .attach(daemon.project_path(), None, None, true)
        .await
        .expect("attach session");

    client
        .send_user_message("trigger lifecycle approval")
        .await
        .expect("send user message");
    let interrupt_id =
        wait_for_interrupt(&client, &daemon, attached.session_id, Some("initial")).await;

    (provider, daemon, attached, interrupt_id)
}

async fn create_parked_session() -> (ScriptedProvider, SpawnedDaemon, AttachedSession, Uuid) {
    create_parked_session_with_hook(false).await
}

async fn create_auto_gate_parked_session_with_hook(
    pause_replay_executing: bool,
) -> (ScriptedProvider, SpawnedDaemon, AttachedSession, Uuid) {
    // Keep the provider alive for the daemon lifetime; dropping it closes the listener.
    let provider = lifecycle_provider().await;
    let mut home = IsolatedHome::new();
    if pause_replay_executing {
        home.set_env("COCKPIT_TEST_PAUSE_PARKED_REPLAY_EXECUTING", "1");
    }
    home.write_local_provider_config(&provider.base_url());
    std::fs::write(
        home.config_dir().join("config.json"),
        r#"{"active_model":{"provider":"local","model":"scripted"},"sandbox_escalation_enabled":true,"defaultApprovalMode":"auto"}"#,
    )
    .expect("write auto approval replay config");
    home.trust_project();
    let daemon = SpawnedDaemon::start_with_home(home).await;
    let client = daemon.client().await;
    let attached = client
        .attach(daemon.project_path(), None, None, true)
        .await
        .expect("attach session");

    client
        .send_user_message("trigger auto lifecycle approval")
        .await
        .expect("send user message");
    let gate_interrupt =
        wait_for_interrupt(&client, &daemon, attached.session_id, Some("initial")).await;
    client
        .approve_interrupt_once(gate_interrupt)
        .await
        .expect("approve gate interrupt");
    let parked_interrupt =
        wait_for_interrupt(&client, &daemon, attached.session_id, Some("initial")).await;

    (provider, daemon, attached, parked_interrupt)
}

async fn create_auto_gate_parked_session()
-> (ScriptedProvider, SpawnedDaemon, AttachedSession, Uuid) {
    create_auto_gate_parked_session_with_hook(false).await
}

/// Milliseconds the injected shutdown-park delay holds the graceful drain's
/// interrupt park (`COCKPIT_TEST_DELAY_SHUTDOWN_PARK_MS`,
/// `daemon-lifecycle-replay-timing-robustness.md`). Chosen strictly greater than
/// the `--grace 2` (2000ms) window these tests restart with — so the pre-fix
/// drain, which released pid/socket at the grace deadline, would leave the row
/// `open` — and strictly less than the 5000ms product-owned
/// `INTERRUPT_PARK_COMMIT_DEADLINE`, so the fixed drain path observes a clean
/// committed park rather than the forced deadline terminal. This forces the
/// worst-case interleaving deterministically instead of relying on host CPU
/// starvation (criteria 2, 3, 8).
const INJECTED_SHUTDOWN_PARK_DELAY_MS: &str = "3000";

/// Like [`create_parked_session`], but the spawned daemon runs with the injected
/// shutdown-park delay above so its next graceful restart deterministically
/// exercises the drain/restart park-commit race (criteria 3, 8). The delay is
/// debug-build + env-gated inside the daemon; it fires only on a worker's
/// `SessionWork::Shutdown` arm.
async fn create_parked_session_with_shutdown_park_delay()
-> (ScriptedProvider, SpawnedDaemon, AttachedSession, Uuid) {
    // Keep the provider alive for the daemon lifetime; dropping it closes the listener.
    let provider = lifecycle_provider().await;
    let mut home = IsolatedHome::new();
    home.set_env(
        "COCKPIT_TEST_DELAY_SHUTDOWN_PARK_MS",
        INJECTED_SHUTDOWN_PARK_DELAY_MS,
    );
    home.write_local_provider_config(&provider.base_url());
    home.trust_project();
    let daemon = SpawnedDaemon::start_with_home(home).await;
    let client = daemon.client().await;
    let attached = client
        .attach(daemon.project_path(), None, None, true)
        .await
        .expect("attach session");

    client
        .send_user_message("trigger lifecycle approval")
        .await
        .expect("send user message");
    let interrupt_id =
        wait_for_interrupt(&client, &daemon, attached.session_id, Some("initial")).await;

    (provider, daemon, attached, interrupt_id)
}

/// Milliseconds the injected attach-reconciliation delay
/// (`COCKPIT_TEST_DELAY_STARTUP_RECONCILE_MS`) holds a resumed worker's
/// crash-reconciliation park. Chosen well below the 5000ms
/// `INTERRUPT_PARK_COMMIT_DEADLINE` so the fixed attach path — which awaits the
/// startup park-commit signal — still returns with a committed park, while
/// leaving a wide window in which a non-awaiting (pre-fix) attach would expose a
/// stale `open` row (criterion 1).
const INJECTED_STARTUP_RECONCILE_DELAY_MS: &str = "2000";

/// Like [`create_parked_session`], but the daemon runs with the injected
/// attach-reconciliation delay so a later resumed-worker attach deterministically
/// exercises the attach/reconciliation park-commit gap (criterion 1). The
/// interrupt is left `open` (no graceful park) for a crash + resume to reconcile.
async fn create_open_interrupt_session_with_reconcile_delay()
-> (ScriptedProvider, SpawnedDaemon, AttachedSession, Uuid) {
    // Keep the provider alive for the daemon lifetime; dropping it closes the listener.
    let provider = lifecycle_provider().await;
    let mut home = IsolatedHome::new();
    home.set_env(
        "COCKPIT_TEST_DELAY_STARTUP_RECONCILE_MS",
        INJECTED_STARTUP_RECONCILE_DELAY_MS,
    );
    home.write_local_provider_config(&provider.base_url());
    home.trust_project();
    let daemon = SpawnedDaemon::start_with_home(home).await;
    let client = daemon.client().await;
    let attached = client
        .attach(daemon.project_path(), None, None, true)
        .await
        .expect("attach session");

    client
        .send_user_message("trigger lifecycle approval")
        .await
        .expect("send user message");
    let interrupt_id =
        wait_for_interrupt(&client, &daemon, attached.session_id, Some("initial")).await;

    (provider, daemon, attached, interrupt_id)
}

/// Deterministic happens-before for a duplicate-resolve negative assertion
/// (criterion 6c). A `ResolveInterrupt` request is dispatched to the session
/// worker via `send_work`, whose `Ack` returns at ENQUEUE time, not after the
/// worker processes it — so the former `sleep(100ms)` was a wall-clock window
/// hoping a stray second execution would surface. Instead, enqueue a benign
/// follow-up user-message turn BEHIND the duplicate on the worker's FIFO queue
/// and condition-poll the DURABLE `session_events` for that turn's persisted
/// rows. Because the worker drains its queue in order, the new rows prove the
/// duplicate was fully processed (and, having no `parked` row to claim, could
/// not have re-executed the replay). This is a happens-before via durable
/// observation — not a wall-clock absence window and immune to event-stream
/// buffering — after which the caller asserts exactly-once execution state.
async fn wait_for_duplicate_resolve_processed(
    client: &cockpit_cli::integration::DaemonClient,
    daemon: &SpawnedDaemon,
    session_id: Uuid,
) {
    let before = session_event_rows(&daemon.db_path(), session_id).len();
    client
        .send_user_message("lifecycle duplicate-resolve sync barrier")
        .await
        .expect("send duplicate-resolve sync-barrier user message");
    wait_until(
        "duplicate-resolve barrier turn persisted",
        Duration::from_secs(20),
        || {
            let db_path = daemon.db_path();
            async move { session_event_rows(&db_path, session_id).len() > before }
        },
    )
    .await;
}

async fn restart_daemon_gracefully(daemon: &SpawnedDaemon) {
    let output = daemon
        .command()
        .args(["daemon", "restart", "--grace", "2"])
        .output()
        .expect("daemon restart command");
    let text = output_text(&output);
    assert!(output.status.success(), "daemon restart failed: {text}");
    assert!(text.contains("daemon: restarted"));
    daemon.wait_for_handshake().await;
}

#[test]
fn lifecycle_graceful_park_round_trip_replays_once() {
    run_daemon_replay_test(async {
        let (provider, daemon, attached, interrupt_id) = create_parked_session().await;

        restart_daemon_gracefully(&daemon).await;

        let db_path = daemon.db_path();
        wait_until(
            "graceful restart parked interrupt",
            Duration::from_secs(5),
            || {
                let db_path = db_path.clone();
                async move { interrupt_row(&db_path, interrupt_id).state == "parked" }
            },
        )
        .await;
        let row = interrupt_row(&db_path, interrupt_id);
        assert_eq!(row.state, "parked");
        assert_replay_payload(&row);
        assert!(
            matches!(
                paused_work_status(&daemon.db_path(), attached.session_id).as_deref(),
                Some("paused" | "resumed")
            ),
            "paused work should remain resumable across restart"
        );
        assert_eq!(tool_call_count(&daemon.db_path(), attached.session_id), 0);

        let client = daemon.client().await;
        let reattached = client
            .attach(daemon.project_path(), Some(attached.session_id), None, true)
            .await
            .expect("reattach session");
        assert_eq!(reattached.session_id, attached.session_id);

        let raised_after_restart =
            wait_for_interrupt(&client, &daemon, attached.session_id, Some("rehydration")).await;
        assert_eq!(raised_after_restart, interrupt_id);

        client
            .approve_interrupt_project(interrupt_id)
            .await
            .expect("approve parked interrupt");
        wait_for_resolved(&client, attached.session_id, interrupt_id).await;

        wait_until("tool call audit row", Duration::from_secs(5), || {
            let db_path = daemon.db_path();
            async move { tool_call_count(&db_path, attached.session_id) == 1 }
        })
        .await;
        assert_eq!(
            tool_call_command(&daemon.db_path(), attached.session_id),
            COMMAND
        );
        assert_eq!(
            interrupt_row(&daemon.db_path(), interrupt_id).state,
            "resolved"
        );
        assert!(
            interrupt_row(&daemon.db_path(), interrupt_id)
                .response_json
                .is_some()
        );

        client
            .approve_interrupt_once(interrupt_id)
            .await
            .expect("duplicate approve request");
        wait_for_duplicate_resolve_processed(&client, &daemon, attached.session_id).await;
        assert_eq!(tool_call_count(&daemon.db_path(), attached.session_id), 1);
        assert!(
            provider.request_count() >= 2,
            "provider should receive initial tool-call and post-tool continuation"
        );
    });
}

#[test]
fn lifecycle_sigkill_open_interrupt_reconciles_and_replays_once() {
    run_daemon_replay_test(async {
        let (_provider, daemon, attached, interrupt_id) = create_parked_session().await;

        let row = interrupt_row(&daemon.db_path(), interrupt_id);
        assert_eq!(row.state, "open");
        assert_replay_payload(&row);
        assert_eq!(tool_call_count(&daemon.db_path(), attached.session_id), 0);

        daemon.sigkill().await;
        daemon.restart_same_home().await;

        let client = daemon.client().await;
        client
            .attach(daemon.project_path(), Some(attached.session_id), None, true)
            .await
            .expect("reattach session");
        wait_until(
            "crash-surviving interrupt parked",
            Duration::from_secs(5),
            || {
                let db_path = daemon.db_path();
                async move { interrupt_row(&db_path, interrupt_id).state == "parked" }
            },
        )
        .await;
        let raised_after_restart =
            wait_for_interrupt(&client, &daemon, attached.session_id, Some("rehydration")).await;
        assert_eq!(raised_after_restart, interrupt_id);

        client
            .approve_interrupt_project(interrupt_id)
            .await
            .expect("approve parked interrupt");
        wait_for_resolved(&client, attached.session_id, interrupt_id).await;

        assert_eq!(tool_call_count(&daemon.db_path(), attached.session_id), 1);
        assert_eq!(
            tool_call_command(&daemon.db_path(), attached.session_id),
            COMMAND
        );
        assert_eq!(
            interrupt_row(&daemon.db_path(), interrupt_id).state,
            "resolved"
        );

        client
            .approve_interrupt_once(interrupt_id)
            .await
            .expect("duplicate approve request");
        wait_for_duplicate_resolve_processed(&client, &daemon, attached.session_id).await;
        assert_eq!(tool_call_count(&daemon.db_path(), attached.session_id), 1);
    });
}

/// Criterion 1: a resumed-worker attach must await the SAME park-commit signal
/// as the drain path before a client can observe the interrupt. With the
/// attach-reconciliation park injected-delayed past normal, a single-shot read
/// right after `attach` returns must already see `parked` — proving `attach`
/// blocked on the worker's startup reconciliation commit. Fails against the
/// pre-fix code, whose `attach` returned as soon as the worker was spawned.
#[test]
fn lifecycle_attach_park_commits_before_interrupt_visible() {
    run_daemon_replay_test(async {
        let (_provider, daemon, attached, interrupt_id) =
            create_open_interrupt_session_with_reconcile_delay().await;
        // Crash before any graceful park: the row is durably `open`.
        assert_eq!(interrupt_row(&daemon.db_path(), interrupt_id).state, "open");

        daemon.sigkill().await;
        daemon.restart_same_home().await;

        let client = daemon.client().await;
        // The resumed-worker attach must not return until the delayed startup
        // crash-reconciliation park has committed. Single-shot read, zero retry
        // budget — no `wait_until`.
        client
            .attach(daemon.project_path(), Some(attached.session_id), None, true)
            .await
            .expect("reattach session");
        assert_eq!(
            interrupt_row(&daemon.db_path(), interrupt_id).state,
            "parked",
            "attach must await the startup park-commit before returning"
        );

        // The rehydration interrupt is still delivered and resolves cleanly.
        assert_eq!(
            wait_for_interrupt(&client, &daemon, attached.session_id, Some("rehydration")).await,
            interrupt_id
        );
        client
            .approve_interrupt_project(interrupt_id)
            .await
            .expect("approve parked interrupt");
        wait_for_resolved(&client, attached.session_id, interrupt_id).await;
        assert_eq!(
            interrupt_row(&daemon.db_path(), interrupt_id).state,
            "resolved"
        );
    });
}

#[test]
fn lifecycle_auto_gate_unavailable_park_replay_runs_approved_command() {
    run_daemon_replay_test(async {
        let (_provider, daemon, attached, interrupt_id) = create_auto_gate_parked_session().await;

        restart_daemon_gracefully(&daemon).await;

        let row = interrupt_row(&daemon.db_path(), interrupt_id);
        assert_eq!(row.state, "parked");
        assert_replay_payload(&row);
        assert!(
            row.parked_gate_json.is_some(),
            "parked inner prompt must carry the already-approved gate memo"
        );
        assert_eq!(tool_call_count(&daemon.db_path(), attached.session_id), 0);

        let client = daemon.client().await;
        client
            .attach(daemon.project_path(), Some(attached.session_id), None, true)
            .await
            .expect("reattach session");
        assert_eq!(
            wait_for_interrupt(&client, &daemon, attached.session_id, Some("rehydration")).await,
            interrupt_id
        );

        client
            .approve_interrupt_project(interrupt_id)
            .await
            .expect("approve parked interrupt");
        drive_auto_replay_to_tool_call(&client, &daemon, attached.session_id).await;
        let output = tool_call_output(&daemon.db_path(), attached.session_id);
        assert!(
            !output.contains("declined") && !output.contains("not run"),
            "approved replay must not be recorded as declined: {output}"
        );
        assert_eq!(
            tool_call_command(&daemon.db_path(), attached.session_id),
            COMMAND
        );
    });
}

#[test]
fn lifecycle_auto_gate_unavailable_sigkill_park_replay_runs_approved_command() {
    run_daemon_replay_test(async {
        let (_provider, daemon, attached, interrupt_id) = create_auto_gate_parked_session().await;

        let row = interrupt_row(&daemon.db_path(), interrupt_id);
        assert_eq!(row.state, "open");
        assert_replay_payload(&row);
        assert!(
            row.parked_gate_json.is_some(),
            "open inner prompt must carry the already-approved gate memo"
        );
        assert_eq!(tool_call_count(&daemon.db_path(), attached.session_id), 0);

        daemon.sigkill().await;
        daemon.restart_same_home().await;

        let client = daemon.client().await;
        client
            .attach(daemon.project_path(), Some(attached.session_id), None, true)
            .await
            .expect("reattach session");
        wait_until(
            "auto gate crash-surviving interrupt parked",
            Duration::from_secs(5),
            || {
                let db_path = daemon.db_path();
                async move { interrupt_row(&db_path, interrupt_id).state == "parked" }
            },
        )
        .await;
        assert_eq!(
            wait_for_interrupt(&client, &daemon, attached.session_id, Some("rehydration")).await,
            interrupt_id
        );

        client
            .approve_interrupt_project(interrupt_id)
            .await
            .expect("approve parked interrupt");
        drive_auto_replay_to_tool_call(&client, &daemon, attached.session_id).await;
        let output = tool_call_output(&daemon.db_path(), attached.session_id);
        assert!(
            !output.contains("declined") && !output.contains("not run"),
            "approved replay must not be recorded as declined: {output}"
        );
        assert_eq!(
            tool_call_command(&daemon.db_path(), attached.session_id),
            COMMAND
        );
    });
}

#[test]
fn lifecycle_deny_round_trip_resolves_without_broadened_rerun() {
    run_daemon_replay_test(async {
        // Injected worst-case interleaving (criterion 3): the daemon's graceful
        // park is delayed past the `--grace 2` window. The single-shot
        // `state == "parked"` read below (no `wait_until`, zero retry budget) is
        // the executable spec that the drain path now gates pid/socket release
        // on the park commit — it must still hold, unmodified, under this pause.
        let (_provider, daemon, attached, interrupt_id) =
            create_parked_session_with_shutdown_park_delay().await;

        restart_daemon_gracefully(&daemon).await;
        assert_eq!(
            interrupt_row(&daemon.db_path(), interrupt_id).state,
            "parked"
        );

        let client = daemon.client().await;
        client
            .attach(daemon.project_path(), Some(attached.session_id), None, true)
            .await
            .expect("reattach session");
        assert_eq!(
            wait_for_interrupt(&client, &daemon, attached.session_id, Some("rehydration")).await,
            interrupt_id
        );

        client
            .deny_interrupt(interrupt_id)
            .await
            .expect("deny parked interrupt");
        wait_for_resolved(&client, attached.session_id, interrupt_id).await;

        let row = interrupt_row(&daemon.db_path(), interrupt_id);
        assert_eq!(row.state, "resolved");
        assert!(
            row.response_json
                .as_deref()
                .is_some_and(|raw| raw.contains("reject"))
        );
        assert_eq!(
            tool_call_count(&daemon.db_path(), attached.session_id),
            1,
            "denied approval records the original sandboxed result once"
        );
    });
}

#[test]
fn lifecycle_restart_command_preserves_parked_session_and_starts_when_absent() {
    run_daemon_replay_test(async {
        let (_provider, daemon, attached, interrupt_id) = create_parked_session().await;
        let old_pid = daemon.pid();

        restart_daemon_gracefully(&daemon).await;
        wait_until("replacement daemon pid", Duration::from_secs(5), || async {
            daemon.try_pid().is_some_and(|pid| pid != old_pid)
        })
        .await;

        let client = daemon.client().await;
        let reattached = client
            .attach(daemon.project_path(), Some(attached.session_id), None, true)
            .await
            .expect("reattach session");
        assert_eq!(reattached.session_id, attached.session_id);
        let db_path = daemon.db_path();
        wait_until("restarted interrupt parked", Duration::from_secs(5), || {
            let db_path = db_path.clone();
            async move { interrupt_row(&db_path, interrupt_id).state == "parked" }
        })
        .await;
        assert_eq!(
            wait_for_interrupt(&client, &daemon, attached.session_id, Some("rehydration")).await,
            interrupt_id
        );
        drop(client);

        let stop = daemon
            .command()
            .args(["daemon", "stop", "--grace", "0"])
            .output()
            .expect("daemon stop command");
        assert!(stop.status.success(), "{}", output_text(&stop));
        wait_until("daemon pid cleanup", Duration::from_secs(5), || async {
            daemon.try_pid().is_none()
        })
        .await;

        let restart = daemon
            .command()
            .args(["daemon", "restart", "--grace", "0"])
            .output()
            .expect("daemon restart command");
        assert!(restart.status.success(), "{}", output_text(&restart));
        assert!(
            output_text(&restart).contains("daemon: was not running; started"),
            "{}",
            output_text(&restart)
        );
        daemon.wait_for_handshake().await;
    });
}

#[test]
fn lifecycle_sigkill_executing_interrupt_reconciles_to_interrupted_without_reexecute() {
    run_daemon_replay_test(async {
        let (_provider, daemon, attached, interrupt_id) =
            create_parked_session_with_hook(true).await;

        restart_daemon_gracefully(&daemon).await;

        let client = daemon.client().await;
        client
            .attach(daemon.project_path(), Some(attached.session_id), None, true)
            .await
            .expect("reattach session");
        assert_eq!(
            wait_for_interrupt(&client, &daemon, attached.session_id, Some("rehydration")).await,
            interrupt_id
        );
        client
            .approve_interrupt_project(interrupt_id)
            .await
            .expect("approve parked interrupt");
        wait_until("parked interrupt executing", Duration::from_secs(5), || {
            let db_path = daemon.db_path();
            async move { interrupt_row(&db_path, interrupt_id).state == "executing" }
        })
        .await;

        daemon.sigkill().await;
        daemon.restart_same_home().await;
        let client = daemon.client().await;
        client
            .attach(daemon.project_path(), Some(attached.session_id), None, true)
            .await
            .expect("reattach session");
        wait_until(
            "executing interrupt reconciled interrupted",
            Duration::from_secs(5),
            || {
                let db_path = daemon.db_path();
                async move { interrupt_row(&db_path, interrupt_id).state == "interrupted" }
            },
        )
        .await;

        client
            .approve_interrupt_once(interrupt_id)
            .await
            .expect("late duplicate approve request");
        wait_for_duplicate_resolve_processed(&client, &daemon, attached.session_id).await;
        assert!(
            tool_call_count(&daemon.db_path(), attached.session_id) <= 1,
            "executing crash must not re-execute parked replay"
        );
    });
}

#[test]
fn lifecycle_attach_replay_across_restart_delivers_persisted_events_once_in_order() {
    run_daemon_replay_test(async {
        // Injected worst-case interleaving (criterion 8): graceful park delayed
        // past `--grace 2`, forcing the drain/restart park-commit race before
        // the exactly-once ordered-replay assertions below.
        let (_provider, daemon, attached, interrupt_id) =
            create_parked_session_with_shutdown_park_delay().await;

        restart_daemon_gracefully(&daemon).await;

        let client = daemon.client().await;
        client
            .attach(daemon.project_path(), Some(attached.session_id), None, true)
            .await
            .expect("reattach session");
        assert_eq!(
            wait_for_interrupt(&client, &daemon, attached.session_id, Some("rehydration")).await,
            interrupt_id
        );
        client
            .approve_interrupt_project(interrupt_id)
            .await
            .expect("approve parked interrupt");
        wait_for_resolved(&client, attached.session_id, interrupt_id).await;
        wait_until("tool call audit row", Duration::from_secs(5), || {
            let db_path = daemon.db_path();
            async move { tool_call_count(&db_path, attached.session_id) == 1 }
        })
        .await;

        let expected_rows = session_event_rows(&daemon.db_path(), attached.session_id);
        assert!(
            expected_rows.iter().any(|(_, kind)| kind == "tool_call"),
            "replay fixture must include at least one persisted tool call"
        );
        let expected_seqs: Vec<_> = expected_rows.iter().map(|(seq, _)| *seq).collect();
        let expected_max = *expected_seqs.last().expect("persisted session events");

        daemon.sigkill().await;
        daemon.restart_same_home().await;
        let replay_client = daemon.client().await;
        let reattached = replay_client
            .attach(
                daemon.project_path(),
                Some(attached.session_id),
                Some(0),
                true,
            )
            .await
            .expect("reattach with replay cursor");
        assert_eq!(reattached.history_len, 0);
        let (max_seq, replay_entries) = wait_for_replay(&replay_client, attached.session_id).await;
        let replay_seqs: Vec<_> = replay_entries.iter().map(|(seq, _)| *seq).collect();

        assert_eq!(replay_seqs, expected_seqs);
        assert!(
            max_seq >= expected_max,
            "replay high-water {max_seq} dropped below persisted history {expected_max}; replay_entries={replay_entries:?}"
        );
        let mut unique = replay_seqs.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique, replay_seqs, "replay seqs must be unique and sorted");
    });
}
