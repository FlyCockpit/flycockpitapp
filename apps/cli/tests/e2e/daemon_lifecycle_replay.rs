//! Daemon lifecycle replay e2e (`daemon-lifecycle-replay-e2e.md`).
//!
//! Durable observations use the subscribed production event stream. Database
//! reads occur only after the matching id/sequence event proves its commit.
//! Process observations use owned-child completion and the replacement status
//! handshake supplied by the shared harness.

use std::path::Path;

use crate::support::{IsolatedHome, ReplayLaunchBarrier, SpawnedDaemon, log_tail, output_text};
use cockpit_cli::integration::{AttachedSession, DaemonEvent};
use cockpit_test_support::provider::{ScriptedProvider, Turn};
use rusqlite::{Connection, params};
use uuid::Uuid;

const TOOL_CALL_ID: &str = "call_lifecycle_bash";
fn lifecycle_command(home: &IsolatedHome) -> String {
    let source = home.home_dir().join("lifecycle-source.txt");
    std::fs::write(&source, "hermetic lifecycle fixture\n")
        .expect("write lifecycle command source");
    format!("cat {}", source.display())
}

async fn lifecycle_provider_for_command(command: &str) -> ScriptedProvider {
    ScriptedProvider::builder()
        .turn(Turn::ToolCall {
            id: TOOL_CALL_ID.into(),
            name: "bash".into(),
            arguments: serde_json::json!({ "command": command }),
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

fn offered_approval_option(db_path: &Path, interrupt_id: Uuid) -> String {
    let conn = open_db(db_path);
    let questions_json: String = conn
        .query_row(
            "SELECT questions_json FROM needs_attention WHERE interrupt_id = ?1",
            params![interrupt_id.to_string()],
            |row| row.get(0),
        )
        .expect("persisted interrupt questions");
    let questions: serde_json::Value =
        serde_json::from_str(&questions_json).expect("parse persisted interrupt questions");
    let offered = questions["questions"][0]["data"]["options"]
        .as_array()
        .expect("single persisted question options");
    for candidate in [
        cockpit_core::approval::ID_APPROVE_ONCE,
        cockpit_core::approval::ID_APPROVE_PROJECT,
        cockpit_core::approval::ID_APPROVE,
        cockpit_core::approval::ID_ESCALATE_RUN_UNCONFINED_ONCE,
        cockpit_core::approval::ID_GITIGNORE_FILE,
    ] {
        if offered
            .iter()
            .any(|option| option["id"].as_str() == Some(candidate))
        {
            return candidate.to_string();
        }
    }
    panic!("persisted interrupt offers no affirmative option: {offered:?}")
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

fn assert_replay_payload(row: &InterruptRow, expected_command: &str) {
    assert_eq!(row.parked_tool.as_deref(), Some("bash"));
    assert_eq!(row.parked_call_id.as_deref(), Some(TOOL_CALL_ID));
    assert_eq!(
        row.parked_args_json
            .as_deref()
            .and_then(|raw| serde_json::from_str::<serde_json::Value>(raw).ok())
            .and_then(|json| json["command"].as_str().map(str::to_string))
            .as_deref(),
        Some(expected_command)
    );
}

async fn wait_for_interrupt(
    client: &cockpit_cli::integration::DaemonClient,
    daemon: &SpawnedDaemon,
    session_id: Uuid,
    reason: Option<&str>,
) -> Uuid {
    loop {
        match client.next_event_unbounded().await.unwrap_or_else(|err| {
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

async fn wait_for_tool_start(client: &cockpit_cli::integration::DaemonClient, session_id: Uuid) {
    loop {
        match client.next_event_unbounded().await.expect("daemon event") {
            DaemonEvent::ToolStart {
                session_id: got,
                call_id,
                ..
            } if got == session_id && call_id == TOOL_CALL_ID => return,
            _ => {}
        }
    }
}

async fn wait_for_replay(
    client: &cockpit_cli::integration::DaemonClient,
    session_id: Uuid,
) -> (i64, Vec<(i64, &'static str)>) {
    loop {
        match client.next_event_unbounded().await.expect("daemon event") {
            DaemonEvent::HistoryReplay {
                session_id: got,
                max_seq,
                entries,
                ..
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
    loop {
        let event = client.next_event_unbounded().await.unwrap_or_else(|err| {
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
            DaemonEvent::ToolEnd {
                session_id: got,
                call_id,
                seq: Some(_),
            }
            | DaemonEvent::ToolError {
                session_id: got,
                call_id,
                seq: Some(_),
            } if got == session_id && call_id == TOOL_CALL_ID => return,
            _ => {}
        }
    }
}

async fn wait_for_tool_terminal_and_resolved(
    client: &cockpit_cli::integration::DaemonClient,
    session_id: Uuid,
    interrupt_id: Uuid,
) -> i64 {
    let mut tool_seq = None;
    let mut resolved = false;
    loop {
        match client
            .next_event_unbounded()
            .await
            .expect("daemon event while waiting for tool terminal and interrupt resolution")
        {
            DaemonEvent::ToolEnd {
                session_id: got,
                call_id,
                seq: Some(seq),
            }
            | DaemonEvent::ToolError {
                session_id: got,
                call_id,
                seq: Some(seq),
            } if got == session_id && call_id == TOOL_CALL_ID => tool_seq = Some(seq),
            DaemonEvent::InterruptResolved {
                session_id: got_session,
                interrupt_id: got_interrupt,
            } if got_session == session_id && got_interrupt == interrupt_id => resolved = true,
            _ => {}
        }
        if let (Some(seq), true) = (tool_seq, resolved) {
            return seq;
        }
    }
}

async fn create_parked_session() -> (ScriptedProvider, SpawnedDaemon, AttachedSession, Uuid) {
    // Keep the provider alive for the daemon lifetime; dropping it closes the listener.
    let home = IsolatedHome::new();
    let provider = lifecycle_provider_for_command(&lifecycle_command(&home)).await;
    home.write_local_provider_config(&provider.base_url());
    let daemon = SpawnedDaemon::start_with_home(home).await;
    daemon.home().trust_project();
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

/// Build a parked replay whose real host operation remains live. Once the
/// durable interrupt state becomes `executing`, SIGKILL therefore lands after
/// the replay claim and before the effect can complete, without a product hook
/// or a wall-clock race.
async fn create_parked_session_with_blocked_replay() -> (
    ScriptedProvider,
    SpawnedDaemon,
    AttachedSession,
    Uuid,
    ReplayLaunchBarrier,
) {
    let home = IsolatedHome::new();
    let launch_barrier = ReplayLaunchBarrier::new(home.project_path());
    let provider = lifecycle_provider_for_command(launch_barrier.command()).await;
    home.write_local_provider_config(&provider.base_url());
    std::fs::write(
        home.config_dir().join("config.json"),
        r#"{"active_model":{"provider":"local","model":"scripted"},"sandbox_escalation_enabled":true,"defaultApprovalMode":"auto"}"#,
    )
    .expect("write blocked replay auto approval config");
    let daemon = SpawnedDaemon::start_with_home(home).await;
    daemon.home().trust_project();
    let client = daemon.client().await;
    let attached = client
        .attach(daemon.project_path(), None, None, true)
        .await
        .expect("attach session");
    client
        .send_user_message("trigger blocked lifecycle approval")
        .await
        .expect("send user message");
    let gate_interrupt =
        wait_for_interrupt(&client, &daemon, attached.session_id, Some("initial")).await;
    let approve = offered_approval_option(&daemon.db_path(), gate_interrupt);
    client
        .answer_interrupt_option(gate_interrupt, approve)
        .await
        .expect("approve blocked replay auto gate");
    let interrupt_id =
        wait_for_interrupt(&client, &daemon, attached.session_id, Some("initial")).await;
    (provider, daemon, attached, interrupt_id, launch_barrier)
}

async fn create_auto_gate_parked_session()
-> (ScriptedProvider, SpawnedDaemon, AttachedSession, Uuid) {
    // Keep the provider alive for the daemon lifetime; dropping it closes the listener.
    let home = IsolatedHome::new();
    let provider = lifecycle_provider_for_command(&lifecycle_command(&home)).await;
    home.write_local_provider_config(&provider.base_url());
    std::fs::write(
        home.config_dir().join("config.json"),
        r#"{"active_model":{"provider":"local","model":"scripted"},"sandbox_escalation_enabled":true,"defaultApprovalMode":"auto"}"#,
    )
    .expect("write auto approval replay config");
    let daemon = SpawnedDaemon::start_with_home(home).await;
    daemon.home().trust_project();
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
    let approve = offered_approval_option(&daemon.db_path(), gate_interrupt);
    client
        .answer_interrupt_option(gate_interrupt, approve)
        .await
        .expect("approve gate interrupt");
    let parked_interrupt =
        wait_for_interrupt(&client, &daemon, attached.session_id, Some("initial")).await;

    (provider, daemon, attached, parked_interrupt)
}

/// Deterministic happens-before for a duplicate-resolve negative assertion
/// (criterion 6c). A `ResolveInterrupt` request is dispatched to the session
/// worker via `send_work`, whose `Ack` returns at ENQUEUE time, not after the
/// worker processes it — so the former fixed delay was a wall-clock window
/// hoping a stray second execution would surface. Instead, enqueue a benign
/// follow-up user-message turn BEHIND the duplicate on the worker's FIFO queue
/// and await its `UserMessageRecorded` commit event. Because the worker drains
/// its queue in order, the new durable sequence proves the
/// duplicate was fully processed (and, having no `parked` row to claim, could
/// not have re-executed the replay). This is a happens-before via durable
/// observation — not a wall-clock absence window and immune to event-stream
/// buffering — after which the caller asserts exactly-once execution state.
async fn wait_for_duplicate_resolve_processed(
    client: &cockpit_cli::integration::DaemonClient,
    daemon: &SpawnedDaemon,
    session_id: Uuid,
) {
    let before = session_event_rows(&daemon.db_path(), session_id)
        .last()
        .map_or(0, |(seq, _)| *seq);
    client
        .send_user_message("lifecycle duplicate-resolve sync barrier")
        .await
        .expect("send duplicate-resolve sync-barrier user message");
    loop {
        match client
            .next_event_unbounded()
            .await
            .expect("barrier commit event")
        {
            DaemonEvent::UserMessageRecorded {
                session_id: got,
                seq,
            } if got == session_id && seq > before => break,
            _ => {}
        }
    }
}

async fn restart_daemon_gracefully(daemon: &SpawnedDaemon) {
    let output = daemon.restart_via_command(2).await;
    let text = output_text(&output);
    assert!(output.status.success(), "daemon restart failed: {text}");
    assert!(text.contains("daemon: restarted"));
    daemon.wait_for_handshake().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn lifecycle_graceful_park_round_trip_replays_once() {
    let (provider, daemon, attached, interrupt_id) = create_parked_session().await;

    restart_daemon_gracefully(&daemon).await;

    let client = daemon.client().await;
    let reattached = client
        .attach(daemon.project_path(), Some(attached.session_id), None, true)
        .await
        .expect("reattach session");
    assert_eq!(reattached.session_id, attached.session_id);

    let raised_after_restart =
        wait_for_interrupt(&client, &daemon, attached.session_id, Some("rehydration")).await;
    assert_eq!(raised_after_restart, interrupt_id);
    let db_path = daemon.db_path();
    let row = interrupt_row(&db_path, interrupt_id);
    assert_eq!(row.state, "parked");
    assert_replay_payload(&row, &lifecycle_command(daemon.home()));
    assert!(
        matches!(
            paused_work_status(&daemon.db_path(), attached.session_id).as_deref(),
            Some("paused" | "resumed")
        ),
        "paused work should remain resumable across restart"
    );
    assert_eq!(tool_call_count(&daemon.db_path(), attached.session_id), 0);
    assert_eq!(interrupt_row(&db_path, interrupt_id).state, "parked");

    client
        .approve_interrupt_project(interrupt_id)
        .await
        .expect("approve parked interrupt");
    let tool_seq =
        wait_for_tool_terminal_and_resolved(&client, attached.session_id, interrupt_id).await;
    assert!(tool_seq > 0);
    assert_eq!(
        tool_call_command(&daemon.db_path(), attached.session_id),
        lifecycle_command(daemon.home())
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
}

#[tokio::test(flavor = "multi_thread")]
async fn lifecycle_sigkill_open_interrupt_reconciles_and_replays_once() {
    let (_provider, daemon, attached, interrupt_id) = create_parked_session().await;

    let row = interrupt_row(&daemon.db_path(), interrupt_id);
    assert_eq!(row.state, "open");
    assert_replay_payload(&row, &lifecycle_command(daemon.home()));
    assert_eq!(tool_call_count(&daemon.db_path(), attached.session_id), 0);

    daemon.sigkill().await;
    daemon.restart_same_home().await;

    let client = daemon.client().await;
    client
        .attach(daemon.project_path(), Some(attached.session_id), None, true)
        .await
        .expect("reattach session");
    let raised_after_restart =
        wait_for_interrupt(&client, &daemon, attached.session_id, Some("rehydration")).await;
    assert_eq!(raised_after_restart, interrupt_id);
    assert_eq!(
        interrupt_row(&daemon.db_path(), interrupt_id).state,
        "parked"
    );

    client
        .approve_interrupt_project(interrupt_id)
        .await
        .expect("approve parked interrupt");
    let tool_seq =
        wait_for_tool_terminal_and_resolved(&client, attached.session_id, interrupt_id).await;
    assert!(tool_seq > 0);

    assert_eq!(tool_call_count(&daemon.db_path(), attached.session_id), 1);
    assert_eq!(
        tool_call_command(&daemon.db_path(), attached.session_id),
        lifecycle_command(daemon.home())
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
}

#[tokio::test(flavor = "multi_thread")]
async fn lifecycle_auto_gate_unavailable_park_replay_runs_approved_command() {
    let (_provider, daemon, attached, interrupt_id) = create_auto_gate_parked_session().await;

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
    let row = interrupt_row(&daemon.db_path(), interrupt_id);
    assert_eq!(row.state, "parked");
    assert_replay_payload(&row, &lifecycle_command(daemon.home()));
    assert!(
        row.parked_gate_json.is_some(),
        "parked inner prompt must carry the already-approved gate memo"
    );
    assert_eq!(tool_call_count(&daemon.db_path(), attached.session_id), 0);

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
        lifecycle_command(daemon.home())
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn lifecycle_auto_gate_unavailable_sigkill_park_replay_runs_approved_command() {
    let (_provider, daemon, attached, interrupt_id) = create_auto_gate_parked_session().await;

    let row = interrupt_row(&daemon.db_path(), interrupt_id);
    assert_eq!(row.state, "open");
    assert_replay_payload(&row, &lifecycle_command(daemon.home()));
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
    assert_eq!(
        wait_for_interrupt(&client, &daemon, attached.session_id, Some("rehydration")).await,
        interrupt_id
    );
    assert_eq!(
        interrupt_row(&daemon.db_path(), interrupt_id).state,
        "parked"
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
        lifecycle_command(daemon.home())
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn lifecycle_deny_round_trip_resolves_without_broadened_rerun() {
    let (_provider, daemon, attached, interrupt_id) = create_parked_session().await;

    // The real registered approval waiter is the shutdown obligation. The
    // restart command cannot return (and its replacement cannot own the
    // pid/socket) until the worker's park transaction reaches a terminal;
    // this single-shot read checks that exit boundary with no polling.
    // The registry's park-commit tests independently hold the terminal to
    // force the excluded interleaving without blocking unrelated SQLite
    // writers in this process-boundary test.
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
    assert_eq!(
        interrupt_row(&daemon.db_path(), interrupt_id).state,
        "parked"
    );

    client
        .deny_interrupt(interrupt_id)
        .await
        .expect("deny parked interrupt");
    let tool_seq =
        wait_for_tool_terminal_and_resolved(&client, attached.session_id, interrupt_id).await;
    assert!(tool_seq > 0);

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
}

#[tokio::test(flavor = "multi_thread")]
async fn lifecycle_restart_command_preserves_parked_session_and_starts_when_absent() {
    let (_provider, daemon, attached, interrupt_id) = create_parked_session().await;
    let old_pid = daemon.pid();

    restart_daemon_gracefully(&daemon).await;
    assert_ne!(
        daemon.pid(),
        old_pid,
        "restart must publish a new generation"
    );

    let client = daemon.client().await;
    let reattached = client
        .attach(daemon.project_path(), Some(attached.session_id), None, true)
        .await
        .expect("reattach session");
    assert_eq!(reattached.session_id, attached.session_id);
    assert_eq!(
        wait_for_interrupt(&client, &daemon, attached.session_id, Some("rehydration")).await,
        interrupt_id
    );
    assert_eq!(
        interrupt_row(&daemon.db_path(), interrupt_id).state,
        "parked"
    );
    drop(client);

    let stop = daemon.stop_via_command(0);
    assert!(stop.status.success(), "{}", output_text(&stop));
    assert!(
        daemon.try_pid().is_none(),
        "stop success must retire pid metadata"
    );

    let restart = daemon.restart_via_command(0).await;
    assert!(restart.status.success(), "{}", output_text(&restart));
    assert!(
        output_text(&restart).contains("daemon: was not running; started"),
        "{}",
        output_text(&restart)
    );
    daemon.wait_for_handshake().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn lifecycle_sigkill_executing_interrupt_reconciles_to_interrupted_without_reexecute() {
    let (_provider, daemon, attached, interrupt_id, mut launch_barrier) =
        create_parked_session_with_blocked_replay().await;

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
    let approve = offered_approval_option(&daemon.db_path(), interrupt_id);
    client
        .answer_interrupt_option(interrupt_id, approve)
        .await
        .expect("approve parked interrupt");
    wait_for_tool_start(&client, attached.session_id).await;
    assert_eq!(
        interrupt_row(&daemon.db_path(), interrupt_id).state,
        "executing",
        "host-effect boundary must follow the durable executing claim"
    );

    {
        let launched = launch_barrier.wait_for_launch();
        tokio::pin!(launched);
        loop {
            tokio::select! {
                () = &mut launched => break,
                event = client.next_event_unbounded() => {
                    if let DaemonEvent::InterruptRaised {
                        session_id,
                        interrupt_id: launch_interrupt,
                        ..
                    } = event.expect("daemon event while crossing host-operation launch barrier")
                        && session_id == attached.session_id
                    {
                        let approve = offered_approval_option(&daemon.db_path(), launch_interrupt);
                        client
                            .answer_interrupt_option(launch_interrupt, approve)
                            .await
                            .expect("approve launch-barrier operation");
                    }
                }
            }
        }
    }
    #[cfg(target_os = "linux")]
    let sandbox_descendants = daemon.capture_owned_sandbox_descendants();

    daemon.sigkill().await;
    #[cfg(target_os = "linux")]
    sandbox_descendants.assert_exited();
    daemon.restart_same_home().await;
    let client = daemon.client().await;
    client
        .attach(daemon.project_path(), Some(attached.session_id), None, true)
        .await
        .expect("reattach session");
    assert_eq!(
        interrupt_row(&daemon.db_path(), interrupt_id).state,
        "interrupted"
    );

    client
        .approve_interrupt_once(interrupt_id)
        .await
        .expect("late duplicate approve request");
    wait_for_duplicate_resolve_processed(&client, &daemon, attached.session_id).await;
    assert!(
        tool_call_count(&daemon.db_path(), attached.session_id) <= 1,
        "executing crash must not re-execute parked replay"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn lifecycle_attach_replay_across_restart_delivers_persisted_events_once_in_order() {
    let (_provider, daemon, attached, interrupt_id) = create_parked_session().await;

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
    let tool_seq =
        wait_for_tool_terminal_and_resolved(&client, attached.session_id, interrupt_id).await;
    assert!(tool_seq > 0);

    assert!(
        session_event_rows(&daemon.db_path(), attached.session_id)
            .iter()
            .any(|(_, kind)| kind == "tool_call"),
        "replay fixture must include at least one persisted tool call"
    );

    daemon.sigkill().await;
    daemon.restart_same_home().await;
    let expected_rows = session_event_rows(&daemon.db_path(), attached.session_id);
    let expected_seqs: Vec<_> = expected_rows.iter().map(|(seq, _)| *seq).collect();
    let expected_max = *expected_seqs.last().expect("persisted session events");
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
    assert_eq!(
        max_seq, expected_max,
        "replay high-water {max_seq} must equal persisted history {expected_max}; replay_entries={replay_entries:?}"
    );
    let mut unique = replay_seqs.clone();
    unique.sort_unstable();
    unique.dedup();
    assert_eq!(unique, replay_seqs, "replay seqs must be unique and sorted");
}
