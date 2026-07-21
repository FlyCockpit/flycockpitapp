#![cfg(unix)]

mod support;

use std::future::Future;
use std::path::Path;
use std::sync::{
    Arc, LazyLock, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;

use cockpit_cli::integration::{AttachedSession, DaemonEvent};
use rusqlite::{Connection, params};
use support::{IsolatedHome, SpawnedDaemon, log_tail, output_text, wait_until};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;

const TOOL_CALL_ID: &str = "call_lifecycle_bash";
const COMMAND: &str = "cat /etc/shadow";

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

#[derive(Clone)]
struct ScriptedProvider {
    base_url: String,
    requests: Arc<AtomicUsize>,
}

impl ScriptedProvider {
    async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind scripted provider");
        let addr = listener.local_addr().expect("scripted provider addr");
        let requests = Arc::new(AtomicUsize::new(0));
        let request_count = requests.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let ordinal = request_count.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    let _body = read_http_request(&mut stream).await;
                    let payload = if ordinal == 0 {
                        tool_call_stream()
                    } else {
                        text_stream("lifecycle complete")
                    };
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        payload.len(),
                        payload
                    );
                    let _ = stream.write_all(resp.as_bytes()).await;
                    let _ = stream.flush().await;
                });
            }
        });
        Self {
            base_url: format!("http://{addr}/v1"),
            requests,
        }
    }

    fn request_count(&self) -> usize {
        self.requests.load(Ordering::SeqCst)
    }
}

async fn read_http_request(stream: &mut tokio::net::TcpStream) -> String {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        let n = match stream.read(&mut tmp).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        buf.extend_from_slice(&tmp[..n]);
        let s = String::from_utf8_lossy(&buf);
        if let Some(idx) = s.find("\r\n\r\n") {
            let header = &s[..idx];
            let body_start = idx + 4;
            let content_len = header
                .lines()
                .find_map(|l| {
                    let l = l.to_ascii_lowercase();
                    l.strip_prefix("content-length:")
                        .map(|v| v.trim().parse::<usize>().unwrap_or(0))
                })
                .unwrap_or(0);
            if buf.len() >= body_start + content_len {
                return String::from_utf8_lossy(&buf[body_start..body_start + content_len])
                    .to_string();
            }
        }
    }
    String::new()
}

fn tool_call_stream() -> String {
    let args = serde_json::json!({ "command": COMMAND }).to_string();
    let escaped_args = serde_json::to_string(&args).expect("serialize tool args string");
    format!(
        "data: {{\"id\":\"c\",\"model\":\"scripted\",\"choices\":[{{\"delta\":{{\"tool_calls\":[{{\"index\":0,\"id\":\"{TOOL_CALL_ID}\",\"type\":\"function\",\"function\":{{\"name\":\"bash\",\"arguments\":{escaped_args}}}}}]}},\"finish_reason\":null}}],\"usage\":null}}\n\n\
         data: {{\"id\":\"c\",\"model\":\"scripted\",\"choices\":[{{\"delta\":{{}},\"finish_reason\":\"tool_calls\"}}],\"usage\":{{\"prompt_tokens\":1,\"completion_tokens\":1,\"total_tokens\":2}}}}\n\n\
         data: [DONE]\n\n"
    )
}

fn text_stream(text: &str) -> String {
    let text = serde_json::to_string(text).expect("serialize text delta");
    format!(
        "data: {{\"id\":\"c\",\"model\":\"scripted\",\"choices\":[{{\"delta\":{{\"content\":{text}}},\"finish_reason\":null}}],\"usage\":null}}\n\n\
         data: {{\"id\":\"c\",\"model\":\"scripted\",\"choices\":[{{\"delta\":{{\"content\":\"\"}},\"finish_reason\":\"stop\"}}],\"usage\":{{\"prompt_tokens\":1,\"completion_tokens\":1,\"total_tokens\":2}}}}\n\n\
         data: [DONE]\n\n"
    )
}

#[derive(Debug, Clone)]
struct InterruptRow {
    state: String,
    parked_tool: Option<String>,
    parked_args_json: Option<String>,
    parked_call_id: Option<String>,
    response_json: Option<String>,
}

fn open_db(path: &Path) -> Connection {
    Connection::open(path).unwrap_or_else(|err| panic!("open db {}: {err}", path.display()))
}

fn interrupt_row(db_path: &Path, interrupt_id: Uuid) -> InterruptRow {
    let conn = open_db(db_path);
    conn.query_row(
        "SELECT state, parked_tool, parked_args_json, parked_call_id, response_json
           FROM needs_attention
          WHERE interrupt_id = ?1",
        params![interrupt_id.to_string()],
        |row| {
            Ok(InterruptRow {
                state: row.get(0)?,
                parked_tool: row.get(1)?,
                parked_args_json: row.get(2)?,
                parked_call_id: row.get(3)?,
                response_json: row.get(4)?,
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

async fn create_parked_session_with_hook(
    pause_replay_executing: bool,
) -> (ScriptedProvider, SpawnedDaemon, AttachedSession, Uuid) {
    let provider = ScriptedProvider::start().await;
    let mut home = IsolatedHome::new();
    if pause_replay_executing {
        home.set_env("COCKPIT_TEST_PAUSE_PARKED_REPLAY_EXECUTING", "1");
    }
    home.write_local_provider_config(&provider.base_url);
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

async fn restart_daemon_gracefully(daemon: &SpawnedDaemon) {
    let output = daemon
        .command()
        .args(["daemon", "restart", "--grace", "2"])
        .output()
        .expect("daemon restart command");
    let text = output_text(&output);
    if !output.status.success() {
        assert!(
            text.contains("daemon connection closed"),
            "unexpected daemon restart failure: {text}"
        );
        let start = daemon
            .command()
            .args(["daemon", "start", "--detach"])
            .output()
            .expect("daemon restart fallback start command");
        assert!(
            start.status.success(),
            "restart fallback start failed after:\n{text}\n{}",
            output_text(&start)
        );
        daemon.wait_for_handshake().await;
        return;
    }
    assert!(text.contains("daemon: restarted"));
    daemon.wait_for_handshake().await;
}

#[test]
fn lifecycle_graceful_park_round_trip_replays_once() {
    run_daemon_replay_test(async {
        let (provider, daemon, attached, interrupt_id) = create_parked_session().await;

        restart_daemon_gracefully(&daemon).await;

        let row = interrupt_row(&daemon.db_path(), interrupt_id);
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
            .approve_interrupt_once(interrupt_id)
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
        tokio::time::sleep(Duration::from_millis(100)).await;
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
            .approve_interrupt_once(interrupt_id)
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
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(tool_call_count(&daemon.db_path(), attached.session_id), 1);
    });
}

#[test]
fn lifecycle_deny_round_trip_resolves_without_broadened_rerun() {
    run_daemon_replay_test(async {
        let (_provider, daemon, attached, interrupt_id) = create_parked_session().await;

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
        assert_eq!(
            interrupt_row(&daemon.db_path(), interrupt_id).state,
            "parked"
        );
        assert_eq!(
            wait_for_interrupt(&client, &daemon, attached.session_id, Some("rehydration")).await,
            interrupt_id
        );

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
            .approve_interrupt_once(interrupt_id)
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
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            tool_call_count(&daemon.db_path(), attached.session_id) <= 1,
            "executing crash must not re-execute parked replay"
        );
    });
}

#[test]
fn lifecycle_attach_replay_across_restart_delivers_persisted_events_once_in_order() {
    run_daemon_replay_test(async {
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
            .approve_interrupt_once(interrupt_id)
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

        assert_eq!(max_seq, expected_max);
        assert_eq!(replay_seqs, expected_seqs);
        let mut unique = replay_seqs.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique, replay_seqs, "replay seqs must be unique and sorted");
    });
}
