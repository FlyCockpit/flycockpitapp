#![cfg(unix)]

mod support;

use std::process::Stdio;
use std::time::Duration;

use cockpit_cli::integration::{DaemonClient, DaemonEvent};
use rusqlite::{Connection, params};
use support::{IsolatedHome, SpawnedDaemon, assert_failure, assert_success, output_text};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Clone)]
struct TextProvider {
    base_url: String,
}

impl TextProvider {
    async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind freshness provider");
        let addr = listener.local_addr().expect("freshness provider addr");
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    read_http_request(&mut stream).await;
                    let payload = text_stream("ephemeral history intact");
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        payload.len(),
                        payload
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                    let _ = stream.flush().await;
                });
            }
        });
        Self {
            base_url: format!("http://{addr}/v1"),
        }
    }
}

async fn read_http_request(stream: &mut tokio::net::TcpStream) {
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 4096];
    loop {
        let count = match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(count) => count,
        };
        bytes.extend_from_slice(&chunk[..count]);
        let text = String::from_utf8_lossy(&bytes);
        let Some(headers_end) = text.find("\r\n\r\n") else {
            continue;
        };
        let content_len = text[..headers_end]
            .lines()
            .find_map(|line| {
                line.to_ascii_lowercase()
                    .strip_prefix("content-length:")
                    .and_then(|value| value.trim().parse::<usize>().ok())
            })
            .unwrap_or(0);
        if bytes.len() >= headers_end + 4 + content_len {
            return;
        }
    }
}

fn text_stream(text: &str) -> String {
    let text = serde_json::to_string(text).expect("serialize provider text");
    format!(
        "data: {{\"id\":\"fresh\",\"model\":\"scripted\",\"choices\":[{{\"delta\":{{\"content\":{text}}},\"finish_reason\":null}}],\"usage\":null}}\n\n\
         data: {{\"id\":\"fresh\",\"model\":\"scripted\",\"choices\":[{{\"delta\":{{\"content\":\"\"}},\"finish_reason\":\"stop\"}}],\"usage\":{{\"prompt_tokens\":1,\"completion_tokens\":1,\"total_tokens\":2}}}}\n\n\
         data: [DONE]\n\n"
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn daemon_trust_read_through() {
    let provider = TextProvider::start().await;
    let home = IsolatedHome::new();
    home.write_local_provider_config(&provider.base_url);
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
    let provider = TextProvider::start().await;
    let home = IsolatedHome::new();
    home.write_local_provider_config(&provider.base_url);
    home.trust_project();

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

#[test]
fn daemon_refuses_stale_schema() {
    let home = IsolatedHome::new();
    let db_path = home.db_path();
    std::fs::create_dir_all(db_path.parent().expect("DB parent")).expect("create DB parent");
    let conn = Connection::open(&db_path).expect("create stale DB");
    conn.execute_batch(
        "CREATE TABLE schema_version (version INTEGER PRIMARY KEY);\n\
         INSERT INTO schema_version(version) VALUES (1);",
    )
    .expect("seed stale migration ledger");
    drop(conn);

    let output = home
        .cockpit()
        .args(["daemon", "start", "--foreground"])
        .output()
        .expect("start daemon against stale schema");
    assert_failure("stale-schema daemon start", &output, &home);
    let text = output_text(&output);
    assert!(text.contains("database schema version mismatch"), "{text}");
    assert!(
        text.contains(&format!(
            "found 0, expected {}",
            cockpit_cli::db::EXPECTED_SCHEMA_VERSION
        )),
        "{text}"
    );
    assert!(text.contains("move the database"), "{text}");
    assert!(text.contains("Development schema resets"), "{text}");
    assert!(!home.pid_file().exists(), "stale daemon pid file survived");
    assert!(!home.socket_path().exists(), "stale daemon socket survived");
    let endpoint = home
        .pid_file()
        .parent()
        .expect("daemon state dir")
        .join("daemon-endpoint.json");
    assert!(!endpoint.exists(), "stale daemon endpoint survived");
}
