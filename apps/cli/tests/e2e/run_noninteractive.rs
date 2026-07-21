use std::process::{Child, Command, Output, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::support::{IsolatedHome, output_text};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const TOOL_CALL_ID: &str = "run-approval-call";

struct RunProvider {
    base_url: String,
    saw_structured_denial: Arc<AtomicBool>,
}

impl RunProvider {
    async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind run provider");
        let addr = listener.local_addr().expect("run provider addr");
        let saw_structured_denial = Arc::new(AtomicBool::new(false));
        let denial_probe = saw_structured_denial.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let denial_probe = denial_probe.clone();
                tokio::spawn(async move {
                    let body = read_http_request(&mut stream).await;
                    if body.contains(
                        "noninteractive run: approval auto-denied; re-run with --approve <class> or use the TUI",
                    ) {
                        denial_probe.store(true, Ordering::SeqCst);
                    }
                    if body.contains("cause inference failure") {
                        let payload = r#"{"error":{"message":"injected inference failure"}}"#;
                        let response = format!(
                            "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            payload.len(),
                            payload
                        );
                        let _ = stream.write_all(response.as_bytes()).await;
                        let _ = stream.flush().await;
                        return;
                    }
                    let payload = if body.contains("\"role\":\"tool\"") {
                        text_stream("adapted after approval result")
                    } else if body.contains("trigger question decision") {
                        question_call_stream()
                    } else if body.contains("trigger") && body.contains("approval") {
                        tool_call_stream(body.contains("sandbox") && cfg!(target_os = "linux"))
                    } else {
                        text_stream("run dispatched")
                    };
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
            saw_structured_denial,
        }
    }
}

async fn read_http_request(stream: &mut tokio::net::TcpStream) -> String {
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 4096];
    loop {
        let count = match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return String::new(),
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
        let body_start = headers_end + 4;
        if bytes.len() >= body_start + content_len {
            return String::from_utf8_lossy(&bytes[body_start..body_start + content_len])
                .to_string();
        }
    }
}

fn tool_call_stream(sandbox_escalation: bool) -> String {
    let args = if sandbox_escalation {
        serde_json::json!({ "command": "cat /etc/hostname" })
    } else {
        serde_json::json!({ "command": "pwd", "cwd": "/etc" })
    }
    .to_string();
    let escaped_args = serde_json::to_string(&args).expect("serialize tool args");
    format!(
        "data: {{\"id\":\"run\",\"model\":\"scripted\",\"choices\":[{{\"delta\":{{\"tool_calls\":[{{\"index\":0,\"id\":\"{TOOL_CALL_ID}\",\"type\":\"function\",\"function\":{{\"name\":\"bash\",\"arguments\":{escaped_args}}}}}]}},\"finish_reason\":null}}],\"usage\":null}}\n\n\
         data: {{\"id\":\"run\",\"model\":\"scripted\",\"choices\":[{{\"delta\":{{}},\"finish_reason\":\"tool_calls\"}}],\"usage\":{{\"prompt_tokens\":1,\"completion_tokens\":1,\"total_tokens\":2}}}}\n\n\
         data: [DONE]\n\n"
    )
}

fn question_call_stream() -> String {
    let args = serde_json::json!({
        "questions": [{ "type": "text", "prompt": "Need input?" }]
    })
    .to_string();
    let escaped_args = serde_json::to_string(&args).expect("serialize question args");
    format!(
        "data: {{\"id\":\"run\",\"model\":\"scripted\",\"choices\":[{{\"delta\":{{\"tool_calls\":[{{\"index\":0,\"id\":\"question-call\",\"type\":\"function\",\"function\":{{\"name\":\"question\",\"arguments\":{escaped_args}}}}}]}},\"finish_reason\":null}}],\"usage\":null}}\n\n\
         data: {{\"id\":\"run\",\"model\":\"scripted\",\"choices\":[{{\"delta\":{{}},\"finish_reason\":\"tool_calls\"}}],\"usage\":{{\"prompt_tokens\":1,\"completion_tokens\":1,\"total_tokens\":2}}}}\n\n\
         data: [DONE]\n\n"
    )
}

fn text_stream(text: &str) -> String {
    let text = serde_json::to_string(text).expect("serialize text delta");
    format!(
        "data: {{\"id\":\"run\",\"model\":\"scripted\",\"choices\":[{{\"delta\":{{\"content\":{text}}},\"finish_reason\":null}}],\"usage\":null}}\n\n\
         data: {{\"id\":\"run\",\"model\":\"scripted\",\"choices\":[{{\"delta\":{{\"content\":\"\"}},\"finish_reason\":\"stop\"}}],\"usage\":{{\"prompt_tokens\":1,\"completion_tokens\":1,\"total_tokens\":2}}}}\n\n\
         data: [DONE]\n\n"
    )
}

fn wait_with_timeout(mut child: Child, timeout: Duration) -> Output {
    let deadline = Instant::now() + timeout;
    loop {
        if child.try_wait().expect("poll run process").is_some() {
            return child.wait_with_output().expect("collect run output");
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let output = child.wait_with_output().expect("collect timed-out run");
            panic!("cockpit run exceeded {timeout:?}: {}", output_text(&output));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn spawn_run(mut command: Command) -> Output {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    wait_with_timeout(
        command.spawn().expect("spawn cockpit run"),
        Duration::from_secs(15),
    )
}

#[test]
fn no_prompt_sources_errors() {
    let home = IsolatedHome::new();
    let mut command = home.cockpit();
    command.args(["run", "--ephemeral"]);
    let output = spawn_run(command);
    assert_eq!(output.status.code(), Some(2), "{}", output_text(&output));
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("no prompt: pass a message, --prompt-file, or pipe stdin")
    );
}

#[test]
fn ephemeral_rejects_continuation() {
    let home = IsolatedHome::new();
    for continuation in [
        ["-c", "message"],
        ["-s", "00000000-0000-0000-0000-000000000001"],
    ] {
        let mut command = home.cockpit();
        command.args(["run", "--ephemeral"]);
        command.args(continuation);
        let output = spawn_run(command);
        assert_eq!(output.status.code(), Some(2), "{}", output_text(&output));
        assert!(String::from_utf8_lossy(&output.stderr).contains(
            "--ephemeral sessions cannot be continued; drop --ephemeral or start a new session"
        ));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ephemeral_flag_combinations_dispatch() {
    let provider = RunProvider::start().await;
    let home = IsolatedHome::new();
    home.write_local_provider_config(&provider.base_url);
    home.trust_project();

    let mut command = home.cockpit();
    command.args([
        "--no-sandbox",
        "run",
        "--ephemeral",
        "--json",
        "message argument wins",
    ]);
    let output = spawn_run(command);
    assert!(output.status.success(), "{}", output_text(&output));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("\"event\":\"user_message_recorded\""),
        "{stdout}"
    );
    assert!(
        stdout.contains("\"event\":\"thinking_started\""),
        "{stdout}"
    );
    assert!(
        stdout.contains("\"event\":\"session_attached\""),
        "{stdout}"
    );
    assert!(
        stdout.contains("\"event\":\"run_complete\",\"exit_code\":0,\"ok\":true"),
        "{stdout}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn inference_failure_is_loud() {
    let provider = RunProvider::start().await;
    let home = IsolatedHome::new();
    home.write_local_provider_config(&provider.base_url);
    home.trust_project();

    let mut default_command = home.cockpit();
    default_command.args(["run", "--ephemeral", "cause inference failure"]);
    let default_output = spawn_run(default_command);
    assert_eq!(
        default_output.status.code(),
        Some(1),
        "{}",
        output_text(&default_output)
    );
    assert!(
        String::from_utf8_lossy(&default_output.stderr).contains("inference failed"),
        "{}",
        output_text(&default_output)
    );
    assert!(
        default_output.stdout.is_empty(),
        "failure without partial text must keep stdout empty: {}",
        output_text(&default_output)
    );

    let mut json_command = home.cockpit();
    json_command.args(["run", "--ephemeral", "--json", "cause inference failure"]);
    let json_output = spawn_run(json_command);
    assert_eq!(
        json_output.status.code(),
        Some(1),
        "{}",
        output_text(&json_output)
    );
    let stdout = String::from_utf8_lossy(&json_output.stdout);
    assert!(
        stdout.contains("\"event\":\"inference_failed\""),
        "{stdout}"
    );
    assert!(
        stdout.contains("\"event\":\"run_complete\",\"exit_code\":1,\"ok\":false"),
        "{stdout}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn usage_errors_exit_two_and_post_attach_error_keeps_session_id() {
    let provider = RunProvider::start().await;
    let home = IsolatedHome::new();
    home.write_local_provider_config(&provider.base_url);
    home.trust_project();

    let mut invalid_agent = home.cockpit();
    invalid_agent.args([
        "run",
        "--ephemeral",
        "--agent",
        "definitely-not-an-agent",
        "message",
    ]);
    let output = spawn_run(invalid_agent);
    assert_eq!(output.status.code(), Some(2), "{}", output_text(&output));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("session: "), "{stderr}");

    std::fs::write(home.project_path().join("invalid.png"), b"not a png")
        .expect("write invalid attachment");
    let mut invalid_attachment = home.cockpit();
    invalid_attachment.args(["run", "--ephemeral", "--file", "invalid.png", "message"]);
    let output = spawn_run(invalid_attachment);
    assert_eq!(output.status.code(), Some(2), "{}", output_text(&output));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("attachment is not a valid PNG"), "{stderr}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cwd_flag_sets_workspace_root() {
    let provider = RunProvider::start().await;
    let home = IsolatedHome::new();
    home.write_local_provider_config(&provider.base_url);
    home.trust_project();
    let target = home.project_path().join("target");
    std::fs::create_dir(&target).expect("create target workspace");

    let mut refused = home.cockpit();
    refused.args([
        "run",
        "--ephemeral",
        "--cwd",
        target.to_str().expect("utf-8 target"),
        "message",
    ]);
    let refused = spawn_run(refused);
    assert_eq!(refused.status.code(), Some(3), "{}", output_text(&refused));
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("workspace trust is not set"),
        "{}",
        output_text(&refused)
    );

    let trust = home
        .cockpit()
        .args([
            "trust",
            "set",
            target.to_str().expect("utf-8 target"),
            "--mode",
            "trust",
        ])
        .output()
        .expect("trust target workspace");
    assert!(trust.status.success(), "{}", output_text(&trust));

    let mut aliased = home.cockpit();
    aliased.args([
        "--project",
        target.to_str().expect("utf-8 target"),
        "run",
        "--ephemeral",
        "--json",
        "message",
    ]);
    let output = spawn_run(aliased);
    assert!(output.status.success(), "{}", output_text(&output));
    let attached = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .find(|event| event["event"] == "session_attached")
        .expect("session_attached event");
    let session_id = attached["session_id"].as_str().expect("session id");
    let connection = rusqlite::Connection::open(home.db_path()).expect("open run db");
    let project_root: String = connection
        .query_row(
            "SELECT project_root FROM sessions WHERE session_id = ?1",
            [session_id],
            |row| row.get(0),
        )
        .expect("query run session root");
    assert_eq!(
        project_root,
        target.canonicalize().unwrap().display().to_string()
    );

    let mut mismatched = home.cockpit();
    mismatched.args([
        "run",
        "--cwd",
        home.project_path().to_str().expect("utf-8 project"),
        "--session",
        session_id,
        "message",
    ]);
    let mismatch = spawn_run(mismatched);
    assert_eq!(
        mismatch.status.code(),
        Some(2),
        "{}",
        output_text(&mismatch)
    );
    assert!(
        String::from_utf8_lossy(&mismatch.stderr).contains("belongs to"),
        "{}",
        output_text(&mismatch)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn run_approval_auto_denied() {
    let provider = RunProvider::start().await;
    let home = IsolatedHome::new();
    home.write_local_provider_config(&provider.base_url);
    std::fs::write(
        home.config_dir().join("config.json"),
        r#"{"active_model":{"provider":"local","model":"scripted"},"sandbox_escalation_enabled":true}"#,
    )
    .expect("enable sandbox escalation");
    home.trust_project();

    let mut default_command = home.cockpit();
    default_command.args(["run", "--ephemeral", "trigger sandbox approval"]);
    let default_output = spawn_run(default_command);
    assert!(
        default_output.status.success(),
        "{}",
        output_text(&default_output)
    );
    let stderr = String::from_utf8_lossy(&default_output.stderr);
    assert!(
        stderr.contains(
            "noninteractive run: approval auto-denied; re-run with --approve <class> or use the TUI"
        ),
        "{stderr}"
    );
    assert!(
        String::from_utf8_lossy(&default_output.stdout).contains("adapted after approval result")
    );
    assert!(
        provider.saw_structured_denial.load(Ordering::SeqCst),
        "model did not receive the structured noninteractive denial"
    );

    let mut json_command = home.cockpit();
    json_command.args(["run", "--ephemeral", "--json", "trigger sandbox approval"]);
    let json_output = spawn_run(json_command);
    assert!(
        json_output.status.success(),
        "{}",
        output_text(&json_output)
    );
    let stdout = String::from_utf8_lossy(&json_output.stdout);
    assert!(
        stdout.contains("\"event\":\"approval_request\""),
        "{stdout}"
    );
    assert!(
        stdout.contains("\"event\":\"approval_resolved\""),
        "{stdout}"
    );
    assert!(stdout.contains("\"outcome\":\"auto_denied\""), "{stdout}");

    provider
        .saw_structured_denial
        .store(false, Ordering::SeqCst);
    let mut question_command = home.cockpit();
    question_command.args(["run", "--ephemeral", "--json", "trigger question decision"]);
    let question_output = spawn_run(question_command);
    assert!(
        question_output.status.success(),
        "{}",
        output_text(&question_output)
    );
    assert!(
        provider.saw_structured_denial.load(Ordering::SeqCst),
        "question-tool cancellation did not reach the model as a structured denial"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn run_approve_class_grants() {
    let provider = RunProvider::start().await;
    let home = IsolatedHome::new();
    home.write_local_provider_config(&provider.base_url);
    home.trust_project();

    let mut command = home.cockpit();
    command.args([
        "run",
        "--ephemeral",
        "--json",
        "--approve",
        "path",
        "trigger approval",
    ]);
    let output = spawn_run(command);
    assert!(output.status.success(), "{}", output_text(&output));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("\"outcome\":\"approved_once\""), "{stdout}");
    assert!(!stdout.contains("\"outcome\":\"auto_denied\""), "{stdout}");
    assert!(stdout.contains("adapted after approval result"), "{stdout}");
}
