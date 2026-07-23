use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use crate::support::{IsolatedHome, output_text};
use cockpit_test_support::provider::{ScriptedProvider, Turn};

const TOOL_CALL_ID: &str = "run-approval-call";

async fn run_provider(turns: Vec<Turn>) -> ScriptedProvider {
    let mut builder = ScriptedProvider::builder();
    for turn in turns {
        builder = builder.turn(turn);
    }
    builder.start().await
}

async fn repeating_text_provider(text: &str) -> ScriptedProvider {
    ScriptedProvider::builder()
        .turn(Turn::Text(text.into()))
        .repeat_last()
        .start()
        .await
}

fn approval_tool_turn(sandbox_escalation: bool) -> Turn {
    let arguments = if sandbox_escalation {
        serde_json::json!({ "command": "cat /etc/hostname" })
    } else {
        serde_json::json!({ "command": "pwd", "cwd": "/etc" })
    };
    Turn::ToolCall {
        id: TOOL_CALL_ID.into(),
        name: "bash".into(),
        arguments,
    }
}

fn question_tool_turn() -> Turn {
    Turn::ToolCall {
        id: "question-call".into(),
        name: "question".into(),
        arguments: serde_json::json!({
            "questions": [{ "type": "text", "prompt": "Need input?" }]
        }),
    }
}

fn text_turn(text: &str) -> Turn {
    Turn::Text(text.into())
}

fn inference_failure_turn() -> Turn {
    Turn::HttpError {
        status: 400,
        body: r#"{"error":{"message":"injected inference failure"}}"#.into(),
    }
}

fn captured_contains(provider: &ScriptedProvider, needle: &str) -> bool {
    provider
        .captured()
        .iter()
        .any(|request| request.body.to_string().contains(needle))
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
    // Keep the provider alive for the spawned run process; dropping it closes the listener.
    let provider = repeating_text_provider("run dispatched").await;
    let home = IsolatedHome::new();
    home.write_local_provider_config(&provider.base_url());
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
    // Keep the provider alive for the spawned run processes; dropping it closes the listener.
    let provider = run_provider(vec![inference_failure_turn(), inference_failure_turn()]).await;
    let home = IsolatedHome::new();
    home.write_local_provider_config(&provider.base_url());
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
    // Keep the provider alive for the spawned run processes; dropping it closes the listener.
    let provider = repeating_text_provider("run dispatched").await;
    let home = IsolatedHome::new();
    home.write_local_provider_config(&provider.base_url());
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
    // Keep the provider alive for the spawned run process; dropping it closes the listener.
    let provider = repeating_text_provider("run dispatched").await;
    let home = IsolatedHome::new();
    home.write_local_provider_config(&provider.base_url());
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
    // Keep the provider alive for the spawned run processes; dropping it closes the listener.
    let provider = run_provider(vec![
        approval_tool_turn(cfg!(target_os = "linux")),
        text_turn("adapted after approval result"),
        approval_tool_turn(cfg!(target_os = "linux")),
        text_turn("adapted after approval result"),
        question_tool_turn(),
        text_turn("adapted after approval result"),
    ])
    .await;
    let home = IsolatedHome::new();
    home.write_local_provider_config(&provider.base_url());
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
        captured_contains(
            &provider,
            "noninteractive run: approval auto-denied; re-run with --approve <class> or use the TUI"
        ),
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

    let mut question_command = home.cockpit();
    question_command.args(["run", "--ephemeral", "--json", "trigger question decision"]);
    let question_output = spawn_run(question_command);
    assert!(
        question_output.status.success(),
        "{}",
        output_text(&question_output)
    );
    assert!(
        captured_contains(&provider, "No interactive client is attached")
            && captured_contains(&provider, "Proceed on your best judgment")
            && captured_contains(&provider, "state the assumption"),
        "headless question guidance did not reach the model"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn run_approve_class_grants() {
    // Keep the provider alive for the spawned run process; dropping it closes the listener.
    let provider = run_provider(vec![
        approval_tool_turn(false),
        text_turn("adapted after approval result"),
    ])
    .await;
    let home = IsolatedHome::new();
    home.write_local_provider_config(&provider.base_url());
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
