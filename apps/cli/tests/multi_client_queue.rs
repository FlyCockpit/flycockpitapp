#![cfg(unix)]

mod support;

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;

use cockpit_cli::integration::{DaemonClient, DaemonEvent};
use support::{IsolatedHome, SpawnedDaemon};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;

const TOOL_CALL_ID: &str = "call_queue_bash";
const COMMAND: &str = "cat /etc/shadow";

#[derive(Clone)]
struct ScriptedProvider {
    base_url: String,
    _requests: Arc<AtomicUsize>,
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
                        text_stream(&format!("queue completion {ordinal}"))
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
            _requests: requests,
        }
    }
}

struct ParkedScenario {
    _provider: ScriptedProvider,
    daemon: SpawnedDaemon,
    client_a: DaemonClient,
    session_id: Uuid,
    interrupt_id: Uuid,
}

async fn parked_scenario() -> ParkedScenario {
    let provider = ScriptedProvider::start().await;
    let home = IsolatedHome::new();
    home.write_local_provider_config(&provider.base_url);
    home.trust_project();
    let daemon = SpawnedDaemon::start_with_home(home).await;
    let client_a = daemon.client().await;
    let attached = client_a
        .attach(daemon.project_path(), None, None, true)
        .await
        .expect("attach first client");
    client_a
        .send_user_message("trigger queue approval")
        .await
        .expect("send first message");
    let interrupt_id = wait_for_interrupt(&client_a, attached.session_id).await;
    ParkedScenario {
        _provider: provider,
        daemon,
        client_a,
        session_id: attached.session_id,
        interrupt_id,
    }
}

async fn wait_for_interrupt(client: &DaemonClient, session_id: Uuid) -> Uuid {
    let mut seen = Vec::new();
    loop {
        let event = client
            .next_event(Duration::from_secs(20))
            .await
            .unwrap_or_else(|error| panic!("interrupt event: {error}; seen: {seen:#?}"));
        seen.push(format!("{event:?}"));
        if let DaemonEvent::InterruptRaised {
            session_id: got,
            interrupt_id,
            ..
        } = event
            && got == session_id
        {
            return interrupt_id;
        }
    }
}

async fn wait_for_queue(client: &DaemonClient, session_id: Uuid, expected_text: Option<&str>) {
    let mut seen = Vec::new();
    loop {
        let event = client
            .next_event(Duration::from_secs(20))
            .await
            .unwrap_or_else(|error| panic!("queue event: {error}; seen: {seen:#?}"));
        seen.push(format!("{event:?}"));
        if let DaemonEvent::QueueUpdated {
            session_id: got,
            texts,
        } = event
            && got == session_id
        {
            match expected_text {
                Some(expected) if texts.iter().any(|text| text == expected) => return,
                None if texts.is_empty() => return,
                _ => {}
            }
        }
    }
}

async fn wait_for_empty_queue_then_idle(client: &DaemonClient, session_id: Uuid) {
    let mut seen = Vec::new();
    let mut saw_empty_queue = false;
    loop {
        let event = client
            .next_event(Duration::from_secs(20))
            .await
            .unwrap_or_else(|error| panic!("queue drain event: {error}; seen: {seen:#?}"));
        seen.push(format!("{event:?}"));
        match event {
            DaemonEvent::QueueUpdated {
                session_id: got,
                texts,
            } if got == session_id && texts.is_empty() => saw_empty_queue = true,
            DaemonEvent::AgentIdle {
                session_id: got, ..
            } if got == session_id && saw_empty_queue => return,
            _ => {}
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn late_attaching_client_receives_queue_snapshot() {
    let scenario = parked_scenario().await;
    let queued = "queued before attach";
    scenario
        .client_a
        .send_user_message(queued)
        .await
        .expect("queue second message");

    let client_b = scenario.daemon.client().await;
    client_b
        .attach(
            scenario.daemon.project_path(),
            Some(scenario.session_id),
            None,
            true,
        )
        .await
        .expect("attach second client");

    wait_for_queue(&client_b, scenario.session_id, Some(queued)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn attached_client_receives_live_queue_updates() {
    let scenario = parked_scenario().await;
    let queued_before_attach = "queued before both attached";
    scenario
        .client_a
        .send_user_message(queued_before_attach)
        .await
        .expect("queue second message");
    let client_b = scenario.daemon.client().await;
    client_b
        .attach(
            scenario.daemon.project_path(),
            Some(scenario.session_id),
            None,
            true,
        )
        .await
        .expect("attach second client");
    wait_for_queue(&client_b, scenario.session_id, Some(queued_before_attach)).await;

    let queued = "third message queued while both attached";
    scenario
        .client_a
        .send_user_message(queued)
        .await
        .expect("queue live message");

    wait_for_queue(&client_b, scenario.session_id, Some(queued)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn attach_replays_empty_queue_snapshot() {
    let scenario = parked_scenario().await;
    scenario
        .client_a
        .send_user_message("queued then drained")
        .await
        .expect("queue second message");
    scenario
        .client_a
        .deny_interrupt(scenario.interrupt_id)
        .await
        .expect("resolve approval interrupt");

    wait_for_empty_queue_then_idle(&scenario.client_a, scenario.session_id).await;

    let client_b = scenario.daemon.client().await;
    client_b
        .attach(
            scenario.daemon.project_path(),
            Some(scenario.session_id),
            None,
            true,
        )
        .await
        .expect("attach after queue drain");

    wait_for_queue(&client_b, scenario.session_id, None).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn second_window_sees_compact_user_message() {
    let provider = ScriptedProvider::start().await;
    let home = IsolatedHome::new();
    home.write_local_provider_config(&provider.base_url);
    home.trust_project();
    let daemon = SpawnedDaemon::start_with_home(home).await;
    let client_a = daemon.client().await;
    let attached = client_a
        .attach(daemon.project_path(), None, None, true)
        .await
        .expect("attach first client");
    let wire = "review <file path=\"src/lib.rs\">expanded contents</file>";
    let display = "review @src/lib.rs";
    client_a
        .send_user_message_with_display(
            wire,
            Some(display.to_string()),
            vec![(
                "read".to_string(),
                "src/lib.rs".to_string(),
                "142 lines".to_string(),
                true,
            )],
        )
        .await
        .expect("send display-aware message");
    let _interrupt_id = wait_for_interrupt(&client_a, attached.session_id).await;

    let client_b = daemon.client().await;
    let replay = client_b
        .attach(daemon.project_path(), Some(attached.session_id), None, true)
        .await
        .expect("attach second client");

    assert!(
        replay.user_row_texts.iter().any(|text| text == display),
        "second window history should contain compact display form: {:?}",
        replay.user_row_texts
    );
    assert!(
        replay.user_row_texts.iter().all(|text| text != wire),
        "second window history must not expose expanded wire form: {:?}",
        replay.user_row_texts
    );
}

async fn read_http_request(stream: &mut tokio::net::TcpStream) -> String {
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 4096];
    loop {
        let read = match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(read) => read,
        };
        buffer.extend_from_slice(&chunk[..read]);
        let request = String::from_utf8_lossy(&buffer);
        if let Some(header_end) = request.find("\r\n\r\n") {
            let content_len = request[..header_end]
                .lines()
                .find_map(|line| {
                    line.to_ascii_lowercase()
                        .strip_prefix("content-length:")
                        .map(|value| value.trim().parse::<usize>().unwrap_or(0))
                })
                .unwrap_or(0);
            let body_start = header_end + 4;
            if buffer.len() >= body_start + content_len {
                return String::from_utf8_lossy(&buffer[body_start..body_start + content_len])
                    .to_string();
            }
        }
    }
    String::new()
}

fn tool_call_stream() -> String {
    let args = serde_json::json!({ "command": COMMAND }).to_string();
    let escaped_args = serde_json::to_string(&args).expect("serialize tool args");
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
