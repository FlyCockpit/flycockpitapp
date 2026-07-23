use std::time::Duration;

use crate::support::{IsolatedHome, SpawnedDaemon};
use cockpit_cli::integration::{DaemonClient, DaemonEvent};
use cockpit_test_support::provider::{ScriptedProvider, Turn};
use uuid::Uuid;

const TOOL_CALL_ID: &str = "call_queue_bash";
const COMMAND: &str = "cat /etc/shadow";

struct ParkedScenario {
    /// Keep the provider alive for the daemon lifetime; dropping it closes the listener.
    _provider: ScriptedProvider,
    daemon: SpawnedDaemon,
    client_a: DaemonClient,
    session_id: Uuid,
    interrupt_id: Uuid,
}

async fn parked_scenario() -> ParkedScenario {
    let provider = queue_provider().await;
    let home = IsolatedHome::new();
    home.write_local_provider_config(&provider.base_url());
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
    // Keep the provider alive for the daemon lifetime; dropping it closes the listener.
    let provider = queue_provider().await;
    let home = IsolatedHome::new();
    home.write_local_provider_config(&provider.base_url());
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

async fn queue_provider() -> ScriptedProvider {
    ScriptedProvider::builder()
        .turn(Turn::ToolCall {
            id: TOOL_CALL_ID.into(),
            name: "bash".into(),
            arguments: serde_json::json!({ "command": COMMAND }),
        })
        .turn(Turn::Text("queue completion".into()))
        .repeat_last()
        .start()
        .await
}
