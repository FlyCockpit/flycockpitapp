use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use futures::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::header::AUTHORIZATION;

use crate::auth::flycockpit::{
    FlycockpitClient, StoredFlycockpitCredential, clear_credential, maybe_load_credential,
};
use crate::daemon::principal::ClientPrincipal;
use crate::daemon::proto::{self, Body, Envelope, Event, InterruptQuestion};
use crate::daemon::relay_envelope::{
    IncomingRelayFrame, RelayPrincipal, daemon_client_frame, daemon_control_frame, parse_incoming,
};
use crate::daemon::server::DaemonContext;

const CONNECTOR_POLL_SECS: u64 = 60;
const CHANNEL_BUFFER: usize = 128;
const OUTBOUND_BUFFER: usize = 256;
const CHANNEL_DUPLEX_BYTES: usize = proto::MAX_FRAME_BYTES;
const ATTENTION_EVENT: &str = "attention";
const PRESENCE_EVENT: &str = "presence";
const HEARTBEAT_SECS: u64 = 30;
const TOKEN_REFRESH_SKEW_SECS: u64 = 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectorRunOutcome {
    Disconnected,
    Disabled,
    Refresh,
    Revoked,
}

#[derive(Debug)]
enum OutboundFrame {
    Client { channel_id: String, payload: Value },
    Control { event: String, payload: Value },
}

struct ChannelHandle {
    input_tx: mpsc::Sender<Value>,
    task: tokio::task::JoinHandle<()>,
}

pub fn spawn_background(ctx: Arc<DaemonContext>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            if ctx.shutdown_signal().is_draining() {
                break;
            }
            match sync_once(ctx.clone()).await {
                Ok(ConnectorRunOutcome::Revoked) => break,
                Ok(ConnectorRunOutcome::Disabled) => {
                    tokio::time::sleep(Duration::from_secs(CONNECTOR_POLL_SECS)).await;
                }
                Ok(ConnectorRunOutcome::Disconnected) => {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
                Ok(ConnectorRunOutcome::Refresh) => {}
                Err(error) => {
                    tracing::warn!(error = %error, "relay connector loop failed");
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
            }
        }
    })
}

async fn sync_once(ctx: Arc<DaemonContext>) -> Result<ConnectorRunOutcome> {
    let Some(credential) = maybe_load_credential() else {
        return Ok(ConnectorRunOutcome::Disabled);
    };
    let Some(state) = ctx
        .db
        .connector_state(&credential.server_url, &credential.instance_id)?
    else {
        return Ok(ConnectorRunOutcome::Disabled);
    };
    if !state.enabled {
        publish_status(
            &ctx,
            &credential,
            false,
            "off",
            state.relay_url.as_deref(),
            None,
        );
        return Ok(ConnectorRunOutcome::Disabled);
    }

    run_enabled_connector(ctx, credential).await
}

async fn run_enabled_connector(
    ctx: Arc<DaemonContext>,
    credential: StoredFlycockpitCredential,
) -> Result<ConnectorRunOutcome> {
    let mut backoff = Backoff::default();
    loop {
        if ctx.shutdown_signal().is_draining() {
            return Ok(ConnectorRunOutcome::Disconnected);
        }
        let Some(state) = ctx
            .db
            .connector_state(&credential.server_url, &credential.instance_id)?
        else {
            return Ok(ConnectorRunOutcome::Disabled);
        };
        if !state.enabled {
            publish_status(
                &ctx,
                &credential,
                false,
                "off",
                state.relay_url.as_deref(),
                None,
            );
            return Ok(ConnectorRunOutcome::Disabled);
        }

        publish_status(
            &ctx,
            &credential,
            true,
            "reconnecting",
            state.relay_url.as_deref(),
            None,
        );
        let token = match FlycockpitClient::new(&credential.server_url) {
            Ok(client) => client.mint_connector_token(&credential).await,
            Err(error) => Err(error),
        };
        let token = match token {
            Ok(token) => token,
            Err(error) => {
                let message = error.to_string();
                publish_status(
                    &ctx,
                    &credential,
                    true,
                    "reconnecting",
                    state.relay_url.as_deref(),
                    Some(&message),
                );
                if is_terminal_auth_error(&message) {
                    let _ = clear_credential();
                    let _ = ctx.db.set_connector_enabled(
                        &credential.server_url,
                        &credential.instance_id,
                        false,
                    );
                    publish_status(&ctx, &credential, false, "off", None, Some(&message));
                    return Ok(ConnectorRunOutcome::Revoked);
                }
                tokio::time::sleep(backoff.next()).await;
                continue;
            }
        };
        let relay_url = token.relay_url.clone();
        let ws_url = daemon_ws_url(&relay_url)?;
        match connect_relay_socket(&ws_url, &token.token).await {
            Ok(ws) => {
                backoff.reset();
                publish_status(&ctx, &credential, true, "connected", Some(&relay_url), None);
                let refresh_after = token_refresh_delay(token.expires_at.as_deref());
                let outcome = run_socket(
                    ctx.clone(),
                    credential.clone(),
                    relay_url.clone(),
                    ws,
                    refresh_after,
                )
                .await;
                match outcome {
                    Ok(ConnectorRunOutcome::Revoked) => return Ok(ConnectorRunOutcome::Revoked),
                    Ok(ConnectorRunOutcome::Refresh) => {
                        publish_status(
                            &ctx,
                            &credential,
                            true,
                            "reconnecting",
                            Some(&relay_url),
                            Some("refreshing connector token"),
                        );
                        continue;
                    }
                    Ok(_) => {
                        publish_status(
                            &ctx,
                            &credential,
                            true,
                            "reconnecting",
                            Some(&relay_url),
                            Some("relay socket disconnected"),
                        );
                    }
                    Err(error) => {
                        let message = error.to_string();
                        publish_status(
                            &ctx,
                            &credential,
                            true,
                            "reconnecting",
                            Some(&relay_url),
                            Some(&message),
                        );
                    }
                }
            }
            Err(error) => {
                let message = error.to_string();
                publish_status(
                    &ctx,
                    &credential,
                    true,
                    "reconnecting",
                    Some(&relay_url),
                    Some(&message),
                );
            }
        }
        tokio::time::sleep(backoff.next()).await;
    }
}

async fn connect_relay_socket(
    ws_url: &str,
    token: &str,
) -> Result<
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
> {
    let mut request = ws_url
        .into_client_request()
        .context("building relay WebSocket request")?;
    let header_value = format!("Bearer {token}")
        .parse()
        .context("building relay authorization header")?;
    request.headers_mut().insert(AUTHORIZATION, header_value);
    let (ws, _) = connect_async(request)
        .await
        .with_context(|| format!("connecting relay WebSocket {ws_url}"))?;
    Ok(ws)
}

async fn run_socket(
    ctx: Arc<DaemonContext>,
    credential: StoredFlycockpitCredential,
    relay_url: String,
    ws: tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    refresh_after: Option<Duration>,
) -> Result<ConnectorRunOutcome> {
    let (mut ws_tx, mut ws_rx) = ws.split();
    let (out_tx, mut out_rx) = mpsc::channel::<OutboundFrame>(OUTBOUND_BUFFER);
    let writer = tokio::spawn(async move {
        while let Some(frame) = out_rx.recv().await {
            let text = match frame {
                OutboundFrame::Client {
                    channel_id,
                    payload,
                } => serde_json::to_string(&daemon_client_frame(channel_id, payload))?,
                OutboundFrame::Control { event, payload } => {
                    serde_json::to_string(&daemon_control_frame(event, payload))?
                }
            };
            ws_tx.send(Message::Text(text.into())).await?;
        }
        anyhow::Ok(())
    });

    let mut channels: HashMap<String, ChannelHandle> = HashMap::new();
    let mut shutdown_rx = ctx.shutdown_signal().subscribe();
    let refresh_sleep =
        tokio::time::sleep(refresh_after.unwrap_or(Duration::from_secs(365 * 24 * 60 * 60)));
    tokio::pin!(refresh_sleep);
    let mut heartbeat = tokio::time::interval(Duration::from_secs(HEARTBEAT_SECS));
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let _ = out_tx
        .send(OutboundFrame::Control {
            event: PRESENCE_EVENT.to_string(),
            payload: json!({ "instanceId": credential.instance_id }),
        })
        .await;
    let result = loop {
        tokio::select! {
            biased;
            _ = shutdown_rx.changed() => {
                break Ok(ConnectorRunOutcome::Disconnected);
            }
            _ = &mut refresh_sleep => {
                break Ok(ConnectorRunOutcome::Refresh);
            }
            _ = heartbeat.tick() => {
                if out_tx
                    .send(OutboundFrame::Control {
                        event: PRESENCE_EVENT.to_string(),
                        payload: json!({ "instanceId": credential.instance_id }),
                    })
                    .await
                    .is_err()
                {
                    break Ok(ConnectorRunOutcome::Disconnected);
                }
            }
            message = ws_rx.next() => {
                let Some(message) = message else {
                    break Ok(ConnectorRunOutcome::Disconnected);
                };
                let message = message.context("reading relay WebSocket frame")?;
                if message.is_close() {
                    break Ok(ConnectorRunOutcome::Disconnected);
                }
                if message.is_ping() || message.is_pong() {
                    continue;
                }
                let text = message.to_text().context("relay sent non-text frame")?;
                match parse_incoming(text).context("parsing relay frame")? {
                    IncomingRelayFrame::System(system) => {
                        tracing::info!(code = %system.code, channel_id = ?system.channel_id, "relay system frame received");
                        if system.code == "forced_disconnect" {
                            if let Some(channel_id) = system.channel_id.as_ref() {
                                if let Some(handle) = channels.remove(channel_id) {
                                    handle.task.abort();
                                }
                                continue;
                            }
                            break Ok(ConnectorRunOutcome::Disconnected);
                        }
                        if system.code == "daemon_replaced" {
                            break Ok(ConnectorRunOutcome::Disconnected);
                        }
                    }
                    IncomingRelayFrame::Client(frame) => {
                        if frame.v != crate::daemon::relay_envelope::RELAY_ENVELOPE_VERSION {
                            continue;
                        }
                        let principal = frame.principal.clone();
                        let handle = channels.entry(frame.channel_id.clone()).or_insert_with(|| {
                            spawn_channel(
                                frame.channel_id.clone(),
                                principal,
                                ctx.clone(),
                                credential.instance_id.clone(),
                                relay_url.clone(),
                                out_tx.clone(),
                            )
                        });
                        if handle.input_tx.try_send(frame.payload).is_err() {
                            tracing::warn!(channel_id = %frame.channel_id, "relay channel input buffer full; dropping channel");
                            handle.task.abort();
                            channels.remove(&frame.channel_id);
                        }
                    }
                }
            }
        }
    };

    for (_, handle) in channels {
        handle.task.abort();
    }
    drop(out_tx);
    writer.abort();
    result
}

fn spawn_channel(
    channel_id: String,
    principal: RelayPrincipal,
    ctx: Arc<DaemonContext>,
    instance_id: String,
    relay_url: String,
    outbound: mpsc::Sender<OutboundFrame>,
) -> ChannelHandle {
    let (input_tx, input_rx) = mpsc::channel(CHANNEL_BUFFER);
    let task = tokio::spawn(async move {
        if let Err(error) = channel_task(
            channel_id,
            principal,
            ctx,
            instance_id,
            relay_url,
            input_rx,
            outbound,
        )
        .await
        {
            tracing::debug!(error = %error, "relay channel closed");
        }
    });
    ChannelHandle { input_tx, task }
}

async fn channel_task(
    channel_id: String,
    principal: RelayPrincipal,
    ctx: Arc<DaemonContext>,
    instance_id: String,
    relay_url: String,
    mut input_rx: mpsc::Receiver<Value>,
    outbound: mpsc::Sender<OutboundFrame>,
) -> Result<()> {
    let (daemon_side, relay_side) = tokio::io::duplex(CHANNEL_DUPLEX_BYTES);
    let daemon_task = tokio::spawn(crate::daemon::server::handle_relay_channel_as(
        daemon_side,
        ctx.clone(),
        ClientPrincipal::from_relay(principal),
    ));
    let (read_half, mut write_half) = tokio::io::split(relay_side);
    let writer = tokio::spawn(async move {
        while let Some(payload) = input_rx.recv().await {
            let mut line = serde_json::to_string(&payload)?;
            line.push('\n');
            write_half.write_all(line.as_bytes()).await?;
        }
        let _ = write_half.shutdown().await;
        anyhow::Ok(())
    });

    let mut lines = BufReader::new(read_half).lines();
    while let Some(line) = lines.next_line().await? {
        if let Some(payload) = attention_payload_from_line(&line, &ctx, &instance_id) {
            let _ = outbound
                .send(OutboundFrame::Control {
                    event: ATTENTION_EVENT.to_string(),
                    payload,
                })
                .await;
        }
        let payload: Value = serde_json::from_str(&line).context("parsing daemon envelope")?;
        outbound
            .send(OutboundFrame::Client {
                channel_id: channel_id.clone(),
                payload,
            })
            .await
            .context("sending relay channel frame")?;
    }

    writer.abort();
    daemon_task.abort();
    let _ = relay_url;
    Ok(())
}

fn publish_status(
    ctx: &DaemonContext,
    credential: &StoredFlycockpitCredential,
    enabled: bool,
    status: &str,
    relay_url: Option<&str>,
    last_error: Option<&str>,
) {
    if let Err(error) = ctx.db.update_connector_status(
        &credential.server_url,
        &credential.instance_id,
        status,
        relay_url,
        last_error,
    ) {
        tracing::warn!(error = %error, "updating connector status failed");
    }
    ctx.broadcast_global(Event::ConnectorStatus {
        enabled,
        status: status.to_string(),
        relay_url: relay_url.map(str::to_string),
        last_error: last_error.map(str::to_string),
    });
}

pub(crate) fn attention_payload_from_line(
    line: &str,
    ctx: &DaemonContext,
    instance_id: &str,
) -> Option<Value> {
    let envelope: Envelope = serde_json::from_str(line).ok()?;
    let Body::Event { event } = envelope.body else {
        return None;
    };
    attention_payload_for_event(&event, ctx, instance_id)
}

pub(crate) fn attention_payload_for_event(
    event: &Event,
    ctx: &DaemonContext,
    instance_id: &str,
) -> Option<Value> {
    let (session_id, kind, description) = match event {
        Event::InterruptRaised {
            session_id,
            question,
            questions,
            ..
        } => {
            let approval = question.as_ref().is_some_and(question_is_approval)
                || questions
                    .as_ref()
                    .is_some_and(|set| set.questions.iter().any(question_is_approval));
            (
                *session_id,
                if approval { "approval" } else { "question" },
                if approval {
                    "Approval needed"
                } else {
                    "Question waiting"
                },
            )
        }
        Event::AgentIdle { session_id, .. } => (*session_id, "turn_done", "Agent finished"),
        Event::SessionPersistFailed { session_id, .. }
        | Event::SessionDriverFailed { session_id, .. }
        | Event::InferenceFailed { session_id, .. } => {
            (*session_id, "turn_error", "Agent turn failed")
        }
        Event::ScheduleCompleted { session_id, .. } => {
            (*session_id, "schedule_done", "Background job finished")
        }
        _ => return None,
    };
    let project_root = ctx
        .db
        .get_session(session_id)
        .ok()
        .flatten()
        .map(|row| row.project_root);
    Some(json!({
        "kind": kind,
        "description": description,
        "sessionId": session_id,
        "projectRoot": project_root,
        "instanceId": instance_id,
    }))
}

fn question_is_approval(question: &InterruptQuestion) -> bool {
    match question {
        InterruptQuestion::Single { permission, .. } => *permission,
        InterruptQuestion::Multi { .. } | InterruptQuestion::Freetext { .. } => false,
    }
}

fn daemon_ws_url(relay_url: &str) -> Result<String> {
    let mut url = reqwest::Url::parse(relay_url).context("parsing relay URL")?;
    match url.scheme() {
        "ws" | "wss" => {}
        scheme => anyhow::bail!("relay URL must use ws or wss, got {scheme}"),
    }
    let path = url.path().trim_end_matches('/').to_string();
    let next = if path.ends_with("/ws/daemon") {
        path
    } else if path.ends_with("/ws") {
        format!("{path}/daemon")
    } else if path.is_empty() || path == "/" {
        "/ws/daemon".to_string()
    } else {
        format!("{path}/ws/daemon")
    };
    url.set_path(&next);
    Ok(url.to_string())
}

fn is_terminal_auth_error(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    lower.contains("revoked") || lower.contains("401") || lower.contains("403")
}

fn token_refresh_delay(expires_at: Option<&str>) -> Option<Duration> {
    let expires_at = expires_at?;
    let expires_at = chrono::DateTime::parse_from_rfc3339(expires_at).ok()?;
    let now = chrono::Utc::now();
    let refresh_at = expires_at.with_timezone(&chrono::Utc)
        - chrono::Duration::seconds(TOKEN_REFRESH_SKEW_SECS as i64);
    let millis = (refresh_at - now).num_milliseconds().max(0) as u64;
    Some(Duration::from_millis(millis))
}

#[derive(Debug, Default)]
struct Backoff {
    idx: usize,
}

impl Backoff {
    fn next(&mut self) -> Duration {
        const STEPS: &[u64] = &[1, 2, 5, 15, 60];
        let secs = STEPS[self.idx.min(STEPS.len() - 1)];
        self.idx = self.idx.saturating_add(1);
        Duration::from_secs(secs) + jitter_for_step(secs)
    }

    fn reset(&mut self) {
        self.idx = 0;
    }
}

fn jitter_for_step(secs: u64) -> Duration {
    let max_millis = (secs * 250).max(1);
    let now = chrono::Utc::now().timestamp_millis().unsigned_abs();
    Duration::from_millis(now % max_millis)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use crate::auth::flycockpit::AccountInfo;
    use crate::daemon::proto::{ErrorCode, ErrorPayload, Request, Response};
    use crate::locks::LockManager;
    use tokio::net::TcpListener;
    use tokio_tungstenite::accept_async;
    use uuid::Uuid;

    fn credential() -> StoredFlycockpitCredential {
        StoredFlycockpitCredential {
            server_url: "https://app.example.test".to_string(),
            instance_id: "instance-1".to_string(),
            instance_token: "fci_secret".to_string(),
            account: AccountInfo {
                user_id: "owner-1".to_string(),
                email: "owner@example.test".to_string(),
            },
            display_name: Some("devbox".to_string()),
        }
    }

    fn test_context() -> (tempfile::TempDir, Arc<DaemonContext>) {
        let tmp = tempfile::tempdir().unwrap();
        let db = crate::db::Db::open_in_memory().unwrap();
        let locks = Arc::new(LockManager::from_db(db.clone()).unwrap());
        let paths = crate::daemon::DaemonPaths {
            pid_file: tmp.path().join("daemon.pid"),
            socket: tmp.path().join("daemon.sock"),
            ephemeral: true,
        };
        (tmp, Arc::new(DaemonContext::new(db, locks, paths)))
    }

    async fn relay_pair() -> (
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
        tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            accept_async(stream).await.unwrap()
        });
        let client = connect_relay_socket(&format!("ws://{addr}/ws/daemon"), "relay-token")
            .await
            .unwrap();
        (client, server.await.unwrap())
    }

    fn stamped_frame(channel_id: &str, payload: Value) -> String {
        serde_json::json!({
            "v": 1,
            "channelId": channel_id,
            "from": "client",
            "principal": {
                "userId": "user-1",
                "grants": [{ "scope": "agent", "projectRoot": null }]
            },
            "payload": payload,
        })
        .to_string()
    }

    async fn next_text(
        ws: &mut tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>,
    ) -> String {
        loop {
            let msg = ws.next().await.unwrap().unwrap();
            if msg.is_text() {
                return msg.into_text().unwrap().to_string();
            }
        }
    }

    #[test]
    fn relay_url_points_to_daemon_socket_path() {
        assert_eq!(
            daemon_ws_url("wss://relay.example.test/ws").unwrap(),
            "wss://relay.example.test/ws/daemon"
        );
        assert_eq!(
            daemon_ws_url("ws://127.0.0.1:3010").unwrap(),
            "ws://127.0.0.1:3010/ws/daemon"
        );
    }

    #[test]
    fn protocol_payload_round_trips_without_handler_translation() {
        let env = Envelope::response(
            Uuid::nil(),
            Response::DaemonStatus {
                pid: 1,
                uptime_secs: 2,
                active_sessions: 0,
                socket_path: "/tmp/cockpit.sock".to_string(),
                daemon_version: "0.1.0".to_string(),
                protocol_version: proto::PROTOCOL_VERSION,
                paused_sessions: 0,
            },
        );
        let line = serde_json::to_string(&env).unwrap();
        let payload: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(
            payload,
            serde_json::to_value(env).unwrap(),
            "relay bridge must carry the daemon envelope unchanged"
        );
    }

    #[tokio::test]
    async fn websocket_channel_round_trips_through_daemon_dispatcher() {
        let (_tmp, ctx) = test_context();
        let (client_ws, mut relay_ws) = relay_pair().await;
        let run = tokio::spawn(run_socket(
            ctx,
            credential(),
            "ws://127.0.0.1/ws".to_string(),
            client_ws,
            None,
        ));

        let request_id = Uuid::new_v4();
        let request = Envelope::request(request_id, Request::DaemonStatus);
        relay_ws
            .send(Message::Text(
                stamped_frame("ch-1", serde_json::to_value(request).unwrap()).into(),
            ))
            .await
            .unwrap();

        let mut matched = None;
        let mut saw_channel = false;
        for _ in 0..8 {
            let next = next_text(&mut relay_ws).await;
            let next: Value = serde_json::from_str(&next).unwrap();
            if next.get("channelId").is_none() {
                continue;
            }
            assert_eq!(next["channelId"], "ch-1");
            saw_channel = true;
            if next["payload"]["id"] == request_id.to_string() {
                matched = Some(next);
                break;
            }
        }
        assert!(saw_channel, "expected at least one channel frame");
        let response = matched.expect("daemon_status response for request id");
        assert_eq!(response["channelId"], "ch-1");
        assert_eq!(response["payload"]["response"], "daemon_status");

        relay_ws.close(None).await.unwrap();
        assert_eq!(
            run.await.unwrap().unwrap(),
            ConnectorRunOutcome::Disconnected
        );
    }

    #[tokio::test]
    async fn websocket_two_channels_keep_responses_isolated() {
        let (_tmp, ctx) = test_context();
        let (client_ws, mut relay_ws) = relay_pair().await;
        let run = tokio::spawn(run_socket(
            ctx,
            credential(),
            "ws://127.0.0.1/ws".to_string(),
            client_ws,
            None,
        ));

        let request_a = Uuid::new_v4();
        let request_b = Uuid::new_v4();
        relay_ws
            .send(Message::Text(
                stamped_frame(
                    "ch-a",
                    serde_json::to_value(Envelope::request(request_a, Request::DaemonStatus))
                        .unwrap(),
                )
                .into(),
            ))
            .await
            .unwrap();
        relay_ws
            .send(Message::Text(
                stamped_frame(
                    "ch-b",
                    serde_json::to_value(Envelope::request(request_b, Request::DaemonStatus))
                        .unwrap(),
                )
                .into(),
            ))
            .await
            .unwrap();

        let mut seen_a = false;
        let mut seen_b = false;
        for _ in 0..12 {
            let next = next_text(&mut relay_ws).await;
            let next: Value = serde_json::from_str(&next).unwrap();
            let Some(channel_id) = next.get("channelId").and_then(Value::as_str) else {
                continue;
            };
            let Some(payload_id) = next
                .get("payload")
                .and_then(|payload| payload.get("id"))
                .and_then(Value::as_str)
            else {
                continue;
            };
            match payload_id {
                id if id == request_a.to_string() => {
                    assert_eq!(channel_id, "ch-a");
                    seen_a = true;
                }
                id if id == request_b.to_string() => {
                    assert_eq!(channel_id, "ch-b");
                    seen_b = true;
                }
                _ => {}
            }
            if seen_a && seen_b {
                break;
            }
        }
        assert!(seen_a, "expected ch-a response");
        assert!(seen_b, "expected ch-b response");

        relay_ws.close(None).await.unwrap();
        assert_eq!(
            run.await.unwrap().unwrap(),
            ConnectorRunOutcome::Disconnected
        );
    }

    #[tokio::test(start_paused = true)]
    async fn websocket_refresh_deadline_reconnects_without_socket_drop() {
        let (_tmp, ctx) = test_context();
        let (client_ws, mut relay_ws) = relay_pair().await;
        let run = tokio::spawn(run_socket(
            ctx,
            credential(),
            "ws://127.0.0.1/ws".to_string(),
            client_ws,
            Some(Duration::from_secs(5)),
        ));

        let presence: Value = serde_json::from_str(&next_text(&mut relay_ws).await).unwrap();
        assert_eq!(presence["event"], "presence");
        tokio::time::advance(Duration::from_secs(5)).await;
        assert_eq!(run.await.unwrap().unwrap(), ConnectorRunOutcome::Refresh);
    }

    #[test]
    fn token_refresh_delay_uses_server_expiration_with_skew() {
        let expires_at = (chrono::Utc::now() + chrono::Duration::seconds(120)).to_rfc3339();
        let delay = token_refresh_delay(Some(&expires_at)).unwrap();
        assert!(delay <= Duration::from_secs(61));
        assert!(delay >= Duration::from_secs(55));

        let expires_at = (chrono::Utc::now() + chrono::Duration::seconds(10)).to_rfc3339();
        assert_eq!(token_refresh_delay(Some(&expires_at)), Some(Duration::ZERO));
    }

    #[test]
    fn backoff_ladder_adds_bounded_jitter() {
        let mut backoff = Backoff::default();
        let first = backoff.next();
        assert!(first >= Duration::from_secs(1));
        assert!(first < Duration::from_millis(1250));
        let second = backoff.next();
        assert!(second >= Duration::from_secs(2));
        assert!(second < Duration::from_millis(2500));
    }

    #[tokio::test]
    async fn force_disconnect_system_frame_stops_connector() {
        let (_tmp, ctx) = test_context();
        let (client_ws, mut relay_ws) = relay_pair().await;
        let run = tokio::spawn(run_socket(
            ctx,
            credential(),
            "ws://127.0.0.1/ws".to_string(),
            client_ws,
            None,
        ));
        let presence: Value = serde_json::from_str(&next_text(&mut relay_ws).await).unwrap();
        assert_eq!(presence["to"], "control");
        assert_eq!(presence["event"], "presence");
        assert_eq!(presence["payload"]["instanceId"], "instance-1");
        relay_ws
            .send(Message::Text(
                serde_json::json!({ "v": 1, "type": "system", "code": "forced_disconnect" })
                    .to_string()
                    .into(),
            ))
            .await
            .unwrap();
        assert_eq!(
            run.await.unwrap().unwrap(),
            ConnectorRunOutcome::Disconnected
        );
    }

    #[test]
    fn attention_payload_is_fixed_string_and_omits_user_text() {
        let (_tmp, ctx) = test_context();
        let event = Event::InterruptRaised {
            session_id: Uuid::new_v4(),
            interrupt_id: Uuid::new_v4(),
            agent: "Build".to_string(),
            description: "please approve DO_NOT_FORWARD_USER_TEXT".to_string(),
            question: Some(InterruptQuestion::Single {
                prompt: "run secret command?".to_string(),
                options: vec![],
                allow_freetext: false,
                command_detail: None,
                permission: true,
                sandbox_escalation: None,
            }),
            questions: None,
        };
        let payload = attention_payload_for_event(&event, &ctx, "instance-1").unwrap();
        assert_eq!(payload["kind"], "approval");
        assert_eq!(payload["description"], "Approval needed");
        let serialized = payload.to_string();
        assert!(!serialized.contains("DO_NOT_FORWARD_USER_TEXT"));
        assert!(!serialized.contains("run secret command"));
    }

    #[test]
    fn protocol_mismatch_error_is_existing_daemon_error() {
        let env = Envelope::error(
            Some(Uuid::nil()),
            ErrorPayload {
                code: ErrorCode::ProtocolVersion,
                message: proto::version_mismatch_message(1),
            },
        );
        let payload = serde_json::to_value(env).unwrap();
        assert_eq!(payload["error"]["code"], "protocol_version");
        assert!(payload["error"]["message"].as_str().unwrap().contains("v1"));
    }
}
