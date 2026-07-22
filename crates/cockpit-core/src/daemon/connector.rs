use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use futures::{SinkExt, StreamExt, future::join_all};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::{mpsc, watch};
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::header::AUTHORIZATION;

use crate::auth::flycockpit::{
    FlycockpitClient, RelayCandidate, RelayChoice, StoredFlycockpitCredential, clear_credential,
    maybe_load_credential, store_relay_choice,
};
use crate::daemon::principal::ClientPrincipal;
use crate::daemon::proto::{self, Body, Envelope, Event, InterruptQuestion};
use crate::daemon::relay_envelope::{
    AttentionEventType, AttentionNotificationPayload, IncomingRelayFrame, RelayPrincipal,
    daemon_client_frame, daemon_control_frame, parse_incoming,
};
use crate::daemon::server::DaemonContext;
use crate::db::connector::ConnectorStatusUpdate;

const CHANNEL_BUFFER: usize = 128;
const OUTBOUND_BUFFER: usize = 256;
const CHANNEL_DUPLEX_BYTES: usize = proto::MAX_FRAME_BYTES;
const PRESENCE_EVENT: &str = "presence";
const HEARTBEAT_SECS: u64 = 30;
const TOKEN_REFRESH_SKEW_SECS: u64 = 60;
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);
const COLD_PROBE_JITTER_MAX: Duration = Duration::from_secs(3);
const STABLE_CONNECTION_RESET: Duration = Duration::from_secs(60);

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
        let mut wake_rx = ctx.connector_wake_rx();
        loop {
            if ctx.shutdown_signal().is_draining() {
                break;
            }
            match sync_once(ctx.clone(), &mut wake_rx).await {
                Ok(ConnectorRunOutcome::Revoked) => break,
                Ok(ConnectorRunOutcome::Disabled) => {
                    sleep_or_connector_wake(&mut wake_rx, Duration::from_secs(60)).await;
                }
                Ok(ConnectorRunOutcome::Disconnected) => {
                    sleep_or_connector_wake(&mut wake_rx, Duration::from_secs(1)).await;
                }
                Ok(ConnectorRunOutcome::Refresh) => {}
                Err(error) => {
                    tracing::warn!(error = %error, "relay connector loop failed");
                    sleep_or_connector_wake(&mut wake_rx, Duration::from_secs(5)).await;
                }
            }
        }
    })
}

async fn sleep_or_connector_wake(wake_rx: &mut watch::Receiver<u64>, duration: Duration) {
    tokio::select! {
        _ = wake_rx.changed() => {}
        _ = tokio::time::sleep(duration) => {}
    }
}

async fn sync_once(
    ctx: Arc<DaemonContext>,
    wake_rx: &mut watch::Receiver<u64>,
) -> Result<ConnectorRunOutcome> {
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
            ConnectorStatusUpdate {
                status: "off",
                relay_url: state.relay_url.as_deref(),
                relay_id: state.relay_id.as_deref(),
                relay_region: state.relay_region.as_deref(),
                last_error: None,
            },
        );
        return Ok(ConnectorRunOutcome::Disabled);
    }

    run_enabled_connector(ctx, credential, wake_rx).await
}

async fn run_enabled_connector(
    ctx: Arc<DaemonContext>,
    mut credential: StoredFlycockpitCredential,
    wake_rx: &mut watch::Receiver<u64>,
) -> Result<ConnectorRunOutcome> {
    let mut backoff = Backoff::default();
    let mut jitter = SystemJitter;
    let mut first_connect = true;
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
                ConnectorStatusUpdate {
                    status: "off",
                    relay_url: state.relay_url.as_deref(),
                    relay_id: state.relay_id.as_deref(),
                    relay_region: state.relay_region.as_deref(),
                    last_error: None,
                },
            );
            return Ok(ConnectorRunOutcome::Disabled);
        }

        publish_status(
            &ctx,
            &credential,
            true,
            ConnectorStatusUpdate {
                status: "reconnecting",
                relay_url: state.relay_url.as_deref(),
                relay_id: state.relay_id.as_deref(),
                relay_region: state.relay_region.as_deref(),
                last_error: None,
            },
        );

        let client = match FlycockpitClient::new(&credential.server_url) {
            Ok(client) => client,
            Err(error) => {
                let message = error.to_string();
                publish_status(
                    &ctx,
                    &credential,
                    true,
                    ConnectorStatusUpdate {
                        status: "reconnecting",
                        relay_url: state.relay_url.as_deref(),
                        relay_id: state.relay_id.as_deref(),
                        relay_region: state.relay_region.as_deref(),
                        last_error: Some(&message),
                    },
                );
                sleep_or_connector_wake(wake_rx, backoff.next(&mut jitter)).await;
                continue;
            }
        };

        let mut stale_cache_retry = false;
        let (choice, token) = loop {
            let selected =
                match select_relay(&client, &credential, first_connect, &mut jitter).await {
                    Ok(Some(selected)) => selected,
                    Ok(None) => {
                        let message = "no relay candidates available";
                        publish_status(
                            &ctx,
                            &credential,
                            true,
                            ConnectorStatusUpdate {
                                status: "reconnecting",
                                relay_url: state.relay_url.as_deref(),
                                relay_id: state.relay_id.as_deref(),
                                relay_region: state.relay_region.as_deref(),
                                last_error: Some(message),
                            },
                        );
                        first_connect = false;
                        sleep_or_connector_wake(wake_rx, backoff.next(&mut jitter)).await;
                        continue;
                    }
                    Err(error) => {
                        let message = error.to_string();
                        publish_status(
                            &ctx,
                            &credential,
                            true,
                            ConnectorStatusUpdate {
                                status: "reconnecting",
                                relay_url: state.relay_url.as_deref(),
                                relay_id: state.relay_id.as_deref(),
                                relay_region: state.relay_region.as_deref(),
                                last_error: Some(&message),
                            },
                        );
                        if is_terminal_auth_error(&message) {
                            let _ = clear_credential();
                            let _ = ctx.db.set_connector_enabled(
                                &credential.server_url,
                                &credential.instance_id,
                                false,
                            );
                            publish_status(
                                &ctx,
                                &credential,
                                false,
                                ConnectorStatusUpdate {
                                    status: "off",
                                    relay_url: None,
                                    relay_id: None,
                                    relay_region: None,
                                    last_error: Some(&message),
                                },
                            );
                            return Ok(ConnectorRunOutcome::Revoked);
                        }
                        first_connect = false;
                        sleep_or_connector_wake(wake_rx, backoff.next(&mut jitter)).await;
                        continue;
                    }
                };

            match client
                .mint_connector_token(&credential, &selected.choice.relay_id)
                .await
            {
                Ok(token) => break (selected.choice, token),
                Err(error)
                    if selected.from_cache
                        && !stale_cache_retry
                        && is_not_found_error(&error.to_string()) =>
                {
                    stale_cache_retry = true;
                    first_connect = false;
                    match store_relay_choice(&credential, None) {
                        Ok(next) => credential = next,
                        Err(store_error) => {
                            tracing::warn!(error = %store_error, "clearing cached relay choice failed");
                            credential.relay_choice = None;
                        }
                    }
                    continue;
                }
                Err(error) => {
                    let message = error.to_string();
                    publish_status(
                        &ctx,
                        &credential,
                        true,
                        ConnectorStatusUpdate {
                            status: "reconnecting",
                            relay_url: Some(&selected.choice.ws_url),
                            relay_id: Some(&selected.choice.relay_id),
                            relay_region: selected.choice.region.as_deref(),
                            last_error: Some(&message),
                        },
                    );
                    if is_terminal_auth_error(&message) {
                        let _ = clear_credential();
                        let _ = ctx.db.set_connector_enabled(
                            &credential.server_url,
                            &credential.instance_id,
                            false,
                        );
                        publish_status(
                            &ctx,
                            &credential,
                            false,
                            ConnectorStatusUpdate {
                                status: "off",
                                relay_url: None,
                                relay_id: None,
                                relay_region: None,
                                last_error: Some(&message),
                            },
                        );
                        return Ok(ConnectorRunOutcome::Revoked);
                    }
                    first_connect = false;
                    sleep_or_connector_wake(wake_rx, backoff.next(&mut jitter)).await;
                    continue;
                }
            }
        };

        first_connect = false;
        match store_relay_choice(&credential, Some(choice.clone())) {
            Ok(next) => credential = next,
            Err(error) => tracing::warn!(error = %error, "storing cached relay choice failed"),
        }
        let relay_url = choice.ws_url.clone();
        let ws_url = daemon_ws_url(&relay_url)?;
        match connect_relay_socket(&ws_url, &token.token).await {
            Ok(ws) => {
                publish_status(
                    &ctx,
                    &credential,
                    true,
                    ConnectorStatusUpdate {
                        status: "connected",
                        relay_url: Some(&relay_url),
                        relay_id: Some(&choice.relay_id),
                        relay_region: choice.region.as_deref(),
                        last_error: None,
                    },
                );
                let connected_at = Instant::now();
                let refresh_after = token_refresh_delay(token.expires_at.as_deref());
                let mut socket_wake_rx = wake_rx.clone();
                let outcome = tokio::select! {
                    outcome = run_socket(
                        ctx.clone(),
                        credential.clone(),
                        relay_url.clone(),
                        ws,
                        refresh_after,
                    ) => outcome,
                    _ = socket_wake_rx.changed() => Ok(ConnectorRunOutcome::Refresh),
                };
                if connected_at.elapsed() >= STABLE_CONNECTION_RESET {
                    backoff.reset();
                }
                match outcome {
                    Ok(ConnectorRunOutcome::Revoked) => return Ok(ConnectorRunOutcome::Revoked),
                    Ok(ConnectorRunOutcome::Refresh) => {
                        publish_status(
                            &ctx,
                            &credential,
                            true,
                            ConnectorStatusUpdate {
                                status: "reconnecting",
                                relay_url: Some(&relay_url),
                                relay_id: Some(&choice.relay_id),
                                relay_region: choice.region.as_deref(),
                                last_error: Some("refreshing connector token"),
                            },
                        );
                        continue;
                    }
                    Ok(_) => {
                        publish_status(
                            &ctx,
                            &credential,
                            true,
                            ConnectorStatusUpdate {
                                status: "reconnecting",
                                relay_url: Some(&relay_url),
                                relay_id: Some(&choice.relay_id),
                                relay_region: choice.region.as_deref(),
                                last_error: Some("relay socket disconnected"),
                            },
                        );
                    }
                    Err(error) => {
                        let message = error.to_string();
                        publish_status(
                            &ctx,
                            &credential,
                            true,
                            ConnectorStatusUpdate {
                                status: "reconnecting",
                                relay_url: Some(&relay_url),
                                relay_id: Some(&choice.relay_id),
                                relay_region: choice.region.as_deref(),
                                last_error: Some(&message),
                            },
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
                    ConnectorStatusUpdate {
                        status: "reconnecting",
                        relay_url: Some(&relay_url),
                        relay_id: Some(&choice.relay_id),
                        relay_region: choice.region.as_deref(),
                        last_error: Some(&message),
                    },
                );
            }
        }
        sleep_or_connector_wake(wake_rx, backoff.next(&mut jitter)).await;
    }
}

#[derive(Debug, Clone)]
struct SelectedRelay {
    choice: RelayChoice,
    from_cache: bool,
}

trait JitterSource {
    fn duration_below(&mut self, cap: Duration) -> Duration;
}

struct SystemJitter;

impl JitterSource for SystemJitter {
    fn duration_below(&mut self, cap: Duration) -> Duration {
        random_duration_below(cap)
    }
}

async fn select_relay(
    client: &FlycockpitClient,
    credential: &StoredFlycockpitCredential,
    first_connect: bool,
    jitter: &mut impl JitterSource,
) -> Result<Option<SelectedRelay>> {
    let now_ms = chrono::Utc::now().timestamp_millis();
    if let Some(choice) = credential
        .relay_choice
        .as_ref()
        .filter(|choice| choice.is_fresh_at(now_ms))
    {
        return Ok(Some(SelectedRelay {
            choice: choice.clone(),
            from_cache: true,
        }));
    }

    let candidates = client.list_relay_candidates(credential).await?;
    select_relay_from_candidates(candidates, first_connect, jitter).await
}

async fn select_relay_from_candidates(
    candidates: Vec<RelayCandidate>,
    first_connect: bool,
    jitter: &mut impl JitterSource,
) -> Result<Option<SelectedRelay>> {
    select_relay_from_candidates_with_timeout(candidates, first_connect, jitter, PROBE_TIMEOUT)
        .await
}

async fn select_relay_from_candidates_with_timeout(
    candidates: Vec<RelayCandidate>,
    first_connect: bool,
    jitter: &mut impl JitterSource,
    probe_timeout: Duration,
) -> Result<Option<SelectedRelay>> {
    if candidates.is_empty() {
        return Ok(None);
    }
    if candidates.len() == 1 {
        return Ok(Some(SelectedRelay {
            choice: choice_from_candidate(candidates[0].clone(), None),
            from_cache: false,
        }));
    }

    if !first_connect {
        tokio::time::sleep(jitter.duration_below(COLD_PROBE_JITTER_MAX)).await;
    }

    let http = reqwest::Client::new();
    let probes = join_all(
        candidates
            .iter()
            .cloned()
            .enumerate()
            .map(|(idx, candidate)| probe_candidate(http.clone(), idx, candidate, probe_timeout)),
    )
    .await;
    let choice = select_choice_from_probe_results(&candidates, probes);
    Ok(Some(SelectedRelay {
        choice,
        from_cache: false,
    }))
}

fn select_choice_from_probe_results(
    candidates: &[RelayCandidate],
    probes: Vec<Option<ProbeResult>>,
) -> RelayChoice {
    let mut best: Option<ProbeResult> = None;
    for probe in probes.into_iter().flatten() {
        match best.as_ref() {
            None => best = Some(probe),
            Some(current) => {
                if probe.rtt + Duration::from_millis(10) < current.rtt {
                    best = Some(probe);
                }
            }
        }
    }

    if let Some(best) = best {
        choice_from_candidate(
            best.candidate,
            Some(best.rtt.as_millis().min(u128::from(u64::MAX)) as u64),
        )
    } else {
        tracing::warn!("all relay health probes failed; falling back to first listed relay");
        choice_from_candidate(candidates[0].clone(), None)
    }
}

#[derive(Debug)]
struct ProbeResult {
    candidate: RelayCandidate,
    rtt: Duration,
}

async fn probe_candidate(
    http: reqwest::Client,
    _idx: usize,
    candidate: RelayCandidate,
    probe_timeout: Duration,
) -> Option<ProbeResult> {
    let url = healthz_url(&candidate.ws_url).ok()?;
    let started = Instant::now();
    let response = tokio::time::timeout(probe_timeout, http.get(url).send())
        .await
        .ok()?
        .ok()?;
    if !response.status().is_success() {
        return None;
    }
    Some(ProbeResult {
        candidate,
        rtt: started.elapsed(),
    })
}

fn choice_from_candidate(candidate: RelayCandidate, rtt_ms: Option<u64>) -> RelayChoice {
    RelayChoice {
        relay_id: candidate.relay_id,
        region: candidate.region,
        ws_url: candidate.ws_url,
        rtt_ms,
        chosen_at: chrono::Utc::now().timestamp_millis(),
    }
}

fn healthz_url(ws_url: &str) -> Result<String> {
    let mut url = reqwest::Url::parse(ws_url).context("parsing relay candidate URL")?;
    match url.scheme() {
        "wss" => url
            .set_scheme("https")
            .map_err(|_| anyhow::anyhow!("invalid https scheme"))?,
        "ws" => url
            .set_scheme("http")
            .map_err(|_| anyhow::anyhow!("invalid http scheme"))?,
        scheme => anyhow::bail!("relay URL must use ws or wss, got {scheme}"),
    }
    url.set_path("/healthz");
    url.set_query(None);
    url.set_fragment(None);
    Ok(url.to_string())
}

fn is_not_found_error(message: &str) -> bool {
    message.contains("404") || message.to_ascii_lowercase().contains("not found")
}

fn random_duration_below(cap: Duration) -> Duration {
    let max_millis = cap.as_millis().min(u128::from(u64::MAX)) as u64;
    if max_millis == 0 {
        return Duration::ZERO;
    }
    Duration::from_millis(rand::random_range(0..=max_millis))
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
    relay_url: String,
    outbound: mpsc::Sender<OutboundFrame>,
) -> ChannelHandle {
    let (input_tx, input_rx) = mpsc::channel(CHANNEL_BUFFER);
    let task = tokio::spawn(async move {
        if let Err(error) =
            channel_task(channel_id, principal, ctx, relay_url, input_rx, outbound).await
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
        if let Some(frame) = attention_frame_from_line(&line, &ctx) {
            let _ = outbound.send(frame).await;
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
    update: ConnectorStatusUpdate<'_>,
) {
    if let Err(error) =
        ctx.db
            .update_connector_status(&credential.server_url, &credential.instance_id, update)
    {
        tracing::warn!(error = %error, "updating connector status failed");
    }
    ctx.broadcast_global(Event::ConnectorStatus {
        enabled,
        status: update.status.to_string(),
        relay_url: update.relay_url.map(str::to_string),
        relay_id: update.relay_id.map(str::to_string),
        relay_region: update.relay_region.map(str::to_string),
        last_error: update.last_error.map(str::to_string),
    });
}

pub(crate) fn attention_payload_from_line(line: &str, ctx: &DaemonContext) -> Option<Value> {
    let envelope: Envelope = serde_json::from_str(line).ok()?;
    let Body::Event { event } = envelope.body else {
        return None;
    };
    attention_payload_for_event(&event, ctx)
}

fn attention_frame_from_line(line: &str, ctx: &DaemonContext) -> Option<OutboundFrame> {
    let payload = attention_payload_from_line(line, ctx)?;
    Some(OutboundFrame::Control {
        event: attention_payload_event_name(&payload)?,
        payload,
    })
}

#[cfg(test)]
fn attention_frame_for_event_with_meta(
    event: &Event,
    ctx: &DaemonContext,
    event_id: String,
    ts: String,
) -> Option<OutboundFrame> {
    let payload = attention_payload_for_event_with_meta(event, ctx, event_id, ts)?;
    let frame_event = attention_event_type_wire_string(&payload.event_type)?;
    Some(OutboundFrame::Control {
        event: frame_event,
        payload: serde_json::to_value(payload).ok()?,
    })
}

pub(crate) fn attention_payload_for_event(event: &Event, ctx: &DaemonContext) -> Option<Value> {
    let event_id = uuid::Uuid::new_v4().to_string();
    let ts = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let payload = attention_payload_for_event_with_meta(event, ctx, event_id, ts)?;
    serde_json::to_value(payload).ok()
}

fn attention_payload_for_event_with_meta(
    event: &Event,
    ctx: &DaemonContext,
    event_id: String,
    ts: String,
) -> Option<AttentionNotificationPayload> {
    let (session_id, event_type, fixed_string_title, fixed_string_body) = match event {
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
                if approval {
                    AttentionEventType::ApprovalNeeded
                } else {
                    AttentionEventType::QuestionRaised
                },
                if approval {
                    "Approval needed"
                } else {
                    "Question waiting"
                },
                if approval {
                    "Open the session to review the request."
                } else {
                    "Open the session to respond."
                },
            )
        }
        Event::AgentIdle { session_id, .. } => (
            *session_id,
            AttentionEventType::TurnDone,
            "Agent finished",
            "Open the session to see the result.",
        ),
        Event::SessionPersistFailed { session_id, .. }
        | Event::SessionDriverFailed { session_id, .. }
        | Event::InferenceFailed { session_id, .. } => (
            *session_id,
            AttentionEventType::TurnError,
            "Agent turn failed",
            "Open the session to inspect it.",
        ),
        Event::ScheduleCompleted { session_id, .. } => (
            *session_id,
            AttentionEventType::ScheduleDone,
            "Background job finished",
            "Open the session to review it.",
        ),
        _ => return None,
    };
    let project_root = ctx
        .db
        .get_session(session_id)
        .ok()
        .flatten()
        .map(|row| row.project_root);
    Some(AttentionNotificationPayload {
        event_id,
        session_id: session_id.to_string(),
        project_root,
        event_type,
        fixed_string_title: fixed_string_title.to_string(),
        fixed_string_body: Some(fixed_string_body.to_string()),
        ts,
        target_principal: None,
    })
}

#[cfg(test)]
fn attention_event_type_wire_string(event_type: &AttentionEventType) -> Option<String> {
    serde_json::to_value(event_type)
        .ok()?
        .as_str()
        .map(str::to_string)
}

fn attention_payload_event_name(payload: &Value) -> Option<String> {
    payload
        .get("eventType")
        .and_then(Value::as_str)
        .map(str::to_string)
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

#[derive(Debug)]
struct Backoff {
    attempt: u32,
    base: Duration,
    cap: Duration,
}

impl Default for Backoff {
    fn default() -> Self {
        Self {
            attempt: 0,
            base: Duration::from_secs(1),
            cap: Duration::from_secs(60),
        }
    }
}

impl Backoff {
    fn next(&mut self, jitter: &mut impl JitterSource) -> Duration {
        let shift = self.attempt.min(20);
        let multiplier = 1_u32.checked_shl(shift).unwrap_or(u32::MAX);
        let max = self.base.saturating_mul(multiplier).min(self.cap);
        self.attempt = self.attempt.saturating_add(1);
        jitter.duration_below(max)
    }

    fn reset(&mut self) {
        self.attempt = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

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
            relay_choice: None,
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
        (
            tmp,
            Arc::new(DaemonContext::new(
                db,
                locks,
                paths,
                crate::daemon::terminal::test_host_factory(),
                crate::daemon::config_source::ConfigSource::fixed(
                    Default::default(),
                    Default::default(),
                ),
            )),
        )
    }

    fn test_session_id(ctx: &DaemonContext) -> Uuid {
        ctx.db
            .create_session("project", "/repo", "Build")
            .unwrap()
            .session_id
    }

    fn interrupt_event(session_id: Uuid, permission: bool) -> Event {
        Event::InterruptRaised {
            session_id,
            interrupt_id: Uuid::new_v4(),
            agent: "Build".to_string(),
            description: "please approve DO_NOT_FORWARD_USER_TEXT".to_string(),
            question: Some(InterruptQuestion::Single {
                prompt: "run secret command?".to_string(),
                options: vec![],
                allow_freetext: false,
                command_detail: None,
                permission,
                approval_class: None,
                sandbox_escalation: None,
            }),
            questions: None,
            pending_count: 0,
            reason: crate::daemon::proto::InterruptRaiseReason::Initial,
        }
    }

    fn attention_payload_for_test(event: &Event, ctx: &DaemonContext) -> Value {
        let payload = attention_payload_for_event_with_meta(
            event,
            ctx,
            "evt-test".to_string(),
            "2026-07-10T00:00:00.000Z".to_string(),
        )
        .unwrap();
        serde_json::to_value(payload).unwrap()
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

    #[derive(Default)]
    struct ZeroJitter;

    impl JitterSource for ZeroJitter {
        fn duration_below(&mut self, _cap: Duration) -> Duration {
            Duration::ZERO
        }
    }

    struct AlternatingJitter {
        high: bool,
    }

    impl JitterSource for AlternatingJitter {
        fn duration_below(&mut self, cap: Duration) -> Duration {
            self.high = !self.high;
            if self.high { cap } else { Duration::ZERO }
        }
    }

    struct RecordingJitter {
        calls: usize,
        value: Duration,
    }

    impl JitterSource for RecordingJitter {
        fn duration_below(&mut self, cap: Duration) -> Duration {
            self.calls += 1;
            self.value.min(cap)
        }
    }

    async fn health_server(delay: Duration, status: u16) -> (String, Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let count = Arc::new(AtomicUsize::new(0));
        let seen = count.clone();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let seen = seen.clone();
                tokio::spawn(async move {
                    seen.fetch_add(1, Ordering::SeqCst);
                    let mut buf = [0_u8; 1024];
                    let _ = stream.readable().await;
                    let _ = stream.try_read(&mut buf);
                    tokio::time::sleep(delay).await;
                    let status_text = if status == 200 { "OK" } else { "ERROR" };
                    let body = if status == 200 {
                        r#"{"ok":true}"#
                    } else {
                        r#"{"ok":false}"#
                    };
                    let raw = format!(
                        "HTTP/1.1 {status} {status_text}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = stream.writable().await;
                    let _ = stream.try_write(raw.as_bytes());
                });
            }
        });
        (format!("ws://{addr}/ws"), count)
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
                database_path: "/tmp/cockpit.db".to_string(),
                schema_version: crate::db::EXPECTED_SCHEMA_VERSION,
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
    fn backoff_uses_full_jitter_and_varies_attempts() {
        let mut backoff = Backoff::default();
        let mut jitter = AlternatingJitter { high: false };
        let mut seen = Vec::new();
        for _ in 0..100 {
            seen.push(backoff.next(&mut jitter));
        }
        assert!(seen.contains(&Duration::ZERO));
        assert!(
            seen.iter()
                .any(|duration| *duration == Duration::from_secs(60))
        );
        assert!(seen.windows(2).any(|pair| pair[0] != pair[1]));
    }

    #[tokio::test]
    async fn fresh_cached_choice_skips_listing_and_probe() {
        let mut credential = credential();
        credential.server_url = "http://localhost:9".to_string();
        credential.relay_choice = Some(RelayChoice {
            relay_id: "relay-cached".to_string(),
            region: Some("iad".to_string()),
            ws_url: "ws://cached.example.test/ws".to_string(),
            rtt_ms: Some(7),
            chosen_at: chrono::Utc::now().timestamp_millis(),
        });
        let client = FlycockpitClient::new(&credential.server_url).unwrap();
        let mut jitter = RecordingJitter {
            calls: 0,
            value: Duration::from_millis(1),
        };

        let selected = select_relay(&client, &credential, false, &mut jitter)
            .await
            .unwrap()
            .unwrap();

        assert!(selected.from_cache);
        assert_eq!(selected.choice.relay_id, "relay-cached");
        assert_eq!(jitter.calls, 0);
    }

    #[tokio::test]
    async fn single_candidate_skips_probe() {
        let (ws_url, requests) = health_server(Duration::ZERO, 200).await;
        let candidate = RelayCandidate {
            relay_id: "relay-one".to_string(),
            region: None,
            ws_url,
        };
        let mut jitter = ZeroJitter;

        let selected = select_relay_from_candidates(vec![candidate], true, &mut jitter)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(selected.choice.relay_id, "relay-one");
        assert_eq!(selected.choice.rtt_ms, None);
        assert_eq!(requests.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn probes_all_candidates_and_selects_fastest_response() {
        let (fast, fast_requests) = health_server(Duration::from_millis(5), 200).await;
        let (medium, medium_requests) = health_server(Duration::from_millis(50), 200).await;
        let (slow, slow_requests) = health_server(Duration::from_millis(200), 200).await;
        let candidates = vec![
            RelayCandidate {
                relay_id: "relay-slow".to_string(),
                region: Some("sfo".to_string()),
                ws_url: slow,
            },
            RelayCandidate {
                relay_id: "relay-fast".to_string(),
                region: Some("iad".to_string()),
                ws_url: fast,
            },
            RelayCandidate {
                relay_id: "relay-medium".to_string(),
                region: Some("fra".to_string()),
                ws_url: medium,
            },
        ];
        let mut jitter = ZeroJitter;

        let selected = select_relay_from_candidates(candidates, true, &mut jitter)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(selected.choice.relay_id, "relay-fast");
        assert_eq!(fast_requests.load(Ordering::SeqCst), 1);
        assert_eq!(medium_requests.load(Ordering::SeqCst), 1);
        assert_eq!(slow_requests.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn probe_timeouts_fall_back_to_responding_or_first_candidate() {
        let candidates = vec![
            RelayCandidate {
                relay_id: "relay-a".to_string(),
                region: None,
                ws_url: "wss://relay-a.example.test/ws".to_string(),
            },
            RelayCandidate {
                relay_id: "relay-ok".to_string(),
                region: None,
                ws_url: "wss://relay-ok.example.test/ws".to_string(),
            },
            RelayCandidate {
                relay_id: "relay-b".to_string(),
                region: None,
                ws_url: "wss://relay-b.example.test/ws".to_string(),
            },
        ];
        let selected = select_choice_from_probe_results(
            &candidates,
            vec![
                None,
                Some(ProbeResult {
                    candidate: candidates[1].clone(),
                    rtt: Duration::from_millis(7),
                }),
                None,
            ],
        );
        assert_eq!(selected.relay_id, "relay-ok");

        let selected = select_choice_from_probe_results(&candidates, vec![None, None, None]);
        assert_eq!(selected.relay_id, "relay-a");
    }

    #[tokio::test]
    async fn cold_probe_jitter_is_skipped_only_on_first_connect() {
        let (a, _) = health_server(Duration::ZERO, 200).await;
        let (b, _) = health_server(Duration::ZERO, 200).await;
        let candidates = || {
            vec![
                RelayCandidate {
                    relay_id: "relay-a".to_string(),
                    region: None,
                    ws_url: a.clone(),
                },
                RelayCandidate {
                    relay_id: "relay-b".to_string(),
                    region: None,
                    ws_url: b.clone(),
                },
            ]
        };
        let mut jitter = RecordingJitter {
            calls: 0,
            value: Duration::from_millis(1),
        };
        let _ = select_relay_from_candidates(candidates(), true, &mut jitter)
            .await
            .unwrap();
        assert_eq!(jitter.calls, 0);

        let _ = select_relay_from_candidates(candidates(), false, &mut jitter)
            .await
            .unwrap();
        assert_eq!(jitter.calls, 1);
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
    fn attention_payload_conforms_to_envelope() {
        let (_tmp, ctx) = test_context();
        let session_id = test_session_id(&ctx);
        let cases = vec![
            (
                interrupt_event(session_id, true),
                AttentionEventType::ApprovalNeeded,
                "Approval needed",
                "Open the session to review the request.",
            ),
            (
                interrupt_event(session_id, false),
                AttentionEventType::QuestionRaised,
                "Question waiting",
                "Open the session to respond.",
            ),
            (
                Event::AgentIdle {
                    session_id,
                    turn_id: Some("turn-1".to_string()),
                    reason: crate::daemon::proto::IdleReason::Completed,
                },
                AttentionEventType::TurnDone,
                "Agent finished",
                "Open the session to see the result.",
            ),
            (
                Event::SessionPersistFailed {
                    session_id,
                    error: "persist failed".to_string(),
                },
                AttentionEventType::TurnError,
                "Agent turn failed",
                "Open the session to inspect it.",
            ),
            (
                Event::ScheduleCompleted {
                    session_id,
                    job_id: "job-1".to_string(),
                    label: "Nightly".to_string(),
                    kind: "background".to_string(),
                    failed: false,
                },
                AttentionEventType::ScheduleDone,
                "Background job finished",
                "Open the session to review it.",
            ),
        ];

        for (event, event_type, title, body) in cases {
            let payload = attention_payload_for_test(&event, &ctx);
            assert!(
                payload.get("instanceId").is_none(),
                "canonical payload omits instanceId"
            );
            let parsed: AttentionNotificationPayload =
                serde_json::from_value(payload).expect("payload conforms");
            assert_eq!(parsed.event_type, event_type);
            assert_eq!(parsed.session_id, session_id.to_string());
            assert_eq!(parsed.project_root.as_deref(), Some("/repo"));
            assert_eq!(parsed.fixed_string_title, title);
            assert_eq!(parsed.fixed_string_body.as_deref(), Some(body));
            assert!(parsed.target_principal.is_none());
        }
    }

    #[test]
    fn attention_frame_event_is_event_type() {
        let (_tmp, ctx) = test_context();
        let event = interrupt_event(test_session_id(&ctx), true);
        let line = serde_json::to_string(&Envelope::event(event)).unwrap();

        let frame = attention_frame_from_line(&line, &ctx).unwrap();

        match frame {
            OutboundFrame::Control { event, payload } => {
                assert_eq!(event, "APPROVAL_NEEDED");
                assert_eq!(payload["eventType"], "APPROVAL_NEEDED");
            }
            OutboundFrame::Client { .. } => panic!("attention emits a control frame"),
        }
    }

    #[test]
    fn attention_payload_has_event_id_and_ts() {
        let (_tmp, ctx) = test_context();
        let event = interrupt_event(test_session_id(&ctx), true);

        let first = attention_payload_for_event_with_meta(
            &event,
            &ctx,
            "evt-1".to_string(),
            "2026-07-10T00:00:00.000Z".to_string(),
        )
        .unwrap();
        let second = attention_payload_for_event_with_meta(
            &event,
            &ctx,
            "evt-2".to_string(),
            "2026-07-10T00:00:01.000Z".to_string(),
        )
        .unwrap();

        assert_eq!(first.event_id, "evt-1");
        assert_eq!(first.ts, "2026-07-10T00:00:00.000Z");
        assert!(first.ts.ends_with('Z'));
        chrono::DateTime::parse_from_rfc3339(&first.ts).expect("ts is RFC3339");
        assert!(!first.event_id.is_empty());
        assert_ne!(first.event_id, second.event_id);
    }

    #[test]
    fn attention_payload_is_fixed_string_and_omits_user_text() {
        let (_tmp, ctx) = test_context();
        let event = interrupt_event(test_session_id(&ctx), true);
        let payload = attention_payload_for_test(&event, &ctx);
        assert_eq!(payload["eventType"], "APPROVAL_NEEDED");
        assert_eq!(payload["fixedStringTitle"], "Approval needed");
        assert_eq!(
            payload["fixedStringBody"],
            "Open the session to review the request."
        );
        let serialized = payload.to_string();
        assert!(!serialized.contains("DO_NOT_FORWARD_USER_TEXT"));
        assert!(!serialized.contains("run secret command"));
    }

    #[test]
    fn attention_payload_matches_control_fixture() {
        let (_tmp, ctx) = test_context();
        let event = interrupt_event(test_session_id(&ctx), true);
        let frame = attention_frame_for_event_with_meta(
            &event,
            &ctx,
            "evt-1".to_string(),
            "2026-07-10T00:00:00.000Z".to_string(),
        )
        .unwrap();
        let OutboundFrame::Control { event, payload } = frame else {
            panic!("attention emits a control frame");
        };
        let actual = serde_json::to_value(daemon_control_frame(event, payload)).unwrap();
        let fixture_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../packages/relay-protocol/fixtures/daemon-control-relay-frame.json");
        let fixture: Value =
            serde_json::from_str(&std::fs::read_to_string(fixture_path).unwrap()).unwrap();
        let actual_payload = actual["payload"].as_object().unwrap();
        let fixture_payload = fixture["payload"].as_object().unwrap();

        assert_eq!(actual["v"], fixture["v"]);
        assert_eq!(actual["to"], fixture["to"]);
        assert_eq!(actual["event"], fixture["event"]);
        assert_eq!(
            actual_payload
                .keys()
                .collect::<std::collections::BTreeSet<_>>(),
            fixture_payload
                .keys()
                .collect::<std::collections::BTreeSet<_>>()
        );
        for key in ["eventType", "fixedStringTitle", "fixedStringBody"] {
            assert_eq!(actual["payload"][key], fixture["payload"][key]);
        }
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
