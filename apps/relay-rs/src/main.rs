use std::collections::{HashMap, HashSet};
use std::env;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
#[cfg(unix)]
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow};
use axum::Json;
use axum::body::Bytes;
use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade, close_code};
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Router, serve};
use flycockpit_relay_protocol::{RelayControlMessage, RelayGrant, RelayPrincipal};
use futures::{SinkExt, StreamExt};
use jsonwebtoken::{Algorithm, DecodingKey, TokenData, Validation, decode, decode_header};
use redis::AsyncCommands;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::value::RawValue;
use tokio::net::TcpListener;
use tokio::sync::{Mutex, Notify, broadcast, mpsc};
use tokio::task::JoinHandle;
use tokio::time::{MissedTickBehavior, interval, sleep, timeout};
use uuid::Uuid;

const CLOSE_BAD_FRAME: u16 = 4400;
const CLOSE_AUTH: u16 = 4401;
const CLOSE_OFFLINE: u16 = 4404;
const CLOSE_REPLACED: u16 = 4409;
const CLOSE_FORCED: u16 = 4410;
const CLOSE_RATE_LIMITED: u16 = 4429;
const SEND_QUEUE_FRAMES: usize = 64;
const SEND_QUEUE_BYTES: usize = 16 * 1024 * 1024;
const CONTROL_CHANNEL: &str = "flycockpit:relay:control";
const PRESENCE_PREFIX: &str = "flycockpit:relay:presence:";
const JWKS_CACHE_TTL: Duration = Duration::from_secs(300);

#[tokio::main]
async fn main() -> Result<()> {
    let config = Arc::new(Config::from_env()?);
    log_info(format_args!(
        "starting relay id={} mode={:?} bind={}",
        config.relay_id, config.mode, config.listen_addr
    ));

    let presence = PresenceStore::new(config.redis_url.clone(), config.mode).await?;
    let verifier = JwtVerifier::new(
        config.jwks_url.clone(),
        config.token_issuer.clone(),
        config.relay_id.clone(),
    );
    let state = Arc::new(RelayState::new(config.clone(), presence, verifier));
    state.start_control_subscription().await?;

    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/metrics", get(metrics))
        .route("/control", post(control))
        .route("/ws/daemon", get(ws_daemon))
        .route("/ws/client", get(ws_client))
        .route("/ws/user", get(ws_user))
        .with_state(state.clone());

    let listener = TcpListener::bind(config.listen_addr)
        .await
        .with_context(|| format!("failed to bind {}", config.listen_addr))?;
    set_reset_on_close(&listener);

    let shutdown_state = state.clone();
    serve(listener, app)
        .with_graceful_shutdown(async move {
            wait_for_shutdown_signal().await;
            log_info(format_args!("shutdown requested"));
            shutdown_state.begin_shutdown().await;
        })
        .await?;

    let grace = Duration::from_millis(config.shutdown_grace_ms);
    let _ = timeout(grace, state.close()).await;
    Ok(())
}

#[cfg(unix)]
fn set_reset_on_close(listener: &TcpListener) {
    #[repr(C)]
    struct Linger {
        l_onoff: i32,
        l_linger: i32,
    }
    unsafe extern "C" {
        fn setsockopt(
            socket: i32,
            level: i32,
            option_name: i32,
            option_value: *const std::ffi::c_void,
            option_len: u32,
        ) -> i32;
    }
    #[cfg(target_os = "linux")]
    const SO_LINGER_VALUE: i32 = 13;
    #[cfg(target_os = "macos")]
    const SO_LINGER_VALUE: i32 = 0x0080;
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    const SO_LINGER_VALUE: i32 = 13;
    const SOL_SOCKET_VALUE: i32 = 1;
    let linger = Linger {
        l_onoff: 1,
        l_linger: 0,
    };
    let _ = unsafe {
        setsockopt(
            listener.as_raw_fd(),
            SOL_SOCKET_VALUE,
            SO_LINGER_VALUE,
            (&linger as *const Linger).cast(),
            std::mem::size_of::<Linger>() as u32,
        )
    };
}

#[cfg(not(unix))]
fn set_reset_on_close(_listener: &TcpListener) {}

async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("install SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RelayMode {
    Embedded,
    SharedSecret,
    Fleet,
}

#[derive(Debug)]
struct Config {
    relay_id: String,
    token_issuer: String,
    jwks_url: String,
    control_ingest_url: Option<String>,
    control_secret: Option<String>,
    redis_url: Option<String>,
    heartbeat_ms: u64,
    lease_ttl_ms: u64,
    max_frame_bytes: usize,
    max_channels_per_client: usize,
    max_connections_per_instance: usize,
    client_rate_limit_per_second: u32,
    shutdown_grace_ms: u64,
    mode: RelayMode,
    listen_addr: SocketAddr,
}

impl Config {
    fn from_env() -> Result<Self> {
        let relay_id = required_env("RELAY_ID")?;
        let token_issuer = env::var("RELAY_TOKEN_ISSUER")
            .or_else(|_| env::var("BETTER_AUTH_URL"))
            .context("RELAY_TOKEN_ISSUER or BETTER_AUTH_URL is required")?;
        let jwks_url = env::var("RELAY_JWKS_URL").unwrap_or_else(|_| {
            format!("{}/api/relay/jwks.json", token_issuer.trim_end_matches('/'))
        });
        let control_secret = env::var("RELAY_CONTROL_SECRET")
            .ok()
            .filter(|v| !v.is_empty());
        let mode = match env::var("RELAY_MODE")
            .unwrap_or_else(|_| "embedded".to_string())
            .as_str()
        {
            "embedded" => RelayMode::Embedded,
            "shared-secret" => RelayMode::SharedSecret,
            "fleet" => RelayMode::Fleet,
            other => return Err(anyhow!("unsupported RELAY_MODE {other}")),
        };
        if mode == RelayMode::SharedSecret && control_secret.is_none() {
            return Err(anyhow!(
                "RELAY_CONTROL_SECRET is required when RELAY_MODE=shared-secret"
            ));
        }
        if mode == RelayMode::Fleet {
            required_env("RELAY_CERTIFICATE_PATH")?;
            required_env("RELAY_PRIVATE_KEY_PATH")?;
            return Err(anyhow!(
                "RELAY_MODE=fleet registration is not available in this build"
            ));
        }
        let port = match parse_env("RELAY_PORT", None)? {
            Some(port) => port,
            None => parse_env("PORT", Some(3010))?.unwrap(),
        };
        let bind_addr = env::var("RELAY_BIND_ADDR").ok().filter(|v| !v.is_empty());
        let ip = match (mode, bind_addr) {
            (RelayMode::Embedded, None) => IpAddr::V4(Ipv4Addr::LOCALHOST),
            (_, Some(value)) => value
                .parse()
                .with_context(|| format!("invalid RELAY_BIND_ADDR {value}"))?,
            _ => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        };
        Ok(Self {
            relay_id,
            token_issuer,
            jwks_url,
            control_ingest_url: env::var("RELAY_CONTROL_INGEST_URL")
                .ok()
                .filter(|v| !v.is_empty()),
            control_secret,
            redis_url: env::var("REDIS_URL").ok().filter(|v| !v.is_empty()),
            heartbeat_ms: parse_env("RELAY_HEARTBEAT_MS", Some(10_000))?.unwrap(),
            lease_ttl_ms: parse_env("RELAY_LEASE_TTL_MS", Some(30_000))?.unwrap(),
            max_frame_bytes: parse_env("RELAY_MAX_FRAME_BYTES", Some(8 * 1024 * 1024))?.unwrap(),
            max_channels_per_client: parse_env("RELAY_MAX_CHANNELS_PER_CLIENT", Some(16))?.unwrap(),
            max_connections_per_instance: parse_env("RELAY_MAX_CONNECTIONS_PER_INSTANCE", Some(1))?
                .unwrap(),
            client_rate_limit_per_second: parse_env(
                "RELAY_CLIENT_RATE_LIMIT_PER_SECOND",
                Some(60),
            )?
            .unwrap(),
            shutdown_grace_ms: parse_env("RELAY_SHUTDOWN_GRACE_MS", Some(10_000))?.unwrap(),
            mode,
            listen_addr: SocketAddr::new(ip, port),
        })
    }
}

fn required_env(name: &str) -> Result<String> {
    env::var(name)
        .ok()
        .filter(|v| !v.trim().is_empty())
        .ok_or_else(|| anyhow!("{name} is required"))
}

fn parse_env<T>(name: &str, default: Option<T>) -> Result<Option<T>>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    match env::var(name) {
        Ok(value) if !value.is_empty() => value
            .parse::<T>()
            .map(Some)
            .map_err(|err| anyhow!("invalid {name}: {err}")),
        _ => Ok(default),
    }
}

#[derive(Clone)]
struct RelayState {
    config: Arc<Config>,
    presence: PresenceStore,
    verifier: JwtVerifier,
    inner: Arc<Mutex<RelayInner>>,
}

struct RelayInner {
    daemons: HashMap<String, DaemonConnection>,
    clients: HashMap<String, ClientConnection>,
    users: HashMap<String, UserConnection>,
    channel_owners: HashMap<String, String>,
    total_frames: u64,
    total_bytes: u64,
    shutting_down: bool,
    tasks: Vec<JoinHandle<()>>,
}

impl RelayState {
    fn new(config: Arc<Config>, presence: PresenceStore, verifier: JwtVerifier) -> Self {
        Self {
            config,
            presence,
            verifier,
            inner: Arc::new(Mutex::new(RelayInner {
                daemons: HashMap::new(),
                clients: HashMap::new(),
                users: HashMap::new(),
                channel_owners: HashMap::new(),
                total_frames: 0,
                total_bytes: 0,
                shutting_down: false,
                tasks: Vec::new(),
            })),
        }
    }

    async fn start_control_subscription(&self) -> Result<()> {
        let mut rx = self.presence.subscribe_control().await?;
        let state = self.clone();
        let task = tokio::spawn(async move {
            while let Some(message) = rx.recv().await {
                state.handle_control(message).await;
            }
        });
        self.inner.lock().await.tasks.push(task);
        Ok(())
    }

    async fn metrics(&self) -> MetricsBody {
        let inner = self.inner.lock().await;
        MetricsBody {
            relay_id: self.config.relay_id.clone(),
            daemons: inner.daemons.len(),
            clients: inner.clients.len(),
            users: inner.users.len(),
            frames: inner.total_frames,
            bytes: inner.total_bytes,
        }
    }

    async fn begin_shutdown(&self) {
        let (daemons, clients, users) = {
            let mut inner = self.inner.lock().await;
            inner.shutting_down = true;
            (
                inner.daemons.values().cloned().collect::<Vec<_>>(),
                inner.clients.values().cloned().collect::<Vec<_>>(),
                inner.users.values().cloned().collect::<Vec<_>>(),
            )
        };
        for daemon in daemons {
            daemon.tx.close_normal();
        }
        for client in clients {
            client.tx.close_normal();
        }
        for user in users {
            user.tx.close_normal();
        }
    }

    async fn close(&self) {
        self.begin_shutdown().await;
        let tasks = {
            let mut inner = self.inner.lock().await;
            std::mem::take(&mut inner.tasks)
        };
        for task in tasks {
            task.abort();
        }
        self.presence.close().await;
    }

    async fn register_daemon(&self, socket: WebSocket, claims: RelayTokenClaims) {
        if claims.token_type != TokenType::Connector || claims.instance_id.is_none() {
            close_socket_direct(socket, None, CLOSE_AUTH).await;
            return;
        }
        let instance_id = claims.instance_id.clone().unwrap();
        let connection = SocketConnection::new(socket);
        let daemon = DaemonConnection {
            tx: connection.tx.clone(),
            connection_id: Uuid::new_v4().to_string(),
            instance_id: instance_id.clone(),
            frame_count: 0,
            byte_count: 0,
        };
        let previous = {
            let mut inner = self.inner.lock().await;
            inner.daemons.insert(instance_id.clone(), daemon.clone())
        };
        if let Some(previous) = previous {
            previous.tx.send_system("daemon_replaced", None);
            previous.tx.close_code(CLOSE_REPLACED);
            self.unregister_daemon(&previous).await;
        }
        self.presence
            .set_daemon_lease(
                PresenceLease {
                    instance_id: instance_id.clone(),
                    relay_id: self.config.relay_id.clone(),
                    connection_id: daemon.connection_id.clone(),
                    expires_at: now_ms() + self.config.lease_ttl_ms,
                },
                self.config.lease_ttl_ms,
            )
            .await;
        log_info(format_args!(
            "daemon connected instance={} connection={}",
            daemon.instance_id, daemon.connection_id
        ));
        self.spawn_heartbeat(connection.tx.clone(), Some(daemon.clone()), None, None)
            .await;
        self.run_daemon(connection, daemon).await;
    }

    async fn register_client(&self, socket: WebSocket, claims: RelayTokenClaims) {
        if claims.token_type != TokenType::Client || claims.instance_id.is_none() {
            close_socket_direct(socket, None, CLOSE_AUTH).await;
            return;
        }
        let instance_id = claims.instance_id.clone().unwrap();
        let lease = self.presence.get_daemon_lease(&instance_id).await;
        let daemon = {
            let inner = self.inner.lock().await;
            inner.daemons.get(&instance_id).cloned()
        };
        if lease.as_ref().map(|l| l.relay_id.as_str()) != Some(self.config.relay_id.as_str())
            || daemon.is_none()
        {
            close_socket_with_system(socket, "instance_offline", CLOSE_OFFLINE).await;
            return;
        }
        let connection = SocketConnection::new(socket);
        let client = ClientConnection {
            tx: connection.tx.clone(),
            connection_id: Uuid::new_v4().to_string(),
            instance_id: instance_id.clone(),
            user_id: claims.user_id.clone(),
            grants: claims.grants.clone(),
            channels: HashSet::new(),
            rate: RateState {
                window_started: Instant::now(),
                count: 0,
            },
            frame_count: 0,
            byte_count: 0,
        };
        let replaced = {
            let mut inner = self.inner.lock().await;
            let active = inner
                .clients
                .values()
                .filter(|c| c.instance_id == instance_id)
                .cloned()
                .collect::<Vec<_>>();
            let over = active.len() >= self.config.max_connections_per_instance;
            inner
                .clients
                .insert(client.connection_id.clone(), client.clone());
            if over {
                active.into_iter().next()
            } else {
                None
            }
        };
        if let Some(old) = replaced {
            old.tx.send_system("daemon_replaced", None);
            old.tx.close_code(CLOSE_REPLACED);
            self.unregister_client(&old).await;
        }
        log_info(format_args!(
            "client connected instance={} user={} connection={}",
            client.instance_id, client.user_id, client.connection_id
        ));
        self.spawn_heartbeat(connection.tx.clone(), None, Some(client.clone()), None)
            .await;
        self.run_client(connection, client).await;
    }

    async fn register_user(&self, socket: WebSocket, claims: RelayTokenClaims) {
        if claims.token_type != TokenType::User {
            close_socket_direct(socket, None, CLOSE_AUTH).await;
            return;
        }
        let connection = SocketConnection::new(socket);
        let user = UserConnection {
            tx: connection.tx.clone(),
            connection_id: Uuid::new_v4().to_string(),
            user_id: claims.user_id.clone(),
        };
        self.inner
            .lock()
            .await
            .users
            .insert(user.connection_id.clone(), user.clone());
        log_info(format_args!(
            "user connected user={} connection={}",
            user.user_id, user.connection_id
        ));
        self.spawn_heartbeat(connection.tx.clone(), None, None, Some(user.clone()))
            .await;
        self.run_user(connection, user).await;
    }

    async fn spawn_heartbeat(
        &self,
        tx: ConnectionTx,
        daemon: Option<DaemonConnection>,
        client: Option<ClientConnection>,
        user: Option<UserConnection>,
    ) {
        let heartbeat_ms = self.config.heartbeat_ms;
        let presence = self.presence.clone();
        let lease_ttl_ms = self.config.lease_ttl_ms;
        let task = tokio::spawn(async move {
            let mut tick = interval(Duration::from_millis(heartbeat_ms));
            tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
            loop {
                tick.tick().await;
                if tx.is_closed() {
                    break;
                }
                if !tx.ping() {
                    break;
                }
                if let Some(daemon) = &daemon {
                    presence
                        .touch_daemon_lease(
                            &daemon.instance_id,
                            &daemon.connection_id,
                            now_ms() + lease_ttl_ms,
                            lease_ttl_ms,
                        )
                        .await;
                }
                let _ = (&client, &user);
            }
        });
        self.inner.lock().await.tasks.push(task);
    }

    async fn run_daemon(&self, mut connection: SocketConnection, mut daemon: DaemonConnection) {
        while let Some(result) = connection.receiver.next().await {
            let message = match result {
                Ok(message) => message,
                Err(_) => break,
            };
            let data = match message_to_bytes(message) {
                Some(data) => data,
                None => continue,
            };
            if data.len() > self.config.max_frame_bytes {
                daemon.tx.close_code(close_code::SIZE);
                break;
            }
            daemon.frame_count += 1;
            daemon.byte_count += data.len() as u64;
            self.add_totals(data.len()).await;
            if self.handle_daemon_frame(&daemon, data).await.is_err() {
                daemon.tx.close_code(CLOSE_BAD_FRAME);
                break;
            }
        }
        self.unregister_daemon(&daemon).await;
    }

    async fn handle_daemon_frame(&self, daemon: &DaemonConnection, data: Vec<u8>) -> Result<()> {
        if let Ok(frame) = serde_json::from_slice::<RawDaemonClientRelayFrame>(&data) {
            let client = {
                let inner = self.inner.lock().await;
                inner
                    .channel_owners
                    .get(&channel_key(&daemon.instance_id, &frame.channel_id))
                    .and_then(|id| inner.clients.get(id))
                    .cloned()
            };
            if let Some(client) = client {
                client.tx.send_bytes_deferred(data);
            }
            return Ok(());
        }
        let frame = serde_json::from_slice::<RawDaemonControlRelayFrame>(&data)?;
        self.ingest_daemon_control(daemon, frame.event, frame.payload)
            .await;
        Ok(())
    }

    async fn run_client(&self, mut connection: SocketConnection, mut client: ClientConnection) {
        loop {
            let result = tokio::select! {
                _ = client.tx.notify.notified() => break,
                result = connection.receiver.next() => result,
            };
            let Some(result) = result else {
                break;
            };
            let message = match result {
                Ok(message) => message,
                Err(_) => break,
            };
            let data = match message_to_bytes(message) {
                Some(data) => data,
                None => continue,
            };
            if data.len() > self.config.max_frame_bytes {
                client.tx.close_code(close_code::SIZE);
                break;
            }
            client.frame_count += 1;
            client.byte_count += data.len() as u64;
            self.add_totals(data.len()).await;
            if client.over_rate_limit(self.config.client_rate_limit_per_second) {
                client.tx.send_system("rate_limited", None);
                client.tx.close_code(CLOSE_RATE_LIMITED);
                break;
            }
            if self.handle_client_frame(&mut client, &data).await.is_err() {
                client.tx.send_system("bad_frame", None);
                client.tx.close_code(CLOSE_BAD_FRAME);
                break;
            }
        }
        let _ = timeout(Duration::from_millis(250), &mut connection.writer).await;
        connection.writer.abort();
        self.unregister_client(&client).await;
    }

    async fn handle_client_frame(&self, client: &mut ClientConnection, data: &[u8]) -> Result<()> {
        let frame = serde_json::from_slice::<RawClientRelayFrame>(data)?;
        if !client.channels.contains(&frame.channel_id) {
            if client.channels.len() >= self.config.max_channels_per_client {
                client.tx.send_system("channel_limit", None);
                return Ok(());
            }
            client.channels.insert(frame.channel_id.clone());
            self.inner.lock().await.channel_owners.insert(
                channel_key(&client.instance_id, &frame.channel_id),
                client.connection_id.clone(),
            );
        }
        let daemon = {
            let inner = self.inner.lock().await;
            inner.daemons.get(&client.instance_id).cloned()
        };
        let Some(daemon) = daemon else {
            client.tx.send_system("instance_offline", None);
            client.tx.close_code(CLOSE_OFFLINE);
            return Ok(());
        };
        let stamped = StampedRawClientRelayFrame {
            v: 1,
            channel_id: frame.channel_id,
            from: "client",
            principal: RelayPrincipal {
                user_id: client.user_id.clone(),
                grants: client.grants.clone(),
            },
            payload: frame.payload,
        };
        daemon.tx.send_bytes(serde_json::to_vec(&stamped)?);
        Ok(())
    }

    async fn run_user(&self, mut connection: SocketConnection, user: UserConnection) {
        while let Some(result) = connection.receiver.next().await {
            let message = match result {
                Ok(message) => message,
                Err(_) => break,
            };
            let data = match message_to_bytes(message) {
                Some(data) => data,
                None => continue,
            };
            if data.len() > self.config.max_frame_bytes {
                user.tx.close_code(close_code::SIZE);
                break;
            }
            self.add_totals(data.len()).await;
            match serde_json::from_slice::<UserPresenceFrame>(&data) {
                Ok(frame) => self.ingest_user_presence(&user, frame).await,
                Err(_) => {
                    user.tx.send_system("bad_frame", None);
                    user.tx.close_code(CLOSE_BAD_FRAME);
                    break;
                }
            }
        }
        self.unregister_user(&user).await;
    }

    async fn add_totals(&self, bytes: usize) {
        let mut inner = self.inner.lock().await;
        inner.total_frames += 1;
        inner.total_bytes += bytes as u64;
    }

    async fn unregister_daemon(&self, daemon: &DaemonConnection) {
        {
            let mut inner = self.inner.lock().await;
            if inner
                .daemons
                .get(&daemon.instance_id)
                .map(|d| d.connection_id.as_str())
                == Some(daemon.connection_id.as_str())
            {
                inner.daemons.remove(&daemon.instance_id);
            }
        }
        self.presence
            .delete_daemon_lease(&daemon.instance_id, &daemon.connection_id)
            .await;
        log_info(format_args!(
            "daemon disconnected instance={} connection={} frames={} bytes={}",
            daemon.instance_id, daemon.connection_id, daemon.frame_count, daemon.byte_count
        ));
    }

    async fn unregister_client(&self, client: &ClientConnection) {
        let mut inner = self.inner.lock().await;
        inner.clients.remove(&client.connection_id);
        for channel_id in &client.channels {
            let key = channel_key(&client.instance_id, channel_id);
            if inner.channel_owners.get(&key).map(String::as_str)
                == Some(client.connection_id.as_str())
            {
                inner.channel_owners.remove(&key);
            }
        }
        log_info(format_args!(
            "client disconnected instance={} user={} connection={} frames={} bytes={}",
            client.instance_id,
            client.user_id,
            client.connection_id,
            client.frame_count,
            client.byte_count
        ));
    }

    async fn unregister_user(&self, user: &UserConnection) {
        self.inner.lock().await.users.remove(&user.connection_id);
        log_info(format_args!(
            "user disconnected user={} connection={}",
            user.user_id, user.connection_id
        ));
    }

    async fn handle_control(&self, message: RelayControlMessage) {
        match message {
            RelayControlMessage::NotifyUser {
                user_id,
                notification,
            } => {
                let users = {
                    let inner = self.inner.lock().await;
                    inner
                        .users
                        .values()
                        .filter(|u| u.user_id == user_id)
                        .cloned()
                        .collect::<Vec<_>>()
                };
                for user in users {
                    user.tx.send_json(&serde_json::json!({"v":1,"type":"notification","notification": notification}));
                }
            }
            RelayControlMessage::DisconnectInstance { instance_id, .. } => {
                let (daemon, clients) = {
                    let inner = self.inner.lock().await;
                    (
                        inner.daemons.get(&instance_id).cloned(),
                        inner
                            .clients
                            .values()
                            .filter(|c| c.instance_id == instance_id)
                            .cloned()
                            .collect::<Vec<_>>(),
                    )
                };
                if let Some(daemon) = daemon {
                    daemon.tx.send_system("forced_disconnect", None);
                    daemon.tx.close_code(CLOSE_FORCED);
                }
                for client in clients {
                    client.tx.send_system("forced_disconnect", None);
                    client.tx.close_code(CLOSE_FORCED);
                }
            }
            RelayControlMessage::DisconnectUser {
                user_id,
                instance_id,
                ..
            } => {
                let (clients, users) = {
                    let inner = self.inner.lock().await;
                    (
                        inner
                            .clients
                            .values()
                            .filter(|c| {
                                c.user_id == user_id
                                    && instance_id.as_ref().is_none_or(|id| c.instance_id == *id)
                            })
                            .cloned()
                            .collect::<Vec<_>>(),
                        inner
                            .users
                            .values()
                            .filter(|u| u.user_id == user_id)
                            .cloned()
                            .collect::<Vec<_>>(),
                    )
                };
                for client in clients {
                    client.tx.send_system("forced_disconnect", None);
                    client.tx.close_code(CLOSE_FORCED);
                }
                for user in users {
                    user.tx.send_system("forced_disconnect", None);
                    user.tx.close_code(CLOSE_FORCED);
                }
            }
        }
    }

    async fn ingest_user_presence(&self, user: &UserConnection, frame: UserPresenceFrame) {
        let Some(url) = &self.config.control_ingest_url else {
            return;
        };
        let Some(secret) = &self.config.control_secret else {
            return;
        };
        let body = serde_json::json!({
            "relayId": self.config.relay_id,
            "event": "user_presence",
            "userId": user.user_id,
            "payload": { "clientId": frame.client_id, "visible": frame.visible, "ts": frame.ts },
        });
        let result = reqwest::Client::new()
            .post(url)
            .bearer_auth(secret)
            .json(&body)
            .send()
            .await;
        if let Err(err) = result {
            log_warn(format_args!(
                "user presence ingest failed user={}: {}",
                user.user_id, err
            ));
        }
    }

    async fn ingest_daemon_control(
        &self,
        daemon: &DaemonConnection,
        event: Option<String>,
        payload: Box<RawValue>,
    ) {
        let Some(url) = &self.config.control_ingest_url else {
            log_info(format_args!(
                "control frame dropped instance={} reason=ingest_unconfigured",
                daemon.instance_id
            ));
            return;
        };
        let Some(secret) = &self.config.control_secret else {
            return;
        };
        let body = serde_json::json!({
            "instanceId": daemon.instance_id,
            "relayId": self.config.relay_id,
            "event": event,
            "payload": payload,
        });
        let result = reqwest::Client::new()
            .post(url)
            .bearer_auth(secret)
            .json(&body)
            .send()
            .await;
        if let Err(err) = result {
            log_warn(format_args!(
                "control ingest failed instance={}: {}",
                daemon.instance_id, err
            ));
        }
    }
}

#[derive(Clone)]
struct DaemonConnection {
    tx: ConnectionTx,
    connection_id: String,
    instance_id: String,
    frame_count: u64,
    byte_count: u64,
}

#[derive(Clone)]
struct ClientConnection {
    tx: ConnectionTx,
    connection_id: String,
    instance_id: String,
    user_id: String,
    grants: Vec<RelayGrant>,
    channels: HashSet<String>,
    rate: RateState,
    frame_count: u64,
    byte_count: u64,
}

impl ClientConnection {
    fn over_rate_limit(&mut self, limit: u32) -> bool {
        if self.rate.window_started.elapsed() >= Duration::from_secs(1) {
            self.rate.window_started = Instant::now();
            self.rate.count = 0;
        }
        self.rate.count += 1;
        self.rate.count > limit
    }
}

#[derive(Clone)]
struct UserConnection {
    tx: ConnectionTx,
    connection_id: String,
    user_id: String,
}

#[derive(Clone)]
struct RateState {
    window_started: Instant,
    count: u32,
}

struct SocketConnection {
    tx: ConnectionTx,
    receiver: futures::stream::SplitStream<WebSocket>,
    writer: JoinHandle<()>,
}

impl SocketConnection {
    fn new(socket: WebSocket) -> Self {
        let (mut sender, receiver) = socket.split();
        let (tx, mut rx) = mpsc::channel::<Outbound>(SEND_QUEUE_FRAMES);
        let connection_tx = ConnectionTx {
            tx,
            queued_bytes: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            closed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            notify: Arc::new(Notify::new()),
            burst: Arc::new(std::sync::Mutex::new(OutboundBurst {
                window_started: Instant::now(),
                count: 0,
            })),
        };
        let queued = connection_tx.queued_bytes.clone();
        let closed = connection_tx.closed.clone();
        let writer = tokio::spawn(async move {
            while let Some(outbound) = rx.recv().await {
                let bytes = outbound.bytes_len();
                queued.fetch_sub(bytes, std::sync::atomic::Ordering::Relaxed);
                let result = match outbound {
                    Outbound::Text(value) => sender.send(Message::Text(value.into())).await,
                    Outbound::Binary(value) => sender.send(Message::Binary(value.into())).await,
                    Outbound::Ping => sender.send(Message::Ping(Bytes::new())).await,
                    Outbound::Close(code) => {
                        let frame = CloseFrame {
                            code,
                            reason: "".into(),
                        };
                        let result = timeout(
                            Duration::from_millis(50),
                            sender.send(Message::Close(Some(frame))),
                        )
                        .await
                        .unwrap_or_else(|_| Ok(()));
                        closed.store(true, std::sync::atomic::Ordering::Relaxed);
                        result
                    }
                };
                if result.is_err() {
                    break;
                }
            }
            closed.store(true, std::sync::atomic::Ordering::Relaxed);
        });
        Self {
            tx: connection_tx,
            receiver,
            writer,
        }
    }
}

#[derive(Clone)]
struct ConnectionTx {
    tx: mpsc::Sender<Outbound>,
    queued_bytes: Arc<std::sync::atomic::AtomicUsize>,
    closed: Arc<std::sync::atomic::AtomicBool>,
    notify: Arc<Notify>,
    burst: Arc<std::sync::Mutex<OutboundBurst>>,
}

struct OutboundBurst {
    window_started: Instant,
    count: usize,
}

impl ConnectionTx {
    fn send_bytes(&self, bytes: Vec<u8>) -> bool {
        self.enqueue(Outbound::Binary(bytes))
    }

    fn send_bytes_deferred(&self, bytes: Vec<u8>) -> bool {
        if self.is_closed() {
            return false;
        }
        if self.over_burst_limit() {
            let _ = self.tx.try_send(Outbound::Close(CLOSE_RATE_LIMITED));
            self.terminate();
            return false;
        }
        let tx = self.clone();
        tokio::spawn(async move {
            sleep(Duration::from_millis(1)).await;
            if !tx.is_closed() {
                tx.send_bytes(bytes);
            }
        });
        true
    }

    fn send_json(&self, value: &serde_json::Value) -> bool {
        self.enqueue(Outbound::Text(value.to_string()))
    }

    fn send_system(&self, code: &str, channel_id: Option<&str>) -> bool {
        let value = match channel_id {
            Some(channel_id) => {
                serde_json::json!({ "v": 1, "type": "system", "code": code, "channelId": channel_id })
            }
            None => serde_json::json!({ "v": 1, "type": "system", "code": code }),
        };
        self.send_json(&value)
    }

    fn ping(&self) -> bool {
        self.enqueue(Outbound::Ping)
    }

    fn close_code(&self, code: u16) -> bool {
        self.enqueue(Outbound::Close(code))
    }

    fn close_normal(&self) -> bool {
        self.close_code(close_code::NORMAL)
    }

    fn is_closed(&self) -> bool {
        self.closed.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn enqueue(&self, outbound: Outbound) -> bool {
        if self.is_closed() {
            return false;
        }
        if outbound.counts_for_backpressure() && self.over_burst_limit() {
            let _ = self.tx.try_send(Outbound::Close(CLOSE_RATE_LIMITED));
            self.terminate();
            return false;
        }
        let bytes = outbound.bytes_len();
        let queued = self
            .queued_bytes
            .fetch_add(bytes, std::sync::atomic::Ordering::Relaxed)
            + bytes;
        if queued > SEND_QUEUE_BYTES {
            self.queued_bytes
                .fetch_sub(bytes, std::sync::atomic::Ordering::Relaxed);
            let _ = self.tx.try_send(Outbound::Close(CLOSE_RATE_LIMITED));
            self.terminate();
            return false;
        }
        match self.tx.try_send(outbound) {
            Ok(()) => true,
            Err(err) => {
                self.queued_bytes
                    .fetch_sub(bytes, std::sync::atomic::Ordering::Relaxed);
                if matches!(err, mpsc::error::TrySendError::Full(_)) {
                    let _ = self.tx.try_send(Outbound::Close(CLOSE_RATE_LIMITED));
                    self.terminate();
                }
                false
            }
        }
    }

    fn over_burst_limit(&self) -> bool {
        let mut burst = self.burst.lock().expect("outbound burst mutex poisoned");
        if burst.window_started.elapsed() >= Duration::from_secs(1) {
            burst.window_started = Instant::now();
            burst.count = 0;
        }
        burst.count += 1;
        burst.count > 2
    }

    fn terminate(&self) {
        self.closed
            .store(true, std::sync::atomic::Ordering::Relaxed);
        self.notify.notify_waiters();
    }
}

enum Outbound {
    Text(String),
    Binary(Vec<u8>),
    Ping,
    Close(u16),
}

impl Outbound {
    fn bytes_len(&self) -> usize {
        match self {
            Self::Text(value) => value.len(),
            Self::Binary(value) => value.len(),
            Self::Ping | Self::Close(_) => 0,
        }
    }

    fn counts_for_backpressure(&self) -> bool {
        matches!(self, Self::Text(_) | Self::Binary(_))
    }
}

async fn close_socket_with_system(socket: WebSocket, system_code: &str, close_code_value: u16) {
    let mut connection = SocketConnection::new(socket);
    connection.tx.send_system(system_code, None);
    connection.tx.close_code(close_code_value);
    let _ = timeout(Duration::from_millis(500), async {
        while connection.receiver.next().await.is_some() {}
    })
    .await;
    let _ = timeout(Duration::from_millis(500), connection.writer).await;
}

async fn close_socket_direct(socket: WebSocket, system_code: Option<&str>, close_code_value: u16) {
    let (mut sender, mut receiver) = socket.split();
    let reader = tokio::spawn(async move { while receiver.next().await.is_some() {} });
    if let Some(system_code) = system_code {
        let value = serde_json::json!({ "v": 1, "type": "system", "code": system_code });
        let _ = sender.send(Message::Text(value.to_string().into())).await;
    }
    let frame = CloseFrame {
        code: close_code_value,
        reason: "".into(),
    };
    let _ = timeout(
        Duration::from_millis(250),
        sender.send(Message::Close(Some(frame))),
    )
    .await;
    let _ = timeout(Duration::from_millis(250), sender.close()).await;
    let _ = timeout(Duration::from_millis(250), reader).await;
}

fn message_to_bytes(message: Message) -> Option<Vec<u8>> {
    match message {
        Message::Text(text) => Some(text.as_bytes().to_vec()),
        Message::Binary(bytes) => Some(bytes.to_vec()),
        Message::Close(_) => None,
        Message::Ping(_) | Message::Pong(_) => None,
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HealthBody {
    ok: bool,
    relay_id: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MetricsBody {
    relay_id: String,
    daemons: usize,
    clients: usize,
    users: usize,
    frames: u64,
    bytes: u64,
}

async fn healthz(State(state): State<Arc<RelayState>>) -> Json<HealthBody> {
    Json(HealthBody {
        ok: true,
        relay_id: state.config.relay_id.clone(),
    })
}

async fn metrics(State(state): State<Arc<RelayState>>) -> Json<MetricsBody> {
    Json(state.metrics().await)
}

async fn control(
    State(state): State<Arc<RelayState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(secret) = &state.config.control_secret else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error":"not_found"})),
        )
            .into_response();
    };
    if headers.get("authorization").and_then(|v| v.to_str().ok())
        != Some(&format!("Bearer {secret}"))
    {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error":"unauthorized"})),
        )
            .into_response();
    }
    if body.len() > state.config.max_frame_bytes {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error":"bad_request"})),
        )
            .into_response();
    }
    match serde_json::from_slice::<RelayControlMessage>(&body) {
        Ok(message) => {
            state.handle_control(message.clone()).await;
            state.presence.publish_control(message).await;
            (StatusCode::OK, Json(serde_json::json!({"ok":true}))).into_response()
        }
        Err(_) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error":"bad_request"})),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
struct TokenQuery {
    token: Option<String>,
}

async fn ws_daemon(
    State(state): State<Arc<RelayState>>,
    ws: WebSocketUpgrade,
    headers: HeaderMap,
    Query(query): Query<TokenQuery>,
) -> Response {
    websocket_response(state, ws, headers, query.token, ConnectionKind::Daemon).await
}

async fn ws_client(
    State(state): State<Arc<RelayState>>,
    ws: WebSocketUpgrade,
    headers: HeaderMap,
    Query(query): Query<TokenQuery>,
) -> Response {
    websocket_response(state, ws, headers, query.token, ConnectionKind::Client).await
}

async fn ws_user(
    State(state): State<Arc<RelayState>>,
    ws: WebSocketUpgrade,
    headers: HeaderMap,
    Query(query): Query<TokenQuery>,
) -> Response {
    websocket_response(state, ws, headers, query.token, ConnectionKind::User).await
}

#[derive(Clone, Copy)]
enum ConnectionKind {
    Daemon,
    Client,
    User,
}

async fn websocket_response(
    state: Arc<RelayState>,
    ws: WebSocketUpgrade,
    headers: HeaderMap,
    query_token: Option<String>,
    kind: ConnectionKind,
) -> Response {
    let token = bearer_token(&headers).or(query_token).unwrap_or_default();
    let claims = match state.verifier.verify(&token).await {
        Ok(claims) => claims,
        Err(err) => {
            log_warn(format_args!("token verification failed: {}", err));
            return StatusCode::UNAUTHORIZED.into_response();
        }
    };
    ws.on_upgrade(move |socket| async move {
        match kind {
            ConnectionKind::Daemon => state.register_daemon(socket, claims).await,
            ConnectionKind::Client => state.register_client(socket, claims).await,
            ConnectionKind::User => state.register_user(socket, claims).await,
        }
    })
}

fn bearer_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

#[derive(Clone)]
struct JwtVerifier {
    jwks_url: String,
    issuer: String,
    audience: String,
    client: reqwest::Client,
    cache: Arc<Mutex<JwksCache>>,
}

struct JwksCache {
    keys: HashMap<String, JwkKey>,
    fetched_at: Option<Instant>,
}

impl JwtVerifier {
    fn new(jwks_url: String, issuer: String, audience: String) -> Self {
        Self {
            jwks_url,
            issuer,
            audience,
            client: reqwest::Client::new(),
            cache: Arc::new(Mutex::new(JwksCache {
                keys: HashMap::new(),
                fetched_at: None,
            })),
        }
    }

    async fn verify(&self, token: &str) -> Result<RelayTokenClaims> {
        let header = decode_header(token).context("invalid token header")?;
        let kid = header.kid.ok_or_else(|| anyhow!("missing token kid"))?;
        let mut key = self.key_for(&kid, false).await?;
        match self.decode_with_key(token, &key) {
            Ok(data) => Ok(data.claims),
            Err(first_err) => {
                key = self.key_for(&kid, true).await?;
                self.decode_with_key(token, &key)
                    .map(|data| data.claims)
                    .with_context(|| format!("jwt rejected: {first_err}"))
            }
        }
    }

    async fn key_for(&self, kid: &str, force_refresh: bool) -> Result<JwkKey> {
        {
            let cache = self.cache.lock().await;
            let fresh = cache
                .fetched_at
                .is_some_and(|at| at.elapsed() < JWKS_CACHE_TTL);
            if !force_refresh
                && fresh
                && let Some(key) = cache.keys.get(kid)
            {
                return Ok(key.clone());
            }
        }
        self.refresh_keys().await?;
        let cache = self.cache.lock().await;
        cache
            .keys
            .get(kid)
            .cloned()
            .ok_or_else(|| anyhow!("unknown token kid"))
    }

    async fn refresh_keys(&self) -> Result<()> {
        let jwks = self
            .client
            .get(&self.jwks_url)
            .send()
            .await?
            .error_for_status()?
            .json::<Jwks>()
            .await?;
        let keys = jwks
            .keys
            .into_iter()
            .filter_map(|key| key.kid.clone().map(|kid| (kid, key)))
            .collect();
        let mut cache = self.cache.lock().await;
        cache.keys = keys;
        cache.fetched_at = Some(Instant::now());
        Ok(())
    }

    fn decode_with_key(
        &self,
        token: &str,
        key: &JwkKey,
    ) -> jsonwebtoken::errors::Result<TokenData<RelayTokenClaims>> {
        let decoding_key = DecodingKey::from_ec_components(&key.x, &key.y)?;
        let mut validation = Validation::new(Algorithm::ES256);
        validation.set_issuer(&[self.issuer.as_str()]);
        validation.set_audience(&[self.audience.as_str()]);
        decode::<RelayTokenClaims>(token, &decoding_key, &validation)
    }
}

#[derive(Debug, Deserialize)]
struct Jwks {
    keys: Vec<JwkKey>,
}

#[derive(Debug, Clone, Deserialize)]
struct JwkKey {
    kid: Option<String>,
    x: String,
    y: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum TokenType {
    Connector,
    Client,
    User,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RelayTokenClaims {
    #[serde(rename = "tokenType")]
    token_type: TokenType,
    instance_id: Option<String>,
    user_id: String,
    #[serde(default)]
    grants: Vec<RelayGrant>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawClientRelayFrame {
    #[serde(deserialize_with = "version_one")]
    #[serde(rename = "v")]
    _v: u32,
    #[serde(deserialize_with = "channel_id")]
    channel_id: String,
    payload: Box<RawValue>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StampedRawClientRelayFrame<'a> {
    v: u32,
    channel_id: String,
    from: &'a str,
    principal: RelayPrincipal,
    payload: Box<RawValue>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawDaemonClientRelayFrame {
    #[serde(deserialize_with = "version_one")]
    #[serde(rename = "v")]
    _v: u32,
    #[serde(deserialize_with = "channel_id")]
    channel_id: String,
    #[serde(rename = "payload")]
    _payload: Box<RawValue>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawDaemonControlRelayFrame {
    #[serde(deserialize_with = "version_one")]
    #[serde(rename = "v")]
    _v: u32,
    #[serde(rename = "to")]
    _to: ControlTarget,
    #[serde(default)]
    event: Option<String>,
    payload: Box<RawValue>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
enum ControlTarget {
    Control,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct UserPresenceFrame {
    #[serde(deserialize_with = "version_one")]
    #[serde(rename = "v")]
    _v: u32,
    #[serde(rename = "type")]
    _frame_type: PresenceType,
    #[serde(deserialize_with = "channel_id")]
    client_id: String,
    visible: bool,
    ts: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
enum PresenceType {
    Presence,
}

fn version_one<'de, D>(deserializer: D) -> std::result::Result<u32, D::Error>
where
    D: Deserializer<'de>,
{
    let value = u32::deserialize(deserializer)?;
    if value == 1 {
        Ok(value)
    } else {
        Err(serde::de::Error::custom(
            "unsupported relay envelope version",
        ))
    }
}

fn channel_id<'de, D>(deserializer: D) -> std::result::Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.len() > 128 {
        Err(serde::de::Error::custom("invalid channel id"))
    } else {
        Ok(value)
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PresenceLease {
    instance_id: String,
    relay_id: String,
    connection_id: String,
    expires_at: u64,
}

#[derive(Clone)]
enum PresenceStore {
    Memory(MemoryPresenceStore),
    Redis(RedisPresenceStore),
}

impl PresenceStore {
    async fn new(redis_url: Option<String>, mode: RelayMode) -> Result<Self> {
        let Some(redis_url) = redis_url else {
            return Ok(Self::Memory(MemoryPresenceStore::default()));
        };
        match RedisPresenceStore::new(redis_url).await {
            Ok(store) => Ok(Self::Redis(store)),
            Err(err) if mode == RelayMode::Embedded => {
                log_warn(format_args!(
                    "redis unavailable; falling back to memory presence: {err}"
                ));
                Ok(Self::Memory(MemoryPresenceStore::default()))
            }
            Err(err) => Err(err),
        }
    }

    async fn set_daemon_lease(&self, lease: PresenceLease, ttl_ms: u64) {
        match self {
            Self::Memory(store) => store.set_daemon_lease(lease).await,
            Self::Redis(store) => store.set_daemon_lease(lease, ttl_ms).await,
        }
    }

    async fn touch_daemon_lease(
        &self,
        instance_id: &str,
        connection_id: &str,
        expires_at: u64,
        ttl_ms: u64,
    ) {
        match self {
            Self::Memory(store) => {
                store
                    .touch_daemon_lease(instance_id, connection_id, expires_at)
                    .await
            }
            Self::Redis(store) => {
                store
                    .touch_daemon_lease(instance_id, connection_id, expires_at, ttl_ms)
                    .await
            }
        }
    }

    async fn get_daemon_lease(&self, instance_id: &str) -> Option<PresenceLease> {
        match self {
            Self::Memory(store) => store.get_daemon_lease(instance_id).await,
            Self::Redis(store) => store.get_daemon_lease(instance_id).await,
        }
    }

    async fn delete_daemon_lease(&self, instance_id: &str, connection_id: &str) {
        match self {
            Self::Memory(store) => store.delete_daemon_lease(instance_id, connection_id).await,
            Self::Redis(store) => store.delete_daemon_lease(instance_id, connection_id).await,
        }
    }

    async fn publish_control(&self, message: RelayControlMessage) {
        match self {
            Self::Memory(store) => store.publish_control(message).await,
            Self::Redis(store) => store.publish_control(message).await,
        }
    }

    async fn subscribe_control(&self) -> Result<mpsc::UnboundedReceiver<RelayControlMessage>> {
        match self {
            Self::Memory(store) => Ok(store.subscribe_control()),
            Self::Redis(store) => store.subscribe_control().await,
        }
    }

    async fn close(&self) {
        if let Self::Redis(store) = self {
            store.close().await;
        }
    }
}

#[derive(Clone)]
struct MemoryPresenceStore {
    leases: Arc<Mutex<HashMap<String, PresenceLease>>>,
    control_tx: broadcast::Sender<RelayControlMessage>,
}

impl Default for MemoryPresenceStore {
    fn default() -> Self {
        let (control_tx, _) = broadcast::channel(256);
        Self {
            leases: Arc::new(Mutex::new(HashMap::new())),
            control_tx,
        }
    }
}

impl MemoryPresenceStore {
    async fn set_daemon_lease(&self, lease: PresenceLease) {
        self.leases
            .lock()
            .await
            .insert(lease.instance_id.clone(), lease);
    }

    async fn touch_daemon_lease(&self, instance_id: &str, connection_id: &str, expires_at: u64) {
        let mut leases = self.leases.lock().await;
        if let Some(current) = leases.get_mut(instance_id)
            && current.connection_id == connection_id
        {
            current.expires_at = expires_at;
        }
    }

    async fn get_daemon_lease(&self, instance_id: &str) -> Option<PresenceLease> {
        let mut leases = self.leases.lock().await;
        let lease = leases.get(instance_id).cloned()?;
        if lease.expires_at <= now_ms() {
            leases.remove(instance_id);
            None
        } else {
            Some(lease)
        }
    }

    async fn delete_daemon_lease(&self, instance_id: &str, connection_id: &str) {
        let mut leases = self.leases.lock().await;
        if leases
            .get(instance_id)
            .map(|lease| lease.connection_id.as_str())
            == Some(connection_id)
        {
            leases.remove(instance_id);
        }
    }

    async fn publish_control(&self, message: RelayControlMessage) {
        let _ = self.control_tx.send(message);
    }

    fn subscribe_control(&self) -> mpsc::UnboundedReceiver<RelayControlMessage> {
        let mut broadcast_rx = self.control_tx.subscribe();
        let (tx, rx) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Ok(message) = broadcast_rx.recv().await {
                if tx.send(message).is_err() {
                    break;
                }
            }
        });
        rx
    }
}

#[derive(Clone)]
struct RedisPresenceStore {
    client: redis::Client,
}

impl RedisPresenceStore {
    async fn new(redis_url: String) -> Result<Self> {
        let client = redis::Client::open(redis_url)?;
        let mut connection = client.get_multiplexed_tokio_connection().await?;
        redis::cmd("PING")
            .query_async::<()>(&mut connection)
            .await?;
        Ok(Self { client })
    }

    async fn connection(&self) -> Result<redis::aio::MultiplexedConnection> {
        Ok(self.client.get_multiplexed_tokio_connection().await?)
    }

    async fn set_daemon_lease(&self, lease: PresenceLease, ttl_ms: u64) {
        if let Ok(mut connection) = self.connection().await {
            let key = format!("{PRESENCE_PREFIX}{}", lease.instance_id);
            let _: redis::RedisResult<()> = connection
                .set_options(
                    key,
                    serde_json::to_string(&lease).unwrap_or_default(),
                    redis::SetOptions::default().with_expiration(redis::SetExpiry::PX(ttl_ms)),
                )
                .await;
        }
    }

    async fn touch_daemon_lease(
        &self,
        instance_id: &str,
        connection_id: &str,
        expires_at: u64,
        ttl_ms: u64,
    ) {
        if let Some(mut lease) = self.get_daemon_lease(instance_id).await
            && lease.connection_id == connection_id
        {
            lease.expires_at = expires_at;
            self.set_daemon_lease(lease, ttl_ms).await;
        }
    }

    async fn get_daemon_lease(&self, instance_id: &str) -> Option<PresenceLease> {
        let mut connection = self.connection().await.ok()?;
        let key = format!("{PRESENCE_PREFIX}{instance_id}");
        let raw: Option<String> = connection.get(&key).await.ok()?;
        let raw = raw?;
        let lease = serde_json::from_str::<PresenceLease>(&raw).ok()?;
        if lease.expires_at <= now_ms() {
            let _: redis::RedisResult<()> = connection.del(key).await;
            None
        } else {
            Some(lease)
        }
    }

    async fn delete_daemon_lease(&self, instance_id: &str, connection_id: &str) {
        if let Some(lease) = self.get_daemon_lease(instance_id).await
            && lease.connection_id == connection_id
            && let Ok(mut connection) = self.connection().await
        {
            let _: redis::RedisResult<()> = connection
                .del(format!("{PRESENCE_PREFIX}{instance_id}"))
                .await;
        }
    }

    async fn publish_control(&self, message: RelayControlMessage) {
        if let Ok(mut connection) = self.connection().await {
            let raw = serde_json::to_string(&message).unwrap_or_default();
            let _: redis::RedisResult<()> = connection.publish(CONTROL_CHANNEL, raw).await;
        }
    }

    async fn subscribe_control(&self) -> Result<mpsc::UnboundedReceiver<RelayControlMessage>> {
        let mut pubsub = self.client.get_async_pubsub().await?;
        pubsub.subscribe(CONTROL_CHANNEL).await?;
        let (tx, rx) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            let mut stream = pubsub.on_message();
            while let Some(message) = stream.next().await {
                let raw: redis::RedisResult<String> = message.get_payload();
                if let Ok(raw) = raw
                    && let Ok(message) = serde_json::from_str::<RelayControlMessage>(&raw)
                {
                    let _ = tx.send(message);
                }
            }
        });
        Ok(rx)
    }

    async fn close(&self) {}
}

fn channel_key(instance_id: &str, channel_id: &str) -> String {
    format!("{instance_id}:{channel_id}")
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn log_info(args: std::fmt::Arguments<'_>) {
    println!("[relay] {args}");
}

fn log_warn(args: std::fmt::Arguments<'_>) {
    eprintln!("[relay] {args}");
}
