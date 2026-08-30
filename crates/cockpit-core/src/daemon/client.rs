//! Daemon discovery and lifecycle composition.
//!
//! Local wire framing and typed request/event transport live in
//! `cockpit-client`; this module owns only process and daemon lifecycle.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use cockpit_client::{DaemonClient, is_protocol_version_mismatch};

use crate::daemon::proto::{self, Request};

const SPAWN_DAEMON_TIMEOUT: Duration = Duration::from_secs(30);

fn mode_for_intent(intent: cockpit_client::LifecycleIntent) -> LifecycleMode {
    match intent {
        cockpit_client::LifecycleIntent::AttachOrPersistent
        | cockpit_client::LifecycleIntent::EnsurePersistent => LifecycleMode::AttachOrPersistent,
        cockpit_client::LifecycleIntent::AttachOrEphemeral => LifecycleMode::AttachOrEphemeral,
    }
}

// ---- lifecycle helpers ----------------------------------------------------

/// Strategy for getting a daemon to talk to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleMode {
    /// Attach to any current owner, otherwise start a persistent owner.
    AttachOrPersistent,
    /// Attach to any current owner, otherwise start an ephemeral owner.
    AttachOrEphemeral,
}

/// Connect-or-spawn result: a ready-to-use client and the lifetime selected
/// for a newly spawned owner. Socket-owner shutdown is governed exclusively
/// by the daemon's client reference count, never by this client process.
pub(crate) struct ConnectedDaemon {
    client: DaemonClient,
    endpoint: cockpit_client::ClientEndpoint,
    owns_daemon: bool,
    socket: PathBuf,
    startup_notice: Option<String>,
}

/// Foreground CLI connection scoped to one operation.
struct OwnedDaemonSession {
    client: DaemonClient,
    in_process_owner: Option<crate::daemon::InProcessDaemonGuard>,
}

/// Foreground command lifecycle preferences.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnedSessionMode {
    AttachOrPersistent,
    AttachOrEphemeral,
}

impl OwnedSessionMode {
    fn lifecycle(self) -> LifecycleMode {
        match self {
            Self::AttachOrPersistent => LifecycleMode::AttachOrPersistent,
            Self::AttachOrEphemeral => LifecycleMode::AttachOrEphemeral,
        }
    }
}

impl OwnedDaemonSession {
    async fn connect(mode: OwnedSessionMode) -> Result<Self> {
        let mut connected = probe_or_spawn(mode.lifecycle()).await?;
        if let Some(notice) = connected.startup_notice.take() {
            eprintln!("{notice}");
        }
        Ok(Self {
            client: connected.client,
            in_process_owner: None,
        })
    }

    /// Attach to a shareable owner when one exists; otherwise boot a private
    /// in-process ephemeral owner for this one foreground operation.
    async fn connect_one_shot() -> Result<Self> {
        use crate::daemon::{DaemonPaths, discover};

        let discovered = discover().await;
        match discover_attach_plan(discovered.status, discovered.hello.is_some()) {
            DiscoverAttachPlan::AttachRunning => {
                let connected = attach_running_with_skew_check(discovered.paths, None).await?;
                return Ok(Self {
                    client: connected.client,
                    in_process_owner: None,
                });
            }
            DiscoverAttachPlan::WaitForRestart => {
                let observed_pid =
                    cockpit_host::daemon_lifecycle::read_pid_file(&discovered.paths.pid_file);
                match wait_for_shared_daemon(&discovered.paths.socket, observed_pid).await {
                    Ok(client) => {
                        return Ok(Self {
                            client,
                            in_process_owner: None,
                        });
                    }
                    Err(SharedWaitError::Released) => {}
                    Err(SharedWaitError::Wedged) => {
                        anyhow::bail!(
                            "shared daemon pid is live but socket never became ready: {}",
                            discovered.paths.socket.display()
                        );
                    }
                }
            }
            DiscoverAttachPlan::Spawn => {}
            DiscoverAttachPlan::FailIncompatible | DiscoverAttachPlan::FailUnreachable => {
                if let Some(hello) = discovered.hello.as_ref() {
                    anyhow::bail!(
                        "{}",
                        proto::incompatible_daemon_protocol_message(hello.protocol_version)
                    );
                }
                anyhow::bail!(
                    "shared daemon pid is live but socket is unreachable: {}",
                    discovered.paths.socket.display()
                );
            }
        }

        let paths = DaemonPaths::resolve_canonical()?.with_ephemeral_lifetime();
        let (endpoint, in_process_owner) =
            crate::daemon::boot_in_process(paths, crate::daemon::terminal::default_host_factory())
                .await?;
        let client =
            DaemonClient::connect_endpoint(&cockpit_client::ClientEndpoint::InProcess(endpoint))
                .await?;
        Ok(Self {
            client,
            in_process_owner,
        })
    }

    fn client(&self) -> &DaemonClient {
        &self.client
    }

    async fn finish<T>(self, result: Result<T>) -> Result<T> {
        let Self {
            client,
            in_process_owner,
        } = self;
        // Retire the operation's transport reference before asking an
        // in-process owner to drain. This mirrors socket last-client teardown
        // and prevents a live client task from retaining the owner context.
        drop(client);
        let shutdown = match in_process_owner {
            Some(owner) => owner.shutdown().await,
            None => Ok(()),
        };
        match (result, shutdown) {
            (Ok(value), Ok(())) => Ok(value),
            (Ok(_), Err(error)) => Err(error).context("shutting down one-shot in-process daemon"),
            (Err(error), Ok(())) => Err(error),
            (Err(error), Err(shutdown_error)) => Err(error).context(format!(
                "one-shot operation failed and in-process daemon shutdown also failed: {shutdown_error:#}"
            )),
        }
    }
}

/// Run one foreground operation with a client that cannot escape its callback.
#[derive(Debug, thiserror::Error)]
pub enum OwnedDaemonRunError {
    #[error("connecting to owned daemon: {0:#}")]
    Connect(#[source] anyhow::Error),
    #[error(transparent)]
    OperationOrCleanup(#[from] anyhow::Error),
}

/// A lifetime-bound view of a daemon client for one owned foreground run.
///
/// This capability deliberately cannot be cloned or converted back into a
/// [`DaemonClient`]. Its lifetime is tied to the runner callback, so neither
/// it nor a borrow derived from it can escape the operation.
pub struct ScopedDaemonClient<'session> {
    client: &'session DaemonClient,
}

impl ScopedDaemonClient<'_> {
    pub async fn request(
        &self,
        request: proto::Request,
    ) -> anyhow::Result<std::result::Result<proto::Response, proto::ErrorPayload>> {
        self.client.request(request).await
    }

    pub async fn request_ok(&self, request: proto::Request) -> anyhow::Result<proto::Response> {
        self.client.request_ok(request).await
    }

    pub async fn next_event(&self) -> Option<proto::Event> {
        self.client.next_event().await
    }

    pub fn negotiated(&self) -> &proto::NegotiatedProtocol {
        self.client.negotiated()
    }
}

impl cockpit_client::DaemonRequestClient for ScopedDaemonClient<'_> {
    async fn request(
        &self,
        request: proto::Request,
    ) -> anyhow::Result<std::result::Result<proto::Response, proto::ErrorPayload>> {
        self.client.request(request).await
    }
}

impl OwnedDaemonRunError {
    pub fn into_inner(self) -> anyhow::Error {
        match self {
            Self::Connect(error) | Self::OperationOrCleanup(error) => error,
        }
    }
}

pub async fn run_owned_daemon<T, F>(
    mode: OwnedSessionMode,
    operation: F,
) -> std::result::Result<T, OwnedDaemonRunError>
where
    F: for<'client> std::ops::FnOnce(
            ScopedDaemonClient<'client>,
        ) -> std::pin::Pin<
            std::boxed::Box<dyn std::future::Future<Output = anyhow::Result<T>> + 'client>,
        >,
{
    let session = OwnedDaemonSession::connect(mode)
        .await
        .map_err(OwnedDaemonRunError::Connect)?;
    let result = operation(ScopedDaemonClient {
        client: session.client(),
    })
    .await;
    session
        .finish(result)
        .await
        .map_err(OwnedDaemonRunError::OperationOrCleanup)
}

/// Run a one-shot foreground operation. It attaches to an existing shareable
/// owner, or otherwise owns a private in-process daemon for the operation.
/// This is reserved for callers that are their owner's only client.
pub async fn run_one_shot_daemon<T, F>(operation: F) -> std::result::Result<T, OwnedDaemonRunError>
where
    F: for<'client> std::ops::FnOnce(
            ScopedDaemonClient<'client>,
        ) -> std::pin::Pin<
            std::boxed::Box<dyn std::future::Future<Output = anyhow::Result<T>> + 'client>,
        >,
{
    let session = OwnedDaemonSession::connect_one_shot()
        .await
        .map_err(OwnedDaemonRunError::Connect)?;
    let result = operation(ScopedDaemonClient {
        client: session.client(),
    })
    .await;
    session
        .finish(result)
        .await
        .map_err(OwnedDaemonRunError::OperationOrCleanup)
}

/// Persistent-only daemon connection. It contains no process-ownership guard,
/// so exposing the client cannot detach an ephemeral child.
pub struct PersistentDaemonSession {
    pub client: DaemonClient,
}

/// Attach to the canonical persistent daemon, spawning one if needed.
///
/// Product CLI commands that need installation state must go through this
/// helper. Spawn failure is fail-closed: callers must not open SQLite.
pub async fn ensure_persistent_daemon() -> Result<PersistentDaemonSession> {
    let connected = probe_or_spawn(LifecycleMode::AttachOrPersistent).await?;
    if connected.owns_daemon {
        anyhow::bail!(
            "persistent daemon attach produced an ephemeral instance; refusing secret or workspace writes"
        );
    }
    Ok(PersistentDaemonSession {
        client: connected.client,
    })
}

/// Run the lifecycle half of the two-phase TUI composition. The CLI owns this
/// task; the TUI can request typed lifecycle policy but cannot probe, spawn,
/// restart, or retain daemon process guards itself.
pub async fn serve_lifecycle_requests(
    mut requests: tokio::sync::mpsc::Receiver<cockpit_client::LifecycleRequest>,
) -> Result<()> {
    while let Some(request) = requests.recv().await {
        // A queued request may be cancelled before the lifecycle actor sees
        // it. Never spawn a daemon for a receiver that is already gone.
        if request.reply.is_closed() {
            continue;
        }
        let mode = mode_for_intent(request.intent);
        let resolved = probe_or_spawn(mode).await.and_then(|mut connected| {
            if matches!(
                request.intent,
                cockpit_client::LifecycleIntent::EnsurePersistent
            ) && connected.owns_daemon
            {
                anyhow::bail!("persistent lifecycle request resolved to an ephemeral daemon");
            }
            Ok(cockpit_client::LifecycleResolution {
                endpoint: connected.endpoint,
                owns_daemon: connected.owns_daemon,
                socket: connected.socket,
                startup_notice: connected.startup_notice,
            })
        });
        match resolved {
            Ok(resolution) => {
                let _ = request.reply.send(Ok(resolution));
            }
            Err(error) => {
                let _ = request.reply.send(Err(error.to_string()));
            }
        }
    }
    Ok(())
}

/// Test-support composition owned below frontends. TUI tests receive only the
/// client capability and never construct or drive core lifecycle requests.
#[cfg(feature = "test-support")]
pub fn test_lifecycle_client() -> cockpit_client::LifecycleClient {
    let (client, requests) = cockpit_client::LifecycleClient::channel(8);
    tokio::spawn(async move {
        let _ = serve_lifecycle_requests(requests).await;
    });
    client
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DiscoverAttachPlan {
    AttachRunning,
    WaitForRestart,
    Spawn,
    FailIncompatible,
    FailUnreachable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RestartWaitPlan {
    WaitForReplacement,
    FailWedged,
}

fn discover_attach_plan(
    status: crate::daemon::DaemonStatus,
    has_hello: bool,
) -> DiscoverAttachPlan {
    use crate::daemon::DaemonStatus;
    match status {
        DaemonStatus::Running => DiscoverAttachPlan::AttachRunning,
        DaemonStatus::IncompatibleProtocol => DiscoverAttachPlan::FailIncompatible,
        DaemonStatus::LivePidSocketUnreachable if !has_hello => DiscoverAttachPlan::WaitForRestart,
        DaemonStatus::LivePidSocketUnreachable | DaemonStatus::UnverifiedPid => {
            DiscoverAttachPlan::FailUnreachable
        }
        DaemonStatus::NotRunning | DaemonStatus::Stale => DiscoverAttachPlan::Spawn,
    }
}

fn after_restart_wait(error: SharedWaitError) -> RestartWaitPlan {
    match error {
        SharedWaitError::Released => RestartWaitPlan::WaitForReplacement,
        SharedWaitError::Wedged => RestartWaitPlan::FailWedged,
    }
}

/// Find the daemon socket, optionally spawn the daemon, return a
/// connected client. Honors [`LifecycleMode`].
pub(crate) async fn probe_or_spawn(mode: LifecycleMode) -> Result<ConnectedDaemon> {
    use crate::daemon::{DaemonPaths, discover, spawn_detached, spawn_detached_ephemeral};

    match mode {
        LifecycleMode::AttachOrPersistent | LifecycleMode::AttachOrEphemeral => {
            let discovered = discover().await;
            match discover_attach_plan(discovered.status, discovered.hello.is_some()) {
                DiscoverAttachPlan::AttachRunning => {
                    let attached =
                        attach_running_with_skew_check(discovered.paths.clone(), None).await;
                    match attached {
                        Ok(connected) => return Ok(connected),
                        Err(error) if is_protocol_version_mismatch(&error) => {
                            return Err(error);
                        }
                        Err(error) => return Err(error),
                    }
                }
                DiscoverAttachPlan::WaitForRestart => {
                    let observed_pid =
                        cockpit_host::daemon_lifecycle::read_pid_file(&discovered.paths.pid_file);
                    let startup_notice = None;
                    match wait_for_shared_daemon(&discovered.paths.socket, observed_pid).await {
                        Ok(client) => {
                            return Ok(ConnectedDaemon {
                                endpoint: local_daemon_endpoint(&discovered.paths.socket),
                                client,
                                owns_daemon: false,
                                socket: discovered.paths.socket,
                                startup_notice,
                            });
                        }
                        Err(error) => match after_restart_wait(error) {
                            RestartWaitPlan::WaitForReplacement => {
                                tracing::info!(
                                    "canonical daemon pid released; waiting for the restart replacement"
                                );
                                match wait_for_shared_daemon(&discovered.paths.socket, None).await {
                                    Ok(client) => {
                                        return Ok(ConnectedDaemon {
                                            endpoint: local_daemon_endpoint(
                                                &discovered.paths.socket,
                                            ),
                                            client,
                                            owns_daemon: false,
                                            socket: discovered.paths.socket,
                                            startup_notice,
                                        });
                                    }
                                    Err(_) => {
                                        tracing::info!(
                                            "restart replacement never bound; spawning a replacement"
                                        );
                                    }
                                }
                            }
                            RestartWaitPlan::FailWedged => {
                                anyhow::bail!(
                                    "shared daemon pid is live but socket never became ready: {}",
                                    discovered.paths.socket.display()
                                );
                            }
                        },
                    }
                }
                DiscoverAttachPlan::Spawn => {}
                DiscoverAttachPlan::FailIncompatible => {
                    if let Some(hello) = discovered.hello.as_ref() {
                        anyhow::bail!(
                            "{}",
                            proto::incompatible_daemon_protocol_message(hello.protocol_version)
                        );
                    }
                    anyhow::bail!(
                        "shared daemon pid is live but socket is unreachable: {}",
                        discovered.paths.socket.display()
                    );
                }
                DiscoverAttachPlan::FailUnreachable => {
                    if let Some(hello) = discovered.hello.as_ref() {
                        anyhow::bail!(
                            "{}",
                            proto::incompatible_daemon_protocol_message(hello.protocol_version)
                        );
                    }
                    anyhow::bail!(
                        "shared daemon pid is live but socket is unreachable: {}",
                        discovered.paths.socket.display()
                    );
                }
            }
        }
    }

    // No reachable daemon to attach to — spawn one.
    //
    // Both lifetimes use the canonical socket. A client preference decides
    // only the first owner's lifetime; an existing owner always wins.
    let ephemeral = matches!(mode, LifecycleMode::AttachOrEphemeral);

    let (paths, pid, provisional_ephemeral_guard) = if ephemeral {
        let paths = DaemonPaths::resolve_canonical()?.with_ephemeral_lifetime();
        let child = spawn_detached_ephemeral(&paths)?;
        let pid = child.id();
        // Arm exact-child cleanup before any await or other cancellation
        // point. Once the daemon has published its verified receipt, its own
        // client reference count becomes the sole shutdown authority.
        let guard = crate::daemon::ephemeral_guard::EphemeralDaemonGuard::new(paths.clone(), child);
        (paths, pid, Some(guard))
    } else {
        // Auto-promoted persistent daemon: never `--no-sandbox` from a
        // client flag (that's a per-session default passed at attach;
        // sandboxing part 2 precedence). Only an explicit
        // `cockpit daemon start --no-sandbox` sets the daemon-level flag.
        let canonical = DaemonPaths::resolve_canonical()?;
        // In-process auto-promote binds a hello-capable owner on a dedicated
        // thread (no OS socket). Connect immediately — do not poll a missing
        // path for [`SPAWN_DAEMON_TIMEOUT`]. The promote guard / AUTO_PROMOTED
        // slot holds that owner for the test lifetime; this client does not.
        #[cfg(any(test, feature = "test-support"))]
        if crate::daemon::in_process_auto_promote_enabled() {
            let pid = crate::daemon::auto_promote_in_process_persistent().await?;
            tracing::info!(
                pid,
                ephemeral = false,
                "in-process persistent daemon promoted"
            );
            let client = connect_local_daemon(&canonical.socket)
                .await
                .with_context(|| {
                    format!(
                        "in-process auto-promote did not publish a hello-capable owner at {}",
                        canonical.socket.display()
                    )
                })?;
            return Ok(ConnectedDaemon {
                endpoint: local_daemon_endpoint(&canonical.socket),
                client,
                owns_daemon: false,
                socket: canonical.socket,
                startup_notice: None,
            });
        }
        let pid = spawn_detached(false)?;
        (canonical, pid, None)
    };
    tracing::info!(pid = pid, ephemeral = ephemeral, "daemon spawned");

    // Wait for the socket + a successful handshake. In-process auto-promote
    // returns above after a registered-owner hello; this wait is only for
    // a spawned child (or an in-process attach that already published).
    let client = wait_for_daemon(&paths.socket).await?;
    if let Some(guard) = provisional_ephemeral_guard.as_ref() {
        guard.bind_published_receipt()?;
        guard.disarm();
    }

    Ok(ConnectedDaemon {
        endpoint: local_daemon_endpoint(&paths.socket),
        client,
        owns_daemon: ephemeral,
        socket: paths.socket,
        startup_notice: None,
    })
}

async fn connect_shared_running(
    paths: crate::daemon::DaemonPaths,
    startup_notice: Option<String>,
) -> Result<ConnectedDaemon> {
    let client = connect_local_daemon(&paths.socket).await?;
    Ok(ConnectedDaemon {
        endpoint: local_daemon_endpoint(&paths.socket),
        client,
        owns_daemon: false,
        socket: paths.socket,
        startup_notice,
    })
}

async fn attach_running_with_skew_check(
    paths: crate::daemon::DaemonPaths,
    fallback_notice: Option<String>,
) -> Result<ConnectedDaemon> {
    match crate::daemon::skew_restart::restart_skewed_daemon_if_idle(&paths).await {
        Ok(crate::daemon::skew_restart::SkewRestartOutcome::Restarted { pid, reason }) => {
            tracing::info!(pid, "daemon version skew auto-restart completed");
            let client = wait_for_daemon(&paths.socket).await?;
            return Ok(ConnectedDaemon {
                endpoint: local_daemon_endpoint(&paths.socket),
                client,
                owns_daemon: false,
                socket: paths.socket,
                startup_notice: Some(match reason {
                    Some(reason) => format!("daemon version skew resolved: {reason}"),
                    None => "daemon version skew resolved by restarting the daemon".to_string(),
                }),
            });
        }
        Ok(crate::daemon::skew_restart::SkewRestartOutcome::Refused {
            reason,
            skew_reason,
        }) => {
            tracing::info!(
                reason = reason.as_deref().unwrap_or("unknown"),
                "daemon version skew auto-restart deferred"
            );
            return connect_shared_running(
                paths,
                format_skew_restart_notice(skew_reason.as_deref(), reason.as_deref()),
            )
            .await;
        }
        Ok(crate::daemon::skew_restart::SkewRestartOutcome::NoticeOnly { reason }) => {
            tracing::info!("daemon version skew surfaced without auto-restart");
            return connect_shared_running(
                paths,
                reason.map(|reason| format!("daemon version skew: {reason}")),
            )
            .await;
        }
        Ok(
            crate::daemon::skew_restart::SkewRestartOutcome::NoSkew
            | crate::daemon::skew_restart::SkewRestartOutcome::InProcess,
        ) => {}
        Err(error) => {
            tracing::debug!(error = %error, "daemon version skew auto-restart check failed");
        }
    }
    connect_shared_running(paths, fallback_notice).await
}

fn format_skew_restart_notice(
    skew_reason: Option<&str>,
    deferred_reason: Option<&str>,
) -> Option<String> {
    let skew_reason = skew_reason?;
    Some(match deferred_reason {
        Some(deferred_reason) => {
            format!("daemon version skew: {skew_reason}; auto-restart deferred: {deferred_reason}")
        }
        None => format!("daemon version skew: {skew_reason}"),
    })
}

/// Connect by socket-path key: a registered in-process owner first, otherwise
/// the Unix socket. In-process auto-promote never publishes an OS socket.
async fn connect_local_daemon(socket: &Path) -> Result<DaemonClient> {
    if let Some(endpoint) = crate::daemon::server::registered_in_process_endpoint(socket) {
        return DaemonClient::connect_endpoint(&cockpit_client::ClientEndpoint::InProcess(
            endpoint,
        ))
        .await;
    }
    DaemonClient::connect(socket).await
}

fn local_daemon_endpoint(socket: &Path) -> cockpit_client::ClientEndpoint {
    if let Some(endpoint) = crate::daemon::server::registered_in_process_endpoint(socket) {
        cockpit_client::ClientEndpoint::InProcess(endpoint)
    } else {
        cockpit_client::ClientEndpoint::Wire(socket.to_path_buf())
    }
}

enum SharedWaitError {
    Released,
    Wedged,
}

/// Poll for the daemon socket and an actual DaemonStatus response.
/// 2ms initial backoff, doubling up to a 50ms ceiling; total cap 30s.
async fn wait_for_daemon(socket: &Path) -> Result<DaemonClient> {
    match wait_for_shared_daemon(socket, None).await {
        Ok(client) => Ok(client),
        Err(SharedWaitError::Released | SharedWaitError::Wedged) => {
            anyhow::bail!("timed out waiting for daemon at {}", socket.display())
        }
    }
}

async fn wait_for_shared_daemon(
    socket: &Path,
    pid: Option<u32>,
) -> std::result::Result<DaemonClient, SharedWaitError> {
    let mut timer = crate::startup::PhaseTimer::start("wait_for_daemon");
    let deadline = std::time::Instant::now() + SPAWN_DAEMON_TIMEOUT;
    // Tight initial backoff: a freshly-spawned daemon child binds and starts
    // accepting in ~15ms (exec + tokio init + a ~4ms boot on a multi-GB DB),
    // so the first retry must land near that mark, not 50ms later. Ramp gently
    // to a 50ms ceiling so a slow/contended spawn doesn't busy-spin.
    let mut backoff = Duration::from_millis(2);

    loop {
        if crate::daemon::server::in_process_context(socket).is_some() || socket.exists() {
            // A connect error just means the socket exists but accept hasn't
            // started yet — fall through to the backoff retry. A registered
            // in-process owner hellos here without an OS socket.
            if let Ok(client) = connect_local_daemon(socket).await {
                // Sanity check — first request after connect.
                if client.request_ok(Request::DaemonStatus).await.is_ok() {
                    timer.phase("spawn_to_ready");
                    timer.done();
                    return Ok(client);
                }
            }
        }
        if pid.is_some_and(|pid| !cockpit_host::daemon_lifecycle::process_exists(pid)) {
            return Err(SharedWaitError::Released);
        }
        if std::time::Instant::now() >= deadline {
            return Err(SharedWaitError::Wedged);
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(Duration::from_millis(50));
    }
}

#[cfg(test)]
pub(super) fn temp_ephemeral_paths(root: &std::path::Path, stem: &str) -> super::DaemonPaths {
    super::DaemonPaths {
        socket: root.join(format!("{stem}.sock")),
        pid_file: root.join(format!("{stem}.pid")),
        ephemeral: true,
    }
}

#[cfg(all(test, unix))]
#[path = "client_tests.rs"]
mod tests;
