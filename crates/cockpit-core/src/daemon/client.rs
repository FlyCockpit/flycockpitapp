//! Daemon discovery and lifecycle composition.
//!
//! Local wire framing and typed request/event transport live in
//! `cockpit-client`; this module owns only process and daemon lifecycle.

use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use cockpit_client::{DaemonClient, is_protocol_version_mismatch};

use crate::daemon::proto::{self, Request};

static OWN_EPHEMERAL_PATHS: OnceLock<Mutex<Option<crate::daemon::DaemonPaths>>> = OnceLock::new();

const SPAWN_DAEMON_TIMEOUT: Duration = Duration::from_secs(30);
const LIFECYCLE_ACCEPT_TIMEOUT: Duration = Duration::from_secs(30);

async fn retain_guard_after_acceptance<G>(
    guard: Option<G>,
    accepted: tokio::sync::oneshot::Receiver<()>,
    retained: &mut Vec<G>,
) {
    if tokio::time::timeout(LIFECYCLE_ACCEPT_TIMEOUT, accepted)
        .await
        .is_ok_and(|accepted| accepted.is_ok())
        && let Some(guard) = guard
    {
        retained.push(guard);
    }
}

fn mode_for_intent(intent: cockpit_client::LifecycleIntent) -> LifecycleMode {
    match intent {
        cockpit_client::LifecycleIntent::AttachOrAutoPromote
        | cockpit_client::LifecycleIntent::EnsurePersistent => LifecycleMode::AttachOrAutoPromote,
        cockpit_client::LifecycleIntent::AttachOrEphemeral => LifecycleMode::AttachOrEphemeral,
        cockpit_client::LifecycleIntent::AlwaysEphemeral => LifecycleMode::AlwaysEphemeral,
        cockpit_client::LifecycleIntent::AttachOwnEphemeral => LifecycleMode::AttachOwnEphemeral,
    }
}

// ---- lifecycle helpers ----------------------------------------------------

/// Strategy for getting a daemon to talk to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleMode {
    /// "Attach if running, otherwise auto-promote a long-running
    /// background daemon." The TUI's default.
    AttachOrAutoPromote,
    /// "Attach if running, otherwise spawn a temporary daemon I'll
    /// stop on exit." Default for `cockpit run`.
    AttachOrEphemeral,
    /// Prefer a private ephemeral daemon that stops when the caller
    /// exits. If a persistent daemon already holds the exclusive
    /// ledger lock, attach to that owner instead. Used by
    /// `cockpit run --ephemeral`.
    AlwaysEphemeral,
    /// "Attach to *my own* per-process ephemeral daemon if it's already
    /// running, otherwise spawn it." The daemonless TUI's mode
    /// (`DaemonChoice::ContinueWithout`): the first attach spawns the
    /// owned ephemeral daemon; every later re-attach in the same TUI
    /// (`/compact`, `/sessions` resume, `/new`) reconnects to that *same*
    /// cached instance path instead of spawning a second one. The path keeps
    /// the caller pid prefix plus a per-spawn nonce via
    /// [`crate::daemon::DaemonPaths::allocate_ephemeral`],
    /// so it never touches the canonical socket and stays isolated from
    /// any other TUI's ephemeral daemon. `owns_daemon = true`.
    AttachOwnEphemeral,
}

/// Connect-or-spawn result: a ready-to-use client plus a flag the
/// caller honors when it's time to shut down — `owns_daemon = true`
/// means "you spawned this daemon, so stop it on your way out."
pub(crate) struct ConnectedDaemon {
    client: DaemonClient,
    endpoint: cockpit_client::ClientEndpoint,
    owns_daemon: bool,
    socket: PathBuf,
    startup_notice: Option<String>,
    /// Provisional ownership begins in `probe_or_spawn` immediately after an
    /// ephemeral child is created. Callers must explicitly take this guard
    /// when publishing a longer-lived owner; every abandoned/error path drops
    /// it and reaps the child.
    owned_daemon_guard: Option<crate::daemon::ephemeral_guard::EphemeralDaemonGuard>,
    owned_in_process_guard: Option<crate::daemon::InProcessDaemonGuard>,
}

enum OwnedDaemonGuard {
    Process(crate::daemon::ephemeral_guard::EphemeralDaemonGuard),
    InProcess(crate::daemon::InProcessDaemonGuard),
}

impl OwnedDaemonGuard {
    fn begin_shutdown(&mut self) {
        if let Self::InProcess(guard) = self {
            guard.begin_shutdown();
        }
    }

    fn shutdown_force_handle(&self) -> Option<crate::daemon::shutdown::ShutdownSignal> {
        match self {
            Self::Process(_) => None,
            Self::InProcess(guard) => Some(guard.shutdown_force_handle()),
        }
    }

    async fn shutdown(self) -> Result<()> {
        match self {
            Self::Process(guard) => {
                let (completed, completion) = tokio::sync::oneshot::channel();
                let owner = std::thread::Builder::new()
                    .name("cockpit-ephemeral-daemon-owner".to_string())
                    .spawn(move || {
                        let result = guard.shutdown();
                        drop(guard);
                        let _ = completed.send(result);
                    })
                    .context("spawning ephemeral daemon owner teardown")?;
                crate::daemon::reap_daemon_owner_thread(owner);
                completion
                    .await
                    .context("ephemeral daemon owner teardown stopped")?
            }
            Self::InProcess(guard) => guard.shutdown().await,
        }
    }
}

impl ConnectedDaemon {
    pub(crate) fn take_owned_daemon_guard(
        &mut self,
    ) -> Option<crate::daemon::ephemeral_guard::EphemeralDaemonGuard> {
        self.owned_daemon_guard.take()
    }

    fn take_lifecycle_guard(&mut self) -> Option<OwnedDaemonGuard> {
        self.owned_daemon_guard
            .take()
            .map(OwnedDaemonGuard::Process)
            .or_else(|| {
                self.owned_in_process_guard
                    .take()
                    .map(OwnedDaemonGuard::InProcess)
            })
    }
}

/// Foreground CLI connection whose ephemeral process ownership cannot be
/// separated from its client. Construction arms signal cleanup before the
/// value is published; [`finish`](Self::finish) joins that cleanup and
/// combines it with the command result.
struct OwnedDaemonSession {
    client: DaemonClient,
    guard: Option<crate::daemon::ephemeral_guard::EphemeralDaemonGuard>,
    signal_task: Option<tokio::task::JoinHandle<()>>,
}

/// Foreground command modes that can only resolve to an attached persistent
/// daemon or an exactly owned child process. In-process TUI ownership is
/// intentionally absent because it requires a different async guard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnedSessionMode {
    AttachOrAutoPromote,
    AttachOrEphemeral,
    AlwaysEphemeral,
}

impl OwnedSessionMode {
    fn lifecycle(self) -> LifecycleMode {
        match self {
            Self::AttachOrAutoPromote => LifecycleMode::AttachOrAutoPromote,
            Self::AttachOrEphemeral => LifecycleMode::AttachOrEphemeral,
            Self::AlwaysEphemeral => LifecycleMode::AlwaysEphemeral,
        }
    }
}

impl OwnedDaemonSession {
    async fn connect(mode: OwnedSessionMode) -> Result<Self> {
        let mut connected = probe_or_spawn(mode.lifecycle()).await?;
        let guard = connected.take_owned_daemon_guard();
        let signal_task =
            match crate::daemon::ephemeral_guard::spawn_signal_shutdown(guard.as_ref(), true) {
                Ok(task) => task,
                Err(error) => {
                    let shutdown = guard.as_ref().map_or(Ok(()), |guard| guard.shutdown());
                    drop(guard);
                    return crate::daemon::ephemeral_guard::aggregate_shutdown_result(
                        Err::<Self, _>(error.context("arming owned-daemon signal cleanup")),
                        shutdown,
                    );
                }
            };
        if let Some(notice) = connected.startup_notice.take() {
            eprintln!("{notice}");
        }
        Ok(Self {
            client: connected.client,
            guard,
            signal_task,
        })
    }

    fn client(&self) -> &DaemonClient {
        &self.client
    }

    async fn finish<T>(mut self, result: Result<T>) -> Result<T> {
        let signal_task = self.signal_task.take();
        if let Some(task) = &signal_task {
            task.abort();
        }
        let shutdown = self.guard.as_ref().map_or(Ok(()), |guard| guard.shutdown());
        self.guard.take();
        if let Some(task) = signal_task {
            let _ = task.await;
        }
        crate::daemon::ephemeral_guard::aggregate_shutdown_result(result, shutdown)
    }
}

/// Run one foreground operation while this module retains inseparable
/// ownership of any ephemeral daemon it starts. The operation can only borrow
/// the authority-free client; every return path joins signal cleanup and
/// aggregates the operation and exact-child shutdown results.
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

impl Drop for OwnedDaemonSession {
    fn drop(&mut self) {
        if let Some(task) = self.signal_task.take() {
            task.abort();
        }
        // `guard` deliberately remains armed. Its Drop joins the same exact
        // cleanup used by explicit finish and signal-driven teardown.
    }
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
    let connected = probe_or_spawn(LifecycleMode::AttachOrAutoPromote).await?;
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
    let mut owned_daemons = Vec::new();
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
            let guard = connected.take_lifecycle_guard();
            Ok((
                cockpit_client::LifecycleResolution {
                    endpoint: connected.endpoint,
                    owns_daemon: connected.owns_daemon,
                    socket: connected.socket,
                    startup_notice: connected.startup_notice,
                },
                guard,
            ))
        });
        match resolved {
            Ok((resolution, guard)) => {
                if request.reply.send(Ok(resolution)).is_err() {
                    // `guard` drops here and reaps an unaccepted ephemeral.
                    continue;
                }
                retain_guard_after_acceptance(guard, request.accepted, &mut owned_daemons).await;
                // A cancelled/missing acceptance drops the guard here.
            }
            Err(error) => {
                let _ = request.reply.send(Err(error.to_string()));
            }
        }
    }
    // Start every owned daemon before waiting for any one of them. A single
    // slow teardown must not consume the grace period of all later owners.
    for guard in &mut owned_daemons {
        guard.begin_shutdown();
    }
    let force_handles = owned_daemons
        .iter()
        .filter_map(OwnedDaemonGuard::shutdown_force_handle)
        .collect::<Vec<_>>();
    let mut shutdowns = std::pin::pin!(futures::future::join_all(
        owned_daemons.into_iter().map(OwnedDaemonGuard::shutdown)
    ));
    let graceful_deadline =
        crate::daemon::shutdown::SHUTDOWN_DRAIN_GRACE + std::time::Duration::from_secs(5);
    let (outcomes, forced) = match tokio::time::timeout(graceful_deadline, &mut shutdowns).await {
        Ok(outcomes) => (outcomes, false),
        Err(_) => {
            // Each in-process supervisor owns its context on an independent
            // OS thread. Promote every still-running context to Forced, then
            // join all supervisors instead of abandoning them with the CLI
            // runtime. Process stop requests run concurrently in the same
            // join set and remain bounded independently.
            for force in &force_handles {
                force.force();
            }
            match tokio::time::timeout(std::time::Duration::from_secs(5), &mut shutdowns).await {
                Ok(outcomes) => (outcomes, true),
                Err(_) => {
                    // Dropping the join set transfers every in-process
                    // supervisor to the runtime-independent reaper through
                    // its guard's Drop. Never wait forever or claim clean.
                    anyhow::bail!(
                        "owned daemon cleanup remained incomplete after the forced terminal deadline"
                    )
                }
            }
        }
    };
    let mut failures = outcomes
        .into_iter()
        .filter_map(Result::err)
        .map(|error| error.to_string())
        .collect::<Vec<_>>();
    if forced {
        failures.push("owned daemon cleanup exceeded its graceful deadline and was forced".into());
    }
    if failures.is_empty() {
        Ok(())
    } else {
        anyhow::bail!(failures.join("; "))
    }
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
    Spawn,
    FailWedged,
}

fn ephemeral_may_spawn_private(mode: LifecycleMode) -> bool {
    matches!(
        mode,
        LifecycleMode::AlwaysEphemeral | LifecycleMode::AttachOrEphemeral
    )
}

fn discover_attach_plan(
    mode: LifecycleMode,
    status: crate::daemon::DaemonStatus,
    has_hello: bool,
) -> DiscoverAttachPlan {
    use crate::daemon::DaemonStatus;
    match status {
        DaemonStatus::Running => DiscoverAttachPlan::AttachRunning,
        DaemonStatus::IncompatibleProtocol if ephemeral_may_spawn_private(mode) => {
            DiscoverAttachPlan::Spawn
        }
        DaemonStatus::IncompatibleProtocol => DiscoverAttachPlan::FailIncompatible,
        DaemonStatus::LivePidSocketUnreachable if !has_hello => DiscoverAttachPlan::WaitForRestart,
        DaemonStatus::LivePidSocketUnreachable | DaemonStatus::UnverifiedPid
            if ephemeral_may_spawn_private(mode) =>
        {
            DiscoverAttachPlan::Spawn
        }
        DaemonStatus::LivePidSocketUnreachable | DaemonStatus::UnverifiedPid => {
            DiscoverAttachPlan::FailUnreachable
        }
        DaemonStatus::NotRunning | DaemonStatus::Stale => DiscoverAttachPlan::Spawn,
    }
}

fn after_restart_wait(mode: LifecycleMode, error: SharedWaitError) -> RestartWaitPlan {
    match error {
        SharedWaitError::Released => RestartWaitPlan::Spawn,
        SharedWaitError::Wedged if ephemeral_may_spawn_private(mode) => RestartWaitPlan::Spawn,
        SharedWaitError::Wedged => RestartWaitPlan::FailWedged,
    }
}

/// Find the daemon socket, optionally spawn the daemon, return a
/// connected client. Honors [`LifecycleMode`].
pub(crate) async fn probe_or_spawn(mode: LifecycleMode) -> Result<ConnectedDaemon> {
    use crate::daemon::{DaemonPaths, discover, spawn_detached, spawn_detached_ephemeral};

    match mode {
        LifecycleMode::AttachOrAutoPromote
        | LifecycleMode::AttachOrEphemeral
        | LifecycleMode::AlwaysEphemeral => {
            let discovered = discover().await;
            match discover_attach_plan(mode, discovered.status, discovered.hello.is_some()) {
                DiscoverAttachPlan::AttachRunning => {
                    let attach_notice = matches!(mode, LifecycleMode::AlwaysEphemeral)
                        .then(|| EPHEMERAL_ATTACH_NOTICE.to_string());
                    let attached = if matches!(
                        mode,
                        LifecycleMode::AttachOrAutoPromote | LifecycleMode::AlwaysEphemeral
                    ) {
                        attach_running_with_skew_check(discovered.paths.clone(), attach_notice)
                            .await
                    } else {
                        connect_shared_running(discovered.paths.clone(), None).await
                    };
                    match attached {
                        Ok(connected) => return Ok(connected),
                        Err(error) if is_protocol_version_mismatch(&error) => {
                            return Err(error);
                        }
                        Err(error) if ephemeral_may_spawn_private(mode) => {
                            tracing::debug!(
                                error = %error,
                                "shared daemon disappeared after discover; spawning a private daemon"
                            );
                        }
                        Err(error) => return Err(error),
                    }
                }
                DiscoverAttachPlan::WaitForRestart => {
                    let observed_pid =
                        cockpit_host::daemon_lifecycle::read_pid_file(&discovered.paths.pid_file);
                    let startup_notice =
                        matches!(mode, LifecycleMode::AlwaysEphemeral).then(|| {
                            "waiting for the already-running persistent daemon to finish restart"
                                .to_string()
                        });
                    match wait_for_shared_daemon(&discovered.paths.socket, observed_pid).await {
                        Ok(client) => {
                            return Ok(ConnectedDaemon {
                                endpoint: local_daemon_endpoint(&discovered.paths.socket),
                                client,
                                owns_daemon: false,
                                socket: discovered.paths.socket,
                                startup_notice,
                                owned_daemon_guard: None,
                                owned_in_process_guard: None,
                            });
                        }
                        Err(error) => match after_restart_wait(mode, error) {
                            RestartWaitPlan::Spawn => {
                                tracing::info!(
                                    "canonical daemon pid released or never bound; spawning a replacement"
                                );
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
        LifecycleMode::AttachOwnEphemeral => {
            // Daemonless TUI sessions stay in this process. Existing helpers
            // still carry the owned ephemeral socket path as a stable lookup
            // key; `connect_local_daemon` resolves a registered in-process
            // context instead of opening a Unix socket.
            let own = own_ephemeral_paths()?;
            let (in_process_endpoint, guard) = crate::daemon::boot_in_process(
                own.clone(),
                crate::daemon::terminal::default_host_factory(),
            )
            .await?;
            let endpoint = cockpit_client::ClientEndpoint::InProcess(in_process_endpoint);
            return Ok(ConnectedDaemon {
                client: DaemonClient::connect_endpoint(&endpoint).await?,
                endpoint,
                owns_daemon: guard.is_some(),
                socket: own.socket,
                startup_notice: None,
                owned_daemon_guard: None,
                owned_in_process_guard: guard,
            });
        }
    }

    // No reachable daemon to attach to — spawn one.
    //
    // `AttachOrAutoPromote` (the canonical TUI) promotes a *persistent*
    // daemon at the canonical path. The ephemeral modes spawn a unique
    // pid+nonce ephemeral daemon (Layer B): socket/pid the canonical
    // `daemon stop`/`status` never sees, with the self-reaping watchdog
    // armed (Layer C) so an uncatchable foreground death can't orphan it.
    let ephemeral = matches!(
        mode,
        LifecycleMode::AttachOrEphemeral
            | LifecycleMode::AlwaysEphemeral
            | LifecycleMode::AttachOwnEphemeral
    );

    let (paths, pid, owned_daemon_guard) = if ephemeral {
        // Allocate the exact ephemeral path set in the parent, then hand it
        // to the spawned daemon to bind. Daemonless TUI reattachments reuse
        // their cached owned path; `AlwaysEphemeral` allocates fresh here.
        let paths = match mode {
            LifecycleMode::AttachOwnEphemeral => own_ephemeral_paths()?,
            _ => DaemonPaths::allocate_ephemeral()?,
        };
        let child = spawn_detached_ephemeral(&paths)?;
        let pid = child.id();
        // Arm ownership before any await or other cancellation point. From
        // here onward every early return owns a guard whose Drop stops exactly
        // this pid+nonce daemon.
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
                owned_daemon_guard: None,
                owned_in_process_guard: None,
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
    if let Some(guard) = owned_daemon_guard.as_ref() {
        guard.bind_published_receipt()?;
    }

    Ok(ConnectedDaemon {
        endpoint: local_daemon_endpoint(&paths.socket),
        client,
        owns_daemon: ephemeral,
        socket: paths.socket,
        startup_notice: None,
        owned_daemon_guard,
        owned_in_process_guard: None,
    })
}

const EPHEMERAL_ATTACH_NOTICE: &str =
    "attaching to the already-running persistent daemon; this run will not stop it";

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
        owned_daemon_guard: None,
        owned_in_process_guard: None,
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
                owned_daemon_guard: None,
                owned_in_process_guard: None,
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

fn own_ephemeral_paths() -> Result<crate::daemon::DaemonPaths> {
    let slot = OWN_EPHEMERAL_PATHS.get_or_init(|| Mutex::new(None));
    let mut guard = slot
        .lock()
        .map_err(|_| anyhow!("owned ephemeral path cache poisoned"))?;
    if let Some(paths) = guard.clone() {
        return Ok(paths);
    }
    let paths = crate::daemon::DaemonPaths::allocate_ephemeral()?;
    *guard = Some(paths.clone());
    Ok(paths)
}

#[cfg(test)]
fn reset_own_ephemeral_paths_for_test() {
    if let Some(slot) = OWN_EPHEMERAL_PATHS.get() {
        *slot.lock().unwrap() = None;
    }
}

#[cfg(test)]
fn set_own_ephemeral_paths_for_test(paths: crate::daemon::DaemonPaths) {
    let slot = OWN_EPHEMERAL_PATHS.get_or_init(|| Mutex::new(None));
    *slot.lock().unwrap() = Some(paths);
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
