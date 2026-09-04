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
/// An accepted ephemeral restart is destructive, so its replacement phase is
/// given one bounded recovery window. This prevents a permanently broken
/// successor from serially wedging the lifecycle host forever.
const PROMOTION_REPLACEMENT_TIMEOUT: Duration = Duration::from_secs(30);

/// One-line presentation notice emitted after an Assistant promotes the
/// shared ledger owner from ephemeral to persistent mode.
pub const ASSISTANT_PERSISTENCE_NOTICE: &str =
    "Assistants run in the background; keeping Cockpit running";

fn mode_for_intent(intent: cockpit_client::LifecycleIntent) -> LifecycleMode {
    match intent {
        cockpit_client::LifecycleIntent::AttachOrPersistent => {
            LifecycleMode::from_background_agents(true)
        }
        cockpit_client::LifecycleIntent::AttachOrEphemeral => {
            LifecycleMode::from_background_agents(false)
        }
        cockpit_client::LifecycleIntent::PromoteToPersistent => LifecycleMode::PromoteToPersistent,
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
    /// Require a persistent owner, replacing an idle ephemeral owner when
    /// necessary. Assistant sessions use this instead of treating the global
    /// background-agents preference as a dead-end block.
    PromoteToPersistent,
}

impl LifecycleMode {
    /// Select the lifetime used only when acquisition must spawn an owner.
    /// Existing owners are always discovered and attached before this policy
    /// is consulted.
    pub fn from_background_agents(background_agents: bool) -> Self {
        if background_agents {
            Self::AttachOrPersistent
        } else {
            Self::AttachOrEphemeral
        }
    }
}

/// Connect-or-spawn result: a ready-to-use client and the lifetime selected
/// for a newly spawned owner. Socket-owner shutdown is governed exclusively
/// by the daemon's client reference count, never by this client process.
pub(crate) struct ConnectedDaemon {
    client: DaemonClient,
    endpoint: cockpit_client::ClientEndpoint,
    owns_daemon: bool,
    ephemeral_owner: bool,
    socket: PathBuf,
    startup_notice: Option<String>,
    promoted_from_ephemeral: bool,
}

/// Foreground CLI connection scoped to one operation.
struct OwnedDaemonSession {
    client: DaemonClient,
}

/// Foreground command lifecycle preferences.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnedSessionMode {
    AttachOrPersistent,
    AttachOrEphemeral,
}

/// Acquire the shareable ledger owner for an ACP process. ACP is multi-window,
/// so this path always resolves a discoverable wire owner (Unix socket or
/// Windows named-pipe identity) and never selects the one-shot in-process
/// optimization. The background-agents setting chooses only the lifetime when
/// this call must start a new owner; an existing owner is always reused.
pub async fn acquire_acp_socket_daemon(background_agents: bool) -> Result<DaemonClient> {
    let mode = if background_agents {
        LifecycleMode::AttachOrPersistent
    } else {
        LifecycleMode::AttachOrEphemeral
    };
    let connected = probe_or_spawn(mode).await?;
    #[cfg(any(unix, windows))]
    {
        validate_acp_connected_daemon(&connected)?;
        // Reuse the already-attached client. When the user prefers background
        // agents, promote the shared ephemeral owner in place so closing the
        // ACP subprocess cannot reap live work. This is not a re-acquire and
        // not a restart.
        if background_agents && connected.ephemeral_owner {
            promote_attached_owner_in_place(&connected.client).await?;
        }
        return Ok(connected.client);
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = connected;
        anyhow::bail!("ACP wire ledger ownership is unavailable on this platform")
    }
}

/// ACP stdio ingress requires a discoverable wire owner with a peer-bound
/// credential from `ExchangeLocalPeerCredential`. In-process auto-promote is
/// intentionally excluded.
fn validate_acp_connected_daemon(connected: &ConnectedDaemon) -> Result<()> {
    if !connected.endpoint.is_discoverable_wire_owner() {
        anyhow::bail!("ACP requires a discoverable wire ledger owner");
    }
    if !connected.client.is_socket_backed() {
        anyhow::bail!("ACP requires a wire-backed ledger client");
    }
    if !connected.client.has_owner_capability() {
        anyhow::bail!("ACP stdio ingress requires a peer-bound owner credential");
    }
    Ok(())
}

/// Request in-place promotion of the owner this client is already talking to.
///
/// Does not spawn, restart, drop the connection, or re-acquire a socket. The
/// RPC is idempotent: a persistent owner acknowledges without changing state.
pub async fn promote_attached_owner_in_place(client: &DaemonClient) -> Result<()> {
    match client.request_ok(Request::PromoteToPersistent).await? {
        proto::Response::Ack => Ok(()),
        other => anyhow::bail!("unexpected live promotion response: {other:?}"),
    }
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
        })
    }

    fn client(&self) -> &DaemonClient {
        &self.client
    }

    async fn finish<T>(self, result: Result<T>) -> Result<T> {
        result
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

/// Run one foreground operation against the shareable ephemeral owner.  The
/// same lifecycle runner owns every foreground acquisition, so an operation
/// that needs a socket-visible daemon (including a later resume) cannot
/// accidentally select a private in-process transport.
pub async fn run_one_shot_daemon<T, F>(operation: F) -> std::result::Result<T, OwnedDaemonRunError>
where
    F: for<'client> std::ops::FnOnce(
            ScopedDaemonClient<'client>,
        ) -> std::pin::Pin<
            std::boxed::Box<dyn std::future::Future<Output = anyhow::Result<T>> + 'client>,
        >,
{
    run_owned_daemon(OwnedSessionMode::AttachOrEphemeral, operation).await
}

/// Run one foreground operation through the persistent Assistant owner.
///
/// This has the same callback boundary as [`run_one_shot_daemon`], but never
/// returns a client backed by the one-shot ephemeral owner: a resumed session
/// may be an Assistant, whose daemon-owned work must survive this command.
/// The callback receives whether lifecycle acquisition promoted the owner;
/// it must wait for its Attach response before presenting Assistant-only UI.
pub async fn run_assistant_daemon<T, F>(operation: F) -> std::result::Result<T, OwnedDaemonRunError>
where
    F: for<'client> std::ops::FnOnce(
            ScopedDaemonClient<'client>,
            bool,
        ) -> std::pin::Pin<
            std::boxed::Box<dyn std::future::Future<Output = anyhow::Result<T>> + 'client>,
        >,
{
    let connected = probe_or_spawn(LifecycleMode::PromoteToPersistent)
        .await
        .map_err(OwnedDaemonRunError::Connect)?;
    if connected.owns_daemon {
        return Err(OwnedDaemonRunError::OperationOrCleanup(anyhow!(
            "persistent daemon attach produced an ephemeral instance; refusing resumed session"
        )));
    }
    operation(
        ScopedDaemonClient {
            client: &connected.client,
        },
        connected.promoted_from_ephemeral,
    )
    .await
    .map_err(OwnedDaemonRunError::OperationOrCleanup)
}

/// Persistent-only daemon connection. It contains no process-ownership guard,
/// so exposing the client cannot detach an ephemeral child.
pub struct PersistentDaemonSession {
    pub client: DaemonClient,
    promoted_from_ephemeral: bool,
}

impl PersistentDaemonSession {
    /// Whether acquiring this session promoted the shared ledger owner from
    /// ephemeral to persistent mode.
    pub fn promoted_from_ephemeral(&self) -> bool {
        self.promoted_from_ephemeral
    }
}

/// Require the canonical persistent daemon, spawning one if needed.
///
/// Product CLI commands that need installation state must go through this
/// helper. Spawn failure is fail-closed: callers must not open SQLite.
pub async fn ensure_persistent_daemon() -> Result<PersistentDaemonSession> {
    // Attaching to an ephemeral owner would leave this caller with a client
    // whose daemon disappears when the original lifetime guard is released.
    // Persistence is the contract of this API, so promote before returning.
    let connected = probe_or_spawn(LifecycleMode::PromoteToPersistent).await?;
    if connected.owns_daemon {
        anyhow::bail!(
            "persistent daemon attach produced an ephemeral instance; refusing secret or workspace writes"
        );
    }
    Ok(PersistentDaemonSession {
        client: connected.client,
        promoted_from_ephemeral: connected.promoted_from_ephemeral,
    })
}

/// Require a persistent daemon for an Assistant session. Unlike ordinary
/// persistent CLI consumers, an Assistant may promote the shared ephemeral
/// owner because its work continues after the opening client exits.
pub async fn ensure_assistant_persistent_daemon() -> Result<PersistentDaemonSession> {
    let connected = probe_or_spawn(LifecycleMode::PromoteToPersistent).await?;
    if connected.owns_daemon {
        anyhow::bail!(
            "persistent daemon attach produced an ephemeral instance; refusing assistant session"
        );
    }
    Ok(PersistentDaemonSession {
        client: connected.client,
        promoted_from_ephemeral: connected.promoted_from_ephemeral,
    })
}

/// Run the lifecycle half of the two-phase TUI composition. The CLI owns this
/// task; the TUI can request typed lifecycle policy but cannot probe, spawn,
/// restart, or retain daemon process guards itself.
pub async fn serve_lifecycle_requests(
    requests: tokio::sync::mpsc::Receiver<cockpit_client::LifecycleRequest>,
) -> Result<()> {
    serve_lifecycle_requests_with(requests, |request| -> LifecycleResolutionFuture<'_> {
        Box::pin(async move {
            let mode = mode_for_intent(request.intent);
            let connected = probe_or_spawn_with_spawn_authorization(mode, Some(request)).await?;
            Ok(lifecycle_resolution(connected))
        })
    })
    .await
}

type LifecycleResolutionFuture<'a> = std::pin::Pin<
    std::boxed::Box<
        dyn std::future::Future<Output = Result<cockpit_client::LifecycleResolution>> + Send + 'a,
    >,
>;

/// Serialize lifecycle work while retaining each request's reply channel in
/// the host. Keeping the loop separate from resolution lets terminal
/// promotion failures prove that the host can accept the next request.
async fn serve_lifecycle_requests_with<F>(
    mut requests: tokio::sync::mpsc::Receiver<cockpit_client::LifecycleRequest>,
    mut resolve: F,
) -> Result<()>
where
    F: for<'a> FnMut(&'a cockpit_client::LifecycleRequest) -> LifecycleResolutionFuture<'a>,
{
    while let Some(request) = requests.recv().await {
        // A queued request may be cancelled before the lifecycle actor sees
        // it. Never spawn a daemon for a cancelled request.
        if request.is_cancelled() || request.reply.is_closed() {
            continue;
        }
        let resolved = resolve(&request).await;
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

fn lifecycle_resolution(connected: ConnectedDaemon) -> cockpit_client::LifecycleResolution {
    cockpit_client::LifecycleResolution {
        endpoint: connected.endpoint,
        owns_daemon: connected.owns_daemon,
        ephemeral_owner: connected.ephemeral_owner,
        socket: connected.socket,
        startup_notice: connected.startup_notice,
        promoted_from_ephemeral: connected.promoted_from_ephemeral,
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
    probe_or_spawn_with_spawn_authorization(mode, None).await
}

/// Promote the shared ephemeral owner to a persistent replacement.
///
/// The lifecycle permit is claimed before `RestartIfIdle`, the destructive
/// transition. It remains held through predecessor release and either the
/// verified persistent attach or the replacement spawn, so a timed-out caller
/// cannot cancel the only request permitted to replace the old owner.
async fn promote_ephemeral_owner(
    paths: &crate::daemon::DaemonPaths,
    lifecycle_request: Option<&cockpit_client::LifecycleRequest>,
) -> Result<ConnectedDaemon> {
    // The detach guard promotes a live owner in place. This keeps the daemon's
    // session workers, subagents, and host processes intact; the owner merely
    // stops participating in last-client ephemeral teardown.
    match promote_live_ephemeral_owner(paths).await {
        Ok(connected) => return Ok(connected),
        Err(error) => {
            tracing::warn!(%error, "in-place daemon promotion failed; trying legacy idle replacement")
        }
    }
    promote_ephemeral_owner_with_recovery_policy(
        paths,
        lifecycle_request,
        PromotionRecoveryPolicy::production(),
    )
    .await
}

async fn promote_live_ephemeral_owner(
    paths: &crate::daemon::DaemonPaths,
) -> Result<ConnectedDaemon> {
    let expected = ephemeral_owner_identity(paths)
        .ok_or_else(|| anyhow!("ephemeral daemon owner identity is unavailable for promotion"))?;
    let client = connect_local_daemon(&paths.socket)
        .await
        .context("connecting to ephemeral daemon for live promotion")?;
    if ephemeral_owner_identity(paths) != Some(expected) {
        anyhow::bail!("ephemeral daemon owner changed before live promotion");
    }
    match client.request_ok(Request::PromoteToPersistent).await? {
        proto::Response::Ack => {}
        other => anyhow::bail!("unexpected live promotion response: {other:?}"),
    }
    drop(client);
    let discovered = crate::daemon::discover().await;
    if discovered.status != crate::daemon::DaemonStatus::Running || discovered.paths.ephemeral {
        anyhow::bail!("daemon did not publish persistent ownership after promotion");
    }
    let mut connected = attach_running_with_skew_check(discovered.paths, None).await?;
    connected.promoted_from_ephemeral = true;
    Ok(connected)
}

#[derive(Clone, Copy)]
struct PromotionRecoveryPolicy {
    replacement_timeout: Duration,
    predecessor_release_timeout: Duration,
}

impl PromotionRecoveryPolicy {
    fn production() -> Self {
        Self {
            replacement_timeout: PROMOTION_REPLACEMENT_TIMEOUT,
            predecessor_release_timeout: crate::daemon::restart_release_timeout(None),
        }
    }
}

async fn promote_ephemeral_owner_with_recovery_policy(
    paths: &crate::daemon::DaemonPaths,
    lifecycle_request: Option<&cockpit_client::LifecycleRequest>,
    recovery: PromotionRecoveryPolicy,
) -> Result<ConnectedDaemon> {
    let mut current_paths = paths.clone();
    let mut spawn_permit = None;
    let mut replacement_required = false;
    let mut replacement_deadline = None;

    loop {
        ensure_promotion_replacement_deadline(replacement_deadline)?;

        if !replacement_required
            && lifecycle_request
                .is_some_and(|request| request.is_cancelled() || request.reply.is_closed())
        {
            anyhow::bail!("assistant daemon lifecycle request was cancelled before promotion");
        }

        // Do not retain creation authority while background work is still
        // running: its next idle boundary must remain cancellable. Once the
        // daemon accepts RestartIfIdle, retain the permit until replacement.
        // From that acceptance onward this is a destructive transaction: the
        // original caller may disappear, but its authorization must still
        // produce (or attach to) the persistent replacement.
        if spawn_permit.is_none() {
            spawn_permit = lifecycle_request
                .map(cockpit_client::LifecycleRequest::authorize_owner_spawn)
                .transpose()
                .map_err(anyhow::Error::msg)?;
        }

        // The canonical socket is reusable. Bind this destructive request to
        // the exact ephemeral generation observed by discovery; otherwise a
        // competing promotion can replace the owner before this connection is
        // made and make us restart its persistent successor.
        let expected_predecessor = ephemeral_owner_identity(&current_paths).ok_or_else(|| {
            anyhow!("ephemeral daemon owner identity is unavailable for promotion")
        })?;
        let old_pid = Some(expected_predecessor.1.pid);
        let client = match connect_local_daemon(&current_paths.socket).await {
            Ok(client) => client,
            Err(error) if replacement_required => {
                // The accepted predecessor can lose its socket between
                // discovery and this retry. Keep the transaction alive and
                // return to discovery rather than dropping its permit.
                tracing::info!(
                    error = %error,
                    "accepted assistant promotion observed a restarting daemon socket"
                );
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
            Err(error) => {
                return Err(error)
                    .context("connecting to ephemeral daemon for persistent promotion");
            }
        };
        if ephemeral_owner_identity(&current_paths) != Some(expected_predecessor.clone()) {
            // Do not issue RestartIfIdle to a socket whose published owner
            // changed while connecting. Return to discovery; the next loop
            // either observes the persistent successor or binds a new
            // ephemeral predecessor before making another destructive call.
            drop(client);
            let discovered = crate::daemon::discover().await;
            match discover_attach_plan(discovered.status, discovered.hello.is_some()) {
                DiscoverAttachPlan::AttachRunning if !discovered.paths.ephemeral => {
                    let mut connected =
                        attach_running_with_skew_check(discovered.paths, None).await?;
                    connected.promoted_from_ephemeral = true;
                    return Ok(connected);
                }
                DiscoverAttachPlan::AttachRunning => {
                    current_paths = discovered.paths;
                    continue;
                }
                DiscoverAttachPlan::WaitForRestart
                | DiscoverAttachPlan::Spawn
                | DiscoverAttachPlan::FailIncompatible
                | DiscoverAttachPlan::FailUnreachable => {
                    anyhow::bail!(
                        "ephemeral daemon owner changed while preparing Assistant promotion"
                    );
                }
            }
        }
        let response = match client.request_ok(Request::RestartIfIdle).await {
            Ok(response) => response,
            Err(error) if replacement_required => {
                tracing::info!(
                    error = %error,
                    "accepted assistant promotion observed a draining daemon connection"
                );
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
            Err(error) => return Err(error).context("requesting ephemeral daemon promotion"),
        };
        let proto::Response::RestartDecision {
            will_restart,
            reason,
        } = response
        else {
            anyhow::bail!("unexpected daemon promotion response: {response:?}");
        };
        drop(client);

        if !will_restart {
            if replacement_required {
                // Another restart decision can observe the predecessor (or a
                // replacement ephemeral owner) while it is already draining.
                // The first accepted decision is irreversible, so retain its
                // authority and wait for the terminal persistent owner rather
                // than treating this as the ordinary busy/cancellable path.
                tracing::info!(
                    reason = reason
                        .as_deref()
                        .unwrap_or("the current daemon cannot restart"),
                    "accepted assistant promotion is waiting for an in-progress restart"
                );
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }

            // A running agent owns its background work. Leave it untouched,
            // release this attempt's authority, and retry at its next idle
            // boundary instead of turning Assistant open into a dead end.
            drop(spawn_permit.take());
            tracing::info!(
                reason = reason
                    .as_deref()
                    .unwrap_or("the current daemon cannot restart"),
                "assistant promotion waiting for ephemeral background work to become idle"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
            let discovered = crate::daemon::discover().await;
            match discover_attach_plan(discovered.status, discovered.hello.is_some()) {
                DiscoverAttachPlan::AttachRunning if !discovered.paths.ephemeral => {
                    let mut connected =
                        attach_running_with_skew_check(discovered.paths, None).await?;
                    connected.promoted_from_ephemeral = true;
                    return Ok(connected);
                }
                DiscoverAttachPlan::AttachRunning => current_paths = discovered.paths,
                DiscoverAttachPlan::WaitForRestart => {
                    // `will_restart == false` also reports an owner that is
                    // already shutting down. Do not re-enter by connecting to
                    // that old socket: wait for its transition, while keeping
                    // this pre-acceptance path cancellable.
                    loop {
                        if lifecycle_request.is_some_and(|request| {
                            request.is_cancelled() || request.reply.is_closed()
                        }) {
                            anyhow::bail!(
                                "assistant daemon lifecycle request was cancelled while waiting for restart"
                            );
                        }

                        tokio::time::sleep(Duration::from_millis(100)).await;
                        let restarted = crate::daemon::discover().await;
                        match discover_attach_plan(restarted.status, restarted.hello.is_some()) {
                            DiscoverAttachPlan::AttachRunning if !restarted.paths.ephemeral => {
                                if let Some(connected) =
                                    try_attach_verified_persistent_replacement(restarted.paths)
                                        .await
                                {
                                    return Ok(connected);
                                }
                            }
                            DiscoverAttachPlan::AttachRunning => {
                                current_paths = restarted.paths;
                                break;
                            }
                            DiscoverAttachPlan::WaitForRestart => {}
                            DiscoverAttachPlan::Spawn => {
                                // The busy retry deliberately dropped its
                                // prior permit. Reclaim authority at this new
                                // creation point so cancellation during the
                                // idle wait cannot spawn an owner after the
                                // request has stopped waiting.
                                spawn_permit = lifecycle_request
                                    .map(cockpit_client::LifecycleRequest::authorize_owner_spawn)
                                    .transpose()
                                    .map_err(anyhow::Error::msg)?;
                                return spawn_verified_persistent_replacement(
                                    &mut spawn_permit,
                                    None,
                                )
                                .await;
                            }
                            DiscoverAttachPlan::FailIncompatible
                            | DiscoverAttachPlan::FailUnreachable => {
                                anyhow::bail!(
                                    "shared daemon became unreachable while waiting to promote Assistant work"
                                );
                            }
                        }
                    }
                }
                DiscoverAttachPlan::Spawn => {
                    // The busy retry deliberately dropped its prior permit.
                    // Reclaim authority at this new creation point so a
                    // cancellation during the idle wait cannot spawn an
                    // owner after the request has stopped waiting.
                    spawn_permit = lifecycle_request
                        .map(cockpit_client::LifecycleRequest::authorize_owner_spawn)
                        .transpose()
                        .map_err(anyhow::Error::msg)?;
                    return spawn_verified_persistent_replacement(&mut spawn_permit, None).await;
                }
                DiscoverAttachPlan::FailIncompatible | DiscoverAttachPlan::FailUnreachable => {
                    anyhow::bail!(
                        "shared daemon became unreachable while waiting to promote Assistant work"
                    );
                }
            }
            continue;
        }

        replacement_required = true;
        replacement_deadline = Some(std::time::Instant::now() + recovery.replacement_timeout);

        if !crate::daemon::wait_for_restart_release(
            &current_paths,
            old_pid,
            recovery.predecessor_release_timeout,
        )
        .await
        {
            // This is an observation deadline, not the transaction deadline:
            // the predecessor may release after it. The accepted restart
            // still owns a replacement obligation, so retain the permit and
            // continue discovery until a persistent owner is verified.
            tracing::warn!(
                "accepted assistant promotion exceeded the predecessor release wait; continuing replacement acquisition"
            );
        }

        loop {
            ensure_promotion_replacement_deadline(replacement_deadline)?;

            // `RestartIfIdle` already accepted the destructive handoff. Do
            // not observe cancellation here: dropping the unused permit would
            // otherwise leave the released predecessor without an authorized
            // replacement. The lifecycle requester waits for this permit's
            // terminal state before it reports its own cancellation.
            let discovered = crate::daemon::discover().await;
            match discover_attach_plan(discovered.status, discovered.hello.is_some()) {
                DiscoverAttachPlan::AttachRunning if !discovered.paths.ephemeral => {
                    if let Some(connected) =
                        try_attach_verified_persistent_replacement(discovered.paths).await
                    {
                        return Ok(connected);
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                DiscoverAttachPlan::AttachRunning => {
                    // A competing ephemeral owner won the release race. Keep
                    // the already-authorized permit and promote that owner;
                    // never claim success merely because *some* replacement
                    // answered the socket.
                    current_paths = discovered.paths;
                    break;
                }
                DiscoverAttachPlan::WaitForRestart => {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                DiscoverAttachPlan::Spawn => {
                    return spawn_verified_persistent_replacement(
                        &mut spawn_permit,
                        replacement_deadline,
                    )
                    .await;
                }
                DiscoverAttachPlan::FailUnreachable => {
                    // The predecessor may still own its receipt while the
                    // socket has already disappeared. This accepted handoff
                    // must wait through that observation instead of dropping
                    // its retained replacement authority.
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                DiscoverAttachPlan::FailIncompatible => {
                    // A competing owner may have appeared between release and
                    // discovery. Its incompatible hello cannot be used as a
                    // promotion target, but the accepted handoff still owns
                    // the replacement obligation. Keep the permit through
                    // the bounded recovery window instead of dropping it at
                    // the first incompatible observation.
                    tracing::warn!(
                        "accepted assistant promotion observed an incompatible replacement; waiting for a persistent owner"
                    );
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }
}

/// Spawn the replacement covered by the promotion permit, then verify that
/// discovery identifies the owner as persistent before reporting success.
async fn spawn_verified_persistent_replacement(
    spawn_permit: &mut Option<cockpit_client::LifecycleSpawnPermit>,
    replacement_deadline: Option<std::time::Instant>,
) -> Result<ConnectedDaemon> {
    let canonical = crate::daemon::DaemonPaths::resolve_canonical()?;
    // Test-only persistent owners are in-process and therefore have no OS
    // receipt to rediscover. Production replacement spawning always takes
    // the detached-child path below and is receipt-verified before attach.
    #[cfg(any(test, feature = "test-support"))]
    if crate::daemon::in_process_auto_promote_enabled() {
        let pid = crate::daemon::auto_promote_in_process_persistent().await?;
        if let Some(permit) = spawn_permit.as_mut() {
            permit.owner_created();
        }
        tracing::info!(pid, "in-process persistent Assistant replacement promoted");
        let client = connect_local_daemon(&canonical.socket)
            .await
            .context("in-process persistent Assistant replacement did not publish a daemon")?;
        return Ok(ConnectedDaemon {
            endpoint: local_daemon_endpoint(&canonical.socket),
            client,
            owns_daemon: false,
            ephemeral_owner: false,
            socket: canonical.socket,
            startup_notice: None,
            promoted_from_ephemeral: true,
        });
    }
    let pid = loop {
        match crate::daemon::spawn_detached(false) {
            Ok(pid) => break pid,
            Err(error) if replacement_deadline.is_some() => {
                // The predecessor can release its metadata before its SQLite
                // boot lock. Retry only inside the accepted handoff's bounded
                // recovery window; its terminal error must release the
                // serial lifecycle host for later requests.
                ensure_promotion_replacement_deadline(replacement_deadline)
                    .context("spawning persistent Assistant replacement")?;
                tracing::warn!(
                    error = %error,
                    "accepted assistant promotion replacement spawn is not ready; retrying within recovery window"
                );
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(error) => return Err(error),
        }
    };
    if let Some(permit) = spawn_permit.as_mut() {
        permit.owner_created();
    }
    tracing::info!(
        pid,
        ephemeral = false,
        "assistant daemon promotion spawned replacement"
    );
    wait_for_verified_persistent_replacement(&canonical.socket, replacement_deadline).await
}

/// Wait for a persistent published owner and return a client that was checked
/// against that same owner identity. A socket handshake alone is insufficient:
/// a predecessor can still answer it while its PID receipt and endpoint are
/// being replaced.
async fn wait_for_verified_persistent_replacement(
    expected_socket: &Path,
    replacement_deadline: Option<std::time::Instant>,
) -> Result<ConnectedDaemon> {
    let deadline =
        replacement_deadline.unwrap_or_else(|| std::time::Instant::now() + SPAWN_DAEMON_TIMEOUT);
    let mut backoff = Duration::from_millis(2);

    loop {
        let discovered = crate::daemon::discover().await;
        if discovered.status == crate::daemon::DaemonStatus::Running
            && !discovered.paths.ephemeral
            && discovered.paths.socket == expected_socket
        {
            if let Some(connected) =
                try_attach_verified_persistent_replacement(discovered.paths).await
            {
                return Ok(connected);
            }
        }

        if std::time::Instant::now() >= deadline {
            anyhow::bail!(
                "timed out waiting for a verified persistent daemon replacement at {}",
                expected_socket.display()
            );
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(Duration::from_millis(50));
    }
}

/// Post-acceptance promotion is a bounded transaction. Before acceptance the
/// requester remains cancellable; afterward this deadline is the observable
/// terminal policy for a successor that cannot become a persistent owner.
fn ensure_promotion_replacement_deadline(deadline: Option<std::time::Instant>) -> Result<()> {
    if deadline.is_some_and(|deadline| std::time::Instant::now() >= deadline) {
        anyhow::bail!(
            "timed out acquiring a persistent Assistant daemon replacement after accepted restart"
        );
    }
    Ok(())
}

/// Connect only when the persistent endpoint and PID receipt still name the
/// same owner generation after the handshake.
async fn try_attach_verified_persistent_replacement(
    paths: crate::daemon::DaemonPaths,
) -> Option<ConnectedDaemon> {
    let identity = persistent_owner_identity(&paths)?;
    let client = connect_local_daemon(&paths.socket).await.ok()?;
    if client.request_ok(Request::DaemonStatus).await.is_err() {
        return None;
    }
    let verified = crate::daemon::discover().await;
    if verified.status != crate::daemon::DaemonStatus::Running
        || verified.paths.ephemeral
        || persistent_owner_identity(&verified.paths) != Some(identity)
    {
        return None;
    }
    Some(ConnectedDaemon {
        endpoint: local_daemon_endpoint(&verified.paths.socket),
        client,
        owns_daemon: false,
        ephemeral_owner: false,
        socket: verified.paths.socket,
        startup_notice: None,
        promoted_from_ephemeral: true,
    })
}

/// The PID receipt and endpoint are published together under the lifecycle
/// lock. Comparing both before and after connecting binds the returned client
/// to one persistent owner generation rather than merely a reusable socket.
fn persistent_owner_identity(
    paths: &crate::daemon::DaemonPaths,
) -> Option<(PathBuf, cockpit_host::daemon_lifecycle::DaemonPidReceipt)> {
    // A numeric legacy PID is not an owner generation. Require the current
    // PID receipt and the shared endpoint record that binds that receipt to
    // this persistent socket before and after the connection handshake.
    if paths.ephemeral {
        return None;
    }
    let canonical = crate::daemon::DaemonPaths::resolve_canonical().ok()?;
    let endpoint = crate::daemon::read_endpoint_record(&canonical)?;
    if endpoint.kind != crate::daemon::DaemonEndpointKind::Persistent
        || endpoint.socket != paths.socket
    {
        return None;
    }
    let cockpit_host::daemon_lifecycle::DaemonPidRecord::Receipt(receipt) =
        cockpit_host::daemon_lifecycle::read_daemon_pid_record(&canonical.pid_file)?
    else {
        return None;
    };
    (receipt == endpoint.receipt).then_some((endpoint.socket, receipt))
}

/// Bind an ephemeral endpoint to the PID receipt published for that exact
/// generation. Unlike a numeric PID or canonical socket path, this identity
/// cannot be reused by a successor daemon.
fn ephemeral_owner_identity(
    paths: &crate::daemon::DaemonPaths,
) -> Option<(PathBuf, cockpit_host::daemon_lifecycle::DaemonPidReceipt)> {
    if !paths.ephemeral {
        return None;
    }
    let canonical = crate::daemon::DaemonPaths::resolve_canonical().ok()?;
    let endpoint = crate::daemon::read_endpoint_record(&canonical)?;
    if endpoint.kind != crate::daemon::DaemonEndpointKind::Ephemeral
        || endpoint.socket != paths.socket
    {
        return None;
    }
    let cockpit_host::daemon_lifecycle::DaemonPidRecord::Receipt(receipt) =
        cockpit_host::daemon_lifecycle::read_daemon_pid_record(&canonical.pid_file)?
    else {
        return None;
    };
    (receipt == endpoint.receipt).then_some((endpoint.socket, receipt))
}

/// Resolve a daemon under optional request-scoped spawn authority. The permit
/// runs through the only owner-creation path, after every discovery or restart
/// wait, so cancellation and creation have a single linearization point.
async fn probe_or_spawn_with_spawn_authorization(
    mode: LifecycleMode,
    lifecycle_request: Option<&cockpit_client::LifecycleRequest>,
) -> Result<ConnectedDaemon> {
    use crate::daemon::{DaemonPaths, discover, spawn_detached, spawn_detached_ephemeral};

    match mode {
        LifecycleMode::AttachOrPersistent
        | LifecycleMode::AttachOrEphemeral
        | LifecycleMode::PromoteToPersistent => {
            let discovered = discover().await;
            match discover_attach_plan(discovered.status, discovered.hello.is_some()) {
                DiscoverAttachPlan::AttachRunning => {
                    if matches!(mode, LifecycleMode::PromoteToPersistent)
                        && discovered.paths.ephemeral
                    {
                        return promote_ephemeral_owner(&discovered.paths, lifecycle_request).await;
                    }
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
                            if matches!(mode, LifecycleMode::PromoteToPersistent)
                                && discovered.paths.ephemeral
                            {
                                // A starting ephemeral owner can publish a
                                // handshake before the original discovery
                                // completes. Do not let that restart wait
                                // bypass Assistant promotion.
                                drop(client);
                                return promote_ephemeral_owner(
                                    &discovered.paths,
                                    lifecycle_request,
                                )
                                .await;
                            }
                            return Ok(ConnectedDaemon {
                                endpoint: local_daemon_endpoint(&discovered.paths.socket),
                                client,
                                owns_daemon: false,
                                ephemeral_owner: discovered.paths.ephemeral,
                                socket: discovered.paths.socket,
                                startup_notice,
                                promoted_from_ephemeral: false,
                            });
                        }
                        Err(error) => match after_restart_wait(error) {
                            RestartWaitPlan::WaitForReplacement => {
                                tracing::info!(
                                    "canonical daemon pid released; waiting for the restart replacement"
                                );
                                match wait_for_shared_daemon(&discovered.paths.socket, None).await {
                                    Ok(client) => {
                                        if matches!(mode, LifecycleMode::PromoteToPersistent)
                                            && discovered.paths.ephemeral
                                        {
                                            // As above, the replacement wait
                                            // may observe the original
                                            // ephemeral starter. It is never a
                                            // valid terminal owner for an
                                            // Assistant lifecycle request.
                                            drop(client);
                                            return promote_ephemeral_owner(
                                                &discovered.paths,
                                                lifecycle_request,
                                            )
                                            .await;
                                        }
                                        return Ok(ConnectedDaemon {
                                            endpoint: local_daemon_endpoint(
                                                &discovered.paths.socket,
                                            ),
                                            client,
                                            owns_daemon: false,
                                            ephemeral_owner: discovered.paths.ephemeral,
                                            socket: discovered.paths.socket,
                                            startup_notice,
                                            promoted_from_ephemeral: false,
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

    // No reachable daemon to attach to — claim the request's spawn permit.
    // The permit is retained until the exact creation call returns, making
    // cancellation and owner creation mutually exclusive.
    let mut spawn_permit = lifecycle_request
        .map(cockpit_client::LifecycleRequest::authorize_owner_spawn)
        .transpose()
        .map_err(anyhow::Error::msg)?;

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
            if let Some(permit) = spawn_permit.as_mut() {
                permit.owner_created();
            }
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
                ephemeral_owner: false,
                socket: canonical.socket,
                startup_notice: None,
                promoted_from_ephemeral: false,
            });
        }
        let pid = spawn_detached(false)?;
        (canonical, pid, None)
    };
    if let Some(permit) = spawn_permit.as_mut() {
        permit.owner_created();
    }
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
        ephemeral_owner: ephemeral,
        socket: paths.socket,
        startup_notice: None,
        promoted_from_ephemeral: false,
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
        ephemeral_owner: paths.ephemeral,
        socket: paths.socket,
        startup_notice,
        promoted_from_ephemeral: false,
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
                ephemeral_owner: paths.ephemeral,
                socket: paths.socket,
                startup_notice: Some(match reason {
                    Some(reason) => format!("daemon version skew resolved: {reason}"),
                    None => "daemon version skew resolved by restarting the daemon".to_string(),
                }),
                promoted_from_ephemeral: false,
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

#[cfg(all(test, any(unix, windows)))]
mod acp_wire_owner_tests {
    use super::*;
    use cockpit_client::{ClientEndpoint, InProcessConnection, InProcessEndpoint};
    use cockpit_proto::{Body, Envelope, ErrorCode, ErrorPayload, RecvFrame, Response};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    struct WireOwnerFixtureState {
        expect_promotion: bool,
        promotion_observed: AtomicBool,
        restart_if_idle_observed: AtomicBool,
    }

    fn connected_with_endpoint(
        client: cockpit_client::DaemonClient,
        endpoint: ClientEndpoint,
    ) -> ConnectedDaemon {
        ConnectedDaemon {
            client,
            endpoint,
            owns_daemon: false,
            ephemeral_owner: false,
            socket: PathBuf::from("daemon.sock"),
            startup_notice: None,
            promoted_from_ephemeral: false,
        }
    }

    fn canonical_ephemeral_paths() -> crate::daemon::DaemonPaths {
        let mut paths = crate::daemon::DaemonPaths::resolve_canonical()
            .expect("resolve isolated canonical daemon paths");
        paths.ephemeral = true;
        paths
    }

    fn spawn_fixture_owner_child() -> (std::process::Child, PathBuf) {
        #[cfg(unix)]
        {
            let executable = std::fs::canonicalize("/bin/sleep").expect("sleep executable");
            let child = std::process::Command::new(&executable)
                .arg("30")
                .spawn()
                .expect("spawn ephemeral owner fixture child");
            (child, executable)
        }
        #[cfg(windows)]
        {
            let executable = PathBuf::from(
                std::env::var("COMSPEC")
                    .unwrap_or_else(|_| String::from("C:\\Windows\\System32\\cmd.exe")),
            );
            let child = std::process::Command::new(&executable)
                .args(["/C", "ping", "127.0.0.1", "-n", "60"])
                .spawn()
                .expect("spawn ephemeral owner fixture child");
            (child, executable)
        }
    }

    fn publish_test_ephemeral_owner(
        paths: &crate::daemon::DaemonPaths,
        child: &std::process::Child,
        executable: &Path,
    ) {
        cockpit_host::daemon_lifecycle::write_pid_file(&paths.pid_file, child.id(), executable)
            .expect("publish ephemeral owner receipt");
        crate::daemon::write_endpoint_record(paths).expect("publish ephemeral endpoint record");
    }

    async fn bind_test_pipe_listener() -> (tempfile::TempDir, PathBuf, crate::daemon::DaemonListener)
    {
        let dir = tempfile::tempdir().expect("tempdir");
        let socket = dir.path().join("daemon.sock");
        let listener = crate::daemon::bind_private_socket(&socket).expect("bind wire owner");
        (dir, socket, listener)
    }

    #[cfg(unix)]
    async fn accept_test_pipe(listener: &crate::daemon::DaemonListener) -> tokio::net::UnixStream {
        listener.accept().await.expect("accept").0
    }

    #[cfg(windows)]
    async fn accept_test_pipe(
        listener: &mut crate::daemon::DaemonListener,
    ) -> tokio::net::windows::named_pipe::NamedPipeServer {
        listener.accept().await.expect("accept")
    }

    async fn send_test_daemon_hello<S>(daemon: &mut cockpit_proto::ProtoStream<S>)
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
    {
        daemon
            .send(&Envelope::response(
                uuid::Uuid::nil(),
                test_daemon_status_response(),
            ))
            .await
            .expect("hello");
    }

    fn test_daemon_status_response() -> Response {
        Response::DaemonStatus {
            pid: 1,
            uptime_secs: 0,
            active_sessions: 0,
            socket_path: "daemon.sock".into(),
            daemon_version: "0.1.acp".into(),
            protocol_version: proto::PROTOCOL_VERSION,
            paused_sessions: 0,
            database_path: "test.db".into(),
            schema_version: crate::db::EXPECTED_SCHEMA_VERSION,
        }
    }

    async fn confirm_test_client_lifetime<S>(daemon: &mut cockpit_proto::ProtoStream<S>)
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
    {
        let id = match daemon.recv().await.expect("recv").expect("frame") {
            RecvFrame::Envelope(envelope) => match envelope.body {
                Body::Request {
                    id,
                    request: Request::DaemonStatus,
                    ..
                } => id,
                other => panic!("expected lifetime confirmation, got {other:?}"),
            },
            other => panic!("expected envelope, got {other:?}"),
        };
        daemon
            .send(&Envelope::response(id, test_daemon_status_response()))
            .await
            .expect("lifetime confirmation");
    }

    async fn complete_test_wire_connect_handshake<S>(daemon: &mut cockpit_proto::ProtoStream<S>)
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
    {
        confirm_test_client_lifetime(daemon).await;
        let id = match daemon.recv().await.expect("recv").expect("frame") {
            RecvFrame::Envelope(envelope) => match envelope.body {
                Body::Request {
                    id,
                    request: Request::ExchangeLocalPeerCredential,
                    ..
                } => id,
                other => panic!("expected peer credential exchange, got {other:?}"),
            },
            other => panic!("expected peer credential exchange envelope, got {other:?}"),
        };
        daemon
            .send(&Envelope::response(
                id,
                Response::LocalPeerCredential {
                    token: proto::OwnerCapabilityToken::new("test-peer-token"),
                    role: proto::LocalClientRole::Cli,
                },
            ))
            .await
            .expect("peer credential exchange");
    }

    async fn serve_wire_owner_connection<S>(
        daemon: &mut cockpit_proto::ProtoStream<S>,
        state: &WireOwnerFixtureState,
    ) where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
    {
        send_test_daemon_hello(daemon).await;
        loop {
            match tokio::time::timeout(Duration::from_millis(500), daemon.recv()).await {
                Ok(Ok(Some(RecvFrame::Envelope(envelope)))) => match envelope.body {
                    Body::Request { id, request, .. } => {
                        let response = match request {
                            Request::DaemonStatus => test_daemon_status_response(),
                            Request::ExchangeLocalPeerCredential => Response::LocalPeerCredential {
                                token: proto::OwnerCapabilityToken::new("test-peer-token"),
                                role: proto::LocalClientRole::Cli,
                            },
                            Request::RestartIfIdle => {
                                state.restart_if_idle_observed.store(true, Ordering::SeqCst);
                                Response::RestartDecision {
                                    will_restart: false,
                                    reason: Some(
                                        "fixture owner stays live for ACP attach tests".into(),
                                    ),
                                }
                            }
                            Request::PromoteToPersistent => {
                                assert!(
                                    state.expect_promotion,
                                    "unexpected PromoteToPersistent on this connection"
                                );
                                state.promotion_observed.store(true, Ordering::SeqCst);
                                Response::Ack
                            }
                            other => panic!("unexpected wire-owner request: {other:?}"),
                        };
                        daemon
                            .send(&Envelope::response(id, response))
                            .await
                            .expect("wire-owner response");
                    }
                    other => panic!("unexpected wire-owner body: {other:?}"),
                },
                _ => break,
            }
        }
    }

    fn spawn_wire_owner_server(
        listener: crate::daemon::DaemonListener,
        expect_promotion: bool,
    ) -> (tokio::task::JoinHandle<()>, Arc<WireOwnerFixtureState>) {
        let state = Arc::new(WireOwnerFixtureState {
            expect_promotion,
            promotion_observed: AtomicBool::new(false),
            restart_if_idle_observed: AtomicBool::new(false),
        });
        let state_for_task = Arc::clone(&state);
        let server = tokio::spawn(async move {
            let mut listener = listener;
            loop {
                #[cfg(unix)]
                let stream = match listener.accept().await {
                    Ok((stream, _)) => stream,
                    Err(_) => break,
                };
                #[cfg(windows)]
                let stream = match listener.accept().await {
                    Ok(stream) => stream,
                    Err(_) => break,
                };
                let mut daemon = cockpit_proto::ProtoStream::new(stream);
                serve_wire_owner_connection(&mut daemon, &state_for_task).await;
            }
        });
        (server, state)
    }

    #[test]
    fn validate_acp_connected_daemon_rejects_in_process_owner() {
        let (requests, _request_rx) = tokio::sync::mpsc::channel(1);
        let (_events_tx, events) = tokio::sync::mpsc::channel(1);
        let (connections, _connection_rx) = tokio::sync::mpsc::channel(1);
        let (sensitive, _sensitive_rx) = tokio::sync::mpsc::channel(1);
        let endpoint = ClientEndpoint::InProcess(InProcessEndpoint::new(connections, sensitive));
        let connected = connected_with_endpoint(
            cockpit_client::DaemonClient::from_in_process(InProcessConnection { requests, events }),
            endpoint,
        );

        let error = validate_acp_connected_daemon(&connected).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("ACP requires a discoverable wire ledger owner")
        );
    }

    #[test]
    fn validate_acp_connected_daemon_rejects_wire_endpoint_with_in_process_client() {
        let (requests, _request_rx) = tokio::sync::mpsc::channel(1);
        let (_events_tx, events) = tokio::sync::mpsc::channel(1);
        let connected = connected_with_endpoint(
            cockpit_client::DaemonClient::from_in_process(InProcessConnection { requests, events }),
            ClientEndpoint::Wire(PathBuf::from("daemon.sock")),
        );

        let error = validate_acp_connected_daemon(&connected).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("ACP requires a wire-backed ledger client")
        );
    }

    #[tokio::test]
    async fn validate_acp_connected_daemon_accepts_wire_owner_with_capability() {
        let (dir, socket, listener) = bind_test_pipe_listener().await;

        let server = tokio::spawn(async move {
            #[cfg(unix)]
            let stream = accept_test_pipe(&listener).await;
            #[cfg(windows)]
            let stream = {
                let mut listener = listener;
                accept_test_pipe(&mut listener).await
            };
            let mut daemon = cockpit_proto::ProtoStream::new(stream);
            send_test_daemon_hello(&mut daemon).await;
            complete_test_wire_connect_handshake(&mut daemon).await;
        });

        let client = cockpit_client::DaemonClient::connect(&socket)
            .await
            .expect("wire connect");
        let connected = connected_with_endpoint(client, ClientEndpoint::Wire(socket.clone()));

        validate_acp_connected_daemon(&connected).expect("wire owner with capability");
        assert!(connected.client.is_socket_backed());

        drop(connected);
        server.await.expect("server");
        drop(dir);
    }

    #[tokio::test]
    async fn validate_acp_connected_daemon_rejects_wire_owner_without_capability() {
        let (dir, socket, listener) = bind_test_pipe_listener().await;

        let server = tokio::spawn(async move {
            #[cfg(unix)]
            let stream = accept_test_pipe(&listener).await;
            #[cfg(windows)]
            let stream = {
                let mut listener = listener;
                accept_test_pipe(&mut listener).await
            };
            let mut daemon = cockpit_proto::ProtoStream::new(stream);
            send_test_daemon_hello(&mut daemon).await;
            confirm_test_client_lifetime(&mut daemon).await;
            let id = match daemon.recv().await.expect("recv").expect("frame") {
                RecvFrame::Envelope(envelope) => match envelope.body {
                    Body::Request {
                        id,
                        request: Request::ExchangeLocalPeerCredential,
                        ..
                    } => id,
                    other => panic!("expected peer credential exchange, got {other:?}"),
                },
                other => panic!("expected peer credential exchange envelope, got {other:?}"),
            };
            daemon
                .send(&Envelope::error(
                    Some(id),
                    ErrorPayload {
                        code: ErrorCode::Authorization,
                        message: "peer role attestation failed".into(),
                    },
                ))
                .await
                .expect("deny peer credential exchange");
        });

        let error = cockpit_client::DaemonClient::connect(&socket)
            .await
            .expect_err("wire connect without peer credential must fail");
        assert!(
            error.to_string().contains("peer role attestation failed"),
            "{error:#}"
        );

        server.await.expect("server");
        drop(dir);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn acquire_acp_socket_daemon_attaches_to_running_wire_owner() {
        let env = crate::test_env::TestEnvGuard::isolated_cockpit_home_async().await;
        let runtime = env.path().expect("isolated runtime root").join("runtime");
        env.set_var("XDG_RUNTIME_DIR", &runtime);

        let paths = canonical_ephemeral_paths();
        let (mut owner_child, executable) = spawn_fixture_owner_child();
        publish_test_ephemeral_owner(&paths, &owner_child, &executable);
        let listener = crate::daemon::bind_private_socket(&paths.socket).expect("bind owner");
        crate::daemon::skew_restart::reset_skew_restart_cooldown_for_tests();
        let (server, fixture) = spawn_wire_owner_server(listener, false);

        let client = acquire_acp_socket_daemon(false)
            .await
            .expect("ACP must attach to a discoverable wire owner");
        assert!(client.is_socket_backed());
        assert!(client.has_owner_capability());
        assert!(
            fixture.restart_if_idle_observed.load(Ordering::SeqCst),
            "attach must run the production version-skew RestartIfIdle probe before reuse"
        );
        assert!(
            !fixture.promotion_observed.load(Ordering::SeqCst),
            "ACP with background_agents=false must not promote an attached ephemeral owner"
        );
        client
            .request_ok(Request::DaemonStatus)
            .await
            .expect("attached wire owner answers DaemonStatus");

        drop(client);
        server.abort();
        owner_child.kill().ok();
        owner_child.wait().ok();
        let _ = std::fs::remove_file(&paths.socket);
        let _ = std::fs::remove_file(&paths.pid_file);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn acquire_acp_socket_daemon_promotes_ephemeral_when_background_agents_enabled() {
        let env = crate::test_env::TestEnvGuard::isolated_cockpit_home_async().await;
        let runtime = env.path().expect("isolated runtime root").join("runtime");
        env.set_var("XDG_RUNTIME_DIR", &runtime);

        let paths = canonical_ephemeral_paths();
        let (mut owner_child, executable) = spawn_fixture_owner_child();
        publish_test_ephemeral_owner(&paths, &owner_child, &executable);
        let listener = crate::daemon::bind_private_socket(&paths.socket).expect("bind owner");
        crate::daemon::skew_restart::reset_skew_restart_cooldown_for_tests();
        let (server, fixture) = spawn_wire_owner_server(listener, true);

        let client = acquire_acp_socket_daemon(true)
            .await
            .expect("ACP must attach and promote an ephemeral wire owner");
        assert!(client.is_socket_backed());
        assert!(client.has_owner_capability());
        assert!(
            fixture.restart_if_idle_observed.load(Ordering::SeqCst),
            "promotion attach must run the production version-skew RestartIfIdle probe before reuse"
        );
        assert!(
            fixture.promotion_observed.load(Ordering::SeqCst),
            "ACP with background_agents=true must promote an attached ephemeral wire owner in place"
        );
        client
            .request_ok(Request::DaemonStatus)
            .await
            .expect("promoted wire owner answers DaemonStatus");

        drop(client);
        server.abort();
        owner_child.kill().ok();
        owner_child.wait().ok();
        let _ = std::fs::remove_file(&paths.socket);
        let _ = std::fs::remove_file(&paths.pid_file);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn acquire_acp_socket_daemon_spawns_ephemeral_wire_owner_when_absent() {
        let env = crate::test_env::TestEnvGuard::isolated_cockpit_home_async().await;
        let runtime = env.path().expect("isolated runtime root").join("runtime");
        env.set_var("XDG_RUNTIME_DIR", &runtime);

        let paths = crate::daemon::DaemonPaths::resolve_canonical().expect("canonical paths");
        assert!(
            !paths.socket.exists() && !paths.pid_file.exists(),
            "isolated home must not already host a daemon"
        );

        let client = acquire_acp_socket_daemon(false)
            .await
            .expect("ACP must spawn a discoverable ephemeral wire owner when none is running");
        assert!(client.is_socket_backed());
        assert!(client.has_owner_capability());
        client
            .request_ok(Request::DaemonStatus)
            .await
            .expect("spawned wire owner answers DaemonStatus");

        drop(client);
        tokio::time::timeout(Duration::from_secs(5), async {
            while paths.socket.exists() || paths.pid_file.exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("spawned ephemeral wire owner must reap after the last ACP client disconnects");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn acquire_acp_socket_daemon_spawns_persistent_wire_owner_when_background_agents_enabled()
    {
        let env = crate::test_env::TestEnvGuard::isolated_cockpit_home_async().await;
        let runtime = env.path().expect("isolated runtime root").join("runtime");
        env.set_var("XDG_RUNTIME_DIR", &runtime);

        let paths = crate::daemon::DaemonPaths::resolve_canonical().expect("canonical paths");
        assert!(
            !paths.socket.exists() && !paths.pid_file.exists(),
            "isolated home must not already host a daemon"
        );

        let client = acquire_acp_socket_daemon(true)
            .await
            .expect("ACP must spawn a discoverable persistent wire owner when none is running");
        assert!(client.is_socket_backed());
        assert!(client.has_owner_capability());
        client
            .request_ok(Request::DaemonStatus)
            .await
            .expect("spawned persistent wire owner answers DaemonStatus");

        drop(client);
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            paths.socket.exists(),
            "background_agents=true spawn must keep the wire owner after ACP disconnect"
        );
        assert!(
            paths.pid_file.exists(),
            "background_agents=true spawn must keep the pid receipt after ACP disconnect"
        );

        crate::daemon::stop(&paths).expect("stop spawned persistent wire owner");
        tokio::time::timeout(Duration::from_secs(5), async {
            while paths.socket.exists() || paths.pid_file.exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("stopped persistent wire owner must retire its metadata");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn acquire_acp_socket_daemon_rejects_in_process_auto_promote_owner() {
        let env = crate::test_env::TestEnvGuard::isolated_cockpit_home_async().await;
        let runtime = env.path().expect("isolated runtime root").join("runtime");
        env.set_var("XDG_RUNTIME_DIR", &runtime);
        let _promote = crate::daemon::enable_in_process_auto_promote();

        let session = ensure_persistent_daemon()
            .await
            .expect("in-process auto-promote must hello");
        let error = acquire_acp_socket_daemon(false)
            .await
            .expect_err("ACP must reject the in-process optimization");
        assert!(
            error
                .to_string()
                .contains("ACP requires a wire-backed ledger client")
                || error
                    .to_string()
                    .contains("ACP requires a discoverable wire ledger owner")
        );
        drop(session);
    }
}

#[cfg(all(test, unix))]
#[path = "client_tests.rs"]
mod tests;
