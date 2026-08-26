//! Daemon discovery and lifecycle composition.
//!
//! Local wire framing and typed request/event transport live in
//! `cockpit-client`; this module owns only process and daemon lifecycle.

use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use anyhow::{Result, anyhow};
use cockpit_client::DaemonClient;

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

// ---- lifecycle helpers ----------------------------------------------------

/// Strategy for getting a daemon to talk to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleMode {
    /// "Attach if running, otherwise auto-promote a long-running
    /// background daemon." The TUI's default.
    AttachOrAutoPromote,
    /// "Attach if running, otherwise spawn a temporary daemon I'll
    /// stop on exit." Default for `cockpit run`. The flag name on
    /// the CLI is `--ephemeral`.
    AttachOrEphemeral,
    /// "Always spawn a fresh ephemeral daemon, even if one is
    /// running." Used by `cockpit run --ephemeral`.
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
pub struct ConnectedDaemon {
    pub client: DaemonClient,
    pub endpoint: cockpit_client::ClientEndpoint,
    pub owns_daemon: bool,
    pub socket: PathBuf,
    pub startup_notice: Option<String>,
    /// Provisional ownership begins in `probe_or_spawn` immediately after an
    /// ephemeral child is created. Callers must explicitly take this guard
    /// when publishing a longer-lived owner; every abandoned/error path drops
    /// it and reaps the child.
    owned_daemon_guard: Option<crate::daemon::ephemeral_guard::EphemeralDaemonGuard>,
}

impl ConnectedDaemon {
    pub fn take_owned_daemon_guard(
        &mut self,
    ) -> Option<crate::daemon::ephemeral_guard::EphemeralDaemonGuard> {
        self.owned_daemon_guard.take()
    }
}

/// Attach to the canonical persistent daemon, spawning one if needed.
///
/// Product CLI commands that need installation state must go through this
/// helper. Spawn failure is fail-closed: callers must not open SQLite.
pub async fn ensure_persistent_daemon() -> Result<ConnectedDaemon> {
    let connected = probe_or_spawn(LifecycleMode::AttachOrAutoPromote).await?;
    if connected.owns_daemon {
        anyhow::bail!(
            "persistent daemon attach produced an ephemeral instance; refusing secret or workspace writes"
        );
    }
    Ok(connected)
}

/// Run the lifecycle half of the two-phase TUI composition. The CLI owns this
/// task; the TUI can request typed lifecycle policy but cannot probe, spawn,
/// restart, or retain daemon process guards itself.
pub async fn serve_lifecycle_requests(
    mut requests: tokio::sync::mpsc::Receiver<cockpit_client::LifecycleRequest>,
) {
    let mut owned_daemons = Vec::new();
    while let Some(request) = requests.recv().await {
        // A queued request may be cancelled before the lifecycle actor sees
        // it. Never spawn a daemon for a receiver that is already gone.
        if request.reply.is_closed() {
            continue;
        }
        let mode = match request.intent {
            cockpit_client::LifecycleIntent::AttachOrAutoPromote
            | cockpit_client::LifecycleIntent::EnsurePersistent => {
                LifecycleMode::AttachOrAutoPromote
            }
            cockpit_client::LifecycleIntent::AttachOrEphemeral => LifecycleMode::AttachOrEphemeral,
            cockpit_client::LifecycleIntent::AlwaysEphemeral => LifecycleMode::AlwaysEphemeral,
            cockpit_client::LifecycleIntent::AttachOwnEphemeral => {
                LifecycleMode::AttachOwnEphemeral
            }
        };
        let resolved = probe_or_spawn(mode).await.and_then(|mut connected| {
            if matches!(
                request.intent,
                cockpit_client::LifecycleIntent::EnsurePersistent
            ) && connected.owns_daemon
            {
                anyhow::bail!("persistent lifecycle request resolved to an ephemeral daemon");
            }
            let guard = connected.take_owned_daemon_guard();
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
}

/// Test-support composition owned below frontends. TUI tests receive only the
/// client capability and never construct or drive core lifecycle requests.
#[cfg(feature = "test-support")]
pub fn test_lifecycle_client() -> cockpit_client::LifecycleClient {
    let (client, requests) = cockpit_client::LifecycleClient::channel(8);
    tokio::spawn(serve_lifecycle_requests(requests));
    client
}

/// Find the daemon socket, optionally spawn the daemon, return a
/// connected client. Honors [`LifecycleMode`].
pub async fn probe_or_spawn(mode: LifecycleMode) -> Result<ConnectedDaemon> {
    use crate::daemon::{
        DaemonPaths, DaemonStatus, discover, spawn_detached, spawn_detached_ephemeral,
    };

    match mode {
        LifecycleMode::AttachOrAutoPromote | LifecycleMode::AttachOrEphemeral => {
            let discovered = discover().await;
            if matches!(discovered.status, DaemonStatus::Running) {
                if matches!(mode, LifecycleMode::AttachOrAutoPromote) {
                    match crate::daemon::skew_restart::restart_skewed_daemon_if_idle(
                        &discovered.paths,
                    )
                    .await
                    {
                        Ok(crate::daemon::skew_restart::SkewRestartOutcome::Restarted {
                            pid,
                            reason,
                        }) => {
                            tracing::info!(pid, "daemon version skew auto-restart completed");
                            let client = wait_for_daemon(&discovered.paths.socket).await?;
                            return Ok(ConnectedDaemon {
                                endpoint: cockpit_client::ClientEndpoint::Wire(
                                    discovered.paths.socket.clone(),
                                ),
                                client,
                                owns_daemon: false,
                                socket: discovered.paths.socket,
                                startup_notice: Some(match reason {
                                    Some(reason) => {
                                        format!("daemon version skew resolved: {reason}")
                                    }
                                    None => "daemon version skew resolved by restarting the daemon"
                                        .to_string(),
                                }),
                                owned_daemon_guard: None,
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
                            let startup_notice = format_skew_restart_notice(
                                skew_reason.as_deref(),
                                reason.as_deref(),
                            );
                            let client = DaemonClient::connect(&discovered.paths.socket).await?;
                            return Ok(ConnectedDaemon {
                                endpoint: cockpit_client::ClientEndpoint::Wire(
                                    discovered.paths.socket.clone(),
                                ),
                                client,
                                owns_daemon: false,
                                socket: discovered.paths.socket,
                                startup_notice,
                                owned_daemon_guard: None,
                            });
                        }
                        Ok(crate::daemon::skew_restart::SkewRestartOutcome::NoticeOnly {
                            reason,
                        }) => {
                            tracing::info!("daemon version skew surfaced without auto-restart");
                            let client = DaemonClient::connect(&discovered.paths.socket).await?;
                            return Ok(ConnectedDaemon {
                                endpoint: cockpit_client::ClientEndpoint::Wire(
                                    discovered.paths.socket.clone(),
                                ),
                                client,
                                owns_daemon: false,
                                socket: discovered.paths.socket,
                                startup_notice: reason
                                    .map(|reason| format!("daemon version skew: {reason}")),
                                owned_daemon_guard: None,
                            });
                        }
                        Ok(
                            crate::daemon::skew_restart::SkewRestartOutcome::NoSkew
                            | crate::daemon::skew_restart::SkewRestartOutcome::InProcess,
                        ) => {}
                        Err(error) => {
                            tracing::debug!(error = %error, "daemon version skew auto-restart check failed");
                        }
                    }
                }
                let client = DaemonClient::connect(&discovered.paths.socket).await?;
                return Ok(ConnectedDaemon {
                    endpoint: cockpit_client::ClientEndpoint::Wire(discovered.paths.socket.clone()),
                    client,
                    owns_daemon: false,
                    socket: discovered.paths.socket,
                    startup_notice: None,
                    owned_daemon_guard: None,
                });
            }
            if matches!(
                discovered.status,
                DaemonStatus::IncompatibleProtocol
                    | DaemonStatus::LivePidSocketUnreachable
                    | DaemonStatus::UnverifiedPid
            ) {
                if let Some(hello) = discovered.hello.as_ref() {
                    anyhow::bail!(
                        "{}",
                        proto::incompatible_daemon_protocol_message(hello.protocol_version)
                    );
                } else {
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
            // key, but `DaemonClient::connect` resolves it to the registered
            // in-process context instead of opening a Unix socket.
            let own = own_ephemeral_paths()?;
            let ctx = crate::daemon::boot_in_process(
                own.clone(),
                crate::daemon::terminal::default_host_factory(),
            )
            .await?;
            let endpoint = cockpit_client::ClientEndpoint::InProcess(
                crate::daemon::server::in_process_endpoint(&ctx),
            );
            return Ok(ConnectedDaemon {
                client: DaemonClient::connect_endpoint(&endpoint).await?,
                endpoint,
                owns_daemon: false,
                socket: own.socket,
                startup_notice: None,
                owned_daemon_guard: None,
            });
        }
        LifecycleMode::AlwaysEphemeral => {
            // Always spawn fresh on a unique pid+nonce ephemeral path
            // (Layer B). It never touches the canonical socket, so it
            // coexists with a persistent daemon — no "already running"
            // bail needed.
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
        let pid = spawn_detached_ephemeral(&paths)?;
        // Arm ownership before any await or other cancellation point. From
        // here onward every early return owns a guard whose Drop stops exactly
        // this pid+nonce daemon.
        let guard = crate::daemon::ephemeral_guard::EphemeralDaemonGuard::new(paths.socket.clone());
        (paths, pid, Some(guard))
    } else {
        // Auto-promoted persistent daemon: never `--no-sandbox` from a
        // client flag (that's a per-session default passed at attach;
        // sandboxing part 2 precedence). Only an explicit
        // `cockpit daemon start --no-sandbox` sets the daemon-level flag.
        let canonical = DaemonPaths::resolve_canonical()?;
        #[cfg(any(test, feature = "test-support"))]
        let pid = if crate::daemon::in_process_auto_promote_enabled() {
            crate::daemon::auto_promote_in_process_persistent().await?
        } else {
            spawn_detached(false)?
        };
        #[cfg(not(any(test, feature = "test-support")))]
        let pid = spawn_detached(false)?;
        (canonical, pid, None)
    };
    tracing::info!(pid = pid, ephemeral = ephemeral, "daemon spawned");

    // Wait for the socket + a successful handshake.
    let client = wait_for_daemon(&paths.socket).await?;

    Ok(ConnectedDaemon {
        endpoint: cockpit_client::ClientEndpoint::Wire(paths.socket.clone()),
        client,
        owns_daemon: ephemeral,
        socket: paths.socket,
        startup_notice: None,
        owned_daemon_guard,
    })
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

/// Poll for the daemon socket and an actual DaemonStatus response.
/// 2ms initial backoff, doubling up to a 50ms ceiling; total cap 30s.
async fn wait_for_daemon(socket: &Path) -> Result<DaemonClient> {
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
            // started yet — fall through to the backoff retry.
            if let Ok(client) = DaemonClient::connect(socket).await {
                // Sanity check — first request after connect.
                if client.request_ok(Request::DaemonStatus).await.is_ok() {
                    timer.phase("spawn_to_ready");
                    timer.done();
                    return Ok(client);
                }
            }
        }
        if std::time::Instant::now() >= deadline {
            anyhow::bail!("timed out waiting for daemon at {}", socket.display());
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(Duration::from_millis(50));
    }
}

#[cfg(test)]
#[cfg(unix)]
mod tests {
    use super::*;
    use crate::daemon::DaemonPaths;
    use crate::daemon::proto::Response;

    #[test]
    fn ephemeral_spawn_arms_raii_before_the_first_wait() {
        let source = include_str!("client.rs");
        let spawn = source
            .find("let pid = spawn_detached_ephemeral(&paths)?;")
            .expect("ephemeral spawn funnel");
        let arm = source[spawn..]
            .find("EphemeralDaemonGuard::new")
            .map(|offset| spawn + offset)
            .expect("provisional owner armed after spawn");
        let wait = source[spawn..]
            .find("wait_for_daemon(&paths.socket).await")
            .map(|offset| spawn + offset)
            .expect("daemon readiness wait");
        assert!(
            spawn < arm && arm < wait,
            "no cancellation window before RAII"
        );
    }

    fn temp_ephemeral_paths(root: &std::path::Path, stem: &str) -> DaemonPaths {
        DaemonPaths {
            socket: root.join(format!("{stem}.sock")),
            pid_file: root.join(format!("{stem}.pid")),
            ephemeral: true,
        }
    }

    /// Daemonless = own ephemeral daemon (`daemonless-tui-ephemeral-lifecycle.md`
    /// §1). `LifecycleMode::AttachOwnEphemeral` attaches to this process's
    /// cached ephemeral daemon when it's already up and reports
    /// `owns_daemon = true` at that exact socket — i.e. a re-attach in the
    /// same daemonless TUI (`/compact`, `/sessions` resume, `/new`)
    /// reconnects to the owned daemon instead of spawning a second one. The
    /// daemon is run in-process at the cached path with isolated XDG dirs, so
    /// the spawn branch (which would launch a child) is never taken.
    #[tokio::test]
    async fn connect_uses_registered_in_process_context_without_socket() {
        let _guard = crate::test_env::lock_async().await;
        reset_own_ephemeral_paths_for_test();
        let root = tempfile::tempdir().expect("daemon path tempdir");

        let paths = temp_ephemeral_paths(root.path(), "cockpit-in-process-test");
        assert!(
            !paths.socket.exists(),
            "in-process transport must not require a socket file"
        );
        let db = crate::db::Db::open_in_memory().expect("in-memory daemon db");
        let ctx = crate::daemon::boot_in_process_with_db(paths.clone(), db)
            .await
            .expect("boot local daemon context");
        let client = DaemonClient::connect(&paths.socket)
            .await
            .expect("connect by local socket key");
        let response = client
            .request_ok(Request::DaemonStatus)
            .await
            .expect("local daemon status");
        match response {
            Response::DaemonStatus { socket_path, .. } => {
                assert_eq!(socket_path, paths.socket.display().to_string());
            }
            other => panic!("unexpected response: {other:?}"),
        }
        assert!(
            !paths.socket.exists(),
            "in-process transport must not create a socket file"
        );
        drop(client);
        drop(ctx);
        reset_own_ephemeral_paths_for_test();
    }

    #[tokio::test]
    async fn attach_own_ephemeral_uses_in_process_context() {
        let _guard = crate::test_env::lock_async().await;
        reset_own_ephemeral_paths_for_test();
        let root = tempfile::tempdir().expect("daemon path tempdir");

        let own = temp_ephemeral_paths(root.path(), "cockpit-eph-test-owned");
        set_own_ephemeral_paths_for_test(own.clone());
        let db = crate::db::Db::open_in_memory().expect("in-memory daemon db");
        let _ctx = crate::daemon::boot_in_process_with_db(own.clone(), db)
            .await
            .expect("boot local daemon context");

        let connected = probe_or_spawn(LifecycleMode::AttachOwnEphemeral)
            .await
            .expect("attach to own in-process daemon");
        assert!(
            !connected.owns_daemon,
            "in-process daemonless mode needs no child-process guard"
        );
        assert_eq!(
            connected.socket, own.socket,
            "must reuse the process-local owned path as the local transport key"
        );
        assert!(
            !connected.socket.exists(),
            "in-process daemonless mode must not bind a Unix socket"
        );
        connected
            .client
            .request_ok(Request::DaemonStatus)
            .await
            .expect("owned in-process daemon answers");

        reset_own_ephemeral_paths_for_test();
    }

    #[test]
    fn attach_own_ephemeral_reuses_cached_path() {
        let _guard = crate::test_env::lock();
        let root = tempfile::tempdir().expect("daemon path tempdir");
        let own = temp_ephemeral_paths(root.path(), "cockpit-eph-test-cache");
        reset_own_ephemeral_paths_for_test();
        set_own_ephemeral_paths_for_test(own.clone());

        let first = own_ephemeral_paths().expect("first owned path");
        let second = own_ephemeral_paths().expect("second owned path");

        assert_eq!(first.socket, own.socket);
        assert_eq!(first.socket, second.socket);
        assert_eq!(first.pid_file, own.pid_file);
        assert_eq!(first.pid_file, second.pid_file);
        reset_own_ephemeral_paths_for_test();
    }

    #[test]
    fn always_ephemeral_allocates_fresh_paths() {
        let root = tempfile::tempdir().expect("daemon path tempdir");
        let first = temp_ephemeral_paths(root.path(), "cockpit-eph-test-always-one");
        let second = temp_ephemeral_paths(root.path(), "cockpit-eph-test-always-two");

        assert_ne!(first.socket, second.socket);
        assert_ne!(first.pid_file, second.pid_file);
    }

    #[tokio::test]
    async fn lifecycle_guard_is_retained_only_after_endpoint_acceptance() {
        struct DropSpy(std::sync::Arc<std::sync::atomic::AtomicUsize>);
        impl Drop for DropSpy {
            fn drop(&mut self) {
                self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
        }

        let drops = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut retained = Vec::new();
        let (accepted, acceptance) = tokio::sync::oneshot::channel();
        accepted.send(()).unwrap();
        retain_guard_after_acceptance(
            Some(DropSpy(std::sync::Arc::clone(&drops))),
            acceptance,
            &mut retained,
        )
        .await;
        assert_eq!(retained.len(), 1);
        assert_eq!(drops.load(std::sync::atomic::Ordering::SeqCst), 0);
        drop(retained);
        assert_eq!(drops.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn cancelled_lifecycle_acceptance_reaps_unclaimed_guard() {
        struct DropSpy(std::sync::Arc<std::sync::atomic::AtomicUsize>);
        impl Drop for DropSpy {
            fn drop(&mut self) {
                self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
        }

        let drops = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut retained = Vec::new();
        let (accepted, acceptance) = tokio::sync::oneshot::channel::<()>();
        drop(accepted);
        retain_guard_after_acceptance(
            Some(DropSpy(std::sync::Arc::clone(&drops))),
            acceptance,
            &mut retained,
        )
        .await;
        assert!(retained.is_empty());
        assert_eq!(drops.load(std::sync::atomic::Ordering::SeqCst), 1);
    }
}
