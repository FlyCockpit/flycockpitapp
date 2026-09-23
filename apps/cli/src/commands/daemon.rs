//! `cockpit daemon` subcommands.

use anyhow::{Context, Result, bail};
use std::path::Path;
use std::time::Duration;

use crate::cli::DaemonCommand;
use crate::daemon::proto::{self, Request, Response};
use crate::daemon::{self, DaemonPaths, DaemonStatus};
use cockpit_client::{DaemonClient, is_protocol_version_mismatch};

const MAX_STOP_GRACE_SECS: u64 = 24 * 60 * 60;
/// Bound on one short supervisor admin round trip (`Stop`, `Status`). A live
/// supervisor answers these immediately; a wedged admin endpoint must not
/// hang the command or consume the lifecycle budget the stop still needs.
const ADMIN_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const PROTOCOL_MISMATCH_STATUS_REMEDY: &str =
    "run `cockpit daemon restart` to restart the daemon on this version";

pub async fn run(cmd: DaemonCommand) -> Result<()> {
    let lifecycle_deadline = matches!(
        &cmd,
        DaemonCommand::Stop { .. } | DaemonCommand::Restart { .. }
    )
    .then(|| tokio::time::Instant::now() + daemon::restart_release_timeout(None));
    let paths = DaemonPaths::resolve()?;
    match cmd {
        DaemonCommand::Supervise {
            no_sandbox,
            resume_all_sessions,
            reexec_child: _,
        } => daemon::supervisor::run(paths, no_sandbox, resume_all_sessions).await,
        DaemonCommand::Worker {
            no_sandbox,
            resume_all_sessions,
        } => {
            if !daemon::supervisor::is_worker_process() {
                bail!("`cockpit daemon worker` may only be launched by the supervisor");
            }
            if no_sandbox {
                // SAFETY: set before the worker boots any session tasks.
                unsafe {
                    std::env::set_var(crate::daemon::session_worker::DAEMON_NO_SANDBOX_ENV, "1");
                }
            }
            let terminal_factory = crate::terminal_host::factory();
            if resume_all_sessions {
                daemon::run_foreground_with_resume(paths, true, terminal_factory).await
            } else {
                daemon::run_foreground(paths, terminal_factory).await
            }
        }
        DaemonCommand::Start {
            foreground,
            detach,
            no_sandbox,
            resume_all_sessions,
        } => {
            if detach && !foreground {
                let pid = daemon::spawn_detached_with_resume_async(no_sandbox, resume_all_sessions)
                    .await?;
                println!(
                    "daemon: spawned (pid {pid})\n  socket: {}",
                    paths.socket.display()
                );
                return Ok(());
            }
            println!(
                "daemon: starting supervisor in foreground (pid {})\n  socket: {}\n  pid file: {}",
                std::process::id(),
                paths.socket.display(),
                paths.pid_file.display()
            );
            daemon::supervisor::run(paths, no_sandbox, resume_all_sessions).await
        }
        DaemonCommand::Stop { grace } => {
            validate_grace(grace)?;
            let deadline = lifecycle_deadline.expect("stop command deadline");
            let old_pid = daemon::daemon_pid(&paths);
            // An unrecognized PID file (e.g. an older build's) yields no PID;
            // the release witness then observes metadata disappearance.
            let unrecognized_pid_file = old_pid.is_none() && paths.pid_file.exists();
            let mut release = daemon::capture_restart_release(&paths, old_pid);
            if let Ok(response) = daemon::supervisor::request_with_timeout(
                &paths,
                daemon::supervisor::AdminCommand::Stop,
                remaining_command_budget(deadline).min(ADMIN_REQUEST_TIMEOUT),
            )
            .await
                && matches!(response, daemon::supervisor::AdminResponse::Stopping { .. })
            {
                if daemon::wait_for_restart_release(
                    &paths,
                    release,
                    remaining_command_budget(deadline),
                )
                .await
                {
                    println!("daemon: stopped");
                    return Ok(());
                }
                if unrecognized_pid_file && daemon::daemon_pid(&paths).is_none() {
                    return Err(daemon::unrecognized_pid_metadata_error(&paths).context(
                        "timed out waiting for the supervisor to stop and release metadata",
                    ));
                }
                bail!("timed out waiting for the supervisor and worker to drain and exit");
            }
            let mut stop_acknowledged = false;
            if let Ok(Ok(client)) = tokio::time::timeout(
                remaining_command_budget(deadline),
                DaemonClient::connect(&paths.socket),
            )
            .await
            {
                let stop_response = tokio::time::timeout(
                    remaining_command_budget(deadline),
                    client.request(Request::StopDaemon { grace_secs: grace }),
                )
                .await;
                match stop_response {
                    Ok(Ok(Ok(_))) => stop_acknowledged = true,
                    Ok(Ok(Err(error))) if error.code == proto::ErrorCode::BootstrapLocked => {
                        // Locked and older locked-bootstrap daemons reject the
                        // connected stop; the receipt-bound platform signal
                        // below still stops them.
                    }
                    Ok(Ok(Err(error))) => bail!("daemon error: {error}"),
                    // A delivery timeout or transport failure leaves the stop
                    // unconfirmed: fall through to the platform signal instead
                    // of failing the stop.
                    Ok(Err(_)) | Err(_) => {}
                }
                drop(client);
            }
            if stop_acknowledged {
                if daemon::wait_for_restart_release(
                    &paths,
                    release,
                    remaining_command_budget(deadline),
                )
                .await
                {
                    println!("daemon: stopped");
                    return Ok(());
                }
                // The acknowledged owner never released its pid and socket:
                // recapture the witness the release wait consumed and signal
                // it down.
                release = daemon::capture_restart_release(&paths, old_pid);
            }
            let stop_paths = paths.clone();
            let stop_budget = remaining_command_budget(deadline);
            let stopped = tokio::task::spawn_blocking(move || {
                daemon::stop_with_timeout(&stop_paths, stop_budget)
            })
            .await
            .context("joining platform daemon stop")??;
            if stopped {
                if !daemon::wait_for_restart_release(
                    &paths,
                    release,
                    remaining_command_budget(deadline),
                )
                .await
                {
                    bail!(
                        "timed out waiting for the previous daemon process to exit and release its pid and socket"
                    );
                }
                if grace.is_some() {
                    println!(
                        "daemon: stopped (socket unreachable; used SIGTERM with default grace)"
                    );
                } else {
                    println!("daemon: stopped");
                }
            } else {
                println!("daemon: not running (no pid file)");
            }
            Ok(())
        }
        DaemonCommand::Restart {
            grace,
            no_resume,
            no_sandbox,
        } => {
            validate_grace(grace)?;
            if paths.socket.exists()
                && let Ok(response) =
                    daemon::supervisor::request(&paths, daemon::supervisor::AdminCommand::Roll)
                        .await
            {
                match response {
                    daemon::supervisor::AdminResponse::Rolled {
                        old_worker_pid,
                        worker_pid,
                        generation,
                        ..
                    } => {
                        println!(
                            "daemon: rolled worker {old_worker_pid} -> {worker_pid} (generation {generation}); attached clients will reconnect"
                        );
                        return Ok(());
                    }
                    daemon::supervisor::AdminResponse::Error { message, .. } => {
                        bail!("supervisor roll failed: {message}")
                    }
                    _ => bail!("supervisor returned an unexpected roll response"),
                }
            }
            let deadline = lifecycle_deadline.expect("restart command deadline");
            let old_pid = daemon::daemon_pid(&paths);
            let release = daemon::capture_restart_release(&paths, old_pid);
            let discovered =
                tokio::time::timeout(remaining_command_budget(deadline), daemon::discover())
                    .await
                    .context("timed out discovering daemon within the restart command deadline")?;
            let should_stop = restart_should_stop(discovered.status);
            // An unrecognized PID file has no parseable PID, but a stop that
            // succeeds against it still replaces a running predecessor.
            let restarted = should_stop
                && (old_pid.is_some()
                    || discovered.status == DaemonStatus::UnrecognizedPidMetadata);
            let replacement_no_sandbox = if should_stop {
                daemon::derive_restart_no_sandbox(&paths, no_sandbox)
            } else {
                no_sandbox
            };
            let resume = !no_resume;

            if should_stop {
                let mut stop_acknowledged = false;
                if let Ok(Ok(client)) = tokio::time::timeout(
                    remaining_command_budget(deadline),
                    DaemonClient::connect(&paths.socket),
                )
                .await
                {
                    let stop_response = tokio::time::timeout(
                        remaining_command_budget(deadline),
                        client.request(Request::StopDaemon { grace_secs: grace }),
                    )
                    .await;
                    match stop_response {
                        Ok(Ok(Ok(_))) => stop_acknowledged = true,
                        Ok(Ok(Err(error))) if error.code == proto::ErrorCode::BootstrapLocked => {
                            // Locked and older locked-bootstrap daemons reject
                            // the connected stop; the receipt-bound platform
                            // signal below still stops them.
                        }
                        Ok(Ok(Err(error))) => bail!("daemon error: {error}"),
                        // A delivery timeout or transport failure leaves the
                        // stop unconfirmed: fall through to the platform
                        // signal instead of failing the restart.
                        Ok(Err(_)) | Err(_) => {}
                    }
                    drop(client);
                }
                let mut released = false;
                // The command-start witness proves the captured predecessor
                // released. The acknowledged wait consumes it, so only that
                // path recaptures a fresh witness for the signal fallback.
                let mut release = Some(release);
                if stop_acknowledged {
                    released = daemon::wait_for_restart_release(
                        &paths,
                        release
                            .take()
                            .expect("restart release witness is consumed once"),
                        remaining_command_budget(deadline),
                    )
                    .await;
                }
                if !released {
                    let release =
                        release.unwrap_or_else(|| daemon::capture_restart_release(&paths, old_pid));
                    let stop_paths = paths.clone();
                    let stop_budget = remaining_command_budget(deadline);
                    let _ = tokio::task::spawn_blocking(move || {
                        daemon::stop_with_timeout(&stop_paths, stop_budget)
                    })
                    .await
                    .context("joining platform daemon restart stop")??;
                    if !daemon::wait_for_restart_release(
                        &paths,
                        release,
                        remaining_command_budget(deadline),
                    )
                    .await
                    {
                        bail!(
                            "timed out waiting for the previous daemon process to exit and release its pid and socket"
                        );
                    }
                }
            }

            let pid =
                daemon::spawn_detached_with_resume_async(replacement_no_sandbox, resume).await?;
            println!("{}", restart_started_message(restarted, pid, &paths.socket));
            Ok(())
        }
        DaemonCommand::Upgrade { binary } => {
            let command = binary.map_or(daemon::supervisor::AdminCommand::Roll, |binary| {
                daemon::supervisor::AdminCommand::Upgrade { binary }
            });
            let response = daemon::supervisor::request(&paths, command).await?;
            match response {
                daemon::supervisor::AdminResponse::Rolled {
                    old_worker_pid,
                    worker_pid,
                    generation,
                    ..
                } => {
                    println!(
                        "daemon: upgraded worker {old_worker_pid} -> {worker_pid} (generation {generation}); attached clients will reconnect"
                    );
                    Ok(())
                }
                daemon::supervisor::AdminResponse::Error { message, .. } => {
                    bail!("supervisor upgrade failed: {message}")
                }
                _ => bail!("supervisor returned an unexpected upgrade response"),
            }
        }
        DaemonCommand::Reexec => {
            let response =
                daemon::supervisor::request(&paths, daemon::supervisor::AdminCommand::Reexec)
                    .await?;
            match response {
                daemon::supervisor::AdminResponse::Reexecing { .. } => {
                    println!("daemon: supervisor reexec started");
                    Ok(())
                }
                daemon::supervisor::AdminResponse::Error { message, .. } => {
                    bail!("supervisor reexec failed: {message}")
                }
                _ => bail!("supervisor returned an unexpected reexec response"),
            }
        }
        DaemonCommand::Status { json } => {
            if let Ok(status) = daemon::supervisor::request_with_timeout(
                &paths,
                daemon::supervisor::AdminCommand::Status,
                ADMIN_REQUEST_TIMEOUT,
            )
            .await
                && let daemon::supervisor::AdminResponse::Status {
                    supervisor_pid,
                    worker_pid,
                    generation,
                    uptime_ms,
                    last_handover,
                    ..
                } = status
            {
                let supervisor = SupervisorStatus {
                    supervisor_pid,
                    worker_pid,
                    generation,
                    uptime_ms,
                    last_handover,
                };
                let socket = paths.socket.display().to_string();
                let worker_status = DaemonClient::connect(&paths.socket)
                    .await?
                    .request_ok(Request::DaemonStatus)
                    .await?;
                match worker_status {
                    Response::DaemonStatus {
                        pid,
                        uptime_secs,
                        active_sessions,
                        paused_sessions,
                        socket_path,
                        daemon_version,
                        protocol_version,
                        database_path,
                        schema_version,
                        pending_recovery_sessions,
                    } => {
                        if json {
                            let mut value = running_json_status(RunningJsonStatus {
                                pid,
                                uptime_secs,
                                active_sessions,
                                paused_sessions,
                                socket_path,
                                daemon_version,
                                protocol_version,
                                database_path,
                                schema_version,
                                pending_recovery_sessions,
                            });
                            insert_supervisor_json_fields(&mut value, &supervisor);
                            println!("{}", serde_json::to_string_pretty(&value)?);
                        } else {
                            println!(
                                "{}",
                                render_supervised_running_status(
                                    &socket,
                                    &supervisor,
                                    &pending_recovery_sessions,
                                )
                            );
                        }
                    }
                    Response::LockedBootstrapHello(hello) => {
                        if json {
                            let mut value = awaiting_onboarding_json_status(
                                &socket,
                                hello.protocol_version,
                                hello.bootstrap_available,
                            );
                            insert_supervisor_json_fields(&mut value, &supervisor);
                            println!("{}", serde_json::to_string_pretty(&value)?);
                        } else {
                            println!(
                                "{}",
                                render_awaiting_onboarding_status(
                                    &socket,
                                    hello.protocol_version,
                                    Some(&supervisor),
                                )
                            );
                        }
                    }
                    other => bail!(
                        "unexpected supervised daemon status response: {}",
                        other.wire_tag()
                    ),
                }
                return Ok(());
            }
            let probe = daemon::discover().await;
            if json {
                return print_json_status(&probe).await;
            }
            match probe.status {
                DaemonStatus::IncompatibleProtocol => {
                    let hello = probe.hello.as_ref().ok_or_else(|| {
                        anyhow::anyhow!("incompatible daemon did not report a hello")
                    })?;
                    println!(
                        "{}",
                        render_incompatible_protocol_status(
                            &probe.paths.socket.display().to_string(),
                            hello,
                        )
                    );
                }
                DaemonStatus::Running => match read_daemon_versions(&probe.paths.socket).await {
                    RunningStatusVersionRead::Versions(versions) => {
                        println!(
                            "{}",
                            render_running_status(
                                &probe.paths.socket.display().to_string(),
                                Some(&versions),
                                None,
                            )
                        );
                    }
                    RunningStatusVersionRead::BootstrapLocked { protocol_version } => {
                        println!(
                            "{}",
                            render_awaiting_onboarding_status(
                                &probe.paths.socket.display().to_string(),
                                protocol_version,
                                None,
                            )
                        );
                    }
                    RunningStatusVersionRead::ProtocolMismatch => {
                        let hello = proto::DaemonHello {
                            daemon_version: "unknown".to_string(),
                            protocol_version: 0,
                        };
                        println!(
                            "{}",
                            render_incompatible_protocol_status(
                                &probe.paths.socket.display().to_string(),
                                &hello,
                            )
                        );
                    }
                    RunningStatusVersionRead::ReadFailed(error) => {
                        println!(
                            "{}",
                            render_running_status(
                                &probe.paths.socket.display().to_string(),
                                None,
                                Some(&error),
                            )
                        );
                    }
                },
                DaemonStatus::LivePidSocketUnreachable => {
                    println!(
                        "daemon: pid file belongs to a live cockpit daemon, but the recorded socket is unreachable\n  pid: {}\n  socket: {}",
                        probe.paths.pid_file.display(),
                        probe.paths.socket.display(),
                    );
                }
                DaemonStatus::UnverifiedPid => {
                    println!(
                        "daemon: pid file names a live process whose identity could not be verified\n  pid: {}\n  socket: {}",
                        probe.paths.pid_file.display(),
                        probe.paths.socket.display(),
                    );
                }
                DaemonStatus::UnrecognizedPidMetadata => {
                    println!(
                        "daemon: pid file is not a receipt this build recognizes (possibly written by an older build) or could not be read; stop the old daemon process manually, then delete the pid file\n  pid: {}\n  socket: {}",
                        probe.paths.pid_file.display(),
                        probe.paths.socket.display(),
                    );
                }
                DaemonStatus::Stale => {
                    println!(
                        "daemon: canonical daemon not responding (stale pid file or socket)\n  pid: {}\n  socket: {}",
                        probe.paths.pid_file.display(),
                        probe.paths.socket.display(),
                    );
                }
                DaemonStatus::NotRunning => {
                    println!("daemon: not running");
                }
            }
            Ok(())
        }
        DaemonCommand::CleanWorktree {
            session_id,
            owner_agent_instance_id,
            lease_id,
        } => {
            let client = DaemonClient::connect(&paths.socket)
                .await
                .context("connecting to the local daemon for managed worktree cleanup")?;
            let response = client
                .request_ok(Request::CleanManagedWorkspaceLease {
                    session_id,
                    owner_agent_instance_id,
                    lease_id,
                })
                .await?;
            if !matches!(response, Response::Ack) {
                bail!("daemon returned unexpected response to managed worktree cleanup");
            }
            println!("managed worktree cleaned: {lease_id}");
            Ok(())
        }
        DaemonCommand::DiagnosticSnapshot {
            path,
            database_snapshot,
            offline,
            no_sandbox,
        } => {
            // Offline in-process fallback: passing `None` (no daemon handle)
            // makes `cli_snapshot` open the DB once via the core daemon-layer
            // diagnostics probe to report openability / schema health. The CLI
            // itself opens no session DB (its ratchet ALLOWED stays empty); the
            // single permitted default-path opener lives in cockpit-core.
            let snapshot_db = database_snapshot
                .as_deref()
                .map(crate::db::Db::open_read_only_diagnostic_snapshot)
                .transpose()?;
            let snapshot = crate::diagnostics::cli_snapshot(
                path.as_deref(),
                no_sandbox,
                offline,
                snapshot_db.as_ref(),
                None,
                None,
                None,
            )
            .await?;
            println!(
                "{}",
                serde_json::json!({
                    "rendered": crate::diagnostics::render(&snapshot),
                    "has_failures": snapshot.has_failures,
                    // This worker is used only when an ephemeral daemon
                    // could not become ready. Keep the classification machine
                    // readable so its parent can preserve the original daemon
                    // error unless the database bootstrap is the actual cause.
                    "database_bootstrap_failure": snapshot.database.iter().any(|line| {
                        line.starts_with("openability: FAILED")
                            || line.starts_with("schema: FAILED")
                            || line.starts_with("path: unavailable")
                    }),
                })
            );
            Ok(())
        }
        DaemonCommand::DiagnosticFailedCalls {
            since_epoch,
            tool,
            model,
            project_id,
            include_recovered,
            limit,
        } => {
            let calls_json = crate::diagnostics::failed_tool_calls_json(
                since_epoch,
                tool,
                model,
                project_id,
                include_recovered,
                limit as usize,
            )
            .await?;
            println!("{calls_json}");
            Ok(())
        }
    }
}

async fn print_json_status(probe: &crate::daemon::DaemonProbe) -> Result<()> {
    let resolved_database_path = crate::db::Db::default_path()?.display().to_string();
    let mut value = serde_json::json!({
        "status": daemon_status_name(probe.status),
        "socket_path": probe.paths.socket.display().to_string(),
        "database_path": resolved_database_path,
        "schema_version": serde_json::Value::Null,
        "version_skew": false,
        "version_skew_reason": serde_json::Value::Null,
    });

    if probe.status == DaemonStatus::IncompatibleProtocol {
        let hello = probe
            .hello
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("incompatible daemon did not report a hello"))?;
        value = incompatible_protocol_json_status(
            &probe.paths.socket.display().to_string(),
            &resolved_database_path,
            hello,
        );
    } else if probe.status == DaemonStatus::Running {
        let response = match DaemonClient::connect(&probe.paths.socket)
            .await?
            .request(Request::DaemonStatus)
            .await?
        {
            Ok(response) => response,
            Err(error) => bail!("daemon error: {error}"),
        };
        value = match response {
            Response::DaemonStatus {
                pid,
                uptime_secs,
                active_sessions,
                socket_path,
                daemon_version,
                protocol_version,
                paused_sessions,
                database_path,
                schema_version,
                pending_recovery_sessions,
            } => running_json_status(RunningJsonStatus {
                pid,
                uptime_secs,
                active_sessions,
                paused_sessions,
                socket_path,
                daemon_version,
                protocol_version,
                database_path,
                schema_version,
                pending_recovery_sessions,
            }),
            Response::LockedBootstrapHello(hello) => awaiting_onboarding_json_status(
                &probe.paths.socket.display().to_string(),
                hello.protocol_version,
                hello.bootstrap_available,
            ),
            other => bail!("unexpected daemon status response: {}", other.wire_tag()),
        };
    }

    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DaemonVersions {
    daemon_version: String,
    protocol_version: u32,
    pending_recovery_sessions: Vec<uuid::Uuid>,
}

enum RunningStatusVersionRead {
    Versions(DaemonVersions),
    BootstrapLocked { protocol_version: u32 },
    ProtocolMismatch,
    ReadFailed(String),
}

struct RunningJsonStatus {
    pid: u32,
    uptime_secs: u64,
    active_sessions: u32,
    paused_sessions: u32,
    socket_path: String,
    daemon_version: String,
    protocol_version: u32,
    database_path: String,
    schema_version: i64,
    pending_recovery_sessions: Vec<uuid::Uuid>,
}

async fn read_daemon_versions(socket: &Path) -> RunningStatusVersionRead {
    let client = match DaemonClient::connect(socket).await {
        Ok(client) => client,
        Err(error) if is_protocol_version_mismatch(&error) => {
            return RunningStatusVersionRead::ProtocolMismatch;
        }
        Err(error) => return RunningStatusVersionRead::ReadFailed(error.to_string()),
    };
    let response = match client.request(Request::DaemonStatus).await {
        Ok(Ok(response)) => response,
        Ok(Err(error)) if is_protocol_mismatch_status_error(&error) => {
            return RunningStatusVersionRead::ProtocolMismatch;
        }
        Ok(Err(error)) => {
            return RunningStatusVersionRead::ReadFailed(format!("daemon error: {error}"));
        }
        Err(error) => return RunningStatusVersionRead::ReadFailed(error.to_string()),
    };

    match response {
        Response::DaemonStatus {
            daemon_version,
            protocol_version,
            pending_recovery_sessions,
            ..
        } => RunningStatusVersionRead::Versions(DaemonVersions {
            daemon_version,
            protocol_version,
            pending_recovery_sessions,
        }),
        Response::LockedBootstrapHello(hello) => RunningStatusVersionRead::BootstrapLocked {
            protocol_version: hello.protocol_version,
        },
        other => RunningStatusVersionRead::ReadFailed(format!(
            "unexpected daemon status response: {}",
            other.wire_tag()
        )),
    }
}

fn is_protocol_mismatch_status_error(error: &proto::ErrorPayload) -> bool {
    error.code == proto::ErrorCode::ProtocolVersion
}

fn render_running_status(
    socket: &str,
    daemon: Option<&DaemonVersions>,
    read_error: Option<&str>,
) -> String {
    let mut output = format!("daemon: running\n  socket: {socket}");
    if let Some(daemon) = daemon {
        output.push_str(&format!(
            "\n  daemon: {} (protocol v{})\n  client: {} (protocol v{})",
            daemon.daemon_version,
            daemon.protocol_version,
            proto::DAEMON_VERSION,
            proto::PROTOCOL_VERSION
        ));
        if let Some(reason) = version_skew_reason(&daemon.daemon_version, daemon.protocol_version) {
            output.push_str(&format!("\n  version skew: {reason}"));
        }
        let pending = if daemon.pending_recovery_sessions.is_empty() {
            "none".to_string()
        } else {
            daemon
                .pending_recovery_sessions
                .iter()
                .map(uuid::Uuid::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        };
        output.push_str(&format!("\n  pending recovery: {pending}"));
    } else if let Some(error) = read_error {
        output.push_str(&format!("\n  could not read daemon version: {error}"));
    }
    output
}

fn render_incompatible_protocol_status(socket: &str, hello: &proto::DaemonHello) -> String {
    format!(
        "daemon: running but speaks an incompatible protocol\n  socket: {socket}\n  daemon: {} (protocol v{})\n  client: {} (protocol v{})\n  {}",
        hello.daemon_version,
        hello.protocol_version,
        proto::DAEMON_VERSION,
        proto::PROTOCOL_VERSION,
        PROTOCOL_MISMATCH_STATUS_REMEDY
    )
}

fn version_skew_reason(daemon_version: &str, protocol_version: u32) -> Option<String> {
    if protocol_version < proto::PROTOCOL_VERSION {
        Some("the running daemon predates this CLI; run `cockpit daemon restart`".to_string())
    } else if protocol_version > proto::PROTOCOL_VERSION {
        Some(
            "the running daemon is newer than this CLI; upgrade the CLI or run `cockpit daemon restart`"
                .to_string(),
        )
    } else if daemon_version != proto::DAEMON_VERSION {
        Some(format!(
            "daemon {daemon_version} vs client {}; run `cockpit daemon restart`",
            proto::DAEMON_VERSION
        ))
    } else {
        None
    }
}

fn running_json_status(status: RunningJsonStatus) -> serde_json::Value {
    let version_skew_reason = version_skew_reason(&status.daemon_version, status.protocol_version);
    serde_json::json!({
        "status": "running",
        "state": DAEMON_STATE_READY,
        "pid": status.pid,
        "uptime_secs": status.uptime_secs,
        "active_sessions": status.active_sessions,
        "paused_sessions": status.paused_sessions,
        "socket_path": status.socket_path,
        "daemon_version": status.daemon_version,
        "protocol_version": status.protocol_version,
        "database_path": status.database_path,
        "schema_version": status.schema_version,
        "pending_recovery_sessions": status.pending_recovery_sessions,
        "version_skew": version_skew_reason.is_some(),
        "version_skew_reason": version_skew_reason,
    })
}

/// `state` of a running daemon whose worker serves normal requests.
const DAEMON_STATE_READY: &str = "ready";
/// `state` of a running daemon whose worker is locked behind first-run
/// onboarding and answers requests with a locked-bootstrap hello.
const DAEMON_STATE_AWAITING_ONBOARDING: &str = "awaiting_onboarding";

/// Supervisor admin `Status` fields shown alongside the worker's answer.
struct SupervisorStatus {
    supervisor_pid: u32,
    worker_pid: u32,
    generation: u64,
    uptime_ms: u64,
    last_handover: Option<String>,
}

fn insert_supervisor_json_fields(value: &mut serde_json::Value, supervisor: &SupervisorStatus) {
    let object = value
        .as_object_mut()
        .expect("running daemon status is a JSON object");
    object.insert("supervisor_pid".into(), supervisor.supervisor_pid.into());
    object.insert("worker_pid".into(), supervisor.worker_pid.into());
    object.insert("generation".into(), supervisor.generation.into());
    object.insert("uptime_ms".into(), supervisor.uptime_ms.into());
    object.insert(
        "last_handover".into(),
        supervisor
            .last_handover
            .clone()
            .map(serde_json::Value::String)
            .unwrap_or(serde_json::Value::Null),
    );
    // The worker cannot report its own pid while it is locked; the
    // supervisor's view of the worker pid is authoritative either way.
    if object.get("pid").is_some_and(serde_json::Value::is_null) {
        object.insert("pid".into(), supervisor.worker_pid.into());
    }
}

fn render_supervisor_lines(output: &mut String, supervisor: &SupervisorStatus) {
    output.push_str(&format!(
        "\n  supervisor pid: {}\n  worker pid: {}\n  generation: {}\n  uptime: {:.3}s\n  last handover: {}",
        supervisor.supervisor_pid,
        supervisor.worker_pid,
        supervisor.generation,
        supervisor.uptime_ms as f64 / 1000.0,
        supervisor.last_handover.as_deref().unwrap_or("none"),
    ));
}

fn render_supervised_running_status(
    socket: &str,
    supervisor: &SupervisorStatus,
    pending_recovery_sessions: &[uuid::Uuid],
) -> String {
    let mut output = "daemon: running".to_string();
    render_supervisor_lines(&mut output, supervisor);
    let pending = if pending_recovery_sessions.is_empty() {
        "none".to_string()
    } else {
        pending_recovery_sessions
            .iter()
            .map(uuid::Uuid::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    };
    output.push_str(&format!(
        "\n  pending recovery: {pending}\n  socket: {socket}"
    ));
    output
}

/// Text status for a daemon whose worker is waiting for first-run
/// onboarding. The locked hello is redacted metadata; only its protocol
/// version is shown (never the capability snapshot).
fn render_awaiting_onboarding_status(
    socket: &str,
    protocol_version: u32,
    supervisor: Option<&SupervisorStatus>,
) -> String {
    let mut output = "daemon: running, awaiting onboarding".to_string();
    if let Some(supervisor) = supervisor {
        render_supervisor_lines(&mut output, supervisor);
    }
    output.push_str(&format!(
        "\n  protocol: v{protocol_version}\n  socket: {socket}"
    ));
    output
}

/// JSON status for a daemon awaiting onboarding. Keeps every key of
/// [`running_json_status`] so existing consumers still find them; values the
/// locked worker does not report are `null`, and `state` distinguishes it
/// from a ready daemon.
fn awaiting_onboarding_json_status(
    socket_path: &str,
    protocol_version: u32,
    bootstrap_available: bool,
) -> serde_json::Value {
    serde_json::json!({
        "status": "running",
        "state": DAEMON_STATE_AWAITING_ONBOARDING,
        "bootstrap_available": bootstrap_available,
        "pid": serde_json::Value::Null,
        "uptime_secs": serde_json::Value::Null,
        "active_sessions": serde_json::Value::Null,
        "paused_sessions": serde_json::Value::Null,
        "socket_path": socket_path,
        "daemon_version": serde_json::Value::Null,
        "protocol_version": protocol_version,
        "database_path": serde_json::Value::Null,
        "schema_version": serde_json::Value::Null,
        "pending_recovery_sessions": serde_json::Value::Null,
        "version_skew": false,
        "version_skew_reason": serde_json::Value::Null,
    })
}

fn incompatible_protocol_json_status(
    socket_path: &str,
    database_path: &str,
    hello: &proto::DaemonHello,
) -> serde_json::Value {
    serde_json::json!({
        "status": "incompatible_protocol",
        "socket_path": socket_path,
        "daemon_version": hello.daemon_version,
        "protocol_version": hello.protocol_version,
        "database_path": database_path,
        "schema_version": serde_json::Value::Null,
        "version_skew": false,
        "version_skew_reason": serde_json::Value::Null,
    })
}

fn daemon_status_name(status: DaemonStatus) -> &'static str {
    match status {
        DaemonStatus::Running => "running",
        DaemonStatus::IncompatibleProtocol => "incompatible_protocol",
        DaemonStatus::LivePidSocketUnreachable => "live_pid_socket_unreachable",
        DaemonStatus::UnverifiedPid => "unverified_pid",
        DaemonStatus::UnrecognizedPidMetadata => "unrecognized_pid_metadata",
        DaemonStatus::Stale => "stale",
        DaemonStatus::NotRunning => "not_running",
    }
}

fn validate_grace(grace: Option<u64>) -> Result<()> {
    if let Some(secs) = grace
        && secs > MAX_STOP_GRACE_SECS
    {
        bail!("--grace must be <= {MAX_STOP_GRACE_SECS} seconds");
    }
    Ok(())
}

fn restart_should_stop(status: DaemonStatus) -> bool {
    matches!(
        status,
        DaemonStatus::Running
            | DaemonStatus::IncompatibleProtocol
            | DaemonStatus::LivePidSocketUnreachable
            | DaemonStatus::UnverifiedPid
            | DaemonStatus::UnrecognizedPidMetadata
    )
}

fn remaining_command_budget(deadline: tokio::time::Instant) -> Duration {
    remaining_command_budget_at(deadline, tokio::time::Instant::now())
}

fn remaining_command_budget_at(
    deadline: tokio::time::Instant,
    now: tokio::time::Instant,
) -> Duration {
    deadline.saturating_duration_since(now)
}

fn restart_started_message(restarted: bool, pid: u32, socket: &std::path::Path) -> String {
    if restarted {
        format!(
            "daemon: restarted (pid {pid}); attached clients will reconnect\n  socket: {}",
            socket.display()
        )
    } else {
        format!(
            "daemon: was not running; started (pid {pid})\n  socket: {}",
            socket.display()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DaemonVersions, RunningJsonStatus, SupervisorStatus, awaiting_onboarding_json_status,
        incompatible_protocol_json_status, insert_supervisor_json_fields,
        remaining_command_budget_at, render_awaiting_onboarding_status,
        render_incompatible_protocol_status, render_running_status,
        render_supervised_running_status, restart_should_stop, restart_started_message,
        running_json_status, validate_grace, version_skew_reason,
    };
    use crate::daemon::DaemonStatus;
    use crate::daemon::proto;
    use std::time::Duration;

    #[test]
    fn grace_validation_allows_zero_and_rejects_absurd_values() {
        assert!(validate_grace(Some(0)).is_ok());
        assert!(validate_grace(Some(24 * 60 * 60)).is_ok());
        let err = validate_grace(Some(24 * 60 * 60 + 1)).unwrap_err();
        assert!(err.to_string().contains("--grace"));
    }

    #[test]
    fn restart_message_routing_uses_verified_daemon_status_not_stale_pid_file() {
        assert!(restart_should_stop(DaemonStatus::Running));
        assert!(restart_should_stop(DaemonStatus::IncompatibleProtocol));
        assert!(restart_should_stop(DaemonStatus::LivePidSocketUnreachable));
        assert!(restart_should_stop(DaemonStatus::UnverifiedPid));
        assert!(restart_should_stop(DaemonStatus::UnrecognizedPidMetadata));
        assert!(!restart_should_stop(DaemonStatus::Stale));
        assert!(!restart_should_stop(DaemonStatus::NotRunning));
    }

    #[test]
    fn restart_output_strings_distinguish_restarted_from_started() {
        let socket = std::path::Path::new("/tmp/cockpit.sock");
        assert_eq!(
            restart_started_message(true, 123, socket),
            "daemon: restarted (pid 123); attached clients will reconnect\n  socket: /tmp/cockpit.sock"
        );
        assert_eq!(
            restart_started_message(false, 456, socket),
            "daemon: was not running; started (pid 456)\n  socket: /tmp/cockpit.sock"
        );
    }

    #[test]
    fn stop_and_restart_operations_consume_one_shared_deadline() {
        let started = tokio::time::Instant::now();
        let deadline = started + Duration::from_secs(30);
        assert_eq!(
            remaining_command_budget_at(deadline, started),
            Duration::from_secs(30),
        );
        assert_eq!(
            remaining_command_budget_at(deadline, started + Duration::from_secs(11)),
            Duration::from_secs(19),
        );
        assert_eq!(
            remaining_command_budget_at(deadline, deadline + Duration::from_secs(1)),
            Duration::ZERO,
        );
    }

    #[test]
    fn daemon_status_version_lines_render_for_matching_versions() {
        let versions = DaemonVersions {
            daemon_version: proto::DAEMON_VERSION.to_string(),
            protocol_version: proto::PROTOCOL_VERSION,
            pending_recovery_sessions: Vec::new(),
        };

        let output = render_running_status("/tmp/cockpit.sock", Some(&versions), None);

        assert_eq!(
            output,
            format!(
                "daemon: running\n  socket: /tmp/cockpit.sock\n  daemon: {} (protocol v{})\n  client: {} (protocol v{})\n  pending recovery: none",
                proto::DAEMON_VERSION,
                proto::PROTOCOL_VERSION,
                proto::DAEMON_VERSION,
                proto::PROTOCOL_VERSION
            )
        );
    }

    #[test]
    fn daemon_status_text_lists_sessions_with_pending_recovery() {
        let session_id = uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000441").unwrap();
        let versions = DaemonVersions {
            daemon_version: proto::DAEMON_VERSION.to_string(),
            protocol_version: proto::PROTOCOL_VERSION,
            pending_recovery_sessions: vec![session_id],
        };

        let output = render_running_status("/tmp/cockpit.sock", Some(&versions), None);

        assert!(output.contains(&format!("pending recovery: {session_id}")));
    }

    #[test]
    fn daemon_status_version_skew_older_daemon_names_restart() {
        let protocol_version = proto::PROTOCOL_VERSION.saturating_sub(1);
        assert!(protocol_version < proto::PROTOCOL_VERSION);
        let versions = DaemonVersions {
            daemon_version: proto::DAEMON_VERSION.to_string(),
            protocol_version,
            pending_recovery_sessions: Vec::new(),
        };

        let output = render_running_status("/tmp/cockpit.sock", Some(&versions), None);

        assert!(output.contains(
            "version skew: the running daemon predates this CLI; run `cockpit daemon restart`"
        ));
        assert_eq!(
            version_skew_reason(&versions.daemon_version, protocol_version).as_deref(),
            Some("the running daemon predates this CLI; run `cockpit daemon restart`")
        );
    }

    #[test]
    fn daemon_status_version_skew_newer_daemon_names_upgrade_and_restart() {
        let protocol_version = proto::PROTOCOL_VERSION + 1;
        let versions = DaemonVersions {
            daemon_version: proto::DAEMON_VERSION.to_string(),
            protocol_version,
            pending_recovery_sessions: Vec::new(),
        };

        let output = render_running_status("/tmp/cockpit.sock", Some(&versions), None);

        assert!(output.contains(
            "version skew: the running daemon is newer than this CLI; upgrade the CLI or run `cockpit daemon restart`"
        ));
    }

    #[test]
    fn daemon_status_version_skew_same_protocol_different_version_string() {
        let versions = DaemonVersions {
            daemon_version: "0.0.test-skew".to_string(),
            protocol_version: proto::PROTOCOL_VERSION,
            pending_recovery_sessions: Vec::new(),
        };

        let output = render_running_status("/tmp/cockpit.sock", Some(&versions), None);

        assert!(output.contains(&format!(
            "version skew: daemon 0.0.test-skew vs client {}; run `cockpit daemon restart`",
            proto::DAEMON_VERSION
        )));
    }

    #[test]
    fn daemon_status_incompatible_protocol_names_restart() {
        let hello = proto::DaemonHello {
            daemon_version: "0.0.old".to_string(),
            protocol_version: 0,
        };
        let output = render_incompatible_protocol_status("/tmp/cockpit.sock", &hello);

        assert_eq!(
            output,
            format!(
                "daemon: running but speaks an incompatible protocol\n  socket: /tmp/cockpit.sock\n  daemon: 0.0.old (protocol v0)\n  client: {} (protocol v{})\n  run `cockpit daemon restart` to restart the daemon on this version",
                proto::DAEMON_VERSION,
                proto::PROTOCOL_VERSION
            )
        );
        assert!(output.contains("run `cockpit daemon restart`"));
    }

    #[test]
    fn daemon_status_json_incompatible_protocol_shape() {
        let hello = proto::DaemonHello {
            daemon_version: "0.0.old".to_string(),
            protocol_version: 0,
        };
        let value =
            incompatible_protocol_json_status("/tmp/cockpit.sock", "/tmp/cockpit.db", &hello);
        let object = value.as_object().expect("json object");
        let mut keys = object.keys().map(String::as_str).collect::<Vec<_>>();
        keys.sort_unstable();

        assert_eq!(
            keys,
            vec![
                "daemon_version",
                "database_path",
                "protocol_version",
                "schema_version",
                "socket_path",
                "status",
                "version_skew",
                "version_skew_reason",
            ]
        );
        assert_eq!(value["status"], "incompatible_protocol");
        assert_eq!(value["socket_path"], "/tmp/cockpit.sock");
        assert_eq!(value["daemon_version"], "0.0.old");
        assert_eq!(value["protocol_version"], 0);
        assert_eq!(value["database_path"], "/tmp/cockpit.db");
        assert!(value["schema_version"].is_null());
        assert_eq!(value["version_skew"], false);
        assert!(value["version_skew_reason"].is_null());
    }

    #[test]
    fn daemon_status_version_classifies_only_typed_errors_as_protocol_mismatch() {
        let typed_protocol_error = proto::ErrorPayload {
            code: proto::ErrorCode::ProtocolVersion,
            message: proto::version_mismatch_message(proto::PROTOCOL_VERSION + 1),
        };
        let envelope_gate_error = proto::ErrorPayload {
            code: proto::ErrorCode::Internal,
            message: "daemon connection closed".to_string(),
        };
        let client_task_stopped_error = proto::ErrorPayload {
            code: proto::ErrorCode::Internal,
            message: "daemon client task has stopped".to_string(),
        };
        let dropped_reply_error = proto::ErrorPayload {
            code: proto::ErrorCode::Internal,
            message: "daemon client dropped reply channel".to_string(),
        };
        let timeout_error = proto::ErrorPayload {
            code: proto::ErrorCode::Internal,
            message: "request timed out after 30s".to_string(),
        };

        assert!(super::is_protocol_mismatch_status_error(
            &typed_protocol_error
        ));
        assert!(!super::is_protocol_mismatch_status_error(
            &envelope_gate_error
        ));
        assert!(!super::is_protocol_mismatch_status_error(
            &client_task_stopped_error
        ));
        assert!(!super::is_protocol_mismatch_status_error(
            &dropped_reply_error
        ));
        assert!(!super::is_protocol_mismatch_status_error(&timeout_error));
    }

    #[test]
    fn daemon_status_version_read_failure_is_non_fatal() {
        let output = render_running_status(
            "/tmp/cockpit.sock",
            None,
            Some("request timed out after 30s"),
        );

        assert_eq!(
            output,
            "daemon: running\n  socket: /tmp/cockpit.sock\n  could not read daemon version: request timed out after 30s"
        );
        assert!(!output.contains("\n  daemon:"));
        assert!(!output.contains("\n  client:"));
    }

    #[test]
    fn daemon_status_version_json_adds_skew_fields_without_changing_existing_keys() {
        let value = running_json_status(RunningJsonStatus {
            pid: 123,
            uptime_secs: 45,
            active_sessions: 2,
            paused_sessions: 1,
            socket_path: "/tmp/cockpit.sock".to_string(),
            daemon_version: "0.0.test-skew".to_string(),
            protocol_version: proto::PROTOCOL_VERSION,
            database_path: "/tmp/cockpit.db".to_string(),
            schema_version: crate::db::EXPECTED_SCHEMA_VERSION,
            pending_recovery_sessions: vec![uuid::Uuid::nil()],
        });
        let object = value.as_object().expect("json object");
        let mut keys = object.keys().map(String::as_str).collect::<Vec<_>>();
        keys.sort_unstable();

        assert_eq!(
            keys,
            vec![
                "active_sessions",
                "daemon_version",
                "database_path",
                "paused_sessions",
                "pending_recovery_sessions",
                "pid",
                "protocol_version",
                "schema_version",
                "socket_path",
                "state",
                "status",
                "uptime_secs",
                "version_skew",
                "version_skew_reason",
            ]
        );
        assert_eq!(value["status"], "running");
        assert_eq!(value["state"], "ready");
        assert!(value["pid"].is_u64());
        assert!(value["uptime_secs"].is_u64());
        assert!(value["active_sessions"].is_u64());
        assert!(value["paused_sessions"].is_u64());
        assert_eq!(
            value["pending_recovery_sessions"],
            serde_json::json!([uuid::Uuid::nil()])
        );
        assert!(value["socket_path"].is_string());
        assert!(value["daemon_version"].is_string());
        assert!(value["protocol_version"].is_u64());
        assert!(value["database_path"].is_string());
        assert!(value["schema_version"].is_i64());
        assert_eq!(value["version_skew"], true);
        assert_eq!(
            value["version_skew_reason"],
            format!(
                "daemon 0.0.test-skew vs client {}; run `cockpit daemon restart`",
                proto::DAEMON_VERSION
            )
        );
    }

    fn supervisor_status() -> SupervisorStatus {
        SupervisorStatus {
            supervisor_pid: 111,
            worker_pid: 222,
            generation: 3,
            uptime_ms: 4_500,
            last_handover: None,
        }
    }

    #[test]
    fn supervised_running_status_text_lists_supervisor_and_worker() {
        let output =
            render_supervised_running_status("/tmp/cockpit.sock", &supervisor_status(), &[]);

        assert_eq!(
            output,
            "daemon: running\n  supervisor pid: 111\n  worker pid: 222\n  generation: 3\n  uptime: 4.500s\n  last handover: none\n  pending recovery: none\n  socket: /tmp/cockpit.sock"
        );
    }

    #[test]
    fn awaiting_onboarding_status_text_names_supervisor_and_worker_pids() {
        let output = render_awaiting_onboarding_status(
            "/tmp/cockpit.sock",
            proto::PROTOCOL_VERSION,
            Some(&supervisor_status()),
        );

        assert_eq!(
            output,
            format!(
                "daemon: running, awaiting onboarding\n  supervisor pid: 111\n  worker pid: 222\n  generation: 3\n  uptime: 4.500s\n  last handover: none\n  protocol: v{}\n  socket: /tmp/cockpit.sock",
                proto::PROTOCOL_VERSION
            )
        );
        assert!(!output.contains("LockedBootstrapHello"));
        assert!(!output.contains("host_capabilities"));
    }

    #[test]
    fn awaiting_onboarding_status_text_without_supervisor_omits_pids() {
        let output = render_awaiting_onboarding_status("/tmp/cockpit.sock", 1, None);

        assert_eq!(
            output,
            "daemon: running, awaiting onboarding\n  protocol: v1\n  socket: /tmp/cockpit.sock"
        );
    }

    #[test]
    fn awaiting_onboarding_status_json_keeps_running_keys_and_adds_state() {
        let running_keys = {
            let value = running_json_status(RunningJsonStatus {
                pid: 1,
                uptime_secs: 1,
                active_sessions: 0,
                paused_sessions: 0,
                socket_path: "/tmp/cockpit.sock".to_string(),
                daemon_version: proto::DAEMON_VERSION.to_string(),
                protocol_version: proto::PROTOCOL_VERSION,
                database_path: "/tmp/cockpit.db".to_string(),
                schema_version: crate::db::EXPECTED_SCHEMA_VERSION,
                pending_recovery_sessions: Vec::new(),
            });
            value
                .as_object()
                .expect("json object")
                .keys()
                .cloned()
                .collect::<Vec<_>>()
        };
        let mut value =
            awaiting_onboarding_json_status("/tmp/cockpit.sock", proto::PROTOCOL_VERSION, true);
        insert_supervisor_json_fields(&mut value, &supervisor_status());
        let object = value.as_object().expect("json object");

        for key in &running_keys {
            assert!(
                object.contains_key(key),
                "awaiting-onboarding JSON lacks `{key}`"
            );
        }
        let mut keys = object.keys().map(String::as_str).collect::<Vec<_>>();
        keys.sort_unstable();
        assert_eq!(
            keys,
            vec![
                "active_sessions",
                "bootstrap_available",
                "daemon_version",
                "database_path",
                "generation",
                "last_handover",
                "paused_sessions",
                "pending_recovery_sessions",
                "pid",
                "protocol_version",
                "schema_version",
                "socket_path",
                "state",
                "status",
                "supervisor_pid",
                "uptime_ms",
                "uptime_secs",
                "version_skew",
                "version_skew_reason",
                "worker_pid",
            ]
        );
        assert_eq!(value["status"], "running");
        assert_eq!(value["state"], "awaiting_onboarding");
        assert_eq!(value["bootstrap_available"], true);
        assert_eq!(value["supervisor_pid"], 111);
        assert_eq!(value["worker_pid"], 222);
        assert_eq!(value["pid"], 222);
        assert_eq!(value["generation"], 3);
        assert_eq!(value["uptime_ms"], 4_500);
        assert!(value["last_handover"].is_null());
        assert_eq!(value["protocol_version"], proto::PROTOCOL_VERSION);
        assert_eq!(value["socket_path"], "/tmp/cockpit.sock");
        assert!(value["daemon_version"].is_null());
        assert!(value["schema_version"].is_null());
        assert_eq!(value["version_skew"], false);
    }

    #[test]
    fn awaiting_onboarding_status_json_without_supervisor_has_null_pid() {
        let value = awaiting_onboarding_json_status("/tmp/cockpit.sock", 1, false);

        assert_eq!(value["state"], "awaiting_onboarding");
        assert_eq!(value["bootstrap_available"], false);
        assert!(value["pid"].is_null());
        assert!(value.get("supervisor_pid").is_none());
    }

    #[test]
    fn supervisor_json_fields_do_not_override_a_worker_reported_pid() {
        let mut value = running_json_status(RunningJsonStatus {
            pid: 999,
            uptime_secs: 1,
            active_sessions: 0,
            paused_sessions: 0,
            socket_path: "/tmp/cockpit.sock".to_string(),
            daemon_version: proto::DAEMON_VERSION.to_string(),
            protocol_version: proto::PROTOCOL_VERSION,
            database_path: "/tmp/cockpit.db".to_string(),
            schema_version: crate::db::EXPECTED_SCHEMA_VERSION,
            pending_recovery_sessions: Vec::new(),
        });
        insert_supervisor_json_fields(&mut value, &supervisor_status());

        assert_eq!(value["pid"], 999);
        assert_eq!(value["worker_pid"], 222);
        assert_eq!(value["state"], "ready");
    }
}
