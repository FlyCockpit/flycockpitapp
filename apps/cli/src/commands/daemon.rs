//! `cockpit daemon` subcommands.

use anyhow::{Result, bail};
use std::time::Duration;

use crate::cli::DaemonCommand;
use crate::daemon::client::DaemonClient;
use crate::daemon::proto::{Request, Response};
use crate::daemon::{self, DaemonPaths, DaemonStatus};

const EPHEMERAL_TUI_NOTE: &str =
    "  note: a live TUI may still be connected to a separate ephemeral daemon.";
const MAX_STOP_GRACE_SECS: u64 = 24 * 60 * 60;

pub async fn run(cmd: DaemonCommand) -> Result<()> {
    let paths = DaemonPaths::resolve()?;
    match cmd {
        DaemonCommand::Start {
            foreground,
            detach,
            no_sandbox,
            resume_all_sessions,
        } => {
            if detach && !foreground {
                let pid = daemon::spawn_detached_with_resume(no_sandbox, resume_all_sessions)?;
                println!(
                    "daemon: spawned (pid {pid})\n  socket: {}",
                    paths.socket.display()
                );
                return Ok(());
            }
            // Foreground mode: blocks until SIGINT/SIGTERM. A daemon
            // launched `--no-sandbox` disables filesystem sandboxing for
            // ALL its sessions (sandboxing part 2): export the marker env
            // var the session workers read at spawn (Layer B style).
            if no_sandbox {
                // SAFETY: set before the runtime spins up worker tasks; a
                // process-global read-only marker thereafter.
                unsafe {
                    std::env::set_var(crate::daemon::session_worker::DAEMON_NO_SANDBOX_ENV, "1");
                }
            }
            println!(
                "daemon: starting in foreground (pid {})\n  socket: {}\n  pid file: {}",
                std::process::id(),
                paths.socket.display(),
                paths.pid_file.display()
            );
            let terminal_factory = crate::terminal_host::factory();
            if resume_all_sessions {
                daemon::run_foreground_with_resume(paths, true, terminal_factory).await
            } else {
                daemon::run_foreground(paths, terminal_factory).await
            }
        }
        DaemonCommand::Stop { grace } => {
            validate_grace(grace)?;
            if let Ok(client) = DaemonClient::connect(&paths.socket).await {
                client
                    .request_ok(Request::StopDaemon { grace_secs: grace })
                    .await?;
                println!("daemon: stopped");
                return Ok(());
            }
            let stopped = daemon::stop(&paths)?;
            if stopped {
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
            let old_pid = daemon::daemon_pid(&paths);
            let discovered = daemon::discover().await;
            let should_stop = restart_should_stop(discovered.status);
            let replacement_no_sandbox = if should_stop {
                daemon::derive_restart_no_sandbox(&paths, no_sandbox)
            } else {
                no_sandbox
            };
            let resume = !no_resume;

            if should_stop {
                let stop_via_socket = if let Ok(client) = DaemonClient::connect(&paths.socket).await
                {
                    client
                        .request_ok(Request::StopDaemon { grace_secs: grace })
                        .await?;
                    true
                } else {
                    let _ = daemon::stop(&paths)?;
                    false
                };
                daemon::wait_for_restart_release(
                    &paths,
                    old_pid,
                    restart_release_timeout_for_stop_path(grace, stop_via_socket),
                )
                .await;
            }

            let pid = daemon::spawn_detached_with_resume(replacement_no_sandbox, resume)?;
            println!(
                "{}",
                restart_started_message(should_stop, pid, &paths.socket)
            );
            Ok(())
        }
        DaemonCommand::Status { json } => {
            let probe = daemon::discover().await;
            if json {
                return print_json_status(&probe).await;
            }
            match probe.status {
                DaemonStatus::Running => {
                    println!(
                        "daemon: running\n  socket: {}",
                        probe.paths.socket.display()
                    );
                }
                DaemonStatus::LivePidSocketUnreachable => {
                    println!(
                        "daemon: pid file belongs to a live cockpit daemon, but the recorded socket is unreachable\n  pid: {}\n  socket: {}\n{}",
                        probe.paths.pid_file.display(),
                        probe.paths.socket.display(),
                        EPHEMERAL_TUI_NOTE
                    );
                }
                DaemonStatus::UnverifiedPid => {
                    println!(
                        "daemon: pid file names a live process whose identity could not be verified\n  pid: {}\n  socket: {}\n{}",
                        probe.paths.pid_file.display(),
                        probe.paths.socket.display(),
                        EPHEMERAL_TUI_NOTE
                    );
                }
                DaemonStatus::Stale => {
                    println!(
                        "daemon: canonical daemon not responding (stale pid file or socket)\n  pid: {}\n  socket: {}\n{}",
                        probe.paths.pid_file.display(),
                        probe.paths.socket.display(),
                        EPHEMERAL_TUI_NOTE
                    );
                }
                DaemonStatus::NotRunning => {
                    println!("daemon: canonical daemon not running\n{EPHEMERAL_TUI_NOTE}");
                }
            }
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
    });

    if probe.status == DaemonStatus::Running {
        let response = DaemonClient::connect(&probe.paths.socket)
            .await?
            .request_ok(Request::DaemonStatus)
            .await?;
        let Response::DaemonStatus {
            pid,
            uptime_secs,
            active_sessions,
            socket_path,
            daemon_version,
            protocol_version,
            paused_sessions,
            database_path,
            schema_version,
        } = response
        else {
            bail!("unexpected daemon status response: {response:?}");
        };
        value = serde_json::json!({
            "status": "running",
            "pid": pid,
            "uptime_secs": uptime_secs,
            "active_sessions": active_sessions,
            "paused_sessions": paused_sessions,
            "socket_path": socket_path,
            "daemon_version": daemon_version,
            "protocol_version": protocol_version,
            "database_path": database_path,
            "schema_version": schema_version,
        });
    }

    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}

fn daemon_status_name(status: DaemonStatus) -> &'static str {
    match status {
        DaemonStatus::Running => "running",
        DaemonStatus::LivePidSocketUnreachable => "live_pid_socket_unreachable",
        DaemonStatus::UnverifiedPid => "unverified_pid",
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
            | DaemonStatus::LivePidSocketUnreachable
            | DaemonStatus::UnverifiedPid
    )
}

fn restart_release_timeout_for_stop_path(grace: Option<u64>, stop_via_socket: bool) -> Duration {
    if stop_via_socket {
        daemon::restart_release_timeout(grace)
    } else {
        daemon::restart_release_timeout(None)
    }
}

fn restart_started_message(restarted: bool, pid: u32, socket: &std::path::Path) -> String {
    if restarted {
        format!(
            "daemon: restarted (pid {pid})\n  socket: {}",
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
        EPHEMERAL_TUI_NOTE, restart_release_timeout_for_stop_path, restart_should_stop,
        restart_started_message, validate_grace,
    };
    use crate::daemon::{self, DaemonStatus};
    use std::time::Duration;

    #[test]
    fn stale_and_not_running_note_mentions_ephemeral_tui_without_discovery() {
        assert!(EPHEMERAL_TUI_NOTE.contains("live TUI"));
        assert!(EPHEMERAL_TUI_NOTE.contains("separate ephemeral daemon"));
        assert!(!EPHEMERAL_TUI_NOTE.contains("pid"));
        assert!(!EPHEMERAL_TUI_NOTE.contains("socket"));
    }

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
        assert!(restart_should_stop(DaemonStatus::LivePidSocketUnreachable));
        assert!(restart_should_stop(DaemonStatus::UnverifiedPid));
        assert!(!restart_should_stop(DaemonStatus::Stale));
        assert!(!restart_should_stop(DaemonStatus::NotRunning));
    }

    #[test]
    fn restart_output_strings_distinguish_restarted_from_started() {
        let socket = std::path::Path::new("/tmp/cockpit.sock");
        assert_eq!(
            restart_started_message(true, 123, socket),
            "daemon: restarted (pid 123)\n  socket: /tmp/cockpit.sock"
        );
        assert_eq!(
            restart_started_message(false, 456, socket),
            "daemon: was not running; started (pid 456)\n  socket: /tmp/cockpit.sock"
        );
    }

    #[test]
    fn restart_fallback_release_wait_uses_default_grace_when_override_cannot_be_forwarded() {
        assert_eq!(
            restart_release_timeout_for_stop_path(Some(0), true),
            Duration::from_secs(2)
        );
        assert_eq!(
            restart_release_timeout_for_stop_path(Some(0), false),
            daemon::restart_release_timeout(None)
        );
    }
}
