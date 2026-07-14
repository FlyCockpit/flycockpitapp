//! `cockpit daemon` subcommands.

use anyhow::{Result, bail};

use crate::cli::DaemonCommand;
use crate::daemon::client::DaemonClient;
use crate::daemon::proto::Request;
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
            if resume_all_sessions {
                daemon::run_foreground_with_resume(paths, true).await
            } else {
                daemon::run_foreground(paths).await
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
            let should_stop =
                old_pid.is_some() || !matches!(discovered.status, DaemonStatus::NotRunning);
            let replacement_no_sandbox = if should_stop {
                daemon::derive_restart_no_sandbox(&paths, no_sandbox)
            } else {
                no_sandbox
            };
            let resume = !no_resume;

            if should_stop {
                if let Ok(client) = DaemonClient::connect(&paths.socket).await {
                    client
                        .request_ok(Request::StopDaemon { grace_secs: grace })
                        .await?;
                } else {
                    let _ = daemon::stop(&paths)?;
                }
                daemon::wait_for_restart_release(
                    &paths,
                    old_pid,
                    daemon::restart_release_timeout(grace),
                )
                .await;
            }

            let pid = daemon::spawn_detached_with_resume(replacement_no_sandbox, resume)?;
            if should_stop {
                println!(
                    "daemon: restarted (pid {pid})\n  socket: {}",
                    paths.socket.display()
                );
            } else {
                println!(
                    "daemon: was not running; started (pid {pid})\n  socket: {}",
                    paths.socket.display()
                );
            }
            Ok(())
        }
        DaemonCommand::Status => {
            let probe = daemon::discover().await;
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

fn validate_grace(grace: Option<u64>) -> Result<()> {
    if let Some(secs) = grace
        && secs > MAX_STOP_GRACE_SECS
    {
        bail!("--grace must be <= {MAX_STOP_GRACE_SECS} seconds");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{EPHEMERAL_TUI_NOTE, validate_grace};

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
}
