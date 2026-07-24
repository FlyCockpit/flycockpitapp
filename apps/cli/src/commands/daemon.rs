//! `cockpit daemon` subcommands.

use anyhow::{Result, bail};
use std::path::Path;
use std::time::Duration;

use crate::cli::DaemonCommand;
use crate::daemon::client::DaemonClient;
use crate::daemon::proto::{self, Request, Response};
use crate::daemon::{self, DaemonPaths, DaemonStatus};

const EPHEMERAL_TUI_NOTE: &str =
    "  note: a live TUI may still be connected to a separate ephemeral daemon.";
const MAX_STOP_GRACE_SECS: u64 = 24 * 60 * 60;
const PROTOCOL_MISMATCH_STATUS_REMEDY: &str =
    "run `cockpit daemon restart` to restart the daemon on this version";

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
        value = running_json_status(RunningJsonStatus {
            pid,
            uptime_secs,
            active_sessions,
            paused_sessions,
            socket_path,
            daemon_version,
            protocol_version,
            database_path,
            schema_version,
        });
    }

    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DaemonVersions {
    daemon_version: String,
    protocol_version: u32,
}

enum RunningStatusVersionRead {
    Versions(DaemonVersions),
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
}

async fn read_daemon_versions(socket: &Path) -> RunningStatusVersionRead {
    let response = match request_daemon_status(socket).await {
        Ok(Ok(response)) => response,
        Ok(Err(error)) if is_protocol_mismatch_status_error(&error) => {
            return RunningStatusVersionRead::ProtocolMismatch;
        }
        Ok(Err(error)) => {
            return RunningStatusVersionRead::ReadFailed(format!("daemon error: {error}"));
        }
        Err(error) => {
            let error = error.to_string();
            if is_envelope_gate_protocol_mismatch(&error) {
                return RunningStatusVersionRead::ProtocolMismatch;
            }
            return RunningStatusVersionRead::ReadFailed(error);
        }
    };

    match response {
        Response::DaemonStatus {
            daemon_version,
            protocol_version,
            ..
        } => RunningStatusVersionRead::Versions(DaemonVersions {
            daemon_version,
            protocol_version,
        }),
        other => RunningStatusVersionRead::ReadFailed(format!(
            "unexpected daemon status response: {other:?}"
        )),
    }
}

fn is_protocol_mismatch_status_error(error: &proto::ErrorPayload) -> bool {
    error.code == proto::ErrorCode::ProtocolVersion
        || is_envelope_gate_protocol_mismatch(&error.message)
}

fn is_envelope_gate_protocol_mismatch(message: &str) -> bool {
    message.contains("wire protocol version mismatch")
        || matches!(
            message,
            "daemon connection closed"
                | "daemon client task has stopped"
                | "daemon client dropped reply channel"
        )
}

async fn request_daemon_status(
    socket: &Path,
) -> Result<std::result::Result<Response, proto::ErrorPayload>> {
    DaemonClient::connect(socket)
        .await?
        .request(Request::DaemonStatus)
        .await
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
    } else if let Some(error) = read_error {
        output.push_str(&format!("\n  could not read daemon version: {error}"));
    }
    output
}

fn render_incompatible_protocol_status(socket: &str, hello: &proto::DaemonHello) -> String {
    format!(
        "daemon: running but speaks an incompatible protocol\n  socket: {socket}\n  daemon: {} (protocol v{})\n  client: {} (protocol v{}, supports v{}..=v{})\n  {}",
        hello.daemon_version,
        hello.protocol_version,
        proto::DAEMON_VERSION,
        proto::PROTOCOL_VERSION,
        proto::MIN_SUPPORTED_PROTOCOL_VERSION,
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
        "pid": status.pid,
        "uptime_secs": status.uptime_secs,
        "active_sessions": status.active_sessions,
        "paused_sessions": status.paused_sessions,
        "socket_path": status.socket_path,
        "daemon_version": status.daemon_version,
        "protocol_version": status.protocol_version,
        "database_path": status.database_path,
        "schema_version": status.schema_version,
        "version_skew": version_skew_reason.is_some(),
        "version_skew_reason": version_skew_reason,
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
        DaemonVersions, EPHEMERAL_TUI_NOTE, RunningJsonStatus, incompatible_protocol_json_status,
        render_incompatible_protocol_status, render_running_status,
        restart_release_timeout_for_stop_path, restart_should_stop, restart_started_message,
        running_json_status, validate_grace, version_skew_reason,
    };
    use crate::daemon::proto;
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
        assert!(restart_should_stop(DaemonStatus::IncompatibleProtocol));
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

    #[test]
    fn daemon_status_version_lines_render_for_matching_versions() {
        let versions = DaemonVersions {
            daemon_version: proto::DAEMON_VERSION.to_string(),
            protocol_version: proto::PROTOCOL_VERSION,
        };

        let output = render_running_status("/tmp/cockpit.sock", Some(&versions), None);

        assert_eq!(
            output,
            format!(
                "daemon: running\n  socket: /tmp/cockpit.sock\n  daemon: {} (protocol v{})\n  client: {} (protocol v{})",
                proto::DAEMON_VERSION,
                proto::PROTOCOL_VERSION,
                proto::DAEMON_VERSION,
                proto::PROTOCOL_VERSION
            )
        );
    }

    #[test]
    fn daemon_status_version_skew_older_daemon_names_restart() {
        let protocol_version = proto::PROTOCOL_VERSION.saturating_sub(1);
        assert!(protocol_version < proto::PROTOCOL_VERSION);
        let versions = DaemonVersions {
            daemon_version: proto::DAEMON_VERSION.to_string(),
            protocol_version,
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
                "daemon: running but speaks an incompatible protocol\n  socket: /tmp/cockpit.sock\n  daemon: 0.0.old (protocol v0)\n  client: {} (protocol v{}, supports v{}..=v{})\n  run `cockpit daemon restart` to restart the daemon on this version",
                proto::DAEMON_VERSION,
                proto::PROTOCOL_VERSION,
                proto::MIN_SUPPORTED_PROTOCOL_VERSION,
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
    fn daemon_status_version_classifies_envelope_gate_refusal_as_protocol_mismatch() {
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
        assert!(super::is_protocol_mismatch_status_error(
            &envelope_gate_error
        ));
        assert!(super::is_protocol_mismatch_status_error(
            &client_task_stopped_error
        ));
        assert!(super::is_protocol_mismatch_status_error(
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
            schema_version: 7,
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
                "pid",
                "protocol_version",
                "schema_version",
                "socket_path",
                "status",
                "uptime_secs",
                "version_skew",
                "version_skew_reason",
            ]
        );
        assert_eq!(value["status"], "running");
        assert!(value["pid"].is_u64());
        assert!(value["uptime_secs"].is_u64());
        assert!(value["active_sessions"].is_u64());
        assert!(value["paused_sessions"].is_u64());
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
}
