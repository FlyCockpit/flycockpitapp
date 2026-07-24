use std::path::Path;
use std::sync::{Mutex as StdMutex, OnceLock};
use std::time::{Duration, Instant};

use anyhow::Result;

use crate::daemon::client::DaemonClient;
use crate::daemon::proto::{self, Request, Response};
use crate::daemon::{self, DaemonPaths};

pub const DEFAULT_SKEW_RESTART_COOLDOWN: Duration = Duration::from_secs(5 * 60);

static LAST_ATTEMPT: OnceLock<StdMutex<Option<Instant>>> = OnceLock::new();

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SkewKind {
    None,
    Compatible(String),
    IncompatibleProtocol,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkewAction {
    DoNothing,
    SurfaceNoticeOnly,
    AttemptRestartIfIdle,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SkewRestartOutcome {
    NoSkew,
    InProcess,
    NoticeOnly {
        reason: Option<String>,
    },
    Refused {
        reason: Option<String>,
        skew_reason: Option<String>,
    },
    Restarted {
        pid: u32,
        reason: Option<String>,
    },
}

pub fn skew_restart_action(
    in_process: bool,
    skew: &SkewKind,
    last_attempt: Option<Instant>,
    now: Instant,
    cooldown: Duration,
) -> SkewAction {
    if in_process {
        return SkewAction::DoNothing;
    }
    match skew {
        SkewKind::None => SkewAction::DoNothing,
        SkewKind::IncompatibleProtocol => SkewAction::SurfaceNoticeOnly,
        SkewKind::Compatible(_) => {
            if let Some(last) = last_attempt
                && now.checked_duration_since(last).unwrap_or_default() < cooldown
            {
                return SkewAction::SurfaceNoticeOnly;
            }
            SkewAction::AttemptRestartIfIdle
        }
    }
}

pub fn version_skew_kind(daemon_version: &str, protocol_version: u32) -> SkewKind {
    match version_skew_reason(daemon_version, protocol_version) {
        Some(reason) => SkewKind::Compatible(reason),
        None => SkewKind::None,
    }
}

pub fn version_skew_reason(daemon_version: &str, protocol_version: u32) -> Option<String> {
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

pub async fn restart_skewed_daemon_if_idle(paths: &DaemonPaths) -> Result<SkewRestartOutcome> {
    restart_skewed_daemon_if_idle_with_cooldown(paths, DEFAULT_SKEW_RESTART_COOLDOWN).await
}

pub async fn restart_skewed_daemon_if_idle_with_cooldown(
    paths: &DaemonPaths,
    cooldown: Duration,
) -> Result<SkewRestartOutcome> {
    if crate::daemon::server::in_process_context(&paths.socket).is_some() {
        return Ok(SkewRestartOutcome::InProcess);
    }

    let skew = read_skew_kind(&paths.socket).await?;
    let now = Instant::now();
    let action = {
        let guard = last_attempt_slot()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        skew_restart_action(false, &skew, *guard, now, cooldown)
    };

    match action {
        SkewAction::DoNothing => Ok(SkewRestartOutcome::NoSkew),
        SkewAction::SurfaceNoticeOnly => Ok(SkewRestartOutcome::NoticeOnly {
            reason: skew.notice_reason(),
        }),
        SkewAction::AttemptRestartIfIdle => {
            record_attempt(now);
            let skew_reason = skew.notice_reason();
            attempt_restart_if_idle(paths, skew_reason).await
        }
    }
}

async fn read_skew_kind(socket: &Path) -> Result<SkewKind> {
    let result = match DaemonClient::connect(socket)
        .await?
        .request(Request::DaemonStatus)
        .await
    {
        Ok(result) => result,
        Err(error) if is_protocol_mismatch_message(&error.to_string()) => {
            return Ok(SkewKind::IncompatibleProtocol);
        }
        Err(error) => return Err(error),
    };
    let response = match result {
        Ok(response) => response,
        Err(error) if is_protocol_mismatch_error(&error) => {
            return Ok(SkewKind::IncompatibleProtocol);
        }
        Err(error) => anyhow::bail!("daemon status request failed: {error}"),
    };
    match response {
        Response::DaemonStatus {
            daemon_version,
            protocol_version,
            ..
        } => Ok(version_skew_kind(&daemon_version, protocol_version)),
        other => anyhow::bail!("unexpected daemon status response: {other:?}"),
    }
}

async fn attempt_restart_if_idle(
    paths: &DaemonPaths,
    skew_reason: Option<String>,
) -> Result<SkewRestartOutcome> {
    let old_pid = daemon::daemon_pid(paths);
    let result = match DaemonClient::connect(&paths.socket)
        .await?
        .request(Request::RestartIfIdle)
        .await
    {
        Ok(result) => result,
        Err(error) if is_protocol_mismatch_message(&error.to_string()) => {
            return Ok(SkewRestartOutcome::NoticeOnly {
                reason: skew_reason,
            });
        }
        Err(error) => return Err(error),
    };
    let response = match result {
        Ok(response) => response,
        Err(error)
            if is_protocol_mismatch_error(&error) || is_unsupported_restart_request(&error) =>
        {
            return Ok(SkewRestartOutcome::NoticeOnly {
                reason: skew_reason,
            });
        }
        Err(error) => anyhow::bail!("restart-if-idle request failed: {error}"),
    };

    let Response::RestartDecision {
        will_restart,
        reason,
    } = response
    else {
        anyhow::bail!("unexpected restart-if-idle response: {response:?}");
    };

    if !will_restart {
        return Ok(SkewRestartOutcome::Refused {
            reason,
            skew_reason,
        });
    }

    if !daemon::wait_for_restart_release(paths, old_pid, daemon::restart_release_timeout(None))
        .await
    {
        let reason = skew_reason.map(|reason| {
            format!("{reason}; auto-restart timed out waiting for the old daemon to exit")
        });
        return Ok(SkewRestartOutcome::NoticeOnly { reason });
    }
    if matches!(
        daemon::discover().await.status,
        daemon::DaemonStatus::Running
    ) {
        return Ok(SkewRestartOutcome::Restarted {
            pid: 0,
            reason: skew_reason,
        });
    }
    let no_sandbox = daemon::derive_restart_no_sandbox(paths, false);
    let pid = daemon::spawn_detached_with_resume(no_sandbox, true)?;
    Ok(SkewRestartOutcome::Restarted {
        pid,
        reason: skew_reason,
    })
}

impl SkewKind {
    fn notice_reason(&self) -> Option<String> {
        match self {
            SkewKind::None => None,
            SkewKind::Compatible(reason) => Some(reason.clone()),
            SkewKind::IncompatibleProtocol => Some(
                "daemon wire protocol is incompatible; run `cockpit daemon restart`".to_string(),
            ),
        }
    }
}

fn is_protocol_mismatch_error(error: &proto::ErrorPayload) -> bool {
    error.code == proto::ErrorCode::ProtocolVersion
        || error.message.contains("wire protocol version mismatch")
}

fn is_protocol_mismatch_message(message: &str) -> bool {
    message.contains("wire protocol version mismatch")
}

fn is_unsupported_restart_request(error: &proto::ErrorPayload) -> bool {
    error.message.contains("restart_if_idle")
        || error.message.contains("RestartIfIdle")
        || error.message.contains("unsupported request")
}

fn last_attempt_slot() -> &'static StdMutex<Option<Instant>> {
    LAST_ATTEMPT.get_or_init(|| StdMutex::new(None))
}

fn record_attempt(now: Instant) {
    *last_attempt_slot()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(now);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skew_restart_action_in_process_does_nothing() {
        let now = Instant::now();
        assert_eq!(
            skew_restart_action(
                true,
                &SkewKind::Compatible("skew".to_string()),
                None,
                now,
                Duration::from_secs(300),
            ),
            SkewAction::DoNothing
        );
    }

    #[test]
    fn skew_restart_action_none_does_nothing() {
        let now = Instant::now();
        assert_eq!(
            skew_restart_action(false, &SkewKind::None, None, now, Duration::from_secs(300)),
            SkewAction::DoNothing
        );
    }

    #[test]
    fn skew_restart_action_incompatible_protocol_surfaces_notice_only() {
        let now = Instant::now();
        assert_eq!(
            skew_restart_action(
                false,
                &SkewKind::IncompatibleProtocol,
                None,
                now,
                Duration::from_secs(300),
            ),
            SkewAction::SurfaceNoticeOnly
        );
    }

    #[test]
    fn skew_restart_action_compatible_within_cooldown_surfaces_notice_only() {
        let now = Instant::now();
        assert_eq!(
            skew_restart_action(
                false,
                &SkewKind::Compatible("skew".to_string()),
                Some(now - Duration::from_secs(10)),
                now,
                Duration::from_secs(300),
            ),
            SkewAction::SurfaceNoticeOnly
        );
    }

    #[test]
    fn skew_restart_action_compatible_past_cooldown_attempts_restart_if_idle() {
        let now = Instant::now();
        assert_eq!(
            skew_restart_action(
                false,
                &SkewKind::Compatible("skew".to_string()),
                Some(now - Duration::from_secs(301)),
                now,
                Duration::from_secs(300),
            ),
            SkewAction::AttemptRestartIfIdle
        );
    }

    #[tokio::test]
    async fn restart_skewed_daemon_if_idle_skips_in_process_context() {
        let _guard = crate::test_env::lock_async().await;
        let root = tempfile::tempdir().expect("daemon path tempdir");
        let paths = DaemonPaths {
            socket: root.path().join("cockpit-in-process-test.sock"),
            pid_file: root.path().join("cockpit-in-process-test.pid"),
            ephemeral: true,
        };
        let db = crate::db::Db::open_in_memory().expect("in-memory daemon db");
        let ctx = crate::daemon::boot_in_process_with_db(paths.clone(), db)
            .expect("boot in-process daemon context");

        let outcome = restart_skewed_daemon_if_idle_with_cooldown(&paths, Duration::ZERO)
            .await
            .expect("in-process restart check");

        assert_eq!(outcome, SkewRestartOutcome::InProcess);
        assert!(
            !paths.socket.exists(),
            "in-process restart check must not touch the socket transport"
        );
        drop(ctx);
    }
}
