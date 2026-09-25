//! Readability helpers for `daemon.log`.
//!
//! `daemon.log` is appended across daemon runs and only rotated by size, and
//! the supervisor and worker share it as their stderr. Without run separation
//! a stale error from an older binary reads like a current one. This module
//! owns the run marker written at the start of each run, the timestamp/role/pid
//! prefix for the plain stderr lines daemon processes write, and the
//! current-run slicing the spawn error tail uses.
//!
//! Security: markers and prefixes carry only a timestamp, the process role,
//! its pid, and the build version. Never add environment values, paths, or
//! configuration here.

use std::fmt;
use std::io::Write;
use std::sync::OnceLock;

/// Recognizable prefix of the line that starts a new daemon run in
/// `daemon.log`. [`current_run_lines`] slices the log tail at the last line
/// beginning with it.
pub const DAEMON_LOG_RUN_MARKER_PREFIX: &str = "=== cockpit daemon run";

/// Build version recorded in the run marker. No build script exposes a git
/// commit today, so the marker records only the package version.
const DAEMON_LOG_BUILD_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Which daemon process wrote a `daemon.log` line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DaemonLogRole {
    /// The CLI process that spawns a detached supervisor.
    Launcher,
    /// The long-lived supervisor process.
    Supervisor,
    /// A supervised worker process.
    Worker,
}

impl DaemonLogRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Launcher => "launcher",
            Self::Supervisor => "supervisor",
            Self::Worker => "worker",
        }
    }
}

impl fmt::Display for DaemonLogRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

static PROCESS_ROLE: OnceLock<DaemonLogRole> = OnceLock::new();

/// Record that this process is a daemon process whose stderr is
/// `daemon.log`. The first call wins; later calls are ignored.
pub fn set_process_role(role: DaemonLogRole) {
    let _ = PROCESS_ROLE.set(role);
}

/// The daemon role of this process, if it is a supervisor or worker.
pub fn process_role() -> Option<DaemonLogRole> {
    PROCESS_ROLE.get().copied()
}

fn rfc3339_utc(now: chrono::DateTime<chrono::Utc>) -> String {
    now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

/// The run-marker line (without trailing newline).
pub fn run_marker_line(
    role: DaemonLogRole,
    pid: u32,
    now: chrono::DateTime<chrono::Utc>,
) -> String {
    format!(
        "{DAEMON_LOG_RUN_MARKER_PREFIX} {} pid={pid} role={role} version={DAEMON_LOG_BUILD_VERSION} ===",
        rfc3339_utc(now),
    )
}

/// Append a run marker for this process to `log`. Best effort: a failed
/// write must not stop the daemon from booting.
pub fn write_run_marker(mut log: impl Write, role: DaemonLogRole) {
    let line = run_marker_line(role, std::process::id(), chrono::Utc::now());
    let _ = writeln!(log, "{line}");
    let _ = log.flush();
}

/// Prefix for one plain stderr line: `<rfc3339> [<role> <pid>]`.
pub fn line_prefix(role: DaemonLogRole, pid: u32, now: chrono::DateTime<chrono::Utc>) -> String {
    format!("{} [{role} {pid}]", rfc3339_utc(now))
}

/// Format one stderr line, prefixed with a timestamp, role, and pid when
/// this process is a daemon process (its stderr is `daemon.log`). Other
/// processes get the line unchanged.
pub fn stderr_line(args: fmt::Arguments<'_>) -> String {
    match process_role() {
        Some(role) => format!(
            "{} {args}",
            line_prefix(role, std::process::id(), chrono::Utc::now())
        ),
        None => args.to_string(),
    }
}

/// `eprintln!` for daemon processes: every line written to `daemon.log`
/// carries a timestamp and the writer's role and pid.
macro_rules! daemon_eprintln {
    ($($arg:tt)*) => {
        eprintln!(
            "{}",
            $crate::daemon::daemon_log::stderr_line(format_args!($($arg)*))
        )
    };
}
pub(crate) use daemon_eprintln;

/// An error line for a daemon process's own stderr, which is `daemon.log`:
/// the full cause chain with every embedded `daemon.log` tail reduced to its
/// reason, so a failure never copies log lines back into the log (nested,
/// ever-growing tails within one run).
pub fn error_text_for_daemon_log(error: &anyhow::Error) -> String {
    super::spawn_notify::error_without_log_tail(error)
}

/// Keep only the lines of `text` that belong to the current run: the last
/// run-marker line and everything after it. When the text holds no marker
/// (an older log, or the marker scrolled out of the read window), every line
/// is returned. A marker with nothing after it yields no lines: the current
/// run has not written anything worth showing yet.
pub fn current_run_lines(text: &str) -> Vec<&str> {
    let lines: Vec<&str> = text.lines().collect();
    match lines
        .iter()
        .rposition(|line| line.starts_with(DAEMON_LOG_RUN_MARKER_PREFIX))
    {
        Some(index) if index + 1 == lines.len() => Vec::new(),
        Some(index) => lines[index..].to_vec(),
        None => lines,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone as _;

    fn fixed_now() -> chrono::DateTime<chrono::Utc> {
        chrono::Utc
            .with_ymd_and_hms(2026, 9, 23, 12, 34, 56)
            .single()
            .expect("valid fixed timestamp")
    }

    #[test]
    fn run_marker_line_names_time_pid_role_and_version() {
        let line = run_marker_line(DaemonLogRole::Supervisor, 4242, fixed_now());

        assert!(line.starts_with(DAEMON_LOG_RUN_MARKER_PREFIX), "{line}");
        assert_eq!(
            line,
            format!(
                "=== cockpit daemon run 2026-09-23T12:34:56.000Z pid=4242 role=supervisor version={} ===",
                env!("CARGO_PKG_VERSION")
            )
        );
    }

    #[test]
    fn write_run_marker_appends_one_marker_line() {
        let mut buffer = b"previous run line\n".to_vec();
        write_run_marker(&mut buffer, DaemonLogRole::Launcher);
        let text = String::from_utf8(buffer).expect("utf8");
        let lines = text.lines().collect::<Vec<_>>();

        assert_eq!(lines.len(), 2, "{text}");
        assert!(lines[1].starts_with(DAEMON_LOG_RUN_MARKER_PREFIX), "{text}");
        assert!(
            lines[1].contains(&format!("pid={} ", std::process::id())),
            "{text}"
        );
        assert!(lines[1].contains("role=launcher"), "{text}");
        assert!(text.ends_with('\n'));
    }

    #[test]
    fn line_prefix_carries_timestamp_role_and_pid() {
        assert_eq!(
            line_prefix(DaemonLogRole::Worker, 7, fixed_now()),
            "2026-09-23T12:34:56.000Z [worker 7]"
        );
    }

    #[test]
    fn current_run_lines_start_at_the_last_marker() {
        let text = format!(
            "old-error\n{DAEMON_LOG_RUN_MARKER_PREFIX} a ===\nold-run-line\n{DAEMON_LOG_RUN_MARKER_PREFIX} b ===\nnew-line-1\nnew-line-2\n"
        );

        assert_eq!(
            current_run_lines(&text),
            vec![
                format!("{DAEMON_LOG_RUN_MARKER_PREFIX} b ==="),
                "new-line-1".to_string(),
                "new-line-2".to_string(),
            ]
        );
    }

    #[test]
    fn current_run_lines_fall_back_to_every_line_without_a_marker() {
        assert_eq!(
            current_run_lines("line-a\nline-b\n"),
            vec!["line-a", "line-b"]
        );
    }

    #[test]
    fn current_run_lines_are_empty_when_the_run_wrote_only_its_marker() {
        let text = format!("stale-error\n{DAEMON_LOG_RUN_MARKER_PREFIX} x ===\n");
        assert!(current_run_lines(&text).is_empty());
    }
}
