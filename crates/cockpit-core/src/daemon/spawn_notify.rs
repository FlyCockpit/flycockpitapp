//! One-shot parent←child boot-status endpoint, daemon log capture, and
//! spawn-wait timeout.
//!
//! The parent binds a private notify endpoint, passes its path (Unix) or pipe
//! name (Windows) in [`super::DAEMON_SPAWN_NOTIFY_ENV`], and waits for a single
//! `Ok{socket}` / `AddrInUse{path}` / `Err{reason}` line. The child reports
//! after bind, or on any boot failure. A child that exits or stays silent is
//! killed (timeout) and the last lines of `daemon.log` are appended to the
//! error, matching the excoc lifecycle log-tail.

use std::io::Write;
#[cfg(unix)]
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::Child;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
#[cfg(unix)]
use std::sync::atomic::AtomicU64;

use super::{
    DAEMON_LOG_FILE, DAEMON_LOG_MAX_BYTES, DAEMON_LOG_ROTATED_FILE, DAEMON_SPAWN_NOTIFY_ENV,
    DaemonBindInUse,
};

const LOG_TAIL_LINES: usize = 20;
const WAIT_POLL: Duration = Duration::from_millis(10);
const REAP_GRACE: Duration = Duration::from_millis(200);
#[cfg(unix)]
const PER_CONNECTION_READ_CAP: Duration = Duration::from_secs(1);
/// How long a reporter keeps its notify connection open waiting for the
/// parent to verify it and read the report before giving up.
#[cfg(unix)]
const REPORTER_LINGER_CAP: Duration = Duration::from_secs(5);
#[cfg(unix)]
const MIN_NOTIFY_READ_TIMEOUT: Duration = Duration::from_millis(1);
#[cfg(unix)]
const NOTIFY_BIND_ATTEMPTS: u32 = 32;

#[cfg(unix)]
static NOTIFY_SEQ: AtomicU64 = AtomicU64::new(1);
static SPAWN_REPORT_SENT: AtomicBool = AtomicBool::new(false);

/// Parsed one-shot boot report from the child.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SpawnReport {
    Ready { socket: PathBuf },
    AddrInUse { path: PathBuf },
    Failed { reason: String },
}

pub(crate) struct SpawnNotifyServer {
    #[cfg(unix)]
    listener: std::os::unix::net::UnixListener,
    #[cfg(unix)]
    path: PathBuf,
    #[cfg(windows)]
    pipe_name: String,
    #[cfg(windows)]
    listener: crate::daemon::windows_pipe::NamedPipeListener,
}

impl SpawnNotifyServer {
    pub(crate) fn bind() -> Result<Self> {
        #[cfg(unix)]
        {
            unix_bind()
        }
        #[cfg(windows)]
        {
            windows_bind()
        }
        #[cfg(not(any(unix, windows)))]
        {
            bail!("daemon spawn notify is not supported on this platform")
        }
    }

    pub(crate) fn endpoint(&self) -> String {
        #[cfg(unix)]
        {
            self.path.to_string_lossy().into_owned()
        }
        #[cfg(windows)]
        {
            self.pipe_name.clone()
        }
        #[cfg(not(any(unix, windows)))]
        {
            String::new()
        }
    }

    pub(crate) fn wait(
        self,
        child: &mut Child,
        log_path: &Path,
        timeout: Duration,
    ) -> Result<SpawnReport> {
        #[cfg(unix)]
        {
            unix_wait(self, child, log_path, timeout)
        }
        #[cfg(windows)]
        {
            windows_wait(self, child, log_path, timeout)
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = (child, log_path, timeout);
            bail!("daemon spawn notify is not supported on this platform")
        }
    }
}

#[cfg(unix)]
impl Drop for SpawnNotifyServer {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Child-side report. No-op when the parent did not pass a notify endpoint.
pub(crate) fn report_ready(socket: &Path) {
    let socket = sanitize_report_payload(&socket.display().to_string());
    report_line(&format!("Ok{{{socket}}}"));
}

pub(crate) fn report_err(error: &anyhow::Error) {
    if let Some(bind) = error.downcast_ref::<DaemonBindInUse>() {
        let path = sanitize_report_payload(&bind.path.display().to_string());
        report_line(&format!("AddrInUse{{{path}}}"));
        return;
    }
    let reason = sanitize_report_payload(&format!("{error:#}"));
    report_line(&format!("Err{{{reason}}}"));
}

fn report_line(line: &str) {
    let Ok(endpoint) = std::env::var(DAEMON_SPAWN_NOTIFY_ENV) else {
        return;
    };
    if endpoint.is_empty() {
        return;
    }
    if SPAWN_REPORT_SENT
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return;
    }
    if let Err(error) = write_report(&endpoint, line) {
        SPAWN_REPORT_SENT.store(false, Ordering::Release);
        tracing::warn!(%error, endpoint, "failed to report daemon spawn status to parent");
    }
}

fn write_report(endpoint: &str, line: &str) -> Result<()> {
    let payload = format!("{line}\n");
    #[cfg(unix)]
    {
        use std::io::Read as _;
        let mut stream = std::os::unix::net::UnixStream::connect(Path::new(endpoint))
            .with_context(|| format!("connecting spawn notify socket {endpoint}"))?;
        stream
            .write_all(payload.as_bytes())
            .context("writing spawn notify report")?;
        // Keep the connection open until the parent has verified us and read
        // the line (it closes its end afterwards). macOS answers
        // `LOCAL_PEERPID` with ENOTCONN once the peer has closed, so closing
        // right after the write lets the parent's PID-bound peer check fail
        // and silently drop the one-shot report. Bounded so a vanished parent
        // cannot stall the daemon.
        let _ = stream.shutdown(std::net::Shutdown::Write);
        stream
            .set_read_timeout(Some(REPORTER_LINGER_CAP))
            .context("setting spawn notify linger timeout")?;
        let mut sink = [0u8; 64];
        loop {
            match stream.read(&mut sink) {
                Ok(0) => break,
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => break,
            }
        }
        Ok(())
    }
    #[cfg(windows)]
    {
        let pipe = cockpit_host::named_pipe::parse_pipe_name(endpoint)
            .with_context(|| format!("parsing spawn notify pipe {endpoint}"))?;
        let mut stream = cockpit_host::named_pipe::open_client_pipe_blocking(&pipe)
            .with_context(|| format!("connecting spawn notify pipe {endpoint}"))?;
        stream
            .write_all(payload.as_bytes())
            .context("writing spawn notify report")?;
        Ok(())
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (endpoint, payload);
        bail!("daemon spawn notify is not supported on this platform")
    }
}

pub(crate) fn parse_report_line(line: &str) -> Result<SpawnReport> {
    let line = line.trim();
    if let Some(body) = line.strip_prefix("Ok{") {
        let socket = body
            .strip_suffix('}')
            .ok_or_else(|| anyhow::anyhow!("malformed Ok spawn notify: {line}"))?;
        return Ok(SpawnReport::Ready {
            socket: PathBuf::from(socket),
        });
    }
    if let Some(body) = line.strip_prefix("AddrInUse{") {
        let path = body
            .strip_suffix('}')
            .ok_or_else(|| anyhow::anyhow!("malformed AddrInUse spawn notify: {line}"))?;
        return Ok(SpawnReport::AddrInUse {
            path: PathBuf::from(path),
        });
    }
    if let Some(body) = line.strip_prefix("Err{") {
        let reason = body
            .strip_suffix('}')
            .ok_or_else(|| anyhow::anyhow!("malformed Err spawn notify: {line}"))?;
        return Ok(SpawnReport::Failed {
            reason: reason.to_string(),
        });
    }
    bail!("malformed spawn notify: {line}")
}

fn sanitize_report_payload(reason: &str) -> String {
    reason.replace(['\n', '\r'], " ")
}

pub(crate) fn prepare_daemon_log(state_dir: &Path) -> Result<std::fs::File> {
    cockpit_host::private_fs::ensure_private_dir(state_dir)
        .with_context(|| format!("securing {}", state_dir.display()))?;
    rotate_daemon_log_if_needed(state_dir)?;
    open_daemon_log_append(state_dir)
}

fn rotate_daemon_log_if_needed(state_dir: &Path) -> Result<()> {
    let log_path = state_dir.join(DAEMON_LOG_FILE);
    let Ok(meta) = std::fs::metadata(&log_path) else {
        return Ok(());
    };
    if meta.len() < DAEMON_LOG_MAX_BYTES {
        return Ok(());
    }
    #[cfg(unix)]
    {
        rotate_daemon_log_fd(state_dir)
    }
    #[cfg(not(unix))]
    {
        let rotated = state_dir.join(DAEMON_LOG_ROTATED_FILE);
        let _ = std::fs::remove_file(&rotated);
        std::fs::rename(&log_path, &rotated)
            .with_context(|| format!("rotating {}", log_path.display()))?;
        Ok(())
    }
}

#[cfg(unix)]
fn rotate_daemon_log_fd(state_dir: &Path) -> Result<()> {
    use std::ffi::CString;
    use std::os::fd::AsRawFd;

    let dir_fd = cockpit_host::private_fs::open_private_dir_handle(state_dir)
        .with_context(|| format!("opening {}", state_dir.display()))?;
    let tolerate_enoent = |result: i32| -> std::io::Result<()> {
        if result == 0 {
            return Ok(());
        }
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::NotFound {
            Ok(())
        } else {
            Err(error)
        }
    };
    let current = CString::new(DAEMON_LOG_FILE).context("daemon.log name")?;
    let rotated = CString::new(DAEMON_LOG_ROTATED_FILE).context("daemon.log.1 name")?;
    // SAFETY: `dir_fd` is a live directory fd from `open_private_dir_handle`;
    // `rotated` is a NUL-terminated CString of a trusted basename.
    tolerate_enoent(unsafe { libc::unlinkat(dir_fd.as_raw_fd(), rotated.as_ptr(), 0) })
        .context("removing rotated daemon.log.1")?;
    // SAFETY: both names are NUL-terminated CStrings of trusted basenames;
    // `dir_fd` is still the same live directory fd.
    tolerate_enoent(unsafe {
        libc::renameat(
            dir_fd.as_raw_fd(),
            current.as_ptr(),
            dir_fd.as_raw_fd(),
            rotated.as_ptr(),
        )
    })
    .context("renaming daemon.log to daemon.log.1")?;
    Ok(())
}

fn open_daemon_log_append(state_dir: &Path) -> Result<std::fs::File> {
    #[cfg(unix)]
    {
        cockpit_host::private_fs::open_private_file_at(
            state_dir,
            std::ffi::OsStr::new(DAEMON_LOG_FILE),
            cockpit_host::private_fs::PrivateFileAccess::Append,
            "daemon log",
        )
        .with_context(|| format!("opening {}/{}", state_dir.display(), DAEMON_LOG_FILE))
    }
    #[cfg(not(unix))]
    {
        let path = state_dir.join(DAEMON_LOG_FILE);
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .with_context(|| format!("opening {}", path.display()))
    }
}

/// The last `n` lines of `daemon.log` that belong to the current run: lines
/// before the last run marker (see [`super::daemon_log`]) are earlier runs and
/// are never shown as if they were current. Without a marker in the read
/// window this is simply the last `n` lines.
pub(crate) fn last_log_lines(log_path: &Path, n: usize) -> String {
    let Ok(data) = std::fs::read(log_path) else {
        return String::new();
    };
    const WINDOW: usize = 64 * 1024;
    let slice = if data.len() > WINDOW {
        &data[data.len() - WINDOW..]
    } else {
        &data
    };
    let text = String::from_utf8_lossy(slice);
    let lines = super::daemon_log::current_run_lines(&text);
    lines
        .iter()
        .rev()
        .take(n)
        .copied()
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<Vec<_>>()
        .join("\n")
}

pub(crate) fn error_with_log_tail(
    reason: impl std::fmt::Display,
    log_path: &Path,
) -> anyhow::Error {
    let tail = last_log_lines(log_path, LOG_TAIL_LINES);
    if tail.trim().is_empty() {
        anyhow::anyhow!("{reason}")
    } else {
        anyhow::anyhow!("{reason}\n--- daemon.log (last {LOG_TAIL_LINES} lines) ---\n{tail}")
    }
}

pub(crate) fn report_to_error(report: SpawnReport, log_path: &Path) -> anyhow::Error {
    match report {
        SpawnReport::Ready { socket } => {
            anyhow::anyhow!(
                "daemon reported ready at {} unexpectedly as an error",
                socket.display()
            )
        }
        SpawnReport::AddrInUse { path } => {
            attach_log_tail(anyhow::Error::from(DaemonBindInUse { path }), log_path)
        }
        SpawnReport::Failed { reason } => error_with_log_tail(reason, log_path),
    }
}

fn attach_log_tail(error: anyhow::Error, log_path: &Path) -> anyhow::Error {
    let reason = error.to_string();
    let tail = last_log_lines(log_path, LOG_TAIL_LINES);
    if tail.trim().is_empty() {
        error
    } else {
        error.context(format!(
            "{reason}\n--- daemon.log (last {LOG_TAIL_LINES} lines) ---\n{tail}"
        ))
    }
}

pub(crate) fn kill_spawned_daemon(child: &mut Child) {
    let pid = child.id();
    #[cfg(unix)]
    {
        cockpit_host::process::terminate_process_group(pid);
        let deadline = Instant::now() + REAP_GRACE;
        while Instant::now() < deadline {
            if child.try_wait().ok().flatten().is_some() {
                return;
            }
            std::thread::sleep(WAIT_POLL);
        }
        cockpit_host::process::kill_process_group(pid);
    }
    let _ = child.kill();
    let _ = child.wait();
}

pub(crate) fn reap_or_kill(child: &mut Child) {
    let deadline = Instant::now() + REAP_GRACE;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return,
            Ok(None) if Instant::now() >= deadline => break,
            Ok(None) => std::thread::sleep(WAIT_POLL),
            Err(_) => break,
        }
    }
    kill_spawned_daemon(child);
}

#[cfg(unix)]
fn unix_bind() -> Result<SpawnNotifyServer> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
    use std::os::unix::net::UnixListener;

    for _ in 0..NOTIFY_BIND_ATTEMPTS {
        let path = short_notify_path()?;
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => continue,
            Err(error) => {
                return Err(error).with_context(|| format!("removing leftover {}", path.display()));
            }
        }
        let listener = match UnixListener::bind(&path) {
            Ok(listener) => listener,
            Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => continue,
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("binding spawn notify socket {}", path.display()));
            }
        };
        if let Err(error) = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
        {
            cleanup_notify_socket(&path);
            return Err(error).with_context(|| format!("chmod 0600 {}", path.display()));
        }
        let meta = match std::fs::symlink_metadata(&path) {
            Ok(meta) => meta,
            Err(error) => {
                cleanup_notify_socket(&path);
                return Err(error).with_context(|| format!("stat {}", path.display()));
            }
        };
        let file_type = meta.file_type();
        let mode = meta.mode() & 0o777;
        let owner = meta.uid();
        // SAFETY: `geteuid` has no preconditions and cannot fail.
        let euid = unsafe { libc::geteuid() };
        if !file_type.is_socket() || owner != euid || mode != 0o600 {
            cleanup_notify_socket(&path);
            anyhow::bail!(
                "refusing to use {}: expected owner-only socket (uid {euid}, mode 0600), \
                 got uid {owner} mode {mode:03o}",
                path.display()
            );
        }
        if let Err(error) = listener.set_nonblocking(true) {
            cleanup_notify_socket(&path);
            return Err(error).context("setting spawn notify socket non-blocking");
        }
        return Ok(SpawnNotifyServer { listener, path });
    }
    bail!("could not bind a spawn notify socket after {NOTIFY_BIND_ATTEMPTS} attempts")
}

#[cfg(unix)]
fn cleanup_notify_socket(path: &Path) {
    let _ = std::fs::remove_file(path);
}

#[cfg(unix)]
fn short_notify_path() -> Result<PathBuf> {
    let seq = NOTIFY_SEQ.fetch_add(1, Ordering::Relaxed);
    let name = format!("ck-n-{}-{seq:x}.sock", std::process::id());
    let candidates = [std::env::temp_dir(), PathBuf::from("/tmp")];
    for dir in candidates {
        let path = dir.join(&name);
        if super::unix_socket_path_is_bindable(&path) {
            return Ok(path);
        }
    }
    bail!(
        "could not place a spawn-notify socket shorter than SUN_LEN; set TMPDIR to a shorter directory"
    )
}

#[cfg(unix)]
fn unix_wait(
    server: SpawnNotifyServer,
    child: &mut Child,
    log_path: &Path,
    timeout: Duration,
) -> Result<SpawnReport> {
    let deadline = Instant::now() + timeout;
    loop {
        match server.listener.accept() {
            Ok((stream, _)) => {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    kill_spawned_daemon(child);
                    return Err(spawn_timeout_error(timeout, log_path));
                }
                if remaining < MIN_NOTIFY_READ_TIMEOUT {
                    kill_spawned_daemon(child);
                    return Err(spawn_timeout_error(timeout, log_path));
                }
                if verify_notify_peer(&stream, child.id()).is_ok() {
                    // BSD-derived kernels may inherit O_NONBLOCK from the
                    // listener. Make this bounded read explicitly blocking so
                    // connect-before-write cannot lose the one-shot report.
                    stream
                        .set_nonblocking(false)
                        .context("setting spawn notify stream blocking")?;
                    let read_budget = remaining.min(PER_CONNECTION_READ_CAP);
                    stream
                        .set_read_timeout(Some(read_budget))
                        .context("setting spawn notify read timeout")?;
                    let mut line = String::new();
                    match BufReader::new(stream).read_line(&mut line) {
                        Ok(0) => {}
                        Ok(_) => {
                            if let Ok(report) = parse_report_line(&line) {
                                return Ok(report);
                            }
                        }
                        Err(error)
                            if matches!(
                                error.kind(),
                                std::io::ErrorKind::WouldBlock
                                    | std::io::ErrorKind::TimedOut
                                    | std::io::ErrorKind::Interrupted
                            ) => {}
                        Err(error) => {
                            return Err(error).context("reading spawn notify report");
                        }
                    }
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => {
                return Err(error).context("accepting spawn notify connection");
            }
        }
        match child.try_wait() {
            Ok(Some(_)) => {
                return Err(error_with_log_tail(
                    "daemon exited before reporting ready",
                    log_path,
                ));
            }
            Ok(None) => {}
            Err(error) => {
                return Err(error).context("polling spawned daemon child");
            }
        }
        if Instant::now() >= deadline {
            kill_spawned_daemon(child);
            return Err(spawn_timeout_error(timeout, log_path));
        }
        std::thread::sleep(WAIT_POLL);
    }
}

fn spawn_timeout_error(timeout: Duration, log_path: &Path) -> anyhow::Error {
    error_with_log_tail(
        format!(
            "timed out waiting for daemon to report ready after {}s",
            timeout.as_secs().max(1)
        ),
        log_path,
    )
}

#[cfg(unix)]
fn verify_notify_peer(
    stream: &std::os::unix::net::UnixStream,
    expected_child_pid: u32,
) -> Result<()> {
    let peer = cockpit_host::peer_cred::peer_identity_from_unix_stream(stream)
        .context("reading spawn notify peer credentials")?;
    // SAFETY: `geteuid` has no preconditions and cannot fail.
    let euid = unsafe { libc::geteuid() };
    if peer.uid != euid {
        anyhow::bail!(
            "refusing spawn notify report from uid {} (expected {euid})",
            peer.uid
        );
    }
    if peer.pid != expected_child_pid {
        anyhow::bail!(
            "refusing spawn notify report from pid {} (expected spawned child {expected_child_pid})",
            peer.pid
        );
    }
    Ok(())
}

#[cfg(windows)]
fn windows_bind() -> Result<SpawnNotifyServer> {
    let listener = crate::daemon::windows_pipe::NamedPipeListener::prepare()
        .context("creating spawn notify named pipe")?;
    let pipe_name = listener.pipe_name().as_str().to_string();
    Ok(SpawnNotifyServer {
        pipe_name,
        listener,
    })
}

#[cfg(windows)]
fn unblock_windows_notify_waiter(pipe_name: &str) {
    let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        return;
    };
    let _ = runtime.block_on(async {
        use tokio::net::windows::named_pipe::ClientOptions;
        if let Ok(client) = ClientOptions::new().open(pipe_name) {
            let _ = client;
        }
    });
}

#[cfg(windows)]
fn drop_windows_notify_waiter(pipe_name: &str, join: std::thread::JoinHandle<Result<SpawnReport>>) {
    if !join.is_finished() {
        unblock_windows_notify_waiter(pipe_name);
    }
    let _ = join.join();
}

#[cfg(windows)]
fn windows_wait(
    server: SpawnNotifyServer,
    child: &mut Child,
    log_path: &Path,
    timeout: Duration,
) -> Result<SpawnReport> {
    let SpawnNotifyServer {
        pipe_name,
        listener,
    } = server;
    let child_pid = child.id();
    let join = std::thread::Builder::new()
        .name("cockpit-spawn-notify".to_string())
        .spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .context("building spawn-notify runtime")?;
            runtime.block_on(async move {
                use std::os::windows::io::AsRawHandle;

                let mut listener = listener;
                let stream = tokio::time::timeout(timeout, listener.accept())
                    .await
                    .map_err(|_| anyhow::anyhow!("spawn notify accept timed out"))?
                    .context("accepting spawn notify pipe")?;
                cockpit_host::named_pipe::named_pipe_peer_is_current_user(stream.as_raw_handle())
                    .context("verifying spawn notify pipe user")?;
                let peer = cockpit_host::peer_cred::peer_identity_from_named_pipe(
                    stream.as_raw_handle(),
                )
                .context("reading spawn notify pipe peer identity")?;
                if peer.pid != child_pid {
                    anyhow::bail!(
                        "refusing spawn notify report from pid {} (expected spawned child {child_pid})",
                        peer.pid
                    );
                }
                let mut line = String::new();
                let mut reader = tokio::io::BufReader::new(stream);
                tokio::io::AsyncBufReadExt::read_line(&mut reader, &mut line)
                    .await
                    .context("reading spawn notify report")?;
                parse_report_line(&line)
            })
        })
        .context("starting spawn-notify waiter")?;
    let deadline = Instant::now() + timeout;
    loop {
        if join.is_finished() {
            return join
                .join()
                .map_err(|_| anyhow::anyhow!("spawn-notify waiter panicked"))?;
        }
        match child.try_wait() {
            Ok(Some(_)) => {
                drop_windows_notify_waiter(&pipe_name, join);
                return Err(error_with_log_tail(
                    "daemon exited before reporting ready",
                    log_path,
                ));
            }
            Ok(None) => {}
            Err(error) => {
                drop_windows_notify_waiter(&pipe_name, join);
                return Err(error).context("polling spawned daemon child");
            }
        }
        if Instant::now() >= deadline {
            kill_spawned_daemon(child);
            drop_windows_notify_waiter(&pipe_name, join);
            return Err(spawn_timeout_error(timeout, log_path));
        }
        std::thread::sleep(WAIT_POLL);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    #[test]
    fn parse_report_line_accepts_ok_addr_in_use_and_err() {
        match parse_report_line("Ok{/tmp/cockpit.sock}\n").unwrap() {
            SpawnReport::Ready { socket } => {
                assert_eq!(socket, PathBuf::from("/tmp/cockpit.sock"));
            }
            other => panic!("unexpected {other:?}"),
        }
        match parse_report_line("AddrInUse{/tmp/cockpit.sock}").unwrap() {
            SpawnReport::AddrInUse { path } => {
                assert_eq!(path, PathBuf::from("/tmp/cockpit.sock"));
            }
            other => panic!("unexpected {other:?}"),
        }
        match parse_report_line("AddrInUse{/tmp/brace}.sock}").unwrap() {
            SpawnReport::AddrInUse { path } => {
                assert_eq!(path, PathBuf::from("/tmp/brace}.sock"));
            }
            other => panic!("unexpected {other:?}"),
        }
        match parse_report_line("Err{binding leak-reveal socket}").unwrap() {
            SpawnReport::Failed { reason } => {
                assert_eq!(reason, "binding leak-reveal socket");
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn addr_in_use_report_keeps_dedicated_exit_code_with_log_tail() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join(DAEMON_LOG_FILE);
        std::fs::write(&log_path, "bind-line\n").unwrap();
        let error = report_to_error(
            SpawnReport::AddrInUse {
                path: PathBuf::from("/tmp/cockpit.sock"),
            },
            &log_path,
        );
        assert_eq!(
            super::super::daemon_error_exit_code(&error),
            super::super::DAEMON_BIND_IN_USE_EXIT_CODE
        );
        let display = format!("{error}");
        assert!(
            display.contains("already in use"),
            "Display must show bind refusal for TUI consumers: {display}"
        );
        assert!(
            !display.starts_with("--- daemon.log"),
            "Display must not lead with the log-tail header: {display}"
        );
        assert!(
            display.contains("bind-line"),
            "Display must include the log tail: {display}"
        );
        let chain = format!("{error:#}");
        assert!(
            chain.contains("already in use"),
            "typed bind refusal must remain in the chain: {chain}"
        );
    }

    #[test]
    fn last_log_lines_returns_the_trailing_window() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("daemon.log");
        let mut body = String::new();
        for i in 0..30 {
            body.push_str(&format!("line-{i}\n"));
        }
        std::fs::write(&path, body).unwrap();
        let tail = last_log_lines(&path, 20);
        assert!(tail.starts_with("line-10"), "{tail}");
        assert!(tail.ends_with("line-29"), "{tail}");
        assert!(!tail.contains("line-9"), "{tail}");
    }

    #[test]
    fn last_log_lines_show_only_the_current_run() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(DAEMON_LOG_FILE);
        let mut log = std::fs::File::create(&path).unwrap();
        writeln!(log, "Error: stale failure from an older binary").unwrap();
        super::super::daemon_log::write_run_marker(
            &log,
            super::super::daemon_log::DaemonLogRole::Supervisor,
        );
        writeln!(log, "current-run-line").unwrap();
        drop(log);

        let tail = last_log_lines(&path, 20);
        assert!(
            tail.starts_with(super::super::daemon_log::DAEMON_LOG_RUN_MARKER_PREFIX),
            "{tail}"
        );
        assert!(tail.ends_with("current-run-line"), "{tail}");
        assert!(!tail.contains("stale failure"), "{tail}");

        let error = error_with_log_tail("boot failed", &path);
        let text = format!("{error:#}");
        assert!(text.contains("current-run-line"), "{text}");
        assert!(!text.contains("stale failure"), "{text}");
    }

    #[test]
    fn last_log_lines_without_a_marker_fall_back_to_the_trailing_lines() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(DAEMON_LOG_FILE);
        std::fs::write(&path, "legacy-1\nlegacy-2\nlegacy-3\n").unwrap();

        assert_eq!(last_log_lines(&path, 2), "legacy-2\nlegacy-3");
    }

    #[test]
    fn a_run_with_only_its_marker_attaches_no_stale_tail() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(DAEMON_LOG_FILE);
        let mut log = std::fs::File::create(&path).unwrap();
        writeln!(log, "Error: stale failure from an older binary").unwrap();
        super::super::daemon_log::write_run_marker(
            &log,
            super::super::daemon_log::DaemonLogRole::Launcher,
        );
        drop(log);

        let error = error_with_log_tail("daemon exited before reporting ready", &path);
        assert_eq!(format!("{error:#}"), "daemon exited before reporting ready");
    }

    #[cfg(unix)]
    #[test]
    fn prepare_daemon_log_keeps_earlier_runs_behind_a_launcher_marker() {
        let dir = tempfile::tempdir().unwrap();
        cockpit_host::private_fs::ensure_private_dir(dir.path()).unwrap();
        let log_path = dir.path().join(DAEMON_LOG_FILE);
        std::fs::write(&log_path, "old-run-error\n").unwrap();
        let file = prepare_daemon_log(dir.path()).unwrap();
        super::super::daemon_log::write_run_marker(
            &file,
            super::super::daemon_log::DaemonLogRole::Launcher,
        );
        drop(file);

        let text = std::fs::read_to_string(&log_path).unwrap();
        let lines = text.lines().collect::<Vec<_>>();
        assert_eq!(lines.len(), 2, "{text}");
        assert_eq!(lines[0], "old-run-error");
        assert!(
            lines[1].starts_with(super::super::daemon_log::DAEMON_LOG_RUN_MARKER_PREFIX),
            "{text}"
        );
        assert!(lines[1].contains("role=launcher"), "{text}");
    }

    #[cfg(unix)]
    #[test]
    fn fake_child_err_report_becomes_the_user_facing_error() {
        if let Ok(endpoint) = std::env::var(REPORTER_ENDPOINT_ENV) {
            write_report(&endpoint, "Err{bind failed: test reason}")
                .expect("child writes spawn report");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        cockpit_host::private_fs::ensure_private_dir(dir.path()).unwrap();
        let log_path = dir.path().join(DAEMON_LOG_FILE);
        std::fs::write(&log_path, "ignored\n").unwrap();
        let server = SpawnNotifyServer::bind().unwrap();
        let mut child = spawn_reporter_child(
            "daemon::spawn_notify::tests::fake_child_err_report_becomes_the_user_facing_error",
            &server,
        );
        let report = server
            .wait(&mut child, &log_path, Duration::from_secs(10))
            .expect("notify report");
        let error = report_to_error(report, &log_path);
        let text = format!("{error:#}");
        assert!(
            text.contains("bind failed: test reason"),
            "user-facing error must carry the child's Err payload: {text}"
        );
        let _ = child.wait();
    }

    #[cfg(unix)]
    const REPORTER_ENDPOINT_ENV: &str = "COCKPIT_TEST_SPAWN_NOTIFY_REPORTER_ENDPOINT";

    /// Re-execute this test binary as the spawned child so the reporter's PID
    /// is the one the parent verifies; the child role runs `write_report`.
    #[cfg(unix)]
    fn spawn_reporter_child(test_name: &str, server: &SpawnNotifyServer) -> Child {
        Command::new(std::env::current_exe().expect("test binary"))
            .args(["--exact", test_name, "--nocapture"])
            .env(REPORTER_ENDPOINT_ENV, server.endpoint())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn reporter child")
    }

    /// Regression (macOS): a report written before the parent accepts must
    /// still be verified and delivered. macOS `LOCAL_PEERPID` fails with
    /// ENOTCONN once the peer has closed, so the production reporter lingers
    /// until the parent has read the line. The reporter is this test binary
    /// re-executed as the spawned child, so the PID-bound check is real.
    #[cfg(unix)]
    #[test]
    fn report_written_before_the_parent_accepts_is_verified_and_delivered() {
        if let Ok(endpoint) = std::env::var(REPORTER_ENDPOINT_ENV) {
            // Child role: report through the production writer, then exit.
            write_report(&endpoint, "Ok{/tmp/cockpit-late-accept.sock}")
                .expect("child writes spawn report");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        cockpit_host::private_fs::ensure_private_dir(dir.path()).unwrap();
        let log_path = dir.path().join(DAEMON_LOG_FILE);
        std::fs::write(&log_path, "ignored\n").unwrap();
        let server = SpawnNotifyServer::bind().unwrap();
        let mut child = spawn_reporter_child(
            "daemon::spawn_notify::tests::report_written_before_the_parent_accepts_is_verified_and_delivered",
            &server,
        );
        // Give the reporter time to connect and write before accepting.
        std::thread::sleep(Duration::from_millis(500));
        let report = server
            .wait(&mut child, &log_path, Duration::from_secs(10))
            .expect("late-accepted report must be verified and delivered");
        match report {
            SpawnReport::Ready { socket } => {
                assert_eq!(socket, PathBuf::from("/tmp/cockpit-late-accept.sock"));
            }
            other => panic!("unexpected {other:?}"),
        }
        assert!(child.wait().expect("reap reporter").success());
    }

    #[cfg(unix)]
    #[test]
    fn silent_child_exit_yields_timeout_error_with_log_tail() {
        let dir = tempfile::tempdir().unwrap();
        cockpit_host::private_fs::ensure_private_dir(dir.path()).unwrap();
        let log_path = dir.path().join(DAEMON_LOG_FILE);
        let mut body = String::new();
        for i in 0..25 {
            body.push_str(&format!("boot-line-{i}\n"));
        }
        std::fs::write(&log_path, &body).unwrap();
        let server = SpawnNotifyServer::bind().unwrap();
        let mut child = Command::new("true").spawn().unwrap();
        let error = server
            .wait(&mut child, &log_path, Duration::from_secs(2))
            .expect_err("silent exit must fail");
        let text = format!("{error:#}");
        assert!(
            text.contains("daemon exited before reporting ready"),
            "silent exit must name the child exit: {text}"
        );
        assert!(
            text.contains("boot-line-24"),
            "silent exit must append the log tail: {text}"
        );
        let _ = child.wait();
    }

    #[cfg(unix)]
    #[test]
    fn hanging_child_is_killed_on_timeout_with_log_tail() {
        let dir = tempfile::tempdir().unwrap();
        cockpit_host::private_fs::ensure_private_dir(dir.path()).unwrap();
        let log_path = dir.path().join(DAEMON_LOG_FILE);
        std::fs::write(&log_path, "still-booting\n").unwrap();
        let server = SpawnNotifyServer::bind().unwrap();
        let mut child = Command::new("sleep").arg("30").spawn().unwrap();
        let error = server
            .wait(&mut child, &log_path, Duration::from_millis(200))
            .expect_err("hanging child must time out");
        let text = format!("{error:#}");
        assert!(
            text.contains("timed out waiting for daemon to report ready"),
            "{text}"
        );
        assert!(text.contains("still-booting"), "{text}");
        let status = child.try_wait().unwrap();
        assert!(
            status.is_some(),
            "timeout must kill the hanging child, got {status:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn prepare_daemon_log_rotates_oversized_file() {
        let dir = tempfile::tempdir().unwrap();
        cockpit_host::private_fs::ensure_private_dir(dir.path()).unwrap();
        let log_path = dir.path().join(DAEMON_LOG_FILE);
        std::fs::write(&log_path, vec![b'x'; (DAEMON_LOG_MAX_BYTES as usize) + 8]).unwrap();
        let _file = prepare_daemon_log(dir.path()).unwrap();
        let rotated = dir.path().join(DAEMON_LOG_ROTATED_FILE);
        assert!(rotated.exists(), "oversized daemon.log must rotate to .1");
        assert!(
            std::fs::metadata(&log_path).unwrap().len() < DAEMON_LOG_MAX_BYTES,
            "fresh log must start empty/small after rotation"
        );
    }
}
