//! Host primitives: private directories, pid identity, and detached spawn.
//!
//! Analog of `crates/cockpit-host`. Kept free of protocol and daemon state.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};
use tokio::net::UnixListener;

use crate::paths::Paths;

/// Fd number the supervisor's listening socket lands on in a worker, matching
/// systemd's `SD_LISTEN_FDS_START`. See [`spawn_worker`].
pub const LISTENER_FD_VAR: &str = "EXCOC_LISTENER_FD";
/// Fd number of the sd_notify-style readiness pipe a worker writes to.
pub const NOTIFY_FD_VAR: &str = "EXCOC_NOTIFY_FD";
/// Inherited wall-clock open time (ms) — the supervisor's durable clock.
pub const OPENED_AT_VAR: &str = "EXCOC_OPENED_AT_MS";
/// Rolling worker version the supervisor stamps on each generation.
pub const WORKER_VERSION_VAR: &str = "EXCOC_WORKER_VERSION";
/// Worker generation counter.
pub const GENERATION_VAR: &str = "EXCOC_GENERATION";

pub fn ensure_private_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path).with_context(|| format!("creating {}", path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("chmod 0700 {}", path.display()))?;
    Ok(())
}

pub fn process_exists(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    // SAFETY: kill(pid, 0) is a documented existence probe.
    let result = unsafe { libc::kill(pid as libc::pid_t, 0) };
    if result == 0 {
        return true;
    }
    io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

pub fn read_pid_file(path: &Path) -> Option<u32> {
    let contents = fs::read_to_string(path).ok()?;
    contents.trim().parse().ok()
}

/// Exclusive pid reservation. Analog of Cockpit's pid-file claim: the winner
/// is the only process allowed to unlink the shared socket, so a losing
/// concurrent starter cannot steal the winner's newly bound endpoint.
pub fn reserve_pid_file(path: &Path, pid: u32) -> Result<()> {
    let mut empty_retries = 0;
    loop {
        match OpenOptions::new().write(true).create_new(true).open(path) {
            Ok(mut file) => {
                writeln!(file, "{pid}").with_context(|| format!("writing {}", path.display()))?;
                file.sync_all()?;
                return Ok(());
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(error).context(format!("creating {}", path.display()));
            }
        }
        match read_pid_file(path) {
            Some(existing) if existing == pid => return Ok(()),
            Some(existing) if process_exists(existing) => {
                bail!("another daemon is already running (pid {existing})");
            }
            Some(_) => match fs::remove_file(path) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(error)
                        .context(format!("removing stale pid file {}", path.display()));
                }
            },
            None => {
                // Another starter created the file but has not written its pid
                // yet. Do not unlink that reservation.
                empty_retries += 1;
                if empty_retries > 50 {
                    bail!("daemon pid file is busy: {}", path.display());
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        }
    }
}

/// Bind inside a 0700 parent, then chmod the socket node 0600.
///
/// Cockpit does the same and then fail-closed verifies owner/mode via lstat;
/// this reference keeps the chmod so a visible socket is never world-reachable.
pub fn bind_private_socket(socket: &Path) -> Result<UnixListener> {
    if let Some(parent) = socket.parent() {
        ensure_private_dir(parent)?;
    }
    let listener =
        UnixListener::bind(socket).with_context(|| format!("binding {}", socket.display()))?;
    fs::set_permissions(socket, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("chmod 0600 {}", socket.display()))?;
    Ok(listener)
}

/// Like [`bind_private_socket`] but returns a blocking `std` listener. The
/// supervisor holds this for its whole life and passes the fd down to each
/// worker (see [`spawn_worker`]); it never accepts on it itself.
pub fn bind_private_listener_std(socket: &Path) -> Result<std::os::unix::net::UnixListener> {
    if let Some(parent) = socket.parent() {
        ensure_private_dir(parent)?;
    }
    let listener = std::os::unix::net::UnixListener::bind(socket)
        .with_context(|| format!("binding {}", socket.display()))?;
    fs::set_permissions(socket, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("chmod 0600 {}", socket.display()))?;
    Ok(listener)
}

/// Spawn a detached `excoc daemon` child.
///
/// `inherit_opened_at_unix_ms` distinguishes the two spawn sites:
/// - `None` — a fresh **primary** daemon that records its own open time.
/// - `Some(ms)` — a **successor** for a hot handoff. It inherits the open time
///   (so uptime stays continuous), binds the staging endpoint, and waits for a
///   `Promote` before taking the canonical socket. Booting the successor from a
///   *different* binary path is where a future self-upgrade would hook in.
pub fn spawn_detached_daemon(paths: &Paths, inherit_opened_at_unix_ms: Option<u64>) -> Result<u32> {
    // We deliberately never wait() on the detached daemon. Normally that is
    // harmless because the daemon outlives every client. A handoff breaks that
    // assumption: the predecessor exits while the client that spawned it (its
    // parent) keeps running, so without auto-reaping it would linger forever as
    // a zombie. Ask the kernel to reap our children instead.
    reap_children_automatically();
    let exe = std::env::current_exe().context("locating own binary")?;
    let mut command = Command::new(exe);
    command
        .arg("daemon")
        .env("EXCOC_HOME", &paths.root)
        .stdin(Stdio::null())
        .stdout(Stdio::null());
    if let Some(ms) = inherit_opened_at_unix_ms {
        command.env("EXCOC_INHERIT_OPENED_AT_MS", ms.to_string());
    }
    match open_child_log(&paths.log_file) {
        Some(file) => {
            command.stderr(file);
        }
        None => {
            command.stderr(Stdio::null());
        }
    }
    if let Some(tick_ms) = std::env::var_os("EXCOC_TICK_MS") {
        command.env("EXCOC_TICK_MS", tick_ms);
    }
    // Leave the caller's session so Ctrl-C on a client does not signal the daemon.
    command.process_group(0);
    let child = command.spawn().context("spawning daemon child")?;
    Ok(child.id())
}

fn open_child_log(path: &Path) -> Option<std::fs::File> {
    if let Some(parent) = path.parent() {
        ensure_private_dir(parent).ok()?;
    }
    OpenOptions::new().create(true).append(true).open(path).ok()
}

/// Make exited children auto-reap instead of becoming zombies. Idempotent and
/// process-global. excoc uses no `tokio::process` and only handles SIGINT /
/// SIGTERM itself, so overriding the default SIGCHLD disposition is safe here.
fn reap_children_automatically() {
    // SAFETY: setting SIGCHLD to SIG_IGN is async-signal-safe and, per POSIX,
    // prevents children from becoming zombies. We never wait() on the daemon.
    unsafe {
        libc::signal(libc::SIGCHLD, libc::SIG_IGN);
    }
}

pub fn terminate(pid: u32) {
    if pid == 0 {
        return;
    }
    // SAFETY: SIGTERM to a previously observed pid; ESRCH is ignored.
    unsafe {
        libc::kill(pid as libc::pid_t, libc::SIGTERM);
    }
}

/// Spawn a detached `excoc supervise` child. Mirrors [`spawn_detached_daemon`]:
/// the first `excoc up` client starts the supervisor the same way the first
/// classic client starts the daemon.
pub fn spawn_detached_supervisor(paths: &Paths) -> Result<u32> {
    reap_children_automatically();
    let exe = std::env::current_exe().context("locating own binary")?;
    let mut command = Command::new(exe);
    command
        .arg("supervise")
        .env("EXCOC_HOME", &paths.root)
        .stdin(Stdio::null())
        .stdout(Stdio::null());
    match open_child_log(&paths.log_file) {
        Some(file) => {
            command.stderr(file);
        }
        None => {
            command.stderr(Stdio::null());
        }
    }
    if let Some(tick_ms) = std::env::var_os("EXCOC_TICK_MS") {
        command.env("EXCOC_TICK_MS", tick_ms);
    }
    command.process_group(0);
    let child = command.spawn().context("spawning supervisor child")?;
    Ok(child.id())
}

/// Spawn a supervised `excoc worker`, handing it the supervisor's listening
/// socket and a fresh readiness pipe.
///
/// This is the crux of the wrapper design and mirrors systemd socket
/// activation: the child inherits the already-bound listening socket at
/// [`LISTENER_FD_VAR`] (fd 3), so the endpoint stays open across the swap, and
/// reports readiness by writing to [`NOTIFY_FD_VAR`] (fd 4), sd_notify-style.
///
/// Returns the child pid and the **read** end of the readiness pipe. The caller
/// awaits a byte (or EOF, meaning the worker died during boot) on that fd. The
/// parent's copy of the write end is closed here so a dying child yields EOF.
pub fn spawn_worker(
    paths: &Paths,
    listener_fd: RawFd,
    opened_at_unix_ms: u64,
    worker_version: u32,
    generation: u32,
) -> Result<(u32, OwnedFd)> {
    reap_children_automatically();

    // A fresh readiness pipe per worker. Both ends start CLOEXEC so they never
    // leak into an unrelated exec; the write end is deliberately un-CLOEXEC'd
    // onto fd 4 in the child via `dup2`.
    let (ready_read, ready_write) = make_pipe().context("creating worker readiness pipe")?;

    // Move the source fds to high numbers so the `dup2(_, 3)` / `dup2(_, 4)` in
    // `pre_exec` cannot clobber the sources or leave a target CLOEXEC'd.
    let listener_hi = dup_to_high(listener_fd).context("duplicating listener fd")?;
    let ready_hi = dup_to_high(ready_write.as_raw_fd()).context("duplicating notify fd")?;
    let listener_hi_raw = listener_hi.as_raw_fd();
    let ready_hi_raw = ready_hi.as_raw_fd();

    let exe = std::env::current_exe().context("locating own binary")?;
    let mut command = Command::new(exe);
    command
        .arg("worker")
        .env("EXCOC_HOME", &paths.root)
        .env(LISTENER_FD_VAR, "3")
        .env(NOTIFY_FD_VAR, "4")
        .env(OPENED_AT_VAR, opened_at_unix_ms.to_string())
        .env(WORKER_VERSION_VAR, worker_version.to_string())
        .env(GENERATION_VAR, generation.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null());
    match open_child_log(&paths.log_file) {
        Some(file) => {
            command.stderr(file);
        }
        None => {
            command.stderr(Stdio::null());
        }
    }
    if let Some(tick_ms) = std::env::var_os("EXCOC_TICK_MS") {
        command.env("EXCOC_TICK_MS", tick_ms);
    }

    // SAFETY: only async-signal-safe calls (`dup2`, `fcntl`) run in the child
    // between fork and exec.
    unsafe {
        command.pre_exec(move || {
            place_fd(listener_hi_raw, 3)?;
            place_fd(ready_hi_raw, 4)?;
            Ok(())
        });
    }

    let child = command.spawn().context("spawning worker child")?;
    // Drop the parent's copies of the write end and the high dups so the only
    // remaining write end lives in the child: then a crash during boot closes
    // the pipe and the caller's read observes EOF instead of hanging.
    drop(ready_write);
    drop(listener_hi);
    drop(ready_hi);
    Ok((child.id(), ready_read))
}

/// Create a pipe with both ends marked CLOEXEC. Returns `(read, write)`.
fn make_pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0 as RawFd; 2];
    // SAFETY: `pipe` fills a two-element array of fds.
    let rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `pipe` returned two fresh, owned fds.
    let read = unsafe { OwnedFd::from_raw_fd(fds[0]) };
    let write = unsafe { OwnedFd::from_raw_fd(fds[1]) };
    set_cloexec(read.as_raw_fd())?;
    set_cloexec(write.as_raw_fd())?;
    Ok((read, write))
}

/// Duplicate `fd` onto the lowest free fd >= 10 (CLOEXEC), keeping fds 3/4 free
/// as `dup2` targets.
fn dup_to_high(fd: RawFd) -> io::Result<OwnedFd> {
    // SAFETY: F_DUPFD_CLOEXEC returns a new owned fd or -1.
    let new = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 10) };
    if new < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `new` is a fresh owned fd.
    Ok(unsafe { OwnedFd::from_raw_fd(new) })
}

fn set_cloexec(fd: RawFd) -> io::Result<()> {
    // SAFETY: plain fcntl flag manipulation on a valid fd.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Place `src` at exactly `target`, clearing CLOEXEC so it survives `exec`.
/// Async-signal-safe: only `dup2` and `fcntl` are used, per `signal-safety(7)`.
fn place_fd(src: RawFd, target: RawFd) -> io::Result<()> {
    // SAFETY: dup2 onto a specific fd; async-signal-safe.
    if unsafe { libc::dup2(src, target) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // `dup2` clears CLOEXEC on the new fd, but if `src == target` it is a no-op
    // and leaves the source's CLOEXEC intact, so clear it explicitly.
    if unsafe { libc::fcntl(target, libc::F_SETFD, 0) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
