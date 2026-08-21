//! Platform clipboard executable adapter with exact argv/env contracts.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[cfg(target_os = "linux")]
use super::display::HeldWaylandConnection;
use super::display::{LinuxDesktopProbe, probe_linux_desktop};
use super::types::{PlatformKind, SafeErrorKind, SessionContext, SkipReason};

/// Combined stdout+stderr cap for clipboard child processes.
pub const EXEC_OUTPUT_CAP: usize = 64 * 1024;
/// Monotonic deadline for each subprocess.
pub const EXEC_DEADLINE: Duration = Duration::from_secs(2);

pub trait ExecutableClipboard: Send {
    fn set_plain(&mut self, text: &str) -> Result<(), SafeErrorKind>;
}

/// Production platform executable adapter.
#[derive(Debug, Default)]
pub struct PlatformExecutable {
    /// Optional pre-held Wayland connection (tests / service injection).
    #[cfg(target_os = "linux")]
    pub wayland: Option<HeldWaylandConnection>,
}

impl ExecutableClipboard for PlatformExecutable {
    fn set_plain(&mut self, text: &str) -> Result<(), SafeErrorKind> {
        match PlatformKind::current() {
            PlatformKind::MacOs => run_pbcopy(text),
            PlatformKind::Windows => run_clip_exe(text),
            PlatformKind::Linux => {
                #[cfg(target_os = "linux")]
                {
                    let held = self.wayland.take();
                    run_wl_copy(text, held)
                }
                #[cfg(not(target_os = "linux"))]
                {
                    let _ = text;
                    Err(SafeErrorKind::Unsupported)
                }
            }
            PlatformKind::Other => Err(SafeErrorKind::Unsupported),
        }
    }
}

/// Executable eligibility before spawn.
pub fn executable_eligibility(ctx: &SessionContext) -> Result<(), SkipReason> {
    if ctx.untrusted_remote {
        return Err(SkipReason::UntrustedRemote);
    }
    if ctx.ssh {
        return Err(SkipReason::SshSession);
    }
    if ctx.wsl_or_container {
        return Err(SkipReason::WslOrContainer);
    }
    if ctx.host_bridge {
        return Err(SkipReason::HostBridge);
    }
    if !ctx.same_host_local_desktop {
        return Err(SkipReason::NotSameHostLocalDesktop);
    }
    match ctx.platform {
        PlatformKind::MacOs | PlatformKind::Windows => Ok(()),
        PlatformKind::Linux => {
            // X11 never eligible. Wayland only with held connection.
            match probe_linux_desktop() {
                #[cfg(target_os = "linux")]
                LinuxDesktopProbe::Wayland(_) => Ok(()),
                #[cfg(target_os = "linux")]
                LinuxDesktopProbe::X11Unsupported { reason } => Err(reason),
                LinuxDesktopProbe::Ineligible { reason } => Err(reason),
            }
        }
        PlatformKind::Other => Err(SkipReason::UnsupportedBackend),
    }
}

/// Like [`executable_eligibility`] but uses a pre-probed Wayland hold for tests.
#[allow(dead_code)]
pub fn executable_eligibility_with_probe(
    ctx: &SessionContext,
    probe: &LinuxDesktopProbe,
) -> Result<(), SkipReason> {
    if ctx.untrusted_remote {
        return Err(SkipReason::UntrustedRemote);
    }
    if ctx.ssh {
        return Err(SkipReason::SshSession);
    }
    if ctx.wsl_or_container {
        return Err(SkipReason::WslOrContainer);
    }
    if ctx.host_bridge {
        return Err(SkipReason::HostBridge);
    }
    if !ctx.same_host_local_desktop {
        return Err(SkipReason::NotSameHostLocalDesktop);
    }
    match ctx.platform {
        PlatformKind::MacOs | PlatformKind::Windows => Ok(()),
        PlatformKind::Linux => match probe {
            #[cfg(target_os = "linux")]
            LinuxDesktopProbe::Wayland(_) => Ok(()),
            #[cfg(target_os = "linux")]
            LinuxDesktopProbe::X11Unsupported { reason } => Err(*reason),
            LinuxDesktopProbe::Ineligible { reason } => Err(*reason),
        },
        PlatformKind::Other => Err(SkipReason::UnsupportedBackend),
    }
}

fn run_pbcopy(text: &str) -> Result<(), SafeErrorKind> {
    let path = Path::new("/usr/bin/pbcopy");
    verify_unix_candidate(path)?;
    spawn_stdin_utf8(path, &[], text, &[])
}

fn run_clip_exe(text: &str) -> Result<(), SafeErrorKind> {
    let path = windows_clip_path()?;
    // UTF-16LE + BOM on stdin, no args.
    let mut encoded = Vec::with_capacity(2 + text.len() * 2);
    encoded.extend_from_slice(&[0xFF, 0xFE]); // BOM
    for unit in text.encode_utf16() {
        encoded.extend_from_slice(&unit.to_le_bytes());
    }
    spawn_stdin_bytes(&path, &[], &encoded, &[])
}

#[cfg(target_os = "linux")]
fn run_wl_copy(text: &str, held: Option<HeldWaylandConnection>) -> Result<(), SafeErrorKind> {
    use std::os::fd::AsRawFd;

    let path = resolve_wl_copy()?;
    let held = held
        .or_else(|| match probe_linux_desktop() {
            #[cfg(target_os = "linux")]
            LinuxDesktopProbe::Wayland(h) => Some(h),
            _ => None,
        })
        .ok_or(SafeErrorKind::Ineligible)?;

    // Duplicate the held socket for the child and pass decimal WAYLAND_SOCKET.
    let src = held.stream().as_raw_fd();
    let dup = unsafe { libc::fcntl(src, libc::F_DUPFD_CLOEXEC, 3) };
    if dup < 0 {
        return Err(SafeErrorKind::SpawnFailed);
    }
    // Child must inherit the socket without CLOEXEC.
    unsafe {
        let flags = libc::fcntl(dup, libc::F_GETFD);
        if flags >= 0 {
            let _ = libc::fcntl(dup, libc::F_SETFD, flags & !libc::FD_CLOEXEC);
        }
    }
    let socket_fd = dup;
    let env = [("WAYLAND_SOCKET", socket_fd.to_string())];
    let env_refs: Vec<(&str, &str)> = env.iter().map(|(k, v)| (*k, v.as_str())).collect();

    let result = spawn_stdin_utf8_with(
        &path,
        &["--type", "text/plain;charset=utf-8"],
        text,
        &env_refs,
        Some(socket_fd),
    );

    // Close our duplicate after spawn (child has its own).
    unsafe {
        let _ = libc::close(socket_fd);
    }
    result
}

#[cfg(target_os = "linux")]
fn resolve_wl_copy() -> Result<PathBuf, SafeErrorKind> {
    let primary = Path::new("/usr/bin/wl-copy");
    if primary.exists() {
        verify_unix_candidate(primary)?;
        return Ok(primary.to_path_buf());
    }
    // /bin/wl-copy accepted only when same verified file identity as /usr/bin/wl-copy.
    // If /usr/bin is missing, /bin alone is never eligible (must match primary identity).
    let alt = Path::new("/bin/wl-copy");
    if alt.exists() && primary.exists() {
        // Both exist — require same device/inode after resolution.
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let a = std::fs::metadata(primary).map_err(|_| SafeErrorKind::Ineligible)?;
            let b = std::fs::metadata(alt).map_err(|_| SafeErrorKind::Ineligible)?;
            if a.dev() == b.dev() && a.ino() == b.ino() {
                verify_unix_candidate(alt)?;
                return Ok(alt.to_path_buf());
            }
        }
    }
    Err(SafeErrorKind::Ineligible)
}

/// Unix candidate: root-owned regular file, not a symlink after resolution,
/// not group/world writable.
pub fn verify_unix_candidate(path: &Path) -> Result<(), SafeErrorKind> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // Reject if the path itself is a symlink before resolution? Spec:
        // "not symlinks after resolution" — resolve and ensure final is regular.
        let resolved = std::fs::canonicalize(path).map_err(|_| SafeErrorKind::Ineligible)?;
        let meta = std::fs::metadata(&resolved).map_err(|_| SafeErrorKind::Ineligible)?;
        if !meta.file_type().is_file() {
            return Err(SafeErrorKind::Ineligible);
        }
        // After canonicalize, path should not be a symlink.
        let lmeta = std::fs::symlink_metadata(&resolved).map_err(|_| SafeErrorKind::Ineligible)?;
        if lmeta.file_type().is_symlink() {
            return Err(SafeErrorKind::Ineligible);
        }
        if meta.uid() != 0 {
            return Err(SafeErrorKind::Ineligible);
        }
        let mode = meta.mode() & 0o777;
        if mode & 0o022 != 0 {
            // group/world writable
            return Err(SafeErrorKind::Ineligible);
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Err(SafeErrorKind::Unsupported)
    }
}

fn windows_clip_path() -> Result<PathBuf, SafeErrorKind> {
    #[cfg(windows)]
    {
        system_directory_clip()
    }
    #[cfg(not(windows))]
    {
        Err(SafeErrorKind::Unsupported)
    }
}

#[cfg(windows)]
fn system_directory_clip() -> Result<PathBuf, SafeErrorKind> {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;

    // windows-sys GetSystemDirectoryW lives under SystemInformation.
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetSystemDirectoryW(buffer: *mut u16, size: u32) -> u32;
    }

    let mut buf = [0u16; 260];
    let len = unsafe { GetSystemDirectoryW(buf.as_mut_ptr(), buf.len() as u32) };
    if len == 0 || len as usize >= buf.len() {
        return Err(SafeErrorKind::Ineligible);
    }
    let dir = OsString::from_wide(&buf[..len as usize]);
    let path = PathBuf::from(dir).join("clip.exe");
    if !path.is_file() {
        return Err(SafeErrorKind::Ineligible);
    }
    Ok(path)
}

fn spawn_stdin_utf8(
    path: &Path,
    args: &[&str],
    text: &str,
    env: &[(&str, &str)],
) -> Result<(), SafeErrorKind> {
    spawn_stdin_utf8_with(path, args, text, env, None)
}

fn spawn_stdin_utf8_with(
    path: &Path,
    args: &[&str],
    text: &str,
    env: &[(&str, &str)],
    inherit_fd: Option<i32>,
) -> Result<(), SafeErrorKind> {
    spawn_stdin_bytes_with(path, args, text.as_bytes(), env, inherit_fd)
}

fn spawn_stdin_bytes(
    path: &Path,
    args: &[&str],
    bytes: &[u8],
    env: &[(&str, &str)],
) -> Result<(), SafeErrorKind> {
    spawn_stdin_bytes_with(path, args, bytes, env, None)
}

fn spawn_stdin_bytes_with(
    path: &Path,
    args: &[&str],
    bytes: &[u8],
    env: &[(&str, &str)],
    _inherit_fd: Option<i32>,
) -> Result<(), SafeErrorKind> {
    let mut cmd = Command::new(path);
    cmd.args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_clear();
    for (k, v) in env {
        cmd.env(k, v);
    }
    // Never pass PATH, XDG_RUNTIME_DIR, WAYLAND_DISPLAY, DISPLAY, etc.

    let mut child = cmd.spawn().map_err(|_| SafeErrorKind::SpawnFailed)?;
    if let Some(mut stdin) = child.stdin.take() {
        // Best-effort write; ignore BrokenPipe if child exits early.
        let _ = stdin.write_all(bytes);
        let _ = stdin.flush();
        drop(stdin);
    }

    let deadline = Instant::now() + EXEC_DEADLINE;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                // Drain with cap (content never logged).
                let _ = drain_capped(&mut child);
                if status.success() {
                    return Ok(());
                }
                return Err(SafeErrorKind::ExitFailure);
            }
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(SafeErrorKind::Timeout);
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(SafeErrorKind::SpawnFailed);
            }
        }
    }
}

fn drain_capped(child: &mut std::process::Child) -> Result<(), SafeErrorKind> {
    use std::io::Read;
    let mut total = 0usize;
    let mut buf = [0u8; 4096];
    if let Some(out) = child.stdout.as_mut() {
        loop {
            match out.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    total = total.saturating_add(n);
                    if total > EXEC_OUTPUT_CAP {
                        return Err(SafeErrorKind::OutputCapExceeded);
                    }
                }
                Err(_) => break,
            }
        }
    }
    if let Some(err) = child.stderr.as_mut() {
        loop {
            match err.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    total = total.saturating_add(n);
                    if total > EXEC_OUTPUT_CAP {
                        return Err(SafeErrorKind::OutputCapExceeded);
                    }
                }
                Err(_) => break,
            }
        }
    }
    Ok(())
}

/// Recording executable for tests.
#[cfg(test)]
#[derive(Debug, Default)]
pub struct RecordingExecutable {
    pub plains: Vec<String>,
    pub fail: Option<SafeErrorKind>,
    #[allow(dead_code)]
    pub argv_log: Vec<Vec<String>>,
}

#[cfg(test)]
impl ExecutableClipboard for RecordingExecutable {
    fn set_plain(&mut self, text: &str) -> Result<(), SafeErrorKind> {
        if let Some(err) = self.fail {
            return Err(err);
        }
        self.plains.push(text.to_string());
        Ok(())
    }
}

/// Documented argv contracts for conformance fixtures.
#[cfg(test)]
pub mod contracts {
    pub const MACOS_PBCOPY: &str = "/usr/bin/pbcopy";
    pub const LINUX_WL_COPY: &str = "/usr/bin/wl-copy";
    pub const LINUX_WL_COPY_ARGS: &[&str] = &["--type", "text/plain;charset=utf-8"];
}
