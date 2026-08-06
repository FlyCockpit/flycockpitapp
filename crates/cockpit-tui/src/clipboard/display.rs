//! Linux display identity proofs for native/executable eligibility.
//!
//! Wayland Native is always Skipped in V1 (arboard cannot consume a held
//! stream). Wayland Executable may use a duplicated held socket via
//! `WAYLAND_SOCKET`. X11 Native and Executable are Unsupported/Skipped.

use super::types::SkipReason;

/// Proven Wayland session holding an authenticated connected socket.
#[cfg(unix)]
#[derive(Debug)]
pub struct HeldWaylandConnection {
    stream: std::os::unix::net::UnixStream,
    pub socket_dev: u64,
    pub socket_ino: u64,
}

#[cfg(unix)]
impl HeldWaylandConnection {
    pub fn stream(&self) -> &std::os::unix::net::UnixStream {
        &self.stream
    }

    pub fn into_stream(self) -> std::os::unix::net::UnixStream {
        self.stream
    }
}

/// Result of probing Linux desktop eligibility.
#[derive(Debug)]
pub enum LinuxDesktopProbe {
    /// Held authenticated Wayland connection (Executable may use it).
    #[cfg(unix)]
    Wayland(HeldWaylandConnection),
    /// X11 present but unsupported for copy in V1.
    X11Unsupported { reason: SkipReason },
    /// No eligible local desktop.
    Ineligible { reason: SkipReason },
}

/// Probe production environment for a held Wayland connection.
#[cfg(target_os = "linux")]
pub fn probe_linux_desktop() -> LinuxDesktopProbe {
    if std::env::var_os("SSH_CONNECTION").is_some() || std::env::var_os("SSH_TTY").is_some() {
        return LinuxDesktopProbe::Ineligible {
            reason: SkipReason::SshSession,
        };
    }
    if std::env::var_os("WSL_DISTRO_NAME").is_some()
        || std::path::Path::new("/.dockerenv").exists()
        || std::path::Path::new("/mnt/wslg").exists()
    {
        return LinuxDesktopProbe::Ineligible {
            reason: SkipReason::WslOrContainer,
        };
    }

    let wayland_display = std::env::var("WAYLAND_DISPLAY").ok();
    let xdg_runtime = std::env::var("XDG_RUNTIME_DIR").ok();
    let display = std::env::var("DISPLAY").ok();

    if let (Some(runtime), Some(wd)) = (xdg_runtime.as_deref(), wayland_display.as_deref()) {
        match open_held_wayland(runtime, wd) {
            Ok(held) => return LinuxDesktopProbe::Wayland(held),
            Err(reason) => {
                if display.is_some() {
                    return LinuxDesktopProbe::X11Unsupported {
                        reason: SkipReason::X11Unsupported,
                    };
                }
                return LinuxDesktopProbe::Ineligible { reason };
            }
        }
    }

    if display.is_some() {
        return LinuxDesktopProbe::X11Unsupported {
            reason: SkipReason::X11Unsupported,
        };
    }

    LinuxDesktopProbe::Ineligible {
        reason: SkipReason::NoHeldAuthenticatedConnection,
    }
}

#[cfg(target_os = "linux")]
fn open_held_wayland(
    runtime: &str,
    wayland_display: &str,
) -> Result<HeldWaylandConnection, SkipReason> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    use std::os::unix::net::UnixStream;
    use std::path::{Component, Path};

    let runtime_path = Path::new(runtime);
    if !runtime_path.is_absolute() {
        return Err(SkipReason::NoHeldAuthenticatedConnection);
    }
    let meta = std::fs::symlink_metadata(runtime_path)
        .map_err(|_| SkipReason::NoHeldAuthenticatedConnection)?;
    if meta.file_type().is_symlink() {
        return Err(SkipReason::NoHeldAuthenticatedConnection);
    }
    let meta =
        std::fs::metadata(runtime_path).map_err(|_| SkipReason::NoHeldAuthenticatedConnection)?;
    let euid = unsafe { libc::geteuid() };
    if meta.uid() != euid {
        return Err(SkipReason::NoHeldAuthenticatedConnection);
    }
    let mode = meta.mode() & 0o777;
    if mode != 0o700 {
        return Err(SkipReason::NoHeldAuthenticatedConnection);
    }

    if wayland_display.is_empty()
        || wayland_display.contains('/')
        || wayland_display.contains('\\')
        || wayland_display == "."
        || wayland_display == ".."
    {
        return Err(SkipReason::NoHeldAuthenticatedConnection);
    }
    let socket_path = runtime_path.join(wayland_display);
    if socket_path
        .components()
        .any(|c| matches!(c, Component::ParentDir))
    {
        return Err(SkipReason::NoHeldAuthenticatedConnection);
    }

    let sock_meta = std::fs::symlink_metadata(&socket_path)
        .map_err(|_| SkipReason::NoHeldAuthenticatedConnection)?;
    if sock_meta.file_type().is_symlink() {
        return Err(SkipReason::NoHeldAuthenticatedConnection);
    }
    if !sock_meta.file_type().is_socket() {
        let mode = sock_meta.mode();
        if mode & libc::S_IFMT != libc::S_IFSOCK {
            return Err(SkipReason::NoHeldAuthenticatedConnection);
        }
    }
    if sock_meta.uid() != euid {
        return Err(SkipReason::NoHeldAuthenticatedConnection);
    }
    let sock_mode = sock_meta.mode() & 0o777;
    if sock_mode & 0o077 != 0 {
        return Err(SkipReason::NoHeldAuthenticatedConnection);
    }

    let stream =
        UnixStream::connect(&socket_path).map_err(|_| SkipReason::NoHeldAuthenticatedConnection)?;

    let post =
        std::fs::metadata(&socket_path).map_err(|_| SkipReason::NoHeldAuthenticatedConnection)?;
    if post.dev() != sock_meta.dev() || post.ino() != sock_meta.ino() {
        return Err(SkipReason::NoHeldAuthenticatedConnection);
    }

    let peer = peer_uid(&stream).map_err(|_| SkipReason::NoHeldAuthenticatedConnection)?;
    if peer != euid {
        return Err(SkipReason::NoHeldAuthenticatedConnection);
    }

    Ok(HeldWaylandConnection {
        stream,
        socket_dev: sock_meta.dev(),
        socket_ino: sock_meta.ino(),
    })
}

#[cfg(target_os = "linux")]
fn peer_uid(stream: &std::os::unix::net::UnixStream) -> std::io::Result<libc::uid_t> {
    use std::mem::MaybeUninit;
    use std::os::fd::AsRawFd;

    let mut cred = MaybeUninit::<libc::ucred>::uninit();
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            cred.as_mut_ptr().cast(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { cred.assume_init().uid })
}

#[cfg(not(target_os = "linux"))]
pub fn probe_linux_desktop() -> LinuxDesktopProbe {
    LinuxDesktopProbe::Ineligible {
        reason: SkipReason::UnsupportedBackend,
    }
}

/// Pure validators used by the identity matrix tests (no real sockets).
#[cfg(test)]
pub mod validate {
    use super::SkipReason;
    use std::path::Path;

    #[cfg(test)]
    pub fn wayland_display_name(name: &str) -> Result<(), SkipReason> {
        if name.is_empty()
            || name.contains('/')
            || name.contains('\\')
            || name == "."
            || name == ".."
            || name.contains('\0')
        {
            return Err(SkipReason::NoHeldAuthenticatedConnection);
        }
        Ok(())
    }

    #[cfg(test)]
    pub fn runtime_dir_path(path: &Path) -> Result<(), SkipReason> {
        if !path.is_absolute() {
            return Err(SkipReason::NoHeldAuthenticatedConnection);
        }
        Ok(())
    }

    #[cfg(test)]
    pub fn display_is_tcp_or_hostname(display: &str) -> bool {
        if let Some(host) = display.split(':').next() {
            if host.is_empty() {
                return false;
            }
            return host.eq_ignore_ascii_case("localhost")
                || host == "127.0.0.1"
                || host == "::1"
                || host.contains('.');
        }
        false
    }
}
