//! Runtime paths for the shared daemon endpoint.
//!
//! Cockpit splits pid (XDG_STATE_HOME) from socket (XDG_RUNTIME_DIR). This
//! example keeps both in one overrideable directory so tests can be hermetic
//! with `EXCOC_HOME`.

use std::path::PathBuf;

use anyhow::{Context, Result};

use crate::host::ensure_private_dir;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Paths {
    pub root: PathBuf,
    pub socket: PathBuf,
    pub pid_file: PathBuf,
    pub log_file: PathBuf,
    /// Staging endpoint a successor binds during a handoff. On promotion it is
    /// atomically renamed onto `socket`, so the canonical path never has a gap
    /// where `attach_or_spawn` could spawn a rogue third daemon.
    pub staging_socket: PathBuf,
    /// Staging pid reservation a successor holds so `reserve_pid_file` does not
    /// bail on the still-live predecessor. Renamed onto `pid_file` at
    /// promotion, atomically transferring ownership.
    pub staging_pid: PathBuf,
    /// Public endpoint for the *supervised* design (`excoc supervise`). The
    /// supervisor binds and owns this socket for its whole life and hands the
    /// listening fd down to each worker generation, so the socket never closes
    /// across an upgrade or a worker crash. Distinct from `socket` so the two
    /// designs can be demoed independently in one `EXCOC_HOME`.
    pub sup_socket: PathBuf,
    /// Identity of the supervisor process (not any worker). A worker never
    /// reserves a pid file — the supervisor owns lifecycle.
    pub sup_pid: PathBuf,
    /// Supervisor control socket. `excoc upgrade` / `excoc sup-status` connect
    /// here to drive the supervisor. This is the small, deliberately frozen
    /// wrapper boundary; the public NDJSON protocol rides `sup_socket` instead.
    pub sup_ctl: PathBuf,
}

impl Paths {
    pub fn resolve() -> Result<Self> {
        let root = match std::env::var_os("EXCOC_HOME") {
            Some(home) if !home.is_empty() => PathBuf::from(home),
            _ => default_runtime_dir()?,
        };
        ensure_private_dir(&root).with_context(|| format!("securing {}", root.display()))?;
        Ok(Self {
            socket: root.join("excoc.sock"),
            pid_file: root.join("excoc.pid"),
            log_file: root.join("excoc.log"),
            staging_socket: root.join("excoc.sock.next"),
            staging_pid: root.join("excoc.pid.next"),
            sup_socket: root.join("excoc.sup.sock"),
            sup_pid: root.join("excoc.sup.pid"),
            sup_ctl: root.join("excoc.sup.ctl"),
            root,
        })
    }
}

fn default_runtime_dir() -> Result<PathBuf> {
    if let Ok(runtime) = std::env::var("XDG_RUNTIME_DIR") {
        let trimmed = runtime.trim();
        if !trimmed.is_empty() {
            return Ok(PathBuf::from(trimmed).join("excoc"));
        }
    }
    let uid = uid();
    Ok(std::env::temp_dir().join(format!("excoc-{uid}")))
}

fn uid() -> u32 {
    // SAFETY: getuid has no preconditions.
    unsafe { libc::getuid() }
}
