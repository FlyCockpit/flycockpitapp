//! Unix `SO_PEERCRED` / `getpeereid` and Windows named-pipe peer process identity.
//!
//! Shared by the daemon control-socket accept loop and any sibling accept paths
//! that must bind an authenticated peer before granting authority.

use anyhow::{Context, Result};

/// Stable peer identity captured at socket accept time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PeerIdentity {
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
}

#[cfg(unix)]
pub fn peer_identity_from_unix_stream(
    stream: &std::os::unix::net::UnixStream,
) -> Result<PeerIdentity> {
    use std::os::fd::AsRawFd;

    let (uid, gid, pid) = peer_ucred(stream.as_raw_fd())?;
    Ok(PeerIdentity { pid, uid, gid })
}

#[cfg(unix)]
fn peer_ucred(fd: std::os::fd::RawFd) -> Result<(u32, u32, u32)> {
    #[cfg(target_os = "linux")]
    {
        use std::mem::MaybeUninit;

        let mut cred = MaybeUninit::<libc::ucred>::uninit();
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        // SAFETY: `getsockopt` writes at most `len` bytes into the valid storage.
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                cred.as_mut_ptr().cast(),
                &mut len,
            )
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error()).context("reading unix socket peer cred");
        }
        // SAFETY: `getsockopt` succeeded and initialized the `ucred` struct.
        let cred = unsafe { cred.assume_init() };
        Ok((cred.uid, cred.gid, cred.pid))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let mut uid: libc::uid_t = 0;
        let mut gid: libc::gid_t = 0;
        // SAFETY: `getpeereid` writes to valid uid/gid pointers for this socket.
        let rc = unsafe { libc::getpeereid(fd, &mut uid, &mut gid) };
        if rc != 0 {
            return Err(std::io::Error::last_os_error()).context("reading unix socket peer uid");
        }
        // Non-Linux Unix exposes uid/gid via `getpeereid` only. Peer-bound
        // credentials on those platforms match uid/gid with pid `0`.
        Ok((uid, gid, 0))
    }
}

#[cfg(windows)]
pub fn peer_identity_from_named_pipe(
    handle: std::os::windows::io::RawHandle,
) -> Result<PeerIdentity> {
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::System::Pipes::GetNamedPipeClientProcessId;

    let mut client_pid = 0_u32;
    // SAFETY: `handle` is a connected named-pipe server end owned by the caller.
    let got_pid = unsafe { GetNamedPipeClientProcessId(handle as HANDLE, &mut client_pid) };
    if got_pid == 0 {
        return Err(std::io::Error::last_os_error())
            .context("reading named-pipe client process id");
    }
    Ok(PeerIdentity {
        pid: client_pid,
        uid: 0,
        gid: 0,
    })
}
