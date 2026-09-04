//! Unix `SO_PEERCRED` / `getpeereid` and Windows named-pipe peer process identity.
//!
//! Shared by the daemon control-socket accept loop and any sibling accept paths
//! that must bind an authenticated peer before granting authority.

use anyhow::{Context, Result};

use crate::daemon_lifecycle::ProcessStartIdentity;

/// Stable peer identity captured at socket accept time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PeerIdentity {
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
    /// Kernel process-start identity for this pid at accept time. Compared on
    /// every credential verification so a recycled pid cannot inherit authority.
    pub process_start: ProcessStartIdentity,
}

#[cfg(unix)]
pub fn peer_identity_from_unix_stream(
    stream: &std::os::unix::net::UnixStream,
) -> Result<PeerIdentity> {
    use std::os::fd::AsRawFd;

    let (uid, gid, pid) = peer_ucred(stream.as_raw_fd())?;
    let process_start = crate::daemon_lifecycle::process_start_identity(pid)
        .context("reading unix socket peer process start identity")?;
    Ok(PeerIdentity {
        pid,
        uid,
        gid,
        process_start,
    })
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
        let pid = peer_pid_from_unix_socket(fd)?;
        Ok((uid, gid, pid))
    }
}

#[cfg(all(unix, not(target_os = "linux")))]
fn peer_pid_from_unix_socket(fd: std::os::fd::RawFd) -> Result<u32> {
    #[cfg(target_os = "macos")]
    {
        let mut pid: libc::pid_t = 0;
        let mut len = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
        // SAFETY: `getsockopt` writes at most `len` bytes into `pid`.
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_LOCAL,
                libc::LOCAL_PEERPID,
                (&mut pid as *mut libc::pid_t).cast(),
                &mut len,
            )
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error())
                .context("reading unix socket LOCAL_PEERPID");
        }
        return u32::try_from(pid).context("unix socket peer pid out of range");
    }
    #[cfg(target_os = "freebsd")]
    {
        use std::mem::MaybeUninit;

        let mut cred = MaybeUninit::<libc::xucred>::uninit();
        let mut len = std::mem::size_of::<libc::xucred>() as libc::socklen_t;
        // SAFETY: `getsockopt` writes at most `len` bytes into the valid storage.
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_LOCAL,
                libc::LOCAL_PEERCRED,
                cred.as_mut_ptr().cast(),
                &mut len,
            )
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error())
                .context("reading unix socket LOCAL_PEERCRED");
        }
        // SAFETY: `getsockopt` succeeded and initialized the `xucred` struct.
        let cred = unsafe { cred.assume_init() };
        return u32::try_from(unsafe { cred.cr_pid__c_anonymous_union.cr_pid })
            .context("unix socket peer pid out of range");
    }
    #[cfg(not(any(target_os = "macos", target_os = "freebsd")))]
    {
        let _ = fd;
        Ok(0)
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
    let process_start = crate::daemon_lifecycle::process_start_identity(client_pid)
        .context("reading named-pipe client process start identity")?;
    Ok(PeerIdentity {
        pid: client_pid,
        uid: 0,
        gid: 0,
        process_start,
    })
}
