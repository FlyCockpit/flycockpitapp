//! Host-owned daemon PID identity and metadata cleanup primitives.
//!
//! Protocol probing and daemon application state stay above this module. These
//! operations deal only in process identity and private host metadata, making
//! their ownership usable by both a foreground daemon and CLI lifecycle code.

use std::path::{Path, PathBuf};

use serde::Deserialize;

/// Result of checking whether a PID still names a Cockpit daemon process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PidIdentity {
    VerifiedDaemon,
    NotDaemon,
    Missing,
    Unverified,
}

/// Read a decimal PID from a daemon metadata file.
pub fn read_pid_file(pid_file: &Path) -> Option<u32> {
    let value = std::fs::read_to_string(pid_file).ok()?;
    value.trim().parse().ok()
}

/// Remove PID and socket metadata only while the PID file still binds the
/// caller's expected process identity.
pub fn remove_metadata_if_pid_matches(pid_file: &Path, socket: &Path, expected_pid: u32) -> bool {
    if read_pid_file(pid_file) != Some(expected_pid) {
        return false;
    }
    let _ = std::fs::remove_file(pid_file);
    let _ = std::fs::remove_file(socket);
    true
}

/// Verify that a live PID's argv is a Cockpit daemon-start invocation.
#[cfg(unix)]
pub fn verify_cockpit_daemon_pid_identity(pid: u32) -> PidIdentity {
    if !process_exists(pid) {
        return PidIdentity::Missing;
    }
    match read_process_cmdline(pid) {
        Ok(args) if cmdline_is_cockpit_daemon(&args) => PidIdentity::VerifiedDaemon,
        Ok(_) => PidIdentity::NotDaemon,
        Err(_) => PidIdentity::Unverified,
    }
}

#[cfg(unix)]
fn process_exists(pid: u32) -> bool {
    // SAFETY: signal 0 performs an existence/permission probe only.
    let rc = unsafe { libc::kill(pid as libc::pid_t, 0) };
    rc == 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
}

#[cfg(all(unix, target_os = "linux"))]
fn read_process_cmdline(pid: u32) -> std::io::Result<Vec<String>> {
    let bytes = std::fs::read(format!("/proc/{pid}/cmdline"))?;
    Ok(split_proc_cmdline(&bytes))
}

#[cfg(all(unix, target_os = "macos"))]
fn read_process_cmdline(pid: u32) -> std::io::Result<Vec<String>> {
    let mut argmax: libc::c_int = 0;
    let mut argmax_len = std::mem::size_of_val(&argmax);
    let mut argmax_mib = [libc::CTL_KERN, libc::KERN_ARGMAX];
    // SAFETY: buffers and lengths follow the sysctl contract.
    let rc = unsafe {
        libc::sysctl(
            argmax_mib.as_mut_ptr(),
            argmax_mib.len() as libc::c_uint,
            &mut argmax as *mut _ as *mut libc::c_void,
            &mut argmax_len,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    if argmax <= 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "KERN_ARGMAX returned a non-positive argv buffer size",
        ));
    }
    let mut bytes = vec![0_u8; argmax as usize];
    let mut len = bytes.len();
    let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid as libc::c_int];
    // SAFETY: the output buffer is allocated to KERN_ARGMAX bytes.
    let rc = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as libc::c_uint,
            bytes.as_mut_ptr().cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    bytes.truncate(len);
    parse_macos_procargs2(&bytes)
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn read_process_cmdline(_pid: u32) -> std::io::Result<Vec<String>> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "pid identity verification is unsupported on this platform",
    ))
}

pub fn split_proc_cmdline(bytes: &[u8]) -> Vec<String> {
    bytes
        .split(|byte| *byte == 0)
        .filter(|part| !part.is_empty())
        .map(|part| String::from_utf8_lossy(part).into_owned())
        .collect()
}

#[cfg(all(unix, any(test, target_os = "macos")))]
pub fn parse_macos_procargs2(bytes: &[u8]) -> std::io::Result<Vec<String>> {
    const WIDTH: usize = std::mem::size_of::<libc::c_int>();
    if bytes.len() < WIDTH {
        return Err(invalid_procargs("KERN_PROCARGS2 data is shorter than argc"));
    }
    let argc = i32::from_ne_bytes(
        bytes[..WIDTH]
            .try_into()
            .map_err(|_| invalid_procargs("invalid argc width"))?,
    );
    if argc <= 0 {
        return Err(invalid_procargs("KERN_PROCARGS2 argc is not positive"));
    }
    let mut position = WIDTH;
    let executable_end = bytes[position..]
        .iter()
        .position(|byte| *byte == 0)
        .map(|offset| position + offset)
        .ok_or_else(|| {
            invalid_procargs("KERN_PROCARGS2 data is missing executable path terminator")
        })?;
    position = executable_end + 1;
    while position < bytes.len() && bytes[position] == 0 {
        position += 1;
    }
    let mut args = Vec::with_capacity(argc as usize);
    while args.len() < argc as usize {
        if position >= bytes.len() {
            return Err(invalid_procargs(
                "KERN_PROCARGS2 data ended before argc arguments",
            ));
        }
        let end = bytes[position..]
            .iter()
            .position(|byte| *byte == 0)
            .map(|offset| position + offset)
            .ok_or_else(|| invalid_procargs("KERN_PROCARGS2 argument is not NUL terminated"))?;
        if end > position {
            args.push(String::from_utf8_lossy(&bytes[position..end]).into_owned());
        }
        position = end + 1;
    }
    Ok(args)
}

#[cfg(all(unix, any(test, target_os = "macos")))]
fn invalid_procargs(message: &'static str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message)
}

pub fn cmdline_is_cockpit_daemon(args: &[String]) -> bool {
    let Some(program) = args.first() else {
        return false;
    };
    let program_name = Path::new(program)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(program);
    program_name.contains("cockpit")
        && args
            .windows(2)
            .any(|pair| pair[0] == "daemon" && pair[1] == "start")
}

#[derive(Debug, Deserialize)]
struct EndpointRecord {
    pid: u32,
    socket: PathBuf,
}

/// Drop guard for foreground-owned PID/socket/endpoint metadata.
#[derive(Debug)]
pub struct ForegroundMetadataGuard {
    pid_file: PathBuf,
    socket: PathBuf,
    endpoint_record: Option<PathBuf>,
    pid: u32,
    armed: bool,
}

impl ForegroundMetadataGuard {
    pub fn new(pid_file: PathBuf, socket: PathBuf, endpoint_record: Option<PathBuf>) -> Self {
        Self {
            pid_file,
            socket,
            endpoint_record,
            pid: std::process::id(),
            armed: true,
        }
    }

    pub fn cleanup(&mut self) {
        if self.armed && remove_metadata_if_pid_matches(&self.pid_file, &self.socket, self.pid) {
            self.remove_owned_endpoint_record();
        }
        self.armed = false;
    }

    fn remove_owned_endpoint_record(&self) {
        let Some(path) = &self.endpoint_record else {
            return;
        };
        let Ok(bytes) = std::fs::read(path) else {
            return;
        };
        let Ok(record) = serde_json::from_slice::<EndpointRecord>(&bytes) else {
            return;
        };
        if record.pid == self.pid && record.socket == self.socket {
            let _ = std::fs::remove_file(path);
        }
    }
}

impl Drop for ForegroundMetadataGuard {
    fn drop(&mut self) {
        self.cleanup();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_guard_removes_only_exact_owned_endpoint() {
        let temp = tempfile::tempdir().expect("tempdir");
        let pid_file = temp.path().join("daemon.pid");
        let socket = temp.path().join("daemon.sock");
        let endpoint = temp.path().join("daemon-endpoint.json");
        std::fs::write(&pid_file, std::process::id().to_string()).expect("pid file");
        std::fs::write(&socket, b"socket metadata").expect("socket metadata");
        std::fs::write(
            &endpoint,
            serde_json::json!({"pid": std::process::id(), "socket": socket}),
        )
        .expect("endpoint record");

        let mut guard =
            ForegroundMetadataGuard::new(pid_file.clone(), socket.clone(), Some(endpoint.clone()));
        guard.cleanup();

        assert!(!pid_file.exists());
        assert!(!socket.exists());
        assert!(!endpoint.exists());
    }

    #[test]
    fn metadata_guard_preserves_mismatched_endpoint_receipt() {
        let temp = tempfile::tempdir().expect("tempdir");
        let pid_file = temp.path().join("daemon.pid");
        let socket = temp.path().join("daemon.sock");
        let endpoint = temp.path().join("daemon-endpoint.json");
        std::fs::write(&pid_file, std::process::id().to_string()).expect("pid file");
        std::fs::write(
            &endpoint,
            serde_json::json!({"pid": std::process::id(), "socket": temp.path().join("other.sock")}),
        )
        .expect("endpoint record");

        ForegroundMetadataGuard::new(pid_file, socket, Some(endpoint.clone())).cleanup();

        assert!(
            endpoint.exists(),
            "foreign endpoint receipt must survive cleanup"
        );
    }
}
