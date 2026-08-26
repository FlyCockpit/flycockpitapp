//! Host-owned daemon PID identity and metadata cleanup primitives.
//!
//! Protocol probing and daemon application state stay above this module. These
//! operations deal only in process identity and private host metadata, making
//! their ownership usable by both a foreground daemon and CLI lifecycle code.

use std::path::{Path, PathBuf};

use serde::Deserialize;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonPidReceipt {
    pub pid: u32,
    pub executable: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DaemonPidRecord {
    Receipt(DaemonPidReceipt),
    LegacyNumeric(u32),
}

/// Result of checking whether a PID still names a Cockpit daemon process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PidIdentity {
    VerifiedDaemon,
    NotDaemon,
    Missing,
    Unverified,
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
pub struct VerifiedDaemonProcess {
    receipt: DaemonPidReceipt,
    pidfd: std::os::fd::OwnedFd,
}

#[cfg(target_os = "linux")]
impl VerifiedDaemonProcess {
    pub fn receipt(&self) -> &DaemonPidReceipt {
        &self.receipt
    }

    pub fn send_sigterm(&self) -> std::io::Result<()> {
        pidfd_send_signal(&self.pidfd, libc::SIGTERM)
    }

    pub fn is_alive(&self) -> std::io::Result<bool> {
        match pidfd_send_signal(&self.pidfd, 0) {
            Ok(()) => Ok(true),
            Err(error) if error.raw_os_error() == Some(libc::ESRCH) => Ok(false),
            Err(error) => Err(error),
        }
    }
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
pub enum VerifiedProcessOutcome {
    Verified(VerifiedDaemonProcess),
    Identity(PidIdentity),
}

/// Acquire a stable kernel handle before validating the receipt. The returned
/// pidfd continues to identify that exact process even if the numeric PID is
/// later recycled.
#[cfg(target_os = "linux")]
pub fn acquire_verified_daemon_process(receipt: &DaemonPidReceipt) -> VerifiedProcessOutcome {
    if i32::try_from(receipt.pid).is_err() {
        return VerifiedProcessOutcome::Identity(PidIdentity::Unverified);
    }
    let pidfd = match pidfd_open(receipt.pid) {
        Ok(pidfd) => pidfd,
        Err(error) if error.raw_os_error() == Some(libc::ESRCH) => {
            return VerifiedProcessOutcome::Identity(PidIdentity::Missing);
        }
        Err(_) => return VerifiedProcessOutcome::Identity(PidIdentity::Unverified),
    };
    let identity = verify_cockpit_daemon_pid_identity(receipt.pid, &receipt.executable);
    if identity != PidIdentity::VerifiedDaemon {
        return VerifiedProcessOutcome::Identity(identity);
    }
    match pidfd_send_signal(&pidfd, 0) {
        Ok(()) => {}
        Err(error) if error.raw_os_error() == Some(libc::ESRCH) => {
            return VerifiedProcessOutcome::Identity(PidIdentity::Missing);
        }
        Err(_) => return VerifiedProcessOutcome::Identity(PidIdentity::Unverified),
    }
    VerifiedProcessOutcome::Verified(VerifiedDaemonProcess {
        receipt: receipt.clone(),
        pidfd,
    })
}

#[cfg(target_os = "linux")]
fn pidfd_open(pid: u32) -> std::io::Result<std::os::fd::OwnedFd> {
    use std::os::fd::FromRawFd as _;
    // SAFETY: pidfd_open returns a new owned descriptor on success.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) } as libc::c_int;
    if fd < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) })
    }
}

#[cfg(target_os = "linux")]
fn pidfd_send_signal(pidfd: &std::os::fd::OwnedFd, signal: libc::c_int) -> std::io::Result<()> {
    use std::os::fd::AsRawFd as _;
    // SAFETY: the descriptor is a live pidfd; null siginfo and zero flags are
    // the documented pidfd_send_signal contract.
    let result = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd.as_raw_fd(),
            signal,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(unix)]
pub fn legacy_pid_identity(pid: u32) -> PidIdentity {
    if process_exists(pid) {
        PidIdentity::Unverified
    } else {
        PidIdentity::Missing
    }
}

/// Read a decimal PID from a daemon metadata file.
pub fn read_pid_file(pid_file: &Path) -> Option<u32> {
    match read_daemon_pid_record(pid_file)? {
        DaemonPidRecord::Receipt(receipt) => Some(receipt.pid),
        DaemonPidRecord::LegacyNumeric(pid) => Some(pid),
    }
}

/// Parse PID and executable identity from one immutable file snapshot.
pub fn read_daemon_pid_record(pid_file: &Path) -> Option<DaemonPidRecord> {
    let value = std::fs::read_to_string(pid_file).ok()?;
    let mut lines = value.lines();
    let first = lines.next()?.trim();
    if first != "cockpit-daemon-pid-v1" {
        let pid = first.parse::<u32>().ok()?;
        if lines.next().is_some() {
            return None;
        }
        return Some(DaemonPidRecord::LegacyNumeric(pid));
    }
    let pid = lines.next()?.parse::<u32>().ok()?;
    let executable = decode_executable_identity(lines.next()?)?;
    if lines.next().is_some() {
        return None;
    }
    Some(DaemonPidRecord::Receipt(DaemonPidReceipt {
        pid,
        executable,
    }))
}

/// Atomically publish a PID together with the exact canonical executable that
/// owns it. This receipt is the authority later used before signaling.
pub fn write_pid_file(
    pid_file: &Path,
    pid: u32,
    executable: &Path,
) -> anyhow::Result<DaemonPidReceipt> {
    let executable = std::fs::canonicalize(executable)?;
    let body = format!(
        "cockpit-daemon-pid-v1\n{pid}\n{}\n",
        encode_executable_identity(&executable)
    );
    crate::private_fs::write_private_file(pid_file, body.as_bytes())?;
    Ok(DaemonPidReceipt { pid, executable })
}

fn encode_executable_identity(executable: &Path) -> String {
    format!(
        "native:{}",
        hex_encode(executable.as_os_str().as_encoded_bytes())
    )
}

fn decode_executable_identity(value: &str) -> Option<PathBuf> {
    let bytes = hex_decode(value.strip_prefix("native:")?)?;
    // SAFETY: bytes were obtained from OsStr::as_encoded_bytes on this host
    // and hex round-tripped without modification. Lifecycle receipts are
    // machine-local and are never portable between platforms or Rust builds.
    let executable = unsafe { std::ffi::OsString::from_encoded_bytes_unchecked(bytes) };
    Some(PathBuf::from(executable))
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn hex_decode(value: &str) -> Option<Vec<u8>> {
    if value.len() % 2 != 0 {
        return None;
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = (pair[0] as char).to_digit(16)? as u8;
            let low = (pair[1] as char).to_digit(16)? as u8;
            Some((high << 4) | low)
        })
        .collect()
}

/// Remove PID and socket metadata only while the PID file still binds the
/// caller's expected process identity.
pub fn remove_metadata_if_receipt_matches(
    pid_file: &Path,
    socket: &Path,
    expected: &DaemonPidReceipt,
) -> bool {
    if read_daemon_pid_record(pid_file) != Some(DaemonPidRecord::Receipt(expected.clone())) {
        return false;
    }
    let _ = std::fs::remove_file(pid_file);
    let _ = std::fs::remove_file(socket);
    true
}

#[cfg(unix)]
pub fn remove_dead_legacy_metadata(pid_file: &Path, socket: &Path, expected_pid: u32) -> bool {
    if read_daemon_pid_record(pid_file) != Some(DaemonPidRecord::LegacyNumeric(expected_pid))
        || legacy_pid_identity(expected_pid) != PidIdentity::Missing
    {
        return false;
    }
    let _ = std::fs::remove_file(pid_file);
    let _ = std::fs::remove_file(socket);
    true
}

/// Verify that a live PID is the exact approved Cockpit executable and its
/// argv is a daemon-start invocation. The approved executable is explicit so
/// production can bind verification to the executable that published the
/// lifecycle metadata; tests must pass their own test-binary path deliberately.
#[cfg(unix)]
pub fn verify_cockpit_daemon_pid_identity(pid: u32, approved_executable: &Path) -> PidIdentity {
    if !process_exists(pid) {
        return PidIdentity::Missing;
    }
    let executable = match read_process_executable(pid) {
        Ok(executable) => executable,
        Err(_) => return PidIdentity::Unverified,
    };
    let args = match read_process_cmdline(pid) {
        Ok(args) => args,
        Err(_) => return PidIdentity::Unverified,
    };
    let daemon_argv = args
        .windows(2)
        .any(|pair| pair[0] == "daemon" && pair[1] == "start");
    if cmdline_is_cockpit_daemon(&args, &executable, approved_executable) {
        PidIdentity::VerifiedDaemon
    } else if daemon_argv {
        // A daemon-shaped process whose executable receipt does not bind is
        // not safe to signal, but neither is it safe to declare stale and
        // unlink beneath it.
        PidIdentity::Unverified
    } else {
        PidIdentity::NotDaemon
    }
}

#[cfg(target_os = "linux")]
fn read_process_executable(pid: u32) -> std::io::Result<PathBuf> {
    std::fs::read_link(format!("/proc/{pid}/exe"))
}

#[cfg(target_os = "macos")]
fn read_process_executable(pid: u32) -> std::io::Result<PathBuf> {
    const PROC_PIDPATHINFO_MAXSIZE: usize = 4 * 1024;
    #[link(name = "proc")]
    unsafe extern "C" {
        fn proc_pidpath(pid: libc::c_int, buffer: *mut libc::c_void, size: u32) -> libc::c_int;
    }
    let mut bytes = vec![0_u8; PROC_PIDPATHINFO_MAXSIZE];
    // SAFETY: proc_pidpath writes at most the supplied buffer length.
    let length = unsafe {
        proc_pidpath(
            pid as libc::c_int,
            bytes.as_mut_ptr().cast(),
            bytes.len() as u32,
        )
    };
    if length <= 0 {
        return Err(std::io::Error::last_os_error());
    }
    bytes.truncate(length as usize);
    Ok(PathBuf::from(String::from_utf8_lossy(&bytes).into_owned()))
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn read_process_executable(_pid: u32) -> std::io::Result<PathBuf> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "executable identity verification is unsupported on this platform",
    ))
}

#[cfg(unix)]
fn process_exists(pid: u32) -> bool {
    let Ok(pid) = libc::pid_t::try_from(pid) else {
        return true;
    };
    // SAFETY: signal 0 performs an existence/permission probe only.
    let rc = unsafe { libc::kill(pid, 0) };
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

#[cfg(any(target_os = "linux", test))]
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

#[cfg(any(unix, test))]
pub fn cmdline_is_cockpit_daemon(
    args: &[String],
    observed_executable: &Path,
    approved_executable: &Path,
) -> bool {
    if args.is_empty() {
        return false;
    }
    exact_executable_identity(observed_executable, approved_executable)
        && args
            .windows(2)
            .any(|pair| pair[0] == "daemon" && pair[1] == "start")
}

#[cfg(any(unix, test))]
fn exact_executable_identity(observed: &Path, approved: &Path) -> bool {
    let Ok(observed) = std::fs::canonicalize(observed) else {
        return false;
    };
    let Ok(approved) = std::fs::canonicalize(approved) else {
        return false;
    };
    observed == approved
}

#[derive(Debug, Deserialize)]
struct EndpointRecord {
    pid: u32,
    socket: PathBuf,
    executable: PathBuf,
}

/// Drop guard for foreground-owned PID/socket/endpoint metadata.
#[derive(Debug)]
pub struct ForegroundMetadataGuard {
    pid_file: PathBuf,
    socket: PathBuf,
    endpoint_record: Option<PathBuf>,
    receipt: DaemonPidReceipt,
    armed: bool,
}

impl ForegroundMetadataGuard {
    pub fn new(
        pid_file: PathBuf,
        socket: PathBuf,
        endpoint_record: Option<PathBuf>,
        receipt: DaemonPidReceipt,
    ) -> Self {
        Self {
            pid_file,
            socket,
            endpoint_record,
            receipt,
            armed: true,
        }
    }

    pub fn cleanup(&mut self) {
        if self.armed
            && remove_metadata_if_receipt_matches(&self.pid_file, &self.socket, &self.receipt)
        {
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
        if record.pid == self.receipt.pid
            && record.socket == self.socket
            && record.executable == self.receipt.executable
        {
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
    fn daemon_cmdline_requires_exact_approved_executable() {
        let temp = tempfile::tempdir().expect("tempdir");
        let approved = temp.path().join("cockpit");
        let lookalike = temp.path().join("cockpit-malware");
        std::fs::write(&approved, b"approved").expect("approved executable fixture");
        std::fs::write(&lookalike, b"lookalike").expect("lookalike executable fixture");

        assert!(cmdline_is_cockpit_daemon(
            &[
                approved.display().to_string(),
                "daemon".into(),
                "start".into(),
            ],
            &approved,
            &approved,
        ));
        assert!(!cmdline_is_cockpit_daemon(
            &[
                lookalike.display().to_string(),
                "daemon".into(),
                "start".into(),
            ],
            &lookalike,
            &approved,
        ));
        assert!(!cmdline_is_cockpit_daemon(
            &[
                approved.display().to_string(),
                "daemon".into(),
                "status".into(),
            ],
            &approved,
            &approved,
        ));
    }

    #[test]
    fn pid_publication_binds_canonical_executable_identity() {
        let temp = tempfile::tempdir().expect("tempdir");
        let executable = temp.path().join("cockpit");
        let pid_file = temp.path().join("daemon.pid");
        std::fs::write(&executable, b"executable fixture").expect("executable fixture");

        let receipt = write_pid_file(&pid_file, 42, &executable).expect("publish pid identity");

        assert_eq!(read_pid_file(&pid_file), Some(42));
        assert_eq!(
            read_daemon_pid_record(&pid_file),
            Some(DaemonPidRecord::Receipt(receipt))
        );
    }

    #[cfg(unix)]
    #[test]
    fn pid_receipt_round_trips_non_utf8_and_newline_path_bytes() {
        use std::os::unix::ffi::OsStringExt as _;

        let temp = tempfile::tempdir().expect("tempdir");
        let name = std::ffi::OsString::from_vec(b"cockpit-\xff-\n-daemon".to_vec());
        let executable = temp.path().join(name);
        let pid_file = temp.path().join("daemon.pid");
        std::fs::write(&executable, b"executable fixture").expect("executable fixture");

        let receipt = write_pid_file(&pid_file, 42, &executable).expect("publish pid identity");

        assert_eq!(
            read_daemon_pid_record(&pid_file),
            Some(DaemonPidRecord::Receipt(receipt))
        );
    }

    #[test]
    fn obsolete_two_line_pid_receipt_fails_closed() {
        let temp = tempfile::tempdir().expect("tempdir");
        let pid_file = temp.path().join("daemon.pid");
        std::fs::write(&pid_file, "42\n/old/ambiguous/encoding\n").expect("old receipt");

        assert_eq!(read_daemon_pid_record(&pid_file), None);
    }

    #[cfg(unix)]
    #[test]
    fn dead_legacy_receipt_allows_stale_metadata_cleanup() {
        let temp = tempfile::tempdir().expect("tempdir");
        let pid_file = temp.path().join("daemon.pid");
        let socket = temp.path().join("daemon.sock");
        let dead_pid = i32::MAX as u32;
        std::fs::write(&pid_file, dead_pid.to_string()).expect("legacy pid receipt");
        std::fs::write(&socket, b"stale socket").expect("stale socket");

        assert_eq!(legacy_pid_identity(dead_pid), PidIdentity::Missing);
        assert!(remove_dead_legacy_metadata(&pid_file, &socket, dead_pid));
        assert!(!pid_file.exists());
        assert!(!socket.exists());
    }

    #[test]
    fn metadata_guard_removes_only_exact_owned_endpoint() {
        let temp = tempfile::tempdir().expect("tempdir");
        let pid_file = temp.path().join("daemon.pid");
        let socket = temp.path().join("daemon.sock");
        let endpoint = temp.path().join("daemon-endpoint.json");
        let executable = std::env::current_exe().expect("test executable");
        let receipt = write_pid_file(&pid_file, std::process::id(), &executable).expect("pid file");
        std::fs::write(&socket, b"socket metadata").expect("socket metadata");
        std::fs::write(
            &endpoint,
            serde_json::json!({"pid": receipt.pid, "socket": socket, "executable": receipt.executable.clone()}),
        )
        .expect("endpoint record");

        let mut guard = ForegroundMetadataGuard::new(
            pid_file.clone(),
            socket.clone(),
            Some(endpoint.clone()),
            receipt,
        );
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
        let executable = std::env::current_exe().expect("test executable");
        let receipt = write_pid_file(&pid_file, std::process::id(), &executable).expect("pid file");
        std::fs::write(
            &endpoint,
            serde_json::json!({"pid": receipt.pid, "socket": temp.path().join("other.sock"), "executable": receipt.executable.clone()}),
        )
        .expect("endpoint record");

        ForegroundMetadataGuard::new(pid_file, socket, Some(endpoint.clone()), receipt).cleanup();

        assert!(
            endpoint.exists(),
            "foreign endpoint receipt must survive cleanup"
        );
    }
}
