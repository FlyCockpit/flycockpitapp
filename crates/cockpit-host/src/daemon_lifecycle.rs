//! Host-owned daemon PID identity and metadata cleanup primitives.
//!
//! Protocol probing and daemon application state stay above this module. These
//! operations deal only in process identity and private host metadata, making
//! their ownership usable by both a foreground daemon and CLI lifecycle code.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonPidReceipt {
    pub pid: u32,
    pub executable: PathBuf,
    pub process_start: ProcessStartIdentity,
    pub publication_nonce: [u8; 32],
}

#[derive(Serialize, Deserialize)]
struct SerializedDaemonPidReceipt {
    version: u8,
    pid: u32,
    executable_identity: String,
    process_start: ProcessStartIdentity,
    publication_nonce_hex: String,
}

impl Serialize for DaemonPidReceipt {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        SerializedDaemonPidReceipt {
            version: 2,
            pid: self.pid,
            executable_identity: encode_executable_identity(&self.executable),
            process_start: self.process_start,
            publication_nonce_hex: hex_encode(&self.publication_nonce),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for DaemonPidReceipt {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = SerializedDaemonPidReceipt::deserialize(deserializer)?;
        if value.version != 2 {
            return Err(serde::de::Error::custom(
                "unsupported daemon receipt version",
            ));
        }
        let executable = decode_executable_identity(&value.executable_identity)
            .ok_or_else(|| serde::de::Error::custom("invalid executable identity"))?;
        let nonce = hex_decode(&value.publication_nonce_hex)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(|| serde::de::Error::custom("invalid publication nonce"))?;
        Ok(Self {
            pid: value.pid,
            executable,
            process_start: value.process_start,
            publication_nonce: nonce,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessStartIdentity {
    pub primary: u64,
    pub secondary: u64,
}

/// Capture the kernel process-start identity for an already-owned child.
/// Callers must retain a stable child/process handle while using this value so
/// a numeric PID cannot be recycled between capture and comparison.
pub fn process_start_identity(pid: u32) -> std::io::Result<ProcessStartIdentity> {
    read_process_start_identity(pid)
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
    let identity = verify_cockpit_daemon_receipt_identity(receipt);
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
    if first != "cockpit-daemon-pid-v2" {
        let pid = first.parse::<u32>().ok()?;
        if lines.next().is_some() {
            return None;
        }
        return Some(DaemonPidRecord::LegacyNumeric(pid));
    }
    let pid = lines.next()?.parse::<u32>().ok()?;
    let executable = decode_executable_identity(lines.next()?)?;
    let process_start = decode_process_start(lines.next()?)?;
    let nonce = hex_decode(lines.next()?.strip_prefix("nonce:")?)?;
    let publication_nonce: [u8; 32] = nonce.try_into().ok()?;
    if lines.next().is_some() {
        return None;
    }
    Some(DaemonPidRecord::Receipt(DaemonPidReceipt {
        pid,
        executable,
        process_start,
        publication_nonce,
    }))
}

/// Atomically publish a PID together with the exact canonical executable that
/// owns it. This receipt is the authority later used before signaling.
pub fn write_pid_file(
    pid_file: &Path,
    pid: u32,
    executable: &Path,
) -> anyhow::Result<DaemonPidReceipt> {
    with_lifecycle_lock(pid_file, || {
        write_pid_file_locked(pid_file, pid, executable)
    })
}

/// Atomically reclaim demonstrably stale lifecycle ownership and reserve it
/// for a new daemon incarnation. Live or unverifiable incumbents are never
/// replaced. The create-new write occurs before releasing the lifecycle lock.
#[cfg(unix)]
pub fn reclaim_stale_and_reserve(
    pid_file: &Path,
    socket: &Path,
    endpoint: Option<&Path>,
    pid: u32,
    executable: &Path,
) -> anyhow::Result<DaemonPidReceipt> {
    with_lifecycle_lock(pid_file, || {
        if pid_file.exists() {
            let incumbent = read_daemon_pid_record(pid_file)
                .ok_or_else(|| anyhow::anyhow!("existing daemon PID reservation is malformed"))?;
            let reclaimable = match &incumbent {
                DaemonPidRecord::Receipt(receipt) => {
                    match verify_cockpit_daemon_receipt_identity(receipt) {
                        PidIdentity::Missing => true,
                        // A recycled PID has a different kernel start identity
                        // and cannot own this reservation. A live matching
                        // incarnation remains protected even if argv probing
                        // observes it mid-transition.
                        PidIdentity::NotDaemon => read_process_start_identity(receipt.pid)
                            .is_ok_and(|start| start != receipt.process_start),
                        PidIdentity::VerifiedDaemon | PidIdentity::Unverified => false,
                    }
                }
                DaemonPidRecord::LegacyNumeric(pid) => {
                    legacy_pid_identity(*pid) == PidIdentity::Missing
                }
            };
            if !reclaimable {
                anyhow::bail!("existing daemon lifecycle reservation is live or unverifiable");
            }
            retire_incumbent_locked(pid_file, socket, endpoint, &incumbent)?;
        }
        write_pid_file_locked(pid_file, pid, executable)
    })
}

#[cfg(unix)]
fn retire_incumbent_locked(
    pid_file: &Path,
    socket: &Path,
    endpoint: Option<&Path>,
    incumbent: &DaemonPidRecord,
) -> anyhow::Result<()> {
    if read_daemon_pid_record(pid_file) != Some(incumbent.clone()) {
        anyhow::bail!("daemon lifecycle reservation changed during locked retirement");
    }
    if let (Some(endpoint), DaemonPidRecord::Receipt(receipt)) = (endpoint, incumbent) {
        retire_matching_endpoint(endpoint, socket, receipt)?;
    }
    match std::fs::remove_file(socket) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    match std::fs::remove_file(pid_file) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn write_pid_file_locked(
    pid_file: &Path,
    pid: u32,
    executable: &Path,
) -> anyhow::Result<DaemonPidReceipt> {
    let executable = std::fs::canonicalize(executable)?;
    let process_start = read_process_start_identity(pid)?;
    let publication_nonce = rand::random::<[u8; 32]>();
    let body = format!(
        "cockpit-daemon-pid-v2\n{pid}\n{}\nstart:{:016x}:{:016x}\nnonce:{}\n",
        encode_executable_identity(&executable),
        process_start.primary,
        process_start.secondary,
        hex_encode(&publication_nonce),
    );
    crate::private_fs::write_private_file_exclusive(pid_file, body.as_bytes())?;
    Ok(DaemonPidReceipt {
        pid,
        executable,
        process_start,
        publication_nonce,
    })
}

pub fn with_lifecycle_lock<T>(
    pid_file: &Path,
    action: impl FnOnce() -> anyhow::Result<T>,
) -> anyhow::Result<T> {
    let lock_path = pid_file.with_extension("lifecycle.lock");
    let lock = open_lifecycle_lock(&lock_path)?;
    lock.lock()?;
    action()
}

#[cfg(unix)]
fn open_lifecycle_lock(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;
    std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .read(true)
        .write(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn open_lifecycle_lock(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(path)
}

fn decode_process_start(value: &str) -> Option<ProcessStartIdentity> {
    let mut parts = value.strip_prefix("start:")?.split(':');
    let primary = u64::from_str_radix(parts.next()?, 16).ok()?;
    let secondary = u64::from_str_radix(parts.next()?, 16).ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some(ProcessStartIdentity { primary, secondary })
}

#[cfg(unix)]
fn encode_executable_identity(executable: &Path) -> String {
    use std::os::unix::ffi::OsStrExt as _;
    format!(
        "unix-bytes:{}",
        hex_encode(executable.as_os_str().as_bytes())
    )
}

#[cfg(windows)]
fn encode_executable_identity(executable: &Path) -> String {
    use std::os::windows::ffi::OsStrExt as _;
    let bytes: Vec<u8> = executable
        .as_os_str()
        .encode_wide()
        .flat_map(u16::to_le_bytes)
        .collect();
    format!("windows-utf16le:{}", hex_encode(&bytes))
}

#[cfg(unix)]
fn decode_executable_identity(value: &str) -> Option<PathBuf> {
    use std::os::unix::ffi::OsStringExt as _;
    Some(PathBuf::from(std::ffi::OsString::from_vec(hex_decode(
        value.strip_prefix("unix-bytes:")?,
    )?)))
}

#[cfg(windows)]
fn decode_executable_identity(value: &str) -> Option<PathBuf> {
    use std::os::windows::ffi::OsStringExt as _;
    let bytes = hex_decode(value.strip_prefix("windows-utf16le:")?)?;
    if bytes.len() % 2 != 0 {
        return None;
    }
    let wide: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect();
    Some(PathBuf::from(std::ffi::OsString::from_wide(&wide)))
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
    if !value.len().is_multiple_of(2) {
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

pub fn retire_metadata_if_receipt_matches(
    pid_file: &Path,
    socket: &Path,
    endpoint: Option<&Path>,
    expected: &DaemonPidReceipt,
) -> anyhow::Result<bool> {
    with_lifecycle_lock(pid_file, || {
        if read_daemon_pid_record(pid_file) != Some(DaemonPidRecord::Receipt(expected.clone())) {
            return Ok(false);
        }
        if let Some(endpoint) = endpoint {
            retire_matching_endpoint(endpoint, socket, expected)?;
        }
        match std::fs::remove_file(socket) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        match std::fs::remove_file(pid_file) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        Ok(true)
    })
}

fn retire_matching_endpoint(
    endpoint: &Path,
    socket: &Path,
    expected: &DaemonPidReceipt,
) -> anyhow::Result<()> {
    let bytes = match std::fs::read(endpoint) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    // A readable malformed or deliberately mismatching record is not ours and
    // is preserved. An unreadable authoritative path is different: callers
    // must fail before retiring PID/socket ownership.
    let Ok(record) = serde_json::from_slice::<EndpointRecord>(&bytes) else {
        return Ok(());
    };
    if record.receipt == *expected && record.socket == socket {
        std::fs::remove_file(endpoint)?;
    }
    Ok(())
}

#[cfg(unix)]
pub fn remove_dead_legacy_metadata(
    pid_file: &Path,
    socket: &Path,
    expected_pid: u32,
) -> anyhow::Result<bool> {
    with_lifecycle_lock(pid_file, || {
        if read_daemon_pid_record(pid_file) != Some(DaemonPidRecord::LegacyNumeric(expected_pid))
            || legacy_pid_identity(expected_pid) != PidIdentity::Missing
        {
            return Ok(false);
        }
        match std::fs::remove_file(socket) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        match std::fs::remove_file(pid_file) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        Ok(true)
    })
}

/// Verify that a live PID is the exact approved Cockpit executable and its
/// argv is a daemon-start invocation. The approved executable is explicit so
/// production can bind verification to the executable that published the
/// lifecycle metadata; tests must pass their own test-binary path deliberately.
#[cfg(unix)]
pub fn verify_cockpit_daemon_receipt_identity(receipt: &DaemonPidReceipt) -> PidIdentity {
    if !process_exists(receipt.pid) {
        return PidIdentity::Missing;
    }
    let start = match read_process_start_identity(receipt.pid) {
        Ok(start) => start,
        Err(_) => return PidIdentity::Unverified,
    };
    if start != receipt.process_start {
        return PidIdentity::NotDaemon;
    }
    let executable = match read_process_executable(receipt.pid) {
        Ok(executable) => executable,
        Err(_) => return PidIdentity::Unverified,
    };
    let args = match read_process_cmdline(receipt.pid) {
        Ok(args) => args,
        Err(_) => return PidIdentity::Unverified,
    };
    let daemon_argv = args
        .windows(2)
        .any(|pair| pair[0] == "daemon" && pair[1] == "start");
    if cmdline_is_cockpit_daemon(&args, &executable, &receipt.executable) {
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
fn read_process_start_identity(pid: u32) -> std::io::Result<ProcessStartIdentity> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let suffix = stat
        .rsplit_once(')')
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "malformed /proc stat")
        })?
        .1;
    let start = suffix
        .split_whitespace()
        .nth(19)
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "missing process starttime")
        })?;
    Ok(ProcessStartIdentity {
        primary: start,
        secondary: 0,
    })
}

#[cfg(target_os = "macos")]
fn read_process_start_identity(pid: u32) -> std::io::Result<ProcessStartIdentity> {
    #[repr(C)]
    struct ProcBsdInfo {
        flags: u32,
        status: u32,
        xstatus: u32,
        pid: u32,
        ppid: u32,
        uid: u32,
        gid: u32,
        ruid: u32,
        rgid: u32,
        svuid: u32,
        svgid: u32,
        rfu_1: u32,
        comm: [libc::c_char; 16],
        name: [libc::c_char; 32],
        nfiles: u32,
        pgid: u32,
        pjobc: u32,
        e_tdev: u32,
        e_tpgid: u32,
        nice: i32,
        start_sec: u64,
        start_usec: u64,
    }
    const _: () = assert!(std::mem::size_of::<ProcBsdInfo>() == 136);
    const _: () = assert!(std::mem::offset_of!(ProcBsdInfo, start_sec) == 120);
    const _: () = assert!(std::mem::offset_of!(ProcBsdInfo, start_usec) == 128);
    #[link(name = "proc")]
    unsafe extern "C" {
        fn proc_pidinfo(
            pid: libc::c_int,
            flavor: libc::c_int,
            arg: u64,
            buffer: *mut libc::c_void,
            size: libc::c_int,
        ) -> libc::c_int;
    }
    let mut info = std::mem::MaybeUninit::<ProcBsdInfo>::zeroed();
    let size = std::mem::size_of::<ProcBsdInfo>() as libc::c_int;
    let read = unsafe { proc_pidinfo(pid as libc::c_int, 3, 0, info.as_mut_ptr().cast(), size) };
    if read != size {
        return if read <= 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("proc_pidinfo returned {read} bytes; expected {size}"),
            ))
        };
    }
    let info = unsafe { info.assume_init() };
    Ok(ProcessStartIdentity {
        primary: info.start_sec,
        secondary: info.start_usec,
    })
}

#[cfg(windows)]
fn read_process_start_identity(pid: u32) -> std::io::Result<ProcessStartIdentity> {
    #[repr(C)]
    struct FileTime {
        low: u32,
        high: u32,
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn OpenProcess(access: u32, inherit: i32, pid: u32) -> *mut std::ffi::c_void;
        fn GetProcessTimes(
            handle: *mut std::ffi::c_void,
            creation: *mut FileTime,
            exit: *mut FileTime,
            kernel: *mut FileTime,
            user: *mut FileTime,
        ) -> i32;
        fn CloseHandle(handle: *mut std::ffi::c_void) -> i32;
    }
    let handle = unsafe { OpenProcess(0x1000, 0, pid) };
    if handle.is_null() {
        return Err(std::io::Error::last_os_error());
    }
    let mut creation = FileTime { low: 0, high: 0 };
    let mut exit = FileTime { low: 0, high: 0 };
    let mut kernel = FileTime { low: 0, high: 0 };
    let mut user = FileTime { low: 0, high: 0 };
    let ok = unsafe { GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user) };
    let error = (ok == 0).then(std::io::Error::last_os_error);
    unsafe {
        CloseHandle(handle);
    }
    if let Some(error) = error {
        return Err(error);
    }
    Ok(ProcessStartIdentity {
        primary: ((creation.high as u64) << 32) | creation.low as u64,
        secondary: 0,
    })
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn read_process_start_identity(_pid: u32) -> std::io::Result<ProcessStartIdentity> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "stable process-start identity is unsupported on this platform",
    ))
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

/// Kernel existence probe (`kill(pid, 0)`). Used by restart to wait until a
/// draining daemon has actually exited and released its exclusive boot lock,
/// not merely unlinked its pid/socket files.
#[cfg(unix)]
pub fn process_exists(pid: u32) -> bool {
    let Ok(pid) = libc::pid_t::try_from(pid) else {
        // An unrepresentable pid cannot be our daemon. Treat it as released
        // so restart waits do not stall and then attach to an unlinked socket.
        return false;
    };
    // SAFETY: signal 0 performs an existence/permission probe only.
    let rc = unsafe { libc::kill(pid, 0) };
    if rc != 0 {
        // ESRCH: gone. EPERM and conversion-adjacent errors: we cannot prove
        // this pid is our daemon, so fail toward released rather than waiting
        // forever.
        return false;
    }
    !process_is_unreaped_zombie(pid)
}

#[cfg(target_os = "linux")]
fn process_is_unreaped_zombie(pid: libc::pid_t) -> bool {
    let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
        return false;
    };
    // comm may contain spaces and parentheses; the state field follows the
    // last ')' of the comm field.
    stat.rsplit_once(')')
        .and_then(|(_, rest)| rest.split_whitespace().next())
        == Some("Z")
}

#[cfg(all(unix, not(target_os = "linux")))]
fn process_is_unreaped_zombie(_pid: libc::pid_t) -> bool {
    false
}

#[cfg(all(unix, target_os = "linux"))]
pub fn read_process_cmdline(pid: u32) -> std::io::Result<Vec<String>> {
    let bytes = std::fs::read(format!("/proc/{pid}/cmdline"))?;
    Ok(split_proc_cmdline(&bytes))
}

#[cfg(all(unix, target_os = "macos"))]
pub fn read_process_cmdline(pid: u32) -> std::io::Result<Vec<String>> {
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
pub fn read_process_cmdline(_pid: u32) -> std::io::Result<Vec<String>> {
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

#[derive(Debug, Serialize, Deserialize)]
struct EndpointRecord {
    socket: PathBuf,
    receipt: DaemonPidReceipt,
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

    pub fn cleanup(&mut self) -> anyhow::Result<()> {
        if self.armed {
            retire_metadata_if_receipt_matches(
                &self.pid_file,
                &self.socket,
                self.endpoint_record.as_deref(),
                &self.receipt,
            )?;
        }
        self.armed = false;
        Ok(())
    }
}

impl Drop for ForegroundMetadataGuard {
    fn drop(&mut self) {
        if let Err(error) = self.cleanup() {
            eprintln!("failed to retire daemon lifecycle metadata: {error:#}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_receipt_fixture(path: &Path, receipt: &DaemonPidReceipt) {
        let body = format!(
            "cockpit-daemon-pid-v2\n{}\n{}\nstart:{:016x}:{:016x}\nnonce:{}\n",
            receipt.pid,
            encode_executable_identity(&receipt.executable),
            receipt.process_start.primary,
            receipt.process_start.secondary,
            hex_encode(&receipt.publication_nonce),
        );
        crate::private_fs::write_private_file_exclusive(path, body.as_bytes())
            .expect("receipt fixture");
    }

    #[test]
    fn process_exists_reports_current_process_and_treats_unrepresentable_pid_as_released() {
        assert!(process_exists(std::process::id()));
        assert!(
            !process_exists(u32::MAX),
            "pid conversion failure must fail toward released"
        );
    }

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

        let pid = std::process::id();
        let receipt = write_pid_file(&pid_file, pid, &executable).expect("publish pid identity");

        assert_eq!(read_pid_file(&pid_file), Some(pid));
        assert_eq!(
            read_daemon_pid_record(&pid_file),
            Some(DaemonPidRecord::Receipt(receipt))
        );
    }

    #[test]
    fn pid_publication_is_an_exclusive_starting_reservation() {
        let temp = tempfile::tempdir().expect("tempdir");
        let executable = std::env::current_exe().expect("test executable");
        let pid_file = temp.path().join("daemon.pid");
        let first =
            write_pid_file(&pid_file, std::process::id(), &executable).expect("first reservation");

        write_pid_file(&pid_file, std::process::id(), &executable)
            .expect_err("second starter must not replace reservation");

        assert_eq!(
            read_daemon_pid_record(&pid_file),
            Some(DaemonPidRecord::Receipt(first))
        );
    }

    #[cfg(unix)]
    #[test]
    fn concurrent_starting_reservations_have_exactly_one_winner() {
        let temp = tempfile::tempdir().expect("tempdir");
        let pid_file = temp.path().join("daemon.pid");
        let socket = temp.path().join("daemon.sock");
        let executable = std::env::current_exe().expect("test executable");
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let attempts: Vec<_> = (0..2)
            .map(|_| {
                let pid_file = pid_file.clone();
                let socket = socket.clone();
                let executable = executable.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    reclaim_stale_and_reserve(
                        &pid_file,
                        &socket,
                        None,
                        std::process::id(),
                        &executable,
                    )
                })
            })
            .collect();
        let results: Vec<_> = attempts
            .into_iter()
            .map(|attempt| attempt.join().expect("starter thread"))
            .collect();

        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(results.iter().filter(|result| result.is_err()).count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn stale_incarnation_is_reclaimed_inside_reservation_transaction() {
        let temp = tempfile::tempdir().expect("tempdir");
        let pid_file = temp.path().join("daemon.pid");
        let socket = temp.path().join("daemon.sock");
        let executable = std::fs::canonicalize(std::env::current_exe().unwrap()).unwrap();
        let stale = DaemonPidReceipt {
            pid: i32::MAX as u32,
            executable: executable.clone(),
            process_start: ProcessStartIdentity {
                primary: 1,
                secondary: 0,
            },
            publication_nonce: [3; 32],
        };
        write_receipt_fixture(&pid_file, &stale);
        std::fs::write(&socket, b"stale socket").expect("stale socket");

        let reserved =
            reclaim_stale_and_reserve(&pid_file, &socket, None, std::process::id(), &executable)
                .expect("reclaim and reserve");

        assert_ne!(reserved.publication_nonce, stale.publication_nonce);
        assert!(!socket.exists());
        assert_eq!(
            read_daemon_pid_record(&pid_file),
            Some(DaemonPidRecord::Receipt(reserved))
        );
    }

    #[cfg(unix)]
    #[test]
    fn stale_reclaim_preserves_incumbent_when_endpoint_is_unreadable() {
        let temp = tempfile::tempdir().expect("tempdir");
        let pid_file = temp.path().join("daemon.pid");
        let socket = temp.path().join("daemon.sock");
        let endpoint = temp.path().join("daemon-endpoint.json");
        let executable = std::fs::canonicalize(std::env::current_exe().unwrap()).unwrap();
        let stale = DaemonPidReceipt {
            pid: i32::MAX as u32,
            executable: executable.clone(),
            process_start: ProcessStartIdentity {
                primary: 1,
                secondary: 0,
            },
            publication_nonce: [9; 32],
        };
        write_receipt_fixture(&pid_file, &stale);
        std::fs::write(&socket, b"stale socket").expect("stale socket");
        std::fs::create_dir(&endpoint).expect("endpoint directory fixture");

        reclaim_stale_and_reserve(
            &pid_file,
            &socket,
            Some(&endpoint),
            std::process::id(),
            &executable,
        )
        .expect_err("unreadable endpoint must abort stale reclaim");

        assert_eq!(
            read_daemon_pid_record(&pid_file),
            Some(DaemonPidRecord::Receipt(stale))
        );
        assert!(socket.exists());
        assert!(endpoint.is_dir());
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

        let receipt = write_pid_file(&pid_file, std::process::id(), &executable)
            .expect("publish pid identity");

        assert_eq!(
            read_daemon_pid_record(&pid_file),
            Some(DaemonPidRecord::Receipt(receipt.clone()))
        );
        let endpoint = EndpointRecord {
            socket: temp.path().join("daemon.sock"),
            receipt,
        };
        let encoded = serde_json::to_vec(&endpoint).expect("serialize endpoint");
        let decoded: EndpointRecord = serde_json::from_slice(&encoded).expect("decode endpoint");
        assert_eq!(decoded.receipt, endpoint.receipt);
    }

    #[test]
    fn obsolete_two_line_pid_receipt_fails_closed() {
        let temp = tempfile::tempdir().expect("tempdir");
        let pid_file = temp.path().join("daemon.pid");
        std::fs::write(&pid_file, "42\n/old/ambiguous/encoding\n").expect("old receipt");

        assert_eq!(read_daemon_pid_record(&pid_file), None);
    }

    #[cfg(windows)]
    #[test]
    fn windows_executable_encoding_round_trips_unpaired_utf16() {
        use std::os::windows::ffi::OsStringExt as _;
        let path = PathBuf::from(std::ffi::OsString::from_wide(&[
            b'C' as u16,
            b':' as u16,
            b'\\' as u16,
            0xd800,
            b'.' as u16,
            b'e' as u16,
            b'x' as u16,
            b'e' as u16,
        ]));

        assert_eq!(
            decode_executable_identity(&encode_executable_identity(&path)),
            Some(path.clone())
        );
        let endpoint = EndpointRecord {
            socket: PathBuf::from("daemon.sock"),
            receipt: DaemonPidReceipt {
                pid: 42,
                executable: path,
                process_start: ProcessStartIdentity {
                    primary: 1,
                    secondary: 0,
                },
                publication_nonce: [7; 32],
            },
        };
        let encoded = serde_json::to_vec(&endpoint).expect("serialize endpoint");
        let decoded: EndpointRecord = serde_json::from_slice(&encoded).expect("decode endpoint");
        assert_eq!(decoded.receipt, endpoint.receipt);
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
        assert!(remove_dead_legacy_metadata(&pid_file, &socket, dead_pid).expect("legacy cleanup"));
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
            serde_json::to_vec(&serde_json::json!({"socket": socket, "receipt": receipt.clone()}))
                .expect("serialize endpoint"),
        )
        .expect("endpoint record");

        let mut guard = ForegroundMetadataGuard::new(
            pid_file.clone(),
            socket.clone(),
            Some(endpoint.clone()),
            receipt,
        );
        guard.cleanup().expect("guard cleanup");

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
            serde_json::to_vec(&serde_json::json!({"socket": temp.path().join("other.sock"), "receipt": receipt.clone()}))
                .expect("serialize endpoint"),
        )
        .expect("endpoint record");

        ForegroundMetadataGuard::new(
            pid_file.clone(),
            socket.clone(),
            Some(endpoint.clone()),
            receipt,
        )
        .cleanup()
        .expect("guard cleanup");

        assert!(
            endpoint.exists(),
            "foreign endpoint receipt must survive cleanup"
        );
        assert!(!pid_file.exists(), "owned PID receipt must still retire");
        assert!(!socket.exists(), "owned socket must still retire");
    }

    #[test]
    fn boot_failure_guard_releases_reservation_without_endpoint() {
        let temp = tempfile::tempdir().expect("tempdir");
        let pid_file = temp.path().join("daemon.pid");
        let socket = temp.path().join("daemon.sock");
        let endpoint = temp.path().join("daemon-endpoint.json");
        let executable = std::env::current_exe().expect("test executable");
        let receipt = write_pid_file(&pid_file, std::process::id(), &executable).expect("pid file");

        ForegroundMetadataGuard::new(
            pid_file.clone(),
            socket.clone(),
            Some(endpoint.clone()),
            receipt,
        )
        .cleanup()
        .expect("boot failure cleanup");

        assert!(!pid_file.exists());
        assert!(!socket.exists());
        assert!(!endpoint.exists());
    }

    #[test]
    fn unreadable_endpoint_aborts_before_owned_pid_and_socket_retirement() {
        let temp = tempfile::tempdir().expect("tempdir");
        let pid_file = temp.path().join("daemon.pid");
        let socket = temp.path().join("daemon.sock");
        let endpoint = temp.path().join("daemon-endpoint.json");
        let executable = std::env::current_exe().expect("test executable");
        let receipt = write_pid_file(&pid_file, std::process::id(), &executable).expect("pid file");
        std::fs::write(&socket, b"owned socket").expect("socket fixture");
        std::fs::create_dir(&endpoint).expect("endpoint directory fixture");

        let error =
            retire_metadata_if_receipt_matches(&pid_file, &socket, Some(&endpoint), &receipt)
                .expect_err("directory endpoint must be an authoritative read error");

        assert!(
            error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|error| error.kind() != std::io::ErrorKind::NotFound)
        );
        assert!(pid_file.exists(), "PID receipt must remain on read error");
        assert!(socket.exists(), "socket must remain on read error");
        assert!(endpoint.is_dir(), "unreadable endpoint must remain");
    }
}
