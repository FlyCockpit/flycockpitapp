//! Local daemon named-pipe identity (Windows) and the portable identity file.
//!
//! The published Windows daemon never binds a well-known unprotected pipe such
//! as `\\.\pipe\cockpit`. The listen name is per-user (current-user SID
//! fingerprint) and per-daemon (a 16-byte random nonce). The filesystem path
//! still used as `DaemonPaths.socket` is an owner-only identity file that
//! names that pipe; clients that see the file expect a live hello promptly,
//! matching the Unix socket-file publication barrier.
//!
//! Stale-owner discovery is explicit: an identity file with no listening pipe
//! is not "running". Callers must treat a missing pipe as stale rather than
//! hanging on an unbounded connect.

use std::path::Path;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Identity-file schema version. Protocol versioning is reset at launch; this
/// is a local discovery document, not a wire version.
pub const PIPE_IDENTITY_VERSION: u8 = 1;

const PIPE_PREFIX: &str = r"\\.\pipe\cockpit-";
const SID_FINGERPRINT_HEX_LEN: usize = 16;
const NONCE_LEN: usize = 16;
const NONCE_HEX_LEN: usize = NONCE_LEN * 2;
const LEAK_REVEAL_SUFFIX: &str = "-leak-reveal";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PipeIdentityRecord {
    version: u8,
    pipe: String,
}

/// A validated local Cockpit pipe name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PipeName(String);

impl PipeName {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn leak_reveal_sibling(&self) -> Result<Self> {
        if self.0.ends_with(LEAK_REVEAL_SUFFIX) {
            bail!("leak-reveal pipe cannot itself have a reveal sibling");
        }
        parse_pipe_name(format!("{}{LEAK_REVEAL_SUFFIX}", self.0))
    }
}

impl AsRef<str> for PipeName {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

/// Derive the per-user, per-daemon listen name from the current-user SID and a
/// random 16-byte nonce. The SID is hashed so the pipe name cannot be guessed
/// from a well-known username and never appears as a global `\\.\pipe\cockpit`.
pub fn derive_pipe_name(user_sid: &str, nonce: &[u8; NONCE_LEN]) -> Result<PipeName> {
    if user_sid.is_empty() || !user_sid.starts_with("S-") {
        bail!("refusing to derive a daemon pipe name from an invalid user SID");
    }
    if nonce.iter().all(|byte| *byte == 0) {
        bail!("refusing to derive a daemon pipe name from a zero nonce");
    }
    let fingerprint = sid_fingerprint(user_sid);
    let nonce_hex = hex_lower(nonce);
    parse_pipe_name(format!("{PIPE_PREFIX}{fingerprint}-{nonce_hex}"))
}

pub fn allocate_pipe_name(user_sid: &str) -> Result<PipeName> {
    derive_pipe_name(user_sid, &rand::random())
}

pub fn parse_pipe_name(name: impl Into<String>) -> Result<PipeName> {
    let name = name.into();
    validate_pipe_name(&name)?;
    Ok(PipeName(name))
}

/// Reject well-known and under-specified pipe names. A valid name is
/// `\\.\pipe\cockpit-<16 hex SID fingerprint>-<32 hex nonce>` with an optional
/// `-leak-reveal` suffix.
pub fn validate_pipe_name(name: &str) -> Result<()> {
    let rest = name
        .strip_prefix(PIPE_PREFIX)
        .ok_or_else(|| anyhow::anyhow!("daemon pipe name must use the private cockpit prefix"))?;
    if rest.is_empty() || rest == "sock" || rest == "daemon" {
        bail!("refusing well-known unprotected daemon pipe name {name}");
    }
    let (body, reveal) = match rest.strip_suffix(LEAK_REVEAL_SUFFIX) {
        Some(body) => (body, true),
        None => (rest, false),
    };
    let Some((fingerprint, nonce)) = body.split_once('-') else {
        bail!("daemon pipe name {name} is missing the per-daemon nonce");
    };
    if fingerprint.len() != SID_FINGERPRINT_HEX_LEN || !is_lower_hex(fingerprint) {
        bail!("daemon pipe name {name} does not carry a per-user SID fingerprint");
    }
    if nonce.len() != NONCE_HEX_LEN || !is_lower_hex(nonce) {
        bail!("daemon pipe name {name} does not carry a per-daemon nonce");
    }
    if body.matches('-').count() != 1 {
        bail!("daemon pipe name {name} has extra components");
    }
    let _ = reveal;
    Ok(())
}

pub fn write_pipe_identity(path: &Path, pipe: &PipeName) -> Result<()> {
    validate_pipe_name(pipe.as_str())?;
    if let Some(parent) = path.parent() {
        crate::private_fs::ensure_private_dir(parent)
            .with_context(|| format!("securing {}", parent.display()))?;
    }
    let record = PipeIdentityRecord {
        version: PIPE_IDENTITY_VERSION,
        pipe: pipe.as_str().to_string(),
    };
    let data = serde_json::to_vec_pretty(&record).context("serializing named-pipe identity")?;
    crate::private_fs::write_private_file(path, &data)
        .with_context(|| format!("writing {}", path.display()))
}

pub fn read_pipe_identity(path: &Path) -> Result<PipeName> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    parse_pipe_identity_bytes(&bytes)
        .with_context(|| format!("parsing named-pipe identity {}", path.display()))
}

pub fn read_pipe_identity_if_present(path: &Path) -> Result<Option<PipeName>> {
    match std::fs::read(path) {
        Ok(bytes) => parse_pipe_identity_bytes(&bytes)
            .map(Some)
            .with_context(|| format!("parsing named-pipe identity {}", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("reading {}", path.display())),
    }
}

fn parse_pipe_identity_bytes(bytes: &[u8]) -> Result<PipeName> {
    let record: PipeIdentityRecord =
        serde_json::from_slice(bytes).context("named-pipe identity is not JSON")?;
    if record.version != PIPE_IDENTITY_VERSION {
        bail!("unsupported named-pipe identity version {}", record.version);
    }
    parse_pipe_name(record.pipe)
}

fn sid_fingerprint(user_sid: &str) -> String {
    let digest = Sha256::digest(user_sid.as_bytes());
    hex_lower(&digest[..SID_FINGERPRINT_HEX_LEN / 2])
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn is_lower_hex(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

/// Owner-only DACL for a local named pipe: current-user Generic All, protected
/// (no inherited Everyone/Users ACEs), no remote clients at the SDDL layer.
#[cfg(windows)]
pub struct OwnerOnlyPipeSecurity {
    descriptor: windows_sys::Win32::Security::PSECURITY_DESCRIPTOR,
    attrs: windows_sys::Win32::Security::SECURITY_ATTRIBUTES,
}

#[cfg(windows)]
impl OwnerOnlyPipeSecurity {
    pub fn for_current_user() -> Result<Self> {
        let sid = current_user_sid()?;
        Self::from_sddl(&format!("D:P(A;;GA;;;{sid})"))
    }

    fn from_sddl(sddl: &str) -> Result<Self> {
        use windows_sys::Win32::Security::Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
        };
        let wide: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
        let mut descriptor = std::ptr::null_mut();
        // SAFETY: `wide` is a live NUL-terminated SDDL string; on success the
        // returned descriptor is LocalAlloc'd and owned by this value.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(std::io::Error::last_os_error())
                .context("building owner-only named-pipe security descriptor");
        }
        let attrs = windows_sys::Win32::Security::SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<windows_sys::Win32::Security::SECURITY_ATTRIBUTES>()
                as u32,
            lpSecurityDescriptor: descriptor,
            bInheritHandle: 0,
        };
        Ok(Self { descriptor, attrs })
    }

    pub fn as_mut_ptr(&mut self) -> *mut std::ffi::c_void {
        (&mut self.attrs as *mut windows_sys::Win32::Security::SECURITY_ATTRIBUTES).cast()
    }
}

#[cfg(windows)]
impl Drop for OwnerOnlyPipeSecurity {
    fn drop(&mut self) {
        if !self.descriptor.is_null() {
            // SAFETY: `descriptor` was allocated by
            // ConvertStringSecurityDescriptorToSecurityDescriptorW.
            unsafe {
                windows_sys::Win32::Foundation::LocalFree(self.descriptor.cast());
            }
            self.descriptor = std::ptr::null_mut();
            self.attrs.lpSecurityDescriptor = std::ptr::null_mut();
        }
    }
}

#[cfg(windows)]
pub fn current_user_sid() -> Result<String> {
    use windows_sys::Win32::Foundation::{CloseHandle, LocalFree};
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows_sys::Win32::Security::{GetTokenInformation, TOKEN_QUERY, TOKEN_USER, TokenUser};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut token = std::ptr::null_mut();
    // SAFETY: GetCurrentProcess returns a pseudo-handle; TOKEN_QUERY is the
    // documented access for TokenUser.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(std::io::Error::last_os_error()).context("opening process token");
    }
    let mut needed = 0_u32;
    // SAFETY: size probe; `needed` is a valid out-pointer.
    unsafe {
        GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut needed);
    }
    if needed == 0 {
        // SAFETY: `token` is the handle OpenProcessToken returned.
        unsafe { CloseHandle(token) };
        return Err(std::io::Error::last_os_error()).context("reading process SID size");
    }
    let mut buffer = vec![0_u8; needed as usize];
    // SAFETY: buffer is sized from the probe; token is still open.
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    };
    if ok == 0 {
        // SAFETY: `token` is still the live process token.
        unsafe { CloseHandle(token) };
        return Err(std::io::Error::last_os_error()).context("reading process SID");
    }
    // SAFETY: GetTokenInformation succeeded and initialized TOKEN_USER in `buffer`.
    let token_user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
    let mut sid_text = std::ptr::null_mut();
    // SAFETY: TOKEN_USER.User.Sid is a live SID inside `buffer`.
    let converted = unsafe { ConvertSidToStringSidW(token_user.User.Sid, &mut sid_text) };
    // SAFETY: `token` is still the live process token.
    unsafe { CloseHandle(token) };
    if converted == 0 {
        return Err(std::io::Error::last_os_error()).context("formatting process SID");
    }
    let mut len = 0_usize;
    // SAFETY: ConvertSidToStringSidW returns a NUL-terminated PWSTR.
    unsafe {
        while *sid_text.add(len) != 0 {
            len += 1;
        }
    }
    // SAFETY: `sid_text` points at `len` UTF-16 code units we just counted.
    let result = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(sid_text, len) });
    // SAFETY: ConvertSidToStringSidW allocated `sid_text` with LocalAlloc.
    unsafe { LocalFree(sid_text.cast()) };
    Ok(result)
}

/// True when a server instance of `pipe` is currently listening.
///
/// `WaitNamedPipeW` with `NMPWAIT_NOWAIT` returns immediately: success means
/// a live server, `ERROR_FILE_NOT_FOUND` means the owner is gone (stale
/// identity file), `ERROR_PIPE_BUSY` means instances exist but are all busy
/// (still a live owner).
#[cfg(windows)]
pub fn pipe_is_listening(pipe: &PipeName) -> bool {
    match wait_pipe(pipe, windows_sys::Win32::System::Pipes::NMPWAIT_NOWAIT) {
        WaitPipe::Ready | WaitPipe::Busy => true,
        WaitPipe::Missing | WaitPipe::Failed => false,
    }
}

#[cfg(windows)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitPipe {
    Ready,
    Busy,
    Missing,
    Failed,
}

#[cfg(windows)]
pub fn wait_pipe(pipe: &PipeName, timeout_ms: u32) -> WaitPipe {
    use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_PIPE_BUSY, GetLastError};
    use windows_sys::Win32::System::Pipes::WaitNamedPipeW;

    let wide: Vec<u16> = pipe
        .as_str()
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    // SAFETY: `wide` is a live NUL-terminated pipe name.
    let ok = unsafe { WaitNamedPipeW(wide.as_ptr(), timeout_ms) };
    if ok != 0 {
        return WaitPipe::Ready;
    }
    // SAFETY: GetLastError reads the thread's last error from WaitNamedPipeW.
    match unsafe { GetLastError() } {
        ERROR_PIPE_BUSY => WaitPipe::Busy,
        ERROR_FILE_NOT_FOUND => WaitPipe::Missing,
        _ => WaitPipe::Failed,
    }
}

/// Same-user check used after a named-pipe accept. Complements the owner-only
/// DACL: a connected client must present the daemon's user SID.
#[cfg(windows)]
pub fn named_pipe_peer_is_current_user(handle: std::os::windows::io::RawHandle) -> Result<()> {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Security::EqualSid;
    use windows_sys::Win32::System::Pipes::GetNamedPipeClientProcessId;
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

    let mut client_pid = 0_u32;
    // SAFETY: `handle` is a connected named-pipe server end owned by the caller.
    let got_pid = unsafe { GetNamedPipeClientProcessId(handle as HANDLE, &mut client_pid) };
    if got_pid == 0 {
        return Err(std::io::Error::last_os_error())
            .context("reading named-pipe client process id");
    }
    // SAFETY: client_pid came from GetNamedPipeClientProcessId on a connected pipe.
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, client_pid) };
    if process.is_null() || process == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error()).context("opening named-pipe client process");
    }
    let client_sid = match process_user_sid(process) {
        Ok(sid) => {
            // SAFETY: `process` is the handle OpenProcess returned.
            unsafe { CloseHandle(process) };
            sid
        }
        Err(error) => {
            // SAFETY: `process` is the handle OpenProcess returned.
            unsafe { CloseHandle(process) };
            return Err(error);
        }
    };
    let daemon_sid = current_user_sid_bytes()?;
    // SAFETY: both SID buffers are live TokenUser allocations.
    let equal = unsafe { EqualSid(client_sid.as_ptr().cast(), daemon_sid.as_ptr().cast()) };
    if equal == 0 {
        bail!("named-pipe peer SID does not match the daemon owner");
    }
    Ok(())
}

#[cfg(windows)]
fn process_user_sid(process: windows_sys::Win32::Foundation::HANDLE) -> Result<Vec<u8>> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::Security::TOKEN_QUERY;
    use windows_sys::Win32::System::Threading::OpenProcessToken;

    let mut token = std::ptr::null_mut();
    // SAFETY: `process` is a live process handle with QUERY_LIMITED_INFORMATION.
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 {
        return Err(std::io::Error::last_os_error()).context("opening client process token");
    }
    let buffer = match token_user_bytes(token) {
        Ok(buffer) => buffer,
        Err(error) => {
            // SAFETY: `token` is the handle OpenProcessToken returned.
            unsafe { CloseHandle(token) };
            return Err(error);
        }
    };
    // SAFETY: `token` is the handle OpenProcessToken returned.
    unsafe { CloseHandle(token) };
    Ok(buffer)
}

#[cfg(windows)]
fn current_user_sid_bytes() -> Result<Vec<u8>> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::Security::TOKEN_QUERY;
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut token = std::ptr::null_mut();
    // SAFETY: GetCurrentProcess is a pseudo-handle; TOKEN_QUERY is documented for TokenUser.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(std::io::Error::last_os_error()).context("opening daemon process token");
    }
    let buffer = match token_user_bytes(token) {
        Ok(buffer) => buffer,
        Err(error) => {
            // SAFETY: `token` is the handle OpenProcessToken returned.
            unsafe { CloseHandle(token) };
            return Err(error);
        }
    };
    // SAFETY: `token` is the handle OpenProcessToken returned.
    unsafe { CloseHandle(token) };
    Ok(buffer)
}

#[cfg(windows)]
fn token_user_bytes(token: windows_sys::Win32::Foundation::HANDLE) -> Result<Vec<u8>> {
    use windows_sys::Win32::Security::{
        CopySid, GetLengthSid, GetTokenInformation, TOKEN_USER, TokenUser,
    };

    let mut needed = 0_u32;
    // SAFETY: size probe; `needed` is a valid out-pointer for a live token.
    unsafe {
        GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut needed);
    }
    if needed == 0 {
        return Err(std::io::Error::last_os_error()).context("reading token user size");
    }
    let mut buffer = vec![0_u8; needed as usize];
    // SAFETY: buffer is sized from the probe; token is still open.
    if unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error()).context("reading token user");
    }
    // SAFETY: GetTokenInformation initialized TOKEN_USER in `buffer`.
    let token_user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
    // SAFETY: User.Sid is a live SID inside `buffer`.
    let sid_len = unsafe { GetLengthSid(token_user.User.Sid) };
    let mut sid = vec![0_u8; sid_len as usize];
    // SAFETY: `sid` is sid_len bytes; source SID is live in `buffer`.
    if unsafe { CopySid(sid_len, sid.as_mut_ptr().cast(), token_user.User.Sid) } == 0 {
        return Err(std::io::Error::last_os_error()).context("copying token user SID");
    }
    Ok(sid)
}

/// Blocking client open used by discovery probes that run before a Tokio
/// runtime owns the thread.
#[cfg(windows)]
pub fn open_client_pipe_blocking(pipe: &PipeName) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(pipe.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_well_known_unprotected_pipe_names() {
        for name in [
            r"\\.\pipe\cockpit",
            r"\\.\pipe\cockpit.sock",
            r"\\.\pipe\cockpit-sock",
            r"\\.\pipe\cockpit-daemon",
            r"\\.\pipe\cockpit-",
            r"\\pipe\cockpit-aaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        ] {
            validate_pipe_name(name).expect_err(name);
        }
    }

    #[test]
    fn accepts_per_user_per_daemon_pipe_names() {
        let nonce = [0x11; 16];
        let name = derive_pipe_name("S-1-5-21-1-2-3-1001", &nonce).expect("derive");
        validate_pipe_name(name.as_str()).expect("valid");
        assert!(name.as_str().starts_with(PIPE_PREFIX));
        assert!(!name.as_str().ends_with(LEAK_REVEAL_SUFFIX));
        let reveal = name.leak_reveal_sibling().expect("reveal sibling");
        assert!(reveal.as_str().ends_with(LEAK_REVEAL_SUFFIX));
        validate_pipe_name(reveal.as_str()).expect("valid reveal");
    }

    #[test]
    fn different_users_and_nonces_do_not_collide() {
        let nonce = [0x22; 16];
        let a = derive_pipe_name("S-1-5-21-1-2-3-1001", &nonce).unwrap();
        let b = derive_pipe_name("S-1-5-21-1-2-3-1002", &nonce).unwrap();
        let c = derive_pipe_name("S-1-5-21-1-2-3-1001", &[0x23; 16]).unwrap();
        assert_ne!(a, b);
        assert_ne!(a, c);
        derive_pipe_name("S-1-5-21-1-2-3-1001", &[0; 16]).expect_err("zero nonce");
        derive_pipe_name("", &nonce).expect_err("empty sid");
    }

    #[test]
    fn identity_file_round_trips_and_rejects_wrong_version() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("daemon.sock");
        let pipe = derive_pipe_name("S-1-5-21-1-2-3-1001", &[0xab; 16]).unwrap();
        write_pipe_identity(&path, &pipe).expect("write");
        assert_eq!(read_pipe_identity(&path).unwrap(), pipe);
        std::fs::write(&path, br#"{"version":2,"pipe":"\\.\pipe\cockpit"}"#).unwrap();
        read_pipe_identity(&path).expect_err("unsupported version");
        assert!(
            read_pipe_identity_if_present(&dir.path().join("missing"))
                .unwrap()
                .is_none()
        );
    }
}
