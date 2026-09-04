//! Authenticated per-peer authority for local socket clients (issue #337).
//!
//! Peers are identified with `SO_PEERCRED` / `getpeereid` (or the Windows named-
//! pipe client PID) and receive daemon-minted credentials bound to that identity.
//! Secret-bearing RPCs require a live peer-bound credential held in the
//! connecting process, not a world-readable file next to the socket.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use rand::RngExt as _;
use serde::{Deserialize, Serialize};

use cockpit_host::peer_cred::PeerIdentity;

use super::principal::{LocalClientRole, PrincipalGrant};

pub fn proto_local_role(role: LocalClientRole) -> cockpit_proto::LocalClientRole {
    match role {
        LocalClientRole::Tui => cockpit_proto::LocalClientRole::Tui,
        LocalClientRole::Cli => cockpit_proto::LocalClientRole::Cli,
        LocalClientRole::Acp => cockpit_proto::LocalClientRole::Acp,
        LocalClientRole::AgentChild => cockpit_proto::LocalClientRole::AgentChild,
        LocalClientRole::Unauthenticated => cockpit_proto::LocalClientRole::Cli,
    }
}

pub fn principal_local_role(role: cockpit_proto::LocalClientRole) -> LocalClientRole {
    match role {
        cockpit_proto::LocalClientRole::Tui => LocalClientRole::Tui,
        cockpit_proto::LocalClientRole::Cli => LocalClientRole::Cli,
        cockpit_proto::LocalClientRole::Acp => LocalClientRole::Acp,
        cockpit_proto::LocalClientRole::AgentChild => LocalClientRole::AgentChild,
    }
}

/// How long a minted peer credential remains valid. PIDs are recycled; keep
/// this short enough that a stale binding cannot outlive the originating peer.
const PEER_CREDENTIAL_TTL: Duration = Duration::from_secs(5 * 60);

/// Hard cap on concurrently registered peer credentials.
const MAX_PEER_CREDENTIAL_RECORDS: usize = 64;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerCredentialToken(pub String);

impl PeerCredentialToken {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for PeerCredentialToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PeerCredentialToken([redacted])")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PeerCredentialRecord {
    peer: PeerIdentity,
    role: LocalClientRole,
    grants: Vec<PrincipalGrant>,
    expires_at_unix_ms: i64,
}

#[derive(Default)]
pub struct PeerCredentialRegistry {
    records: Mutex<HashMap<String, PeerCredentialRecord>>,
}

impl PeerCredentialRegistry {
    pub fn mint(
        &self,
        peer: PeerIdentity,
        role: LocalClientRole,
        grants: Vec<PrincipalGrant>,
    ) -> PeerCredentialToken {
        let mut bytes = [0_u8; 32];
        rand::rng().fill(&mut bytes);
        let token = PeerCredentialToken(crate::intel::hex_lower(&bytes));
        let expires_at_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_millis() as i64 + PEER_CREDENTIAL_TTL.as_millis() as i64)
            .unwrap_or(i64::MAX);
        let record = PeerCredentialRecord {
            peer,
            role,
            grants,
            expires_at_unix_ms,
        };
        let mut records = self
            .records
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        records.retain(|_, existing| existing.expires_at_unix_ms > now_unix_ms());
        records.retain(|_, existing| existing.peer != peer);
        if records.len() >= MAX_PEER_CREDENTIAL_RECORDS {
            records.retain(|_, existing| {
                existing.expires_at_unix_ms
                    > now_unix_ms() + PEER_CREDENTIAL_TTL.as_millis() as i64 / 2
            });
            while records.len() >= MAX_PEER_CREDENTIAL_RECORDS {
                let Some(oldest_key) = records
                    .iter()
                    .min_by_key(|(_, existing)| existing.expires_at_unix_ms)
                    .map(|(key, _)| key.clone())
                else {
                    break;
                };
                records.remove(&oldest_key);
            }
        }
        records.insert(token.0.clone(), record);
        token
    }

    pub fn verify(
        &self,
        peer: PeerIdentity,
        presented: &str,
    ) -> Option<(LocalClientRole, Vec<PrincipalGrant>)> {
        if !peer_identity_matches_live_process(peer) {
            return None;
        }
        let mut records = self
            .records
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        records.retain(|_, existing| existing.expires_at_unix_ms > now_unix_ms());
        let record = records.get(presented)?;
        if record.peer != peer {
            return None;
        }
        Some((record.role, record.grants.clone()))
    }

    pub fn revoke_for_peer(&self, peer: PeerIdentity) {
        let mut records = self
            .records
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        records.retain(|_, record| record.peer != peer);
    }
}

fn now_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or(0)
}

/// True when the peer identity still refers to a live process with matching
/// credentials. Fails closed when the pid cannot be probed.
pub fn peer_identity_matches_live_process(peer: PeerIdentity) -> bool {
    if peer.pid == 0 {
        return false;
    }
    if !cockpit_host::daemon_lifecycle::process_exists(peer.pid) {
        return false;
    }
    #[cfg(unix)]
    {
        if let Ok((uid, gid)) = read_process_uid_gid(peer.pid) {
            return uid == peer.uid && gid == peer.gid;
        }
        return false;
    }
    #[cfg(windows)]
    {
        true
    }
}

/// Attest the connecting peer's local client role from its live process image.
pub fn attest_local_client_role(
    peer: PeerIdentity,
    approved_executable: &Path,
) -> Result<Option<LocalClientRole>> {
    if peer.pid == 0 || !peer_identity_matches_live_process(peer) {
        return Ok(None);
    }
    let exe = read_process_exe(peer.pid)?;
    if !exact_executable_identity(&exe, approved_executable) {
        return Ok(attest_agent_child_role(peer, approved_executable));
    }
    let cmdline = read_process_cmdline(peer.pid)?;
    Ok(Some(classify_cockpit_cmdline(&cmdline)))
}

fn attest_agent_child_role(
    peer: PeerIdentity,
    approved_executable: &Path,
) -> Option<LocalClientRole> {
    let parent_pid = read_parent_pid(peer.pid).ok()??;
    if parent_pid == 0 || !cockpit_host::daemon_lifecycle::process_exists(parent_pid) {
        return None;
    }
    let parent_exe = read_process_exe(parent_pid).ok()?;
    if exact_executable_identity(&parent_exe, approved_executable) {
        return Some(LocalClientRole::AgentChild);
    }
    None
}

fn classify_cockpit_cmdline(cmdline: &[String]) -> LocalClientRole {
    let args = cmdline
        .iter()
        .skip(1)
        .map(|arg| arg.as_str())
        .collect::<Vec<_>>();
    if args.first() == Some(&"acp") {
        return LocalClientRole::Acp;
    }
    if args.first() == Some(&"daemon") {
        return LocalClientRole::Cli;
    }
    if args
        .iter()
        .any(|arg| matches!(*arg, "tui" | "attach" | "run"))
    {
        return LocalClientRole::Tui;
    }
    if args.is_empty() {
        return LocalClientRole::Tui;
    }
    LocalClientRole::Cli
}

fn exact_executable_identity(observed: &Path, approved: &Path) -> bool {
    cockpit_host::daemon_lifecycle::exact_executable_identity(observed, approved)
}

#[cfg(unix)]
fn read_process_uid_gid(pid: u32) -> Result<(u32, u32)> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status"))
        .with_context(|| format!("reading /proc/{pid}/status"))?;
    let mut uid = None;
    let mut gid = None;
    for line in status.lines() {
        if let Some(value) = line.strip_prefix("Uid:\t") {
            uid = value
                .split_whitespace()
                .next()
                .and_then(|part| part.parse().ok());
        } else if let Some(value) = line.strip_prefix("Gid:\t") {
            gid = value
                .split_whitespace()
                .next()
                .and_then(|part| part.parse().ok());
        }
    }
    match (uid, gid) {
        (Some(uid), Some(gid)) => Ok((uid, gid)),
        _ => bail!("missing uid/gid in /proc/{pid}/status"),
    }
}

#[cfg(unix)]
fn read_process_exe(pid: u32) -> Result<PathBuf> {
    let path = format!("/proc/{pid}/exe");
    std::fs::read_link(&path).with_context(|| format!("reading {path}"))
}

#[cfg(windows)]
fn read_process_exe(pid: u32) -> Result<PathBuf> {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

    // SAFETY: pid is a live peer captured at accept time.
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if process.is_null() || process == INVALID_HANDLE_VALUE {
        bail!("opening peer process {pid}");
    }
    let mut buffer = vec![0u16; 32_768];
    let mut size = buffer.len() as u32;
    // SAFETY: `process` is valid and `buffer` is writable for `size` UTF-16 units.
    let ok = unsafe {
        windows_sys::Win32::System::Threading::QueryFullProcessImageNameW(
            process,
            0,
            buffer.as_mut_ptr(),
            &mut size,
        )
    };
    // SAFETY: `process` was opened above.
    unsafe { CloseHandle(process) };
    if ok == 0 {
        bail!("reading peer process image name for {pid}");
    }
    buffer.truncate(size as usize);
    Ok(PathBuf::from(OsString::from_wide(&buffer)))
}

#[cfg(unix)]
fn read_process_cmdline(pid: u32) -> Result<Vec<String>> {
    let bytes = std::fs::read(format!("/proc/{pid}/cmdline"))
        .with_context(|| format!("reading /proc/{pid}/cmdline"))?;
    Ok(bytes
        .split(|byte| *byte == 0)
        .filter(|part| !part.is_empty())
        .map(|part| String::from_utf8_lossy(part).into_owned())
        .collect())
}

#[cfg(windows)]
fn read_process_cmdline(pid: u32) -> Result<Vec<String>> {
    let exe = read_process_exe(pid)?;
    Ok(vec![
        exe.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("cockpit")
            .to_string(),
    ])
}

#[cfg(unix)]
fn read_parent_pid(pid: u32) -> Result<Option<u32>> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status"))
        .with_context(|| format!("reading /proc/{pid}/status"))?;
    for line in status.lines() {
        if let Some(ppid) = line.strip_prefix("PPid:\t") {
            return Ok(ppid.trim().parse().ok());
        }
    }
    Ok(None)
}

#[cfg(windows)]
fn read_parent_pid(pid: u32) -> Result<Option<u32>> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
        TH32CS_SNAPPROCESS,
    };

    // SAFETY: snapshot APIs are used with valid stack structs.
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot.is_null() {
            return Ok(None);
        }
        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..std::mem::zeroed()
        };
        let mut found = None;
        if Process32FirstW(snapshot, &mut entry) != 0 {
            loop {
                if entry.th32ProcessID == pid {
                    found = Some(entry.th32ParentProcessID);
                    break;
                }
                if Process32NextW(snapshot, &mut entry) == 0 {
                    break;
                }
            }
        }
        CloseHandle(snapshot);
        Ok(found)
    }
}

pub fn default_agent_child_grants() -> Vec<PrincipalGrant> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_cockpit_cmdline_maps_roles() {
        assert_eq!(
            classify_cockpit_cmdline(&["cockpit".into()]),
            LocalClientRole::Tui
        );
        assert_eq!(
            classify_cockpit_cmdline(&["cockpit".into(), "acp".into()]),
            LocalClientRole::Acp
        );
        assert_eq!(
            classify_cockpit_cmdline(&["cockpit".into(), "daemon".into(), "status".into()]),
            LocalClientRole::Cli
        );
        assert_eq!(
            classify_cockpit_cmdline(&["cockpit".into(), "run".into(), "task".into()]),
            LocalClientRole::Tui
        );
    }

    #[test]
    fn peer_credential_registry_binds_to_peer_identity() {
        let registry = PeerCredentialRegistry::default();
        let pid = std::process::id();
        #[cfg(unix)]
        let (uid, gid) = read_process_uid_gid(pid).expect("uid/gid");
        #[cfg(windows)]
        let (uid, gid) = (0_u32, 0_u32);
        let peer = PeerIdentity { pid, uid, gid };
        let token = registry.mint(peer, LocalClientRole::Cli, Vec::new());
        assert!(
            registry
                .verify(peer, token.as_str())
                .is_some_and(|(role, _)| role == LocalClientRole::Cli)
        );
        assert!(
            registry
                .verify(
                    PeerIdentity {
                        pid: peer.pid.saturating_add(1),
                        uid,
                        gid,
                    },
                    token.as_str()
                )
                .is_none()
        );
    }
}
