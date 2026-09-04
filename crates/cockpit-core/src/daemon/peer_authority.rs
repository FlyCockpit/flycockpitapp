//! Authenticated per-peer authority for local socket clients (issue #337).
//!
//! Peers are identified with `SO_PEERCRED` / `getpeereid` (or the Windows named-
//! pipe client PID) and receive daemon-minted credentials bound to that identity
//! and the minting connection. Secret-bearing RPCs require a live peer-bound
//! credential held in the connecting process, not a world-readable file next to
//! the socket.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rand::RngExt as _;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

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
    connection_id: Uuid,
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
        connection_id: Uuid,
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
            connection_id,
            role,
            grants,
            expires_at_unix_ms,
        };
        let mut records = self
            .records
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        records.retain(|_, existing| existing.expires_at_unix_ms > now_unix_ms());
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
        connection_id: Uuid,
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
        if record.peer != peer || record.connection_id != connection_id {
            return None;
        }
        Some((record.role, record.grants.clone()))
    }

    pub fn expires_at_unix_ms(&self, connection_id: Uuid, presented: &str) -> Option<i64> {
        let records = self
            .records
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        records
            .get(presented)
            .filter(|record| record.connection_id == connection_id)
            .map(|record| record.expires_at_unix_ms)
    }

    pub fn revoke_for_connection(&self, connection_id: Uuid) {
        let mut records = self
            .records
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        records.retain(|_, record| record.connection_id != connection_id);
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
        match cockpit_host::daemon_lifecycle::read_process_credentials(peer.pid) {
            Ok((uid, gid)) => uid == peer.uid && gid == peer.gid,
            Err(_) => false,
        }
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
) -> Option<LocalClientRole> {
    if peer.pid == 0 || !peer_identity_matches_live_process(peer) {
        return None;
    }
    let exe = cockpit_host::daemon_lifecycle::read_process_executable(peer.pid).ok()?;
    if !cockpit_host::daemon_lifecycle::exact_executable_identity(&exe, approved_executable) {
        return attest_agent_child_role(peer, approved_executable);
    }
    let cmdline = cockpit_host::daemon_lifecycle::read_process_cmdline(peer.pid).ok()?;
    Some(classify_cockpit_cmdline(&cmdline))
}

fn attest_agent_child_role(
    peer: PeerIdentity,
    approved_executable: &Path,
) -> Option<LocalClientRole> {
    let parent_pid = cockpit_host::daemon_lifecycle::read_parent_process_id(peer.pid).ok()??;
    if parent_pid == 0 || !cockpit_host::daemon_lifecycle::process_exists(parent_pid) {
        return None;
    }
    let parent_exe = cockpit_host::daemon_lifecycle::read_process_executable(parent_pid).ok()?;
    if cockpit_host::daemon_lifecycle::exact_executable_identity(&parent_exe, approved_executable) {
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
    fn peer_credential_registry_binds_to_peer_identity_and_connection() {
        let registry = PeerCredentialRegistry::default();
        let pid = std::process::id();
        #[cfg(unix)]
        let (uid, gid) =
            cockpit_host::daemon_lifecycle::read_process_credentials(pid).expect("uid/gid");
        #[cfg(windows)]
        let (uid, gid) = (0_u32, 0_u32);
        let peer = PeerIdentity { pid, uid, gid };
        let connection_id = Uuid::new_v4();
        let token = registry.mint(peer, connection_id, LocalClientRole::Cli, Vec::new());
        assert!(
            registry
                .verify(peer, connection_id, token.as_str())
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
                    connection_id,
                    token.as_str()
                )
                .is_none()
        );
        assert!(
            registry
                .verify(peer, Uuid::new_v4(), token.as_str())
                .is_none()
        );
    }
}
