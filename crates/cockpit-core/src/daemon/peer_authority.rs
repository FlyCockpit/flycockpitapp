//! Authenticated per-peer authority for local socket clients (issue #337).
//!
//! Peers are identified with `SO_PEERCRED` / `getpeereid` (or the Windows named-
//! pipe client PID) and receive daemon-minted credentials bound to that identity
//! and the minting connection. Secret-bearing RPCs require a live peer-bound
//! credential held in the connecting process, not a world-readable file next to
//! the socket.
//!
//! Owner-class credentials are never self-service. The exchange mints them
//! only against trusted launch provenance: the one-time launch ticket the
//! spawning process passed to the daemon through the spawn environment,
//! bound to the launcher's exact process identity. An unconfined same-uid
//! process can run the approved executable with recognized arguments, but
//! without the launch ticket it stays an unauthenticated, table-governed
//! peer.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Context as _;
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

/// How long a peer credential stays valid without renewal. PIDs are
/// recycled; keep this short enough that a stale binding cannot outlive the
/// originating peer.
///
/// A credential is renewed only by the daemon, only while the connection
/// that minted it is still being served (its [`PeerCredentialLease`] is
/// alive), and only after re-verifying that the minting peer is still the
/// exact live process. A live owner connection therefore never loses owner
/// authority to the clock (issue #546), while a record orphaned by a
/// cancelled or leaked connection handler, or whose peer process is gone,
/// lapses within one TTL. Deadlines are on the [`CredentialClock`], which
/// counts only time the host is awake, so wall-clock steps and host suspend
/// never revoke a live connection on any supported platform.
const PEER_CREDENTIAL_TTL: Duration = Duration::from_secs(5 * 60);

/// Renewal cadence as a fraction of the TTL: a live record is renewed at
/// least twice before it could lapse, so one late tick never revokes it.
const PEER_CREDENTIAL_RENEWALS_PER_TTL: u32 = 3;

/// Why the daemon withdrew a connection's peer credential. Carried to the
/// connection so the user is told why owner authority was lost and how to
/// recover, instead of seeing bare authorization refusals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerCredentialRevocation {
    /// The record reached its TTL without being renewed.
    Lapsed,
    /// Renewal re-verification found the minting peer is no longer the exact
    /// live process that exchanged the credential.
    PeerChanged,
    /// The registry was full and this record was evicted.
    Evicted,
    /// The connection presented a credential the registry no longer holds.
    Unrecognized,
}

impl PeerCredentialRevocation {
    pub fn describe(self) -> &'static str {
        match self {
            Self::Lapsed => "its local owner credential lapsed without renewal",
            Self::PeerChanged => {
                "the daemon could not re-verify this process as the credential holder"
            }
            Self::Evicted => {
                "its local owner credential was evicted because too many local clients are connected"
            }
            Self::Unrecognized => {
                "it presented a local owner credential the daemon no longer holds"
            }
        }
    }
}

/// Result of one daemon-side renewal attempt for a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerCredentialRenewal {
    /// The connection holds no credential (not exchanged yet, or revoked).
    NoCredential,
    Renewed,
    /// The record could not be renewed and has been revoked; the
    /// connection's invalidation hook has been notified.
    Revoked(PeerCredentialRevocation),
}

/// Hard cap on concurrently registered peer credentials.
const MAX_PEER_CREDENTIAL_RECORDS: usize = 64;

/// Spawn-environment slot carrying the one-time daemon launch ticket from the
/// spawning cockpit process to the daemon child. The launcher generates the
/// ticket, passes it here at spawn, and retains it only in memory; the daemon
/// records it at boot and scrubs it from its own environment so descendants
/// never inherit it.
pub(crate) const DAEMON_LAUNCH_TICKET_ENV: &str = "COCKPIT_DAEMON_LAUNCH_TICKET";

/// Launch tickets are 32 random bytes, hex-encoded (64 lowercase hex chars).
const LAUNCH_TICKET_HEX_LEN: usize = 64;

/// Mint a fresh launch ticket for the daemon this process is about to spawn.
/// The caller keeps one copy in memory and passes the other through the
/// child's spawn environment.
pub(crate) fn mint_launch_ticket() -> String {
    let mut bytes = [0_u8; 32];
    rand::rng().fill(&mut bytes);
    crate::intel::hex_lower(&bytes)
}

fn launch_ticket_is_well_formed(ticket: &str) -> bool {
    ticket.len() == LAUNCH_TICKET_HEX_LEN
        && ticket
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Same derivation the daemon and socket client use for the launch-ticket
/// file. Confined children are denied this path.
pub(crate) fn launch_ticket_path_for_socket(control_socket: &Path) -> PathBuf {
    let stem = control_socket
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("cockpit");
    let file_name = format!("{stem}.launch-ticket");
    match control_socket.parent() {
        Some(parent) => parent.join(file_name),
        None => PathBuf::from(file_name),
    }
}

/// Persist the launch ticket for follower cockpit CLI processes on the same
/// uid. The file is daemon-private and denied to confined children.
pub(crate) fn persist_launch_ticket(socket: &Path, ticket: &str) -> anyhow::Result<()> {
    if !launch_ticket_is_well_formed(ticket) {
        anyhow::bail!("refusing to persist malformed launch ticket");
    }
    let path = launch_ticket_path_for_socket(socket);
    if let Some(parent) = path.parent() {
        cockpit_host::private_fs::ensure_private_dir(parent)
            .with_context(|| format!("securing {}", parent.display()))?;
    }
    cockpit_host::private_fs::write_private_file(&path, ticket.as_bytes())
        .with_context(|| format!("writing {}", path.display()))
}

/// Load the persisted launch ticket for follower cockpit CLI processes.
pub(crate) fn load_persisted_launch_ticket(socket: &Path) -> Option<String> {
    let path = launch_ticket_path_for_socket(socket);
    let bytes = std::fs::read(&path).ok()?;
    let ticket = String::from_utf8(bytes).ok()?;
    let ticket = ticket.trim();
    if launch_ticket_is_well_formed(ticket) {
        Some(ticket.to_string())
    } else {
        None
    }
}

/// True when `presented` matches the daemon-private launch ticket file for
/// this socket. Follower cockpit processes and integration harnesses use
/// this path when the spawner has exited but the persisted ticket remains.
pub(crate) fn verify_persisted_launch_ticket(
    socket: &Path,
    presented: Option<&str>,
    peer: PeerIdentity,
) -> bool {
    let Some(presented) = presented else {
        return false;
    };
    let Some(persisted) = load_persisted_launch_ticket(socket) else {
        return false;
    };
    if !super::owner_capability::constant_time_eq(persisted.as_bytes(), presented.as_bytes()) {
        return false;
    }
    #[cfg(unix)]
    {
        if let Ok((uid, _)) = cockpit_host::daemon_lifecycle::read_process_credentials(peer.pid) {
            return uid == peer.uid;
        }
    }
    true
}

/// Trusted launch provenance recorded once at daemon boot from the spawn
/// environment. `launcher` is the exact process identity of the daemon's
/// parent at boot; a launcher that already exited (or a human shell running
/// `daemon start --foreground` without a ticket) leaves no usable anchor and
/// owner-class exchange stays denied — fail closed.
#[derive(Debug, Clone, PartialEq, Eq)]
struct DaemonLaunchProvenance {
    ticket: String,
    launcher: Option<PeerIdentity>,
}

/// Capture the exact identity of this process's parent, if it is observable.
pub(crate) fn capture_launcher_identity() -> Option<PeerIdentity> {
    let pid = cockpit_host::daemon_lifecycle::read_parent_process_id(std::process::id()).ok()??;
    if pid == 0 {
        return None;
    }
    let process_start = cockpit_host::daemon_lifecycle::process_start_identity(pid).ok()?;
    #[cfg(unix)]
    let (uid, gid) = cockpit_host::daemon_lifecycle::read_process_credentials(pid).ok()?;
    #[cfg(windows)]
    let (uid, gid) = (0_u32, 0_u32);
    Some(PeerIdentity {
        pid,
        uid,
        gid,
        process_start,
    })
}

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
    expires_at: CredentialInstant,
}

/// A point on the credential clock: time the host has been *awake* since an
/// arbitrary process-local origin. See [`CredentialClock`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct CredentialInstant(Duration);

impl CredentialInstant {
    fn after(self, duration: Duration) -> Self {
        Self(self.0.saturating_add(duration))
    }

    /// Awake time left until `self`, measured from `now`; zero once due.
    pub fn remaining_since(self, now: Self) -> Duration {
        self.0.saturating_sub(now.0)
    }
}

/// Source of credential deadlines. Credential lifetime is measured in time
/// the host is awake, never in time it spends suspended: nothing can run,
/// renew, or exit while the host sleeps, so suspend must not consume a live
/// connection's TTL (issue #546). Production uses [`SuspendExcludingClock`].
pub trait CredentialClock: Send + Sync {
    fn now(&self) -> CredentialInstant;
}

/// Platform clock that stops while the host is suspended:
/// - macOS: Rust's `Instant` is `CLOCK_UPTIME_RAW` (mach absolute time),
///   which does not advance during sleep.
/// - Linux: Rust's `Instant` is `CLOCK_MONOTONIC`, which excludes suspend
///   (`CLOCK_BOOTTIME` is the variant that includes it).
/// - Windows: Rust's `Instant` is `QueryPerformanceCounter`, which *includes*
///   standby and hibernation, so it is not used. `QueryUnbiasedInterruptTime`
///   excludes time spent in sleep or hibernation.
pub struct SuspendExcludingClock;

impl CredentialClock for SuspendExcludingClock {
    #[cfg(not(windows))]
    fn now(&self) -> CredentialInstant {
        static ORIGIN: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
        let origin = *ORIGIN.get_or_init(std::time::Instant::now);
        CredentialInstant(std::time::Instant::now().saturating_duration_since(origin))
    }

    #[cfg(windows)]
    fn now(&self) -> CredentialInstant {
        let mut unbiased_100ns = 0_u64;
        // SAFETY: the out-pointer is a valid, writable u64 for the call.
        let ok = unsafe {
            windows_sys::Win32::System::WindowsProgramming::QueryUnbiasedInterruptTime(
                &mut unbiased_100ns,
            )
        };
        // The call only fails for an invalid pointer; never treat a failure
        // as "time stopped" (that would extend credentials).
        assert!(ok != 0, "QueryUnbiasedInterruptTime failed");
        CredentialInstant(Duration::from_nanos(unbiased_100ns.saturating_mul(100)))
    }
}

/// The connection is told which credential was withdrawn and why. The token
/// binds the notice to that exact credential, so a delayed notice can never
/// downgrade a fresh re-exchange on the same connection.
type InvalidationHook = Arc<dyn Fn(&str, PeerCredentialRevocation) + Send + Sync>;

#[cfg(test)]
type MintBoundary = Arc<dyn Fn() -> Box<dyn Send> + Send + Sync>;

/// Why a credential was withdrawn, kept until its connection ends so a
/// connection that learns of the loss late (a queued frame, a dropped notice)
/// reports the real cause.
#[derive(Clone)]
struct RevocationRecord {
    token: String,
    reason: PeerCredentialRevocation,
}

impl std::fmt::Debug for RevocationRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RevocationRecord")
            .field("reason", &self.reason)
            .finish_non_exhaustive()
    }
}

/// A record removed from the registry for a reason its connection must hear.
struct Withdrawn {
    connection_id: Uuid,
    token: String,
    reason: PeerCredentialRevocation,
    hook: Option<InvalidationHook>,
}

/// Record removal, cause publication and connection teardown share this lock.
/// Notifications only carry snapshots; they never mutate registry state.
#[derive(Default)]
struct RegistryState {
    records: HashMap<String, PeerCredentialRecord>,
    /// Only the owning lease opens a production generation. Release closes it
    /// under this same lock, fencing even an executor already inside dispatch.
    connections: HashMap<Uuid, Uuid>,
    invalidation_hooks: HashMap<Uuid, InvalidationHook>,
    revocations: HashMap<Uuid, RevocationRecord>,
}

impl RegistryState {
    fn release_connection(&mut self, connection_id: Uuid) {
        self.connections.remove(&connection_id);
        self.invalidation_hooks.remove(&connection_id);
        self.records
            .retain(|_, record| record.connection_id != connection_id);
        self.revocations.remove(&connection_id);
    }

    fn withdraw(&mut self, token: &str, reason: PeerCredentialRevocation) -> Option<Withdrawn> {
        let record = self.records.remove(token)?;
        self.revocations.insert(
            record.connection_id,
            RevocationRecord {
                token: token.to_string(),
                reason,
            },
        );
        Some(Withdrawn {
            connection_id: record.connection_id,
            token: token.to_string(),
            reason,
            hook: self.invalidation_hooks.get(&record.connection_id).cloned(),
        })
    }
}

/// Why `try_mint` refused to issue a credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerCredentialMintError {
    /// The registry is full of credentials at least as privileged as the
    /// requested one; minting would evict an owner for a non-owner.
    Full,
    /// The producer's connection lease has ended or has been replaced.
    ConnectionClosed,
}

/// A producer's exact lease generation. Copying this handle does not keep the
/// lease alive: every mint and renewal must still match registry state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCredentialConnection {
    connection_id: Uuid,
    generation: Uuid,
}

pub struct PeerCredentialRegistry {
    state: Mutex<RegistryState>,
    #[cfg(test)]
    before_notifications: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    #[cfg(test)]
    before_mint: Mutex<Option<MintBoundary>>,
    /// Trusted launch provenance recorded once at daemon boot. `None` means
    /// this daemon was not spawned with a launch ticket (human foreground
    /// start, in-process boot) and no socket peer can ever exchange for an
    /// owner-class credential.
    launch_provenance: Mutex<Option<DaemonLaunchProvenance>>,
    ttl: Duration,
    clock: Arc<dyn CredentialClock>,
}

impl Default for PeerCredentialRegistry {
    fn default() -> Self {
        Self::with_ttl_and_clock(PEER_CREDENTIAL_TTL, Arc::new(SuspendExcludingClock))
    }
}

impl PeerCredentialRegistry {
    fn with_ttl_and_clock(ttl: Duration, clock: Arc<dyn CredentialClock>) -> Self {
        Self {
            state: Mutex::new(RegistryState::default()),
            #[cfg(test)]
            before_notifications: Mutex::new(None),
            #[cfg(test)]
            before_mint: Mutex::new(None),
            launch_provenance: Mutex::new(None),
            ttl,
            clock,
        }
    }

    /// Test seam: a registry whose credentials lapse after `ttl`, so expiry
    /// and renewal are exercised without waiting for the production TTL.
    #[cfg(test)]
    pub(crate) fn with_ttl_for_test(ttl: Duration) -> Self {
        Self::with_ttl_and_clock(ttl, Arc::new(SuspendExcludingClock))
    }

    /// Test seam: a registry on an explicit credential clock (for example
    /// one that models host suspend).
    #[cfg(test)]
    pub(crate) fn with_clock_for_test(ttl: Duration, clock: Arc<dyn CredentialClock>) -> Self {
        Self::with_ttl_and_clock(ttl, clock)
    }

    /// Now, on this registry's credential clock.
    pub fn now(&self) -> CredentialInstant {
        self.clock.now()
    }

    /// How often a live connection's [`PeerCredentialLease`] renews.
    pub fn renewal_interval(&self) -> Duration {
        self.ttl / PEER_CREDENTIAL_RENEWALS_PER_TTL
    }

    /// Record the launch provenance the spawning process passed through the
    /// environment, capturing the launcher's exact process identity from the
    /// daemon's parent at boot. Scrubs the environment slot so descendants
    /// of this daemon never inherit the ticket.
    pub fn record_launch_provenance_from_environment(&self) {
        let Some(ticket) = std::env::var(DAEMON_LAUNCH_TICKET_ENV).ok() else {
            return;
        };
        // SAFETY: the environment is process-global and this runs once during
        // daemon boot, before worker tasks and spawned children exist.
        unsafe {
            std::env::remove_var(DAEMON_LAUNCH_TICKET_ENV);
        }
        self.record_launch_provenance(ticket, capture_launcher_identity());
    }

    /// Fail-closed recording: a malformed ticket or an unobservable launcher
    /// installs no usable provenance.
    pub fn record_launch_provenance(&self, ticket: String, launcher: Option<PeerIdentity>) {
        if !launch_ticket_is_well_formed(&ticket) {
            tracing::warn!(
                "ignoring malformed daemon launch ticket; owner-class exchange stays denied"
            );
            return;
        }
        *self
            .launch_provenance
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) =
            Some(DaemonLaunchProvenance { ticket, launcher });
    }

    /// The recorded launch ticket, if any. Used to persist a daemon-private
    /// follower file after boot.
    pub(crate) fn recorded_launch_ticket(&self) -> Option<String> {
        self.launch_provenance
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
            .map(|provenance| provenance.ticket.clone())
    }

    /// True when `presented` is exactly the launch ticket minted for this
    /// daemon and `peer` is allowed to present it.
    ///
    /// The spawning cockpit process may exchange while it is still live. Later
    /// cockpit CLI processes from the same uid read the daemon-private launch
    /// ticket file and exchange as followers.
    pub fn verify_launch_provenance(&self, presented: Option<&str>, peer: PeerIdentity) -> bool {
        let Some(presented) = presented else {
            return false;
        };
        let provenance = self
            .launch_provenance
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(provenance) = provenance.as_ref() else {
            return false;
        };
        if !super::owner_capability::constant_time_eq(
            provenance.ticket.as_bytes(),
            presented.as_bytes(),
        ) {
            return false;
        }
        match provenance.launcher.as_ref() {
            Some(launcher) if launcher == &peer => true,
            Some(launcher) => peer.uid == launcher.uid,
            // Launcher exited before boot observation: the ticket (and the
            // daemon-private follower file derived from it) is the binding.
            None => true,
        }
    }

    /// Test seam for the in-process daemon fixtures: install provenance
    /// explicitly with the chosen launcher identity. Production only records
    /// from the spawn environment at boot.
    #[cfg(test)]
    pub fn install_launch_provenance_for_test(&self, ticket: &str, launcher: PeerIdentity) {
        self.record_launch_provenance(ticket.to_string(), Some(launcher));
    }

    #[cfg(test)]
    fn register_invalidation_hook(
        &self,
        connection_id: Uuid,
        hook: impl Fn(&str, PeerCredentialRevocation) + Send + Sync + 'static,
    ) {
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .invalidation_hooks
            .insert(connection_id, Arc::new(hook));
    }

    fn open_connection(
        &self,
        connection_id: Uuid,
        hook: Option<InvalidationHook>,
    ) -> PeerCredentialConnection {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let generation = *state
            .connections
            .entry(connection_id)
            .or_insert_with(Uuid::new_v4);
        if let Some(hook) = hook {
            state.invalidation_hooks.insert(connection_id, hook);
        }
        PeerCredentialConnection {
            connection_id,
            generation,
        }
    }

    #[cfg(test)]
    fn connection_for_test(&self, connection_id: Uuid) -> PeerCredentialConnection {
        // Registry-only fixtures have no runtime/handler. Production producers
        // can obtain a generation only from their handler's lease.
        self.open_connection(connection_id, None)
    }

    /// Called only after the registry-state lock is released. A callback may
    /// re-enter the registry or race connection release; neither can recreate
    /// a record or a cause through this notification snapshot.
    fn notify_withdrawn(&self, withdrawn: Vec<Withdrawn>) {
        if withdrawn.is_empty() {
            return;
        }
        #[cfg(test)]
        {
            let boundary = self.before_notifications.lock().unwrap().clone();
            if let Some(boundary) = boundary {
                boundary();
            }
        }
        for notice in withdrawn {
            if let Some(hook) = notice.hook {
                hook(&notice.token, notice.reason);
            }
            tracing::debug!(connection_id = %notice.connection_id, "peer credential withdrawn");
        }
    }

    /// Why the exact token was withdrawn. Its cause is visible in the same
    /// state transition that makes verification fail.
    pub fn revocation_cause(
        &self,
        connection_id: Uuid,
        presented: &str,
    ) -> Option<PeerCredentialRevocation> {
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .revocations
            .get(&connection_id)
            .filter(|record| record.token == presented)
            .map(|record| record.reason)
    }

    fn prune_expired_records(&self, state: &mut RegistryState) -> Vec<Withdrawn> {
        let now = self.now();
        let tokens: Vec<_> = state
            .records
            .iter()
            .filter(|(_, record)| record.expires_at <= now)
            .map(|(token, _)| token.clone())
            .collect();
        tokens
            .into_iter()
            .filter_map(|token| state.withdraw(&token, PeerCredentialRevocation::Lapsed))
            .collect()
    }

    #[cfg(test)]
    pub(crate) fn before_notifications_for_test(
        &self,
        boundary: impl Fn() + Send + Sync + 'static,
    ) {
        *self.before_notifications.lock().unwrap() = Some(Arc::new(boundary));
    }

    #[cfg(test)]
    pub(crate) fn before_mint_for_test(
        &self,
        boundary: impl Fn() -> Box<dyn Send> + Send + Sync + 'static,
    ) {
        *self.before_mint.lock().unwrap() = Some(Arc::new(boundary));
    }

    /// Issue a credential for `peer` on a still-live lease generation,
    /// replacing that connection's previous credential. Admission and release
    /// share the registry lock; a cancelled producer cannot recreate authority.
    ///
    /// At the record cap only actually lapsed records are pruned; then the
    /// least privileged, nearest-to-lapse record that is *no more privileged
    /// than the new one* is evicted. A non-owner exchange therefore never
    /// evicts an owner credential: when only owners remain it is refused.
    pub fn try_mint(
        &self,
        peer: PeerIdentity,
        connection: PeerCredentialConnection,
        role: LocalClientRole,
        grants: Vec<PrincipalGrant>,
    ) -> Result<PeerCredentialToken, PeerCredentialMintError> {
        #[cfg(test)]
        let _mint_boundary = {
            let boundary = self.before_mint.lock().unwrap().clone();
            boundary.map(|boundary| boundary())
        };
        let mut bytes = [0_u8; 32];
        rand::rng().fill(&mut bytes);
        let token = PeerCredentialToken(crate::intel::hex_lower(&bytes));
        let withdrawn = {
            let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
            if state.connections.get(&connection.connection_id) != Some(&connection.generation) {
                return Err(PeerCredentialMintError::ConnectionClosed);
            }
            let connection_id = connection.connection_id;
            let mut withdrawn = self.prune_expired_records(&mut state);
            // Re-exchange replaces only this connection's prior credential.
            state
                .records
                .retain(|_, existing| existing.connection_id != connection_id);
            let incoming_owner = role.is_owner_class();
            while state.records.len() >= MAX_PEER_CREDENTIAL_RECORDS {
                let Some(victim_key) = state
                    .records
                    .iter()
                    .filter(|(_, existing)| incoming_owner || !existing.role.is_owner_class())
                    .min_by_key(|(_, existing)| {
                        (existing.role.is_owner_class(), existing.expires_at)
                    })
                    .map(|(key, _)| key.clone())
                else {
                    drop(state);
                    self.notify_withdrawn(withdrawn);
                    return Err(PeerCredentialMintError::Full);
                };
                if let Some(notice) = state.withdraw(&victim_key, PeerCredentialRevocation::Evicted)
                {
                    withdrawn.push(notice);
                }
            }
            state.records.insert(
                token.0.clone(),
                PeerCredentialRecord {
                    peer,
                    connection_id,
                    role,
                    grants,
                    expires_at: self.now().after(self.ttl),
                },
            );
            state.revocations.remove(&connection_id);
            withdrawn
        };
        self.notify_withdrawn(withdrawn);
        Ok(token)
    }

    /// [`Self::try_mint`] for tests that never fill the registry.
    #[cfg(test)]
    pub fn mint(
        &self,
        peer: PeerIdentity,
        connection_id: Uuid,
        role: LocalClientRole,
        grants: Vec<PrincipalGrant>,
    ) -> PeerCredentialToken {
        self.try_mint(peer, self.connection_for_test(connection_id), role, grants)
            .expect("test registry has capacity")
    }

    /// Daemon-side renewal of the credential held by `connection_id`. Only a
    /// [`PeerCredentialLease`] (owned by the live connection handler) calls
    /// this. The minting peer is re-verified as the exact live process
    /// before the deadline moves; an already lapsed record is never revived.
    fn renew_connection(&self, connection: PeerCredentialConnection) -> PeerCredentialRenewal {
        let connection_id = connection.connection_id;
        let held = {
            let state = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if state.connections.get(&connection_id) != Some(&connection.generation) {
                return PeerCredentialRenewal::NoCredential;
            }
            state
                .records
                .iter()
                .find(|(_, record)| record.connection_id == connection_id)
                .map(|(token, record)| (token.clone(), record.peer, record.expires_at))
        };
        let Some((token, peer, expires_at)) = held else {
            return PeerCredentialRenewal::NoCredential;
        };
        let refusal = if expires_at <= self.now() {
            Some(PeerCredentialRevocation::Lapsed)
        } else if !peer_identity_matches_live_process(peer) {
            Some(PeerCredentialRevocation::PeerChanged)
        } else {
            None
        };
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.connections.get(&connection_id) != Some(&connection.generation) {
            return PeerCredentialRenewal::NoCredential;
        }
        let Some(record) = state
            .records
            .get_mut(&token)
            .filter(|record| record.connection_id == connection_id)
        else {
            // Replaced by a re-exchange or revoked while the peer was probed.
            return PeerCredentialRenewal::NoCredential;
        };
        let now = self.now();
        let refusal =
            refusal.or((record.expires_at <= now).then_some(PeerCredentialRevocation::Lapsed));
        match refusal {
            None => {
                record.expires_at = now.after(self.ttl);
                PeerCredentialRenewal::Renewed
            }
            Some(reason) => {
                let notice = state
                    .withdraw(&token, reason)
                    .expect("record checked above");
                drop(state);
                self.notify_withdrawn(vec![notice]);
                PeerCredentialRenewal::Revoked(reason)
            }
        }
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
        let (lapsed, verified) = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let lapsed = self.prune_expired_records(&mut state);
            let verified = state.records.get(presented).and_then(|record| {
                if record.peer != peer || record.connection_id != connection_id {
                    return None;
                }
                Some((record.role, record.grants.clone()))
            });
            (lapsed, verified)
        };
        self.notify_withdrawn(lapsed);
        verified
    }

    pub fn verify_without_prune(
        &self,
        peer: PeerIdentity,
        connection_id: Uuid,
        presented: &str,
    ) -> Option<(LocalClientRole, Vec<PrincipalGrant>)> {
        if !peer_identity_matches_live_process(peer) {
            return None;
        }
        let state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let record = state.records.get(presented)?;
        if record.expires_at <= self.now() {
            return None;
        }
        if record.peer != peer || record.connection_id != connection_id {
            return None;
        }
        Some((record.role, record.grants.clone()))
    }

    /// Verify a credential on the authenticated sibling sensitive transport.
    /// The token remains bound to the exact OS peer that obtained it; the
    /// sibling connection has no control-connection id of its own.
    pub fn verify_sensitive_peer(
        &self,
        peer: PeerIdentity,
        presented: &str,
    ) -> Option<(LocalClientRole, Vec<PrincipalGrant>)> {
        if !peer_identity_matches_live_process(peer) {
            return None;
        }
        let state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let record = state.records.get(presented)?;
        if record.expires_at <= self.now() || record.peer != peer {
            return None;
        }
        Some((record.role, record.grants.clone()))
    }

    /// Current deadline of `presented` on `connection_id`, on the credential
    /// clock; it moves forward each time the connection's lease renews it.
    pub fn expires_at(&self, connection_id: Uuid, presented: &str) -> Option<CredentialInstant> {
        let state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state
            .records
            .get(presented)
            .filter(|record| record.connection_id == connection_id)
            .map(|record| record.expires_at)
    }

    /// Withdraw the connection's credential. The connection is told why
    /// through its invalidation hook, when one is still registered.
    pub fn revoke_for_connection(&self, connection_id: Uuid, reason: PeerCredentialRevocation) {
        let withdrawn = {
            let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
            let tokens: Vec<_> = state
                .records
                .iter()
                .filter(|(_, record)| record.connection_id == connection_id)
                .map(|(token, _)| token.clone())
                .collect();
            tokens
                .into_iter()
                .filter_map(|token| state.withdraw(&token, reason))
                .collect()
        };
        self.notify_withdrawn(withdrawn);
    }

    /// Teardown is serialized with removal and cause publication. Notifications
    /// already in flight cannot recreate the released connection's state.
    pub fn release_connection(&self, connection_id: Uuid) {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        state.release_connection(connection_id);
    }

    fn release_lease(&self, connection: PeerCredentialConnection) {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if state.connections.get(&connection.connection_id) == Some(&connection.generation) {
            state.release_connection(connection.connection_id);
        }
    }

    #[cfg(test)]
    fn renew_connection_for_test(&self, connection_id: Uuid) -> PeerCredentialRenewal {
        let connection = {
            let state = self.state.lock().unwrap();
            state
                .connections
                .get(&connection_id)
                .map(|generation| PeerCredentialConnection {
                    connection_id,
                    generation: *generation,
                })
        };
        connection.map_or(PeerCredentialRenewal::NoCredential, |connection| {
            self.renew_connection(connection)
        })
    }

    #[cfg(test)]
    pub(crate) fn invalidation_hook_count(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .invalidation_hooks
            .len()
    }

    #[cfg(test)]
    pub(crate) fn connection_count_for_test(&self) -> usize {
        self.state.lock().unwrap().connections.len()
    }

    #[cfg(test)]
    pub(crate) fn connection_records_for_test(&self) -> Vec<(Uuid, String)> {
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .records
            .iter()
            .map(|(token, record)| (record.connection_id, token.clone()))
            .collect()
    }
}

/// Binds a connection's peer credential, and the hook that tells the
/// connection about revocation, to the lifetime of the connection handler
/// that owns them. While held, the lease renews the connection's credential
/// every [`PeerCredentialRegistry::renewal_interval`] (each renewal
/// re-verifies the peer process); dropping it, on every teardown path
/// including task cancellation, unwinding and early returns, stops renewal
/// and releases the credential, its hook, and its recorded revocation cause.
/// Must be created inside a Tokio runtime.
pub struct PeerCredentialLease {
    registry: Arc<PeerCredentialRegistry>,
    connection: PeerCredentialConnection,
    renewal: tokio::task::AbortHandle,
}

impl PeerCredentialLease {
    pub fn hold(registry: Arc<PeerCredentialRegistry>, connection_id: Uuid) -> Self {
        Self::hold_inner(registry, connection_id, None)
    }

    fn hold_inner(
        registry: Arc<PeerCredentialRegistry>,
        connection_id: Uuid,
        hook: Option<InvalidationHook>,
    ) -> Self {
        let connection = registry.open_connection(connection_id, hook);
        let renewal_registry = registry.clone();
        let renewal = tokio::spawn(async move {
            let period = renewal_registry.renewal_interval();
            let mut ticks = tokio::time::interval_at(tokio::time::Instant::now() + period, period);
            ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticks.tick().await;
                if let PeerCredentialRenewal::Revoked(reason) =
                    renewal_registry.renew_connection(connection)
                {
                    tracing::warn!(
                        %connection_id,
                        ?reason,
                        "peer credential could not be renewed; connection lost its local authority"
                    );
                }
            }
        })
        .abort_handle();
        Self {
            registry,
            connection,
            renewal,
        }
    }

    /// [`Self::hold`] plus the connection's revocation hook, owned by the
    /// same guard so cancellation can never leave the hook registered.
    pub fn hold_with_invalidation_hook(
        registry: Arc<PeerCredentialRegistry>,
        connection_id: Uuid,
        hook: impl Fn(&str, PeerCredentialRevocation) + Send + Sync + 'static,
    ) -> Self {
        Self::hold_inner(registry, connection_id, Some(Arc::new(hook)))
    }

    pub fn connection(&self) -> PeerCredentialConnection {
        self.connection
    }
}

impl Drop for PeerCredentialLease {
    fn drop(&mut self) {
        self.renewal.abort();
        self.registry.release_lease(self.connection);
    }
}

/// True when a socket peer's cached owner capability still matches a live
/// peer-bound registry record. In-process clients keep the cached flag.
pub fn socket_peer_owner_capability_live(
    registry: &PeerCredentialRegistry,
    socket_peer: Option<PeerIdentity>,
    connection_id: Uuid,
    active_peer_credential: Option<&str>,
    cached_has_owner_capability: bool,
) -> bool {
    if !cached_has_owner_capability {
        return false;
    }
    match socket_peer {
        None => true,
        Some(peer) => active_peer_credential
            .and_then(|token| registry.verify_without_prune(peer, connection_id, token))
            .is_some_and(|(role, _)| role.is_owner_class()),
    }
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
    match cockpit_host::daemon_lifecycle::process_start_identity(peer.pid) {
        Ok(start) if start != peer.process_start => return false,
        Err(_) => return false,
        Ok(_) => {}
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
    #[cfg(unix)]
    {
        let cmdline = cockpit_host::daemon_lifecycle::read_process_cmdline(peer.pid).ok()?;
        classify_cockpit_cmdline(&cmdline)
    }
    #[cfg(windows)]
    {
        None
    }
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

fn classify_cockpit_cmdline(cmdline: &[String]) -> Option<LocalClientRole> {
    let args = cmdline
        .iter()
        .skip(1)
        .map(|arg| arg.as_str())
        .collect::<Vec<_>>();
    if args.first() == Some(&"acp") {
        return Some(LocalClientRole::Acp);
    }
    if args.is_empty() {
        return Some(LocalClientRole::Tui);
    }
    if args
        .iter()
        .any(|arg| matches!(*arg, "tui" | "attach" | "run"))
    {
        return Some(LocalClientRole::Tui);
    }
    if matches!(
        args.first(),
        Some(&"code") | Some(&"assistant") | Some(&"computer")
    ) {
        return Some(LocalClientRole::Tui);
    }
    Some(LocalClientRole::Cli)
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
            Some(LocalClientRole::Tui)
        );
        assert_eq!(
            classify_cockpit_cmdline(&["cockpit".into(), "acp".into()]),
            Some(LocalClientRole::Acp)
        );
        assert_eq!(
            classify_cockpit_cmdline(&["cockpit".into(), "daemon".into(), "status".into()]),
            Some(LocalClientRole::Cli)
        );
        assert_eq!(
            classify_cockpit_cmdline(&["cockpit".into(), "run".into(), "task".into()]),
            Some(LocalClientRole::Tui)
        );
        assert_eq!(
            classify_cockpit_cmdline(&["cockpit".into(), "evil".into()]),
            Some(LocalClientRole::Cli)
        );
        assert_eq!(
            classify_cockpit_cmdline(&["cockpit".into(), "trust".into(), "set".into()]),
            Some(LocalClientRole::Cli)
        );
    }

    #[test]
    fn repeated_mint_on_one_connection_does_not_evict_unrelated_credentials() {
        let registry = PeerCredentialRegistry::default();
        let pid = std::process::id();
        #[cfg(unix)]
        let (uid, gid) =
            cockpit_host::daemon_lifecycle::read_process_credentials(pid).expect("uid/gid");
        #[cfg(windows)]
        let (uid, gid) = (0_u32, 0_u32);
        let peer = PeerIdentity {
            pid,
            uid,
            gid,
            process_start: cockpit_host::daemon_lifecycle::process_start_identity(pid)
                .expect("process start"),
        };
        let mut unrelated = Vec::new();
        for _ in 0..MAX_PEER_CREDENTIAL_RECORDS {
            let connection_id = Uuid::new_v4();
            unrelated.push((
                connection_id,
                registry.mint(peer, connection_id, LocalClientRole::Cli, Vec::new()),
            ));
        }
        let attacker_connection = unrelated[0].0;
        for _ in 0..32 {
            registry.mint(
                peer,
                attacker_connection,
                LocalClientRole::AgentChild,
                Vec::new(),
            );
        }
        for (connection_id, token) in unrelated.iter().skip(1) {
            assert!(
                registry
                    .verify(peer, *connection_id, token.as_str())
                    .is_some(),
                "unrelated credential must survive repeated exchange on another connection"
            );
        }
    }

    #[test]
    fn socket_peer_owner_capability_live_requires_peer_bound_token() {
        let registry = PeerCredentialRegistry::default();
        let pid = std::process::id();
        #[cfg(unix)]
        let (uid, gid) =
            cockpit_host::daemon_lifecycle::read_process_credentials(pid).expect("uid/gid");
        #[cfg(windows)]
        let (uid, gid) = (0_u32, 0_u32);
        let peer = PeerIdentity {
            pid,
            uid,
            gid,
            process_start: cockpit_host::daemon_lifecycle::process_start_identity(pid)
                .expect("process start"),
        };
        let connection_id = Uuid::new_v4();
        assert!(!socket_peer_owner_capability_live(
            &registry,
            Some(peer),
            connection_id,
            None,
            true,
        ));
        let token = registry.mint(peer, connection_id, LocalClientRole::Cli, Vec::new());
        assert!(socket_peer_owner_capability_live(
            &registry,
            Some(peer),
            connection_id,
            Some(token.as_str()),
            true,
        ));
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
        let peer = PeerIdentity {
            pid,
            uid,
            gid,
            process_start: cockpit_host::daemon_lifecycle::process_start_identity(pid)
                .expect("process start"),
        };
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
                        process_start: peer.process_start,
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

    fn current_process_peer_identity() -> PeerIdentity {
        let pid = std::process::id();
        #[cfg(unix)]
        let (uid, gid) =
            cockpit_host::daemon_lifecycle::read_process_credentials(pid).expect("uid/gid");
        #[cfg(windows)]
        let (uid, gid) = (0_u32, 0_u32);
        PeerIdentity {
            pid,
            uid,
            gid,
            process_start: cockpit_host::daemon_lifecycle::process_start_identity(pid)
                .expect("process start"),
        }
    }

    /// N1: release occurs after removal, before its deferred notification.
    /// The callback then re-enters the real registry, proving that external
    /// callbacks do not retain its state lock or recreate released state.
    #[test]
    fn r3_withdrawal_racing_release_leaves_no_dead_cause() {
        let registry = Arc::new(PeerCredentialRegistry::default());
        let connection_id = Uuid::new_v4();
        let token = registry.mint(
            current_process_peer_identity(),
            connection_id,
            LocalClientRole::Tui,
            vec![],
        );
        let entered = Arc::new(std::sync::Barrier::new(2));
        let resume = Arc::new(std::sync::Barrier::new(2));
        let hook_registry = Arc::downgrade(&registry);
        let boundary_entered = entered.clone();
        let boundary_resume = resume.clone();
        registry.before_notifications_for_test(move || {
            boundary_entered.wait();
            boundary_resume.wait();
        });
        registry.register_invalidation_hook(connection_id, move |token, _| {
            assert!(
                hook_registry
                    .upgrade()
                    .unwrap()
                    .expires_at(connection_id, token)
                    .is_none()
            );
        });
        let worker_registry = registry.clone();
        let withdrawal = std::thread::spawn(move || {
            worker_registry
                .revoke_for_connection(connection_id, PeerCredentialRevocation::PeerChanged)
        });
        entered.wait();
        registry.release_connection(connection_id);
        resume.wait();
        withdrawal.join().unwrap();
        assert_eq!(
            registry.revocation_cause(connection_id, token.as_str()),
            None,
            "a deferred withdrawal must not recreate the released connection's cause"
        );
        let state = registry.state.lock().unwrap();
        assert!(state.records.is_empty());
        assert!(state.invalidation_hooks.is_empty());
        assert!(
            state.revocations.is_empty(),
            "no dead connection state survives"
        );
    }

    /// A copied producer cannot outlive its lease or borrow a successor's
    /// generation, even if an internal caller reuses the connection UUID.
    #[tokio::test]
    async fn released_generation_cannot_mint_renew_or_release_its_successor() {
        let registry = Arc::new(PeerCredentialRegistry::default());
        let peer = current_process_peer_identity();
        let id = Uuid::new_v4();
        let lease = PeerCredentialLease::hold(registry.clone(), id);
        let old = lease.connection();
        let old_token = registry
            .try_mint(peer, old, LocalClientRole::Tui, vec![])
            .unwrap();
        assert!(
            registry
                .verify_sensitive_peer(peer, old_token.as_str())
                .is_some()
        );
        drop(lease);
        assert_eq!(
            registry.try_mint(peer, old, LocalClientRole::Tui, vec![]),
            Err(PeerCredentialMintError::ConnectionClosed)
        );
        assert_eq!(
            registry.renew_connection(old),
            PeerCredentialRenewal::NoCredential
        );
        assert!(
            registry
                .verify_sensitive_peer(peer, old_token.as_str())
                .is_none()
        );
        assert_eq!(registry.connection_count_for_test(), 0);

        let successor = PeerCredentialLease::hold(registry.clone(), id);
        let current = successor.connection();
        assert_ne!(old, current);
        let token = registry
            .try_mint(peer, current, LocalClientRole::Tui, vec![])
            .unwrap();
        assert_eq!(
            registry.try_mint(peer, old, LocalClientRole::Tui, vec![]),
            Err(PeerCredentialMintError::ConnectionClosed)
        );
        assert_eq!(
            registry.renew_connection(old),
            PeerCredentialRenewal::NoCredential
        );
        registry.release_lease(old);
        assert!(
            registry
                .verify_sensitive_peer(peer, token.as_str())
                .is_some(),
            "a stale producer/release must not remove the successor"
        );
        assert_eq!(
            registry.renew_connection(current),
            PeerCredentialRenewal::Renewed
        );
        registry.revoke_for_connection(id, PeerCredentialRevocation::PeerChanged);
        assert_eq!(
            registry.renew_connection(current),
            PeerCredentialRenewal::NoCredential
        );
        assert!(
            registry
                .verify_sensitive_peer(peer, token.as_str())
                .is_none()
        );
        let fresh = registry
            .try_mint(peer, current, LocalClientRole::Tui, vec![])
            .unwrap();
        assert!(
            registry
                .verify_sensitive_peer(peer, fresh.as_str())
                .is_some(),
            "a still-served connection may exchange again after withdrawal"
        );
        drop(successor);
        assert_eq!(registry.connection_count_for_test(), 0);
        assert!(registry.connection_records_for_test().is_empty());
        assert!(registry.state.lock().unwrap().revocations.is_empty());
    }

    const SHORT_TTL: Duration = Duration::from_millis(300);

    /// Issue #546: renewal by the live connection keeps its credential valid
    /// across many TTLs; the same record without renewal lapses.
    #[test]
    fn renewed_credential_outlives_the_ttl_and_an_unrenewed_one_lapses() {
        let registry = PeerCredentialRegistry::with_ttl_for_test(SHORT_TTL);
        let peer = current_process_peer_identity();
        let live = Uuid::new_v4();
        let orphan = Uuid::new_v4();
        let live_token = registry.mint(peer, live, LocalClientRole::Tui, Vec::new());
        let orphan_token = registry.mint(peer, orphan, LocalClientRole::Tui, Vec::new());
        for _ in 0..6 {
            std::thread::sleep(registry.renewal_interval());
            assert_eq!(
                registry.renew_connection_for_test(live),
                PeerCredentialRenewal::Renewed
            );
        }
        assert!(
            registry
                .verify(peer, live, live_token.as_str())
                .is_some_and(|(role, _)| role.is_owner_class()),
            "a renewed credential stays valid well past its TTL"
        );
        assert!(
            registry
                .verify(peer, orphan, orphan_token.as_str())
                .is_none(),
            "a credential nobody renews lapses within its TTL"
        );
    }

    /// A lapsed record is never revived by a late renewal.
    #[test]
    fn late_renewal_never_revives_a_lapsed_credential() {
        let registry = Arc::new(PeerCredentialRegistry::with_ttl_for_test(SHORT_TTL));
        let peer = current_process_peer_identity();
        let connection_id = Uuid::new_v4();
        let reasons = Arc::new(Mutex::new(Vec::new()));
        let hook_reasons = reasons.clone();
        registry.register_invalidation_hook(connection_id, move |_token, reason| {
            hook_reasons.lock().unwrap().push(reason);
        });
        let token = registry.mint(peer, connection_id, LocalClientRole::Tui, Vec::new());
        std::thread::sleep(SHORT_TTL + Duration::from_millis(50));
        assert_eq!(
            registry.renew_connection_for_test(connection_id),
            PeerCredentialRenewal::Revoked(PeerCredentialRevocation::Lapsed)
        );
        assert!(
            registry
                .verify(peer, connection_id, token.as_str())
                .is_none()
        );
        assert_eq!(
            registry.renew_connection_for_test(connection_id),
            PeerCredentialRenewal::NoCredential
        );
        assert_eq!(
            *reasons.lock().unwrap(),
            vec![PeerCredentialRevocation::Lapsed]
        );
    }

    /// Renewal re-verifies the minting peer: a record whose peer is no longer
    /// the exact live process is revoked, and the connection is told why.
    #[test]
    fn renewal_revokes_a_credential_whose_peer_is_no_longer_live() {
        let registry = PeerCredentialRegistry::with_ttl_for_test(Duration::from_secs(60));
        let live = current_process_peer_identity();
        let recycled = PeerIdentity {
            process_start: cockpit_host::daemon_lifecycle::ProcessStartIdentity {
                primary: live.process_start.primary.wrapping_add(1),
                ..live.process_start
            },
            ..live
        };
        let connection_id = Uuid::new_v4();
        let reasons = Arc::new(Mutex::new(Vec::new()));
        let hook_reasons = reasons.clone();
        registry.register_invalidation_hook(connection_id, move |_token, reason| {
            hook_reasons.lock().unwrap().push(reason);
        });
        let token = registry.mint(recycled, connection_id, LocalClientRole::Tui, Vec::new());
        assert_eq!(
            registry.renew_connection_for_test(connection_id),
            PeerCredentialRenewal::Revoked(PeerCredentialRevocation::PeerChanged)
        );
        assert!(registry.expires_at(connection_id, token.as_str()).is_none());
        assert_eq!(
            *reasons.lock().unwrap(),
            vec![PeerCredentialRevocation::PeerChanged]
        );
    }

    /// A flood of non-owner exchanges at the registry cap evicts other
    /// non-owner records, never the local owner's credential.
    #[test]
    fn non_owner_exchange_flood_never_evicts_the_owner_credential() {
        let registry = PeerCredentialRegistry::default();
        let peer = current_process_peer_identity();
        let owner_connection = Uuid::new_v4();
        let owner_token = registry.mint(peer, owner_connection, LocalClientRole::Tui, Vec::new());
        for _ in 0..(MAX_PEER_CREDENTIAL_RECORDS * 2) {
            registry.mint(
                peer,
                Uuid::new_v4(),
                LocalClientRole::AgentChild,
                Vec::new(),
            );
        }
        assert!(
            registry
                .verify(peer, owner_connection, owner_token.as_str())
                .is_some_and(|(role, _)| role.is_owner_class()),
            "the owner credential must survive non-owner churn at the cap"
        );
    }

    /// C6: an owner whose renewal is late, but whose credential has not
    /// lapsed, is never evicted while non-owner records exist (no
    /// role-blind "near expiry" sweep).
    #[test]
    fn unexpired_near_deadline_owner_outranks_non_owners_at_the_cap() {
        let registry = PeerCredentialRegistry::with_ttl_for_test(Duration::from_secs(3));
        let peer = current_process_peer_identity();
        let owner = Uuid::new_v4();
        let token = registry.mint(peer, owner, LocalClientRole::Tui, vec![]);
        for _ in 0..MAX_PEER_CREDENTIAL_RECORDS - 1 {
            registry.mint(peer, Uuid::new_v4(), LocalClientRole::AgentChild, vec![]);
        }
        // One delayed renewal: past half the TTL, still well before it.
        std::thread::sleep(Duration::from_millis(1700));
        assert!(registry.verify(peer, owner, token.as_str()).is_some());
        registry.mint(peer, Uuid::new_v4(), LocalClientRole::AgentChild, vec![]);
        assert!(
            registry.verify(peer, owner, token.as_str()).is_some(),
            "an unexpired owner must be evicted only after every non-owner record"
        );
    }

    /// C6: the cap never evicts an owner for a non-owner. A non-owner
    /// exchange into a registry holding only owners is refused, while an
    /// owner can always mint into a registry of non-owners.
    #[test]
    fn non_owner_exchange_never_evicts_an_owner_to_fit() {
        let registry = PeerCredentialRegistry::default();
        let peer = current_process_peer_identity();
        let owners: Vec<_> = (0..MAX_PEER_CREDENTIAL_RECORDS)
            .map(|_| {
                let id = Uuid::new_v4();
                (id, registry.mint(peer, id, LocalClientRole::Cli, vec![]))
            })
            .collect();
        assert_eq!(
            registry.try_mint(
                peer,
                registry.connection_for_test(Uuid::new_v4()),
                LocalClientRole::AgentChild,
                vec![]
            ),
            Err(PeerCredentialMintError::Full)
        );
        for (id, token) in &owners {
            assert!(registry.verify(peer, *id, token.as_str()).is_some());
        }

        let registry = PeerCredentialRegistry::default();
        for _ in 0..MAX_PEER_CREDENTIAL_RECORDS {
            registry.mint(peer, Uuid::new_v4(), LocalClientRole::AgentChild, vec![]);
        }
        let owner = Uuid::new_v4();
        let token = registry
            .try_mint(
                peer,
                registry.connection_for_test(owner),
                LocalClientRole::Tui,
                vec![],
            )
            .expect("an owner may displace a non-owner at the cap");
        assert!(registry.verify(peer, owner, token.as_str()).is_some());
        assert_eq!(
            registry.connection_records_for_test().len(),
            MAX_PEER_CREDENTIAL_RECORDS
        );
    }

    /// Clock that models a host which sleeps: tests advance only the awake
    /// time the credential clock counts.
    struct ManualClock(Mutex<Duration>);

    impl CredentialClock for ManualClock {
        fn now(&self) -> CredentialInstant {
            CredentialInstant(*self.0.lock().unwrap())
        }
    }

    /// C3: host suspend does not consume a live credential's TTL. The
    /// registry measures lifetime on its credential clock (awake time only),
    /// never on a clock that keeps running across suspend, so after a
    /// "suspend" longer than the TTL the next renewal still succeeds; awake
    /// time beyond the TTL still lapses it.
    #[test]
    fn host_suspend_longer_than_the_ttl_does_not_lapse_a_live_credential() {
        let clock = Arc::new(ManualClock(Mutex::new(Duration::ZERO)));
        let registry =
            PeerCredentialRegistry::with_clock_for_test(Duration::from_millis(200), clock.clone());
        let peer = current_process_peer_identity();
        let id = Uuid::new_v4();
        let token = registry.mint(peer, id, LocalClientRole::Tui, vec![]);
        // Host suspended: real (and Windows QPC) time passes, awake time does not.
        std::thread::sleep(Duration::from_millis(500));
        assert!(registry.verify(peer, id, token.as_str()).is_some());
        assert_eq!(
            registry.renew_connection_for_test(id),
            PeerCredentialRenewal::Renewed
        );
        *clock.0.lock().unwrap() += Duration::from_millis(150);
        assert_eq!(
            registry.renew_connection_for_test(id),
            PeerCredentialRenewal::Renewed
        );
        // Awake past the TTL without renewal: lapsed, never revived.
        *clock.0.lock().unwrap() += Duration::from_millis(250);
        assert!(registry.verify(peer, id, token.as_str()).is_none());
        assert_eq!(
            registry.renew_connection_for_test(id),
            PeerCredentialRenewal::NoCredential
        );
    }

    /// C7: the registry remembers why it withdrew a token until the
    /// connection ends, so late readers report the real cause; a fresh
    /// exchange or connection teardown clears it.
    #[test]
    fn revocation_cause_is_recorded_until_reexchange_or_release() {
        let registry = PeerCredentialRegistry::default();
        let peer = current_process_peer_identity();
        let id = Uuid::new_v4();
        let token = registry.mint(peer, id, LocalClientRole::Tui, vec![]);
        registry.revoke_for_connection(id, PeerCredentialRevocation::PeerChanged);
        assert_eq!(
            registry.revocation_cause(id, token.as_str()),
            Some(PeerCredentialRevocation::PeerChanged)
        );
        assert_eq!(registry.revocation_cause(id, "other-token"), None);
        let fresh = registry.mint(peer, id, LocalClientRole::Tui, vec![]);
        assert_eq!(registry.revocation_cause(id, token.as_str()), None);
        registry.revoke_for_connection(id, PeerCredentialRevocation::Evicted);
        registry.release_connection(id);
        assert_eq!(registry.revocation_cause(id, fresh.as_str()), None);
    }

    /// Reviewer probe (#546 r1): renewal racing revocation never revives.
    #[test]
    fn renewal_racing_revoke_does_not_revive() {
        let registry = Arc::new(PeerCredentialRegistry::default());
        let peer = current_process_peer_identity();
        for _ in 0..100 {
            let id = Uuid::new_v4();
            let token = registry.mint(peer, id, LocalClientRole::Tui, vec![]);
            let barrier = Arc::new(std::sync::Barrier::new(2));
            let renewer = {
                let registry = registry.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    registry.renew_connection_for_test(id)
                })
            };
            barrier.wait();
            registry.revoke_for_connection(id, PeerCredentialRevocation::Unrecognized);
            let _ = renewer.join().unwrap();
            assert!(
                registry
                    .verify_sensitive_peer(peer, token.as_str())
                    .is_none(),
                "revoked authority must not survive a concurrent renewal"
            );
            assert_eq!(
                registry.renew_connection_for_test(id),
                PeerCredentialRenewal::NoCredential
            );
        }
    }

    /// Reviewer probe (#546 r1) + C5: cancelling the task that holds a lease
    /// removes the credential, the hook, and the renewal task's registry
    /// reference.
    #[tokio::test]
    async fn lease_cancellation_releases_token_hook_and_renewal_task() {
        let registry = Arc::new(PeerCredentialRegistry::with_ttl_for_test(SHORT_TTL));
        let peer = current_process_peer_identity();
        let id = Uuid::new_v4();
        let token = registry.mint(peer, id, LocalClientRole::Tui, vec![]);
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let task = {
            let registry = registry.clone();
            tokio::spawn(async move {
                let _lease =
                    PeerCredentialLease::hold_with_invalidation_hook(registry, id, |_, _| {});
                ready_tx.send(()).unwrap();
                std::future::pending::<()>().await;
            })
        };
        ready_rx.await.unwrap();
        assert_eq!(registry.invalidation_hook_count(), 1);
        tokio::time::sleep(SHORT_TTL * 2).await;
        assert!(
            registry
                .verify_sensitive_peer(peer, token.as_str())
                .is_some()
        );
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert!(
            registry
                .verify_sensitive_peer(peer, token.as_str())
                .is_none()
        );
        assert_eq!(
            registry.invalidation_hook_count(),
            0,
            "cancellation must unregister the connection's hook"
        );
        tokio::time::sleep(SHORT_TTL * 2).await;
        assert_eq!(
            Arc::strong_count(&registry),
            1,
            "the renewal task must release its registry clone after cancellation"
        );
        assert!(registry.connection_records_for_test().is_empty());
    }

    /// Reviewer probe (#546 r1): a killed peer can neither renew nor use the
    /// sensitive sibling.
    #[cfg(unix)]
    #[tokio::test]
    async fn killed_peer_cannot_renew_or_use_sensitive_authority() {
        let mut child = tokio::process::Command::new("/bin/sleep")
            .arg("10")
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let pid = child.id().unwrap();
        let (uid, gid) = cockpit_host::daemon_lifecycle::read_process_credentials(pid).unwrap();
        let peer = PeerIdentity {
            pid,
            uid,
            gid,
            process_start: cockpit_host::daemon_lifecycle::process_start_identity(pid).unwrap(),
        };
        let registry = PeerCredentialRegistry::default();
        let id = Uuid::new_v4();
        let token = registry.mint(peer, id, LocalClientRole::Tui, vec![]);
        assert!(
            registry
                .verify_sensitive_peer(peer, token.as_str())
                .is_some()
        );
        assert_eq!(
            registry.renew_connection_for_test(id),
            PeerCredentialRenewal::Renewed
        );
        child.kill().await.unwrap();
        assert_eq!(
            registry.renew_connection_for_test(id),
            PeerCredentialRenewal::Revoked(PeerCredentialRevocation::PeerChanged)
        );
        assert!(
            registry
                .verify_sensitive_peer(peer, token.as_str())
                .is_none()
        );
        assert!(registry.expires_at(id, token.as_str()).is_none());
    }

    /// The lease renews while held and releases the credential when the
    /// connection handler drops it (including cancellation).
    #[tokio::test]
    async fn lease_renews_while_held_and_releases_on_drop() {
        let registry = Arc::new(PeerCredentialRegistry::with_ttl_for_test(SHORT_TTL));
        let peer = current_process_peer_identity();
        let connection_id = Uuid::new_v4();
        let lease = PeerCredentialLease::hold(registry.clone(), connection_id);
        let token = registry.mint(peer, connection_id, LocalClientRole::Tui, Vec::new());
        tokio::time::sleep(SHORT_TTL * 4).await;
        assert!(
            registry
                .verify(peer, connection_id, token.as_str())
                .is_some(),
            "a held lease keeps the connection's credential valid"
        );
        drop(lease);
        assert!(
            registry
                .verify(peer, connection_id, token.as_str())
                .is_none(),
            "dropping the lease releases the credential at once"
        );
    }

    #[test]
    fn mint_launch_ticket_is_well_formed_and_unique() {
        let first = mint_launch_ticket();
        let second = mint_launch_ticket();
        assert!(launch_ticket_is_well_formed(&first));
        assert!(launch_ticket_is_well_formed(&second));
        assert_ne!(first, second);
        assert!(!launch_ticket_is_well_formed(""));
        assert!(!launch_ticket_is_well_formed(
            "A".repeat(LAUNCH_TICKET_HEX_LEN).as_str()
        ));
        assert!(!launch_ticket_is_well_formed(
            "0".repeat(LAUNCH_TICKET_HEX_LEN - 1).as_str()
        ));
        assert!(!launch_ticket_is_well_formed(
            "g".repeat(LAUNCH_TICKET_HEX_LEN).as_str()
        ));
    }

    #[test]
    fn launch_provenance_admits_only_the_launcher_holding_the_ticket() {
        let registry = PeerCredentialRegistry::default();
        let launcher = current_process_peer_identity();
        let ticket = mint_launch_ticket();

        // No provenance recorded: fail closed for every presenter.
        assert!(!registry.verify_launch_provenance(Some(&ticket), launcher));

        registry.record_launch_provenance(ticket.clone(), Some(launcher));
        // Exact launcher presenting the exact ticket is admitted.
        assert!(registry.verify_launch_provenance(Some(&ticket), launcher));
        // A follower on the same uid may present the persisted ticket.
        assert!(registry.verify_launch_provenance(
            Some(&ticket),
            PeerIdentity {
                pid: launcher.pid.saturating_add(1),
                uid: launcher.uid,
                gid: launcher.gid,
                process_start: launcher.process_start,
            },
        ));
        // A different uid presenting the stolen ticket is denied.
        assert!(!registry.verify_launch_provenance(
            Some(&ticket),
            PeerIdentity {
                pid: launcher.pid,
                uid: launcher.uid.saturating_add(1),
                gid: launcher.gid,
                process_start: launcher.process_start,
            },
        ));
        // The launcher presenting the wrong ticket is denied.
        assert!(!registry.verify_launch_provenance(Some("0".repeat(64).as_str()), launcher));
        // No presented token is denied.
        assert!(!registry.verify_launch_provenance(None, launcher));
    }

    #[test]
    fn launch_provenance_without_a_launcher_identity_allows_ticket_holders() {
        let registry = PeerCredentialRegistry::default();
        let ticket = mint_launch_ticket();
        registry.record_launch_provenance(ticket.clone(), None);
        assert!(registry.verify_launch_provenance(Some(&ticket), current_process_peer_identity()));
        assert!(!registry.verify_launch_provenance(
            Some("0".repeat(64).as_str()),
            current_process_peer_identity()
        ));
    }

    #[test]
    fn malformed_launch_ticket_is_never_recorded() {
        let registry = PeerCredentialRegistry::default();
        let launcher = current_process_peer_identity();
        registry.record_launch_provenance("not-hex".to_string(), Some(launcher));
        assert!(!registry.verify_launch_provenance(Some("not-hex"), launcher));
    }
}

#[cfg(test)]
mod security_r4_debug {
    use super::*;
    #[test]
    fn r4_revocation_record_debug_is_value_free() {
        let record = RevocationRecord {
            token: "NovelRevocation515Secret78529".into(),
            reason: PeerCredentialRevocation::Lapsed,
        };
        for rendered in [format!("{record:?}"), format!("{record:#?}")] {
            assert!(!rendered.contains("NovelRevocation515Secret78529"));
            assert!(rendered.contains("Lapsed"));
        }
    }
}
