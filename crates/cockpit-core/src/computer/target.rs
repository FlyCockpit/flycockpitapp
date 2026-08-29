//! Platform-neutral target identity evidence and physical target keys.
//!
//! The coordinator is the sole consumer of normalized snapshots. Platform
//! adapters convert OS types before returning; no native handles cross this
//! boundary. Application/title/role classifications are advisory only — Yolo is complete agent trust for
//! application/title/role classification.

use std::fmt;

use super::host_identity::{HostInstallationId, domain_hash};

/// Maximum retained redacted title/class hint length (bytes).
pub const MAX_HINT_BYTES: usize = 64;

/// Backend kind is diagnostic/metadata only — never partitions the lease.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BackendKind {
    VirtualDisplay,
    RealDesktopX11,
    RealDesktopMacOs,
    RealDesktopWindows,
    RealDesktopWayland,
    Unknown,
}

impl BackendKind {
    /// A short, stable, safe diagnostic label for this backend kind. Carried
    /// only as authorization metadata (never partitions the lease).
    pub fn diagnostic_label(&self) -> &'static str {
        match self {
            BackendKind::VirtualDisplay => "virtual_display",
            BackendKind::RealDesktopX11 => "real_desktop_x11",
            BackendKind::RealDesktopMacOs => "real_desktop_macos",
            BackendKind::RealDesktopWindows => "real_desktop_windows",
            BackendKind::RealDesktopWayland => "real_desktop_wayland",
            BackendKind::Unknown => "unknown",
        }
    }
}

/// Why a field or whole snapshot is unavailable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum TargetUnavailableReason {
    HostIdentityUnavailable,
    FocusIdentityUnavailable,
    PermissionDenied,
    SessionInactive,
    SessionTransition,
    LockOrSecureDesktop,
    StaleTarget,
    AmbiguousOutput,
    AdapterTerminalFailure,
    UnsupportedPlatform,
    EpochOverflow,
    MissingCapability,
    VirtualDisplayNoPhysicalLease,
    ProviderUnregistered,
    PortalExpired,
    SourceReplaced,
    Reconnect,
    XwaylandFallbackForbidden,
    PartialEvidence,
    QueryMismatch,
    /// An Ask-tier dispatch has neither a host lease nor a known virtual
    /// display UUID, so the delegation lease cannot be scoped to a real
    /// target. Dispatch fails closed: no human prompt, no backend input.
    VirtualIdentityUnavailable,
}

/// Source of a particular evidence field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EvidenceSource {
    MachAuditToken,
    CgSession,
    AppKitWorkspace,
    Accessibility,
    CgWindowList,
    ColorSyncDisplayUuid,
    WinSessionDesktop,
    WinForeground,
    WinAppx,
    WinMonitor,
    X11ServerSetup,
    X11NetActiveWindow,
    X11Randr,
    AtSpi,
    WaylandProvider,
    VirtualEngine,
    InjectedTest,
}

/// Opaque focused-window ID (platform-neutral bytes after adapter conversion).
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct OpaqueWindowId {
    bytes: [u8; 16],
}

impl OpaqueWindowId {
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self { bytes }
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.bytes
    }
}

impl fmt::Debug for OpaqueWindowId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OpaqueWindowId([opaque])")
    }
}

/// Stable application identity when the OS exposes one (bundle id, Appx, etc.).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StableApplicationId {
    pub kind: &'static str,
    /// Bounded, non-secret identifier string.
    pub value: String,
}

/// Geometry in physical pixels plus scale.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct TargetGeometry {
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
    pub scale: f64,
}

/// Bounded redacted title/class hint — never durable raw content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactedHint {
    /// Truncated/redacted preview for diagnostics only.
    pub redacted: String,
    /// Domain-separated hash of the raw value (for audit projections).
    pub hash: [u8; 32],
}

impl RedactedHint {
    pub fn from_raw(raw: &str) -> Self {
        let hash = domain_hash(b"cockpit.target.hint.v1", &[raw.as_bytes()]);
        let redacted = if raw.chars().count() <= 8 {
            "***".to_string()
        } else {
            format!("{}…", raw.chars().take(4).collect::<String>())
        };
        let redacted = if redacted.len() > MAX_HINT_BYTES {
            redacted.chars().take(16).collect()
        } else {
            redacted
        };
        Self { redacted, hash }
    }
}

/// Per-field availability for typed partial evidence.
#[derive(Debug, Clone, PartialEq)]
pub enum FieldEvidence<T> {
    Available {
        value: T,
        source: EvidenceSource,
    },
    Unavailable {
        reason: TargetUnavailableReason,
        source: Option<EvidenceSource>,
    },
}

impl<T> FieldEvidence<T> {
    pub fn available(value: T, source: EvidenceSource) -> Self {
        Self::Available { value, source }
    }

    pub fn unavailable(reason: TargetUnavailableReason, source: Option<EvidenceSource>) -> Self {
        Self::Unavailable { reason, source }
    }

    pub fn as_ref(&self) -> FieldEvidence<&T> {
        match self {
            Self::Available { value, source } => FieldEvidence::Available {
                value,
                source: *source,
            },
            Self::Unavailable { reason, source } => FieldEvidence::Unavailable {
                reason: *reason,
                source: *source,
            },
        }
    }

    pub fn is_available(&self) -> bool {
        matches!(self, Self::Available { .. })
    }
}

/// Engine-owned focused target evidence captured as one coherent snapshot.
#[derive(Debug, Clone, PartialEq)]
pub struct TargetIdentityEvidence {
    pub backend_kind: BackendKind,
    pub host_installation_id: FieldEvidence<HostInstallationId>,
    pub platform_session_or_seat_id: FieldEvidence<[u8; 32]>,
    pub physical_display_id: FieldEvidence<[u8; 32]>,
    pub focused_window_id: FieldEvidence<OpaqueWindowId>,
    pub process_id: FieldEvidence<u32>,
    pub stable_application_id: FieldEvidence<StableApplicationId>,
    pub accessibility_role: FieldEvidence<String>,
    pub accessibility_subrole: FieldEvidence<String>,
    pub title_hint: FieldEvidence<RedactedHint>,
    pub class_hint: FieldEvidence<RedactedHint>,
    pub geometry: FieldEvidence<TargetGeometry>,
    /// Monotonic generation allocated whenever any identity/geometry component changes.
    pub focus_generation: u64,
    /// Adapter-observed epoch (never labeled `os_focus_sequence`).
    pub adapter_observed_epoch: u64,
    /// Whether this snapshot used an immediate synchronous recheck.
    pub synchronous_recheck: bool,
    /// Virtual display UUID when target is virtual (no host-global physical lease).
    pub virtual_display_uuid: Option<[u8; 16]>,
    pub virtual_backend_generation: Option<u64>,
}

impl TargetIdentityEvidence {
    /// Build the physical target key when all three key fields are available.
    /// Virtual displays return `None` (they do not acquire a host-global lease).
    pub fn physical_target_key(&self) -> Result<PhysicalTargetKey, TargetUnavailableReason> {
        if self.virtual_display_uuid.is_some() {
            return Err(TargetUnavailableReason::VirtualDisplayNoPhysicalLease);
        }
        let host = match &self.host_installation_id {
            FieldEvidence::Available { value, .. } => *value,
            FieldEvidence::Unavailable { reason, .. } => return Err(*reason),
        };
        let session = match &self.platform_session_or_seat_id {
            FieldEvidence::Available { value, .. } => *value,
            FieldEvidence::Unavailable { reason, .. } => return Err(*reason),
        };
        let display = match &self.physical_display_id {
            FieldEvidence::Available { value, .. } => *value,
            FieldEvidence::Unavailable { reason, .. } => return Err(*reason),
        };
        Ok(PhysicalTargetKey {
            host_installation_id: host,
            platform_session_or_seat_id: session,
            physical_display_id: display,
        })
    }
}

/// Sole key for the host-global input arbiter.
///
/// Exactly `(host_installation_id, platform_session_or_seat_id, physical_display_id)`.
/// Backend kind, title, bundle name, PID alone, or provider/model fields can never
/// key, partition, or bypass the lease.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PhysicalTargetKey {
    pub host_installation_id: HostInstallationId,
    pub platform_session_or_seat_id: [u8; 32],
    pub physical_display_id: [u8; 32],
}

impl fmt::Debug for PhysicalTargetKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PhysicalTargetKey")
            .field("host_installation_id", &self.host_installation_id)
            .field("platform_session_or_seat_id", &"[REDACTED; 32]")
            .field("physical_display_id", &"[REDACTED; 32]")
            .finish()
    }
}

impl PhysicalTargetKey {
    pub fn new(
        host_installation_id: HostInstallationId,
        platform_session_or_seat_id: [u8; 32],
        physical_display_id: [u8; 32],
    ) -> Self {
        Self {
            host_installation_id,
            platform_session_or_seat_id,
            physical_display_id,
        }
    }
}

/// Durable audit/export projection — no raw titles, pixels, credentials, or IDs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafeTargetAuditProjection {
    pub backend_kind: BackendKind,
    pub focus_generation: u64,
    pub adapter_observed_epoch: u64,
    pub synchronous_recheck: bool,
    pub host_identity: super::host_identity::HostIdentityDiagnostic,
    pub session_present: bool,
    pub display_present: bool,
    pub window_present: bool,
    pub process_id_present: bool,
    pub title_hint_hash: Option<[u8; 32]>,
    pub class_hint_hash: Option<[u8; 32]>,
    pub unavailable: Vec<TargetUnavailableReason>,
    /// Explicitly forbidden stronger claim labels must not appear in events.
    pub sequence_claim: SequenceClaim,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SequenceClaim {
    /// Only allowed claim for macOS/Windows.
    AdapterObservedEpoch,
    /// X11/Wayland may claim stronger sequencing only under exact contracts.
    OrderedEventContract,
}

impl TargetIdentityEvidence {
    pub fn safe_audit_projection(&self) -> SafeTargetAuditProjection {
        use super::host_identity::HostIdentityDiagnostic;
        let mut unavailable = Vec::new();
        let host_identity = match &self.host_installation_id {
            FieldEvidence::Available { .. } => HostIdentityDiagnostic::Present,
            FieldEvidence::Unavailable { reason, .. } => {
                unavailable.push(*reason);
                HostIdentityDiagnostic::Unavailable(
                    super::host_identity::HostIdentityUnavailableReason::IoFailure,
                )
            }
        };
        let title_hint_hash = match &self.title_hint {
            FieldEvidence::Available { value, .. } => Some(value.hash),
            FieldEvidence::Unavailable { reason, .. } => {
                unavailable.push(*reason);
                None
            }
        };
        let class_hint_hash = match &self.class_hint {
            FieldEvidence::Available { value, .. } => Some(value.hash),
            FieldEvidence::Unavailable { reason, .. } => {
                unavailable.push(*reason);
                None
            }
        };
        SafeTargetAuditProjection {
            backend_kind: self.backend_kind,
            focus_generation: self.focus_generation,
            adapter_observed_epoch: self.adapter_observed_epoch,
            synchronous_recheck: self.synchronous_recheck,
            host_identity,
            session_present: self.platform_session_or_seat_id.is_available(),
            display_present: self.physical_display_id.is_available(),
            window_present: self.focused_window_id.is_available(),
            process_id_present: self.process_id.is_available(),
            title_hint_hash,
            class_hint_hash,
            unavailable,
            sequence_claim: SequenceClaim::AdapterObservedEpoch,
        }
    }
}

/// Checked generation reducer: increments when identity/geometry components change.
#[derive(Debug, Default)]
pub struct FocusGenerationReducer {
    last: Option<GenerationFingerprint>,
    generation: u64,
}

#[derive(Debug, Clone, PartialEq)]
struct GenerationFingerprint {
    session: Option<[u8; 32]>,
    display: Option<[u8; 32]>,
    window: Option<[u8; 16]>,
    process_id: Option<u32>,
    app: Option<String>,
    geometry: Option<(i32, i32, u32, u32)>,
    scale_bits: Option<u64>,
}

impl FocusGenerationReducer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn current(&self) -> u64 {
        self.generation
    }

    /// Observe a fingerprint derived from evidence fields; returns the generation.
    pub fn observe(
        &mut self,
        evidence: &TargetIdentityEvidence,
    ) -> Result<u64, TargetUnavailableReason> {
        let fp = GenerationFingerprint {
            session: field_value(&evidence.platform_session_or_seat_id).copied(),
            display: field_value(&evidence.physical_display_id).copied(),
            window: field_value(&evidence.focused_window_id).map(|w| *w.as_bytes()),
            process_id: field_value(&evidence.process_id).copied(),
            app: field_value(&evidence.stable_application_id).map(|a| a.value.clone()),
            geometry: field_value(&evidence.geometry).map(|g| (g.x, g.y, g.width, g.height)),
            scale_bits: field_value(&evidence.geometry).map(|g| g.scale.to_bits()),
        };
        match &self.last {
            None => {
                self.last = Some(fp);
                self.generation = 1;
            }
            Some(prev) if prev == &fp => {}
            Some(_) => {
                self.generation = self
                    .generation
                    .checked_add(1)
                    .ok_or(TargetUnavailableReason::EpochOverflow)?;
                self.last = Some(fp);
            }
        }
        Ok(self.generation)
    }
}

fn field_value<T>(field: &FieldEvidence<T>) -> Option<&T> {
    match field {
        FieldEvidence::Available { value, .. } => Some(value),
        FieldEvidence::Unavailable { .. } => None,
    }
}

/// Platform-neutral evidence adapter. OS types never cross this trait.
///
/// `Send + Sync` is required because coordinators live on the driver stack and
/// the driver is cloned into `tokio::spawn`ed noninteractive work.
pub trait TargetEvidenceAdapter: Send + Sync {
    fn backend_kind(&self) -> BackendKind;

    /// Capture one coherent snapshot. Individual field helpers are not public
    /// to tools/providers — only the coordinator calls this.
    fn capture_snapshot(&mut self) -> Result<TargetIdentityEvidence, TargetUnavailableReason>;

    /// Adapter-observed epoch (increments for every consumed native event).
    fn observed_focus_epoch(&self) -> u64;
}

/// Coordinator: sole caller of adapters; captures before planning and pre-handoff.
#[derive(Debug)]
pub struct TargetEvidenceCoordinator<A: TargetEvidenceAdapter> {
    adapter: A,
    reducer: FocusGenerationReducer,
    last_snapshot: Option<TargetIdentityEvidence>,
    /// Recorded input dispatches for tests (never real desktop).
    pub dispatched_inputs: Vec<PlannedInput>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedInput {
    pub action_label: String,
    pub physical_key: Option<PhysicalTargetKey>,
    pub focus_generation: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandoffDecision {
    Allow {
        key: Option<PhysicalTargetKey>,
        focus_generation: u64,
    },
    Reject {
        reason: TargetUnavailableReason,
    },
}

impl<A: TargetEvidenceAdapter> TargetEvidenceCoordinator<A> {
    pub fn new(adapter: A) -> Self {
        Self {
            adapter,
            reducer: FocusGenerationReducer::new(),
            last_snapshot: None,
            dispatched_inputs: Vec::new(),
        }
    }

    pub fn adapter(&self) -> &A {
        &self.adapter
    }

    pub fn adapter_mut(&mut self) -> &mut A {
        &mut self.adapter
    }

    /// Capture evidence before planning/authorization.
    pub fn capture_for_planning(
        &mut self,
    ) -> Result<TargetIdentityEvidence, TargetUnavailableReason> {
        let mut snap = self.adapter.capture_snapshot()?;
        let focus_gen = self.reducer.observe(&snap)?;
        snap.focus_generation = focus_gen;
        self.last_snapshot = Some(snap.clone());
        Ok(snap)
    }

    /// Immediate pre-handoff capture. Any target-key/epoch/window/geometry/scale
    /// mismatch vs the planning snapshot is `stale_target` with zero input.
    pub fn pre_handoff_check(
        &mut self,
        planning: &TargetIdentityEvidence,
    ) -> Result<TargetIdentityEvidence, TargetUnavailableReason> {
        let mut snap = self.adapter.capture_snapshot()?;
        snap.synchronous_recheck = true;
        let focus_gen = self.reducer.observe(&snap)?;
        snap.focus_generation = focus_gen;

        if snap.adapter_observed_epoch != planning.adapter_observed_epoch {
            return Err(TargetUnavailableReason::StaleTarget);
        }
        if planning_fingerprint(planning) != planning_fingerprint(&snap) {
            return Err(TargetUnavailableReason::StaleTarget);
        }
        // If pre-handoff is unavailable after a previously available read → stale.
        if had_core_identity(planning) && !had_core_identity(&snap) {
            return Err(TargetUnavailableReason::StaleTarget);
        }
        self.last_snapshot = Some(snap.clone());
        Ok(snap)
    }

    /// Attempt handoff: records input only when allowed.
    pub fn handoff(
        &mut self,
        planning: &TargetIdentityEvidence,
        action_label: impl Into<String>,
    ) -> HandoffDecision {
        match self.pre_handoff_check(planning) {
            Ok(snap) => {
                let key = snap.physical_target_key().ok();
                let focus_generation = snap.focus_generation;
                self.dispatched_inputs.push(PlannedInput {
                    action_label: action_label.into(),
                    physical_key: key,
                    focus_generation,
                });
                HandoffDecision::Allow {
                    key,
                    focus_generation,
                }
            }
            Err(reason) => HandoffDecision::Reject { reason },
        }
    }

    /// Yolo policy: sensitive application/role/title never cause denial or prompt.
    /// Only host capability, stale evidence, missing grant, unsupported backend reject.
    pub fn yolo_evaluate_target(
        &self,
        evidence: &TargetIdentityEvidence,
        real_desktop_granted: bool,
        backend_supported: bool,
    ) -> Result<(), TargetUnavailableReason> {
        // Advisory classifications intentionally unused for denial.
        let _ = &evidence.title_hint;
        let _ = &evidence.accessibility_role;
        let _ = &evidence.stable_application_id;

        if !backend_supported {
            return Err(TargetUnavailableReason::UnsupportedPlatform);
        }
        if evidence.backend_kind != BackendKind::VirtualDisplay && !real_desktop_granted {
            return Err(TargetUnavailableReason::MissingCapability);
        }
        if let FieldEvidence::Unavailable { reason, .. } = &evidence.host_installation_id
            && evidence.backend_kind != BackendKind::VirtualDisplay
        {
            return Err(*reason);
        }
        Ok(())
    }
}

fn had_core_identity(e: &TargetIdentityEvidence) -> bool {
    e.focused_window_id.is_available()
        && e.platform_session_or_seat_id.is_available()
        && e.physical_display_id.is_available()
}

fn planning_fingerprint(e: &TargetIdentityEvidence) -> String {
    format!(
        "{:?}|{:?}|{:?}|{:?}|{:?}|{:?}",
        field_value(&e.platform_session_or_seat_id),
        field_value(&e.physical_display_id),
        field_value(&e.focused_window_id).map(|w| *w.as_bytes()),
        field_value(&e.process_id),
        field_value(&e.geometry).map(|g| (g.x, g.y, g.width, g.height, g.scale.to_bits())),
        e.virtual_display_uuid,
    )
}

/// Host-global input lease table keyed only by [`PhysicalTargetKey`].
#[derive(Debug, Default)]
pub struct PhysicalInputLeaseTable {
    /// Occupied keys → lease owner token (opaque).
    leases: std::collections::BTreeMap<LeaseKey, u64>,
    next_owner: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct LeaseKey {
    host: [u8; 32],
    session: [u8; 32],
    display: [u8; 32],
}

impl From<&PhysicalTargetKey> for LeaseKey {
    fn from(k: &PhysicalTargetKey) -> Self {
        Self {
            host: k.host_installation_id.0,
            session: k.platform_session_or_seat_id,
            display: k.physical_display_id,
        }
    }
}

impl PhysicalInputLeaseTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Acquire exclusive lease. Two backend kinds with the same physical key contend.
    pub fn try_acquire(&mut self, key: &PhysicalTargetKey) -> Option<u64> {
        let lk = LeaseKey::from(key);
        if self.leases.contains_key(&lk) {
            return None;
        }
        self.next_owner = self.next_owner.saturating_add(1);
        let owner = self.next_owner;
        self.leases.insert(lk, owner);
        Some(owner)
    }

    pub fn release(&mut self, key: &PhysicalTargetKey, owner: u64) -> bool {
        let lk = LeaseKey::from(key);
        match self.leases.get(&lk) {
            Some(o) if *o == owner => {
                self.leases.remove(&lk);
                true
            }
            _ => false,
        }
    }

    pub fn is_held(&self, key: &PhysicalTargetKey) -> bool {
        self.leases.contains_key(&LeaseKey::from(key))
    }
}

/// Reject provider/model-supplied identity construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderSuppliedIdentity {
    pub claimed_host: Option<[u8; 32]>,
    pub claimed_session: Option<[u8; 32]>,
    pub claimed_display: Option<[u8; 32]>,
    pub claimed_window: Option<[u8; 16]>,
}

pub fn reject_provider_supplied_identity(
    _supplied: &ProviderSuppliedIdentity,
) -> Result<(), TargetUnavailableReason> {
    // Model/provider/tool payloads cannot construct target keys or generations.
    Err(TargetUnavailableReason::MissingCapability)
}

/// Fake adapter for hermetic tests (generation-controlled races, no real windows).
#[derive(Debug, Clone)]
pub struct FakeTargetEvidenceAdapter {
    pub backend_kind: BackendKind,
    pub snapshot: TargetIdentityEvidence,
    pub epoch: u64,
    /// When set, next capture returns this error.
    pub next_error: Option<TargetUnavailableReason>,
    /// Queue of snapshots for successive captures (planning then handoff).
    pub snapshot_queue: Vec<TargetIdentityEvidence>,
    pub capture_count: usize,
}

impl FakeTargetEvidenceAdapter {
    pub fn new(snapshot: TargetIdentityEvidence) -> Self {
        Self {
            backend_kind: snapshot.backend_kind,
            snapshot,
            epoch: 1,
            next_error: None,
            snapshot_queue: Vec::new(),
            capture_count: 0,
        }
    }

    pub fn with_queue(backend_kind: BackendKind, queue: Vec<TargetIdentityEvidence>) -> Self {
        let snapshot = queue
            .first()
            .cloned()
            .unwrap_or_else(|| empty_unavailable(backend_kind));
        Self {
            backend_kind,
            snapshot,
            epoch: 1,
            next_error: None,
            snapshot_queue: queue,
            capture_count: 0,
        }
    }

    pub fn advance_epoch(&mut self) {
        self.epoch = self.epoch.saturating_add(1);
        self.snapshot.adapter_observed_epoch = self.epoch;
    }

    pub fn mutate_window(&mut self, id: [u8; 16]) {
        self.snapshot.focused_window_id =
            FieldEvidence::available(OpaqueWindowId::from_bytes(id), EvidenceSource::InjectedTest);
        self.advance_epoch();
    }

    pub fn mutate_geometry(&mut self, g: TargetGeometry) {
        self.snapshot.geometry = FieldEvidence::available(g, EvidenceSource::InjectedTest);
        self.advance_epoch();
    }

    pub fn clear_identity(&mut self) {
        self.snapshot.focused_window_id = FieldEvidence::unavailable(
            TargetUnavailableReason::FocusIdentityUnavailable,
            Some(EvidenceSource::InjectedTest),
        );
        self.snapshot.platform_session_or_seat_id = FieldEvidence::unavailable(
            TargetUnavailableReason::FocusIdentityUnavailable,
            Some(EvidenceSource::InjectedTest),
        );
        self.snapshot.physical_display_id = FieldEvidence::unavailable(
            TargetUnavailableReason::FocusIdentityUnavailable,
            Some(EvidenceSource::InjectedTest),
        );
        self.advance_epoch();
    }
}

impl TargetEvidenceAdapter for FakeTargetEvidenceAdapter {
    fn backend_kind(&self) -> BackendKind {
        self.backend_kind
    }

    fn capture_snapshot(&mut self) -> Result<TargetIdentityEvidence, TargetUnavailableReason> {
        self.capture_count += 1;
        if let Some(err) = self.next_error.take() {
            return Err(err);
        }
        if !self.snapshot_queue.is_empty() {
            let idx = (self.capture_count - 1).min(self.snapshot_queue.len() - 1);
            let mut snap = self.snapshot_queue[idx].clone();
            snap.adapter_observed_epoch = self.epoch;
            return Ok(snap);
        }
        let mut snap = self.snapshot.clone();
        snap.adapter_observed_epoch = self.epoch;
        Ok(snap)
    }

    fn observed_focus_epoch(&self) -> u64 {
        self.epoch
    }
}

pub fn empty_unavailable(backend_kind: BackendKind) -> TargetIdentityEvidence {
    TargetIdentityEvidence {
        backend_kind,
        host_installation_id: FieldEvidence::unavailable(
            TargetUnavailableReason::HostIdentityUnavailable,
            None,
        ),
        platform_session_or_seat_id: FieldEvidence::unavailable(
            TargetUnavailableReason::FocusIdentityUnavailable,
            None,
        ),
        physical_display_id: FieldEvidence::unavailable(
            TargetUnavailableReason::FocusIdentityUnavailable,
            None,
        ),
        focused_window_id: FieldEvidence::unavailable(
            TargetUnavailableReason::FocusIdentityUnavailable,
            None,
        ),
        process_id: FieldEvidence::unavailable(
            TargetUnavailableReason::FocusIdentityUnavailable,
            None,
        ),
        stable_application_id: FieldEvidence::unavailable(
            TargetUnavailableReason::PartialEvidence,
            None,
        ),
        accessibility_role: FieldEvidence::unavailable(
            TargetUnavailableReason::PartialEvidence,
            None,
        ),
        accessibility_subrole: FieldEvidence::unavailable(
            TargetUnavailableReason::PartialEvidence,
            None,
        ),
        title_hint: FieldEvidence::unavailable(TargetUnavailableReason::PartialEvidence, None),
        class_hint: FieldEvidence::unavailable(TargetUnavailableReason::PartialEvidence, None),
        geometry: FieldEvidence::unavailable(TargetUnavailableReason::PartialEvidence, None),
        focus_generation: 0,
        adapter_observed_epoch: 0,
        synchronous_recheck: false,
        virtual_display_uuid: None,
        virtual_backend_generation: None,
    }
}

pub fn sample_physical_evidence(
    host: HostInstallationId,
    session: [u8; 32],
    display: [u8; 32],
    window: [u8; 16],
    pid: u32,
) -> TargetIdentityEvidence {
    TargetIdentityEvidence {
        backend_kind: BackendKind::RealDesktopX11,
        host_installation_id: FieldEvidence::available(host, EvidenceSource::InjectedTest),
        platform_session_or_seat_id: FieldEvidence::available(
            session,
            EvidenceSource::InjectedTest,
        ),
        physical_display_id: FieldEvidence::available(display, EvidenceSource::InjectedTest),
        focused_window_id: FieldEvidence::available(
            OpaqueWindowId::from_bytes(window),
            EvidenceSource::InjectedTest,
        ),
        process_id: FieldEvidence::available(pid, EvidenceSource::InjectedTest),
        stable_application_id: FieldEvidence::available(
            StableApplicationId {
                kind: "test.app",
                value: "com.example.app".into(),
            },
            EvidenceSource::InjectedTest,
        ),
        accessibility_role: FieldEvidence::available(
            "AXWindow".into(),
            EvidenceSource::InjectedTest,
        ),
        accessibility_subrole: FieldEvidence::unavailable(
            TargetUnavailableReason::PartialEvidence,
            None,
        ),
        title_hint: FieldEvidence::available(
            RedactedHint::from_raw("Secret Document — Banking"),
            EvidenceSource::InjectedTest,
        ),
        class_hint: FieldEvidence::available(
            RedactedHint::from_raw("Browser"),
            EvidenceSource::InjectedTest,
        ),
        geometry: FieldEvidence::available(
            TargetGeometry {
                x: 10,
                y: 20,
                width: 800,
                height: 600,
                scale: 2.0,
            },
            EvidenceSource::InjectedTest,
        ),
        // Injected-test fixture carries a live focus generation so coordinator
        // paths that dispatch focus-gated actions can pass the focus gate.
        focus_generation: 1,
        adapter_observed_epoch: 1,
        synchronous_recheck: false,
        virtual_display_uuid: None,
        virtual_backend_generation: None,
    }
}

pub fn sample_virtual_evidence(uuid: [u8; 16], generation: u64) -> TargetIdentityEvidence {
    let mut e = empty_unavailable(BackendKind::VirtualDisplay);
    e.virtual_display_uuid = Some(uuid);
    e.virtual_backend_generation = Some(generation);
    e.physical_display_id = FieldEvidence::available(
        domain_hash(b"cockpit.virtual.display.v1", &[&uuid]),
        EvidenceSource::VirtualEngine,
    );
    e.platform_session_or_seat_id = FieldEvidence::available(
        domain_hash(b"cockpit.virtual.session.v1", &[&generation.to_le_bytes()]),
        EvidenceSource::VirtualEngine,
    );
    e.host_installation_id = FieldEvidence::unavailable(
        TargetUnavailableReason::VirtualDisplayNoPhysicalLease,
        Some(EvidenceSource::VirtualEngine),
    );
    e.focused_window_id = FieldEvidence::available(
        OpaqueWindowId::from_bytes(uuid),
        EvidenceSource::VirtualEngine,
    );
    e.geometry = FieldEvidence::available(
        TargetGeometry {
            x: 0,
            y: 0,
            width: 1280,
            height: 720,
            scale: 1.0,
        },
        EvidenceSource::VirtualEngine,
    );
    e.adapter_observed_epoch = 1;
    e
}
