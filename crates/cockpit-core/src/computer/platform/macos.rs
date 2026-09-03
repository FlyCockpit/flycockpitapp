//! macOS target-evidence pure logic, callback gate, and typed literal tables.
//!
//! Real AppKit/AX/CoreGraphics queries run only on the owned adapter worker
//! (cfg target_os = "macos"). Required tests exercise pure logic and the
//! MacCallbackGate lifecycle without real desktop actions.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};

use crate::computer::host_identity::{HostIdentityRng, domain_hash};

/// Snapshot an authority record before its durable pre-post pending mark.
/// Generic so the rollback state machine is testable on non-macOS builders;
/// the macOS backend supplies its private journal record type.
///
/// This stays in the cross-platform `platform::macos` module (not the
/// macOS-only `macos_backend`) so the pure state machine keeps compiling and
/// testing on non-macOS builders. No other platform backend owns a durable
/// host-input authority journal, so there is no sibling to unify with; the
/// `pub(in crate::computer)` scope is exactly the sibling backend module
/// plus this module's own tests.
pub(in crate::computer) fn begin_known_pre_post<T: Clone>(
    state: &mut T,
    mark_pending: impl FnOnce(&mut T),
) -> T {
    let previous = state.clone();
    mark_pending(state);
    previous
}

/// Restore the byte-for-byte logical authority state captured before prepare.
pub(in crate::computer) fn rollback_known_pre_post<T>(state: &mut T, previous: T) {
    *state = previous;
}

/// Durable held-input ownership is only known when the window that received
/// the downs is recorded with it. A journal that lists keys or buttons and
/// omits that identity cannot be recovered into a window-addressed release.
pub(in crate::computer) fn mac_held_input_identity_is_complete(
    keys: &[u16],
    buttons_held: bool,
    window: Option<[u8; 16]>,
) -> bool {
    (keys.is_empty() && !buttons_held) || window.is_some()
}

#[cfg(target_os = "macos")]
use crate::computer::host_identity::{
    HostInstallationId, RealHostIdentityFs, SysHostIdentityRng, load_or_create_host_installation_id,
};
#[cfg(target_os = "macos")]
use crate::computer::target::{
    BackendKind, EvidenceSource, FieldEvidence, FocusGenerationReducer, RedactedHint,
    StableApplicationId, TargetEvidenceAdapter, TargetGeometry, TargetIdentityEvidence,
    empty_unavailable,
};
use crate::computer::target::{OpaqueWindowId, TargetUnavailableReason};

/// Apple `AU_DEFAUDITSID` — audit session id zero is nondefault-required.
pub const AU_DEFAUDITSID: u32 = 0;

/// Expected `TASK_AUDIT_TOKEN` count (eight u32 values).
pub const TASK_AUDIT_TOKEN_COUNT_EXPECTED: u32 = 8;

/// Index of `au_asid_t` in public `audit_token_t.val[6]`.
pub const AUDIT_TOKEN_ASID_INDEX: usize = 6;

/// Exact typed CGSession keys constructed via `CFString::from_static_str`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CgSessionKey {
    UserId,
    ConsoleSet,
    OnConsole,
    LoginDone,
}

impl CgSessionKey {
    pub const fn as_static_str(self) -> &'static str {
        match self {
            Self::UserId => "kCGSSessionUserIDKey",
            Self::ConsoleSet => "kCGSSessionConsoleSetKey",
            Self::OnConsole => "kCGSSessionOnConsoleKey",
            Self::LoginDone => "kCGSessionLoginDoneKey",
        }
    }

    pub fn all() -> &'static [CgSessionKey] {
        &[
            Self::UserId,
            Self::ConsoleSet,
            Self::OnConsole,
            Self::LoginDone,
        ]
    }
}

/// Exact AX attribute literals.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MacAxAttribute {
    FocusedApplication,
    FocusedWindow,
    FocusedUIElement,
    Role,
    Subrole,
    Title,
    Position,
    Size,
    Windows,
}

impl MacAxAttribute {
    pub const fn as_static_str(self) -> &'static str {
        match self {
            Self::FocusedApplication => "AXFocusedApplication",
            Self::FocusedWindow => "AXFocusedWindow",
            Self::FocusedUIElement => "AXFocusedUIElement",
            Self::Role => "AXRole",
            Self::Subrole => "AXSubrole",
            Self::Title => "AXTitle",
            Self::Position => "AXPosition",
            Self::Size => "AXSize",
            Self::Windows => "AXWindows",
        }
    }

    pub fn all() -> &'static [MacAxAttribute] {
        &[
            Self::FocusedApplication,
            Self::FocusedWindow,
            Self::FocusedUIElement,
            Self::Role,
            Self::Subrole,
            Self::Title,
            Self::Position,
            Self::Size,
            Self::Windows,
        ]
    }
}

/// Exact AX notification literals.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MacAxNotification {
    FocusedWindowChanged,
    Moved,
    Resized,
    TitleChanged,
    UiElementDestroyed,
}

impl MacAxNotification {
    pub const fn as_static_str(self) -> &'static str {
        match self {
            Self::FocusedWindowChanged => "AXFocusedWindowChanged",
            Self::Moved => "AXMoved",
            Self::Resized => "AXResized",
            Self::TitleChanged => "AXTitleChanged",
            Self::UiElementDestroyed => "AXUIElementDestroyed",
        }
    }

    pub fn application_notifications() -> &'static [MacAxNotification] {
        &[Self::FocusedWindowChanged]
    }

    pub fn window_notifications() -> &'static [MacAxNotification] {
        &[
            Self::Moved,
            Self::Resized,
            Self::TitleChanged,
            Self::UiElementDestroyed,
        ]
    }
}

/// AXValue type tags for CGPoint/CGSize.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AxValueTag {
    CgPoint,
    CgSize,
    Other(u32),
}

/// Extract audit-session ID from a typed audit token layout.
///
/// Production uses `mach2::task::task_info(..., TASK_AUDIT_TOKEN, ...)` and
/// copies `audit_token_t.val[6]`. Tests inject status/count/token arrays.
pub fn extract_audit_session_id(
    kern_success: bool,
    returned_count: u32,
    val: &[u32],
) -> Result<u32, MacEvidenceError> {
    if !kern_success {
        return Err(MacEvidenceError::TaskInfoFailure);
    }
    if returned_count != TASK_AUDIT_TOKEN_COUNT_EXPECTED {
        return Err(MacEvidenceError::AuditTokenCountMismatch {
            got: returned_count,
        });
    }
    if val.len() < AUDIT_TOKEN_ASID_INDEX + 1 {
        return Err(MacEvidenceError::AuditTokenLayoutMismatch);
    }
    let asid = val[AUDIT_TOKEN_ASID_INDEX];
    if asid == AU_DEFAUDITSID {
        return Err(MacEvidenceError::DefaultAuditSession);
    }
    Ok(asid)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MacEvidenceError {
    TaskInfoFailure,
    AuditTokenCountMismatch { got: u32 },
    AuditTokenLayoutMismatch,
    DefaultAuditSession,
    SessionKeyMissing(&'static str),
    SessionKeyWrongType(&'static str),
    SessionUidMismatch,
    SessionValueChanged,
    SessionInactive,
    AxValueTagMismatch,
    JoinZeroCandidates,
    JoinMultipleCandidates,
    JoinDestroyedWindow,
    JoinPidOrBoundsChanged,
    JoinWrongTypedField,
    DisplayUnavailable,
    PermissionDenied,
    Stale,
}

/// Decode one CGSession snapshot value (injected).
#[derive(Debug, Clone, PartialEq)]
pub enum CgSessionValue {
    Number(u32),
    Bool(bool),
    Missing,
    WrongType,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CgSessionSnapshot {
    pub user_id: CgSessionValue,
    pub console_set: CgSessionValue,
    pub on_console: CgSessionValue,
    pub login_done: CgSessionValue,
}

pub fn validate_cg_session(
    snap: &CgSessionSnapshot,
    effective_uid: u32,
    previous: Option<&CgSessionSnapshot>,
) -> Result<(u32, u32), MacEvidenceError> {
    let uid = match &snap.user_id {
        CgSessionValue::Number(v) => *v,
        CgSessionValue::Missing => {
            return Err(MacEvidenceError::SessionKeyMissing(
                CgSessionKey::UserId.as_static_str(),
            ));
        }
        _ => {
            return Err(MacEvidenceError::SessionKeyWrongType(
                CgSessionKey::UserId.as_static_str(),
            ));
        }
    };
    if uid != effective_uid {
        return Err(MacEvidenceError::SessionUidMismatch);
    }
    let console_set = match &snap.console_set {
        CgSessionValue::Number(v) => *v,
        CgSessionValue::Missing => {
            return Err(MacEvidenceError::SessionKeyMissing(
                CgSessionKey::ConsoleSet.as_static_str(),
            ));
        }
        _ => {
            return Err(MacEvidenceError::SessionKeyWrongType(
                CgSessionKey::ConsoleSet.as_static_str(),
            ));
        }
    };
    match &snap.on_console {
        CgSessionValue::Bool(true) => {}
        CgSessionValue::Bool(false) => return Err(MacEvidenceError::SessionInactive),
        CgSessionValue::Missing => {
            return Err(MacEvidenceError::SessionKeyMissing(
                CgSessionKey::OnConsole.as_static_str(),
            ));
        }
        _ => {
            return Err(MacEvidenceError::SessionKeyWrongType(
                CgSessionKey::OnConsole.as_static_str(),
            ));
        }
    }
    match &snap.login_done {
        CgSessionValue::Bool(true) => {}
        CgSessionValue::Bool(false) => return Err(MacEvidenceError::SessionInactive),
        CgSessionValue::Missing => {
            return Err(MacEvidenceError::SessionKeyMissing(
                CgSessionKey::LoginDone.as_static_str(),
            ));
        }
        _ => {
            return Err(MacEvidenceError::SessionKeyWrongType(
                CgSessionKey::LoginDone.as_static_str(),
            ));
        }
    }
    if let Some(prev) = previous
        && prev != snap
    {
        return Err(MacEvidenceError::SessionValueChanged);
    }
    Ok((uid, console_set))
}

/// CG window list candidate used for the public AX-to-CG join.
#[derive(Debug, Clone, PartialEq)]
pub struct CgWindowCandidate {
    pub owner_pid: u32,
    pub bounds: (f64, f64, f64, f64),
    pub window_number: u32,
    pub title: Option<String>,
    pub z_order: u32,
    pub destroyed: bool,
    pub wrong_typed_field: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AxWindowRect {
    pub x: f64,
    pub y: f64,
    pub w: f64,
    pub h: f64,
    pub position_tag: AxValueTag,
    pub size_tag: AxValueTag,
}

/// Deterministic public-only AX→CG join. Title/z-order never tie-break.
pub fn join_ax_to_cg_window(
    frontmost_pid: u32,
    ax_rect: &AxWindowRect,
    candidates: &[CgWindowCandidate],
    recheck_pid: u32,
    recheck_ax: &AxWindowRect,
    recheck_frontmost_pid: u32,
) -> Result<u32, MacEvidenceError> {
    if !matches!(ax_rect.position_tag, AxValueTag::CgPoint)
        || !matches!(ax_rect.size_tag, AxValueTag::CgSize)
    {
        return Err(MacEvidenceError::AxValueTagMismatch);
    }
    if frontmost_pid != recheck_pid
        || frontmost_pid != recheck_frontmost_pid
        || ax_rect != recheck_ax
    {
        return Err(MacEvidenceError::JoinPidOrBoundsChanged);
    }

    let mut matches = Vec::new();
    for c in candidates {
        if c.wrong_typed_field {
            return Err(MacEvidenceError::JoinWrongTypedField);
        }
        if c.destroyed {
            continue;
        }
        if c.owner_pid != frontmost_pid {
            continue;
        }
        if c.bounds != (ax_rect.x, ax_rect.y, ax_rect.w, ax_rect.h) {
            continue;
        }
        if c.window_number == 0 {
            continue;
        }
        matches.push(c);
    }

    match matches.len() {
        0 => Err(MacEvidenceError::JoinZeroCandidates),
        1 => Ok(matches[0].window_number),
        _ => Err(MacEvidenceError::JoinMultipleCandidates),
    }
}

/// Display geometry + ColorSync UUID candidate for selection.
pub type DisplayCandidate = (u32, (f64, f64, f64, f64), [u8; 16]);

/// Display selection: greatest bounds intersection; ties choose lowest display id.
pub fn select_display_for_window(
    window: (f64, f64, f64, f64),
    displays: &[DisplayCandidate],
) -> Result<[u8; 16], MacEvidenceError> {
    if displays.is_empty() {
        return Err(MacEvidenceError::DisplayUnavailable);
    }
    let mut best_area = -1.0_f64;
    let mut best_id = u32::MAX;
    let mut best_uuid = [0u8; 16];
    let mut found = false;
    for &(id, bounds, uuid) in displays {
        let area = intersection_area(window, bounds);
        if area <= 0.0 {
            continue;
        }
        if area > best_area || (area == best_area && id < best_id) {
            best_area = area;
            best_id = id;
            best_uuid = uuid;
            found = true;
        }
    }
    if !found {
        return Err(MacEvidenceError::DisplayUnavailable);
    }
    Ok(best_uuid)
}

fn intersection_area(a: (f64, f64, f64, f64), b: (f64, f64, f64, f64)) -> f64 {
    let (ax, ay, aw, ah) = a;
    let (bx, by, bw, bh) = b;
    let x1 = ax.max(bx);
    let y1 = ay.max(by);
    let x2 = (ax + aw).min(bx + bw);
    let y2 = (ay + ah).min(by + bh);
    let w = (x2 - x1).max(0.0);
    let h = (y2 - y1).max(0.0);
    w * h
}

pub fn session_id_from_asid(asid: u32) -> [u8; 32] {
    domain_hash(b"cockpit.macos.session.v1", &[&asid.to_le_bytes()])
}

pub fn display_id_from_uuid_bytes(uuid: [u8; 16]) -> [u8; 32] {
    // Physical key field stores domain-hash of the exact 16 CFUUID bytes so
    // all platforms share a 32-byte display slot; the raw 16 bytes are the
    // authoritative ColorSync evidence before hashing.
    domain_hash(b"cockpit.macos.display.uuid.v1", &[&uuid])
}

/// Length of the planted macOS window-generation token stored beside the
/// recyclable PID/CGWindowID pair. Matches the eight bytes remaining in
/// [`OpaqueWindowId`] after those targeting fields.
pub const MACOS_WINDOW_GENERATION_LEN: usize = 8;

/// Encode the live macOS injection target into the platform-neutral window id.
///
/// PID and CoreGraphics window number occupy the first eight little-endian
/// bytes so the backend can address that process and recheck that window
/// without guessing current focus. The remaining eight bytes are a random
/// generation token planted on the CoreGraphics window object so a recycled
/// PID/window-number pair is a different identity.
pub fn opaque_macos_window_id(
    pid: u32,
    window_number: u32,
    generation: [u8; MACOS_WINDOW_GENERATION_LEN],
) -> OpaqueWindowId {
    let mut bytes = [0_u8; 16];
    bytes[..4].copy_from_slice(&pid.to_le_bytes());
    bytes[4..8].copy_from_slice(&window_number.to_le_bytes());
    bytes[8..].copy_from_slice(&generation);
    OpaqueWindowId::from_bytes(bytes)
}

/// PID and CoreGraphics window number stored by [`opaque_macos_window_id`].
/// `None` when either targeting field is zero so callers refuse rather than
/// post through the session-global HID tap.
pub fn macos_injection_target_from_opaque(id: &OpaqueWindowId) -> Option<(u32, u32)> {
    let (pid, window_number, _) = macos_window_identity_from_opaque(id)?;
    Some((pid, window_number))
}

/// PID, CoreGraphics window number, and planted generation stored by
/// [`opaque_macos_window_id`]. `None` when any field is zero so a recycled
/// pair cannot match without the generation token.
pub fn macos_window_identity_from_opaque(
    id: &OpaqueWindowId,
) -> Option<(u32, u32, [u8; MACOS_WINDOW_GENERATION_LEN])> {
    let bytes = id.as_bytes();
    let pid = u32::from_le_bytes(bytes[..4].try_into().ok()?);
    let window_number = u32::from_le_bytes(bytes[4..8].try_into().ok()?);
    let mut generation = [0_u8; MACOS_WINDOW_GENERATION_LEN];
    generation.copy_from_slice(&bytes[8..]);
    if pid == 0 || window_number == 0 || macos_generation_is_zero(&generation) {
        return None;
    }
    Some((pid, window_number, generation))
}

fn macos_generation_is_zero(generation: &[u8; MACOS_WINDOW_GENERATION_LEN]) -> bool {
    generation.iter().all(|byte| *byte == 0)
}

/// Live window observed during crash recovery. The planted generation is the
/// durable object identity; PID and window number are recyclable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacosLiveWindowCandidate {
    pub pid: u32,
    pub window_number: u32,
    pub planted_generation: Option<[u8; MACOS_WINDOW_GENERATION_LEN]>,
}

/// Authenticate a journaled macOS window identity against live candidates.
///
/// A recycled PID/window-number pair is the evidenced object only when the
/// planted generation still matches. Missing or different tokens fail closed.
/// This is the production crash-recovery decision used by
/// `restore_macos_injection_target`.
pub fn restore_macos_window_object(
    journal: &OpaqueWindowId,
    candidates: &[MacosLiveWindowCandidate],
) -> Result<usize, TargetUnavailableReason> {
    let (pid, window_number, generation) =
        macos_window_identity_from_opaque(journal).ok_or(TargetUnavailableReason::QueryMismatch)?;
    let mut indexes = Vec::new();
    let mut pair_seen = false;
    for (index, candidate) in candidates.iter().enumerate() {
        if candidate.pid != pid || candidate.window_number != window_number {
            continue;
        }
        pair_seen = true;
        if candidate.planted_generation.as_ref() == Some(&generation) {
            indexes.push(index);
        }
    }
    match indexes.len() {
        1 => Ok(indexes[0]),
        0 if pair_seen => Err(TargetUnavailableReason::StaleTarget),
        0 => Err(TargetUnavailableReason::FocusIdentityUnavailable),
        _ => Err(TargetUnavailableReason::AmbiguousOutput),
    }
}

/// Persistence for the generation token planted on a CoreGraphics window.
pub trait MacosWindowGenerationStore {
    fn read(
        &self,
        window_number: u32,
    ) -> Result<Option<[u8; MACOS_WINDOW_GENERATION_LEN]>, TargetUnavailableReason>;
    fn plant(
        &self,
        window_number: u32,
        generation: [u8; MACOS_WINDOW_GENERATION_LEN],
    ) -> Result<(), TargetUnavailableReason>;
}

/// Read the planted generation, or plant a random token once.
///
/// An existing token is never overwritten. A replacement window that reuses a
/// PID/window-number pair starts empty and receives a new random token, so a
/// restarted adapter cannot authenticate the recycled pair with the crashed
/// process's journal.
pub fn read_or_plant_macos_window_generation<R, S>(
    store: &S,
    rng: &mut R,
    window_number: u32,
) -> Result<[u8; MACOS_WINDOW_GENERATION_LEN], TargetUnavailableReason>
where
    R: HostIdentityRng,
    S: MacosWindowGenerationStore,
{
    if window_number == 0 {
        return Err(TargetUnavailableReason::FocusIdentityUnavailable);
    }
    if let Some(existing) = store.read(window_number)? {
        if !macos_generation_is_zero(&existing) {
            return Ok(existing);
        }
    }
    let mut generation = [0_u8; MACOS_WINDOW_GENERATION_LEN];
    rng.try_fill_bytes(&mut generation)
        .map_err(|_| TargetUnavailableReason::MissingCapability)?;
    if macos_generation_is_zero(&generation) {
        return Err(TargetUnavailableReason::MissingCapability);
    }
    store.plant(window_number, generation)?;
    let live = store
        .read(window_number)?
        .ok_or(TargetUnavailableReason::QueryMismatch)?;
    if live != generation {
        return Err(TargetUnavailableReason::QueryMismatch);
    }
    Ok(generation)
}

/// Irreversible macOS delivery addressed to a retained AX window object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacosAxDeliveryError {
    StaleTarget,
    QueryMismatch,
    MissingWindowLocationSetter,
    AmbiguousDelivery,
}

/// Host for AX-object delivery. The irreversible post is
/// [`MacosAxWindowDelivery::post_to_held_ax`]; PID and window number are not
/// operands of that call.
pub trait MacosAxWindowDelivery {
    fn ax_is_live(&self) -> bool;
    fn resolve_from_ax(
        &self,
    ) -> Result<(u32, u32, [u8; MACOS_WINDOW_GENERATION_LEN], (f64, f64)), MacosAxDeliveryError>;
    fn window_location_setter_available(&self) -> bool;
    fn post_to_held_ax(&mut self) -> Result<(), MacosAxDeliveryError>;
}

/// Authenticate the retained AX window, then post to that held object.
///
/// A missing window-local location setter fails closed: process-directed
/// posting without it cannot bind the event to the authenticated window.
/// A recycled PID/window-number pair fails `resolve_from_ax` because the
/// planted generation does not match.
pub fn deliver_to_authenticated_ax_window<H: MacosAxWindowDelivery>(
    host: &mut H,
    expected: OpaqueWindowId,
) -> Result<(), MacosAxDeliveryError> {
    if !host.ax_is_live() {
        return Err(MacosAxDeliveryError::StaleTarget);
    }
    if !host.window_location_setter_available() {
        return Err(MacosAxDeliveryError::MissingWindowLocationSetter);
    }
    let expected_id =
        macos_window_identity_from_opaque(&expected).ok_or(MacosAxDeliveryError::QueryMismatch)?;
    let (pid, window_number, generation, _origin) = host.resolve_from_ax()?;
    if (pid, window_number, generation) != expected_id {
        return Err(MacosAxDeliveryError::StaleTarget);
    }
    host.post_to_held_ax()?;
    if !host.ax_is_live() {
        return Ok(());
    }
    match host.resolve_from_ax() {
        Ok((live_pid, live_window, live_generation, _))
            if (live_pid, live_window, live_generation) == expected_id =>
        {
            Ok(())
        }
        _ => Err(MacosAxDeliveryError::AmbiguousDelivery),
    }
}

/// Live focused-window targeting fields observed independently of the
/// adapter's AX lifetime epoch. The backend uses these to bind and recheck
/// injection; coordinator identity still compares the full opaque id.
#[cfg(target_os = "macos")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MacLiveFocusedWindow {
    pub pid: u32,
    pub window_number: u32,
}

/// Pure-logic facade used by table tests (injected OS answers).
#[derive(Debug, Default)]
pub struct MacOsEvidenceLogic;

// --- Callback gate and lifecycle (AC7) ------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacProducerKind {
    NsWorkspaceActivate,
    NsWorkspaceSessionBecameActive,
    NsWorkspaceSessionResignedActive,
    AxFocusedWindowChanged,
    AxMoved,
    AxResized,
    AxTitleChanged,
    AxDestroyed,
    CgDisplayReconfiguration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MacNativeEvent {
    Producer {
        kind: MacProducerKind,
        lifecycle_generation: u64,
    },
    Shutdown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MacCallbackTerminalReason {
    QueueFull,
    QueueClosed,
    InFlightOverflow,
    CallbackPanic,
    NormalWakeHardFailure,
    TerminalWakeHardFailure,
    ReceiverEof,
}

const EVENT_QUEUE_CAPACITY: usize = 64;

struct GateInner {
    accepting_callbacks: bool,
    in_flight: u64,
    lifecycle_generation: u64,
    events: VecDeque<MacNativeEvent>,
    closed: bool,
    terminal_failure: Option<MacCallbackTerminalReason>,
    terminal_latched: bool,
    /// Tracks reverse teardown order for tests.
    teardown_steps: Vec<&'static str>,
    registered: RegisteredSources,
    descriptor_in_producer_accounting: bool,
}

#[derive(Debug, Clone, Default)]
struct RegisteredSources {
    ns_workspace_tokens: usize,
    ax_app_notifications: usize,
    ax_window_notifications: usize,
    ax_run_loop_source: bool,
    cg_display_callback: bool,
    normal_descriptor: bool,
    terminal_descriptor: bool,
    normal_source: bool,
    terminal_source: bool,
}

/// Ref-counted producer gate: acceptance, generation, in-flight, terminal latch.
#[derive(Clone)]
pub struct MacCallbackGate {
    inner: Arc<(Mutex<GateInner>, Condvar)>,
    /// Independent terminal-failure wake coalescing.
    terminal_wake_pending: Arc<AtomicBool>,
    normal_wake_pending: Arc<AtomicBool>,
    /// Coordinator-visible terminal latch (exactly-once).
    terminal_reason: Arc<Mutex<Option<MacCallbackTerminalReason>>>,
    producer_enter_count: Arc<AtomicU64>,
    producer_reject_count: Arc<AtomicU64>,
}

impl MacCallbackGate {
    pub fn new() -> Self {
        Self {
            inner: Arc::new((
                Mutex::new(GateInner {
                    accepting_callbacks: false,
                    in_flight: 0,
                    lifecycle_generation: 1,
                    events: VecDeque::new(),
                    closed: false,
                    terminal_failure: None,
                    terminal_latched: false,
                    teardown_steps: Vec::new(),
                    registered: RegisteredSources::default(),
                    descriptor_in_producer_accounting: false,
                }),
                Condvar::new(),
            )),
            terminal_wake_pending: Arc::new(AtomicBool::new(false)),
            normal_wake_pending: Arc::new(AtomicBool::new(false)),
            terminal_reason: Arc::new(Mutex::new(None)),
            producer_enter_count: Arc::new(AtomicU64::new(0)),
            producer_reject_count: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn mark_ready_full_registration(&self) {
        let mut g = self.inner.0.lock().unwrap();
        g.registered.ns_workspace_tokens = 3;
        g.registered.ax_app_notifications = 1;
        g.registered.ax_window_notifications = 4;
        g.registered.ax_run_loop_source = true;
        g.registered.cg_display_callback = true;
        g.registered.normal_descriptor = true;
        g.registered.terminal_descriptor = true;
        g.registered.normal_source = true;
        g.registered.terminal_source = true;
        g.accepting_callbacks = true;
    }

    pub fn mark_ready_ax_denied(&self) {
        let mut g = self.inner.0.lock().unwrap();
        g.registered.ns_workspace_tokens = 3;
        g.registered.ax_app_notifications = 0;
        g.registered.ax_window_notifications = 0;
        g.registered.ax_run_loop_source = false;
        g.registered.cg_display_callback = true;
        g.registered.normal_descriptor = true;
        g.registered.terminal_descriptor = true;
        g.registered.normal_source = true;
        g.registered.terminal_source = true;
        g.accepting_callbacks = true;
    }

    pub fn is_ready(&self) -> bool {
        let g = self.inner.0.lock().unwrap();
        g.registered.normal_descriptor
            && g.registered.terminal_descriptor
            && g.registered.normal_source
            && g.registered.terminal_source
            && g.registered.ns_workspace_tokens == 3
            && g.registered.cg_display_callback
            && (g.registered.ax_run_loop_source
                || (g.registered.ax_app_notifications == 0
                    && g.registered.ax_window_notifications == 0))
            && g.accepting_callbacks
    }

    pub fn registration_snapshot(&self) -> (usize, usize, usize, bool, bool) {
        let g = self.inner.0.lock().unwrap();
        (
            g.registered.ns_workspace_tokens,
            g.registered.ax_app_notifications,
            g.registered.ax_window_notifications,
            g.registered.ax_run_loop_source,
            g.registered.cg_display_callback,
        )
    }

    /// Producer enter — increments in_flight before reading accepting_callbacks.
    pub fn producer_enter(&self, kind: MacProducerKind) -> Option<ProducerEnterGuard> {
        let mut g = self.inner.0.lock().unwrap();
        // Checked in_flight increment before acceptance read.
        let next = match g.in_flight.checked_add(1) {
            Some(v) => v,
            None => {
                self.latch_terminal_locked(&mut g, MacCallbackTerminalReason::InFlightOverflow);
                return None;
            }
        };
        g.in_flight = next;
        self.producer_enter_count.fetch_add(1, Ordering::SeqCst);

        if !g.accepting_callbacks || g.closed {
            // Counted but enqueues nothing.
            self.producer_reject_count.fetch_add(1, Ordering::SeqCst);
            return Some(ProducerEnterGuard {
                gate: self.clone(),
                lifecycle_generation: 0,
                kind,
                accepted: false,
            });
        }
        let life_gen = g.lifecycle_generation;
        Some(ProducerEnterGuard {
            gate: self.clone(),
            lifecycle_generation: life_gen,
            kind,
            accepted: true,
        })
    }

    fn producer_leave(&self) {
        let mut g = self.inner.0.lock().unwrap();
        g.in_flight = g.in_flight.saturating_sub(1);
        self.inner.1.notify_all();
    }

    /// Returns `false` when the queue is closed or full (terminal latch set).
    pub fn enqueue_from_producer(&self, kind: MacProducerKind, lifecycle_generation: u64) -> bool {
        let mut g = self.inner.0.lock().unwrap();
        if g.closed {
            self.latch_terminal_locked(&mut g, MacCallbackTerminalReason::QueueClosed);
            return false;
        }
        if g.events.len() >= EVENT_QUEUE_CAPACITY {
            self.latch_terminal_locked(&mut g, MacCallbackTerminalReason::QueueFull);
            return false;
        }
        // Reject stale lifecycle generation.
        if lifecycle_generation != g.lifecycle_generation {
            return true;
        }
        g.events.push_back(MacNativeEvent::Producer {
            kind,
            lifecycle_generation,
        });
        self.normal_wake_write(false);
        true
    }

    pub fn simulate_producer_panic(&self) {
        let mut g = self.inner.0.lock().unwrap();
        self.latch_terminal_locked(&mut g, MacCallbackTerminalReason::CallbackPanic);
    }

    pub fn simulate_normal_wake_hard_failure(&self) {
        let mut g = self.inner.0.lock().unwrap();
        self.latch_terminal_locked(&mut g, MacCallbackTerminalReason::NormalWakeHardFailure);
    }

    pub fn simulate_terminal_wake_hard_failure(&self) {
        // Hard terminal-wake error closes both endpoints (modeled as latch).
        let mut g = self.inner.0.lock().unwrap();
        self.latch_terminal_locked(&mut g, MacCallbackTerminalReason::TerminalWakeHardFailure);
    }

    pub fn simulate_receiver_eof(&self) {
        let mut g = self.inner.0.lock().unwrap();
        self.latch_terminal_locked(&mut g, MacCallbackTerminalReason::ReceiverEof);
    }

    fn latch_terminal_locked(&self, g: &mut GateInner, reason: MacCallbackTerminalReason) {
        if g.terminal_latched {
            return;
        }
        g.terminal_latched = true;
        g.terminal_failure = Some(reason.clone());
        g.accepting_callbacks = false;
        *self.terminal_reason.lock().unwrap() = Some(reason);
        // Winner writes one byte to independent terminal-wake stream.
        let _ = self.terminal_wake_pending.compare_exchange(
            false,
            true,
            Ordering::SeqCst,
            Ordering::SeqCst,
        );
    }

    /// WouldBlock on wake is success (earlier byte already readable).
    pub fn normal_wake_write(&self, hard_fail: bool) {
        if hard_fail {
            self.simulate_normal_wake_hard_failure();
            return;
        }
        // Coalesce: second write is WouldBlock-equivalent success.
        let _ = self.normal_wake_pending.compare_exchange(
            false,
            true,
            Ordering::SeqCst,
            Ordering::SeqCst,
        );
    }

    pub fn drain_normal_wake(&self) -> bool {
        self.normal_wake_pending.swap(false, Ordering::SeqCst)
    }

    pub fn drain_terminal_wake(&self) -> bool {
        self.terminal_wake_pending.swap(false, Ordering::SeqCst)
    }

    /// Descriptor callbacks never enter producer in-flight accounting.
    pub fn descriptor_callback_drain(&self) -> Vec<MacNativeEvent> {
        let mut g = self.inner.0.lock().unwrap();
        // Explicitly excluded from producer accounting.
        debug_assert!(!g.descriptor_in_producer_accounting);
        let mut out = Vec::new();
        while let Some(ev) = g.events.pop_front() {
            out.push(ev);
        }
        // Consume terminal latch into worker state once.
        if let Some(reason) = g.terminal_failure.take() {
            g.accepting_callbacks = false;
            let _ = reason;
        }
        out
    }

    pub fn observe_terminal(&self) -> Option<MacCallbackTerminalReason> {
        self.terminal_reason.lock().unwrap().clone()
    }

    pub fn in_flight(&self) -> u64 {
        self.inner.0.lock().unwrap().in_flight
    }

    pub fn producer_enter_count(&self) -> u64 {
        self.producer_enter_count.load(Ordering::SeqCst)
    }

    pub fn producer_reject_count(&self) -> u64 {
        self.producer_reject_count.load(Ordering::SeqCst)
    }

    /// Begin shutdown: clear accepting before enqueueing shutdown command.
    pub fn begin_shutdown(&self) {
        let mut g = self.inner.0.lock().unwrap();
        g.accepting_callbacks = false;
        g.events.push_back(MacNativeEvent::Shutdown);
        drop(g);
        self.normal_wake_write(false);
    }

    /// Exact reverse-registration teardown after producer quiescence.
    pub fn run_teardown(&self) -> Vec<&'static str> {
        let mut g = self.inner.0.lock().unwrap();
        g.accepting_callbacks = false;

        // Reverse: CG, AX window notifs, AX app, AX source, NSWorkspace tokens.
        if g.registered.cg_display_callback {
            g.teardown_steps.push("remove_cg_display_callback");
            g.registered.cg_display_callback = false;
        }
        while g.registered.ax_window_notifications > 0 {
            g.teardown_steps.push("remove_ax_window_notification");
            g.registered.ax_window_notifications -= 1;
        }
        if g.registered.ax_app_notifications > 0 {
            g.teardown_steps.push("remove_ax_app_notification");
            g.registered.ax_app_notifications = 0;
        }
        if g.registered.ax_run_loop_source {
            g.teardown_steps.push("remove_ax_run_loop_source");
            g.registered.ax_run_loop_source = false;
        }
        while g.registered.ns_workspace_tokens > 0 {
            g.teardown_steps.push("remove_ns_workspace_token");
            g.registered.ns_workspace_tokens -= 1;
        }

        // Wait until producer in_flight == 0 (without holding event queue for tests:
        // we already hold the mutex; condition wait pattern).
        while g.in_flight > 0 {
            g = self.inner.1.wait(g).unwrap();
        }
        g.teardown_steps.push("quiesce_producers");

        // Drain pre-boundary events + terminal latch.
        g.events.clear();
        g.terminal_failure = None;
        g.teardown_steps.push("drain_events");

        // Reverse dual-descriptor disable/source-remove/invalidate/stop.
        if g.registered.terminal_source {
            g.teardown_steps.push("disable_terminal_descriptor");
            g.registered.terminal_source = false;
        }
        if g.registered.normal_source {
            g.teardown_steps.push("disable_normal_descriptor");
            g.registered.normal_source = false;
        }
        if g.registered.terminal_descriptor {
            g.teardown_steps.push("remove_terminal_source");
            g.registered.terminal_descriptor = false;
        }
        if g.registered.normal_descriptor {
            g.teardown_steps.push("remove_normal_source");
            g.registered.normal_descriptor = false;
        }
        g.teardown_steps.push("invalidate_descriptors");
        g.teardown_steps.push("cf_run_loop_stop");
        g.teardown_steps.push("drop_contexts_streams");
        g.teardown_steps.push("acknowledge_shutdown");
        g.closed = true;
        g.lifecycle_generation = g.lifecycle_generation.saturating_add(1);
        g.teardown_steps.clone()
    }

    pub fn teardown_steps(&self) -> Vec<&'static str> {
        self.inner.0.lock().unwrap().teardown_steps.clone()
    }

    pub fn is_closed(&self) -> bool {
        self.inner.0.lock().unwrap().closed
    }

    pub fn bump_lifecycle_generation(&self) {
        let mut g = self.inner.0.lock().unwrap();
        g.lifecycle_generation = g.lifecycle_generation.saturating_add(1);
    }

    pub fn lifecycle_generation(&self) -> u64 {
        self.inner.0.lock().unwrap().lifecycle_generation
    }
}

impl Default for MacCallbackGate {
    fn default() -> Self {
        Self::new()
    }
}

pub struct ProducerEnterGuard {
    gate: MacCallbackGate,
    pub lifecycle_generation: u64,
    pub kind: MacProducerKind,
    pub accepted: bool,
}

impl ProducerEnterGuard {
    /// Enqueues the producer event. Returns `false` if the gate rejected it.
    pub fn enqueue(self) -> bool {
        if !self.accepted {
            return true;
        }
        self.gate
            .enqueue_from_producer(self.kind, self.lifecycle_generation)
    }
}

impl Drop for ProducerEnterGuard {
    fn drop(&mut self) {
        self.gate.producer_leave();
    }
}

/// Observed-epoch counter for named macOS native events.
#[derive(Debug, Default)]
pub struct MacObservedEpoch {
    pub epoch: u64,
    pub unavailable: bool,
}

impl MacObservedEpoch {
    pub fn consume(&mut self, _kind: MacProducerKind) -> Result<u64, MacEvidenceError> {
        if self.unavailable {
            return Err(MacEvidenceError::Stale);
        }
        match self.epoch.checked_add(1) {
            Some(v) => {
                self.epoch = v;
                Ok(v)
            }
            None => {
                self.unavailable = true;
                Err(MacEvidenceError::Stale)
            }
        }
    }
}

// --- Production adapter ---------------------------------------------------

/// Retained AX lifetime witness for the focused window.
///
/// The one piece of adapter state that is not plain data: a retained
/// accessibility object held between snapshots so `CFEqual` can prove live
/// window identity. AX window numbers, CoreGraphics window numbers, and PIDs
/// are all recyclable, so this object — unlike every other AX/AppKit/
/// CoreGraphics handle, which `capture_snapshot` acquires fresh on the
/// calling thread — must persist across calls and cannot be re-acquired.
///
/// The witness API is deliberately restricted to thread-safe CF operations:
/// object-identity comparison and the atomic `CFRetain`/`CFRelease` of the
/// retained pointer. Accessibility messaging is never routed through it;
/// the input backend's liveness check uses [`ax_window_element_is_live`] on
/// the inner element from the dispatch thread.
#[cfg(target_os = "macos")]
#[derive(Clone)]
pub(crate) struct MacFocusedWindowWitness(
    objc2_core_foundation::CFRetained<objc2_application_services::AXUIElement>,
);

#[cfg(target_os = "macos")]
impl MacFocusedWindowWitness {
    fn new(
        element: objc2_core_foundation::CFRetained<objc2_application_services::AXUIElement>,
    ) -> Self {
        Self(element)
    }

    /// `CFEqual` object-identity comparison against a freshly acquired AX
    /// element. This is AX's object identity, not a comparison of window
    /// bounds or recyclable window numbers.
    pub(crate) fn same_element(&self, element: &objc2_application_services::AXUIElement) -> bool {
        objc2_core_foundation::CFEqual(Some(self.0.as_ref()), Some(element))
    }

    pub(crate) fn element(&self) -> &objc2_application_services::AXUIElement {
        &self.0
    }
}

// SAFETY: `AXUIElementRef` is an immutable CoreFoundation object, and this
// witness only performs thread-safe CF operations on it: `CFEqual` identity
// comparison plus the atomic `CFRetain`/`CFRelease` of the retained pointer
// (the same basis on which objc2-core-foundation itself implements
// `Send`/`Sync` for `CFRetained<T>` once `T` is `Send + Sync`). Accessibility
// messaging (`AXUIElementCopyAttributeValue` and friends) is never sent
// through the witness — every AX query inside `capture_snapshot` acquires a
// fresh element on the calling thread — so no AX run-loop or main-thread
// affinity crosses these impls.
#[cfg(target_os = "macos")]
unsafe impl Send for MacFocusedWindowWitness {}
#[cfg(target_os = "macos")]
unsafe impl Sync for MacFocusedWindowWitness {}

#[cfg(target_os = "macos")]
impl std::fmt::Debug for MacFocusedWindowWitness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MacFocusedWindowWitness(<retained AXUIElement>)")
    }
}

/// Synchronous macOS AX/AppKit/CoreGraphics evidence adapter.
///
/// Native references are created and consumed inside `capture_snapshot`; no
/// AppKit, AX, or CoreFoundation object crosses the platform-neutral trait.
#[cfg(target_os = "macos")]
#[derive(Debug)]
pub struct MacOsTargetEvidenceAdapter {
    host: HostInstallationId,
    reducer: FocusGenerationReducer,
    observed_epoch: u64,
    /// Retained AX element for the currently observed focused window. AX
    /// window and CoreGraphics numbers are recyclable; this retained live AX
    /// object is the lifetime witness that distinguishes a replacement from
    /// the prior object even when those numeric IDs are identical. Held as
    /// [`MacFocusedWindowWitness`], the sole sanctioned cross-thread shape
    /// for a retained AX element (thread-safe CF operations only).
    focused_window_lifetime: Option<MacFocusedWindowWitness>,
}

#[cfg(target_os = "macos")]
impl MacOsTargetEvidenceAdapter {
    pub fn new() -> Result<Self, TargetUnavailableReason> {
        // SAFETY: This is a read-only TCC preflight and does not request or
        // mutate system permission state.
        if !unsafe { objc2_application_services::AXIsProcessTrusted() } {
            return Err(TargetUnavailableReason::PermissionDenied);
        }
        let data_dir = crate::config::resolve::cockpit_data_dir()
            .map_err(|_| TargetUnavailableReason::HostIdentityUnavailable)?;
        let host = load_or_create_host_installation_id(
            &data_dir,
            &mut SysHostIdentityRng,
            &mut RealHostIdentityFs,
        )
        .map_err(|_| TargetUnavailableReason::HostIdentityUnavailable)?;
        Ok(Self {
            host,
            reducer: FocusGenerationReducer::new(),
            observed_epoch: 0,
            focused_window_lifetime: None,
        })
    }

    fn capture_macos_snapshot(
        &mut self,
    ) -> Result<TargetIdentityEvidence, TargetUnavailableReason> {
        use objc2_app_kit::NSWorkspace;
        use objc2_application_services::AXUIElement;
        use objc2_core_graphics::{
            CGDisplayBounds, CGDisplayCopyDisplayMode, CGDisplayMode, CGError,
            CGGetActiveDisplayList, CGMainDisplayID,
        };

        let session = current_audit_session_id()?;
        // CGEvent is host-wide, so the process's non-default audit session is
        // not sufficient proof that it owns the displayed desktop. Capture a
        // typed CGSession snapshot before querying focus and require the same
        // active console session after the complete evidence bracket.
        let login_session = current_active_login_session()?;
        let workspace = NSWorkspace::sharedWorkspace();
        let frontmost = workspace
            .frontmostApplication()
            .ok_or(TargetUnavailableReason::FocusIdentityUnavailable)?;
        let frontmost_pid = u32::try_from(frontmost.processIdentifier())
            .map_err(|_| TargetUnavailableReason::FocusIdentityUnavailable)?;

        // SAFETY: AX returns retained CF objects. `ax_attribute` validates the
        // status and takes ownership of each +1 result before downcasting.
        let system = unsafe { AXUIElement::new_system_wide() };
        let application = ax_attribute(&system, MacAxAttribute::FocusedApplication)?
            .downcast::<AXUIElement>()
            .map_err(|_| TargetUnavailableReason::QueryMismatch)?;
        let mut ax_pid: libc::pid_t = 0;
        let pid_status = unsafe { application.pid(std::ptr::NonNull::from(&mut ax_pid)) };
        if pid_status != objc2_application_services::AXError::Success
            || u32::try_from(ax_pid).ok() != Some(frontmost_pid)
        {
            return Err(TargetUnavailableReason::QueryMismatch);
        }
        let window = ax_attribute(&application, MacAxAttribute::FocusedWindow)?
            .downcast::<AXUIElement>()
            .map_err(|_| TargetUnavailableReason::QueryMismatch)?;

        // `CFEqual` is AX's object-identity comparison, not a comparison of
        // window bounds or the recyclable CGWindowID. Keep the prior object
        // retained across snapshots: a destroyed AX element and a replacement
        // that happens to receive the same PID/window number compare unequal.
        // Durable identity is the generation token planted on the CoreGraphics
        // window object (read-or-plant, never overwritten).
        let same_live_window = self
            .focused_window_lifetime
            .as_ref()
            .is_some_and(|witness| witness.same_element(&window));
        if !same_live_window {
            self.focused_window_lifetime = Some(MacFocusedWindowWitness::new(window.clone()));
        }

        let (position, size) = ax_window_rect(&window)?;
        let window_number = cg_window_number_for_ax_window(frontmost_pid, position, size)?;

        let mut displays = [0_u32; 32];
        let mut display_count = 0_u32;
        // SAFETY: `displays` has exactly the advertised capacity and
        // `display_count` is a valid writable out pointer.
        let display_status = unsafe {
            CGGetActiveDisplayList(
                displays.len() as u32,
                displays.as_mut_ptr(),
                &mut display_count,
            )
        };
        if display_status != CGError::Success || display_count == 0 {
            return Err(TargetUnavailableReason::MissingCapability);
        }
        let display_count = usize::try_from(display_count)
            .ok()
            .filter(|count| *count <= displays.len())
            .ok_or(TargetUnavailableReason::QueryMismatch)?;
        let window_rect = (position.x, position.y, size.width, size.height);
        let mut selected = None;
        for display in &displays[..display_count] {
            let bounds = CGDisplayBounds(*display);
            let area = intersection_area(
                window_rect,
                (
                    bounds.origin.x,
                    bounds.origin.y,
                    bounds.size.width,
                    bounds.size.height,
                ),
            );
            match selected {
                None if area > 0.0 => selected = Some((*display, bounds, area)),
                Some((best_id, _, best_area))
                    if area > best_area || (area == best_area && *display < best_id) =>
                {
                    selected = Some((*display, bounds, area));
                }
                _ => {}
            }
        }
        let (display_id, display_bounds, _) =
            selected.ok_or(TargetUnavailableReason::AmbiguousOutput)?;
        // The backend currently captures and maps coordinates against the main
        // display only. Never attach secondary-display evidence to that
        // surface: fail the physical open closed until a display-bound backend
        // is composed with the adapter.
        if display_id != CGMainDisplayID() {
            return Err(TargetUnavailableReason::AmbiguousOutput);
        }
        let mode = CGDisplayCopyDisplayMode(display_id)
            .ok_or(TargetUnavailableReason::MissingCapability)?;
        let logical_width = CGDisplayMode::width(Some(&mode));
        let physical_width = CGDisplayMode::pixel_width(Some(&mode));
        if logical_width == 0 || physical_width == 0 {
            return Err(TargetUnavailableReason::QueryMismatch);
        }
        let scale = physical_width as f64 / logical_width as f64;
        if !scale.is_finite() || scale <= 0.0 {
            return Err(TargetUnavailableReason::QueryMismatch);
        }
        // SAFETY: ColorSync documents a non-null retained UUID for a valid
        // active display ID. objc2 represents that audited contract directly.
        let display_uuid =
            unsafe { objc2_color_sync::CGDisplayCreateUUIDFromDisplayID(display_id) };
        let display_uuid_bytes: [u8; 16] = display_uuid.uuid_bytes().into();

        let title = ax_optional_string(&window, MacAxAttribute::Title);
        // Widget/field identity for risk classification (issue #290): the
        // focused UI element, never the focused window. A missing focused
        // control leaves these unavailable so TypeText fail-closes as
        // Credential rather than treating AXWindow as a text field.
        let focused_widget = match ax_attribute(&application, MacAxAttribute::FocusedUIElement) {
            Ok(value) => value.downcast::<AXUIElement>().ok(),
            Err(TargetUnavailableReason::PermissionDenied) => {
                return Err(TargetUnavailableReason::PermissionDenied);
            }
            Err(_) => None,
        };
        let widget_role = focused_widget
            .as_ref()
            .and_then(|element| ax_optional_string(element, MacAxAttribute::Role));
        let widget_subrole = focused_widget
            .as_ref()
            .and_then(|element| ax_optional_string(element, MacAxAttribute::Subrole));
        let bundle_id = frontmost.bundleIdentifier().map(|value| value.to_string());
        let app_name = frontmost.localizedName().map(|value| value.to_string());

        // Recheck both independently observed focus authorities after all
        // component queries to close the synchronous evidence bracket.
        let recheck_frontmost_pid = workspace
            .frontmostApplication()
            .and_then(|app| u32::try_from(app.processIdentifier()).ok());
        let recheck_application = ax_attribute(&system, MacAxAttribute::FocusedApplication)?
            .downcast::<AXUIElement>()
            .map_err(|_| TargetUnavailableReason::QueryMismatch)?;
        let mut recheck_ax_pid: libc::pid_t = 0;
        let recheck_status =
            unsafe { recheck_application.pid(std::ptr::NonNull::from(&mut recheck_ax_pid)) };
        if recheck_status != objc2_application_services::AXError::Success
            || recheck_frontmost_pid != Some(frontmost_pid)
            || u32::try_from(recheck_ax_pid).ok() != Some(frontmost_pid)
        {
            return Err(TargetUnavailableReason::StaleTarget);
        }
        let recheck_window = ax_attribute(&recheck_application, MacAxAttribute::FocusedWindow)?
            .downcast::<AXUIElement>()
            .map_err(|_| TargetUnavailableReason::QueryMismatch)?;
        // The numeric CoreGraphics window number and AX geometry below can be
        // recycled after the original window is destroyed. Recheck the live
        // AX object against the retained lifetime witness before accepting
        // those observable fields, otherwise a same-PID replacement could
        // inherit the original window's epoch during this synchronous bracket.
        let recheck_same_lifetime = self
            .focused_window_lifetime
            .as_ref()
            .is_some_and(|witness| witness.same_element(&recheck_window));
        if !recheck_same_lifetime {
            return Err(TargetUnavailableReason::StaleTarget);
        }
        let (recheck_position, recheck_size) = ax_window_rect(&recheck_window)?;
        let recheck_window_number =
            cg_window_number_for_ax_window(frontmost_pid, recheck_position, recheck_size)?;
        if recheck_position != position
            || recheck_size != size
            || recheck_window_number != window_number
        {
            return Err(TargetUnavailableReason::StaleTarget);
        }
        let recheck_widget =
            match ax_attribute(&recheck_application, MacAxAttribute::FocusedUIElement) {
                Ok(value) => value.downcast::<AXUIElement>().ok(),
                Err(TargetUnavailableReason::PermissionDenied) => {
                    return Err(TargetUnavailableReason::PermissionDenied);
                }
                Err(_) => None,
            };
        let recheck_widget_role = recheck_widget
            .as_ref()
            .and_then(|element| ax_optional_string(element, MacAxAttribute::Role));
        let recheck_widget_subrole = recheck_widget
            .as_ref()
            .and_then(|element| ax_optional_string(element, MacAxAttribute::Subrole));
        if recheck_widget_role != widget_role || recheck_widget_subrole != widget_subrole {
            return Err(TargetUnavailableReason::StaleTarget);
        }

        let mut snapshot = empty_unavailable(BackendKind::RealDesktopMacOs);
        snapshot.host_installation_id =
            FieldEvidence::available(self.host, EvidenceSource::MachAuditToken);
        snapshot.platform_session_or_seat_id = FieldEvidence::available(
            session_id_from_asid(session),
            EvidenceSource::MachAuditToken,
        );
        snapshot.physical_display_id = FieldEvidence::available(
            display_id_from_uuid_bytes(display_uuid_bytes),
            EvidenceSource::ColorSyncDisplayUuid,
        );
        let generation = read_or_plant_macos_window_generation(
            &LiveMacosWindowGenerationStore,
            &mut SysHostIdentityRng,
            window_number,
        )?;
        snapshot.focused_window_id = FieldEvidence::available(
            opaque_macos_window_id(frontmost_pid, window_number, generation),
            EvidenceSource::CgWindowList,
        );
        snapshot.process_id =
            FieldEvidence::available(frontmost_pid, EvidenceSource::AppKitWorkspace);
        snapshot.stable_application_id = bundle_id.map_or_else(
            || {
                FieldEvidence::unavailable(
                    TargetUnavailableReason::PartialEvidence,
                    Some(EvidenceSource::AppKitWorkspace),
                )
            },
            |value| {
                FieldEvidence::available(
                    StableApplicationId {
                        kind: "macos.bundle_id",
                        value,
                    },
                    EvidenceSource::AppKitWorkspace,
                )
            },
        );
        // TODO(issue #188 follow-up): semantic accessibility-driven
        // perception remains deferred; these AX fields are target-widget
        // evidence for risk classification only (issue #290), while
        // screenshots remain the model's perception surface.
        snapshot.accessibility_role = optional_ax_field(widget_role);
        snapshot.accessibility_subrole = optional_ax_field(widget_subrole);
        snapshot.title_hint = title.map_or_else(
            || {
                FieldEvidence::unavailable(
                    TargetUnavailableReason::PartialEvidence,
                    Some(EvidenceSource::Accessibility),
                )
            },
            |value| {
                FieldEvidence::available(
                    RedactedHint::from_raw(&value),
                    EvidenceSource::Accessibility,
                )
            },
        );
        snapshot.class_hint = app_name.map_or_else(
            || {
                FieldEvidence::unavailable(
                    TargetUnavailableReason::PartialEvidence,
                    Some(EvidenceSource::AppKitWorkspace),
                )
            },
            |value| {
                FieldEvidence::available(
                    RedactedHint::from_raw(&value),
                    EvidenceSource::AppKitWorkspace,
                )
            },
        );
        snapshot.geometry = FieldEvidence::available(
            TargetGeometry {
                x: (position.x * scale).round() as i32,
                y: (position.y * scale).round() as i32,
                width: (size.width * scale).round() as u32,
                height: (size.height * scale).round() as u32,
                scale,
            },
            EvidenceSource::Accessibility,
        );
        snapshot.desktop_geometry = FieldEvidence::available(
            TargetGeometry {
                x: (display_bounds.origin.x * scale).round() as i32,
                y: (display_bounds.origin.y * scale).round() as i32,
                width: (display_bounds.size.width * scale).round() as u32,
                height: (display_bounds.size.height * scale).round() as u32,
                scale,
            },
            EvidenceSource::ColorSyncDisplayUuid,
        );
        validate_current_login_session(&login_session)?;
        snapshot.synchronous_recheck = true;
        Ok(snapshot)
    }
}

#[cfg(target_os = "macos")]
impl TargetEvidenceAdapter for MacOsTargetEvidenceAdapter {
    fn backend_kind(&self) -> BackendKind {
        BackendKind::RealDesktopMacOs
    }

    fn capture_snapshot(&mut self) -> Result<TargetIdentityEvidence, TargetUnavailableReason> {
        let mut snapshot = self.capture_macos_snapshot()?;
        // This adapter does not publish a native callback stream yet, so a
        // synchronous snapshot is not itself an observed focus event. The
        // pre-handoff bracket below compares the complete fingerprint, which
        // includes the planted window-generation token; advancing a process-local
        // counter on every read would reject every otherwise stable dispatch.
        snapshot.adapter_observed_epoch = self.observed_epoch;
        snapshot.focus_generation = self.reducer.observe(&snapshot)?;
        Ok(snapshot)
    }

    fn observed_focus_epoch(&self) -> u64 {
        self.observed_epoch
    }
}

#[cfg(target_os = "macos")]
fn ax_window_rect(
    window: &objc2_application_services::AXUIElement,
) -> Result<
    (
        objc2_core_foundation::CGPoint,
        objc2_core_foundation::CGSize,
    ),
    TargetUnavailableReason,
> {
    use objc2_application_services::{AXValue, AXValueType};
    use objc2_core_foundation::{CGPoint, CGSize};

    let position_value = ax_attribute(window, MacAxAttribute::Position)?
        .downcast::<AXValue>()
        .map_err(|_| TargetUnavailableReason::QueryMismatch)?;
    let size_value = ax_attribute(window, MacAxAttribute::Size)?
        .downcast::<AXValue>()
        .map_err(|_| TargetUnavailableReason::QueryMismatch)?;
    let mut position = CGPoint::default();
    let mut size = CGSize::default();
    // SAFETY: Both destinations are initialized, correctly aligned native
    // geometry values and remain live for the duration of each AX call.
    let position_ok = unsafe {
        position_value.r#type() == AXValueType::CGPoint
            && position_value.value(
                AXValueType::CGPoint,
                std::ptr::NonNull::new_unchecked(
                    (&mut position as *mut CGPoint).cast::<std::ffi::c_void>(),
                ),
            )
    };
    let size_ok = unsafe {
        size_value.r#type() == AXValueType::CGSize
            && size_value.value(
                AXValueType::CGSize,
                std::ptr::NonNull::new_unchecked(
                    (&mut size as *mut CGSize).cast::<std::ffi::c_void>(),
                ),
            )
    };
    if !position_ok
        || !size_ok
        || !position.x.is_finite()
        || !position.y.is_finite()
        || !size.width.is_finite()
        || !size.height.is_finite()
        || size.width <= 0.0
        || size.height <= 0.0
    {
        return Err(TargetUnavailableReason::QueryMismatch);
    }
    Ok((position, size))
}

/// Resolve AX's focused window to the public CoreGraphics window number.
/// The window number is a live compositor object identity; unlike AX bounds,
/// it does not change when the window moves or resizes.
#[cfg(target_os = "macos")]
fn cg_window_number_for_ax_window(
    expected_pid: u32,
    position: objc2_core_foundation::CGPoint,
    size: objc2_core_foundation::CGSize,
) -> Result<u32, TargetUnavailableReason> {
    use objc2_core_foundation::{CFArray, CFDictionary, CFRetained, CGRect};
    use objc2_core_graphics::{
        CGRectMakeWithDictionaryRepresentation, CGWindowListCopyWindowInfo, CGWindowListOption,
        kCGNullWindowID, kCGWindowBounds, kCGWindowNumber, kCGWindowOwnerPID,
    };

    let info = CGWindowListCopyWindowInfo(
        CGWindowListOption::OptionOnScreenOnly | CGWindowListOption::ExcludeDesktopElements,
        kCGNullWindowID,
    )
    .ok_or(TargetUnavailableReason::MissingCapability)?;
    // CoreGraphics documents this return as an array of CFDictionary entries.
    // The cast only supplies that documented element type to objc2.
    let info: CFRetained<CFArray<CFDictionary>> = unsafe { CFRetained::cast_unchecked(info) };
    let owner_pid_key = unsafe { kCGWindowOwnerPID };
    let window_number_key = unsafe { kCGWindowNumber };
    let bounds_key = unsafe { kCGWindowBounds };
    let mut matches = Vec::new();
    for dictionary in info.iter() {
        // `CFArray::iter` yields owned `CFRetained<CFDictionary>` values;
        // the lookup helpers borrow the dictionary through `CFRetained`'s
        // `Deref` for the duration of each call.
        let owner_pid = cg_number_value(&dictionary, owner_pid_key)?;
        if owner_pid != i64::from(expected_pid) {
            continue;
        }
        let bounds_value = cg_dictionary_value(&dictionary, bounds_key)
            .ok_or(TargetUnavailableReason::QueryMismatch)?;
        let bounds_dictionary = bounds_value
            .downcast_ref::<CFDictionary>()
            .ok_or(TargetUnavailableReason::QueryMismatch)?;
        let mut bounds = CGRect::default();
        // SAFETY: `bounds_dictionary` is checked as a CFDictionary and
        // `bounds` is an initialized writable CGRect. CoreGraphics validates
        // the dictionary's typed geometry fields before returning true.
        let bounds_ok =
            unsafe { CGRectMakeWithDictionaryRepresentation(Some(bounds_dictionary), &mut bounds) };
        if !bounds_ok {
            return Err(TargetUnavailableReason::QueryMismatch);
        }
        if (
            bounds.origin.x,
            bounds.origin.y,
            bounds.size.width,
            bounds.size.height,
        ) != (position.x, position.y, size.width, size.height)
        {
            continue;
        }
        let window_number = cg_number_value(&dictionary, window_number_key)?;
        let window_number = u32::try_from(window_number)
            .ok()
            .filter(|number| *number != 0)
            .ok_or(TargetUnavailableReason::QueryMismatch)?;
        matches.push(window_number);
    }
    match matches.as_slice() {
        [window_number] => Ok(*window_number),
        [] => Err(TargetUnavailableReason::FocusIdentityUnavailable),
        _ => Err(TargetUnavailableReason::AmbiguousOutput),
    }
}

/// Live focused window the input backend can address and recheck.
///
/// This is the same AX/CG join the evidence adapter uses for targeting
/// fields. The backend retains the AX object and authenticates delivery with
/// the CGS-planted generation token so a recycled PID/window number pair
/// cannot match at delivery.
#[cfg(target_os = "macos")]
pub(crate) struct MacLiveInjectionTarget {
    pub window: MacLiveFocusedWindow,
    pub ax: MacFocusedWindowWitness,
}

#[cfg(target_os = "macos")]
pub(crate) fn live_focused_macos_injection_target()
-> Result<MacLiveInjectionTarget, TargetUnavailableReason> {
    use objc2_app_kit::NSWorkspace;
    use objc2_application_services::AXUIElement;

    let workspace = NSWorkspace::sharedWorkspace();
    let frontmost = workspace
        .frontmostApplication()
        .ok_or(TargetUnavailableReason::FocusIdentityUnavailable)?;
    let frontmost_pid = u32::try_from(frontmost.processIdentifier())
        .map_err(|_| TargetUnavailableReason::FocusIdentityUnavailable)?;
    // SAFETY: AX returns retained CF objects. `ax_attribute` validates the
    // status and takes ownership of each +1 result before downcasting.
    let system = unsafe { AXUIElement::new_system_wide() };
    let application = ax_attribute(&system, MacAxAttribute::FocusedApplication)?
        .downcast::<AXUIElement>()
        .map_err(|_| TargetUnavailableReason::QueryMismatch)?;
    let mut ax_pid: libc::pid_t = 0;
    let pid_status = unsafe { application.pid(std::ptr::NonNull::from(&mut ax_pid)) };
    if pid_status != objc2_application_services::AXError::Success
        || u32::try_from(ax_pid).ok() != Some(frontmost_pid)
    {
        return Err(TargetUnavailableReason::QueryMismatch);
    }
    let window = ax_attribute(&application, MacAxAttribute::FocusedWindow)?
        .downcast::<AXUIElement>()
        .map_err(|_| TargetUnavailableReason::QueryMismatch)?;
    let (position, size) = ax_window_rect(&window)?;
    let window_number = cg_window_number_for_ax_window(frontmost_pid, position, size)?;
    if window_number == 0 {
        return Err(TargetUnavailableReason::FocusIdentityUnavailable);
    }
    Ok(MacLiveInjectionTarget {
        window: MacLiveFocusedWindow {
            pid: frontmost_pid,
            window_number,
        },
        ax: MacFocusedWindowWitness::new(window),
    })
}

/// True when the retained AX window object still answers attribute queries.
/// A destroyed window (and therefore a recycled PID/window-number pair) fails.
#[cfg(target_os = "macos")]
pub(crate) fn ax_window_element_is_live(element: &objc2_application_services::AXUIElement) -> bool {
    ax_attribute(element, MacAxAttribute::Role).is_ok()
}

/// Re-acquire the AX window object named by a persisted opaque id.
///
/// Crash recovery has no retained CF witness. Live AX windows of the journaled
/// process are joined by CoreGraphics window number and authenticated by
/// [`restore_macos_window_object`] against the planted generation. A recycled
/// pair whose planted token does not match is refused.
#[cfg(target_os = "macos")]
pub(crate) fn restore_macos_injection_target(
    opaque: &OpaqueWindowId,
) -> Result<MacLiveInjectionTarget, TargetUnavailableReason> {
    use objc2_application_services::AXUIElement;
    use objc2_core_foundation::{CFArray, CFRetained};

    let (pid, _, _) =
        macos_window_identity_from_opaque(opaque).ok_or(TargetUnavailableReason::QueryMismatch)?;
    let pid_t = libc::pid_t::try_from(pid).map_err(|_| TargetUnavailableReason::QueryMismatch)?;
    // SAFETY: AXUIElementCreateApplication is documented to return a retained
    // application element for any pid; a dead pid fails subsequent queries.
    let application = unsafe { AXUIElement::new_application(pid_t) };
    let windows = ax_attribute(&application, MacAxAttribute::Windows)?;
    // AXWindows is documented as an array of AXUIElementRef. The cast only
    // supplies that element type; each window is still joined by CG number.
    let windows: CFRetained<CFArray<AXUIElement>> = unsafe { CFRetained::cast_unchecked(windows) };
    let mut candidates = Vec::new();
    let mut ax_windows = Vec::new();
    for window in windows.iter() {
        let Ok((position, size)) = ax_window_rect(&window) else {
            continue;
        };
        let Ok(window_number) = cg_window_number_for_ax_window(pid, position, size) else {
            continue;
        };
        candidates.push(MacosLiveWindowCandidate {
            pid,
            window_number,
            planted_generation: read_macos_window_generation(window_number)?,
        });
        ax_windows.push(window);
    }
    let index = restore_macos_window_object(opaque, &candidates)?;
    let selected = &candidates[index];
    Ok(MacLiveInjectionTarget {
        window: MacLiveFocusedWindow {
            pid: selected.pid,
            window_number: selected.window_number,
        },
        ax: MacFocusedWindowWitness::new(ax_windows.swap_remove(index)),
    })
}

/// Live pid and CGWindowID read from the retained AX window object, then
/// authenticated against the generation planted on that CoreGraphics window.
/// The returned window number is the destination operand stamped onto the
/// event; a stored pid/window-number pair is never the destination.
#[cfg(target_os = "macos")]
#[derive(Debug, Clone, Copy)]
pub(crate) struct MacAddressedInjection {
    pub pid: libc::pid_t,
    pub window_number: u32,
    pub origin: objc2_core_foundation::CGPoint,
}

/// Address the retained AX window object for irreversible delivery.
///
/// Pid and CGWindowID are read from the live AX element and authenticated by
/// the planted generation. AXRaise is best-effort visual ordering; it is not
/// the destination. Focus writes are not a lock and are not used as the
/// delivery operand.
#[cfg(target_os = "macos")]
pub(crate) fn address_macos_injection_window(
    witness: &MacFocusedWindowWitness,
    expected: &OpaqueWindowId,
) -> Result<MacAddressedInjection, TargetUnavailableReason> {
    use objc2_application_services::AXError;
    use objc2_core_foundation::CFString;

    let (expected_pid, expected_window, expected_generation) =
        macos_window_identity_from_opaque(expected)
            .ok_or(TargetUnavailableReason::QueryMismatch)?;
    let window = witness.element();
    if !ax_window_element_is_live(window) {
        return Err(TargetUnavailableReason::StaleTarget);
    }
    let mut pid: libc::pid_t = 0;
    let pid_status = unsafe { window.pid(std::ptr::NonNull::from(&mut pid)) };
    if pid_status != AXError::Success || pid <= 0 || u32::try_from(pid).ok() != Some(expected_pid) {
        return Err(TargetUnavailableReason::QueryMismatch);
    }
    let (position, size) = ax_window_rect(window)?;
    let window_number = cg_window_number_for_ax_window(expected_pid, position, size)?;
    if window_number != expected_window {
        return Err(TargetUnavailableReason::StaleTarget);
    }
    let planted =
        read_macos_window_generation(window_number)?.ok_or(TargetUnavailableReason::StaleTarget)?;
    if planted != expected_generation {
        return Err(TargetUnavailableReason::StaleTarget);
    }
    let raise = CFString::from_static_str("AXRaise");
    let _ = unsafe { window.perform_action(&raise) };
    Ok(MacAddressedInjection {
        pid,
        window_number,
        origin: position,
    })
}

const MACOS_WINDOW_GENERATION_KEY: &str = "com.flycockpit.window-generation";

#[cfg(target_os = "macos")]
struct LiveMacosWindowGenerationStore;

#[cfg(target_os = "macos")]
impl MacosWindowGenerationStore for LiveMacosWindowGenerationStore {
    fn read(
        &self,
        window_number: u32,
    ) -> Result<Option<[u8; MACOS_WINDOW_GENERATION_LEN]>, TargetUnavailableReason> {
        read_macos_window_generation(window_number)
    }

    fn plant(
        &self,
        window_number: u32,
        generation: [u8; MACOS_WINDOW_GENERATION_LEN],
    ) -> Result<(), TargetUnavailableReason> {
        plant_macos_window_generation(window_number, generation)
    }
}

#[cfg(target_os = "macos")]
fn plant_macos_window_generation(
    window_number: u32,
    generation: [u8; MACOS_WINDOW_GENERATION_LEN],
) -> Result<(), TargetUnavailableReason> {
    let Some(set) = cgs_set_window_property() else {
        return Err(TargetUnavailableReason::MissingCapability);
    };
    let cid = cgs_main_connection_id().ok_or(TargetUnavailableReason::MissingCapability)?;
    use objc2_core_foundation::CFType;
    use std::convert::AsRef;

    let key = objc2_core_foundation::CFString::from_static_str(MACOS_WINDOW_GENERATION_KEY);
    let value = objc2_core_foundation::CFData::from_bytes(&generation);
    // SAFETY: `key`/`value` are live CF objects for the call; CGS copies them.
    let status = unsafe {
        set(
            cid,
            window_number,
            AsRef::<CFType>::as_ref(&key) as *const _ as *const std::ffi::c_void,
            AsRef::<CFType>::as_ref(&value) as *const _ as *const std::ffi::c_void,
        )
    };
    if status != 0 {
        return Err(TargetUnavailableReason::QueryMismatch);
    }
    let live = read_macos_window_generation(window_number)?
        .ok_or(TargetUnavailableReason::QueryMismatch)?;
    if live != generation {
        return Err(TargetUnavailableReason::QueryMismatch);
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn read_macos_window_generation(
    window_number: u32,
) -> Result<Option<[u8; MACOS_WINDOW_GENERATION_LEN]>, TargetUnavailableReason> {
    let Some(copy) = cgs_copy_window_property() else {
        return Ok(None);
    };
    let Some(cid) = cgs_main_connection_id() else {
        return Ok(None);
    };
    use objc2_core_foundation::CFType;
    use std::convert::AsRef;

    let key = objc2_core_foundation::CFString::from_static_str(MACOS_WINDOW_GENERATION_KEY);
    let mut raw: *const CFType = std::ptr::null();
    // SAFETY: `raw` is a writable out pointer. On success CGS returns a +1 CF object.
    let status = unsafe {
        copy(
            cid,
            window_number,
            AsRef::<CFType>::as_ref(&key) as *const _ as *const std::ffi::c_void,
            (&mut raw as *mut *const CFType).cast(),
        )
    };
    if status != 0 || raw.is_null() {
        return Ok(None);
    }
    let raw =
        std::ptr::NonNull::new(raw.cast_mut()).ok_or(TargetUnavailableReason::QueryMismatch)?;
    // SAFETY: CGSCopyWindowProperty transferred a +1 CF object.
    let value = unsafe { objc2_core_foundation::CFRetained::from_raw(raw) };
    let Ok(data) = value.downcast::<objc2_core_foundation::CFData>() else {
        // Prior development cycles stored CFNumber tokens under this key; treat
        // any non-CFData value as unplanted so a new generation can be written.
        return Ok(None);
    };
    // SAFETY: `data` is an immutable local retain; the slice is copied below.
    let bytes = unsafe { data.as_bytes_unchecked() };
    if bytes.len() != MACOS_WINDOW_GENERATION_LEN {
        return Ok(None);
    }
    let mut generation = [0_u8; MACOS_WINDOW_GENERATION_LEN];
    generation.copy_from_slice(bytes);
    if macos_generation_is_zero(&generation) {
        return Ok(None);
    }
    Ok(Some(generation))
}

#[cfg(target_os = "macos")]
fn cgs_main_connection_id() -> Option<i32> {
    type Fn = unsafe extern "C" fn() -> i32;
    static CACHED: std::sync::OnceLock<Option<Fn>> = std::sync::OnceLock::new();
    let f = CACHED.get_or_init(|| dlsym_fn(c"CGSMainConnectionID"))?;
    // SAFETY: CGSMainConnectionID takes no arguments and returns the process
    // WindowServer connection id.
    Some(unsafe { f() })
}

#[cfg(target_os = "macos")]
fn cgs_set_window_property()
-> Option<unsafe extern "C" fn(i32, u32, *const std::ffi::c_void, *const std::ffi::c_void) -> i32> {
    static CACHED: std::sync::OnceLock<
        Option<
            unsafe extern "C" fn(i32, u32, *const std::ffi::c_void, *const std::ffi::c_void) -> i32,
        >,
    > = std::sync::OnceLock::new();
    *CACHED.get_or_init(|| dlsym_fn(c"CGSSetWindowProperty"))
}

#[cfg(target_os = "macos")]
fn cgs_copy_window_property() -> Option<
    unsafe extern "C" fn(i32, u32, *const std::ffi::c_void, *mut *const std::ffi::c_void) -> i32,
> {
    static CACHED: std::sync::OnceLock<
        Option<
            unsafe extern "C" fn(
                i32,
                u32,
                *const std::ffi::c_void,
                *mut *const std::ffi::c_void,
            ) -> i32,
        >,
    > = std::sync::OnceLock::new();
    *CACHED.get_or_init(|| dlsym_fn(c"CGSCopyWindowProperty"))
}

#[cfg(target_os = "macos")]
fn dlsym_fn<T>(name: &std::ffi::CStr) -> Option<T> {
    const RTLD_DEFAULT: *mut std::ffi::c_void = (-2_isize) as *mut std::ffi::c_void;
    // SAFETY: `name` is a static C string; a NULL return means the symbol is absent.
    let mut ptr = unsafe { libc::dlsym(RTLD_DEFAULT, name.as_ptr()) };
    if ptr.is_null() {
        let sky = unsafe {
            libc::dlopen(
                c"/System/Library/PrivateFrameworks/SkyLight.framework/SkyLight".as_ptr(),
                libc::RTLD_LAZY,
            )
        };
        if sky.is_null() {
            return None;
        }
        ptr = unsafe { libc::dlsym(sky, name.as_ptr()) };
        if ptr.is_null() {
            return None;
        }
    }
    Some(unsafe { std::mem::transmute_copy(&ptr) })
}

#[cfg(target_os = "macos")]
fn cg_dictionary_value<'a>(
    dictionary: &'a objc2_core_foundation::CFDictionary,
    key: &objc2_core_foundation::CFString,
) -> Option<&'a objc2_core_foundation::CFType> {
    use objc2_core_foundation::{CFDictionary, CFString, CFType};

    // CGWindowList dictionaries are dynamically typed. Reinterpret only the
    // generic parameters (the CF object layout is identical), then downcast
    // each value before use.
    let typed =
        unsafe { &*(dictionary as *const CFDictionary).cast::<CFDictionary<CFString, CFType>>() };
    // SAFETY: `typed` supplies the actual key/value CF types documented for a
    // CGWindowList entry; the returned reference lives no longer than `dictionary`.
    unsafe { typed.get_unchecked(key) }
}

#[cfg(target_os = "macos")]
fn cg_number_value(
    dictionary: &objc2_core_foundation::CFDictionary,
    key: &objc2_core_foundation::CFString,
) -> Result<i64, TargetUnavailableReason> {
    use objc2_core_foundation::CFNumber;

    cg_dictionary_value(dictionary, key)
        .and_then(|value| value.downcast_ref::<CFNumber>())
        .and_then(CFNumber::as_i64)
        .ok_or(TargetUnavailableReason::QueryMismatch)
}

#[cfg(target_os = "macos")]
fn current_audit_session_id() -> Result<u32, TargetUnavailableReason> {
    use mach2::kern_return::KERN_SUCCESS;
    use mach2::message::audit_token_t;
    use mach2::task::task_info;
    use mach2::task_info::{TASK_AUDIT_TOKEN, TASK_AUDIT_TOKEN_COUNT, task_info_t};
    use mach2::traps::mach_task_self;

    let mut token = audit_token_t::default();
    let mut count = TASK_AUDIT_TOKEN_COUNT;
    // SAFETY: `token` is the exact public TASK_AUDIT_TOKEN layout, and count
    // advertises its size in natural_t units as required by task_info.
    let status = unsafe {
        task_info(
            mach_task_self(),
            TASK_AUDIT_TOKEN,
            (&mut token as *mut audit_token_t).cast::<i32>() as task_info_t,
            &mut count,
        )
    };
    extract_audit_session_id(status == KERN_SUCCESS, count, &token.val)
        .map_err(|_| TargetUnavailableReason::SessionInactive)
}

/// Capture the current login session and prove that it belongs to this
/// process's effective UID and is the active, fully logged-in console session.
///
/// The caller retains the snapshot and passes it to
/// [`validate_current_login_session`] after its evidence bracket. That second
/// read rejects fast-user-switch and login transitions that occur while AX and
/// CoreGraphics focus evidence is being gathered.
#[cfg(target_os = "macos")]
fn current_active_login_session() -> Result<CgSessionSnapshot, TargetUnavailableReason> {
    use objc2_core_foundation::{CFBoolean, CFNumber};
    use objc2_core_graphics::CGSessionCopyCurrentDictionary;

    let dictionary =
        CGSessionCopyCurrentDictionary().ok_or(TargetUnavailableReason::SessionInactive)?;
    let snapshot = CgSessionSnapshot {
        user_id: cg_session_value(&dictionary, CgSessionKey::UserId, |value| {
            value
                .downcast_ref::<CFNumber>()
                .and_then(CFNumber::as_i64)
                .and_then(|number| u32::try_from(number).ok())
                .map(CgSessionValue::Number)
        }),
        console_set: cg_session_value(&dictionary, CgSessionKey::ConsoleSet, |value| {
            value
                .downcast_ref::<CFNumber>()
                .and_then(CFNumber::as_i64)
                .and_then(|number| u32::try_from(number).ok())
                .map(CgSessionValue::Number)
        }),
        on_console: cg_session_value(&dictionary, CgSessionKey::OnConsole, |value| {
            value
                .downcast_ref::<CFBoolean>()
                .map(|boolean| CgSessionValue::Bool(boolean.as_bool()))
        }),
        login_done: cg_session_value(&dictionary, CgSessionKey::LoginDone, |value| {
            value
                .downcast_ref::<CFBoolean>()
                .map(|boolean| CgSessionValue::Bool(boolean.as_bool()))
        }),
    };
    // SAFETY: `geteuid` has no preconditions and only reads this process's
    // effective credentials.
    let effective_uid = u32::try_from(unsafe { libc::geteuid() })
        .map_err(|_| TargetUnavailableReason::SessionInactive)?;
    validate_cg_session(&snapshot, effective_uid, None)
        .map_err(|_| TargetUnavailableReason::SessionInactive)?;
    Ok(snapshot)
}

#[cfg(target_os = "macos")]
fn validate_current_login_session(
    previous: &CgSessionSnapshot,
) -> Result<(), TargetUnavailableReason> {
    let current = current_active_login_session()?;
    // SAFETY: `geteuid` has no preconditions and only reads this process's
    // effective credentials.
    let effective_uid = u32::try_from(unsafe { libc::geteuid() })
        .map_err(|_| TargetUnavailableReason::SessionInactive)?;
    validate_cg_session(&current, effective_uid, Some(previous))
        .map(|_| ())
        .map_err(|_| TargetUnavailableReason::SessionInactive)
}

/// Reboundable proof of the active macOS console session used by the
/// host-wide CGEvent sink. The backend retains one of these for its complete
/// lifetime and rechecks it at the irreversible post primitive; evidence
/// captured only at coordinator handoff is insufficient because a multi-event
/// action may span a fast-user-switch transition.
#[cfg(target_os = "macos")]
#[derive(Debug, Clone)]
pub(crate) struct MacActiveConsoleSession {
    login: CgSessionSnapshot,
    audit_session_id: u32,
}

#[cfg(target_os = "macos")]
impl MacActiveConsoleSession {
    pub(crate) fn capture() -> Result<Self, TargetUnavailableReason> {
        Ok(Self {
            login: current_active_login_session()?,
            audit_session_id: current_audit_session_id()?,
        })
    }

    pub(crate) fn recheck(&self) -> Result<(), TargetUnavailableReason> {
        validate_current_login_session(&self.login)?;
        if current_audit_session_id()? != self.audit_session_id {
            return Err(TargetUnavailableReason::SessionInactive);
        }
        Ok(())
    }

    pub(crate) fn identity(&self) -> Result<(u32, u32, u32), TargetUnavailableReason> {
        let effective_uid = u32::try_from(unsafe { libc::geteuid() })
            .map_err(|_| TargetUnavailableReason::SessionInactive)?;
        let (owner_uid, console_set) = validate_cg_session(&self.login, effective_uid, None)
            .map_err(|_| TargetUnavailableReason::SessionInactive)?;
        Ok((owner_uid, console_set, self.audit_session_id))
    }
}

#[cfg(target_os = "macos")]
fn cg_session_value(
    dictionary: &objc2_core_foundation::CFDictionary,
    key: CgSessionKey,
    decode: impl FnOnce(&objc2_core_foundation::CFType) -> Option<CgSessionValue>,
) -> CgSessionValue {
    let key = objc2_core_foundation::CFString::from_static_str(key.as_static_str());
    cg_dictionary_value(dictionary, &key).map_or(CgSessionValue::Missing, |value| {
        decode(value).unwrap_or(CgSessionValue::WrongType)
    })
}

#[cfg(target_os = "macos")]
fn ax_attribute(
    element: &objc2_application_services::AXUIElement,
    attribute: MacAxAttribute,
) -> Result<objc2_core_foundation::CFRetained<objc2_core_foundation::CFType>, TargetUnavailableReason>
{
    use objc2_application_services::AXError;
    use objc2_core_foundation::{CFRetained, CFString, CFType};

    let name = CFString::from_static_str(attribute.as_static_str());
    let mut raw: *const CFType = std::ptr::null();
    // SAFETY: `raw` is a valid writable out pointer. On success AX returns a
    // non-null +1 CF object, transferred immediately into CFRetained.
    let status = unsafe { element.copy_attribute_value(&name, std::ptr::NonNull::from(&mut raw)) };
    if status == AXError::APIDisabled {
        return Err(TargetUnavailableReason::PermissionDenied);
    }
    if status != AXError::Success {
        return Err(TargetUnavailableReason::FocusIdentityUnavailable);
    }
    let raw =
        std::ptr::NonNull::new(raw.cast_mut()).ok_or(TargetUnavailableReason::QueryMismatch)?;
    // SAFETY: AXUIElementCopyAttributeValue returned success and ownership of
    // the non-null +1 value represented by `raw`.
    Ok(unsafe { CFRetained::from_raw(raw) })
}

#[cfg(target_os = "macos")]
fn ax_string(
    element: &objc2_application_services::AXUIElement,
    attribute: MacAxAttribute,
) -> Result<String, TargetUnavailableReason> {
    ax_attribute(element, attribute)?
        .downcast::<objc2_core_foundation::CFString>()
        .map(|value| value.to_string())
        .map_err(|_| TargetUnavailableReason::QueryMismatch)
}

#[cfg(target_os = "macos")]
fn ax_optional_string(
    element: &objc2_application_services::AXUIElement,
    attribute: MacAxAttribute,
) -> Option<String> {
    ax_string(element, attribute).ok()
}

#[cfg(target_os = "macos")]
fn optional_ax_field(value: Option<String>) -> FieldEvidence<String> {
    value.map_or_else(
        || {
            FieldEvidence::unavailable(
                TargetUnavailableReason::PartialEvidence,
                Some(EvidenceSource::Accessibility),
            )
        },
        |value| FieldEvidence::available(value, EvidenceSource::Accessibility),
    )
}

#[cfg(test)]
mod authority_transaction_tests {
    use super::{begin_known_pre_post, rollback_known_pre_post};

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct AuthorityState {
        pending: bool,
        keys: Vec<u16>,
        generation: u64,
    }

    #[test]
    fn held_input_without_a_window_identity_is_incomplete() {
        assert!(super::mac_held_input_identity_is_complete(&[], false, None));
        assert!(!super::mac_held_input_identity_is_complete(
            &[12],
            false,
            None
        ));
        assert!(!super::mac_held_input_identity_is_complete(&[], true, None));
        assert!(super::mac_held_input_identity_is_complete(
            &[12],
            true,
            Some([7u8; 16])
        ));
    }

    #[test]
    fn known_pre_post_refusal_restores_exact_prior_authority_state() {
        let expected = AuthorityState {
            pending: false,
            keys: vec![12, 44],
            generation: 9,
        };
        let mut state = expected.clone();
        let previous = begin_known_pre_post(&mut state, |state| state.pending = true);
        assert!(state.pending);
        rollback_known_pre_post(&mut state, previous);
        assert_eq!(state, expected);
    }
}

#[cfg(test)]
mod opaque_window_tests {
    use super::{
        MACOS_WINDOW_GENERATION_LEN, MacosAxDeliveryError, MacosAxWindowDelivery,
        MacosLiveWindowCandidate, MacosWindowGenerationStore, deliver_to_authenticated_ax_window,
        macos_injection_target_from_opaque, macos_window_identity_from_opaque,
        opaque_macos_window_id, read_or_plant_macos_window_generation, restore_macos_window_object,
    };
    use crate::computer::host_identity::FixedHostIdentityRng;
    use crate::computer::target::TargetUnavailableReason;
    use std::cell::RefCell;
    use std::collections::HashMap;

    const GEN_A: [u8; MACOS_WINDOW_GENERATION_LEN] =
        [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
    const GEN_B: [u8; MACOS_WINDOW_GENERATION_LEN] =
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x10, 0x20];

    #[test]
    fn macos_window_id_round_trips_targeting_fields_and_rejects_zeros() {
        let id = opaque_macos_window_id(4242, 99, GEN_A);
        assert_eq!(macos_injection_target_from_opaque(&id), Some((4242, 99)));
        assert_eq!(
            macos_window_identity_from_opaque(&id),
            Some((4242, 99, GEN_A))
        );
        assert_eq!(id.as_bytes()[8..], GEN_A);
        assert_eq!(
            macos_injection_target_from_opaque(&opaque_macos_window_id(0, 99, GEN_A)),
            None
        );
        assert_eq!(
            macos_injection_target_from_opaque(&opaque_macos_window_id(1, 0, GEN_A)),
            None
        );
        assert_eq!(
            macos_window_identity_from_opaque(&opaque_macos_window_id(
                1,
                1,
                [0; MACOS_WINDOW_GENERATION_LEN]
            )),
            None
        );
    }

    #[test]
    fn planted_generation_distinguishes_recycled_pid_window_pairs() {
        let first = opaque_macos_window_id(8, 16, GEN_A);
        let recycled = opaque_macos_window_id(8, 16, GEN_B);
        assert_ne!(first, recycled);
        assert_eq!(macos_injection_target_from_opaque(&first), Some((8, 16)));
        assert_eq!(macos_injection_target_from_opaque(&recycled), Some((8, 16)));
        assert_eq!(
            macos_window_identity_from_opaque(&first),
            Some((8, 16, GEN_A))
        );
        assert_eq!(
            macos_window_identity_from_opaque(&recycled),
            Some((8, 16, GEN_B))
        );
    }

    #[test]
    fn restore_macos_window_object_refuses_recycled_pair_with_a_new_adapter_token() {
        let journal = opaque_macos_window_id(42, 7, GEN_A);
        let recycled = [MacosLiveWindowCandidate {
            pid: 42,
            window_number: 7,
            planted_generation: Some(GEN_B),
        }];
        assert_eq!(
            restore_macos_window_object(&journal, &recycled),
            Err(TargetUnavailableReason::StaleTarget)
        );
        let missing = [MacosLiveWindowCandidate {
            pid: 42,
            window_number: 7,
            planted_generation: None,
        }];
        assert_eq!(
            restore_macos_window_object(&journal, &missing),
            Err(TargetUnavailableReason::StaleTarget)
        );
        let live = [MacosLiveWindowCandidate {
            pid: 42,
            window_number: 7,
            planted_generation: Some(GEN_A),
        }];
        assert_eq!(restore_macos_window_object(&journal, &live), Ok(0));
    }

    #[test]
    fn restore_macos_window_object_refuses_the_resettable_epoch_one_collision() {
        // A process-local counter that Default-resets plants 1 on the first
        // window after restart. That is not a durable object identity: the
        // crashed process's first window was also commonly 1.
        let counter_one = 1_u64.to_le_bytes();
        let journal = opaque_macos_window_id(8, 16, counter_one);
        let replacement_after_restart = [MacosLiveWindowCandidate {
            pid: 8,
            window_number: 16,
            planted_generation: Some(GEN_A),
        }];
        assert_eq!(
            restore_macos_window_object(&journal, &replacement_after_restart),
            Err(TargetUnavailableReason::StaleTarget)
        );
    }

    #[derive(Default)]
    struct MapGenerationStore {
        planted: RefCell<HashMap<u32, [u8; MACOS_WINDOW_GENERATION_LEN]>>,
        plant_count: RefCell<usize>,
    }

    impl MacosWindowGenerationStore for MapGenerationStore {
        fn read(
            &self,
            window_number: u32,
        ) -> Result<Option<[u8; MACOS_WINDOW_GENERATION_LEN]>, TargetUnavailableReason> {
            Ok(self.planted.borrow().get(&window_number).copied())
        }

        fn plant(
            &self,
            window_number: u32,
            generation: [u8; MACOS_WINDOW_GENERATION_LEN],
        ) -> Result<(), TargetUnavailableReason> {
            *self.plant_count.borrow_mut() += 1;
            self.planted.borrow_mut().insert(window_number, generation);
            Ok(())
        }
    }

    #[test]
    fn read_or_plant_never_overwrites_an_existing_generation() {
        let store = MapGenerationStore::default();
        let mut first_rng = FixedHostIdentityRng::new([0x11; 32]);
        let planted =
            read_or_plant_macos_window_generation(&store, &mut first_rng, 99).expect("plant");
        let mut second_rng = FixedHostIdentityRng::new([0x22; 32]);
        let again =
            read_or_plant_macos_window_generation(&store, &mut second_rng, 99).expect("read");
        assert_eq!(planted, again);
        assert_eq!(*store.plant_count.borrow(), 1);
        let recycled = MapGenerationStore::default();
        let mut restart_rng = FixedHostIdentityRng::new([0x22; 32]);
        let replacement = read_or_plant_macos_window_generation(&recycled, &mut restart_rng, 99)
            .expect("plant recycled");
        assert_ne!(planted, replacement);
        let journal = opaque_macos_window_id(1, 99, planted);
        let candidates = [MacosLiveWindowCandidate {
            pid: 1,
            window_number: 99,
            planted_generation: Some(replacement),
        }];
        assert_eq!(
            restore_macos_window_object(&journal, &candidates),
            Err(TargetUnavailableReason::StaleTarget)
        );
    }

    struct RecordingAxHost {
        live: bool,
        identity: (u32, u32, [u8; MACOS_WINDOW_GENERATION_LEN], (f64, f64)),
        location_setter: bool,
        posts: usize,
        recycle_on_post: bool,
        recycled_identity: (u32, u32, [u8; MACOS_WINDOW_GENERATION_LEN], (f64, f64)),
    }

    impl MacosAxWindowDelivery for RecordingAxHost {
        fn ax_is_live(&self) -> bool {
            self.live
        }

        fn resolve_from_ax(
            &self,
        ) -> Result<(u32, u32, [u8; MACOS_WINDOW_GENERATION_LEN], (f64, f64)), MacosAxDeliveryError>
        {
            Ok(self.identity)
        }

        fn window_location_setter_available(&self) -> bool {
            self.location_setter
        }

        fn post_to_held_ax(&mut self) -> Result<(), MacosAxDeliveryError> {
            if self.recycle_on_post {
                self.identity = self.recycled_identity;
            }
            self.posts += 1;
            Ok(())
        }
    }

    #[test]
    fn deliver_to_authenticated_ax_window_requires_live_ax_and_location_setter() {
        let expected = opaque_macos_window_id(9, 3, GEN_A);
        let mut dead = RecordingAxHost {
            live: false,
            identity: (9, 3, GEN_A, (0.0, 0.0)),
            location_setter: true,
            posts: 0,
            recycle_on_post: false,
            recycled_identity: (9, 3, GEN_B, (0.0, 0.0)),
        };
        assert_eq!(
            deliver_to_authenticated_ax_window(&mut dead, expected),
            Err(MacosAxDeliveryError::StaleTarget)
        );
        assert_eq!(dead.posts, 0);

        let mut no_setter = RecordingAxHost {
            live: true,
            identity: (9, 3, GEN_A, (0.0, 0.0)),
            location_setter: false,
            posts: 0,
            recycle_on_post: false,
            recycled_identity: (9, 3, GEN_B, (0.0, 0.0)),
        };
        assert_eq!(
            deliver_to_authenticated_ax_window(&mut no_setter, expected),
            Err(MacosAxDeliveryError::MissingWindowLocationSetter)
        );
        assert_eq!(no_setter.posts, 0);
    }

    #[test]
    fn deliver_to_authenticated_ax_window_refuses_recycled_generation_and_posts_only_to_held_ax() {
        let expected = opaque_macos_window_id(9, 3, GEN_A);
        let mut recycled_before_post = RecordingAxHost {
            live: true,
            identity: (9, 3, GEN_B, (0.0, 0.0)),
            location_setter: true,
            posts: 0,
            recycle_on_post: false,
            recycled_identity: (9, 3, GEN_B, (0.0, 0.0)),
        };
        assert_eq!(
            deliver_to_authenticated_ax_window(&mut recycled_before_post, expected),
            Err(MacosAxDeliveryError::StaleTarget)
        );
        assert_eq!(recycled_before_post.posts, 0);

        let mut ok = RecordingAxHost {
            live: true,
            identity: (9, 3, GEN_A, (1.0, 2.0)),
            location_setter: true,
            posts: 0,
            recycle_on_post: false,
            recycled_identity: (9, 3, GEN_B, (0.0, 0.0)),
        };
        assert_eq!(
            deliver_to_authenticated_ax_window(&mut ok, expected),
            Ok(())
        );
        assert_eq!(ok.posts, 1);

        let mut recycled_during_post = RecordingAxHost {
            live: true,
            identity: (9, 3, GEN_A, (1.0, 2.0)),
            location_setter: true,
            posts: 0,
            recycle_on_post: true,
            recycled_identity: (9, 3, GEN_B, (1.0, 2.0)),
        };
        assert_eq!(
            deliver_to_authenticated_ax_window(&mut recycled_during_post, expected),
            Err(MacosAxDeliveryError::AmbiguousDelivery)
        );
        assert_eq!(recycled_during_post.posts, 1);
    }
}

#[cfg(all(test, target_os = "macos"))]
mod macos_gui_tests {
    use super::*;

    #[test]
    #[ignore = "requires an interactive macOS login and Accessibility permission"]
    fn captures_focused_ax_evidence() {
        let mut adapter = MacOsTargetEvidenceAdapter::new().expect("construct AX adapter");
        let snapshot = adapter.capture_snapshot().expect("capture AX evidence");
        assert_eq!(snapshot.backend_kind, BackendKind::RealDesktopMacOs);
        assert!(snapshot.physical_target_key().is_ok());
        // Role is the focused widget, not the window. Window-only focus
        // leaves this unavailable rather than reporting AXWindow.
        if let FieldEvidence::Available { value, .. } = &snapshot.accessibility_role {
            assert_ne!(value.as_str(), "AXWindow");
            assert_ne!(value.as_str(), "AXApplication");
        }
        assert!(snapshot.process_id.is_available());
        assert!(snapshot.synchronous_recheck);
    }
}
