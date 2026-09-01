//! macOS target-evidence pure logic, callback gate, and typed literal tables.
//!
//! Real AppKit/AX/CoreGraphics queries run only on the owned adapter worker
//! (cfg target_os = "macos"). Required tests exercise pure logic and the
//! MacCallbackGate lifecycle without real desktop actions.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};

use crate::computer::host_identity::domain_hash;

#[cfg(target_os = "macos")]
use crate::computer::host_identity::{
    HostInstallationId, RealHostIdentityFs, SysHostIdentityRng, load_or_create_host_installation_id,
};
#[cfg(target_os = "macos")]
use crate::computer::target::{
    BackendKind, EvidenceSource, FieldEvidence, FocusGenerationReducer, OpaqueWindowId,
    RedactedHint, StableApplicationId, TargetEvidenceAdapter, TargetGeometry,
    TargetIdentityEvidence, TargetUnavailableReason, empty_unavailable,
};

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
    Role,
    Subrole,
    Title,
    Position,
    Size,
}

impl MacAxAttribute {
    pub const fn as_static_str(self) -> &'static str {
        match self {
            Self::FocusedApplication => "AXFocusedApplication",
            Self::FocusedWindow => "AXFocusedWindow",
            Self::Role => "AXRole",
            Self::Subrole => "AXSubrole",
            Self::Title => "AXTitle",
            Self::Position => "AXPosition",
            Self::Size => "AXSize",
        }
    }

    pub fn all() -> &'static [MacAxAttribute] {
        &[
            Self::FocusedApplication,
            Self::FocusedWindow,
            Self::Role,
            Self::Subrole,
            Self::Title,
            Self::Position,
            Self::Size,
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
        })
    }

    fn capture_macos_snapshot(
        &self,
    ) -> Result<TargetIdentityEvidence, TargetUnavailableReason> {
        use objc2_app_kit::NSWorkspace;
        use objc2_application_services::{AXUIElement, AXValue, AXValueType};
        use objc2_core_foundation::{CGPoint, CGSize, CFString};
        use objc2_core_graphics::{
            CGDisplayBounds, CGDisplayCopyDisplayMode, CGDisplayMode, CGError,
            CGGetActiveDisplayList,
        };

        let session = current_audit_session_id()?;
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
        let pid_status = unsafe {
            application.pid(std::ptr::NonNull::from(&mut ax_pid))
        };
        if pid_status != objc2_application_services::AXError::Success
            || u32::try_from(ax_pid).ok() != Some(frontmost_pid)
        {
            return Err(TargetUnavailableReason::QueryMismatch);
        }
        let window = ax_attribute(&application, MacAxAttribute::FocusedWindow)?
            .downcast::<AXUIElement>()
            .map_err(|_| TargetUnavailableReason::QueryMismatch)?;

        let position_value = ax_attribute(&window, MacAxAttribute::Position)?
            .downcast::<AXValue>()
            .map_err(|_| TargetUnavailableReason::QueryMismatch)?;
        let size_value = ax_attribute(&window, MacAxAttribute::Size)?
            .downcast::<AXValue>()
            .map_err(|_| TargetUnavailableReason::QueryMismatch)?;
        let mut position = CGPoint::default();
        let mut size = CGSize::default();
        // SAFETY: Both destinations are initialized, correctly aligned native
        // geometry values and remain live for the duration of each call.
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
        let display_uuid = unsafe {
            objc2_color_sync::CGDisplayCreateUUIDFromDisplayID(display_id)
        };
        let display_uuid_bytes: [u8; 16] = display_uuid.uuid_bytes().into();

        let role = ax_string(&window, MacAxAttribute::Role)?;
        let subrole = ax_optional_string(&window, MacAxAttribute::Subrole);
        let title = ax_optional_string(&window, MacAxAttribute::Title);
        let bundle_id = frontmost
            .bundleIdentifier()
            .map(|value| value.to_string());
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
        let recheck_status = unsafe {
            recheck_application.pid(std::ptr::NonNull::from(&mut recheck_ax_pid))
        };
        if recheck_status != objc2_application_services::AXError::Success
            || recheck_frontmost_pid != Some(frontmost_pid)
            || u32::try_from(recheck_ax_pid).ok() != Some(frontmost_pid)
        {
            return Err(TargetUnavailableReason::StaleTarget);
        }

        let window_hash = domain_hash(
            b"cockpit.macos.ax-window.v1",
            &[
                &frontmost_pid.to_le_bytes(),
                &position.x.to_bits().to_le_bytes(),
                &position.y.to_bits().to_le_bytes(),
                &size.width.to_bits().to_le_bytes(),
                &size.height.to_bits().to_le_bytes(),
            ],
        );
        let mut window_id = [0_u8; 16];
        window_id.copy_from_slice(&window_hash[..16]);

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
        snapshot.focused_window_id = FieldEvidence::available(
            OpaqueWindowId::from_bytes(window_id),
            EvidenceSource::Accessibility,
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
        snapshot.accessibility_role =
            FieldEvidence::available(role, EvidenceSource::Accessibility);
        snapshot.accessibility_subrole = optional_ax_field(subrole);
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
        self.observed_epoch = self
            .observed_epoch
            .checked_add(1)
            .ok_or(TargetUnavailableReason::EpochOverflow)?;
        snapshot.adapter_observed_epoch = self.observed_epoch;
        snapshot.focus_generation = self.reducer.observe(&snapshot)?;
        Ok(snapshot)
    }

    fn observed_focus_epoch(&self) -> u64 {
        self.observed_epoch
    }
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
    let status = unsafe {
        element.copy_attribute_value(&name, std::ptr::NonNull::from(&mut raw))
    };
    if status == AXError::APIDisabled {
        return Err(TargetUnavailableReason::PermissionDenied);
    }
    if status != AXError::Success {
        return Err(TargetUnavailableReason::FocusIdentityUnavailable);
    }
    let raw = std::ptr::NonNull::new(raw.cast_mut())
        .ok_or(TargetUnavailableReason::QueryMismatch)?;
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
        assert!(snapshot.accessibility_role.is_available());
        assert!(snapshot.process_id.is_available());
        assert!(snapshot.synchronous_recheck);
    }
}
