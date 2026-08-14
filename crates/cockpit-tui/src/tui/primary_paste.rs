//! Linux-only PRIMARY-selection paste capability.
//!
//! This module is deliberately separate from copy delivery, OSC52, and the
//! ordinary clipboard paste path. A PRIMARY read is allowed only when the
//! caller supplies a held authenticated local-display connection and a
//! reviewed adapter that consumes that connection. No production backend is
//! enabled: arboard's public Linux API reconnects via `Clipboard::new` and
//! cannot take a held stream.

use crate::clipboard::PlatformKind;

/// Opaque proof that a local display connection is already authenticated
/// and held by the caller. It is not a display path, environment name, or
/// reconnect handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeldLocalDisplayConnection {
    pub backend: PrimaryDisplayBackend,
    pub token: u64,
}

/// Display backends considered for PRIMARY paste.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrimaryDisplayBackend {
    /// A test fixture that already holds an authenticated local connection.
    WaylandHeld,
    /// X11 PRIMARY is unsupported: the public APIs reopen DISPLAY.
    X11,
    /// arboard `Clipboard::new` + `GetExtLinux::clipboard(Primary)` reconnects.
    ArboardReconnect,
    /// Unknown or unreviewed compositor protocol.
    Unknown,
}

/// Trust and platform facts for PRIMARY eligibility. Tests inject these;
/// production constructs them without mutating the process environment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrimaryPasteEnv {
    pub platform: PlatformKind,
    pub ssh: bool,
    pub wsl_or_container: bool,
    pub host_bridge: bool,
}

impl PrimaryPasteEnv {
    pub fn production() -> Self {
        let ctx = crate::clipboard::SessionContext::detect();
        Self {
            platform: ctx.platform,
            ssh: ctx.ssh,
            wsl_or_container: ctx.wsl_or_container,
            host_bridge: ctx.host_bridge,
        }
    }

    pub fn local_linux() -> Self {
        Self {
            platform: PlatformKind::Linux,
            ssh: false,
            wsl_or_container: false,
            host_bridge: false,
        }
    }
}

/// TUI layer that owns a middle-button press.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrimaryPasteLayer {
    Composer,
    Chat,
    Footer,
    ContextMenu,
    Settings,
    Dialog,
    Overlay,
    KeysOverlay,
    EmbeddedPane,
    BtwPane,
    SuggestionBox,
    Other,
}

/// Why PRIMARY paste must not run. Never includes display identity or
/// clipboard contents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrimaryPasteSkip {
    NotLinux,
    MouseCaptureOff,
    NotComposer,
    SshSession,
    WslOrContainer,
    HostBridge,
    UnsupportedBackend,
    NoHeldAuthenticatedConnection,
}

/// Content-free PRIMARY read outcome. Text is only present when a held
/// adapter produced plain text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrimaryPasteOutcome {
    Text(String),
    Empty,
    ImageOnly,
    Failed,
    Unsupported,
}

/// Adapter start result. Pending reads complete later through the
/// generation token; immediate results still go through the same
/// accept path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrimaryPasteBegin {
    Pending,
    Completed(PrimaryPasteOutcome),
    Rejected,
}

/// Snapshot of App-owned identity that a late PRIMARY result must still
/// match. Focus, composer, terminal, modal, and capture changes produce
/// a different epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrimaryPasteViewEpoch {
    pub terminal_generation: u64,
    pub draft_generation: u64,
    pub mouse_capture: bool,
    pub pane_focused: bool,
    pub composer_eligible: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingPrimaryPaste {
    pub generation: u64,
    pub correlation_id: uuid::Uuid,
    pub view: PrimaryPasteViewEpoch,
}

/// Sealed PRIMARY reader. Enabled implementations must consume `held`.
pub trait PrimaryPasteAdapter {
    fn read_primary(&self, held: &HeldLocalDisplayConnection) -> PrimaryPasteBegin;
}

/// Production backend: no reviewed adapter can consume a held connection.
#[derive(Debug, Default, Clone, Copy)]
pub struct UnsupportedPrimaryPasteAdapter;

impl PrimaryPasteAdapter for UnsupportedPrimaryPasteAdapter {
    fn read_primary(&self, _held: &HeldLocalDisplayConnection) -> PrimaryPasteBegin {
        PrimaryPasteBegin::Rejected
    }
}

/// Test adapter that only reads PRIMARY from a matching held token.
#[derive(Debug, Clone)]
pub struct FakeHeldPrimaryAdapter {
    pub required_token: u64,
    pub reads: std::rc::Rc<std::cell::Cell<u32>>,
    pub last_token: std::rc::Rc<std::cell::Cell<Option<u64>>>,
    pub immediate: std::rc::Rc<std::cell::RefCell<Option<PrimaryPasteOutcome>>>,
}

impl FakeHeldPrimaryAdapter {
    pub fn new(required_token: u64) -> Self {
        Self {
            required_token,
            reads: std::rc::Rc::new(std::cell::Cell::new(0)),
            last_token: std::rc::Rc::new(std::cell::Cell::new(None)),
            immediate: std::rc::Rc::new(std::cell::RefCell::new(None)),
        }
    }
}

impl PrimaryPasteAdapter for FakeHeldPrimaryAdapter {
    fn read_primary(&self, held: &HeldLocalDisplayConnection) -> PrimaryPasteBegin {
        self.reads.set(self.reads.get().saturating_add(1));
        self.last_token.set(Some(held.token));
        if held.backend != PrimaryDisplayBackend::WaylandHeld || held.token != self.required_token {
            return PrimaryPasteBegin::Rejected;
        }
        match self.immediate.borrow_mut().take() {
            Some(outcome) => PrimaryPasteBegin::Completed(outcome),
            None => PrimaryPasteBegin::Pending,
        }
    }
}

#[derive(Debug, Clone)]
enum InstalledAdapter {
    Unsupported,
    Fake(FakeHeldPrimaryAdapter),
}

/// Injectable PRIMARY capability and in-flight generation token.
#[derive(Debug, Clone)]
pub struct PrimaryPasteController {
    env: PrimaryPasteEnv,
    backend: PrimaryDisplayBackend,
    held: Option<HeldLocalDisplayConnection>,
    adapter: InstalledAdapter,
    generation: u64,
    pending: Option<PendingPrimaryPaste>,
    accepted_count: u32,
    last_accepted: Option<uuid::Uuid>,
}

impl Default for PrimaryPasteController {
    fn default() -> Self {
        Self::production()
    }
}

impl PrimaryPasteController {
    pub fn production() -> Self {
        Self {
            env: PrimaryPasteEnv::production(),
            backend: PrimaryDisplayBackend::ArboardReconnect,
            held: None,
            adapter: InstalledAdapter::Unsupported,
            generation: 0,
            pending: None,
            accepted_count: 0,
            last_accepted: None,
        }
    }

    pub fn for_test(env: PrimaryPasteEnv, adapter: FakeHeldPrimaryAdapter) -> Self {
        let held = (env.platform == PlatformKind::Linux
            && !env.ssh
            && !env.wsl_or_container
            && !env.host_bridge)
            .then_some(HeldLocalDisplayConnection {
                backend: PrimaryDisplayBackend::WaylandHeld,
                token: adapter.required_token,
            });
        Self {
            env,
            backend: if held.is_some() {
                PrimaryDisplayBackend::WaylandHeld
            } else {
                PrimaryDisplayBackend::Unknown
            },
            held,
            adapter: InstalledAdapter::Fake(adapter),
            generation: 0,
            pending: None,
            accepted_count: 0,
            last_accepted: None,
        }
    }

    pub fn env(&self) -> PrimaryPasteEnv {
        self.env
    }

    pub fn set_env(&mut self, env: PrimaryPasteEnv) {
        self.env = env;
        if env.ssh || env.wsl_or_container || env.host_bridge || env.platform != PlatformKind::Linux
        {
            self.held = None;
            if matches!(self.backend, PrimaryDisplayBackend::WaylandHeld) {
                self.backend = PrimaryDisplayBackend::Unknown;
            }
        }
    }

    pub fn set_backend(&mut self, backend: PrimaryDisplayBackend) {
        self.backend = backend;
        if !matches!(backend, PrimaryDisplayBackend::WaylandHeld) {
            self.held = None;
        }
    }

    pub fn set_held(&mut self, held: Option<HeldLocalDisplayConnection>) {
        self.held = held;
    }

    pub fn adapter_reads(&self) -> u32 {
        match &self.adapter {
            InstalledAdapter::Unsupported => 0,
            InstalledAdapter::Fake(adapter) => adapter.reads.get(),
        }
    }

    pub fn last_held_token(&self) -> Option<u64> {
        match &self.adapter {
            InstalledAdapter::Unsupported => None,
            InstalledAdapter::Fake(adapter) => adapter.last_token.get(),
        }
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn pending(&self) -> Option<PendingPrimaryPaste> {
        self.pending
    }

    pub fn accepted_count(&self) -> u32 {
        self.accepted_count
    }

    pub fn last_accepted(&self) -> Option<uuid::Uuid> {
        self.last_accepted
    }

    pub fn eligibility(
        &self,
        layer: PrimaryPasteLayer,
        mouse_capture: bool,
    ) -> Result<(), PrimaryPasteSkip> {
        eligibility(
            self.env,
            self.backend,
            self.held.as_ref(),
            layer,
            mouse_capture,
        )
    }

    /// Invalidate any in-flight PRIMARY read. Late results for the old
    /// generation become inert.
    pub fn invalidate(&mut self) {
        self.generation = self.generation.saturating_add(1);
        self.pending = None;
    }

    /// Start a PRIMARY read when every gate passes. The adapter is not
    /// invoked on any skip.
    pub fn consider_request(
        &mut self,
        layer: PrimaryPasteLayer,
        mouse_capture: bool,
        view: PrimaryPasteViewEpoch,
    ) -> Option<(u64, Option<PrimaryPasteOutcome>)> {
        if self.eligibility(layer, mouse_capture).is_err() {
            return None;
        }
        let held = self.held?;
        self.generation = self.generation.saturating_add(1);
        let generation = self.generation;
        let correlation_id = uuid::Uuid::new_v4();
        self.pending = Some(PendingPrimaryPaste {
            generation,
            correlation_id,
            view,
        });
        let begin = match &self.adapter {
            InstalledAdapter::Unsupported => PrimaryPasteBegin::Rejected,
            InstalledAdapter::Fake(adapter) => adapter.read_primary(&held),
        };
        match begin {
            PrimaryPasteBegin::Pending => Some((generation, None)),
            PrimaryPasteBegin::Completed(outcome) => Some((generation, Some(outcome))),
            PrimaryPasteBegin::Rejected => {
                self.pending = None;
                None
            }
        }
    }

    /// Apply a later adapter result. Only the matching generation and view
    /// may enqueue one NativePaste correlation.
    pub fn accept_result(
        &mut self,
        generation: u64,
        outcome: PrimaryPasteOutcome,
        view: PrimaryPasteViewEpoch,
    ) -> PrimaryPasteAccept {
        let Some(pending) = self.pending else {
            return PrimaryPasteAccept::Inert;
        };
        if pending.generation != generation {
            return PrimaryPasteAccept::Inert;
        }
        self.pending = None;
        if pending.view != view || !view.composer_eligible {
            return PrimaryPasteAccept::Inert;
        }
        match outcome {
            PrimaryPasteOutcome::Text(text) if !text.is_empty() => {
                self.accepted_count = self.accepted_count.saturating_add(1);
                self.last_accepted = Some(pending.correlation_id);
                PrimaryPasteAccept::Enqueue {
                    correlation_id: pending.correlation_id,
                    text,
                }
            }
            PrimaryPasteOutcome::Empty | PrimaryPasteOutcome::ImageOnly => {
                PrimaryPasteAccept::NoSelection
            }
            PrimaryPasteOutcome::Failed => PrimaryPasteAccept::Failed,
            PrimaryPasteOutcome::Text(_) | PrimaryPasteOutcome::Unsupported => {
                PrimaryPasteAccept::Inert
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrimaryPasteAccept {
    Enqueue {
        correlation_id: uuid::Uuid,
        text: String,
    },
    NoSelection,
    Failed,
    Inert,
}

pub fn eligibility(
    env: PrimaryPasteEnv,
    backend: PrimaryDisplayBackend,
    held: Option<&HeldLocalDisplayConnection>,
    layer: PrimaryPasteLayer,
    mouse_capture: bool,
) -> Result<(), PrimaryPasteSkip> {
    if env.platform != PlatformKind::Linux {
        return Err(PrimaryPasteSkip::NotLinux);
    }
    if !mouse_capture {
        return Err(PrimaryPasteSkip::MouseCaptureOff);
    }
    if layer != PrimaryPasteLayer::Composer {
        return Err(PrimaryPasteSkip::NotComposer);
    }
    if env.ssh {
        return Err(PrimaryPasteSkip::SshSession);
    }
    if env.wsl_or_container {
        return Err(PrimaryPasteSkip::WslOrContainer);
    }
    if env.host_bridge {
        return Err(PrimaryPasteSkip::HostBridge);
    }
    if !matches!(backend, PrimaryDisplayBackend::WaylandHeld) {
        return Err(PrimaryPasteSkip::UnsupportedBackend);
    }
    match held {
        Some(connection)
            if connection.backend == PrimaryDisplayBackend::WaylandHeld
                && connection.token != 0 =>
        {
            Ok(())
        }
        _ => Err(PrimaryPasteSkip::NoHeldAuthenticatedConnection),
    }
}
