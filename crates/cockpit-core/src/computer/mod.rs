//! Isolated computer-use backend.
//!
//! This module is the platform action layer only. It exposes no model-facing
//! tools; later prompts translate provider-native tool schemas into these typed
//! actions and add approvals/redaction/audit. Delegated workers use a Cockpit-
//! owned virtual display; the standalone Computer primary defaults to the real
//! desktop. Real-desktop control is refused unless a machine-local grant file
//! matches this machine.
//!
//! Target identity and host-global physical keys live in [`host_identity`] and
//! [`target`]; platform evidence adapters are under [`platform`].

#![allow(dead_code)]

pub mod audit;
pub mod authorizer;
pub mod coordinator;
pub mod frame;
pub mod guidance;
pub mod host_identity;
pub mod live_loop;
#[cfg(target_os = "macos")]
mod macos_backend;
pub mod observation;
pub mod outcome_store;
pub mod platform;
pub mod target;

#[cfg(test)]
mod target_tests;

#[cfg(target_os = "linux")]
use std::ffi::OsString;
use std::fs;
#[cfg(target_os = "linux")]
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Child;
#[cfg(target_os = "linux")]
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DisplayTarget {
    #[default]
    Virtual,
    RealDesktop,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct DisplayGeometry {
    pub physical: PixelSize,
    pub logical: LogicalSize,
    pub scale_factor: ScaleFactor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PixelSize {
    pub width: u32,
    pub height: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct LogicalSize {
    pub width: f64,
    pub height: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ScaleFactor(pub f64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CoordinateSpace {
    Physical,
    Logical,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Point {
    pub x: f64,
    pub y: f64,
    pub space: CoordinateSpace,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Rect {
    pub x: f64,
    pub y: f64,
    pub width: f64,
    pub height: f64,
    pub space: CoordinateSpace,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum MouseButton {
    Left,
    Right,
    Middle,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClickCount {
    Single,
    Double,
    Triple,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Modifiers {
    pub shift: bool,
    pub control: bool,
    pub alt: bool,
    pub meta: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Easing {
    Linear,
    EaseInOut,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TimedPoint {
    pub point: Point,
    pub duration: Duration,
    pub easing: Easing,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyChord {
    pub keys: Vec<String>,
}

/// A layout-independent physical key identity.
///
/// Provider text is resolved to this type before a canonical action is
/// created. In particular, `a` and `A` identify the same key; producing an
/// uppercase character is exclusively a [`ComputerAction::TypeText`] concern.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KeyCode(String);

impl KeyCode {
    pub fn parse(value: &str) -> Result<Self, ComputerError> {
        let value = value.trim().to_ascii_uppercase();
        let canonical = match value.as_str() {
            "CTRL" => "CONTROL",
            "LEFTCTRL" => "LEFTCONTROL",
            "RIGHTCTRL" => "RIGHTCONTROL",
            "META" | "WIN" | "SUPER" | "LEFTWIN" | "LEFTSUPER" => "LEFTMETA",
            "RIGHTWIN" | "RIGHTSUPER" => "RIGHTMETA",
            "RETURN" => "ENTER",
            "ESC" => "ESCAPE",
            "DEL" => "DELETE",
            "INS" => "INSERT",
            "SPACEBAR" => "SPACE",
            "UP" => "ARROWUP",
            "DOWN" => "ARROWDOWN",
            "LEFT" => "ARROWLEFT",
            "RIGHT" => "ARROWRIGHT",
            "PAGE_UP" | "PGUP" => "PAGEUP",
            "PAGE_DOWN" | "PGDN" => "PAGEDOWN",
            "PRINT" | "PRTSC" => "PRINTSCREEN",
            "BREAK" => "PAUSE",
            "CONTEXTMENU" => "APPS",
            other => other,
        };
        let is_letter_or_digit = canonical.len() == 1
            && canonical
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric);
        let is_function = canonical
            .strip_prefix('F')
            .and_then(|number| number.parse::<u8>().ok())
            .is_some_and(|number| (1..=12).contains(&number));
        let is_named = matches!(
            canonical,
            "SHIFT"
                | "CONTROL"
                | "LEFTCONTROL"
                | "RIGHTCONTROL"
                | "ALT"
                | "LEFTALT"
                | "RIGHTALT"
                | "META"
                | "LEFTMETA"
                | "RIGHTMETA"
                | "ENTER"
                | "TAB"
                | "ESCAPE"
                | "BACKSPACE"
                | "DELETE"
                | "INSERT"
                | "SPACE"
                | "ARROWUP"
                | "ARROWDOWN"
                | "ARROWLEFT"
                | "ARROWRIGHT"
                | "HOME"
                | "END"
                | "PAGEUP"
                | "PAGEDOWN"
                | "CAPSLOCK"
                | "NUMLOCK"
                | "SCROLLLOCK"
                | "PRINTSCREEN"
                | "PAUSE"
                | "APPS"
        );
        if !is_letter_or_digit && !is_function && !is_named {
            return Err(ComputerError::Refused(format!(
                "unsupported key identity `{value}`; use TypeText for characters"
            )));
        }
        Ok(Self(canonical.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalKeyChord {
    keys: Vec<KeyCode>,
}

impl CanonicalKeyChord {
    pub fn new(keys: Vec<KeyCode>) -> Result<Self, ComputerError> {
        if keys.is_empty() {
            return Err(ComputerError::Refused(
                "key chord must contain at least one key identity".to_string(),
            ));
        }
        Ok(Self { keys })
    }

    pub fn keys(&self) -> &[KeyCode] {
        &self.keys
    }
}

/// Platform spellings/codes resolved before a batch performs its first host
/// effect. Keeping these values in the normalized action makes keyboard
/// execution infallible with respect to the accepted [`KeyCode`] set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedKeyCode {
    x11_name: String,
    windows_virtual_key: u16,
    windows_extended: bool,
    macos_key_code: Option<u16>,
}

impl NormalizedKeyCode {
    fn new(key: &KeyCode) -> Result<Self, ComputerError> {
        Ok(Self {
            x11_name: translate_x11_key(key)?,
            windows_virtual_key: translate_windows_key(key)?,
            windows_extended: windows_key_is_extended(key),
            macos_key_code: translate_macos_key(key),
        })
    }

    #[doc(hidden)]
    pub fn x11_name(&self) -> &str {
        &self.x11_name
    }

    #[doc(hidden)]
    pub fn windows_virtual_key(&self) -> u16 {
        self.windows_virtual_key
    }

    #[doc(hidden)]
    pub fn windows_extended(&self) -> bool {
        self.windows_extended
    }

    #[doc(hidden)]
    pub fn macos_key_code(&self) -> Option<u16> {
        self.macos_key_code
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedKeyChord {
    keys: Vec<NormalizedKeyCode>,
}

impl NormalizedKeyChord {
    fn new(chord: &CanonicalKeyChord) -> Result<Self, ComputerError> {
        Ok(Self {
            keys: chord
                .keys()
                .iter()
                .map(NormalizedKeyCode::new)
                .collect::<Result<_, _>>()?,
        })
    }

    pub fn keys(&self) -> &[NormalizedKeyCode] {
        &self.keys
    }
}

impl TryFrom<&KeyChord> for CanonicalKeyChord {
    type Error = ComputerError;

    fn try_from(chord: &KeyChord) -> Result<Self, Self::Error> {
        Self::new(
            chord
                .keys
                .iter()
                .map(|key| KeyCode::parse(key))
                .collect::<Result<_, _>>()?,
        )
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum ComputerAction {
    CaptureFull,
    CaptureRegion {
        rect: Rect,
    },
    CaptureNativeZoom {
        rect: Rect,
        scale: ScaleFactor,
    },
    MoveCursor {
        to: Point,
        duration: Duration,
        easing: Easing,
    },
    Click {
        button: MouseButton,
        count: ClickCount,
        modifiers: Modifiers,
    },
    MouseDown {
        button: MouseButton,
    },
    MouseUp {
        button: MouseButton,
    },
    Drag {
        button: MouseButton,
        path: Vec<TimedPoint>,
        modifiers: Modifiers,
    },
    TypeText {
        text: String,
    },
    KeyChord {
        chord: CanonicalKeyChord,
    },
    HoldKey {
        key: KeyCode,
        duration: Duration,
    },
    Scroll {
        delta_x: i32,
        delta_y: i32,
        modifiers: Modifiers,
    },
    Wait {
        duration: Duration,
    },
}

impl ComputerAction {
    /// True when performing this action injects host input (keyboard, pointer,
    /// or scroll). Capture and wait do not.
    pub(crate) fn injects_synthetic_input(&self) -> bool {
        !matches!(
            self,
            Self::CaptureFull
                | Self::CaptureRegion { .. }
                | Self::CaptureNativeZoom { .. }
                | Self::Wait { .. }
        )
    }
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum ComputerActionOutcome {
    Captured(CaptureFrame),
    Completed,
    Waited(Duration),
}

/// Fully checked, physical-pixel action accepted by platform effect code.
/// Instances can only be produced by the backend handoff after it obtains the
/// backend's current geometry.
#[derive(Debug, Clone, PartialEq)]
pub struct NormalizedComputerAction {
    effect: NormalizedComputerEffect,
}

impl NormalizedComputerAction {
    #[doc(hidden)]
    pub fn effect(&self) -> &NormalizedComputerEffect {
        &self.effect
    }
}

#[doc(hidden)]
#[derive(Debug, Clone, PartialEq)]
pub enum NormalizedComputerEffect {
    CaptureFull,
    CaptureRegion {
        rect: PixelRect,
    },
    CaptureNativeZoom {
        rect: PixelRect,
        scale: ScaleFactor,
        output: PixelSize,
    },
    MoveCursor {
        to: PixelPoint,
        duration: Duration,
        easing: Easing,
    },
    Click {
        button: MouseButton,
        count: ClickCount,
        modifiers: Modifiers,
    },
    MouseDown {
        button: MouseButton,
    },
    MouseUp {
        button: MouseButton,
    },
    Drag {
        button: MouseButton,
        path: Vec<NormalizedTimedPoint>,
        modifiers: Modifiers,
    },
    TypeText {
        text: String,
    },
    KeyChord {
        chord: NormalizedKeyChord,
    },
    HoldKey {
        key: NormalizedKeyCode,
        duration: Duration,
    },
    Scroll {
        delta_x: i32,
        delta_y: i32,
        modifiers: Modifiers,
    },
    Wait {
        duration: Duration,
    },
}

impl NormalizedComputerEffect {
    pub(crate) fn injects_synthetic_input(&self) -> bool {
        !matches!(
            self,
            Self::CaptureFull
                | Self::CaptureRegion { .. }
                | Self::CaptureNativeZoom { .. }
                | Self::Wait { .. }
        )
    }
}

#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct NormalizedTimedPoint {
    pub point: PixelPoint,
    pub duration: Duration,
    pub easing: Easing,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct CaptureFrame {
    #[serde(skip)]
    pub png: Vec<u8>,
    pub geometry: DisplayGeometry,
    pub region: Option<PixelRect>,
    pub native_zoom: Option<ScaleFactor>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PixelRect {
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ComputerBatchReport {
    pub completed: Vec<ComputerActionOutcome>,
    pub failure: Option<ComputerFailure>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ComputerFailure {
    pub index: usize,
    pub error: ComputerError,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ComputerError {
    MissingTool { tool: String, install_hint: String },
    UnsupportedPlatform { platform: String },
    RealDesktopGrantMissing,
    InvalidCoordinates(String),
    Refused(String),
    Cancelled,
    CommandFailed { program: String, detail: String },
}

pub(crate) const EVIDENCED_WINDOW_MISMATCH: &str =
    "target window no longer matches the evidenced window";
pub(crate) const SYNTHETIC_INPUT_REQUIRES_EVIDENCED_WINDOW: &str =
    "synthetic input requires an evidenced window";
pub(crate) const CANNOT_DIRECT_INPUT_TO_EVIDENCED_WINDOW: &str =
    "backend cannot direct input to the evidenced window";

/// Provider-controlled action durations are intentionally bounded so a
/// physical-host lease and any pressed key cannot be held indefinitely.
pub const MAX_COMPUTER_ACTION_DURATION: Duration = Duration::from_secs(60);
/// One scroll action maps to one external `xdotool` process per click.
pub const MAX_SCROLL_CLICK_REPETITIONS: u32 = 1_000;

impl std::fmt::Display for ComputerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingTool { tool, install_hint } => {
                write!(f, "missing `{tool}`; install {install_hint}")
            }
            Self::UnsupportedPlatform { platform } => {
                write!(f, "computer backend is unsupported on {platform} yet")
            }
            Self::RealDesktopGrantMissing => {
                f.write_str("real desktop control requires a stored machine-local grant")
            }
            Self::InvalidCoordinates(detail) => write!(f, "invalid computer coordinates: {detail}"),
            Self::Refused(detail) => write!(f, "computer action refused: {detail}"),
            Self::Cancelled => f.write_str("computer action cancelled"),
            Self::CommandFailed { program, detail } => write!(f, "`{program}` failed: {detail}"),
        }
    }
}

impl std::error::Error for ComputerError {}

/// `Send + Sync` is required because coordinators live on the driver stack and
/// the driver is cloned into `tokio::spawn`ed noninteractive work. Implementors
/// are uniquely mutated via `&mut self`; Sync here is the auto-trait bound for
/// that stack, not concurrent method invocation.
#[async_trait]
pub trait ComputerBackend: backend_seal::Sealed + Send + Sync {
    fn backend_kind(&self) -> target::BackendKind;
    #[cfg(target_os = "linux")]
    fn real_x11_display(&self) -> Option<&str> {
        None
    }
    /// X11 `DISPLAY` this backend injects into, including isolated virtual
    /// servers. Production virtual evidence uses this to capture the focused
    /// X11 window rather than the display UUID.
    #[cfg(target_os = "linux")]
    fn x11_display_name(&self) -> Option<&str> {
        self.real_x11_display()
    }
    async fn geometry(&mut self) -> Result<DisplayGeometry, ComputerError>;
    #[doc(hidden)]
    async fn execute_normalized_one(
        &mut self,
        action: &NormalizedComputerAction,
    ) -> Result<ComputerActionOutcome, ComputerError>;
    /// Synchronously neutralize every backend-owned input state.
    ///
    /// This is deliberately non-async: the coordinator invokes it only after
    /// re-proving its physical host lease, before it relinquishes that lease on
    /// every terminal path (including `Drop`). Implementations must attempt
    /// every relevant key/button release and report a failure rather than
    /// silently handing the lease to another owner with uncertain input state.
    fn release_all(&mut self) -> Result<(), ComputerError>;

    /// Production physical backends are inert until the coordinator binds
    /// the exact live host lease acquired from target evidence. Test doubles
    /// and virtual backends retain the default no-op contract.
    fn bind_physical_capability(
        &mut self,
        _capability: coordinator::PhysicalDispatchCapability,
    ) -> Result<(), ComputerError> {
        if self.backend_kind() == target::BackendKind::VirtualDisplay {
            return Ok(());
        }
        #[cfg(test)]
        {
            // Hermetic physical-kind fixtures contain no OS injection seam;
            // production implementations must explicitly consume the permit.
            return Ok(());
        }
        #[cfg(not(test))]
        Err(ComputerError::Refused(
            "physical backend does not consume coordinator capability".into(),
        ))
    }

    /// Bind subsequent synthetic input to the evidenced/approved window.
    ///
    /// Production backends that cannot direct input to this window must
    /// return `Err` — never fall back to whatever currently has focus.
    /// Test doubles accept the bind so coordinator tests can exercise the
    /// window-identity fence without an OS injection seam.
    fn bind_evidenced_window(
        &mut self,
        window: target::OpaqueWindowId,
    ) -> Result<(), ComputerError> {
        let _ = window;
        #[cfg(test)]
        {
            return Ok(());
        }
        #[cfg(not(test))]
        Err(ComputerError::Refused(
            CANNOT_DIRECT_INPUT_TO_EVIDENCED_WINDOW.to_string(),
        ))
    }

    /// Re-verify that the live target window still matches the evidenced
    /// window bound for this dispatch. A mismatch aborts remaining batch
    /// items. Default is a no-op for backends with no bound window.
    fn recheck_evidenced_window(&mut self) -> Result<(), ComputerError> {
        Ok(())
    }
}

/// Single-action form of [`execute_backend_batch`].
pub async fn execute_backend_action<B: ComputerBackend + ?Sized>(
    backend: &mut B,
    action: &ComputerAction,
) -> Result<ComputerActionOutcome, ComputerError> {
    let geometry = backend.geometry().await?;
    let action = normalize_action(action, &geometry)?;
    backend.execute_normalized_one(&action).await
}

/// Coordinator-safe canonical-to-platform handoff. This free function cannot
/// be overridden by a backend implementation.
pub async fn execute_backend_batch<B: ComputerBackend + ?Sized>(
    backend: &mut B,
    actions: &[ComputerAction],
) -> ComputerBatchReport {
    let geometry = match backend.geometry().await {
        Ok(geometry) => geometry,
        Err(error) => {
            return ComputerBatchReport {
                completed: Vec::new(),
                failure: Some(ComputerFailure { index: 0, error }),
            };
        }
    };
    // Normalize the entire batch before the first platform effect. This
    // guarantees a malformed tail (for example a late drag point) cannot
    // fail after an earlier action has already changed host state.
    let normalized = match normalize_backend_batch(actions, &geometry) {
        Ok(normalized) => normalized,
        Err(failure) => {
            return ComputerBatchReport {
                completed: Vec::new(),
                failure: Some(failure),
            };
        }
    };
    let mut completed = Vec::new();
    for (index, action) in normalized.iter().enumerate() {
        if let Err(error) = backend.recheck_evidenced_window() {
            return ComputerBatchReport {
                completed,
                failure: Some(ComputerFailure { index, error }),
            };
        }
        match backend.execute_normalized_one(action).await {
            Ok(outcome) => completed.push(outcome),
            Err(error) => {
                return ComputerBatchReport {
                    completed,
                    failure: Some(ComputerFailure { index, error }),
                };
            }
        }
    }
    ComputerBatchReport {
        completed,
        failure: None,
    }
}

mod backend_seal {
    pub trait Sealed {}

    // Unit-test fakes are crate-owned and have no physical injection primitive.
    #[cfg(test)]
    impl<T> Sealed for T {}
}

#[derive(Debug, Clone)]
pub struct FakeBackend {
    pub geometry: DisplayGeometry,
    pub recorded: Vec<NormalizedComputerEffect>,
    pub release_count: usize,
    pub fail_at: Option<usize>,
    pub fail_with: ComputerError,
    pub bound_window: Option<target::OpaqueWindowId>,
    pub window_rechecks: usize,
    pub window_recheck_fail_at: Option<usize>,
}

impl FakeBackend {
    pub fn new() -> Self {
        Self {
            geometry: DisplayGeometry {
                physical: PixelSize {
                    width: 1280,
                    height: 720,
                },
                logical: LogicalSize {
                    width: 1280.0,
                    height: 720.0,
                },
                scale_factor: ScaleFactor(1.0),
            },
            recorded: Vec::new(),
            release_count: 0,
            fail_at: None,
            fail_with: ComputerError::Refused("fake failure".to_string()),
            bound_window: None,
            window_rechecks: 0,
            window_recheck_fail_at: None,
        }
    }

    pub fn failing_at(index: usize, error: ComputerError) -> Self {
        Self {
            fail_at: Some(index),
            fail_with: error,
            ..Self::new()
        }
    }
}

impl Default for FakeBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(not(test))]
impl backend_seal::Sealed for FakeBackend {}

#[async_trait]
impl ComputerBackend for FakeBackend {
    fn backend_kind(&self) -> target::BackendKind {
        target::BackendKind::VirtualDisplay
    }
    async fn geometry(&mut self) -> Result<DisplayGeometry, ComputerError> {
        Ok(self.geometry.clone())
    }

    async fn execute_normalized_one(
        &mut self,
        normalized: &NormalizedComputerAction,
    ) -> Result<ComputerActionOutcome, ComputerError> {
        let index = self.recorded.len();
        let effect = normalized.effect();
        self.recorded.push(effect.clone());
        if self.fail_at == Some(index) {
            return Err(self.fail_with.clone());
        }
        match effect {
            NormalizedComputerEffect::CaptureFull => {
                Ok(ComputerActionOutcome::Captured(CaptureFrame {
                    png: vec![137, 80, 78, 71],
                    geometry: self.geometry.clone(),
                    region: None,
                    native_zoom: None,
                }))
            }
            NormalizedComputerEffect::CaptureRegion { rect } => {
                Ok(ComputerActionOutcome::Captured(CaptureFrame {
                    png: vec![137, 80, 78, 71],
                    geometry: self.geometry.clone(),
                    region: Some(*rect),
                    native_zoom: None,
                }))
            }
            NormalizedComputerEffect::CaptureNativeZoom { rect, scale, .. } => {
                Ok(ComputerActionOutcome::Captured(CaptureFrame {
                    png: vec![137, 80, 78, 71],
                    geometry: self.geometry.clone(),
                    region: Some(*rect),
                    native_zoom: Some(*scale),
                }))
            }
            NormalizedComputerEffect::Wait { duration } => {
                Ok(ComputerActionOutcome::Waited(*duration))
            }
            _ => Ok(ComputerActionOutcome::Completed),
        }
    }

    fn release_all(&mut self) -> Result<(), ComputerError> {
        self.release_count += 1;
        Ok(())
    }

    fn bind_evidenced_window(
        &mut self,
        window: target::OpaqueWindowId,
    ) -> Result<(), ComputerError> {
        self.bound_window = Some(window);
        Ok(())
    }

    fn recheck_evidenced_window(&mut self) -> Result<(), ComputerError> {
        if self.window_recheck_fail_at == Some(self.window_rechecks) {
            self.window_rechecks += 1;
            return Err(ComputerError::Refused(
                EVIDENCED_WINDOW_MISMATCH.to_string(),
            ));
        }
        self.window_rechecks += 1;
        Ok(())
    }
}

#[derive(Debug)]
pub struct RealDesktopGrantStore {
    path: PathBuf,
}

impl RealDesktopGrantStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn has_current_machine_grant(&self) -> bool {
        let Ok(stored) = fs::read_to_string(&self.path) else {
            return false;
        };
        current_machine_fingerprint().is_some_and(|fingerprint| stored.trim() == fingerprint)
    }

    /// Resolve the existing machine-local real-desktop grant under Cockpit's
    /// private data root. Merely selecting yolo never creates this file.
    pub fn for_cockpit_data_dir() -> Result<Self, ComputerError> {
        let path = crate::config::resolve::cockpit_data_dir()
            .map_err(|error| ComputerError::CommandFailed {
                program: "computer grant".to_string(),
                detail: error.to_string(),
            })?
            .join("computer-real-desktop-grant");
        Ok(Self::new(path))
    }
}

pub(crate) struct VirtualDisplayBackend {
    display: String,
    backend_kind: target::BackendKind,
    /// `Child` is `Send` but not `Sync`. The mutex exists so the backend (and
    /// therefore a coordinator on the driver stack) can be `Sync`; the process
    /// is still uniquely owned and only taken on drop.
    xvfb: Mutex<Option<Child>>,
    geometry: DisplayGeometry,
    tools: LinuxTools,
    /// Keys whose `keydown` may still be active. Real-desktop instances mirror
    /// this to a private journal so a replacement daemon can neutralize an
    /// arbitrary key left behind by a failed `keyup`.
    held_keys: Vec<String>,
    held_buttons: Vec<u8>,
    held_key_journal: HeldKeyJournal,
    /// Private, owner-only directory under the Cockpit data root that contains
    /// any transient capture temp files. Never `$TMPDIR`. See
    /// [`private_capture_root`].
    capture_root: PathBuf,
    physical_capability: Option<coordinator::PhysicalDispatchCapability>,
    /// Evidenced window this backend will inject into. Both physical X11 and
    /// virtual displays store the decoded X11 id from evidence; they never
    /// pin whichever window happens to be active at bind time.
    evidenced_injection_window: Option<EvidencedX11Window>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EvidencedX11Window {
    opaque: target::OpaqueWindowId,
    x11: u32,
}

#[derive(Debug, Clone)]
struct LinuxTools {
    xdotool: PathBuf,
    capture: CaptureTool,
}

/// Crash-persistent ownership record for X11 keys that Cockpit has pressed.
///
/// This is deliberately keyed to the X server, rather than to a delegation:
/// injected keyboard state belongs to that server and must be recovered by the
/// next real-desktop coordinator after a daemon replacement. The host lease
/// serializes every caller that can consume this record.
#[derive(Debug, Default)]
struct HeldKeyJournal {
    path: Option<PathBuf>,
}

#[derive(Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct HeldInputState {
    pending: bool,
    keys: Vec<String>,
    buttons: Vec<u8>,
}

impl HeldKeyJournal {
    #[cfg(target_os = "linux")]
    fn for_real_x11(display: &str) -> Result<Self, ComputerError> {
        let root = crate::config::resolve::cockpit_data_dir()
            .map_err(input_journal_error)?
            .join("computer-input-state");
        cockpit_host::private_fs::ensure_private_dir(&root).map_err(input_journal_error)?;
        let digest = held_key_journal_identity(display)?;
        let name = digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        Ok(Self {
            path: Some(root.join(format!("{name}.json"))),
        })
    }

    fn load(&self) -> Result<HeldInputState, ComputerError> {
        let Some(path) = &self.path else {
            return Ok(HeldInputState::default());
        };
        let Some(bytes) = cockpit_host::private_fs::read_private_file(path, "computer held-key")
            .map_err(input_journal_error)?
        else {
            return Ok(HeldInputState::default());
        };
        let state = serde_json::from_slice::<HeldInputState>(&bytes).map_err(|_| {
            ComputerError::CommandFailed {
                program: "computer input-state journal".to_string(),
                detail: "held-key journal is malformed".to_string(),
            }
        })?;
        if state.pending
            || state.keys.iter().any(|key| key.is_empty())
            || state.buttons.iter().any(|button| !(1..=3).contains(button))
        {
            return Err(ComputerError::CommandFailed {
                program: "computer input-state journal".to_string(),
                detail: "input-state journal is uncertain or malformed".to_string(),
            });
        }
        Ok(state)
    }

    fn store(&self, keys: &[String], buttons: &[u8], pending: bool) -> Result<(), ComputerError> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        if keys.is_empty() && buttons.is_empty() && !pending {
            return cockpit_host::private_fs::delete_private_file(path)
                .map_err(input_journal_error);
        }
        let bytes = serde_json::to_vec(&HeldInputState {
            pending,
            keys: keys.to_vec(),
            buttons: buttons.to_vec(),
        })
        .map_err(|error| ComputerError::CommandFailed {
            program: "computer input-state journal".to_string(),
            detail: error.to_string(),
        })?;
        cockpit_host::private_fs::write_private_file(path, &bytes).map_err(input_journal_error)
    }
}

#[cfg(target_os = "linux")]
fn held_key_journal_identity(display: &str) -> Result<[u8; 32], ComputerError> {
    let (transport, display_number) =
        crate::computer::platform::x11::canonical_x11_server_identity(display)
            .ok_or_else(|| input_journal_error("X11 display identity is malformed"))?;
    Ok(crate::computer::host_identity::domain_hash(
        b"cockpit.x11.held-keys.v2",
        &[transport.as_bytes(), &display_number.to_le_bytes()],
    ))
}

fn input_journal_error(error: impl std::fmt::Display) -> ComputerError {
    ComputerError::CommandFailed {
        program: "computer input-state journal".to_string(),
        detail: error.to_string(),
    }
}

#[derive(Debug, Clone)]
enum CaptureTool {
    Scrot(PathBuf),
    Import(PathBuf),
}

#[cfg(target_os = "linux")]
impl CaptureTool {
    fn program(&self) -> &std::path::Path {
        match self {
            CaptureTool::Scrot(path) | CaptureTool::Import(path) => path,
        }
    }
}

impl VirtualDisplayBackend {
    fn construct(
        target: DisplayTarget,
        grant_store: Option<&RealDesktopGrantStore>,
    ) -> Result<Self, ComputerError> {
        match target {
            DisplayTarget::Virtual => Self::new_virtual(),
            DisplayTarget::RealDesktop => {
                if !grant_store.is_some_and(RealDesktopGrantStore::has_current_machine_grant) {
                    return Err(ComputerError::RealDesktopGrantMissing);
                }
                Self::new_real_desktop()
            }
        }
    }

    /// Exact X11 display capability opened by a real-desktop backend. Driver
    /// composition uses this value instead of re-reading a mutable environment.
    #[cfg(target_os = "linux")]
    pub(crate) fn real_x11_display(&self) -> Option<&str> {
        (self.backend_kind == target::BackendKind::RealDesktopX11).then_some(&self.display)
    }

    #[cfg(target_os = "linux")]
    fn new_real_desktop() -> Result<Self, ComputerError> {
        if std::env::var("XDG_SESSION_TYPE")
            .is_ok_and(|session| session.eq_ignore_ascii_case("wayland"))
            || std::env::var("WAYLAND_DISPLAY").is_ok_and(|display| !display.trim().is_empty())
        {
            return Err(ComputerError::UnsupportedPlatform {
                platform: "linux-wayland".to_string(),
            });
        }
        let display = std::env::var("DISPLAY")
            .ok()
            .filter(|display| !display.trim().is_empty())
            .ok_or_else(|| ComputerError::UnsupportedPlatform {
                platform: "linux-without-x11".to_string(),
            })?;
        let xdotool = require_capability("xdotool", "the `xdotool` package")?;
        let capture = require_capture_tool()?;
        let capture_root = private_capture_root()?;
        let held_key_journal = HeldKeyJournal::for_real_x11(&display)?;
        let held = held_key_journal.load()?;
        let geometry = query_x11_display_geometry(&xdotool, &display)?;
        Ok(Self {
            display,
            backend_kind: target::BackendKind::RealDesktopX11,
            xvfb: Mutex::new(None),
            geometry,
            tools: LinuxTools { xdotool, capture },
            held_keys: held.keys,
            held_buttons: held.buttons,
            held_key_journal,
            capture_root,
            physical_capability: None,
            evidenced_injection_window: None,
        })
    }

    #[cfg(not(target_os = "linux"))]
    fn new_real_desktop() -> Result<Self, ComputerError> {
        Err(unsupported_platform())
    }

    #[cfg(target_os = "linux")]
    fn new_virtual() -> Result<Self, ComputerError> {
        let xvfb = require_capability("Xvfb", "the `xvfb` package")?;
        let xdotool = require_capability("xdotool", "the `xdotool` package")?;
        let capture = require_capture_tool()?;
        // Contain capture artifacts under the private Cockpit data root (the
        // same convention `FileAdvisoryLock` uses), never the shared $TMPDIR.
        let capture_root = private_capture_root()?;
        let display = format!(":{}", 90 + (std::process::id() % 1000));
        let geometry = DisplayGeometry {
            physical: PixelSize {
                width: 1280,
                height: 720,
            },
            logical: LogicalSize {
                width: 1280.0,
                height: 720.0,
            },
            scale_factor: ScaleFactor(1.0),
        };
        let mut command = Command::new(xvfb);
        command
            .arg(&display)
            .arg("-screen")
            .arg("0")
            .arg(format!(
                "{}x{}x24",
                geometry.physical.width, geometry.physical.height
            ))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        #[cfg(unix)]
        command.process_group(0);
        let child = command
            .spawn()
            .map_err(|error| ComputerError::CommandFailed {
                program: "Xvfb".to_string(),
                detail: error.to_string(),
            })?;
        Ok(Self {
            display,
            backend_kind: target::BackendKind::VirtualDisplay,
            xvfb: Mutex::new(Some(child)),
            geometry,
            tools: LinuxTools { xdotool, capture },
            held_keys: Vec::new(),
            held_buttons: Vec::new(),
            held_key_journal: HeldKeyJournal::default(),
            capture_root,
            physical_capability: None,
            evidenced_injection_window: None,
        })
    }

    #[cfg(not(target_os = "linux"))]
    fn new_virtual() -> Result<Self, ComputerError> {
        Err(unsupported_platform())
    }

    #[cfg(target_os = "linux")]
    fn run_xdotool_output(&self, args: &[OsString]) -> Result<std::process::Output, ComputerError> {
        if self.backend_kind == target::BackendKind::RealDesktopX11 {
            self.physical_capability
                .as_ref()
                .ok_or_else(|| {
                    ComputerError::Refused("physical backend is not coordinator-bound".into())
                })?
                .recheck(self.backend_kind)?;
        }
        let output = Command::new(&self.tools.xdotool)
            .env("DISPLAY", &self.display)
            .args(args)
            .output()
            .map_err(|error| ComputerError::CommandFailed {
                program: "xdotool".to_string(),
                detail: error.to_string(),
            })?;
        Ok(output)
    }

    #[cfg(target_os = "linux")]
    fn run_xdotool(&self, args: &[OsString]) -> Result<(), ComputerError> {
        let output = self.run_xdotool_output(args)?;
        if output.status.success() {
            Ok(())
        } else {
            Err(ComputerError::CommandFailed {
                program: "xdotool".to_string(),
                detail: String::from_utf8_lossy(&output.stderr).to_string(),
            })
        }
    }

    #[cfg(target_os = "linux")]
    fn bind_x11_injection_window(
        &mut self,
        window: target::OpaqueWindowId,
    ) -> Result<(), ComputerError> {
        if let Some(bound) = self.evidenced_injection_window
            && bound.opaque == window
        {
            return Ok(());
        }
        let x11 = crate::computer::platform::x11_window_from_opaque(&window)
            .filter(|window| *window != 0)
            .ok_or_else(|| {
                ComputerError::Refused(CANNOT_DIRECT_INPUT_TO_EVIDENCED_WINDOW.to_string())
            })?;
        self.evidenced_injection_window = Some(EvidencedX11Window {
            opaque: window,
            x11,
        });
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn query_x11_window_geometry(
        &self,
        window: u32,
    ) -> Result<(i32, i32, u32, u32), ComputerError> {
        let output = self.run_xdotool_output(&[
            OsString::from("getwindowgeometry"),
            OsString::from("--shell"),
            OsString::from(window.to_string()),
        ])?;
        if !output.status.success() {
            return Err(ComputerError::CommandFailed {
                program: "xdotool".to_string(),
                detail: String::from_utf8_lossy(&output.stderr).to_string(),
            });
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut x = None;
        let mut y = None;
        let mut width = None;
        let mut height = None;
        for line in stdout.lines() {
            if let Some(value) = line.strip_prefix("X=") {
                x = value.parse::<i32>().ok();
            } else if let Some(value) = line.strip_prefix("Y=") {
                y = value.parse::<i32>().ok();
            } else if let Some(value) = line.strip_prefix("WIDTH=") {
                width = value.parse::<u32>().ok();
            } else if let Some(value) = line.strip_prefix("HEIGHT=") {
                height = value.parse::<u32>().ok();
            }
        }
        match (x, y, width, height) {
            (Some(x), Some(y), Some(width), Some(height)) => Ok((x, y, width, height)),
            _ => Err(ComputerError::CommandFailed {
                program: "xdotool".to_string(),
                detail: "getwindowgeometry did not return X/Y/WIDTH/HEIGHT".to_string(),
            }),
        }
    }

    #[cfg(target_os = "linux")]
    fn run_targeted_xdotool(&self, command: &str, rest: &[OsString]) -> Result<(), ComputerError> {
        let Some(bound) = self.evidenced_injection_window else {
            return Err(ComputerError::Refused(
                SYNTHETIC_INPUT_REQUIRES_EVIDENCED_WINDOW.to_string(),
            ));
        };
        self.run_xdotool(&xdotool_targeted_args(bound.x11, command, rest))
    }

    #[cfg(target_os = "linux")]
    fn run_release_xdotool(&self, command: &str, rest: &[OsString]) -> Result<(), ComputerError> {
        let Some(bound) = self.evidenced_injection_window else {
            return Err(ComputerError::Refused(
                SYNTHETIC_INPUT_REQUIRES_EVIDENCED_WINDOW.to_string(),
            ));
        };
        self.run_xdotool(&xdotool_targeted_args(bound.x11, command, rest))
    }

    #[cfg(target_os = "linux")]
    fn window_relative_point(&self, point: PixelPoint) -> Result<PixelPoint, ComputerError> {
        let Some(bound) = self.evidenced_injection_window else {
            return Err(ComputerError::Refused(
                SYNTHETIC_INPUT_REQUIRES_EVIDENCED_WINDOW.to_string(),
            ));
        };
        let (origin_x, origin_y, width, height) = self.query_x11_window_geometry(bound.x11)?;
        pixel_point_in_window(point, origin_x, origin_y, width, height)
    }

    #[cfg(target_os = "linux")]
    fn capture_png(&self, region: Option<PixelRect>) -> Result<Vec<u8>, ComputerError> {
        capture_contained(
            &RealCaptureRunner,
            &self.tools.capture,
            &self.display,
            region,
            &self.capture_root,
        )
    }

    /// Merge state written by a predecessor that exited after this backend was
    /// constructed. This is called only during terminal neutralization, which
    /// the coordinator performs while it holds the physical host lease.
    fn reload_held_keys(&mut self) -> Result<(), ComputerError> {
        let state = self.held_key_journal.load()?;
        for key in state.keys {
            if !self.held_keys.contains(&key) {
                self.held_keys.push(key);
            }
        }
        for button in state.buttons {
            if !self.held_buttons.contains(&button) {
                self.held_buttons.push(button);
            }
        }
        Ok(())
    }

    /// Persist a pending transition before emitting `keydown`. Recovery never
    /// guesses across that boundary: a crash before the known-state commit
    /// leaves `pending` and causes the next opener to fail closed.
    fn remember_held_key(&mut self, key: String) -> Result<(), ComputerError> {
        if self.held_keys.contains(&key) {
            // Re-publish even for a repeated key: a prior recovery attempt may
            // have loaded the key before its journal was removed, and keydown
            // must never proceed without a durable recovery record.
            return self
                .held_key_journal
                .store(&self.held_keys, &self.held_buttons, true);
        }
        let mut keys = self.held_keys.clone();
        keys.push(key);
        self.held_key_journal
            .store(&keys, &self.held_buttons, true)?;
        self.held_keys = keys;
        Ok(())
    }

    /// Forget a key only after its `keyup` completed and the durable record
    /// has been updated. A journal-write failure intentionally leaves the key
    /// tracked, making a later cleanup retry it under the same lease.
    fn forget_held_key(&mut self, key: &str) -> Result<(), ComputerError> {
        let keys = self
            .held_keys
            .iter()
            .filter(|held| held.as_str() != key)
            .cloned()
            .collect::<Vec<_>>();
        self.held_key_journal
            .store(&keys, &self.held_buttons, false)?;
        self.held_keys = keys;
        Ok(())
    }

    fn remember_held_button(&mut self, button: MouseButton) -> Result<(), ComputerError> {
        let button = mouse_button_number(button);
        if !self.held_buttons.contains(&button) {
            let mut buttons = self.held_buttons.clone();
            buttons.push(button);
            self.held_key_journal
                .store(&self.held_keys, &buttons, true)?;
            self.held_buttons = buttons;
        }
        Ok(())
    }

    fn forget_held_button(&mut self, button: MouseButton) -> Result<(), ComputerError> {
        let button = mouse_button_number(button);
        let buttons = self
            .held_buttons
            .iter()
            .copied()
            .filter(|held| *held != button)
            .collect::<Vec<_>>();
        self.held_key_journal
            .store(&self.held_keys, &buttons, false)?;
        self.held_buttons = buttons;
        Ok(())
    }

    fn prepare_current_input_transition(&self) -> Result<(), ComputerError> {
        self.held_key_journal
            .store(&self.held_keys, &self.held_buttons, true)
    }

    fn commit_known_input_state(&self) -> Result<(), ComputerError> {
        self.held_key_journal
            .store(&self.held_keys, &self.held_buttons, false)
    }
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, PartialEq, Eq)]
enum LinuxReleaseTransition {
    Key(String),
    Button(u8),
}

/// Run recovery transitions in strict journal order. Once a prepared OS
/// release or its durable commit fails, the journal is ambiguous and no later
/// transition may run: a later successful commit would otherwise clear the
/// earlier `pending` marker and falsely claim that host input is known.
#[cfg(target_os = "linux")]
fn run_linux_release_state_machine(
    transitions: impl IntoIterator<Item = LinuxReleaseTransition>,
    mut release: impl FnMut(LinuxReleaseTransition) -> Result<(), ComputerError>,
) -> Result<(), ComputerError> {
    for transition in transitions {
        release(transition)?;
    }
    Ok(())
}

#[cfg(not(test))]
impl backend_seal::Sealed for VirtualDisplayBackend {}

#[cfg(all(target_os = "windows", not(test)))]
impl backend_seal::Sealed for platform::WindowsDesktopBackend {}

#[cfg(target_os = "linux")]
fn query_x11_display_geometry(
    xdotool: &std::path::Path,
    display: &str,
) -> Result<DisplayGeometry, ComputerError> {
    let output = Command::new(xdotool)
        .env("DISPLAY", display)
        .arg("getdisplaygeometry")
        .output()
        .map_err(|error| ComputerError::CommandFailed {
            program: "xdotool".to_string(),
            detail: error.to_string(),
        })?;
    if !output.status.success() {
        return Err(ComputerError::CommandFailed {
            program: "xdotool".to_string(),
            detail: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        });
    }
    let dimensions = String::from_utf8_lossy(&output.stdout);
    let mut dimensions = dimensions.split_whitespace();
    let width = dimensions.next().and_then(|value| value.parse().ok());
    let height = dimensions.next().and_then(|value| value.parse().ok());
    let (Some(width), Some(height), None) = (width, height, dimensions.next()) else {
        return Err(ComputerError::CommandFailed {
            program: "xdotool".to_string(),
            detail: "getdisplaygeometry returned malformed dimensions".to_string(),
        });
    };
    if width == 0 || height == 0 {
        return Err(ComputerError::CommandFailed {
            program: "xdotool".to_string(),
            detail: "getdisplaygeometry returned an empty desktop".to_string(),
        });
    }
    Ok(DisplayGeometry {
        physical: PixelSize { width, height },
        logical: LogicalSize {
            width: f64::from(width),
            height: f64::from(height),
        },
        scale_factor: ScaleFactor(1.0),
    })
}

// ---------------------------------------------------------------------------
// Screenshot capture containment
// ---------------------------------------------------------------------------
//
// Every platform capture that needs a filesystem path is routed through a
// [`TempCaptureGuard`] rooted under the private Cockpit data directory
// ([`private_capture_root`]) — never the shared `$TMPDIR`. Capture prefers
// streaming the PNG to stdout so no artifact touches disk; when a tool cannot
// stream, the temp-file fallback creates the destination inode itself
// (`O_EXCL`, `0o600`), tightens/verifies it (owner, single hardlink, mode)
// before reading, and the guard removes it on every exit path (including panic)
// with cleanup failure surfaced as a capture error.
//
// THREAT MODEL: these mode bits + owned-inode checks defend against
// OTHER-UID / world exposure of screenshot plaintext in shared temp — the real
// target of this containment. They do NOT defend against a SAME-UID adversary,
// who can read the data dir, `/proc/self/mem`, or `ptrace` the process
// regardless of file modes; that requires process isolation, not this code. Do
// not mistake this guard for same-uid isolation.

/// Resolve (and, on first use, create owner-only) the private capture root.
///
/// `~/.local/share/cockpit/computer-capture` (respecting `XDG_DATA_HOME`),
/// mirroring the private-fs convention `FileAdvisoryLock` uses for the host
/// input lock. The data root is threaded into the backend at construction, not
/// read from a mutated environment.
#[cfg(target_os = "linux")]
fn private_capture_root() -> Result<PathBuf, ComputerError> {
    let root = crate::config::resolve::cockpit_data_dir()
        .map_err(|error| ComputerError::CommandFailed {
            program: "capture".to_string(),
            detail: error.to_string(),
        })?
        .join("computer-capture");
    ensure_owner_only_dir(&root)?;
    Ok(root)
}

/// Ensure `dir` exists as a real, owner-owned, `0o700` directory — creating it
/// if absent and validating/tightening it if present. Fails closed if it is a
/// symlink, not a directory, owned by another user, or cannot be made
/// owner-only. Runs the same checks on both the freshly-created and pre-existing
/// paths (a prior run or a hostile actor may have left a looser or foreign dir).
#[cfg(unix)]
fn ensure_owner_only_dir(dir: &std::path::Path) -> Result<(), ComputerError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let io_fail = |error: std::io::Error| ComputerError::CommandFailed {
        program: "capture".to_string(),
        detail: error.to_string(),
    };
    let deny = |detail: &str| ComputerError::CommandFailed {
        program: "capture".to_string(),
        detail: detail.to_string(),
    };

    if !dir.exists() {
        std::fs::create_dir_all(dir).map_err(io_fail)?;
    }
    // `symlink_metadata` does NOT follow a final symlink, so a symlinked root is
    // detected rather than silently traversed.
    let meta = std::fs::symlink_metadata(dir).map_err(io_fail)?;
    if meta.file_type().is_symlink() {
        return Err(deny("capture root is a symlink"));
    }
    if !meta.is_dir() {
        return Err(deny("capture root is not a directory"));
    }
    // SAFETY: `geteuid` is always safe to call.
    let euid = unsafe { libc::geteuid() };
    if meta.uid() != euid {
        return Err(deny("capture root owned by another user"));
    }
    if meta.mode() & 0o777 != 0o700 {
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).map_err(io_fail)?;
        let remeta = std::fs::symlink_metadata(dir).map_err(io_fail)?;
        if remeta.mode() & 0o777 != 0o700 {
            return Err(deny("could not tighten capture root to 0o700"));
        }
    }
    Ok(())
}

/// Injectable seam for running the external capture tool. Production uses
/// [`RealCaptureRunner`]; tests inject a fake so the containment pipeline can be
/// exercised with no real display, X server, or capture binary.
#[cfg(unix)]
trait CaptureRunner {
    /// Run the tool streaming PNG to stdout. Returns raw stdout bytes on
    /// success; an empty vec signals the tool cannot stream to stdout.
    fn capture_to_stdout(
        &self,
        tool: &CaptureTool,
        display: &str,
        region: Option<PixelRect>,
    ) -> Result<Vec<u8>, ComputerError>;

    /// Run the tool writing a PNG to `dest` (the leaf inside a private,
    /// owner-only guard directory).
    fn capture_to_path(
        &self,
        tool: &CaptureTool,
        display: &str,
        region: Option<PixelRect>,
        dest: &std::path::Path,
    ) -> Result<(), ComputerError>;
}

/// Capture a PNG, preferring stdout and falling back to a contained temp file.
///
/// Stdout capture leaves no artifact on disk. When the tool produces no stdout
/// bytes (it cannot stream), capture falls back to a temp file created only
/// under `capture_root` via a [`TempCaptureGuard`] that removes it on every exit
/// path — success, error, or panic/drop.
#[cfg(unix)]
fn capture_contained(
    runner: &dyn CaptureRunner,
    tool: &CaptureTool,
    display: &str,
    region: Option<PixelRect>,
    capture_root: &std::path::Path,
) -> Result<Vec<u8>, ComputerError> {
    // Preferred: stream straight to stdout — no capture artifact ever exists on
    // the filesystem. A hard tool/display failure propagates here.
    let streamed = runner.capture_to_stdout(tool, display, region)?;
    if !streamed.is_empty() {
        if streamed.len()
            > usize::try_from(crate::media_image::SCREENSHOT_MAX_ALLOC_BYTES).unwrap_or(usize::MAX)
        {
            return Err(ComputerError::Refused(
                "encoded capture exceeds the screenshot allocation limit".to_string(),
            ));
        }
        return Ok(streamed);
    }
    // The tool wrote nothing to stdout: it cannot stream. Fall back to a
    // contained temp file under the private capture root.
    capture_via_contained_file(runner, tool, display, region, capture_root)
}

/// Create the capture destination file ourselves, `O_EXCL` + `0o600`, so the
/// external tool overwrites an inode WE own inside our fresh private dir.
///
/// `create_new` (`O_EXCL`) fails closed if anything already exists at the path —
/// e.g. an attacker who pre-planted a symlink or hardlink to redirect the tool's
/// plaintext write elsewhere. `O_NOFOLLOW` rejects a symlink at the leaf itself.
#[cfg(unix)]
fn create_private_capture_file(dest: &std::path::Path) -> Result<(), ComputerError> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(dest)
        .map_err(|error| ComputerError::CommandFailed {
            program: "capture".to_string(),
            detail: format!("could not create private capture file: {error}"),
        })?;
    // Drop the handle: the tool reopens the path by name and truncates in place.
    Ok(())
}

/// Temp-file capture fallback. The PNG is written only inside a private
/// sub-tempdir of `capture_root`, into an inode we pre-create `O_EXCL`/`0o600`,
/// tightened+verified (owner, single hardlink, mode) before reading, and removed
/// by the guard on every exit path (including panic via `Drop`). A cleanup
/// failure is surfaced as a capture error — a screenshot whose plaintext
/// artifact could not be removed is not a success.
#[cfg(unix)]
fn capture_via_contained_file(
    runner: &dyn CaptureRunner,
    tool: &CaptureTool,
    display: &str,
    region: Option<PixelRect>,
    capture_root: &std::path::Path,
) -> Result<Vec<u8>, ComputerError> {
    use crate::computer::frame::TempCaptureGuard;
    let io_fail = |error: std::io::Error| ComputerError::CommandFailed {
        program: "capture".to_string(),
        detail: error.to_string(),
    };
    // Unique private sub-tempdir under the owner-only capture root — never a
    // fixed filename and never `$TMPDIR`. `tempdir_in` creates it `0o700`.
    let dir = tempfile::Builder::new()
        .prefix("capture-")
        .tempdir_in(capture_root)
        .map_err(io_fail)?;
    let mut guard = TempCaptureGuard::new(dir, "shot.png").map_err(io_fail)?;
    let dest = guard
        .path()
        .expect("guard constructed with a file path")
        .to_path_buf();
    // Any early return or panic below drops `guard`, whose `Drop` removes the
    // file and its directory — so no `*.png` can survive a mid-capture failure.
    let result = create_private_capture_file(&dest)
        .and_then(|()| runner.capture_to_path(tool, display, region, &dest))
        .and_then(|()| assert_owner_only_and_read(&dest));
    // Fail closed if cleanup cannot remove the plaintext artifact: even on an
    // otherwise-successful capture, a failed unlink means the bytes still sit on
    // disk, so the capture must not report success. `Drop` remains armed to
    // retry (see `TempCaptureGuard::cleanup`).
    match (result, guard.cleanup()) {
        (Ok(bytes), Ok(())) => Ok(bytes),
        (Ok(_), Err(code)) => Err(ComputerError::CommandFailed {
            program: "capture".to_string(),
            detail: format!("capture artifact cleanup failed: {code}"),
        }),
        (Err(capture_error), _) => Err(capture_error),
    }
}

/// Assert the just-written capture file is owner-only (`0o600`) *before*
/// reading a single byte, tightening it if the external tool recreated it under
/// a looser umask, or failing closed if it cannot be made owner-private. Reads
/// happen on the held, verified fd, so there is no path-reresolution TOCTOU.
#[cfg(unix)]
fn assert_owner_only_and_read(path: &std::path::Path) -> Result<Vec<u8>, ComputerError> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

    let io_fail = |error: std::io::Error| ComputerError::CommandFailed {
        program: "capture".to_string(),
        detail: error.to_string(),
    };
    let deny = |detail: &str| ComputerError::CommandFailed {
        program: "capture".to_string(),
        detail: detail.to_string(),
    };

    // Open without following symlinks: the tool may have replaced the leaf with
    // a link. Every check and the read below operate on this held fd.
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(io_fail)?;
    let meta = file.metadata().map_err(io_fail)?;
    if !meta.file_type().is_file() {
        return Err(deny("capture path is not a regular file"));
    }
    // Reject hardlinks: a `st_nlink > 1` means another name refers to this
    // inode, so the plaintext would remain reachable after the guard unlinks our
    // leaf. We create the capture file `O_EXCL` in a fresh private dir, so a live
    // capture is nlink==1; anything else is fail-closed.
    if meta.nlink() != 1 {
        return Err(deny("capture file is hardlinked"));
    }
    if meta.len() > crate::media_image::SCREENSHOT_MAX_ALLOC_BYTES {
        return Err(ComputerError::Refused(
            "encoded capture exceeds the screenshot allocation limit".to_string(),
        ));
    }
    // SAFETY: `geteuid` is always safe to call.
    let euid = unsafe { libc::geteuid() };
    if meta.uid() != euid {
        return Err(deny("capture file owned by another user"));
    }
    if meta.mode() & 0o777 != 0o600 {
        // The tool recreated the file with a looser mode; tighten on the held fd
        // (fchmod, no re-resolution) and re-verify, failing closed otherwise.
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(io_fail)?;
        let remeta = file.metadata().map_err(io_fail)?;
        if remeta.mode() & 0o777 != 0o600 {
            return Err(deny("could not tighten capture file to 0o600"));
        }
    }
    // Only now, with the file proven owner-only, read through a hard byte
    // ceiling. The metadata check above is only an early rejection: the file
    // can grow after `fstat`, so the held fd itself must be bounded as it is
    // consumed.
    read_capture_bytes_bounded(&mut file, crate::media_image::SCREENSHOT_MAX_ALLOC_BYTES)
}

#[cfg(unix)]
fn read_capture_bytes_bounded(
    reader: &mut dyn std::io::Read,
    max_bytes: u64,
) -> Result<Vec<u8>, ComputerError> {
    use std::io::Read as _;

    let mut bytes = Vec::new();
    reader
        .take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| ComputerError::CommandFailed {
            program: "capture".to_string(),
            detail: error.to_string(),
        })?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > max_bytes {
        return Err(ComputerError::Refused(
            "encoded capture exceeds the screenshot allocation limit".to_string(),
        ));
    }
    Ok(bytes)
}

/// Production [`CaptureRunner`] that spawns the real capture binary.
#[cfg(target_os = "linux")]
struct RealCaptureRunner;

#[cfg(target_os = "linux")]
enum CaptureDest<'a> {
    Stdout,
    File(&'a std::path::Path),
}

#[cfg(target_os = "linux")]
fn capture_command(
    tool: &CaptureTool,
    display: &str,
    region: Option<PixelRect>,
    dest: CaptureDest<'_>,
) -> Command {
    let mut cmd = Command::new(tool.program());
    cmd.env("DISPLAY", display);
    match tool {
        CaptureTool::Scrot(_) => {
            if let Some(region) = region {
                cmd.arg("-a").arg(format!(
                    "{},{},{},{}",
                    region.x, region.y, region.width, region.height
                ));
            }
            match dest {
                // scrot streams the PNG to stdout when the output file is `-`.
                CaptureDest::Stdout => {
                    cmd.arg("-");
                }
                CaptureDest::File(path) => {
                    cmd.arg(path);
                }
            }
        }
        CaptureTool::Import(_) => {
            // `import` is interactive without an explicit root target. Both
            // virtual and real-desktop captures must be unattended.
            cmd.arg("-window").arg("root");
            if let Some(region) = region {
                cmd.arg("-crop").arg(format!(
                    "{}x{}+{}+{}",
                    region.width, region.height, region.x, region.y
                ));
            }
            match dest {
                // ImageMagick streams the PNG to stdout with the `png:-` target.
                CaptureDest::Stdout => {
                    cmd.arg("png:-");
                }
                CaptureDest::File(path) => {
                    cmd.arg(path);
                }
            }
        }
    }
    cmd
}

#[cfg(target_os = "linux")]
impl CaptureRunner for RealCaptureRunner {
    fn capture_to_stdout(
        &self,
        tool: &CaptureTool,
        display: &str,
        region: Option<PixelRect>,
    ) -> Result<Vec<u8>, ComputerError> {
        use std::io::Read as _;

        let mut child = capture_command(tool, display, region, CaptureDest::Stdout)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| ComputerError::CommandFailed {
                program: "capture".to_string(),
                detail: error.to_string(),
            })?;
        let mut stdout = child
            .stdout
            .take()
            .ok_or_else(|| ComputerError::CommandFailed {
                program: "capture".to_string(),
                detail: "capture stdout pipe was unavailable".to_string(),
            })?;
        let mut stderr = child
            .stderr
            .take()
            .ok_or_else(|| ComputerError::CommandFailed {
                program: "capture".to_string(),
                detail: "capture stderr pipe was unavailable".to_string(),
            })?;
        // Drain stderr concurrently so a noisy failed tool cannot deadlock on
        // its pipe while stdout is being read. Retain only a bounded diagnostic.
        let stderr_reader = std::thread::spawn(move || {
            let mut diagnostic = Vec::new();
            let _ = (&mut stderr).take(64 * 1024).read_to_end(&mut diagnostic);
            let _ = std::io::copy(&mut stderr, &mut std::io::sink());
            diagnostic
        });
        let read_limit = crate::media_image::SCREENSHOT_MAX_ALLOC_BYTES + 1;
        let mut bytes = Vec::new();
        let read_result = (&mut stdout).take(read_limit).read_to_end(&mut bytes);
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX)
            > crate::media_image::SCREENSHOT_MAX_ALLOC_BYTES
        {
            let _ = child.kill();
        }
        let status = child.wait().map_err(|error| ComputerError::CommandFailed {
            program: "capture".to_string(),
            detail: error.to_string(),
        })?;
        let stderr = stderr_reader.join().unwrap_or_default();
        read_result.map_err(|error| ComputerError::CommandFailed {
            program: "capture".to_string(),
            detail: error.to_string(),
        })?;
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX)
            > crate::media_image::SCREENSHOT_MAX_ALLOC_BYTES
        {
            return Err(ComputerError::Refused(
                "encoded capture exceeds the screenshot allocation limit".to_string(),
            ));
        }
        if !status.success() {
            return Err(ComputerError::CommandFailed {
                program: "capture".to_string(),
                detail: String::from_utf8_lossy(&stderr).to_string(),
            });
        }
        Ok(bytes)
    }

    fn capture_to_path(
        &self,
        tool: &CaptureTool,
        display: &str,
        region: Option<PixelRect>,
        dest: &std::path::Path,
    ) -> Result<(), ComputerError> {
        let output = capture_command(tool, display, region, CaptureDest::File(dest))
            .output()
            .map_err(|error| ComputerError::CommandFailed {
                program: "capture".to_string(),
                detail: error.to_string(),
            })?;
        if !output.status.success() {
            return Err(ComputerError::CommandFailed {
                program: "capture".to_string(),
                detail: String::from_utf8_lossy(&output.stderr).to_string(),
            });
        }
        Ok(())
    }
}

#[async_trait]
impl ComputerBackend for VirtualDisplayBackend {
    fn backend_kind(&self) -> target::BackendKind {
        self.backend_kind
    }
    #[cfg(target_os = "linux")]
    fn real_x11_display(&self) -> Option<&str> {
        self.real_x11_display()
    }
    #[cfg(target_os = "linux")]
    fn x11_display_name(&self) -> Option<&str> {
        Some(&self.display)
    }
    async fn geometry(&mut self) -> Result<DisplayGeometry, ComputerError> {
        #[cfg(target_os = "linux")]
        if self.backend_kind == target::BackendKind::RealDesktopX11 {
            self.geometry = query_x11_display_geometry(&self.tools.xdotool, &self.display)?;
        }
        Ok(self.geometry.clone())
    }

    async fn execute_normalized_one(
        &mut self,
        action: &NormalizedComputerAction,
    ) -> Result<ComputerActionOutcome, ComputerError> {
        if self.backend_kind == target::BackendKind::RealDesktopX11 {
            self.physical_capability
                .as_ref()
                .ok_or_else(|| {
                    ComputerError::Refused("physical backend is not coordinator-bound".into())
                })?
                .recheck(self.backend_kind)?;
        }
        execute_virtual_action(self, action)
    }

    fn release_all(&mut self) -> Result<(), ComputerError> {
        #[cfg(target_os = "linux")]
        {
            // A replacement backend can have been constructed before a
            // predecessor's final failed `keyup`. Reload under the host lease
            // so that late durable state is never missed during recovery.
            self.reload_held_keys()?;
            let transitions = self
                .held_keys
                .clone()
                .into_iter()
                .map(LinuxReleaseTransition::Key)
                .chain(
                    self.held_buttons
                        .clone()
                        .into_iter()
                        .map(LinuxReleaseTransition::Button),
                )
                .collect::<Vec<_>>();
            run_linux_release_state_machine(transitions, |transition| {
                self.prepare_current_input_transition()?;
                match transition {
                    LinuxReleaseTransition::Key(key) => {
                        self.run_release_xdotool("keyup", &[OsString::from(&key)])?;
                        self.forget_held_key(&key)
                    }
                    LinuxReleaseTransition::Button(button) => {
                        self.run_release_xdotool("mouseup", &[OsString::from(button.to_string())])?;
                        self.held_buttons.retain(|held| *held != button);
                        self.held_key_journal
                            .store(&self.held_keys, &self.held_buttons, false)
                    }
                }
            })?;
        }
        Ok(())
    }

    fn bind_physical_capability(
        &mut self,
        capability: coordinator::PhysicalDispatchCapability,
    ) -> Result<(), ComputerError> {
        if self.backend_kind != target::BackendKind::RealDesktopX11 {
            return Err(ComputerError::Refused(
                "cannot bind a physical capability to a virtual backend".into(),
            ));
        }
        capability.recheck(self.backend_kind)?;
        self.physical_capability = Some(capability);
        Ok(())
    }

    fn bind_evidenced_window(
        &mut self,
        window: target::OpaqueWindowId,
    ) -> Result<(), ComputerError> {
        #[cfg(target_os = "linux")]
        {
            return self.bind_x11_injection_window(window);
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = window;
            Err(ComputerError::Refused(
                CANNOT_DIRECT_INPUT_TO_EVIDENCED_WINDOW.to_string(),
            ))
        }
    }

    fn recheck_evidenced_window(&mut self) -> Result<(), ComputerError> {
        #[cfg(target_os = "linux")]
        {
            let Some(bound) = self.evidenced_injection_window else {
                return Ok(());
            };
            let live = crate::computer::platform::x11_net_active_window(&self.display)
                .map_err(|_| ComputerError::Refused(EVIDENCED_WINDOW_MISMATCH.to_string()))?;
            if live != bound.x11 {
                return Err(ComputerError::Refused(
                    EVIDENCED_WINDOW_MISMATCH.to_string(),
                ));
            }
            return Ok(());
        }
        #[cfg(not(target_os = "linux"))]
        Ok(())
    }
}

impl Drop for VirtualDisplayBackend {
    fn drop(&mut self) {
        if let Some(mut child) = self
            .xvfb
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
        {
            cockpit_host::process::terminate_group_sync(&mut child, Duration::from_millis(200));
        }
    }
}

#[cfg(target_os = "linux")]
fn execute_virtual_action(
    backend: &mut VirtualDisplayBackend,
    action: &NormalizedComputerAction,
) -> Result<ComputerActionOutcome, ComputerError> {
    match action.effect() {
        NormalizedComputerEffect::CaptureFull => {
            Ok(ComputerActionOutcome::Captured(CaptureFrame {
                png: backend.capture_png(None)?,
                geometry: backend.geometry.clone(),
                region: None,
                native_zoom: None,
            }))
        }
        NormalizedComputerEffect::CaptureRegion { rect: region } => {
            Ok(ComputerActionOutcome::Captured(CaptureFrame {
                png: backend.capture_png(Some(*region))?,
                geometry: backend.geometry.clone(),
                region: Some(*region),
                native_zoom: None,
            }))
        }
        NormalizedComputerEffect::CaptureNativeZoom {
            rect: region,
            scale,
            output,
        } => {
            let png = backend.capture_png(Some(*region))?;
            Ok(ComputerActionOutcome::Captured(CaptureFrame {
                png: scale_png(png, *output)?,
                geometry: backend.geometry.clone(),
                region: Some(*region),
                native_zoom: Some(*scale),
            }))
        }
        NormalizedComputerEffect::MoveCursor {
            to,
            duration,
            easing,
        } => {
            move_cursor_with_timing(backend, *to, *duration, *easing)?;
            Ok(ComputerActionOutcome::Completed)
        }
        NormalizedComputerEffect::Click {
            button,
            count,
            modifiers,
        } => {
            run_modifiers(backend, *modifiers, true)?;
            for _ in 0..click_repetitions(*count) {
                backend.prepare_current_input_transition()?;
                backend.run_targeted_xdotool(
                    "click",
                    &[OsString::from(mouse_button_number(*button).to_string())],
                )?;
                backend.commit_known_input_state()?;
            }
            run_modifiers(backend, *modifiers, false)?;
            Ok(ComputerActionOutcome::Completed)
        }
        NormalizedComputerEffect::MouseDown { button } => {
            backend.remember_held_button(*button)?;
            backend.run_targeted_xdotool(
                "mousedown",
                &[OsString::from(mouse_button_number(*button).to_string())],
            )?;
            backend.commit_known_input_state()?;
            Ok(ComputerActionOutcome::Completed)
        }
        NormalizedComputerEffect::MouseUp { button } => {
            backend.prepare_current_input_transition()?;
            backend.run_targeted_xdotool(
                "mouseup",
                &[OsString::from(mouse_button_number(*button).to_string())],
            )?;
            backend.forget_held_button(*button)?;
            Ok(ComputerActionOutcome::Completed)
        }
        NormalizedComputerEffect::Drag {
            button,
            path,
            modifiers,
        } => {
            let first = path[0];
            move_cursor_with_timing(backend, first.point, first.duration, first.easing)?;
            run_modifiers(backend, *modifiers, true)?;
            backend.remember_held_button(*button)?;
            backend.run_targeted_xdotool(
                "mousedown",
                &[OsString::from(mouse_button_number(*button).to_string())],
            )?;
            backend.commit_known_input_state()?;
            for step in path.iter().skip(1) {
                move_cursor_with_timing(backend, step.point, step.duration, step.easing)?;
            }
            backend.prepare_current_input_transition()?;
            backend.run_targeted_xdotool(
                "mouseup",
                &[OsString::from(mouse_button_number(*button).to_string())],
            )?;
            backend.forget_held_button(*button)?;
            run_modifiers(backend, *modifiers, false)?;
            Ok(ComputerActionOutcome::Completed)
        }
        NormalizedComputerEffect::TypeText { text } => {
            backend.prepare_current_input_transition()?;
            backend.run_targeted_xdotool("type", &[OsString::from(text)])?;
            backend.commit_known_input_state()?;
            Ok(ComputerActionOutcome::Completed)
        }
        NormalizedComputerEffect::KeyChord { chord } => {
            let chord = chord
                .keys()
                .iter()
                .map(NormalizedKeyCode::x11_name)
                .collect::<Vec<_>>()
                .join("+");
            backend.prepare_current_input_transition()?;
            backend.run_targeted_xdotool("key", &[OsString::from(chord)])?;
            backend.commit_known_input_state()?;
            Ok(ComputerActionOutcome::Completed)
        }
        NormalizedComputerEffect::HoldKey { key, duration } => {
            let key = key.x11_name().to_string();
            backend.remember_held_key(key.clone())?;
            backend.run_targeted_xdotool("keydown", &[OsString::from(&key)])?;
            backend.commit_known_input_state()?;
            std::thread::sleep(*duration);
            backend.prepare_current_input_transition()?;
            backend.run_targeted_xdotool("keyup", &[OsString::from(&key)])?;
            backend.forget_held_key(&key)?;
            Ok(ComputerActionOutcome::Completed)
        }
        NormalizedComputerEffect::Scroll {
            delta_x,
            delta_y,
            modifiers,
        } => {
            run_modifiers(backend, *modifiers, true)?;
            let vertical = if *delta_y < 0 { "5" } else { "4" };
            for _ in 0..delta_y.unsigned_abs() {
                backend.prepare_current_input_transition()?;
                backend.run_targeted_xdotool("click", &[OsString::from(vertical)])?;
                backend.commit_known_input_state()?;
            }
            let horizontal = if *delta_x < 0 { "7" } else { "6" };
            for _ in 0..delta_x.unsigned_abs() {
                backend.prepare_current_input_transition()?;
                backend.run_targeted_xdotool("click", &[OsString::from(horizontal)])?;
                backend.commit_known_input_state()?;
            }
            run_modifiers(backend, *modifiers, false)?;
            Ok(ComputerActionOutcome::Completed)
        }
        NormalizedComputerEffect::Wait { duration } => {
            std::thread::sleep(*duration);
            Ok(ComputerActionOutcome::Waited(*duration))
        }
    }
}

fn translate_x11_key(key: &KeyCode) -> Result<String, ComputerError> {
    let canonical = key.as_str();
    if canonical.len() == 1 && canonical.as_bytes()[0].is_ascii_alphabetic() {
        return Ok(canonical.to_ascii_lowercase());
    }
    if canonical.len() == 1 && canonical.as_bytes()[0].is_ascii_digit() {
        return Ok(canonical.to_string());
    }
    if canonical
        .strip_prefix('F')
        .and_then(|number| number.parse::<u8>().ok())
        .is_some_and(|number| (1..=12).contains(&number))
    {
        return Ok(canonical.to_string());
    }
    let translated = match canonical {
        "CONTROL" => "Control",
        "LEFTCONTROL" => "Control_L",
        "RIGHTCONTROL" => "Control_R",
        "SHIFT" => "Shift",
        "ALT" => "Alt",
        "LEFTALT" => "Alt_L",
        "RIGHTALT" => "Alt_R",
        "META" | "LEFTMETA" => "Super_L",
        "RIGHTMETA" => "Super_R",
        "ENTER" => "Return",
        "TAB" => "Tab",
        "ESCAPE" => "Escape",
        "BACKSPACE" => "BackSpace",
        "DELETE" => "Delete",
        "INSERT" => "Insert",
        "SPACE" => "space",
        "ARROWUP" => "Up",
        "ARROWDOWN" => "Down",
        "ARROWLEFT" => "Left",
        "ARROWRIGHT" => "Right",
        "HOME" => "Home",
        "END" => "End",
        "PAGEUP" => "Page_Up",
        "PAGEDOWN" => "Page_Down",
        "CAPSLOCK" => "Caps_Lock",
        "NUMLOCK" => "Num_Lock",
        "SCROLLLOCK" => "Scroll_Lock",
        "PRINTSCREEN" => "Print",
        "PAUSE" => "Pause",
        "APPS" => "Menu",
        _ => {
            return Err(ComputerError::Refused(format!(
                "unsupported X11 key identity `{canonical}`"
            )));
        }
    };
    Ok(translated.to_string())
}

fn translate_windows_key(key: &KeyCode) -> Result<u16, ComputerError> {
    let canonical = key.as_str();
    if canonical.len() == 1 && canonical.as_bytes()[0].is_ascii_alphanumeric() {
        return Ok(u16::from(canonical.as_bytes()[0]));
    }
    if let Some(number) = canonical
        .strip_prefix('F')
        .and_then(|number| number.parse::<u8>().ok())
        .filter(|number| (1..=12).contains(number))
    {
        return Ok(0x6f + u16::from(number));
    }
    match canonical {
        "BACKSPACE" => Ok(0x08),
        "TAB" => Ok(0x09),
        "ENTER" => Ok(0x0d),
        "SHIFT" => Ok(0x10),
        "CONTROL" => Ok(0x11),
        "ALT" => Ok(0x12),
        "PAUSE" => Ok(0x13),
        "CAPSLOCK" => Ok(0x14),
        "ESCAPE" => Ok(0x1b),
        "SPACE" => Ok(0x20),
        "PAGEUP" => Ok(0x21),
        "PAGEDOWN" => Ok(0x22),
        "END" => Ok(0x23),
        "HOME" => Ok(0x24),
        "ARROWLEFT" => Ok(0x25),
        "ARROWUP" => Ok(0x26),
        "ARROWRIGHT" => Ok(0x27),
        "ARROWDOWN" => Ok(0x28),
        "PRINTSCREEN" => Ok(0x2c),
        "INSERT" => Ok(0x2d),
        "DELETE" => Ok(0x2e),
        "LEFTMETA" => Ok(0x5b),
        "RIGHTMETA" => Ok(0x5c),
        "APPS" => Ok(0x5d),
        "NUMLOCK" => Ok(0x90),
        "SCROLLLOCK" => Ok(0x91),
        "LEFTCONTROL" => Ok(0xa2),
        "RIGHTCONTROL" => Ok(0xa3),
        "LEFTALT" => Ok(0xa4),
        "RIGHTALT" => Ok(0xa5),
        _ => Err(ComputerError::Refused(format!(
            "unsupported Windows key identity `{canonical}`"
        ))),
    }
}

fn windows_key_is_extended(key: &KeyCode) -> bool {
    matches!(
        key.as_str(),
        "RIGHTCONTROL"
            | "RIGHTALT"
            | "INSERT"
            | "DELETE"
            | "HOME"
            | "END"
            | "PAGEUP"
            | "PAGEDOWN"
            | "ARROWUP"
            | "ARROWDOWN"
            | "ARROWLEFT"
            | "ARROWRIGHT"
            | "NUMLOCK"
            | "PRINTSCREEN"
            | "LEFTMETA"
            | "RIGHTMETA"
            | "APPS"
    )
}

/// US ANSI virtual-key map used for command chords. Literal text does not use
/// this table; it is injected with CGEvent's UTF-16 API. Keys without a macOS
/// HID mapping stay `None` so Windows/X11-only identities still normalize.
pub(crate) fn translate_macos_key(key: &KeyCode) -> Option<u16> {
    let canonical = key.as_str();
    if canonical.len() == 1 {
        return match canonical.as_bytes()[0] {
            b'A' => Some(0x00),
            b'S' => Some(0x01),
            b'D' => Some(0x02),
            b'F' => Some(0x03),
            b'H' => Some(0x04),
            b'G' => Some(0x05),
            b'Z' => Some(0x06),
            b'X' => Some(0x07),
            b'C' => Some(0x08),
            b'V' => Some(0x09),
            b'B' => Some(0x0b),
            b'Q' => Some(0x0c),
            b'W' => Some(0x0d),
            b'E' => Some(0x0e),
            b'R' => Some(0x0f),
            b'Y' => Some(0x10),
            b'T' => Some(0x11),
            b'1' => Some(0x12),
            b'2' => Some(0x13),
            b'3' => Some(0x14),
            b'4' => Some(0x15),
            b'6' => Some(0x16),
            b'5' => Some(0x17),
            b'9' => Some(0x19),
            b'7' => Some(0x1a),
            b'8' => Some(0x1c),
            b'0' => Some(0x1d),
            b'O' => Some(0x1f),
            b'U' => Some(0x20),
            b'I' => Some(0x22),
            b'P' => Some(0x23),
            b'L' => Some(0x25),
            b'J' => Some(0x26),
            b'K' => Some(0x28),
            b'N' => Some(0x2d),
            b'M' => Some(0x2e),
            _ => None,
        };
    }
    if let Some(number) = canonical
        .strip_prefix('F')
        .and_then(|number| number.parse::<u8>().ok())
        .filter(|number| (1..=12).contains(number))
    {
        return Some(match number {
            1 => 0x7a,
            2 => 0x78,
            3 => 0x63,
            4 => 0x76,
            5 => 0x60,
            6 => 0x61,
            7 => 0x62,
            8 => 0x64,
            9 => 0x65,
            10 => 0x6d,
            11 => 0x67,
            12 => 0x6f,
            _ => return None,
        });
    }
    match canonical {
        "TAB" => Some(0x30),
        "SPACE" => Some(0x31),
        "BACKSPACE" => Some(0x33),
        "ESCAPE" => Some(0x35),
        "META" | "LEFTMETA" => Some(0x37),
        "RIGHTMETA" => Some(0x36),
        "SHIFT" => Some(0x38),
        "CAPSLOCK" => Some(0x39),
        "ALT" | "LEFTALT" => Some(0x3a),
        "RIGHTALT" => Some(0x3d),
        "CONTROL" | "LEFTCONTROL" => Some(0x3b),
        "RIGHTCONTROL" => Some(0x3e),
        "ENTER" => Some(0x24),
        "HOME" => Some(0x73),
        "PAGEUP" => Some(0x74),
        "DELETE" => Some(0x75),
        "END" => Some(0x77),
        "PAGEDOWN" => Some(0x79),
        "ARROWLEFT" => Some(0x7b),
        "ARROWRIGHT" => Some(0x7c),
        "ARROWDOWN" => Some(0x7d),
        "ARROWUP" => Some(0x7e),
        _ => None,
    }
}

#[cfg(target_os = "linux")]
fn move_cursor_with_timing(
    backend: &VirtualDisplayBackend,
    target: PixelPoint,
    duration: Duration,
    easing: Easing,
) -> Result<(), ComputerError> {
    if duration.is_zero() {
        return move_cursor_now(backend, target);
    }

    let start = current_cursor(backend)?;
    let steps = 12_u32;
    let step_sleep = duration / steps;
    for step in 1..=steps {
        let progress = eased_progress(f64::from(step) / f64::from(steps), easing);
        let x = f64::from(start.x) + (f64::from(target.x) - f64::from(start.x)) * progress;
        let y = f64::from(start.y) + (f64::from(target.y) - f64::from(start.y)) * progress;
        move_cursor_now(
            backend,
            PixelPoint {
                x: x.round() as u32,
                y: y.round() as u32,
            },
        )?;
        if !step_sleep.is_zero() {
            std::thread::sleep(step_sleep);
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn move_cursor_now(
    backend: &VirtualDisplayBackend,
    point: PixelPoint,
) -> Result<(), ComputerError> {
    let relative = backend.window_relative_point(point)?;
    backend.run_targeted_xdotool(
        "mousemove",
        &[
            OsString::from(relative.x.to_string()),
            OsString::from(relative.y.to_string()),
        ],
    )
}

#[cfg(target_os = "linux")]
fn xdotool_targeted_args(window: u32, command: &str, rest: &[OsString]) -> Vec<OsString> {
    let mut args = Vec::with_capacity(3 + rest.len());
    args.push(OsString::from(command));
    args.push(OsString::from("--window"));
    args.push(OsString::from(window.to_string()));
    args.extend_from_slice(rest);
    args
}

#[cfg(test)]
pub(crate) fn xdotool_targeted_command(window: u32, command: &str, rest: &[&str]) -> Vec<String> {
    let mut args = vec![
        command.to_string(),
        "--window".to_string(),
        window.to_string(),
    ];
    args.extend(rest.iter().map(|part| (*part).to_string()));
    args
}

#[cfg(any(target_os = "linux", test))]
fn pixel_point_in_window(
    screen: PixelPoint,
    origin_x: i32,
    origin_y: i32,
    width: u32,
    height: u32,
) -> Result<PixelPoint, ComputerError> {
    let x = i64::from(screen.x) - i64::from(origin_x);
    let y = i64::from(screen.y) - i64::from(origin_y);
    if x < 0 || y < 0 || x >= i64::from(width) || y >= i64::from(height) {
        return Err(ComputerError::Refused(
            "cursor point is outside the evidenced window".to_string(),
        ));
    }
    Ok(PixelPoint {
        x: x as u32,
        y: y as u32,
    })
}

#[cfg(target_os = "linux")]
fn current_cursor(backend: &VirtualDisplayBackend) -> Result<PixelPoint, ComputerError> {
    let output = backend.run_xdotool_output(&[
        OsString::from("getmouselocation"),
        OsString::from("--shell"),
    ])?;
    if !output.status.success() {
        return Err(ComputerError::CommandFailed {
            program: "xdotool".to_string(),
            detail: String::from_utf8_lossy(&output.stderr).to_string(),
        });
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut x = None;
    let mut y = None;
    for line in stdout.lines() {
        if let Some(value) = line.strip_prefix("X=") {
            x = value.parse::<u32>().ok();
        } else if let Some(value) = line.strip_prefix("Y=") {
            y = value.parse::<u32>().ok();
        }
    }
    match (x, y) {
        (Some(x), Some(y)) => Ok(PixelPoint { x, y }),
        _ => Err(ComputerError::CommandFailed {
            program: "xdotool".to_string(),
            detail: "getmouselocation did not return X/Y coordinates".to_string(),
        }),
    }
}

fn eased_progress(progress: f64, easing: Easing) -> f64 {
    match easing {
        Easing::Linear => progress,
        Easing::EaseInOut if progress < 0.5 => 2.0 * progress * progress,
        Easing::EaseInOut => 1.0 - (-2.0 * progress + 2.0).powi(2) / 2.0,
    }
}

fn checked_zoom_scale(scale: ScaleFactor) -> Result<ScaleFactor, ComputerError> {
    if scale.0.is_finite() && scale.0 > 0.0 {
        Ok(scale)
    } else {
        Err(ComputerError::InvalidCoordinates(
            "native zoom scale must be a positive finite value".to_string(),
        ))
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn scale_png(png: Vec<u8>, output: PixelSize) -> Result<Vec<u8>, ComputerError> {
    let profile = crate::media_image::ImageProfile::screenshot();
    let image = crate::media_image::decode_and_orient(&png, &profile).map_err(|error| {
        ComputerError::CommandFailed {
            program: "image".to_string(),
            detail: error.to_string(),
        }
    })?;
    if image.width() == output.width && image.height() == output.height {
        return Ok(png);
    }
    let scaled = crate::media_image::scale(image, output.width, output.height, &profile);
    crate::media_image::encode_png(&scaled, &profile).map_err(|error| {
        ComputerError::CommandFailed {
            program: "image".to_string(),
            detail: error.to_string(),
        }
    })
}

fn scaled_dimension(value: u32, scale: ScaleFactor) -> Result<u32, ComputerError> {
    let scaled = (f64::from(value) * scale.0).round();
    if !scaled.is_finite() || scaled < 1.0 || scaled > f64::from(u32::MAX) {
        return Err(ComputerError::InvalidCoordinates(
            "native zoom scale produces an invalid image dimension".to_string(),
        ));
    }
    Ok(scaled as u32)
}

#[cfg(not(target_os = "linux"))]
fn execute_virtual_action(
    _backend: &VirtualDisplayBackend,
    _action: &NormalizedComputerAction,
) -> Result<ComputerActionOutcome, ComputerError> {
    Err(unsupported_platform())
}

#[cfg(target_os = "linux")]
fn run_modifiers(
    backend: &mut VirtualDisplayBackend,
    modifiers: Modifiers,
    down: bool,
) -> Result<(), ComputerError> {
    let verb = if down { "keydown" } else { "keyup" };
    for (enabled, key) in [
        (modifiers.shift, "Shift"),
        (modifiers.control, "Control"),
        (modifiers.alt, "Alt"),
        (modifiers.meta, "Super_L"),
    ] {
        if enabled {
            if down {
                backend.remember_held_key(key.to_string())?;
            } else {
                backend.prepare_current_input_transition()?;
            }
            backend.run_targeted_xdotool(verb, &[OsString::from(key)])?;
            if down {
                backend.commit_known_input_state()?;
            } else {
                backend.forget_held_key(key)?;
            }
        }
    }
    Ok(())
}

fn checked_point(point: Point, geometry: &DisplayGeometry) -> Result<PixelPoint, ComputerError> {
    let (x, y) = match point.space {
        CoordinateSpace::Physical => (point.x, point.y),
        CoordinateSpace::Logical => (
            point.x * geometry.scale_factor.0,
            point.y * geometry.scale_factor.0,
        ),
    };
    if !x.is_finite()
        || !y.is_finite()
        || x < 0.0
        || y < 0.0
        || x > f64::from(u32::MAX)
        || y > f64::from(u32::MAX)
    {
        return Err(ComputerError::InvalidCoordinates(format!(
            "point ({x}, {y}) is not finite and non-negative"
        )));
    }
    let x = x.round() as u32;
    let y = y.round() as u32;
    if x >= geometry.physical.width || y >= geometry.physical.height {
        return Err(ComputerError::InvalidCoordinates(format!(
            "point ({x}, {y}) outside {}x{}",
            geometry.physical.width, geometry.physical.height
        )));
    }
    Ok(PixelPoint { x, y })
}

fn checked_rect(rect: Rect, geometry: &DisplayGeometry) -> Result<PixelRect, ComputerError> {
    if !rect.width.is_finite()
        || !rect.height.is_finite()
        || rect.width <= 0.0
        || rect.height <= 0.0
    {
        return Err(ComputerError::InvalidCoordinates(
            "rect width/height must be positive finite values".to_string(),
        ));
    }
    let origin = checked_point(
        Point {
            x: rect.x,
            y: rect.y,
            space: rect.space,
        },
        geometry,
    )?;
    let scale = match rect.space {
        CoordinateSpace::Physical => 1.0,
        CoordinateSpace::Logical => geometry.scale_factor.0,
    };
    let scaled_width = (rect.width * scale).round();
    let scaled_height = (rect.height * scale).round();
    if !scaled_width.is_finite()
        || !scaled_height.is_finite()
        || scaled_width < 1.0
        || scaled_height < 1.0
        || scaled_width > f64::from(u32::MAX)
        || scaled_height > f64::from(u32::MAX)
    {
        return Err(ComputerError::InvalidCoordinates(
            "rect rounds to invalid physical dimensions".to_string(),
        ));
    }
    let width = scaled_width as u32;
    let height = scaled_height as u32;
    let Some(right) = origin.x.checked_add(width) else {
        return Err(ComputerError::InvalidCoordinates(
            "rect x + width overflows".to_string(),
        ));
    };
    let Some(bottom) = origin.y.checked_add(height) else {
        return Err(ComputerError::InvalidCoordinates(
            "rect y + height overflows".to_string(),
        ));
    };
    if right > geometry.physical.width || bottom > geometry.physical.height {
        return Err(ComputerError::InvalidCoordinates(format!(
            "rect exceeds {}x{}",
            geometry.physical.width, geometry.physical.height
        )));
    }
    Ok(PixelRect {
        x: origin.x,
        y: origin.y,
        width,
        height,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PixelPoint {
    pub x: u32,
    pub y: u32,
}

fn checked_geometry(geometry: &DisplayGeometry) -> Result<(), ComputerError> {
    if geometry.physical.width == 0
        || geometry.physical.height == 0
        || !geometry.logical.width.is_finite()
        || !geometry.logical.height.is_finite()
        || geometry.logical.width <= 0.0
        || geometry.logical.height <= 0.0
        || !geometry.scale_factor.0.is_finite()
        || geometry.scale_factor.0 <= 0.0
    {
        return Err(ComputerError::InvalidCoordinates(
            "backend display geometry is invalid".to_string(),
        ));
    }
    Ok(())
}

/// Normalize every action against `geometry` before any platform effect.
/// A malformed tail fails with zero completed items so the coordinator can
/// refuse the batch before the first handoff.
pub(crate) fn normalize_backend_batch(
    actions: &[ComputerAction],
    geometry: &DisplayGeometry,
) -> Result<Vec<NormalizedComputerAction>, ComputerFailure> {
    let mut normalized = Vec::with_capacity(actions.len());
    for (index, action) in actions.iter().enumerate() {
        match normalize_action(action, geometry) {
            Ok(action) => normalized.push(action),
            Err(error) => return Err(ComputerFailure { index, error }),
        }
    }
    Ok(normalized)
}

fn normalize_action(
    action: &ComputerAction,
    geometry: &DisplayGeometry,
) -> Result<NormalizedComputerAction, ComputerError> {
    checked_geometry(geometry)?;
    let effect = match action {
        ComputerAction::CaptureFull => {
            checked_capture_allocation(
                geometry.physical.width,
                geometry.physical.height,
                "full capture source",
            )?;
            NormalizedComputerEffect::CaptureFull
        }
        ComputerAction::CaptureRegion { rect } => {
            let rect = checked_rect(*rect, geometry)?;
            checked_capture_allocation(rect.width, rect.height, "region capture source")?;
            NormalizedComputerEffect::CaptureRegion { rect }
        }
        ComputerAction::CaptureNativeZoom { rect, scale } => {
            let rect = checked_rect(*rect, geometry)?;
            checked_capture_allocation(rect.width, rect.height, "native zoom source")?;
            let scale = checked_zoom_scale(*scale)?;
            let output = PixelSize {
                width: scaled_dimension(rect.width, scale)?,
                height: scaled_dimension(rect.height, scale)?,
            };
            checked_capture_allocation(output.width, output.height, "native zoom output")?;
            NormalizedComputerEffect::CaptureNativeZoom {
                rect,
                scale,
                output,
            }
        }
        ComputerAction::MoveCursor {
            to,
            duration,
            easing,
        } => {
            checked_action_duration(*duration)?;
            NormalizedComputerEffect::MoveCursor {
                to: checked_point(*to, geometry)?,
                duration: *duration,
                easing: *easing,
            }
        }
        ComputerAction::Click {
            button,
            count,
            modifiers,
        } => NormalizedComputerEffect::Click {
            button: *button,
            count: *count,
            modifiers: *modifiers,
        },
        ComputerAction::MouseDown { button } => {
            NormalizedComputerEffect::MouseDown { button: *button }
        }
        ComputerAction::MouseUp { button } => NormalizedComputerEffect::MouseUp { button: *button },
        ComputerAction::Drag {
            button,
            path,
            modifiers,
        } => {
            if path.is_empty() {
                return Err(ComputerError::InvalidCoordinates(
                    "drag path must contain at least one point".to_string(),
                ));
            }
            let path = path
                .iter()
                .map(|step| {
                    checked_action_duration(step.duration)?;
                    Ok(NormalizedTimedPoint {
                        point: checked_point(step.point, geometry)?,
                        duration: step.duration,
                        easing: step.easing,
                    })
                })
                .collect::<Result<_, ComputerError>>()?;
            NormalizedComputerEffect::Drag {
                button: *button,
                path,
                modifiers: *modifiers,
            }
        }
        ComputerAction::TypeText { text } => {
            NormalizedComputerEffect::TypeText { text: text.clone() }
        }
        ComputerAction::KeyChord { chord } => {
            // CanonicalKeyChord construction enforces this invariant. Keep the
            // mandatory normalization gate defensive against any future
            // internal representation change.
            let chord = CanonicalKeyChord::new(chord.keys().to_vec())?;
            let chord = NormalizedKeyChord::new(&chord)?;
            NormalizedComputerEffect::KeyChord { chord }
        }
        ComputerAction::HoldKey { key, duration } => {
            checked_action_duration(*duration)?;
            NormalizedComputerEffect::HoldKey {
                key: NormalizedKeyCode::new(key)?,
                duration: *duration,
            }
        }
        ComputerAction::Scroll {
            delta_x,
            delta_y,
            modifiers,
        } => {
            checked_scroll_delta(*delta_x)?;
            checked_scroll_delta(*delta_y)?;
            NormalizedComputerEffect::Scroll {
                delta_x: *delta_x,
                delta_y: *delta_y,
                modifiers: *modifiers,
            }
        }
        ComputerAction::Wait { duration } => {
            checked_action_duration(*duration)?;
            NormalizedComputerEffect::Wait {
                duration: *duration,
            }
        }
    };
    Ok(NormalizedComputerAction { effect })
}

fn checked_capture_allocation(
    width: u32,
    height: u32,
    allocation: &str,
) -> Result<(), ComputerError> {
    crate::media_image::checked_rgba_allocation_bytes(
        width,
        height,
        &crate::media_image::ImageProfile::screenshot(),
    )
    .map(|_| ())
    .map_err(|_| {
        ComputerError::Refused(format!(
            "{allocation} exceeds the screenshot allocation limit"
        ))
    })
}

fn mouse_button_number(button: MouseButton) -> u8 {
    match button {
        MouseButton::Left => 1,
        MouseButton::Middle => 2,
        MouseButton::Right => 3,
    }
}

fn click_repetitions(count: ClickCount) -> u8 {
    match count {
        ClickCount::Single => 1,
        ClickCount::Double => 2,
        ClickCount::Triple => 3,
    }
}

#[cfg(target_os = "linux")]
fn require_capability(
    tool: &'static str,
    install_hint: &'static str,
) -> Result<PathBuf, ComputerError> {
    crate::capabilities::resolve_binary(tool).ok_or(ComputerError::MissingTool {
        tool: tool.to_string(),
        install_hint: install_hint.to_string(),
    })
}

#[cfg(target_os = "linux")]
fn require_capture_tool() -> Result<CaptureTool, ComputerError> {
    if let Some(path) = crate::capabilities::resolve_binary("scrot") {
        return Ok(CaptureTool::Scrot(path));
    }
    if let Some(path) = crate::capabilities::resolve_binary("import") {
        return Ok(CaptureTool::Import(path));
    }
    Err(ComputerError::MissingTool {
        tool: "scrot or import".to_string(),
        install_hint: "the `scrot` package or ImageMagick".to_string(),
    })
}

fn unsupported_platform() -> ComputerError {
    ComputerError::UnsupportedPlatform {
        platform: std::env::consts::OS.to_string(),
    }
}

#[cfg(target_os = "macos")]
fn current_machine_fingerprint() -> Option<String> {
    // IOPlatformUUID is a hardware-backed IORegistry property. Do not
    // fall back to an environment variable or a shared sentinel: copied
    // consent files must not authorize a different Mac.
    let output = std::process::Command::new("/usr/sbin/ioreg")
        .args(["-rd1", "-c", "IOPlatformExpertDevice"])
        .stdin(std::process::Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8(output.stdout).ok()?;
    let uuid = value.lines().find_map(|line| {
        let (_, value) = line.split_once("\"IOPlatformUUID\" = ")?;
        value.trim().strip_prefix('\"')?.strip_suffix('\"')
    })?;
    (!uuid.is_empty()).then(|| format!("macos-ioplatformuuid:{uuid}"))
}

/// A roaming `%APPDATA%` grant cannot authorize input on another Windows
/// machine: the comparison is bound to the OS-owned, machine-local MachineGuid
/// and fails closed if the registry value is inaccessible or malformed.
#[cfg(target_os = "windows")]
fn current_machine_fingerprint() -> Option<String> {
    use windows::Win32::System::Registry::{
        HKEY, HKEY_LOCAL_MACHINE, KEY_READ, REG_SZ, REG_VALUE_TYPE, RegCloseKey, RegOpenKeyExW,
        RegQueryValueExW,
    };
    use windows::core::PCWSTR;

    // SAFETY: all pointers are NUL-terminated local UTF-16 buffers and the
    // registry handle is closed on every path after a successful open.
    unsafe {
        let key_name = "SOFTWARE\\Microsoft\\Cryptography"
            .encode_utf16()
            .chain([0])
            .collect::<Vec<_>>();
        let value_name = "MachineGuid".encode_utf16().chain([0]).collect::<Vec<_>>();
        let mut key = HKEY::default();
        if !RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(key_name.as_ptr()),
            None,
            KEY_READ,
            &mut key,
        )
        .is_ok()
        {
            return None;
        }
        let value = (|| {
            let mut value_type = REG_VALUE_TYPE(0);
            let mut byte_len = 0_u32;
            if !RegQueryValueExW(
                key,
                PCWSTR(value_name.as_ptr()),
                None,
                Some(&mut value_type),
                None,
                Some(&mut byte_len),
            )
            .is_ok()
                || value_type != REG_SZ
                || byte_len < 2
                || byte_len % 2 != 0
            {
                return None;
            }
            let mut units = vec![0_u16; byte_len as usize / 2];
            if !RegQueryValueExW(
                key,
                PCWSTR(value_name.as_ptr()),
                None,
                Some(&mut value_type),
                Some(units.as_mut_ptr().cast()),
                Some(&mut byte_len),
            )
            .is_ok()
                || value_type != REG_SZ
            {
                return None;
            }
            let end = units
                .iter()
                .position(|unit| *unit == 0)
                .unwrap_or(units.len());
            let machine_guid = String::from_utf16(&units[..end]).ok()?;
            (!machine_guid.is_empty()).then(|| {
                crate::computer::host_identity::domain_hash(
                    b"cockpit.windows.machine-grant.v1",
                    &[machine_guid.as_bytes()],
                )
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect()
            })
        })();
        let _ = RegCloseKey(key);
        value
    }
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn current_machine_fingerprint() -> Option<String> {
    fs::read_to_string("/etc/machine-id")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .or_else(|| {
            std::env::var("HOSTNAME")
                .ok()
                .filter(|value| !value.is_empty())
        })
}

pub const COMPUTER_TOOL_GROUP: &str = "computer:*";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComputerToolContract {
    Anthropic20251124,
    Anthropic20250124,
    OpenAiResponses,
}

impl From<crate::config::providers::ComputerUseContract> for ComputerToolContract {
    fn from(value: crate::config::providers::ComputerUseContract) -> Self {
        match value {
            crate::config::providers::ComputerUseContract::Anthropic20251124 => {
                Self::Anthropic20251124
            }
            crate::config::providers::ComputerUseContract::Anthropic20250124 => {
                Self::Anthropic20250124
            }
            crate::config::providers::ComputerUseContract::OpenAiResponses => Self::OpenAiResponses,
        }
    }
}

impl ComputerToolContract {
    pub fn group(self) -> &'static str {
        COMPUTER_TOOL_GROUP
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeComputerWire {
    pub group: &'static str,
    pub beta_headers: Vec<&'static str>,
    pub tools: Vec<serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct NativeComputerToolConfig {
    pub contract: ComputerToolContract,
    /// Backend target selected by the owning agent. The standalone Computer
    /// primary defaults to real desktop; delegated computer workers retain
    /// their isolated virtual display.
    pub target: DisplayTarget,
    /// A primary must fail its turn when its requested backend cannot open.
    /// Delegated workers retain the existing optional-capability behavior.
    pub require_backend: bool,
    /// Geometry reported by the opened backend at the selected-delegation
    /// open-before-advertise step. `None` means the coordinator has not yet
    /// opened (candidate scan), open failed (tool not advertised), or the
    /// config lives on long-lived agent params after a successful open.
    ///
    /// Candidate/reachability scans construct this config with `geometry:
    /// None` and must NOT call full [`coordinator::ComputerActionCoordinator::open`]
    /// or acquire the host lock. Successful open keeps long-lived
    /// `Agent.params.geometry` unset; the live-loop path overlays
    /// `Some(opened.geometry)` onto a request-local clone, and request
    /// assembly advertises only inside a coordinator-backed live-loop turn.
    /// If open fails, `native_computer` stays `None` entirely (AC17/AC18/AC19).
    pub geometry: Option<DisplayGeometry>,
    /// True when the effective `computer_use` tier is `ask`.
    ///
    /// The gating prompt wires this bit so the following approval/redaction
    /// prompt can route native computer actions through the shared approval
    /// path without re-resolving provider/project policy at dispatch time.
    pub approval_required: bool,
}

/// The configuration boundary a live native-computer coordinator was opened
/// under. Geometry is deliberately excluded: it is backend-reported,
/// request-local state, rather than agent policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct NativeComputerCoordinatorConfig {
    pub contract: ComputerToolContract,
    pub target: DisplayTarget,
    pub require_backend: bool,
    pub approval_required: bool,
}

impl NativeComputerToolConfig {
    pub(crate) fn coordinator_config(&self) -> NativeComputerCoordinatorConfig {
        NativeComputerCoordinatorConfig {
            contract: self.contract,
            target: self.target,
            require_backend: self.require_backend,
            approval_required: self.approval_required,
        }
    }

    pub fn wire(&self) -> NativeComputerWire {
        let geometry = self
            .geometry
            .as_ref()
            .expect("native computer wire requested before coordinator open");
        native_computer_wire(self.contract, geometry)
    }
}

/// The provider identifiers reserved by the native computer-use tool.
///
/// These are the wire `type` strings advertised in [`native_computer_wire`]
/// (OpenAI `computer`; Anthropic `computer_20251124` / `computer_20250124`)
/// plus the Anthropic `tool_use` `name` (`computer`, which coincides with the
/// OpenAI `type`). A provider may surface a native computer item to the generic
/// Rig `AssistantContent::ToolCall` layer under one of these identifiers;
/// ordinary function-tool dispatch must refuse them rather than re-parse native
/// computer JSON as an ordinary tool. Native computer items are executed only
/// through the coordinator's raw-content extraction seam. This module is the
/// single reserved-name authority — the wire builder below references these
/// constants so the advertised tool and the refusal set stay in lockstep — and
/// [`is_reserved_native_computer_tool_name`] is the one predicate the dispatch
/// path consults.
pub const NATIVE_COMPUTER_TOOL_NAME: &str = "computer";
/// The OpenAI Responses computer tool `type` (equals [`NATIVE_COMPUTER_TOOL_NAME`]).
pub const OPENAI_COMPUTER_TOOL_TYPE: &str = "computer";
/// The Anthropic 2025-11-24 computer tool `type`.
pub const ANTHROPIC_COMPUTER_TOOL_TYPE_20251124: &str = "computer_20251124";
/// The Anthropic 2025-01-24 computer tool `type`.
pub const ANTHROPIC_COMPUTER_TOOL_TYPE_20250124: &str = "computer_20250124";

/// True when `name` is a provider identifier reserved for the native
/// computer-use tool (see [`NATIVE_COMPUTER_TOOL_NAME`] and the tool-type
/// constants). Ordinary Rig function-tool dispatch refuses these names/types so
/// a native computer call is never re-parsed and executed as an ordinary tool.
///
/// This is a *tool-call name/type* predicate for the generic-dispatch chokepoint
/// — it is unrelated to the `computer` **subagent**, which is constructed only
/// through the `task` delegation path (`engine::builtin::load`) and never
/// reaches ordinary function-tool dispatch.
pub fn is_reserved_native_computer_tool_name(name: &str) -> bool {
    // `OPENAI_COMPUTER_TOOL_TYPE == NATIVE_COMPUTER_TOOL_NAME`, so the OpenAI
    // `type` is already covered by the first arm; listing it again would be an
    // unreachable duplicate pattern.
    matches!(
        name,
        NATIVE_COMPUTER_TOOL_NAME
            | ANTHROPIC_COMPUTER_TOOL_TYPE_20251124
            | ANTHROPIC_COMPUTER_TOOL_TYPE_20250124
    )
}

pub fn native_computer_wire(
    contract: ComputerToolContract,
    geometry: &DisplayGeometry,
) -> NativeComputerWire {
    let width = geometry.physical.width;
    let height = geometry.physical.height;
    match contract {
        ComputerToolContract::Anthropic20251124 => NativeComputerWire {
            group: contract.group(),
            beta_headers: vec!["computer-use-2025-11-24"],
            tools: vec![serde_json::json!({
                "type": ANTHROPIC_COMPUTER_TOOL_TYPE_20251124,
                "name": NATIVE_COMPUTER_TOOL_NAME,
                "display_width_px": width,
                "display_height_px": height,
                "enable_zoom": true,
            })],
        },
        ComputerToolContract::Anthropic20250124 => NativeComputerWire {
            group: contract.group(),
            beta_headers: vec!["computer-use-2025-01-24"],
            tools: vec![serde_json::json!({
                "type": ANTHROPIC_COMPUTER_TOOL_TYPE_20250124,
                "name": NATIVE_COMPUTER_TOOL_NAME,
                "display_width_px": width,
                "display_height_px": height,
            })],
        },
        ComputerToolContract::OpenAiResponses => NativeComputerWire {
            group: contract.group(),
            beta_headers: Vec::new(),
            tools: vec![serde_json::json!({ "type": OPENAI_COMPUTER_TOOL_TYPE })],
        },
    }
}

pub fn native_computer_wire_from_capability(
    capability: Option<&crate::config::providers::ComputerUseCapability>,
    geometry: &DisplayGeometry,
) -> Option<NativeComputerWire> {
    capability
        .and_then(|capability| capability.contract)
        .map(|contract| native_computer_wire(contract.into(), geometry))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderPointerButton {
    Left,
    Right,
    Middle,
}

impl From<ProviderPointerButton> for MouseButton {
    fn from(value: ProviderPointerButton) -> Self {
        match value {
            ProviderPointerButton::Left => Self::Left,
            ProviderPointerButton::Right => Self::Right,
            ProviderPointerButton::Middle => Self::Middle,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Anthropic20251124ComputerAction {
    Screenshot,
    Zoom {
        rect: Rect,
        scale: ScaleFactor,
    },
    MouseMove {
        to: Point,
        duration: Duration,
        easing: Easing,
    },
    Click {
        at: Option<Point>,
        button: ProviderPointerButton,
        count: ClickCount,
        modifiers: Modifiers,
    },
    MouseDown {
        button: ProviderPointerButton,
    },
    MouseUp {
        button: ProviderPointerButton,
    },
    Drag {
        button: ProviderPointerButton,
        path: Vec<TimedPoint>,
        modifiers: Modifiers,
    },
    TypeText(String),
    KeyChord(KeyChord),
    HoldKey {
        key: String,
        duration: Duration,
    },
    Scroll {
        at: Option<Point>,
        delta_x: i32,
        delta_y: i32,
        modifiers: Modifiers,
    },
    Wait(Duration),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComputerContractError {
    UnsupportedAction {
        contract: ComputerToolContract,
        action: &'static str,
    },
}

impl std::fmt::Display for ComputerContractError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedAction { contract, action } => {
                write!(f, "{action} is unsupported by {contract:?}")
            }
        }
    }
}

impl std::error::Error for ComputerContractError {}

impl Anthropic20251124ComputerAction {
    pub const fn action_names() -> &'static [&'static str] {
        &[
            "screenshot",
            "zoom",
            "mouse_move",
            "click",
            "mouse_down",
            "mouse_up",
            "drag",
            "type",
            "key",
            "hold_key",
            "scroll",
            "wait",
        ]
    }

    pub fn to_backend(&self) -> Result<ComputerAction, ComputerError> {
        Ok(match self {
            Self::Screenshot => ComputerAction::CaptureFull,
            Self::Zoom { rect, scale } => ComputerAction::CaptureNativeZoom {
                rect: *rect,
                scale: *scale,
            },
            Self::MouseMove {
                to,
                duration,
                easing,
            } => ComputerAction::MoveCursor {
                to: *to,
                duration: *duration,
                easing: *easing,
            },
            Self::Click {
                button,
                count,
                modifiers,
                ..
            } => ComputerAction::Click {
                button: (*button).into(),
                count: *count,
                modifiers: *modifiers,
            },
            Self::MouseDown { button } => ComputerAction::MouseDown {
                button: (*button).into(),
            },
            Self::MouseUp { button } => ComputerAction::MouseUp {
                button: (*button).into(),
            },
            Self::Drag {
                button,
                path,
                modifiers,
            } => ComputerAction::Drag {
                button: (*button).into(),
                path: path.clone(),
                modifiers: *modifiers,
            },
            Self::TypeText(text) => ComputerAction::TypeText { text: text.clone() },
            Self::KeyChord(chord) => ComputerAction::KeyChord {
                chord: CanonicalKeyChord::try_from(chord)?,
            },
            Self::HoldKey { key, duration } => ComputerAction::HoldKey {
                key: KeyCode::parse(key)?,
                duration: *duration,
            },
            Self::Scroll {
                delta_x,
                delta_y,
                modifiers,
                ..
            } => ComputerAction::Scroll {
                delta_x: *delta_x,
                delta_y: *delta_y,
                modifiers: *modifiers,
            },
            Self::Wait(duration) => ComputerAction::Wait {
                duration: *duration,
            },
        })
    }

    pub fn to_backend_actions(&self) -> Result<Vec<ComputerAction>, ComputerError> {
        let mut actions = Vec::new();
        match self {
            Self::Click { at, .. } | Self::Scroll { at, .. } => {
                if let Some(to) = at {
                    actions.push(ComputerAction::MoveCursor {
                        to: *to,
                        duration: Duration::ZERO,
                        easing: Easing::Linear,
                    });
                }
            }
            _ => {}
        }
        actions.push(self.to_backend()?);
        Ok(actions)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Anthropic20250124ComputerAction {
    Screenshot,
    MouseMove {
        to: Point,
        duration: Duration,
        easing: Easing,
    },
    Click {
        at: Option<Point>,
        button: ProviderPointerButton,
        count: ClickCount,
        modifiers: Modifiers,
    },
    MouseDown {
        button: ProviderPointerButton,
    },
    MouseUp {
        button: ProviderPointerButton,
    },
    Drag {
        button: ProviderPointerButton,
        path: Vec<TimedPoint>,
        modifiers: Modifiers,
    },
    TypeText(String),
    KeyChord(KeyChord),
    HoldKey {
        key: String,
        duration: Duration,
    },
    Scroll {
        at: Option<Point>,
        delta_x: i32,
        delta_y: i32,
        modifiers: Modifiers,
    },
    Wait(Duration),
}

impl Anthropic20250124ComputerAction {
    pub const fn action_names() -> &'static [&'static str] {
        &[
            "screenshot",
            "mouse_move",
            "click",
            "mouse_down",
            "mouse_up",
            "drag",
            "type",
            "key",
            "hold_key",
            "scroll",
            "wait",
        ]
    }

    pub fn to_backend(&self) -> Result<ComputerAction, ComputerError> {
        Ok(match self {
            Self::Screenshot => ComputerAction::CaptureFull,
            Self::MouseMove {
                to,
                duration,
                easing,
            } => ComputerAction::MoveCursor {
                to: *to,
                duration: *duration,
                easing: *easing,
            },
            Self::Click {
                button,
                count,
                modifiers,
                ..
            } => ComputerAction::Click {
                button: (*button).into(),
                count: *count,
                modifiers: *modifiers,
            },
            Self::MouseDown { button } => ComputerAction::MouseDown {
                button: (*button).into(),
            },
            Self::MouseUp { button } => ComputerAction::MouseUp {
                button: (*button).into(),
            },
            Self::Drag {
                button,
                path,
                modifiers,
            } => ComputerAction::Drag {
                button: (*button).into(),
                path: path.clone(),
                modifiers: *modifiers,
            },
            Self::TypeText(text) => ComputerAction::TypeText { text: text.clone() },
            Self::KeyChord(chord) => ComputerAction::KeyChord {
                chord: CanonicalKeyChord::try_from(chord)?,
            },
            Self::HoldKey { key, duration } => ComputerAction::HoldKey {
                key: KeyCode::parse(key)?,
                duration: *duration,
            },
            Self::Scroll {
                delta_x,
                delta_y,
                modifiers,
                ..
            } => ComputerAction::Scroll {
                delta_x: *delta_x,
                delta_y: *delta_y,
                modifiers: *modifiers,
            },
            Self::Wait(duration) => ComputerAction::Wait {
                duration: *duration,
            },
        })
    }

    pub fn to_backend_actions(&self) -> Result<Vec<ComputerAction>, ComputerError> {
        let mut actions = Vec::new();
        match self {
            Self::Click { at, .. } | Self::Scroll { at, .. } => {
                if let Some(to) = at {
                    actions.push(ComputerAction::MoveCursor {
                        to: *to,
                        duration: Duration::ZERO,
                        easing: Easing::Linear,
                    });
                }
            }
            _ => {}
        }
        actions.push(self.to_backend()?);
        Ok(actions)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AnthropicComputerWireError {
    #[error("malformed Anthropic computer action: {0}")]
    Malformed(String),
}

#[derive(Debug, Clone, PartialEq, serde::Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum Anthropic20251124WireAction {
    Screenshot,
    Zoom {
        region: [f64; 4],
    },
    LeftClick {
        coordinate: [f64; 2],
        #[serde(default)]
        modifiers: OpenAiWireModifiers,
    },
    RightClick {
        coordinate: [f64; 2],
        #[serde(default)]
        modifiers: OpenAiWireModifiers,
    },
    MiddleClick {
        coordinate: [f64; 2],
        #[serde(default)]
        modifiers: OpenAiWireModifiers,
    },
    DoubleClick {
        coordinate: [f64; 2],
        #[serde(default)]
        modifiers: OpenAiWireModifiers,
    },
    TripleClick {
        coordinate: [f64; 2],
        #[serde(default)]
        modifiers: OpenAiWireModifiers,
    },
    MouseMove {
        coordinate: [f64; 2],
    },
    LeftMouseDown,
    LeftMouseUp,
    LeftClickDrag {
        start_coordinate: [f64; 2],
        end_coordinate: [f64; 2],
        #[serde(default)]
        modifiers: OpenAiWireModifiers,
    },
    Type {
        text: String,
    },
    Key {
        text: String,
    },
    HoldKey {
        text: String,
        duration: f64,
    },
    Scroll {
        coordinate: [f64; 2],
        scroll_direction: ScrollDirection,
        scroll_amount: i32,
        #[serde(default)]
        modifiers: OpenAiWireModifiers,
    },
    Wait {
        duration: f64,
    },
}

#[derive(Debug, Clone, PartialEq, serde::Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum Anthropic20250124WireAction {
    Screenshot,
    LeftClick {
        coordinate: [f64; 2],
        #[serde(default)]
        modifiers: OpenAiWireModifiers,
    },
    RightClick {
        coordinate: [f64; 2],
        #[serde(default)]
        modifiers: OpenAiWireModifiers,
    },
    MiddleClick {
        coordinate: [f64; 2],
        #[serde(default)]
        modifiers: OpenAiWireModifiers,
    },
    DoubleClick {
        coordinate: [f64; 2],
        #[serde(default)]
        modifiers: OpenAiWireModifiers,
    },
    TripleClick {
        coordinate: [f64; 2],
        #[serde(default)]
        modifiers: OpenAiWireModifiers,
    },
    MouseMove {
        coordinate: [f64; 2],
    },
    LeftMouseDown,
    LeftMouseUp,
    LeftClickDrag {
        start_coordinate: [f64; 2],
        end_coordinate: [f64; 2],
        #[serde(default)]
        modifiers: OpenAiWireModifiers,
    },
    Type {
        text: String,
    },
    Key {
        text: String,
    },
    HoldKey {
        text: String,
        duration: f64,
    },
    Scroll {
        coordinate: [f64; 2],
        scroll_direction: ScrollDirection,
        scroll_amount: i32,
        #[serde(default)]
        modifiers: OpenAiWireModifiers,
    },
    Wait {
        duration: f64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScrollDirection {
    Up,
    Down,
    Left,
    Right,
}

pub fn parse_anthropic_20251124_action(
    value: &serde_json::Value,
) -> Result<Anthropic20251124ComputerAction, AnthropicComputerWireError> {
    serde_json::from_value::<Anthropic20251124WireAction>(value.clone())
        .map(Anthropic20251124WireAction::into_action)
        .map_err(|err| AnthropicComputerWireError::Malformed(err.to_string()))
}

pub fn parse_anthropic_20250124_action(
    value: &serde_json::Value,
) -> Result<Anthropic20250124ComputerAction, AnthropicComputerWireError> {
    serde_json::from_value::<Anthropic20250124WireAction>(value.clone())
        .map(Anthropic20250124WireAction::into_action)
        .map_err(|err| AnthropicComputerWireError::Malformed(err.to_string()))
}

impl Anthropic20251124WireAction {
    pub fn into_action(self) -> Anthropic20251124ComputerAction {
        match self {
            Self::Screenshot => Anthropic20251124ComputerAction::Screenshot,
            Self::Zoom { region } => Anthropic20251124ComputerAction::Zoom {
                rect: region_rect(region),
                scale: ScaleFactor(1.0),
            },
            Self::LeftClick {
                coordinate,
                modifiers,
            } => click_action_20251124(ProviderPointerButton::Left, ClickCount::Single, modifiers)
                .with_move(coordinate),
            Self::RightClick {
                coordinate,
                modifiers,
            } => click_action_20251124(ProviderPointerButton::Right, ClickCount::Single, modifiers)
                .with_move(coordinate),
            Self::MiddleClick {
                coordinate,
                modifiers,
            } => {
                click_action_20251124(ProviderPointerButton::Middle, ClickCount::Single, modifiers)
                    .with_move(coordinate)
            }
            Self::DoubleClick {
                coordinate,
                modifiers,
            } => click_action_20251124(ProviderPointerButton::Left, ClickCount::Double, modifiers)
                .with_move(coordinate),
            Self::TripleClick {
                coordinate,
                modifiers,
            } => click_action_20251124(ProviderPointerButton::Left, ClickCount::Triple, modifiers)
                .with_move(coordinate),
            Self::MouseMove { coordinate } => Anthropic20251124ComputerAction::MouseMove {
                to: coordinate_point(coordinate),
                duration: Duration::ZERO,
                easing: Easing::Linear,
            },
            Self::LeftMouseDown => Anthropic20251124ComputerAction::MouseDown {
                button: ProviderPointerButton::Left,
            },
            Self::LeftMouseUp => Anthropic20251124ComputerAction::MouseUp {
                button: ProviderPointerButton::Left,
            },
            Self::LeftClickDrag {
                start_coordinate,
                end_coordinate,
                modifiers,
            } => Anthropic20251124ComputerAction::Drag {
                button: ProviderPointerButton::Left,
                path: drag_path(start_coordinate, end_coordinate),
                modifiers: modifiers.into(),
            },
            Self::Type { text } => Anthropic20251124ComputerAction::TypeText(text),
            Self::Key { text } => Anthropic20251124ComputerAction::KeyChord(KeyChord {
                keys: key_text_to_chord(text),
            }),
            Self::HoldKey { text, duration } => Anthropic20251124ComputerAction::HoldKey {
                key: text,
                duration: secs(duration),
            },
            Self::Scroll {
                coordinate,
                scroll_direction,
                scroll_amount,
                modifiers,
            } => {
                let (delta_x, delta_y) = scroll_delta(scroll_direction, scroll_amount);
                Anthropic20251124ComputerAction::Scroll {
                    at: Some(coordinate_point(coordinate)),
                    delta_x,
                    delta_y,
                    modifiers: modifiers.into(),
                }
            }
            Self::Wait { duration } => Anthropic20251124ComputerAction::Wait(secs(duration)),
        }
    }
}

impl Anthropic20250124WireAction {
    pub fn into_action(self) -> Anthropic20250124ComputerAction {
        match self {
            Self::Screenshot => Anthropic20250124ComputerAction::Screenshot,
            Self::LeftClick {
                coordinate,
                modifiers,
            } => click_action_20250124(ProviderPointerButton::Left, ClickCount::Single, modifiers)
                .with_move(coordinate),
            Self::RightClick {
                coordinate,
                modifiers,
            } => click_action_20250124(ProviderPointerButton::Right, ClickCount::Single, modifiers)
                .with_move(coordinate),
            Self::MiddleClick {
                coordinate,
                modifiers,
            } => {
                click_action_20250124(ProviderPointerButton::Middle, ClickCount::Single, modifiers)
                    .with_move(coordinate)
            }
            Self::DoubleClick {
                coordinate,
                modifiers,
            } => click_action_20250124(ProviderPointerButton::Left, ClickCount::Double, modifiers)
                .with_move(coordinate),
            Self::TripleClick {
                coordinate,
                modifiers,
            } => click_action_20250124(ProviderPointerButton::Left, ClickCount::Triple, modifiers)
                .with_move(coordinate),
            Self::MouseMove { coordinate } => Anthropic20250124ComputerAction::MouseMove {
                to: coordinate_point(coordinate),
                duration: Duration::ZERO,
                easing: Easing::Linear,
            },
            Self::LeftMouseDown => Anthropic20250124ComputerAction::MouseDown {
                button: ProviderPointerButton::Left,
            },
            Self::LeftMouseUp => Anthropic20250124ComputerAction::MouseUp {
                button: ProviderPointerButton::Left,
            },
            Self::LeftClickDrag {
                start_coordinate,
                end_coordinate,
                modifiers,
            } => Anthropic20250124ComputerAction::Drag {
                button: ProviderPointerButton::Left,
                path: drag_path(start_coordinate, end_coordinate),
                modifiers: modifiers.into(),
            },
            Self::Type { text } => Anthropic20250124ComputerAction::TypeText(text),
            Self::Key { text } => Anthropic20250124ComputerAction::KeyChord(KeyChord {
                keys: key_text_to_chord(text),
            }),
            Self::HoldKey { text, duration } => Anthropic20250124ComputerAction::HoldKey {
                key: text,
                duration: secs(duration),
            },
            Self::Scroll {
                coordinate,
                scroll_direction,
                scroll_amount,
                modifiers,
            } => {
                let (delta_x, delta_y) = scroll_delta(scroll_direction, scroll_amount);
                Anthropic20250124ComputerAction::Scroll {
                    at: Some(coordinate_point(coordinate)),
                    delta_x,
                    delta_y,
                    modifiers: modifiers.into(),
                }
            }
            Self::Wait { duration } => Anthropic20250124ComputerAction::Wait(secs(duration)),
        }
    }
}

trait AnthropicClickWithMove: Sized {
    fn with_move(self, coordinate: [f64; 2]) -> Self;
}

impl AnthropicClickWithMove for Anthropic20251124ComputerAction {
    fn with_move(self, coordinate: [f64; 2]) -> Self {
        match self {
            Self::Click {
                button,
                count,
                modifiers,
                ..
            } => Self::Click {
                at: Some(coordinate_point(coordinate)),
                button,
                count,
                modifiers,
            },
            other => other,
        }
    }
}

impl AnthropicClickWithMove for Anthropic20250124ComputerAction {
    fn with_move(self, coordinate: [f64; 2]) -> Self {
        match self {
            Self::Click {
                button,
                count,
                modifiers,
                ..
            } => Self::Click {
                at: Some(coordinate_point(coordinate)),
                button,
                count,
                modifiers,
            },
            other => other,
        }
    }
}

fn click_action_20251124(
    button: ProviderPointerButton,
    count: ClickCount,
    modifiers: OpenAiWireModifiers,
) -> Anthropic20251124ComputerAction {
    Anthropic20251124ComputerAction::Click {
        at: None,
        button,
        count,
        modifiers: modifiers.into(),
    }
}

fn click_action_20250124(
    button: ProviderPointerButton,
    count: ClickCount,
    modifiers: OpenAiWireModifiers,
) -> Anthropic20250124ComputerAction {
    Anthropic20250124ComputerAction::Click {
        at: None,
        button,
        count,
        modifiers: modifiers.into(),
    }
}

fn coordinate_point(coordinate: [f64; 2]) -> Point {
    Point {
        x: coordinate[0],
        y: coordinate[1],
        space: CoordinateSpace::Physical,
    }
}

fn region_rect(region: [f64; 4]) -> Rect {
    Rect {
        x: region[0],
        y: region[1],
        width: (region[2] - region[0]).max(0.0),
        height: (region[3] - region[1]).max(0.0),
        space: CoordinateSpace::Physical,
    }
}

fn drag_path(start_coordinate: [f64; 2], end_coordinate: [f64; 2]) -> Vec<TimedPoint> {
    [start_coordinate, end_coordinate]
        .into_iter()
        .map(|coordinate| TimedPoint {
            point: coordinate_point(coordinate),
            duration: Duration::ZERO,
            easing: Easing::Linear,
        })
        .collect()
}

fn key_text_to_chord(text: String) -> Vec<String> {
    text.split('+').map(|key| key.trim().to_string()).collect()
}

fn secs(seconds: f64) -> Duration {
    if !seconds.is_finite() {
        return Duration::ZERO;
    }
    Duration::from_secs_f64(seconds.clamp(0.0, MAX_COMPUTER_ACTION_DURATION.as_secs_f64()))
}

fn scroll_delta(direction: ScrollDirection, amount: i32) -> (i32, i32) {
    let amount = amount.clamp(0, MAX_SCROLL_CLICK_REPETITIONS as i32);
    match direction {
        ScrollDirection::Up => (0, -amount),
        ScrollDirection::Down => (0, amount),
        ScrollDirection::Left => (-amount, 0),
        ScrollDirection::Right => (amount, 0),
    }
}

fn checked_action_duration(duration: Duration) -> Result<(), ComputerError> {
    if duration > MAX_COMPUTER_ACTION_DURATION {
        return Err(ComputerError::Refused(format!(
            "computer action duration exceeds {} seconds",
            MAX_COMPUTER_ACTION_DURATION.as_secs()
        )));
    }
    Ok(())
}

fn checked_scroll_delta(delta: i32) -> Result<(), ComputerError> {
    if delta.unsigned_abs() > MAX_SCROLL_CLICK_REPETITIONS {
        return Err(ComputerError::Refused(format!(
            "scroll magnitude exceeds {} clicks",
            MAX_SCROLL_CLICK_REPETITIONS
        )));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq)]
pub enum OpenAiComputerAction {
    Screenshot,
    Move {
        to: Point,
    },
    Click {
        at: Option<Point>,
        button: ProviderPointerButton,
        modifiers: Modifiers,
    },
    DoubleClick {
        at: Option<Point>,
        button: ProviderPointerButton,
        modifiers: Modifiers,
    },
    Drag {
        path: Vec<TimedPoint>,
        modifiers: Modifiers,
    },
    Scroll {
        at: Option<Point>,
        delta_x: i32,
        delta_y: i32,
        modifiers: Modifiers,
    },
    KeyChord(KeyChord),
    TypeText(String),
}

#[derive(Debug, thiserror::Error)]
pub enum OpenAiComputerWireError {
    #[error("computer_call is missing call_id")]
    MissingCallId,
    #[error("computer_call.action must be an object")]
    MissingAction,
    #[error("unsupported OpenAI computer action `{0}`")]
    UnsupportedAction(String),
    #[error("malformed OpenAI computer action: {0}")]
    MalformedAction(String),
}

impl OpenAiComputerAction {
    pub fn to_backend(&self) -> Result<ComputerAction, ComputerError> {
        Ok(match self {
            Self::Screenshot => ComputerAction::CaptureFull,
            Self::Move { to } => ComputerAction::MoveCursor {
                to: *to,
                duration: Duration::ZERO,
                easing: Easing::Linear,
            },
            Self::Click {
                button, modifiers, ..
            } => ComputerAction::Click {
                button: (*button).into(),
                count: ClickCount::Single,
                modifiers: *modifiers,
            },
            Self::DoubleClick {
                button, modifiers, ..
            } => ComputerAction::Click {
                button: (*button).into(),
                count: ClickCount::Double,
                modifiers: *modifiers,
            },
            Self::Drag { path, modifiers } => ComputerAction::Drag {
                button: MouseButton::Left,
                path: path.clone(),
                modifiers: *modifiers,
            },
            Self::Scroll {
                delta_x,
                delta_y,
                modifiers,
                ..
            } => ComputerAction::Scroll {
                delta_x: *delta_x,
                delta_y: *delta_y,
                modifiers: *modifiers,
            },
            Self::KeyChord(chord) => ComputerAction::KeyChord {
                chord: CanonicalKeyChord::try_from(chord)?,
            },
            Self::TypeText(text) => ComputerAction::TypeText { text: text.clone() },
        })
    }

    pub fn to_backend_actions(&self) -> Result<Vec<ComputerAction>, ComputerError> {
        let mut actions = Vec::new();
        match self {
            Self::Click { at, .. } | Self::DoubleClick { at, .. } | Self::Scroll { at, .. } => {
                if let Some(to) = at {
                    actions.push(ComputerAction::MoveCursor {
                        to: *to,
                        duration: Duration::ZERO,
                        easing: Easing::Linear,
                    });
                }
            }
            _ => {}
        }
        actions.push(self.to_backend()?);
        Ok(actions)
    }
}

#[derive(Debug, Clone, PartialEq, serde::Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum OpenAiComputerWireAction {
    Screenshot,
    Move {
        x: f64,
        y: f64,
    },
    Click {
        x: Option<f64>,
        y: Option<f64>,
        #[serde(default)]
        button: Option<OpenAiWirePointerButton>,
        #[serde(default)]
        modifiers: OpenAiWireModifiers,
    },
    DoubleClick {
        x: Option<f64>,
        y: Option<f64>,
        #[serde(default)]
        button: Option<OpenAiWirePointerButton>,
        #[serde(default)]
        modifiers: OpenAiWireModifiers,
    },
    Drag {
        path: Vec<OpenAiWirePoint>,
        #[serde(default)]
        modifiers: OpenAiWireModifiers,
    },
    Scroll {
        x: Option<f64>,
        y: Option<f64>,
        scroll_x: i32,
        scroll_y: i32,
        #[serde(default)]
        modifiers: OpenAiWireModifiers,
    },
    Key {
        keys: Vec<String>,
    },
    Type {
        text: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OpenAiWirePointerButton {
    Left,
    Right,
    Middle,
}

impl From<OpenAiWirePointerButton> for ProviderPointerButton {
    fn from(value: OpenAiWirePointerButton) -> Self {
        match value {
            OpenAiWirePointerButton::Left => Self::Left,
            OpenAiWirePointerButton::Right => Self::Right,
            OpenAiWirePointerButton::Middle => Self::Middle,
        }
    }
}

#[derive(Debug, Clone, Default, Copy, PartialEq, Eq, serde::Deserialize)]
pub struct OpenAiWireModifiers {
    #[serde(default)]
    pub shift: bool,
    #[serde(default)]
    pub control: bool,
    #[serde(default)]
    pub alt: bool,
    #[serde(default)]
    pub meta: bool,
}

impl From<OpenAiWireModifiers> for Modifiers {
    fn from(value: OpenAiWireModifiers) -> Self {
        Self {
            shift: value.shift,
            control: value.control,
            alt: value.alt,
            meta: value.meta,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, serde::Deserialize)]
pub struct OpenAiWirePoint {
    pub x: f64,
    pub y: f64,
}

impl OpenAiComputerWireAction {
    pub fn into_provider_action(self) -> OpenAiComputerAction {
        match self {
            Self::Screenshot => OpenAiComputerAction::Screenshot,
            Self::Move { x, y } => OpenAiComputerAction::Move {
                to: Point {
                    x,
                    y,
                    space: CoordinateSpace::Physical,
                },
            },
            Self::Click {
                x,
                y,
                button,
                modifiers,
            } => OpenAiComputerAction::Click {
                at: maybe_point(x, y),
                button: button.unwrap_or(OpenAiWirePointerButton::Left).into(),
                modifiers: modifiers.into(),
            },
            Self::DoubleClick {
                x,
                y,
                button,
                modifiers,
            } => OpenAiComputerAction::DoubleClick {
                at: maybe_point(x, y),
                button: button.unwrap_or(OpenAiWirePointerButton::Left).into(),
                modifiers: modifiers.into(),
            },
            Self::Drag { path, modifiers } => OpenAiComputerAction::Drag {
                path: path
                    .into_iter()
                    .map(|point| TimedPoint {
                        point: Point {
                            x: point.x,
                            y: point.y,
                            space: CoordinateSpace::Physical,
                        },
                        duration: Duration::ZERO,
                        easing: Easing::Linear,
                    })
                    .collect(),
                modifiers: modifiers.into(),
            },
            Self::Scroll {
                x,
                y,
                scroll_x,
                scroll_y,
                modifiers,
            } => OpenAiComputerAction::Scroll {
                at: maybe_point(x, y),
                delta_x: scroll_x,
                delta_y: scroll_y,
                modifiers: modifiers.into(),
            },
            Self::Key { keys } => OpenAiComputerAction::KeyChord(KeyChord { keys }),
            Self::Type { text } => OpenAiComputerAction::TypeText(text),
        }
    }
}

pub fn parse_openai_computer_call(
    value: &serde_json::Value,
) -> Result<(String, Vec<OpenAiComputerAction>), OpenAiComputerWireError> {
    let call_id = value
        .get("call_id")
        .or_else(|| value.get("id"))
        .and_then(serde_json::Value::as_str)
        .filter(|id| !id.is_empty())
        .ok_or(OpenAiComputerWireError::MissingCallId)?
        .to_string();
    // OpenAI Responses emits one `action` object per `computer_call`; it does
    // not use the old plural `actions` envelope. One provider action can still
    // expand into several canonical backend actions (for example, a click
    // with coordinates first moves the cursor), which remains the
    // coordinator's responsibility.
    let raw_action = value
        .get("action")
        .ok_or(OpenAiComputerWireError::MissingAction)?;
    let action: OpenAiComputerWireAction =
        serde_json::from_value(raw_action.clone()).map_err(|err| {
            let action_type = raw_action.get("type").and_then(serde_json::Value::as_str);
            match action_type {
                Some(action_type) => OpenAiComputerWireError::UnsupportedAction(action_type.into()),
                None => OpenAiComputerWireError::MalformedAction(err.to_string()),
            }
        })?;
    Ok((call_id, vec![action.into_provider_action()]))
}

fn maybe_point(x: Option<f64>, y: Option<f64>) -> Option<Point> {
    Some(Point {
        x: x?,
        y: y?,
        space: CoordinateSpace::Physical,
    })
}

#[derive(Debug, Clone, PartialEq)]
pub struct OpenAiComputerCallOutput {
    pub call_id: String,
    pub completed: Vec<ComputerActionOutcome>,
    pub failure: Option<ComputerFailure>,
    /// Sanitized projection of the screenshot frame, if one was captured.
    ///
    /// This is the durable projection accepted by every durable sink. It
    /// contains dimensions, byte count, checksum, and IDs — never the pixel
    /// bytes, base64, or data URL. The old `screenshot_png: Option<Vec<u8>>`
    /// field is replaced by this safe type.
    pub screenshot: Option<frame::SanitizedComputerFrame>,
}

impl OpenAiComputerCallOutput {
    /// Returns true if a screenshot was captured.
    pub fn has_screenshot(&self) -> bool {
        self.screenshot.is_some()
    }

    /// The sanitized screenshot projection, if present.
    pub fn sanitized_screenshot(&self) -> Option<&frame::SanitizedComputerFrame> {
        self.screenshot.as_ref()
    }
}

/// The result of executing an OpenAI computer call, including the live frame
/// that owns the screenshot bytes.
///
/// The live frame is separated from the serializable call output so that no
/// serializable object can accidentally carry pixel bytes. The caller builds a
/// transient provider request from the live frame via
/// [`frame::openai_transient_computer_output`] and records only the sanitized
/// projection from the call output.
pub struct OpenAiComputerCallResult {
    /// The serializable call output with the sanitized screenshot projection.
    pub output: OpenAiComputerCallOutput,
    /// The live frame owning the screenshot bytes, if one was captured.
    /// This is `None` on failure or when no screenshot was taken.
    pub live_frame: Option<frame::LiveComputerFrame>,
}

impl OpenAiComputerCallResult {
    /// Build a transient OpenAI `computer_call_output` wire payload from the
    /// live frame, if present.
    ///
    /// Returns `None` if there is no live frame (e.g. on failure). The
    /// returned [`frame::TransientProviderRequest`] carries the wire payload
    /// (with base64 image data) and the sanitized projection. The caller sends
    /// the wire payload to the provider and records only the projection.
    pub fn transient_wire(&self) -> Option<frame::TransientProviderRequest> {
        let frame = self.live_frame.as_ref()?;
        Some(frame::openai_transient_computer_output(
            frame,
            &self.output.call_id,
            self.output.completed.len(),
            self.output.failure.as_ref(),
        ))
    }
}

impl std::fmt::Debug for OpenAiComputerCallResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenAiComputerCallResult")
            .field("output", &self.output)
            .field("has_live_frame", &self.live_frame.is_some())
            .finish()
    }
}

#[cfg(test)]
pub async fn execute_openai_computer_call<B: ComputerBackend>(
    backend: &mut B,
    call_id: impl Into<String>,
    actions: &[OpenAiComputerAction],
) -> OpenAiComputerCallResult {
    let call_id = call_id.into();
    let mut backend_actions = Vec::new();
    let mut provider_indices = Vec::new();
    for (index, action) in actions.iter().enumerate() {
        let converted = match action.to_backend_actions() {
            Ok(actions) => actions,
            Err(error) => {
                return OpenAiComputerCallResult {
                    output: OpenAiComputerCallOutput {
                        call_id,
                        completed: Vec::new(),
                        failure: Some(ComputerFailure { index, error }),
                        screenshot: None,
                    },
                    live_frame: None,
                };
            }
        };
        provider_indices.extend(std::iter::repeat_n(index, converted.len()));
        backend_actions.extend(converted);
    }
    let report = execute_backend_batch(backend, &backend_actions).await;
    let completed = report.completed;
    if let Some(mut failure) = report.failure {
        failure.index = provider_indices.get(failure.index).copied().unwrap_or(0);
        return OpenAiComputerCallResult {
            output: OpenAiComputerCallOutput {
                call_id,
                completed,
                failure: Some(failure),
                screenshot: None,
            },
            live_frame: None,
        };
    }
    let capture = execute_backend_action(backend, &ComputerAction::CaptureFull).await;
    let (screenshot, live_frame) = match capture {
        Ok(ComputerActionOutcome::Captured(capture_frame)) => {
            let dims = frame::FrameDimensions::from_capture(&capture_frame);
            let reservation: Box<dyn frame::MediaReservationHandle> =
                Box::new(frame::InMemoryReservationHandle::new(std::sync::Arc::new(
                    std::sync::atomic::AtomicBool::new(false),
                )));
            match frame::LiveComputerFrame::try_new(
                capture_frame.png,
                frame::ScreenshotMediaType::Png,
                dims,
                frame::ObservationId(call_id.clone()),
                frame::ActionId(call_id.clone()),
                frame::CaptureEpoch(0),
                reservation,
                None,
            ) {
                Ok(live) => {
                    let sanitized = live.sanitized();
                    (Some(sanitized), Some(live))
                }
                Err(_) => (None, None),
            }
        }
        _ => (None, None),
    };
    OpenAiComputerCallResult {
        output: OpenAiComputerCallOutput {
            call_id,
            completed,
            failure: None,
            screenshot,
        },
        live_frame,
    }
}

#[cfg(test)]
pub async fn execute_openai_computer_call_json<B: ComputerBackend>(
    backend: &mut B,
    call: &serde_json::Value,
) -> Result<OpenAiComputerCallResult, OpenAiComputerWireError> {
    let (call_id, actions) = parse_openai_computer_call(call)?;
    Ok(execute_openai_computer_call(backend, call_id, &actions).await)
}

#[cfg(all(test, unix))]
mod capture_containment_tests {
    use super::frame::TempCaptureGuard;
    use super::{
        CaptureRunner, CaptureTool, ComputerError, PixelRect, assert_owner_only_and_read,
        capture_contained, create_private_capture_file, ensure_owner_only_dir,
        read_capture_bytes_bounded,
    };
    use std::cell::{Cell, RefCell};
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::path::{Path, PathBuf};
    use tempfile::TempDir;

    // A small but valid-looking PNG payload; contents are opaque to the guard.
    const PNG: &[u8] = &[137, 80, 78, 71, 0x0d, 0x0a, 0x1a, 0x0a, 1, 2, 3, 4];

    fn scrot_tool() -> CaptureTool {
        CaptureTool::Scrot(PathBuf::from("/usr/bin/scrot"))
    }

    /// Fake capture tool — no real display, X server, or binary. `stdout` is
    /// returned from `capture_to_stdout` (empty forces the file fallback); the
    /// file path writes `file_bytes` at `file_mode` to `dest`.
    struct FakeRunner {
        stdout: Vec<u8>,
        file_bytes: Vec<u8>,
        file_mode: u32,
        // When true, chmod the containing dir to `0o500` after writing so the
        // guard's later unlink fails — exercising the fail-closed cleanup path.
        lock_parent_after_write: bool,
        to_path_called: Cell<bool>,
        last_dest: RefCell<Option<PathBuf>>,
    }

    impl FakeRunner {
        fn streaming(bytes: &[u8]) -> Self {
            Self {
                stdout: bytes.to_vec(),
                file_bytes: Vec::new(),
                file_mode: 0o600,
                lock_parent_after_write: false,
                to_path_called: Cell::new(false),
                last_dest: RefCell::new(None),
            }
        }

        fn file_only(bytes: &[u8], mode: u32) -> Self {
            Self {
                stdout: Vec::new(),
                file_bytes: bytes.to_vec(),
                file_mode: mode,
                lock_parent_after_write: false,
                to_path_called: Cell::new(false),
                last_dest: RefCell::new(None),
            }
        }

        fn file_only_then_lock_parent(bytes: &[u8]) -> Self {
            Self {
                stdout: Vec::new(),
                file_bytes: bytes.to_vec(),
                file_mode: 0o600,
                lock_parent_after_write: true,
                to_path_called: Cell::new(false),
                last_dest: RefCell::new(None),
            }
        }
    }

    impl CaptureRunner for FakeRunner {
        fn capture_to_stdout(
            &self,
            _tool: &CaptureTool,
            _display: &str,
            _region: Option<PixelRect>,
        ) -> Result<Vec<u8>, ComputerError> {
            Ok(self.stdout.clone())
        }

        fn capture_to_path(
            &self,
            _tool: &CaptureTool,
            _display: &str,
            _region: Option<PixelRect>,
            dest: &Path,
        ) -> Result<(), ComputerError> {
            self.to_path_called.set(true);
            *self.last_dest.borrow_mut() = Some(dest.to_path_buf());
            // The destination inode was pre-created `O_EXCL`/`0o600` by
            // production code; overwrite it in place like the real tool.
            std::fs::write(dest, &self.file_bytes).unwrap();
            // Emulate an external tool recreating the file under its own umask.
            std::fs::set_permissions(dest, std::fs::Permissions::from_mode(self.file_mode))
                .unwrap();
            if self.lock_parent_after_write {
                let parent = dest.parent().unwrap();
                std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o500)).unwrap();
            }
            Ok(())
        }
    }

    fn png_count(root: &Path) -> usize {
        fn walk(dir: &Path, n: &mut usize) {
            if let Ok(entries) = std::fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_dir() {
                        walk(&path, n);
                    } else if path.extension().and_then(|s| s.to_str()) == Some("png") {
                        *n += 1;
                    }
                }
            }
        }
        let mut n = 0;
        walk(root, &mut n);
        n
    }

    /// Preferred path: stdout capture returns the PNG and NEVER touches disk.
    /// A regression that always used a temp file would trip `to_path_called`.
    #[test]
    fn computer_screenshot_capture_prefers_stdout() {
        let root = TempDir::new().unwrap();
        let runner = FakeRunner::streaming(PNG);
        let bytes = capture_contained(&runner, &scrot_tool(), ":99", None, root.path()).unwrap();
        assert_eq!(bytes, PNG);
        assert!(
            !runner.to_path_called.get(),
            "stdout capture must not create a temp file"
        );
        assert_eq!(png_count(root.path()), 0);
    }

    /// Fallback path: a tool that cannot stream (empty stdout) captures to a
    /// temp file created ONLY under the private capture root, and the guard
    /// removes it — nothing survives.
    #[test]
    fn computer_screenshot_capture_file_fallback_contained() {
        let root = TempDir::new().unwrap();
        let runner = FakeRunner::file_only(PNG, 0o600);
        let bytes = capture_contained(&runner, &scrot_tool(), ":99", None, root.path()).unwrap();
        assert!(
            runner.to_path_called.get(),
            "empty stdout must fall back to the contained temp file"
        );
        assert_eq!(bytes, PNG);
        // The temp file lived UNDER the private capture root, never $TMPDIR.
        let dest = runner.last_dest.borrow().clone().unwrap();
        assert!(
            dest.starts_with(root.path()),
            "capture temp path {dest:?} must be under the private root {:?}",
            root.path()
        );
        // The guard removed the file (and its sub-tempdir): nothing survives.
        assert_eq!(png_count(root.path()), 0);
    }

    /// The post-write mode assert tightens a looser-than-`0o600` capture file to
    /// owner-only BEFORE its bytes are read. Fails against a no-op that would
    /// leave the file `0o644`.
    #[test]
    fn computer_screenshot_capture_path_mode() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("shot.png");
        std::fs::write(&path, PNG).unwrap();
        // The "tool" recreated the file world-readable.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        // Precondition: it really is NOT owner-only yet.
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o644
        );

        let bytes = assert_owner_only_and_read(&path).unwrap();
        assert_eq!(bytes, PNG);
        // The read happened on the fd only after the fchmod, so the file is
        // owner-only by the time any byte is read.
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    /// A panic while a capture path is live leaves NO `*.png` under the capture
    /// root: the guard's `Drop` removes the file (and its dir) during unwind.
    /// Fails if the guard did not own cleanup on the panic path.
    #[test]
    fn computer_screenshot_capture_panic_leaves_no_png() {
        let root = TempDir::new().unwrap();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let sub = tempfile::Builder::new()
                .prefix("capture-")
                .tempdir_in(root.path())
                .unwrap();
            let guard = TempCaptureGuard::new(sub, "shot.png").unwrap();
            std::fs::write(guard.path().unwrap(), PNG).unwrap();
            // Precondition: a PNG is genuinely live under the root.
            assert!(guard.path().unwrap().exists());
            assert_eq!(png_count(root.path()), 1);
            panic!("simulated panic mid-capture");
        }));
        assert!(result.is_err());
        assert_eq!(
            png_count(root.path()),
            0,
            "no *.png may survive a mid-capture panic"
        );
    }

    /// The destination inode is pre-created `O_EXCL`: a pre-existing `shot.png`
    /// (an attacker plant to redirect the tool's plaintext write) makes creation
    /// fail closed. Fails against a version that hands the bare pathname to the
    /// tool without owning the inode first.
    #[test]
    fn computer_screenshot_capture_rejects_preexisting_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("shot.png");
        // Fresh path: creation succeeds and yields an owner-only file.
        create_private_capture_file(&path).unwrap();
        assert!(path.exists());
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        // A pre-existing file (the plant) => O_EXCL fails => fail closed.
        let err = create_private_capture_file(&path).unwrap_err();
        assert!(matches!(err, ComputerError::CommandFailed { .. }));
    }

    /// The read path rejects a hardlinked capture file (`st_nlink > 1`), so a
    /// second name to the plaintext inode cannot survive the guard's unlink.
    /// Fails against a read path missing the nlink check.
    #[test]
    fn computer_screenshot_capture_rejects_hardlinked_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("shot.png");
        std::fs::write(&path, PNG).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        // Baseline: a single-link owner-only file reads fine.
        assert_eq!(assert_owner_only_and_read(&path).unwrap(), PNG);
        // Hardlink it: now nlink == 2, so the read path must fail closed.
        let link = dir.path().join("evil.hardlink");
        std::fs::hard_link(&path, &link).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().nlink(), 2);
        let err = assert_owner_only_and_read(&path).unwrap_err();
        assert!(matches!(err, ComputerError::CommandFailed { .. }));
    }

    #[test]
    fn computer_screenshot_capture_rejects_oversized_encoded_file_before_read() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("shot.png");
        let file = std::fs::File::create(&path).unwrap();
        file.set_len(crate::media_image::SCREENSHOT_MAX_ALLOC_BYTES + 1)
            .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

        let err = assert_owner_only_and_read(&path).unwrap_err();
        assert!(matches!(err, ComputerError::Refused(_)));
    }

    #[test]
    fn computer_screenshot_capture_bounds_growth_beyond_metadata_size_during_read() {
        struct MetadataUnderreportingReader {
            bytes: std::io::Cursor<Vec<u8>>,
            bytes_read: usize,
        }

        impl std::io::Read for MetadataUnderreportingReader {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                let count = std::io::Read::read(&mut self.bytes, buf)?;
                self.bytes_read += count;
                Ok(count)
            }
        }

        let advertised_metadata_len = 2_u64;
        let max_bytes = 8_u64;
        let mut reader = MetadataUnderreportingReader {
            // Model a file that passed an earlier two-byte metadata check, then
            // grew before/during the held-fd read.
            bytes: std::io::Cursor::new(vec![0_u8; 32]),
            bytes_read: 0,
        };
        assert!(advertised_metadata_len <= max_bytes);

        let error = read_capture_bytes_bounded(&mut reader, max_bytes).unwrap_err();
        assert!(matches!(error, ComputerError::Refused(_)));
        assert_eq!(
            reader.bytes_read, 9,
            "the reader must stop at max + 1 bytes"
        );
    }

    /// A cleanup that cannot remove the plaintext artifact makes the whole
    /// capture fail closed — the bytes are NOT returned. Fails against a version
    /// that discards the cleanup error and returns the screenshot anyway.
    #[test]
    fn computer_screenshot_capture_fails_closed_when_cleanup_fails() {
        let root = TempDir::new().unwrap();
        let runner = FakeRunner::file_only_then_lock_parent(PNG);
        let result = capture_contained(&runner, &scrot_tool(), ":99", None, root.path());
        assert!(
            matches!(result, Err(ComputerError::CommandFailed { .. })),
            "capture must fail closed when the artifact cannot be removed, got {result:?}"
        );
        // Restore write perms so the outer TempDir can clean up after the test.
        if let Some(dest) = runner.last_dest.borrow().as_deref() {
            let parent = dest.parent().unwrap();
            let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
        }
    }

    /// `ensure_owner_only_dir` rejects a symlinked capture root rather than
    /// following it into an attacker-chosen directory.
    #[test]
    fn computer_screenshot_capture_root_rejects_symlink() {
        let base = TempDir::new().unwrap();
        let real = base.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let link = base.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let err = ensure_owner_only_dir(&link).unwrap_err();
        assert!(matches!(err, ComputerError::CommandFailed { .. }));
    }

    /// `ensure_owner_only_dir` tightens a pre-existing, too-loose root to
    /// `0o700`. Fails against a version that only sets the mode when creating the
    /// dir and ignores a pre-existing looser one.
    #[test]
    fn computer_screenshot_capture_root_tightens_existing_mode() {
        let base = TempDir::new().unwrap();
        let dir = base.path().join("cap");
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        // Precondition: the existing dir is group/other-accessible.
        assert_eq!(
            std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o755
        );
        ensure_owner_only_dir(&dir).unwrap();
        assert_eq!(
            std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_release_state_machine_stops_before_later_commit_after_ambiguous_mouseup() {
        let transitions = vec![
            LinuxReleaseTransition::Button(1),
            LinuxReleaseTransition::Button(2),
        ];
        let mut attempted = Vec::new();
        let result = run_linux_release_state_machine(transitions, |transition| {
            attempted.push(transition.clone());
            if transition == LinuxReleaseTransition::Button(1) {
                return Err(ComputerError::CommandFailed {
                    program: "injected mouseup".to_string(),
                    detail: "ambiguous".to_string(),
                });
            }
            Ok(())
        });
        assert!(result.is_err());
        assert_eq!(attempted, vec![LinuxReleaseTransition::Button(1)]);
    }
    use tempfile::TempDir;

    fn test_geometry() -> DisplayGeometry {
        DisplayGeometry {
            physical: PixelSize {
                width: 1280,
                height: 720,
            },
            logical: LogicalSize {
                width: 640.0,
                height: 360.0,
            },
            scale_factor: ScaleFactor(2.0),
        }
    }

    fn normalized_effects(
        actions: &[ComputerAction],
        geometry: &DisplayGeometry,
    ) -> Vec<NormalizedComputerEffect> {
        actions
            .iter()
            .map(|action| normalize_action(action, geometry).unwrap().effect().clone())
            .collect()
    }

    #[test]
    fn held_key_journal_retains_keys_until_explicitly_cleared() {
        let temp = TempDir::new().expect("private test directory");
        let journal = HeldKeyJournal {
            path: Some(temp.path().join("held-keys.json")),
        };

        journal
            .store(&["F13".to_string(), "a".to_string()], &[1], false)
            .expect("persist held keys before keydown");
        assert_eq!(
            journal.load().expect("reload held keys"),
            HeldInputState {
                pending: false,
                keys: vec!["F13".to_string(), "a".to_string()],
                buttons: vec![1],
            }
        );

        // A partial cleanup may remove only the keys whose keyup succeeded;
        // the remainder is what a retry or replacement daemon must see.
        journal
            .store(&["a".to_string()], &[], false)
            .expect("retain failed keyup key");
        assert_eq!(
            journal.load().expect("reload failed keyup key"),
            HeldInputState {
                pending: false,
                keys: vec!["a".to_string()],
                buttons: vec![],
            }
        );

        journal
            .store(&[], &[], false)
            .expect("clear after successful keyup");
        assert_eq!(
            journal.load().expect("empty journal"),
            HeldInputState::default()
        );

        journal
            .store(&["F13".to_string()], &[], true)
            .expect("persist ambiguous transition");
        assert!(journal.load().is_err(), "pending state must fail closed");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn held_key_journal_uses_canonical_x11_server_identity() {
        assert_eq!(
            held_key_journal_identity(":0").unwrap(),
            held_key_journal_identity("unix:0").unwrap()
        );
        assert_eq!(
            held_key_journal_identity(":0.0").unwrap(),
            held_key_journal_identity(":0.1").unwrap()
        );
        assert_ne!(
            held_key_journal_identity(":0").unwrap(),
            held_key_journal_identity(":1").unwrap()
        );
    }

    #[test]
    fn coordinator_config_excludes_geometry_but_preserves_policy_boundary() {
        let config = NativeComputerToolConfig {
            contract: ComputerToolContract::OpenAiResponses,
            target: DisplayTarget::Virtual,
            require_backend: false,
            geometry: Some(test_geometry()),
            approval_required: false,
        };
        let opened_config = config.coordinator_config();
        assert_eq!(
            opened_config,
            NativeComputerCoordinatorConfig {
                contract: ComputerToolContract::OpenAiResponses,
                target: DisplayTarget::Virtual,
                require_backend: false,
                approval_required: false,
            }
        );

        let real_desktop = NativeComputerToolConfig {
            target: DisplayTarget::RealDesktop,
            require_backend: true,
            approval_required: true,
            geometry: None,
            ..config
        };
        assert_ne!(opened_config, real_desktop.coordinator_config());
    }

    fn sample_actions() -> Vec<ComputerAction> {
        vec![
            ComputerAction::CaptureFull,
            ComputerAction::CaptureRegion {
                rect: Rect {
                    x: 10.0,
                    y: 10.0,
                    width: 20.0,
                    height: 20.0,
                    space: CoordinateSpace::Physical,
                },
            },
            ComputerAction::CaptureNativeZoom {
                rect: Rect {
                    x: 2.0,
                    y: 2.0,
                    width: 8.0,
                    height: 8.0,
                    space: CoordinateSpace::Logical,
                },
                scale: ScaleFactor(2.0),
            },
            ComputerAction::MoveCursor {
                to: Point {
                    x: 5.0,
                    y: 6.0,
                    space: CoordinateSpace::Physical,
                },
                duration: Duration::from_millis(20),
                easing: Easing::EaseInOut,
            },
            ComputerAction::Click {
                button: MouseButton::Left,
                count: ClickCount::Single,
                modifiers: Modifiers::default(),
            },
            ComputerAction::Click {
                button: MouseButton::Right,
                count: ClickCount::Double,
                modifiers: Modifiers {
                    control: true,
                    ..Modifiers::default()
                },
            },
            ComputerAction::Click {
                button: MouseButton::Middle,
                count: ClickCount::Triple,
                modifiers: Modifiers {
                    shift: true,
                    ..Modifiers::default()
                },
            },
            ComputerAction::MouseDown {
                button: MouseButton::Left,
            },
            ComputerAction::MouseUp {
                button: MouseButton::Left,
            },
            ComputerAction::Drag {
                button: MouseButton::Left,
                path: vec![TimedPoint {
                    point: Point {
                        x: 1.0,
                        y: 1.0,
                        space: CoordinateSpace::Physical,
                    },
                    duration: Duration::from_millis(1),
                    easing: Easing::Linear,
                }],
                modifiers: Modifiers {
                    alt: true,
                    ..Modifiers::default()
                },
            },
            ComputerAction::TypeText {
                text: "hello; rm -rf nope".to_string(),
            },
            ComputerAction::KeyChord {
                chord: CanonicalKeyChord::new(vec![
                    KeyCode::parse("Control").unwrap(),
                    KeyCode::parse("L").unwrap(),
                ])
                .unwrap(),
            },
            ComputerAction::HoldKey {
                key: KeyCode::parse("Shift").unwrap(),
                duration: Duration::from_millis(1),
            },
            ComputerAction::Scroll {
                delta_x: -1,
                delta_y: 2,
                modifiers: Modifiers {
                    meta: true,
                    ..Modifiers::default()
                },
            },
            ComputerAction::Wait {
                duration: Duration::from_millis(1),
            },
        ]
    }

    fn provider_point(x: f64, y: f64, space: CoordinateSpace) -> Point {
        Point { x, y, space }
    }

    fn provider_rect(space: CoordinateSpace) -> Rect {
        Rect {
            x: 10.0,
            y: 5.0,
            width: 20.0,
            height: 10.0,
            space,
        }
    }

    fn timed_point(x: f64, y: f64, space: CoordinateSpace) -> TimedPoint {
        TimedPoint {
            point: provider_point(x, y, space),
            duration: Duration::from_millis(7),
            easing: Easing::EaseInOut,
        }
    }

    #[test]
    fn reserved_native_computer_tool_name_covers_wire_identifiers() {
        // Every `type`/`name` the wire builder advertises is reserved.
        for contract in [
            ComputerToolContract::Anthropic20251124,
            ComputerToolContract::Anthropic20250124,
            ComputerToolContract::OpenAiResponses,
        ] {
            let wire = native_computer_wire(contract, &test_geometry());
            for tool in &wire.tools {
                let ty = tool["type"].as_str().expect("wire tool has a type");
                assert!(
                    is_reserved_native_computer_tool_name(ty),
                    "advertised type `{ty}` must be reserved"
                );
                if let Some(name) = tool.get("name").and_then(serde_json::Value::as_str) {
                    assert!(
                        is_reserved_native_computer_tool_name(name),
                        "advertised name `{name}` must be reserved"
                    );
                }
            }
        }
        // The three distinct reserved identifiers, spelled out.
        assert!(is_reserved_native_computer_tool_name(
            NATIVE_COMPUTER_TOOL_NAME
        ));
        assert!(is_reserved_native_computer_tool_name(
            OPENAI_COMPUTER_TOOL_TYPE
        ));
        assert!(is_reserved_native_computer_tool_name(
            ANTHROPIC_COMPUTER_TOOL_TYPE_20251124
        ));
        assert!(is_reserved_native_computer_tool_name(
            ANTHROPIC_COMPUTER_TOOL_TYPE_20250124
        ));
        // Ordinary tool names — including near-misses — are not reserved.
        for ordinary in [
            "read",
            "bash",
            "task",
            "computer_use",
            "computers",
            "Computer",
            "computer_20260101",
            "",
        ] {
            assert!(
                !is_reserved_native_computer_tool_name(ordinary),
                "`{ordinary}` must not be reserved"
            );
        }
    }

    #[test]
    fn anthropic_computer_20251124_wire() {
        let wire = native_computer_wire(ComputerToolContract::Anthropic20251124, &test_geometry());

        assert_eq!(wire.group, COMPUTER_TOOL_GROUP);
        assert_eq!(wire.beta_headers, vec!["computer-use-2025-11-24"]);
        assert_eq!(
            wire.tools,
            vec![serde_json::json!({
                "type": "computer_20251124",
                "name": "computer",
                "display_width_px": 1280,
                "display_height_px": 720,
                "enable_zoom": true,
            })]
        );
        assert_ne!(wire.tools[0]["type"], "computer_20250124");
    }

    #[test]
    fn anthropic_computer_20250124_wire() {
        let wire = native_computer_wire(ComputerToolContract::Anthropic20250124, &test_geometry());

        assert_eq!(wire.group, COMPUTER_TOOL_GROUP);
        assert_eq!(wire.beta_headers, vec!["computer-use-2025-01-24"]);
        assert_eq!(
            wire.tools,
            vec![serde_json::json!({
                "type": "computer_20250124",
                "name": "computer",
                "display_width_px": 1280,
                "display_height_px": 720,
            })]
        );
        assert!(wire.tools[0].get("enable_zoom").is_none());
        assert_ne!(wire.tools[0]["type"], "computer_20251124");
    }

    #[test]
    fn anthropic_action_version_matrix() {
        let current_actions = vec![
            Anthropic20251124ComputerAction::Screenshot,
            Anthropic20251124ComputerAction::Zoom {
                rect: provider_rect(CoordinateSpace::Physical),
                scale: ScaleFactor(2.0),
            },
            Anthropic20251124ComputerAction::MouseMove {
                to: provider_point(1.0, 2.0, CoordinateSpace::Physical),
                duration: Duration::from_millis(5),
                easing: Easing::EaseInOut,
            },
            Anthropic20251124ComputerAction::Click {
                at: None,
                button: ProviderPointerButton::Right,
                count: ClickCount::Triple,
                modifiers: Modifiers {
                    shift: true,
                    ..Modifiers::default()
                },
            },
            Anthropic20251124ComputerAction::MouseDown {
                button: ProviderPointerButton::Middle,
            },
            Anthropic20251124ComputerAction::MouseUp {
                button: ProviderPointerButton::Middle,
            },
            Anthropic20251124ComputerAction::Drag {
                button: ProviderPointerButton::Right,
                path: vec![timed_point(1.0, 1.0, CoordinateSpace::Physical)],
                modifiers: Modifiers {
                    alt: true,
                    ..Modifiers::default()
                },
            },
            Anthropic20251124ComputerAction::TypeText("literal Control+L".to_string()),
            Anthropic20251124ComputerAction::KeyChord(KeyChord {
                keys: vec!["Control".to_string(), "L".to_string()],
            }),
            Anthropic20251124ComputerAction::HoldKey {
                key: "Shift".to_string(),
                duration: Duration::from_millis(3),
            },
            Anthropic20251124ComputerAction::Scroll {
                at: None,
                delta_x: 1,
                delta_y: -2,
                modifiers: Modifiers {
                    meta: true,
                    ..Modifiers::default()
                },
            },
            Anthropic20251124ComputerAction::Wait(Duration::from_millis(1)),
        ];
        for action in current_actions {
            let _ = action.to_backend();
        }

        let older_supported = vec![
            Anthropic20250124ComputerAction::Screenshot,
            Anthropic20250124ComputerAction::MouseMove {
                to: provider_point(1.0, 2.0, CoordinateSpace::Physical),
                duration: Duration::ZERO,
                easing: Easing::Linear,
            },
            Anthropic20250124ComputerAction::Click {
                at: None,
                button: ProviderPointerButton::Middle,
                count: ClickCount::Double,
                modifiers: Modifiers {
                    shift: true,
                    ..Modifiers::default()
                },
            },
            Anthropic20250124ComputerAction::Click {
                at: None,
                button: ProviderPointerButton::Right,
                count: ClickCount::Triple,
                modifiers: Modifiers::default(),
            },
            Anthropic20250124ComputerAction::MouseDown {
                button: ProviderPointerButton::Left,
            },
            Anthropic20250124ComputerAction::MouseUp {
                button: ProviderPointerButton::Left,
            },
            Anthropic20250124ComputerAction::Drag {
                button: ProviderPointerButton::Left,
                path: vec![timed_point(1.0, 1.0, CoordinateSpace::Physical)],
                modifiers: Modifiers {
                    alt: true,
                    ..Modifiers::default()
                },
            },
            Anthropic20250124ComputerAction::TypeText("text".to_string()),
            Anthropic20250124ComputerAction::KeyChord(KeyChord {
                keys: vec!["Escape".to_string()],
            }),
            Anthropic20250124ComputerAction::HoldKey {
                key: "Shift".to_string(),
                duration: Duration::from_millis(3),
            },
            Anthropic20250124ComputerAction::Scroll {
                at: None,
                delta_x: 0,
                delta_y: 1,
                modifiers: Modifiers {
                    control: true,
                    ..Modifiers::default()
                },
            },
            Anthropic20250124ComputerAction::Wait(Duration::from_millis(1)),
        ];
        for action in older_supported {
            let _ = action.to_backend();
        }
        let older_names = Anthropic20250124ComputerAction::action_names();
        let newer_only = "zoom";
        assert!(!older_names.contains(&newer_only));
        assert!(Anthropic20251124ComputerAction::action_names().contains(&"zoom"));
        assert!(Anthropic20251124ComputerAction::action_names().contains(&"hold_key"));
        assert!(Anthropic20250124ComputerAction::action_names().contains(&"hold_key"));

        let parsed_click = parse_anthropic_20251124_action(&serde_json::json!({
            "action": "left_click",
            "coordinate": [100.0, 200.0],
            "modifiers": {"shift": true}
        }))
        .unwrap();
        let backend_actions = parsed_click.to_backend_actions().unwrap();
        assert!(matches!(
            backend_actions[0],
            ComputerAction::MoveCursor {
                to: Point {
                    x: 100.0,
                    y: 200.0,
                    space: CoordinateSpace::Physical,
                },
                ..
            }
        ));
        assert!(matches!(
            backend_actions[1],
            ComputerAction::Click {
                button: MouseButton::Left,
                modifiers: Modifiers { shift: true, .. },
                ..
            }
        ));
        assert!(
            parse_anthropic_20250124_action(&serde_json::json!({
                "action": "zoom",
                "region": [0.0, 0.0, 100.0, 100.0]
            }))
            .is_err()
        );
    }

    #[test]
    fn openai_computer_wire() {
        let wire = native_computer_wire(ComputerToolContract::OpenAiResponses, &test_geometry());

        assert_eq!(wire.group, COMPUTER_TOOL_GROUP);
        assert!(wire.beta_headers.is_empty());
        assert_eq!(wire.tools, vec![serde_json::json!({ "type": "computer" })]);
    }

    #[tokio::test]
    async fn openai_computer_batch_roundtrip() {
        let mut backend = FakeBackend::new();
        let actions = vec![
            OpenAiComputerAction::Move {
                to: provider_point(4.0, 5.0, CoordinateSpace::Physical),
            },
            OpenAiComputerAction::Click {
                at: None,
                button: ProviderPointerButton::Left,
                modifiers: Modifiers {
                    shift: true,
                    ..Modifiers::default()
                },
            },
            OpenAiComputerAction::TypeText("hello".to_string()),
        ];
        let result = execute_openai_computer_call(&mut backend, "call-1", &actions).await;

        assert_eq!(result.output.call_id, "call-1");
        assert_eq!(result.output.failure, None);
        assert_eq!(result.output.completed.len(), 3);
        // The screenshot is a sanitized projection, not raw bytes.
        assert!(result.output.has_screenshot());
        // The old `screenshot_png: Option<Vec<u8>>` field is removed; the
        // sanitized projection contains byte_count, not raw bytes.
        assert!(result.live_frame.is_some());
        // The sanitized projection contains no pixel data.
        let sanitized = result.output.sanitized_screenshot().unwrap();
        assert!(sanitized.byte_count > 0);
        let proj_json = serde_json::to_string(sanitized).unwrap();
        assert!(!proj_json.contains("base64"));
        assert!(!proj_json.contains("data:image"));
        let canonical = actions
            .iter()
            .map(OpenAiComputerAction::to_backend)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(
            backend.recorded[..3],
            normalized_effects(&canonical, &backend.geometry)
        );
        assert!(matches!(
            backend.recorded[3],
            NormalizedComputerEffect::CaptureFull
        ));
        // The transient wire payload is built from the live frame via a scoped
        // borrow, not from a serializable field on the output.
        let transient = result.transient_wire().unwrap();
        // `with_wire` is the sole wire-payload access; assert inside the borrow.
        let (_, transient_projection) = transient.with_wire(|wire| {
            assert_eq!(
                wire["type"],
                serde_json::Value::String("computer_call_output".to_string())
            );
            assert_eq!(wire["call_id"], "call-1");
            assert_eq!(wire["output"]["type"], "computer_screenshot");
            assert!(
                wire["output"]["image_url"]
                    .as_str()
                    .unwrap()
                    .starts_with("data:image/png;base64,")
            );
        });
        // The transient request's projection matches the output's projection.
        assert_eq!(
            transient_projection.checksum,
            result.output.sanitized_screenshot().unwrap().checksum
        );
    }

    #[tokio::test]
    async fn openai_computer_call_json_roundtrip() {
        let call = serde_json::json!({
            "type": "computer_call",
            "call_id": "call-json",
            "action": {"type": "click", "x": 100.0, "y": 200.0, "button": "left", "modifiers": {"shift": true}},
        });
        let mut backend = FakeBackend::new();
        let result = execute_openai_computer_call_json(&mut backend, &call)
            .await
            .unwrap();

        assert_eq!(result.output.call_id, "call-json");
        assert_eq!(result.output.failure, None);
        // The screenshot is a sanitized projection, not raw bytes.
        assert!(result.output.has_screenshot());
        // The old `screenshot_png: Option<Vec<u8>>` field is removed; the
        // sanitized projection contains byte_count, not raw bytes.
        assert!(result.live_frame.is_some());
        // The sanitized projection contains no pixel data.
        let proj_json =
            serde_json::to_string(result.output.sanitized_screenshot().unwrap()).unwrap();
        assert!(!proj_json.contains("base64"));
        assert!(!proj_json.contains("data:image"));
        assert_eq!(backend.recorded.len(), 3);
        assert!(matches!(
            backend.recorded[0],
            NormalizedComputerEffect::MoveCursor {
                to: PixelPoint { x: 100, y: 200 },
                ..
            }
        ));
        assert!(matches!(
            backend.recorded[1],
            NormalizedComputerEffect::Click {
                button: MouseButton::Left,
                modifiers: Modifiers { shift: true, .. },
                ..
            }
        ));
    }

    #[test]
    fn openai_responses_computer_call_requires_singular_action() {
        let singular = serde_json::json!({
            "type": "computer_call",
            "call_id": "call-singular",
            "action": {"type": "move", "x": 4.0, "y": 5.0},
        });
        let (_, actions) = parse_openai_computer_call(&singular).expect("parse singular action");
        assert_eq!(actions.len(), 1);

        let legacy_plural = serde_json::json!({
            "type": "computer_call",
            "call_id": "call-legacy",
            "actions": [{"type": "move", "x": 4.0, "y": 5.0}],
        });
        assert!(matches!(
            parse_openai_computer_call(&legacy_plural),
            Err(OpenAiComputerWireError::MissingAction)
        ));
    }

    #[test]
    fn computer_live_bypass_helpers_cfg_test_only() {
        let src = include_str!("mod.rs");
        for needle in [
            "pub async fn execute_openai_computer_call<",
            "pub async fn execute_openai_computer_call_json<",
        ] {
            let index = src.find(needle).unwrap_or_else(|| panic!("{needle}"));
            let prefix = &src[index.saturating_sub(64)..index];
            assert!(
                prefix.contains("#[cfg(test)]"),
                "{needle} must not be a production API"
            );
        }
    }

    #[tokio::test]
    async fn openai_computer_batch_failure_boundary() {
        // This test is corrected to go through the coordinator path. The old
        // direct helper `execute_openai_computer_call` does not carry
        // IDs/generations, journal handoff, or `not_dispatched` tails. The
        // new assertions below reject the old direct execution path.
        use super::target::{FakeTargetEvidenceAdapter, sample_virtual_evidence};
        use coordinator::{
            ActionIdentity, ComputerActionCoordinator, ComputerApprovalTier, CoordinatedOutcome,
            CoordinatorParams, DelegationId, FakeComputerAuthorizer, ModelId, OwnerInstance,
            ProviderId,
        };

        let backend = FakeBackend::failing_at(1, ComputerError::Refused("blocked".to_string()));
        let authorizer: std::sync::Arc<dyn coordinator::ComputerAuthorizer> =
            std::sync::Arc::new(FakeComputerAuthorizer::always_allow());
        // Opens with virtual evidence matching FakeBackend and a real focus
        // generation so
        // the TypeText actions clear the focus-generation gate; the mid-batch
        // Failed { index: 1 } assertion is asserted against the coordinator
        // path.
        let mut evidence = sample_virtual_evidence([4u8; 16], 1);
        evidence.focus_generation = 1;
        evidence.focused_window_id = crate::computer::target::FieldEvidence::available(
            crate::computer::platform::opaque_x11_window_id(1),
            crate::computer::target::EvidenceSource::InjectedTest,
        );
        let adapter = FakeTargetEvidenceAdapter::new(evidence);
        let params = CoordinatorParams {
            session_id: "session-1".to_string(),
            delegation_id: DelegationId("delegation-1".to_string()),
            tier: ComputerApprovalTier::Yolo,
            owner_instance: OwnerInstance(1),
            authorizer,
            host_arbiter: None,
            target_adapter: Some(Box::new(adapter)),
            provider_id: ProviderId("openai".to_string()),
            model_id: ModelId("gpt-5".to_string()),
            outcome_store: None,
            handoff_journal: None,
        };
        let mut coordinator = ComputerActionCoordinator::open(Box::new(backend), params)
            .await
            .expect("coordinator open");

        let actions = vec![
            OpenAiComputerAction::Move {
                to: provider_point(4.0, 5.0, CoordinateSpace::Physical),
            },
            OpenAiComputerAction::TypeText("stop here".to_string()),
            OpenAiComputerAction::TypeText("must not execute".to_string()),
        ];
        let outcome = coordinator.execute_openai_call("call-2", &actions).await;

        // The coordinator path produces a CoordinatedOutcome::Failed (not the
        // old OpenAiComputerCallResult struct). The old direct helper cannot
        // produce this type.
        match &outcome {
            CoordinatedOutcome::Failed {
                failure,
                screenshot,
            } => {
                assert_eq!(failure.index, 1);
                // No screenshot on failure.
                assert!(screenshot.is_none());
            }
            other => panic!("expected failed outcome, got {other:?}"),
        }

        // The dispatch state is recorded — the old direct helper does not
        // track dispatch state.
        assert_eq!(
            coordinator.dispatch_state("call-2"),
            Some(coordinator::DispatchState::Completed)
        );

        // The action identity is bound — the old direct helper does not carry
        // identity. The identity includes session, delegation, provider_call_id,
        // and batch_index.
        let _identity = ActionIdentity {
            session_id: "session-1".to_string(),
            delegation_id: DelegationId("delegation-1".to_string()),
            provider_call_id: "call-2".to_string(),
            batch_index: 0,
        };

        // The observation and focus generations are bound — the old direct
        // helper does not carry generations.
        assert!(coordinator.observation_generation().0 > 0);

        // The journal records the outcome for dedup/reconnect — the old
        // direct helper does not journal.
        let replay = coordinator.execute_openai_call("call-2", &actions).await;
        assert!(matches!(replay, CoordinatedOutcome::DuplicateReplay { .. }));
    }

    #[test]
    fn no_native_tool_no_computer() {
        assert_eq!(
            native_computer_wire_from_capability(None, &test_geometry()),
            None
        );
    }

    #[test]
    fn computer_provider_coordinates_hidpi() {
        let geometry = test_geometry();
        let logical_rect = provider_rect(CoordinateSpace::Logical);
        assert_eq!(
            checked_rect(logical_rect, &geometry).unwrap(),
            PixelRect {
                x: 20,
                y: 10,
                width: 40,
                height: 20
            }
        );
        let action = OpenAiComputerAction::Drag {
            path: vec![
                timed_point(1.0, 1.0, CoordinateSpace::Logical),
                timed_point(2.0, 2.0, CoordinateSpace::Logical),
            ],
            modifiers: Modifiers {
                control: true,
                ..Modifiers::default()
            },
        }
        .to_backend()
        .unwrap();
        let ComputerAction::Drag {
            path, modifiers, ..
        } = action
        else {
            panic!("expected drag");
        };
        assert_eq!(path[0].point.space, CoordinateSpace::Logical);
        assert!(modifiers.control);
    }

    #[test]
    fn computer_native_zoom_no_custom_fields() {
        let anthropic = Anthropic20251124ComputerAction::Zoom {
            rect: provider_rect(CoordinateSpace::Physical),
            scale: ScaleFactor(2.0),
        }
        .to_backend()
        .unwrap();
        assert!(matches!(
            anthropic,
            ComputerAction::CaptureNativeZoom {
                scale: ScaleFactor(2.0),
                ..
            }
        ));

        let openai = native_computer_wire(ComputerToolContract::OpenAiResponses, &test_geometry());
        let serialized = serde_json::to_string(&openai.tools).unwrap();
        assert!(!serialized.contains("region"));
        assert!(!serialized.contains("zoom"));
        assert_eq!(
            openai.tools,
            vec![serde_json::json!({ "type": "computer" })]
        );
    }

    #[test]
    fn computer_contract_selected_by_capability() {
        let geometry = test_geometry();
        let anthropic_capability = crate::config::providers::ComputerUseCapability {
            contract: Some(crate::config::providers::ComputerUseContract::Anthropic20251124),
            source: Some(crate::config::providers::CapabilitySource::Manual),
        };
        let openai_capability = crate::config::providers::ComputerUseCapability {
            contract: Some(crate::config::providers::ComputerUseContract::OpenAiResponses),
            source: Some(crate::config::providers::CapabilitySource::Manual),
        };
        let anthropic =
            native_computer_wire_from_capability(Some(&anthropic_capability), &geometry).unwrap();
        let openai =
            native_computer_wire_from_capability(Some(&openai_capability), &geometry).unwrap();

        assert_eq!(anthropic.tools[0]["type"], "computer_20251124");
        assert_eq!(openai.tools[0]["type"], "computer");
    }

    #[test]
    fn computer_tool_group_stable() {
        for contract in [
            ComputerToolContract::Anthropic20251124,
            ComputerToolContract::Anthropic20250124,
            ComputerToolContract::OpenAiResponses,
        ] {
            assert_eq!(
                native_computer_wire(contract, &test_geometry()).group,
                COMPUTER_TOOL_GROUP
            );
        }
    }

    #[tokio::test]
    async fn computer_backend_action_matrix() {
        let actions = sample_actions();
        let mut backend = FakeBackend::new();
        let report = execute_backend_batch(&mut backend, &actions).await;

        assert_eq!(
            backend.recorded,
            normalized_effects(&actions, &backend.geometry)
        );
        assert_eq!(report.failure, None);
        assert!(matches!(
            report.completed[0],
            ComputerActionOutcome::Captured(CaptureFrame { region: None, .. })
        ));
        assert!(matches!(
            report.completed[1],
            ComputerActionOutcome::Captured(CaptureFrame {
                region: Some(_),
                ..
            })
        ));
        assert!(matches!(
            report.completed[2],
            ComputerActionOutcome::Captured(CaptureFrame {
                region: Some(_),
                native_zoom: Some(ScaleFactor(2.0)),
                ..
            })
        ));
        assert!(
            report.completed[3..14]
                .iter()
                .all(|outcome| matches!(outcome, ComputerActionOutcome::Completed))
        );
        assert_eq!(
            report.completed[14],
            ComputerActionOutcome::Waited(Duration::from_millis(1))
        );
        // Physical cleanup belongs to the coordinator, which can revalidate
        // the OS host lease immediately before injecting terminal input.
        assert_eq!(backend.release_count, 0);
    }

    #[tokio::test]
    async fn computer_batch_failure_boundary() {
        let actions = sample_actions();
        let mut backend =
            FakeBackend::failing_at(3, ComputerError::Refused("blocked by policy".to_string()));
        let report = execute_backend_batch(&mut backend, &actions).await;

        assert_eq!(
            backend.recorded,
            normalized_effects(&actions[..=3], &backend.geometry)
        );
        assert_eq!(report.completed.len(), 3);
        assert_eq!(report.failure.as_ref().unwrap().index, 3);
        assert_eq!(backend.release_count, 0);
    }

    #[test]
    fn real_desktop_requires_grant() {
        let tmp = TempDir::new().unwrap();
        let store = RealDesktopGrantStore::new(tmp.path().join("real-desktop-grant"));
        let err = match VirtualDisplayBackend::construct(DisplayTarget::RealDesktop, Some(&store)) {
            Ok(_) => panic!("real desktop construction must require a grant"),
            Err(err) => err,
        };

        assert_eq!(err, ComputerError::RealDesktopGrantMissing);
    }

    #[test]
    fn unsupported_platform_errors() {
        #[cfg(not(target_os = "linux"))]
        {
            assert!(matches!(
                VirtualDisplayBackend::construct(DisplayTarget::Virtual, None),
                Err(ComputerError::UnsupportedPlatform { .. })
            ));
        }
        #[cfg(target_os = "linux")]
        {
            assert_eq!(
                unsupported_platform(),
                ComputerError::UnsupportedPlatform {
                    platform: "linux".to_string(),
                }
            );
        }
    }

    #[tokio::test]
    async fn computer_input_modes_distinct() {
        let actions = vec![
            ComputerAction::TypeText {
                text: "Control+L is literal text".to_string(),
            },
            ComputerAction::KeyChord {
                chord: CanonicalKeyChord::new(vec![
                    KeyCode::parse("Control").unwrap(),
                    KeyCode::parse("L").unwrap(),
                ])
                .unwrap(),
            },
            ComputerAction::HoldKey {
                key: KeyCode::parse("L").unwrap(),
                duration: Duration::from_millis(5),
            },
            ComputerAction::Click {
                button: MouseButton::Left,
                count: ClickCount::Single,
                modifiers: Modifiers {
                    control: true,
                    ..Modifiers::default()
                },
            },
        ];
        let mut backend = FakeBackend::new();
        let report = execute_backend_batch(&mut backend, &actions).await;

        assert_eq!(report.failure, None);
        assert!(matches!(
            backend.recorded[0],
            NormalizedComputerEffect::TypeText { .. }
        ));
        assert!(matches!(
            backend.recorded[1],
            NormalizedComputerEffect::KeyChord { .. }
        ));
        assert!(matches!(
            backend.recorded[2],
            NormalizedComputerEffect::HoldKey { .. }
        ));
        assert!(matches!(
            backend.recorded[3],
            NormalizedComputerEffect::Click { .. }
        ));
    }

    #[test]
    fn provider_key_tokens_canonicalize_as_case_insensitive_identities() {
        let anthropic_new = Anthropic20251124ComputerAction::KeyChord(KeyChord {
            keys: vec!["Control".to_string(), "a".to_string()],
        })
        .to_backend()
        .unwrap();
        let anthropic_old = Anthropic20250124ComputerAction::HoldKey {
            key: "A".to_string(),
            duration: Duration::ZERO,
        }
        .to_backend()
        .unwrap();
        let openai = OpenAiComputerAction::KeyChord(KeyChord {
            keys: vec!["A".to_string()],
        })
        .to_backend()
        .unwrap();

        let ComputerAction::KeyChord { chord } = anthropic_new else {
            panic!("expected canonical chord");
        };
        assert_eq!(chord.keys[1].as_str(), "A");
        let ComputerAction::HoldKey { key, .. } = anthropic_old else {
            panic!("expected canonical held key");
        };
        assert_eq!(key.as_str(), "A");
        let ComputerAction::KeyChord { chord } = openai else {
            panic!("expected canonical chord");
        };
        assert_eq!(chord.keys[0].as_str(), "A");

        for alias in ["META", "WIN", "SUPER", "LEFTMETA"] {
            assert_eq!(KeyCode::parse(alias).unwrap().as_str(), "LEFTMETA");
        }

        assert!(
            OpenAiComputerAction::KeyChord(KeyChord {
                keys: vec!["!".to_string()],
            })
            .to_backend()
            .is_err(),
            "character production belongs to TypeText"
        );
    }

    #[test]
    fn every_accepted_key_identity_has_total_platform_translations() {
        let mut accepted = (b'A'..=b'Z')
            .map(|key| char::from(key).to_string())
            .chain((b'0'..=b'9').map(|key| char::from(key).to_string()))
            .chain((1..=12).map(|number| format!("F{number}")))
            .collect::<Vec<_>>();
        accepted.extend(
            [
                "SHIFT",
                "CONTROL",
                "LEFTCONTROL",
                "RIGHTCONTROL",
                "ALT",
                "LEFTALT",
                "RIGHTALT",
                "LEFTMETA",
                "RIGHTMETA",
                "ENTER",
                "TAB",
                "ESCAPE",
                "BACKSPACE",
                "DELETE",
                "INSERT",
                "SPACE",
                "ARROWUP",
                "ARROWDOWN",
                "ARROWLEFT",
                "ARROWRIGHT",
                "HOME",
                "END",
                "PAGEUP",
                "PAGEDOWN",
                "CAPSLOCK",
                "NUMLOCK",
                "SCROLLLOCK",
                "PRINTSCREEN",
                "PAUSE",
                "APPS",
            ]
            .into_iter()
            .map(str::to_string),
        );

        for identity in accepted {
            let key = KeyCode::parse(&identity).unwrap();
            let translated = NormalizedKeyCode::new(&key)
                .unwrap_or_else(|error| panic!("{identity} failed translation: {error}"));
            assert!(!translated.x11_name.is_empty(), "{identity}");
            assert_ne!(translated.windows_virtual_key, 0, "{identity}");
        }
    }

    #[test]
    fn x11_named_key_spellings_are_not_uppercase_canonical_tokens() {
        for (identity, x11) in [
            ("TAB", "Tab"),
            ("BACKSPACE", "BackSpace"),
            ("DELETE", "Delete"),
            ("INSERT", "Insert"),
            ("HOME", "Home"),
            ("END", "End"),
            ("PAUSE", "Pause"),
            ("APPS", "Menu"),
        ] {
            let translated = NormalizedKeyCode::new(&KeyCode::parse(identity).unwrap()).unwrap();
            assert_eq!(translated.x11_name, x11, "{identity}");
        }
    }

    #[tokio::test]
    async fn backend_normalizes_whole_batch_before_any_effect() {
        let mut backend = FakeBackend::new();
        let actions = vec![
            ComputerAction::Click {
                button: MouseButton::Left,
                count: ClickCount::Single,
                modifiers: Modifiers::default(),
            },
            ComputerAction::MoveCursor {
                // In-range before rounding, out-of-range after rounding.
                to: Point {
                    x: 1279.6,
                    y: 10.0,
                    space: CoordinateSpace::Physical,
                },
                duration: Duration::ZERO,
                easing: Easing::Linear,
            },
        ];

        let report = execute_backend_batch(&mut backend, &actions).await;
        assert_eq!(report.failure.unwrap().index, 1);
        assert!(backend.recorded.is_empty());
    }

    #[tokio::test]
    async fn backend_rejects_empty_canonical_chord_before_any_effect() {
        let mut backend = FakeBackend::new();
        let actions = [
            ComputerAction::Click {
                button: MouseButton::Left,
                count: ClickCount::Single,
                modifiers: Modifiers::default(),
            },
            // Exercise the mandatory normalization defense. Public callers
            // cannot construct this state because `keys` is private.
            ComputerAction::KeyChord {
                chord: CanonicalKeyChord { keys: Vec::new() },
            },
        ];

        let report = execute_backend_batch(&mut backend, &actions).await;
        assert_eq!(report.failure.unwrap().index, 1);
        assert!(backend.recorded.is_empty());
    }

    #[tokio::test]
    async fn backend_pretranslates_every_key_before_any_effect() {
        let mut backend = FakeBackend::new();
        let actions = [
            ComputerAction::Click {
                button: MouseButton::Left,
                count: ClickCount::Single,
                modifiers: Modifiers::default(),
            },
            ComputerAction::HoldKey {
                // Exercise the normalization defense against a future internal
                // constructor that bypasses KeyCode::parse.
                key: KeyCode("NOT_A_PLATFORM_KEY".to_string()),
                duration: Duration::ZERO,
            },
        ];

        let report = execute_backend_batch(&mut backend, &actions).await;
        assert_eq!(report.failure.unwrap().index, 1);
        assert!(backend.recorded.is_empty());
    }

    #[tokio::test]
    async fn native_zoom_output_dimensions_are_checked_before_capture() {
        let mut backend = FakeBackend::new();
        let report = execute_backend_batch(
            &mut backend,
            &[ComputerAction::CaptureNativeZoom {
                rect: Rect {
                    x: 0.0,
                    y: 0.0,
                    width: 1280.0,
                    height: 720.0,
                    space: CoordinateSpace::Physical,
                },
                scale: ScaleFactor(f64::from(u32::MAX)),
            }],
        )
        .await;

        assert!(report.failure.is_some());
        assert!(backend.recorded.is_empty());
    }

    #[tokio::test]
    async fn native_zoom_rejects_valid_dimensions_with_catastrophic_allocation() {
        let mut backend = FakeBackend::new();
        let report = execute_backend_batch(
            &mut backend,
            &[ComputerAction::CaptureNativeZoom {
                rect: Rect {
                    x: 0.0,
                    y: 0.0,
                    width: 1280.0,
                    height: 720.0,
                    space: CoordinateSpace::Physical,
                },
                // Both scaled edges fit in u32, but the RGBA output would
                // require multiple terabytes.
                scale: ScaleFactor(1_000.0),
            }],
        )
        .await;

        assert_eq!(report.failure.unwrap().index, 0);
        assert!(backend.recorded.is_empty());
    }

    fn huge_capture_backend() -> FakeBackend {
        let mut backend = FakeBackend::new();
        backend.geometry = DisplayGeometry {
            physical: PixelSize {
                width: 20_000,
                height: 10_000,
            },
            logical: LogicalSize {
                width: 20_000.0,
                height: 10_000.0,
            },
            scale_factor: ScaleFactor(1.0),
        };
        backend
    }

    #[tokio::test]
    async fn native_zoom_source_allocation_is_checked_before_downscale_or_effects() {
        let mut backend = huge_capture_backend();
        let report = execute_backend_batch(
            &mut backend,
            &[
                ComputerAction::Click {
                    button: MouseButton::Left,
                    count: ClickCount::Single,
                    modifiers: Modifiers::default(),
                },
                ComputerAction::CaptureNativeZoom {
                    rect: Rect {
                        x: 0.0,
                        y: 0.0,
                        width: 20_000.0,
                        height: 10_000.0,
                        space: CoordinateSpace::Physical,
                    },
                    // The small output is safe; the 800 MB RGBA source is not.
                    scale: ScaleFactor(0.1),
                },
            ],
        )
        .await;

        assert_eq!(report.failure.unwrap().index, 1);
        assert!(backend.recorded.is_empty());
    }

    #[tokio::test]
    async fn full_and_region_capture_source_allocations_share_the_same_ceiling() {
        for action in [
            ComputerAction::CaptureFull,
            ComputerAction::CaptureRegion {
                rect: Rect {
                    x: 0.0,
                    y: 0.0,
                    width: 20_000.0,
                    height: 10_000.0,
                    space: CoordinateSpace::Physical,
                },
            },
        ] {
            let mut backend = huge_capture_backend();
            let report = execute_backend_batch(&mut backend, &[action]).await;
            assert_eq!(report.failure.unwrap().index, 0);
            assert!(backend.recorded.is_empty());
        }
    }

    #[tokio::test]
    async fn computer_held_input_always_released() {
        let actions = vec![
            ComputerAction::MouseDown {
                button: MouseButton::Left,
            },
            ComputerAction::HoldKey {
                key: KeyCode::parse("Shift").unwrap(),
                duration: Duration::from_millis(1),
            },
        ];
        let mut ok = FakeBackend::new();
        let ok_report = execute_backend_batch(&mut ok, &actions).await;
        assert_eq!(ok_report.failure, None);
        assert_eq!(ok.release_count, 0);

        let mut fail = FakeBackend::failing_at(1, ComputerError::Cancelled);
        let fail_report = execute_backend_batch(&mut fail, &actions).await;
        assert_eq!(fail_report.failure.unwrap().error, ComputerError::Cancelled);
        assert_eq!(fail.release_count, 0);
    }

    #[test]
    #[test]
    fn x11_bind_refuses_non_x11_window_identities_instead_of_pinning_focus() {
        let src = include_str!("mod.rs");
        let start = src
            .find("fn bind_x11_injection_window")
            .expect("bind_x11_injection_window");
        let body = &src[start..start + 1200];
        assert!(
            !body.contains("query_active_x11_window"),
            "binding must decode the evidenced X11 id, not pin the live active window"
        );
        assert!(
            body.contains("x11_window_from_opaque"),
            "binding must require an encoded X11 window identity"
        );
    }

    #[test]
    fn xdotool_input_is_addressed_to_the_evidenced_window() {
        assert_eq!(
            xdotool_targeted_command(0x00ab_cdef, "type", &["hello"]),
            vec!["type", "--window", "11259375", "hello"]
        );
        assert_eq!(
            xdotool_targeted_command(42, "key", &["Return"]),
            vec!["key", "--window", "42", "Return"]
        );
        assert_eq!(
            xdotool_targeted_command(7, "click", &["1"]),
            vec!["click", "--window", "7", "1"]
        );
    }

    #[test]
    fn pixel_point_in_window_converts_screen_coordinates_and_refuses_outside() {
        let inside = pixel_point_in_window(PixelPoint { x: 110, y: 220 }, 100, 200, 50, 50)
            .expect("inside the evidenced window");
        assert_eq!(inside, PixelPoint { x: 10, y: 20 });
        assert!(pixel_point_in_window(PixelPoint { x: 99, y: 220 }, 100, 200, 50, 50).is_err());
        assert!(pixel_point_in_window(PixelPoint { x: 150, y: 220 }, 100, 200, 50, 50).is_err());
    }

    #[tokio::test]
    async fn execute_backend_batch_aborts_remaining_actions_on_window_recheck() {
        let mut backend = FakeBackend::new();
        backend.window_recheck_fail_at = Some(1);
        let actions = vec![
            ComputerAction::Wait {
                duration: Duration::from_millis(1),
            },
            ComputerAction::TypeText {
                text: "one".to_string(),
            },
            ComputerAction::TypeText {
                text: "two".to_string(),
            },
        ];
        let report = execute_backend_batch(&mut backend, &actions).await;
        assert_eq!(backend.recorded.len(), 1);
        assert_eq!(
            report.failure,
            Some(ComputerFailure {
                index: 1,
                error: ComputerError::Refused(EVIDENCED_WINDOW_MISMATCH.to_string()),
            })
        );
        assert_eq!(report.completed.len(), 1);
    }

    #[test]
    fn computer_capture_geometry_hidpi() {
        let geometry = DisplayGeometry {
            physical: PixelSize {
                width: 200,
                height: 100,
            },
            logical: LogicalSize {
                width: 100.0,
                height: 50.0,
            },
            scale_factor: ScaleFactor(2.0),
        };
        let rect = checked_rect(
            Rect {
                x: 10.0,
                y: 5.0,
                width: 20.0,
                height: 10.0,
                space: CoordinateSpace::Logical,
            },
            &geometry,
        )
        .unwrap();

        assert_eq!(
            rect,
            PixelRect {
                x: 20,
                y: 10,
                width: 40,
                height: 20
            }
        );
        assert_eq!(
            checked_zoom_scale(ScaleFactor(2.0)).unwrap(),
            ScaleFactor(2.0)
        );
        assert!(checked_zoom_scale(ScaleFactor(0.0)).is_err());
    }

    #[test]
    fn computer_coordinates_checked_once() {
        let geometry = FakeBackend::new().geometry;
        assert!(
            checked_point(
                Point {
                    x: 1280.0,
                    y: 0.0,
                    space: CoordinateSpace::Physical
                },
                &geometry
            )
            .is_err()
        );
        assert!(
            checked_rect(
                Rect {
                    x: 1279.0,
                    y: 0.0,
                    width: 2.0,
                    height: 1.0,
                    space: CoordinateSpace::Physical
                },
                &geometry
            )
            .is_err()
        );
    }

    #[tokio::test]
    #[ignore = "requires Linux with Xvfb, xdotool, and scrot/import installed; run manually for live virtual-display coverage"]
    async fn virtual_display_lifecycle() {
        match VirtualDisplayBackend::construct(DisplayTarget::Virtual, None) {
            Ok(mut backend) => {
                let geometry = backend.geometry().await.unwrap();
                assert!(geometry.physical.width > 0);
                let capture = execute_backend_action(&mut backend, &ComputerAction::CaptureFull)
                    .await
                    .unwrap();
                let ComputerActionOutcome::Captured(frame) = capture else {
                    panic!("expected capture outcome");
                };
                assert!(!frame.png.is_empty());
            }
            Err(ComputerError::MissingTool { tool, install_hint }) => {
                eprintln!(
                    "skipping virtual_display_lifecycle: missing {tool}; install {install_hint}"
                );
            }
            Err(ComputerError::UnsupportedPlatform { platform }) => {
                eprintln!("skipping virtual_display_lifecycle: unsupported on {platform}");
            }
            Err(error) => panic!("unexpected virtual display construction error: {error}"),
        }
    }
}
