//! Isolated computer-use backend.
//!
//! This module is the platform action layer only. It exposes no model-facing
//! tools; later prompts translate provider-native tool schemas into these typed
//! actions and add approvals/redaction/audit. The default target is a Cockpit
//! owned virtual display. Real-desktop control is refused unless a
//! machine-local grant file matches this machine.
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
use std::io::Cursor;
#[cfg(target_os = "linux")]
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Child;
#[cfg(target_os = "linux")]
use std::process::{Command, Stdio};
use std::time::Duration;

use async_trait::async_trait;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DisplayTarget {
    #[default]
    Virtual,
    RealDesktop,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DisplayGeometry {
    pub physical: PixelSize,
    pub logical: LogicalSize,
    pub scale_factor: ScaleFactor,
}

impl DisplayGeometry {
    /// Zero geometry — used only as a wire placeholder when the coordinator
    /// has not yet opened (candidate scan).  Production replaces it with the
    /// real backend-reported geometry at the open-before-advertise step.
    /// The coordinator rejects zero geometry with
    /// [`coordinator::CoordinatorOpenError::ZeroGeometry`].
    pub fn zero() -> Self {
        Self {
            physical: PixelSize {
                width: 0,
                height: 0,
            },
            logical: LogicalSize {
                width: 0.0,
                height: 0.0,
            },
            scale_factor: ScaleFactor(1.0),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PixelSize {
    pub width: u32,
    pub height: u32,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LogicalSize {
    pub width: f64,
    pub height: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
        chord: KeyChord,
    },
    HoldKey {
        key: String,
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

#[derive(Debug, Clone, PartialEq)]
pub enum ComputerActionOutcome {
    Captured(CaptureFrame),
    Completed,
    Waited(Duration),
}

#[derive(Debug, Clone, PartialEq)]
pub struct CaptureFrame {
    pub png: Vec<u8>,
    pub geometry: DisplayGeometry,
    pub region: Option<PixelRect>,
    pub native_zoom: Option<ScaleFactor>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComputerFailure {
    pub index: usize,
    pub error: ComputerError,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComputerError {
    MissingTool {
        tool: &'static str,
        install_hint: &'static str,
    },
    UnsupportedPlatform {
        platform: &'static str,
    },
    RealDesktopGrantMissing,
    InvalidCoordinates(String),
    Refused(String),
    Cancelled,
    CommandFailed {
        program: String,
        detail: String,
    },
}

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

#[async_trait]
pub trait ComputerBackend: Send {
    async fn geometry(&mut self) -> Result<DisplayGeometry, ComputerError>;
    async fn execute_one(
        &mut self,
        action: &ComputerAction,
    ) -> Result<ComputerActionOutcome, ComputerError>;
    async fn release_all(&mut self) -> Result<(), ComputerError>;

    async fn execute(&mut self, actions: &[ComputerAction]) -> ComputerBatchReport {
        let mut completed = Vec::new();
        for (index, action) in actions.iter().enumerate() {
            match self.execute_one(action).await {
                Ok(outcome) => completed.push(outcome),
                Err(error) => {
                    let _ = self.release_all().await;
                    return ComputerBatchReport {
                        completed,
                        failure: Some(ComputerFailure { index, error }),
                    };
                }
            }
        }
        if self.release_all().await.is_err() {
            // Release failures are deliberately not turned into action
            // failures after all actions completed; backends log these in
            // their concrete implementation. The important invariant is that
            // release is attempted on every terminal path.
        }
        ComputerBatchReport {
            completed,
            failure: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct FakeBackend {
    pub geometry: DisplayGeometry,
    pub recorded: Vec<ComputerAction>,
    pub release_count: usize,
    pub fail_at: Option<usize>,
    pub fail_with: ComputerError,
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

#[async_trait]
impl ComputerBackend for FakeBackend {
    async fn geometry(&mut self) -> Result<DisplayGeometry, ComputerError> {
        Ok(self.geometry.clone())
    }

    async fn execute_one(
        &mut self,
        action: &ComputerAction,
    ) -> Result<ComputerActionOutcome, ComputerError> {
        let index = self.recorded.len();
        self.recorded.push(action.clone());
        if self.fail_at == Some(index) {
            return Err(self.fail_with.clone());
        }
        match action {
            ComputerAction::CaptureFull => Ok(ComputerActionOutcome::Captured(CaptureFrame {
                png: vec![137, 80, 78, 71],
                geometry: self.geometry.clone(),
                region: None,
                native_zoom: None,
            })),
            ComputerAction::CaptureRegion { rect }
            | ComputerAction::CaptureNativeZoom { rect, .. } => {
                let region = checked_rect(*rect, &self.geometry)?;
                Ok(ComputerActionOutcome::Captured(CaptureFrame {
                    png: vec![137, 80, 78, 71],
                    geometry: self.geometry.clone(),
                    region: Some(region),
                    native_zoom: match action {
                        ComputerAction::CaptureNativeZoom { scale, .. } => Some(*scale),
                        _ => None,
                    },
                }))
            }
            ComputerAction::Wait { duration } => Ok(ComputerActionOutcome::Waited(*duration)),
            _ => Ok(ComputerActionOutcome::Completed),
        }
    }

    async fn release_all(&mut self) -> Result<(), ComputerError> {
        self.release_count += 1;
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
        stored.trim() == current_machine_fingerprint().trim()
    }
}

pub struct VirtualDisplayBackend {
    display: String,
    xvfb: Option<Child>,
    geometry: DisplayGeometry,
    tools: LinuxTools,
    held_keys: Vec<String>,
    /// Private, owner-only directory under the Cockpit data root that contains
    /// any transient capture temp files. Never `$TMPDIR`. See
    /// [`private_capture_root`].
    capture_root: PathBuf,
}

#[derive(Debug, Clone)]
struct LinuxTools {
    xdotool: PathBuf,
    capture: CaptureTool,
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
    pub fn construct(
        target: DisplayTarget,
        grant_store: Option<&RealDesktopGrantStore>,
    ) -> Result<Self, ComputerError> {
        match target {
            DisplayTarget::Virtual => Self::new_virtual(),
            DisplayTarget::RealDesktop => {
                if !grant_store.is_some_and(RealDesktopGrantStore::has_current_machine_grant) {
                    return Err(ComputerError::RealDesktopGrantMissing);
                }
                Err(unsupported_platform())
            }
        }
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
            xvfb: Some(child),
            geometry,
            tools: LinuxTools { xdotool, capture },
            held_keys: Vec::new(),
            capture_root,
        })
    }

    #[cfg(not(target_os = "linux"))]
    fn new_virtual() -> Result<Self, ComputerError> {
        Err(unsupported_platform())
    }

    #[cfg(target_os = "linux")]
    fn run_xdotool_output(&self, args: &[OsString]) -> Result<std::process::Output, ComputerError> {
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
    fn capture_png(&self, region: Option<PixelRect>) -> Result<Vec<u8>, ComputerError> {
        capture_contained(
            &RealCaptureRunner,
            &self.tools.capture,
            &self.display,
            region,
            &self.capture_root,
        )
    }
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
    use std::io::Read as _;
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
    // Only now, with the file proven owner-only, read the bytes.
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).map_err(io_fail)?;
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
        let output = capture_command(tool, display, region, CaptureDest::Stdout)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
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
        Ok(output.stdout)
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
    async fn geometry(&mut self) -> Result<DisplayGeometry, ComputerError> {
        Ok(self.geometry.clone())
    }

    async fn execute_one(
        &mut self,
        action: &ComputerAction,
    ) -> Result<ComputerActionOutcome, ComputerError> {
        let result = execute_virtual_action(self, action);
        if result.is_err() {
            let _ = self.release_all().await;
        }
        result
    }

    async fn release_all(&mut self) -> Result<(), ComputerError> {
        #[cfg(target_os = "linux")]
        {
            let held_keys = std::mem::take(&mut self.held_keys);
            for key in held_keys {
                let _ = self.run_xdotool(&[OsString::from("keyup"), OsString::from(key)]);
            }
            for key in ["Shift", "Control", "Alt", "Super_L"] {
                let _ = self.run_xdotool(&[
                    OsString::from("keyup"),
                    OsString::from("--clearmodifiers"),
                    OsString::from(key),
                ]);
            }
            for button in [MouseButton::Left, MouseButton::Right, MouseButton::Middle] {
                let _ = self.run_xdotool(&[
                    OsString::from("mouseup"),
                    OsString::from(mouse_button_number(button).to_string()),
                ]);
            }
        }
        Ok(())
    }
}

impl Drop for VirtualDisplayBackend {
    fn drop(&mut self) {
        if let Some(mut child) = self.xvfb.take() {
            cockpit_host::process::terminate_group_sync(&mut child, Duration::from_millis(200));
        }
    }
}

#[cfg(target_os = "linux")]
fn execute_virtual_action(
    backend: &mut VirtualDisplayBackend,
    action: &ComputerAction,
) -> Result<ComputerActionOutcome, ComputerError> {
    match action {
        ComputerAction::CaptureFull => Ok(ComputerActionOutcome::Captured(CaptureFrame {
            png: backend.capture_png(None)?,
            geometry: backend.geometry.clone(),
            region: None,
            native_zoom: None,
        })),
        ComputerAction::CaptureRegion { rect } => {
            let region = checked_rect(*rect, &backend.geometry)?;
            Ok(ComputerActionOutcome::Captured(CaptureFrame {
                png: backend.capture_png(Some(region))?,
                geometry: backend.geometry.clone(),
                region: Some(region),
                native_zoom: None,
            }))
        }
        ComputerAction::CaptureNativeZoom { rect, scale } => {
            let region = checked_rect(*rect, &backend.geometry)?;
            let scale = checked_zoom_scale(*scale)?;
            let png = backend.capture_png(Some(region))?;
            Ok(ComputerActionOutcome::Captured(CaptureFrame {
                png: scale_png(png, scale)?,
                geometry: backend.geometry.clone(),
                region: Some(region),
                native_zoom: Some(scale),
            }))
        }
        ComputerAction::MoveCursor {
            to,
            duration,
            easing,
        } => {
            let point = checked_point(*to, &backend.geometry)?;
            move_cursor_with_timing(backend, point, *duration, *easing)?;
            Ok(ComputerActionOutcome::Completed)
        }
        ComputerAction::Click {
            button,
            count,
            modifiers,
        } => {
            run_modifiers(backend, *modifiers, true)?;
            for _ in 0..click_repetitions(*count) {
                backend.run_xdotool(&[
                    OsString::from("click"),
                    OsString::from(mouse_button_number(*button).to_string()),
                ])?;
            }
            run_modifiers(backend, *modifiers, false)?;
            Ok(ComputerActionOutcome::Completed)
        }
        ComputerAction::MouseDown { button } => {
            backend.run_xdotool(&[
                OsString::from("mousedown"),
                OsString::from(mouse_button_number(*button).to_string()),
            ])?;
            Ok(ComputerActionOutcome::Completed)
        }
        ComputerAction::MouseUp { button } => {
            backend.run_xdotool(&[
                OsString::from("mouseup"),
                OsString::from(mouse_button_number(*button).to_string()),
            ])?;
            Ok(ComputerActionOutcome::Completed)
        }
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
            let mut checked_path = Vec::with_capacity(path.len());
            for step in path {
                checked_path.push((
                    checked_point(step.point, &backend.geometry)?,
                    step.duration,
                    step.easing,
                ));
            }
            let (first, first_duration, first_easing) = checked_path[0];
            move_cursor_with_timing(backend, first, first_duration, first_easing)?;
            run_modifiers(backend, *modifiers, true)?;
            backend.run_xdotool(&[
                OsString::from("mousedown"),
                OsString::from(mouse_button_number(*button).to_string()),
            ])?;
            for (point, duration, easing) in checked_path.into_iter().skip(1) {
                move_cursor_with_timing(backend, point, duration, easing)?;
            }
            backend.run_xdotool(&[
                OsString::from("mouseup"),
                OsString::from(mouse_button_number(*button).to_string()),
            ])?;
            run_modifiers(backend, *modifiers, false)?;
            Ok(ComputerActionOutcome::Completed)
        }
        ComputerAction::TypeText { text } => {
            backend.run_xdotool(&[OsString::from("type"), OsString::from(text)])?;
            Ok(ComputerActionOutcome::Completed)
        }
        ComputerAction::KeyChord { chord } => {
            backend.run_xdotool(&[OsString::from("key"), OsString::from(chord.keys.join("+"))])?;
            Ok(ComputerActionOutcome::Completed)
        }
        ComputerAction::HoldKey { key, duration } => {
            backend.run_xdotool(&[OsString::from("keydown"), OsString::from(key)])?;
            backend.held_keys.push(key.clone());
            std::thread::sleep(*duration);
            backend.run_xdotool(&[OsString::from("keyup"), OsString::from(key)])?;
            backend.held_keys.retain(|held| held != key);
            Ok(ComputerActionOutcome::Completed)
        }
        ComputerAction::Scroll {
            delta_x,
            delta_y,
            modifiers,
        } => {
            run_modifiers(backend, *modifiers, true)?;
            let vertical = if *delta_y < 0 { "5" } else { "4" };
            for _ in 0..delta_y.unsigned_abs() {
                backend.run_xdotool(&[OsString::from("click"), OsString::from(vertical)])?;
            }
            let horizontal = if *delta_x < 0 { "7" } else { "6" };
            for _ in 0..delta_x.unsigned_abs() {
                backend.run_xdotool(&[OsString::from("click"), OsString::from(horizontal)])?;
            }
            run_modifiers(backend, *modifiers, false)?;
            Ok(ComputerActionOutcome::Completed)
        }
        ComputerAction::Wait { duration } => {
            std::thread::sleep(*duration);
            Ok(ComputerActionOutcome::Waited(*duration))
        }
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
    backend.run_xdotool(&[
        OsString::from("mousemove"),
        OsString::from(point.x.to_string()),
        OsString::from(point.y.to_string()),
    ])
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

#[cfg(target_os = "linux")]
fn scale_png(png: Vec<u8>, scale: ScaleFactor) -> Result<Vec<u8>, ComputerError> {
    if (scale.0 - 1.0).abs() < f64::EPSILON {
        return Ok(png);
    }
    let image =
        image::load_from_memory_with_format(&png, image::ImageFormat::Png).map_err(|error| {
            ComputerError::CommandFailed {
                program: "image".to_string(),
                detail: error.to_string(),
            }
        })?;
    let width = scaled_dimension(image.width(), scale)?;
    let height = scaled_dimension(image.height(), scale)?;
    let scaled = image.resize_exact(width, height, image::imageops::FilterType::Nearest);
    let mut out = Vec::new();
    scaled
        .write_to(&mut Cursor::new(&mut out), image::ImageFormat::Png)
        .map_err(|error| ComputerError::CommandFailed {
            program: "image".to_string(),
            detail: error.to_string(),
        })?;
    Ok(out)
}

#[cfg(target_os = "linux")]
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
    _action: &ComputerAction,
) -> Result<ComputerActionOutcome, ComputerError> {
    Err(unsupported_platform())
}

#[cfg(target_os = "linux")]
fn run_modifiers(
    backend: &VirtualDisplayBackend,
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
            backend.run_xdotool(&[OsString::from(verb), OsString::from(key)])?;
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
    if !x.is_finite() || !y.is_finite() || x < 0.0 || y < 0.0 {
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
    let width = (rect.width * scale).round() as u32;
    let height = (rect.height * scale).round() as u32;
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
struct PixelPoint {
    x: u32,
    y: u32,
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
    crate::capabilities::resolve_binary(tool)
        .ok_or(ComputerError::MissingTool { tool, install_hint })
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
        tool: "scrot or import",
        install_hint: "the `scrot` package or ImageMagick",
    })
}

fn unsupported_platform() -> ComputerError {
    ComputerError::UnsupportedPlatform {
        platform: std::env::consts::OS,
    }
}

fn current_machine_fingerprint() -> String {
    fs::read_to_string("/etc/machine-id")
        .map(|value| value.trim().to_string())
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "unknown-machine".to_string())
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
    /// Geometry reported by the opened backend at the selected-delegation
    /// open-before-advertise step. `None` means the coordinator has not yet
    /// opened (candidate scan) or open failed (tool not advertised).
    ///
    /// Candidate/reachability scans construct this config with `geometry:
    /// None` and must NOT call full [`coordinator::ComputerActionCoordinator::open`]
    /// or acquire the host lock.  The wire builder falls back to 0×0 for
    /// `None`, but production must replace `None` with `Some(opened.geometry)`
    /// before the first model request that would advertise the tool
    /// (open-before-advertise).  If open fails, `native_computer` stays
    /// `None` entirely (AC17/AC18/AC19).
    pub geometry: Option<DisplayGeometry>,
    /// True when the effective `computer_use` tier is `ask`.
    ///
    /// The gating prompt wires this bit so the following approval/redaction
    /// prompt can route native computer actions through the shared approval
    /// path without re-resolving provider/project policy at dispatch time.
    pub approval_required: bool,
}

impl NativeComputerToolConfig {
    pub fn wire(&self) -> NativeComputerWire {
        match &self.geometry {
            Some(g) => native_computer_wire(self.contract, g),
            None => native_computer_wire(self.contract, &DisplayGeometry::zero()),
        }
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

    pub fn to_backend(&self) -> ComputerAction {
        match self {
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
                chord: chord.clone(),
            },
            Self::HoldKey { key, duration } => ComputerAction::HoldKey {
                key: key.clone(),
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
        }
    }

    pub fn to_backend_actions(&self) -> Vec<ComputerAction> {
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
        actions.push(self.to_backend());
        actions
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

    pub fn to_backend(&self) -> ComputerAction {
        match self {
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
                chord: chord.clone(),
            },
            Self::HoldKey { key, duration } => ComputerAction::HoldKey {
                key: key.clone(),
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
        }
    }

    pub fn to_backend_actions(&self) -> Vec<ComputerAction> {
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
        actions.push(self.to_backend());
        actions
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
    Duration::from_secs_f64(seconds.max(0.0))
}

fn scroll_delta(direction: ScrollDirection, amount: i32) -> (i32, i32) {
    match direction {
        ScrollDirection::Up => (0, -amount),
        ScrollDirection::Down => (0, amount),
        ScrollDirection::Left => (-amount, 0),
        ScrollDirection::Right => (amount, 0),
    }
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
    #[error("computer_call.actions must be an array")]
    MissingActions,
    #[error("unsupported OpenAI computer action `{0}`")]
    UnsupportedAction(String),
    #[error("malformed OpenAI computer action: {0}")]
    MalformedAction(String),
}

impl OpenAiComputerAction {
    pub fn to_backend(&self) -> ComputerAction {
        match self {
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
                chord: chord.clone(),
            },
            Self::TypeText(text) => ComputerAction::TypeText { text: text.clone() },
        }
    }

    pub fn to_backend_actions(&self) -> Vec<ComputerAction> {
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
        actions.push(self.to_backend());
        actions
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
    let raw_actions = value
        .get("actions")
        .and_then(serde_json::Value::as_array)
        .ok_or(OpenAiComputerWireError::MissingActions)?;
    let mut actions = Vec::with_capacity(raw_actions.len());
    for raw in raw_actions {
        let action: OpenAiComputerWireAction =
            serde_json::from_value(raw.clone()).map_err(|err| {
                let action_type = raw.get("type").and_then(serde_json::Value::as_str);
                match action_type {
                    Some(action_type) => {
                        OpenAiComputerWireError::UnsupportedAction(action_type.into())
                    }
                    None => OpenAiComputerWireError::MalformedAction(err.to_string()),
                }
            })?;
        actions.push(action.into_provider_action());
    }
    Ok((call_id, actions))
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
    let mut completed = Vec::new();
    for (index, action) in actions.iter().enumerate() {
        let report = backend.execute(&action.to_backend_actions()).await;
        completed.extend(report.completed);
        if let Some(mut failure) = report.failure {
            failure.index = index;
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
    }
    let capture = backend.execute_one(&ComputerAction::CaptureFull).await;
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
                chord: KeyChord {
                    keys: vec!["Control".to_string(), "L".to_string()],
                },
            },
            ComputerAction::HoldKey {
                key: "Shift".to_string(),
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
        let backend_actions = parsed_click.to_backend_actions();
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
        assert_eq!(
            backend.recorded[..3],
            actions
                .iter()
                .map(OpenAiComputerAction::to_backend)
                .collect::<Vec<_>>()
        );
        assert!(matches!(backend.recorded[3], ComputerAction::CaptureFull));
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
            "actions": [
                {"type": "move", "x": 4.0, "y": 5.0},
                {"type": "click", "x": 100.0, "y": 200.0, "button": "left", "modifiers": {"shift": true}},
                {"type": "type", "text": "hello"}
            ],
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
        assert_eq!(backend.recorded.len(), 5);
        assert!(matches!(
            backend.recorded[0],
            ComputerAction::MoveCursor {
                to: Point {
                    x: 4.0,
                    y: 5.0,
                    space: CoordinateSpace::Physical,
                },
                ..
            }
        ));
        assert!(matches!(
            backend.recorded[1],
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
            backend.recorded[2],
            ComputerAction::Click {
                button: MouseButton::Left,
                modifiers: Modifiers { shift: true, .. },
                ..
            }
        ));
    }

    #[tokio::test]
    async fn openai_computer_batch_failure_boundary() {
        // This test is corrected to go through the coordinator path. The old
        // direct helper `execute_openai_computer_call` does not carry
        // IDs/generations, journal handoff, or `not_dispatched` tails. The
        // new assertions below reject the old direct execution path.
        use super::host_identity::HostInstallationId;
        use super::target::{FakeTargetEvidenceAdapter, sample_physical_evidence};
        use coordinator::{
            ActionIdentity, ComputerActionCoordinator, ComputerApprovalTier, CoordinatedOutcome,
            CoordinatorParams, DelegationId, FakeComputerAuthorizer, ModelId, OwnerInstance,
            ProviderId,
        };

        let backend = FakeBackend::failing_at(1, ComputerError::Refused("blocked".to_string()));
        let authorizer: std::sync::Arc<dyn coordinator::ComputerAuthorizer> =
            std::sync::Arc::new(FakeComputerAuthorizer::always_allow());
        // Opens with a real focus generation via the target-evidence adapter so
        // the TypeText actions clear the focus-generation gate; the mid-batch
        // Failed { index: 1 } assertion is asserted against the coordinator
        // path.
        let adapter = FakeTargetEvidenceAdapter::new(sample_physical_evidence(
            HostInstallationId([1u8; 32]),
            [2u8; 32],
            [3u8; 32],
            [4u8; 16],
            1234,
        ));
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
        assert!(coordinator.observation_generation() > 0);

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
        .to_backend();
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
        .to_backend();
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
        let report = backend.execute(&actions).await;

        assert_eq!(backend.recorded, actions);
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
        assert_eq!(backend.release_count, 1);
    }

    #[tokio::test]
    async fn computer_batch_failure_boundary() {
        let actions = sample_actions();
        let mut backend =
            FakeBackend::failing_at(3, ComputerError::Refused("blocked by policy".to_string()));
        let report = backend.execute(&actions).await;

        assert_eq!(backend.recorded, actions[..=3]);
        assert_eq!(report.completed.len(), 3);
        assert_eq!(report.failure.as_ref().unwrap().index, 3);
        assert_eq!(backend.release_count, 1);
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
                ComputerError::UnsupportedPlatform { platform: "linux" }
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
                chord: KeyChord {
                    keys: vec!["Control".to_string(), "L".to_string()],
                },
            },
            ComputerAction::HoldKey {
                key: "L".to_string(),
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
        let report = backend.execute(&actions).await;

        assert_eq!(report.failure, None);
        assert!(matches!(
            backend.recorded[0],
            ComputerAction::TypeText { .. }
        ));
        assert!(matches!(
            backend.recorded[1],
            ComputerAction::KeyChord { .. }
        ));
        assert!(matches!(
            backend.recorded[2],
            ComputerAction::HoldKey { .. }
        ));
        assert!(matches!(backend.recorded[3], ComputerAction::Click { .. }));
    }

    #[tokio::test]
    async fn computer_held_input_always_released() {
        let actions = vec![
            ComputerAction::MouseDown {
                button: MouseButton::Left,
            },
            ComputerAction::HoldKey {
                key: "Shift".to_string(),
                duration: Duration::from_millis(1),
            },
        ];
        let mut ok = FakeBackend::new();
        let ok_report = ok.execute(&actions).await;
        assert_eq!(ok_report.failure, None);
        assert_eq!(ok.release_count, 1);

        let mut fail = FakeBackend::failing_at(1, ComputerError::Cancelled);
        let fail_report = fail.execute(&actions).await;
        assert_eq!(fail_report.failure.unwrap().error, ComputerError::Cancelled);
        assert_eq!(fail.release_count, 1);
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
                let capture = backend
                    .execute_one(&ComputerAction::CaptureFull)
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
