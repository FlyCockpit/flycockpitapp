//! Isolated computer-use backend.
//!
//! This module is the platform action layer only. It exposes no model-facing
//! tools; later prompts translate provider-native tool schemas into these typed
//! actions and add approvals/redaction/audit. The default target is a Cockpit
//! owned virtual display. Real-desktop control is refused unless a
//! machine-local grant file matches this machine.

#![allow(dead_code)]

#[cfg(target_os = "linux")]
use std::ffi::OsString;
use std::fs;
#[cfg(target_os = "linux")]
use std::io::Cursor;
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

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ScaleFactor(pub f64);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MouseButton {
    Left,
    Right,
    Middle,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClickCount {
    Single,
    Double,
    Triple,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
        let child = Command::new(xvfb)
            .arg(&display)
            .arg("-screen")
            .arg("0")
            .arg(format!(
                "{}x{}x24",
                geometry.physical.width, geometry.physical.height
            ))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
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
        let tmp = tempfile::NamedTempFile::new().map_err(|error| ComputerError::CommandFailed {
            program: "tempfile".to_string(),
            detail: error.to_string(),
        })?;
        let path = tmp.path().to_path_buf();
        let mut command = match &self.tools.capture {
            CaptureTool::Scrot(program) => {
                let mut cmd = Command::new(program);
                if let Some(region) = region {
                    cmd.arg("-a").arg(format!(
                        "{},{},{},{}",
                        region.x, region.y, region.width, region.height
                    ));
                }
                cmd.arg(&path);
                cmd
            }
            CaptureTool::Import(program) => {
                let mut cmd = Command::new(program);
                if let Some(region) = region {
                    cmd.arg("-crop").arg(format!(
                        "{}x{}+{}+{}",
                        region.width, region.height, region.x, region.y
                    ));
                }
                cmd.arg(&path);
                cmd
            }
        };
        let output = command
            .env("DISPLAY", &self.display)
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
        fs::read(path).map_err(|error| ComputerError::CommandFailed {
            program: "capture".to_string(),
            detail: error.to_string(),
        })
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
            let _ = child.kill();
            let _ = child.wait();
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
    pub geometry: DisplayGeometry,
    /// True when the effective `computer_use` tier is `ask`.
    ///
    /// The gating prompt wires this bit so the following approval/redaction
    /// prompt can route native computer actions through the shared approval
    /// path without re-resolving provider/project policy at dispatch time.
    pub approval_required: bool,
}

impl NativeComputerToolConfig {
    pub fn wire(&self) -> NativeComputerWire {
        native_computer_wire(self.contract, &self.geometry)
    }
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
                "type": "computer_20251124",
                "name": "computer",
                "display_width_px": width,
                "display_height_px": height,
                "enable_zoom": true,
            })],
        },
        ComputerToolContract::Anthropic20250124 => NativeComputerWire {
            group: contract.group(),
            beta_headers: vec!["computer-use-2025-01-24"],
            tools: vec![serde_json::json!({
                "type": "computer_20250124",
                "name": "computer",
                "display_width_px": width,
                "display_height_px": height,
            })],
        },
        ComputerToolContract::OpenAiResponses => NativeComputerWire {
            group: contract.group(),
            beta_headers: Vec::new(),
            tools: vec![serde_json::json!({ "type": "computer" })],
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
    pub screenshot_png: Option<Vec<u8>>,
}

impl OpenAiComputerCallOutput {
    pub fn wire_item(&self) -> serde_json::Value {
        let mut output = serde_json::Map::new();
        output.insert(
            "type".to_string(),
            serde_json::Value::String("computer_call_output".to_string()),
        );
        output.insert(
            "call_id".to_string(),
            serde_json::Value::String(self.call_id.clone()),
        );
        output.insert(
            "completed".to_string(),
            serde_json::json!(self.completed.len()),
        );
        if let Some(failure) = &self.failure {
            output.insert(
                "failure".to_string(),
                serde_json::json!({
                    "index": failure.index,
                    "error": failure.error.to_string(),
                }),
            );
        } else if let Some(png) = &self.screenshot_png {
            use base64::Engine as _;
            output.insert(
                "output".to_string(),
                serde_json::json!({
                    "type": "computer_screenshot",
                    "image_url": format!(
                        "data:image/png;base64,{}",
                        base64::engine::general_purpose::STANDARD.encode(png)
                    ),
                }),
            );
        }
        serde_json::Value::Object(output)
    }
}

pub async fn execute_openai_computer_call<B: ComputerBackend>(
    backend: &mut B,
    call_id: impl Into<String>,
    actions: &[OpenAiComputerAction],
) -> OpenAiComputerCallOutput {
    let call_id = call_id.into();
    let mut completed = Vec::new();
    for (index, action) in actions.iter().enumerate() {
        let report = backend.execute(&action.to_backend_actions()).await;
        completed.extend(report.completed);
        if let Some(mut failure) = report.failure {
            failure.index = index;
            return OpenAiComputerCallOutput {
                call_id,
                completed,
                failure: Some(failure),
                screenshot_png: None,
            };
        }
    }
    let screenshot = match backend.execute_one(&ComputerAction::CaptureFull).await {
        Ok(ComputerActionOutcome::Captured(frame)) => Some(frame.png),
        Ok(_) | Err(_) => None,
    };
    OpenAiComputerCallOutput {
        call_id,
        completed,
        failure: None,
        screenshot_png: screenshot,
    }
}

pub async fn execute_openai_computer_call_json<B: ComputerBackend>(
    backend: &mut B,
    call: &serde_json::Value,
) -> Result<OpenAiComputerCallOutput, OpenAiComputerWireError> {
    let (call_id, actions) = parse_openai_computer_call(call)?;
    Ok(execute_openai_computer_call(backend, call_id, &actions).await)
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
        for newer_only in ["zoom"] {
            assert!(!older_names.contains(&newer_only));
        }
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
        let output = execute_openai_computer_call(&mut backend, "call-1", &actions).await;

        assert_eq!(output.call_id, "call-1");
        assert_eq!(output.failure, None);
        assert_eq!(output.completed.len(), 3);
        assert!(output.screenshot_png.is_some());
        assert_eq!(
            backend.recorded[..3],
            actions
                .iter()
                .map(OpenAiComputerAction::to_backend)
                .collect::<Vec<_>>()
        );
        assert!(matches!(backend.recorded[3], ComputerAction::CaptureFull));
        assert_eq!(
            output.wire_item()["type"],
            serde_json::Value::String("computer_call_output".to_string())
        );
        assert_eq!(output.wire_item()["call_id"], "call-1");
        assert_eq!(output.wire_item()["output"]["type"], "computer_screenshot");
        assert!(
            output.wire_item()["output"]["image_url"]
                .as_str()
                .unwrap()
                .starts_with("data:image/png;base64,")
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
        let output = execute_openai_computer_call_json(&mut backend, &call)
            .await
            .unwrap();

        assert_eq!(output.call_id, "call-json");
        assert_eq!(output.failure, None);
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
        let mut backend = FakeBackend::failing_at(1, ComputerError::Refused("blocked".to_string()));
        let actions = vec![
            OpenAiComputerAction::Move {
                to: provider_point(4.0, 5.0, CoordinateSpace::Physical),
            },
            OpenAiComputerAction::TypeText("stop here".to_string()),
            OpenAiComputerAction::TypeText("must not execute".to_string()),
        ];
        let output = execute_openai_computer_call(&mut backend, "call-2", &actions).await;

        assert_eq!(output.call_id, "call-2");
        assert_eq!(output.completed.len(), 1);
        assert_eq!(output.failure.as_ref().unwrap().index, 1);
        assert_eq!(output.screenshot_png, None);
        assert_eq!(
            backend.recorded,
            actions[..=1]
                .iter()
                .map(OpenAiComputerAction::to_backend)
                .collect::<Vec<_>>()
        );
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
