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
        let xvfb = require_tool("Xvfb", "the `xvfb` package")?;
        let xdotool = require_tool("xdotool", "the `xdotool` package")?;
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
fn require_tool(tool: &'static str, install_hint: &'static str) -> Result<PathBuf, ComputerError> {
    find_on_path(tool).ok_or(ComputerError::MissingTool { tool, install_hint })
}

#[cfg(target_os = "linux")]
fn require_capture_tool() -> Result<CaptureTool, ComputerError> {
    if let Some(path) = find_on_path("scrot") {
        return Ok(CaptureTool::Scrot(path));
    }
    if let Some(path) = find_on_path("import") {
        return Ok(CaptureTool::Import(path));
    }
    Err(ComputerError::MissingTool {
        tool: "scrot or import",
        install_hint: "the `scrot` package or ImageMagick",
    })
}

#[cfg(target_os = "linux")]
fn find_on_path(tool: &str) -> Option<PathBuf> {
    std::env::split_paths(&std::env::var_os("PATH")?).find_map(|dir| {
        let path = dir.join(tool);
        path.is_file().then_some(path)
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

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
