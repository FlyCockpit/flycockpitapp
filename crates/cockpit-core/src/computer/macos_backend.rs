//! macOS physical-desktop capture and CGEvent input backend.
//!
//! Perception remains pixel-based. Accessibility is queried separately by the
//! target-evidence adapter and is never used to choose action coordinates.

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use async_trait::async_trait;
use objc2_core_foundation::CGPoint;
use objc2_core_graphics::{
    CGDisplayCopyDisplayMode, CGDisplayMode, CGEvent, CGEventField, CGEventFlags, CGEventSource,
    CGEventSourceStateID, CGEventTapLocation, CGEventType, CGMainDisplayID, CGMouseButton,
    CGPreflightPostEventAccess, CGPreflightScreenCaptureAccess, CGScrollEventUnit,
};

use super::{
    CaptureFrame, ClickCount, ComputerAction, ComputerActionOutcome, ComputerBackend,
    ComputerError, DisplayGeometry, Easing, Modifiers, MouseButton, PixelPoint, PixelRect,
    PixelSize, ScaleFactor, checked_action_duration, checked_point, checked_rect,
    checked_scroll_delta, checked_zoom_scale, click_repetitions, eased_progress, scale_png,
};
use crate::computer::target::BackendKind;

const SCREENCAPTURE: &str = "/usr/sbin/screencapture";
const MOVE_STEPS: u32 = 12;

/// Physical macOS desktop backend. Construction performs both TCC preflights;
/// it never opens a usable backend when Screen Recording or Accessibility /
/// Input Monitoring access is absent.
pub struct MacOsComputerBackend {
    source: objc2_core_foundation::CFRetained<CGEventSource>,
    geometry: DisplayGeometry,
    held_keys: Vec<u16>,
    held_buttons: Vec<MouseButton>,
}

// CoreGraphics' immutable event source is safe to retain behind the backend's
// unique `&mut self` dispatch seam. objc2 conservatively does not mark every CF
// wrapper Send/Sync, while the native CGEventSourceRef is thread-safe.
unsafe impl Send for MacOsComputerBackend {}
unsafe impl Sync for MacOsComputerBackend {}

impl MacOsComputerBackend {
    pub fn construct() -> Result<Self, ComputerError> {
        if !Path::new(SCREENCAPTURE).is_file() {
            return Err(ComputerError::MissingTool {
                tool: SCREENCAPTURE.to_string(),
                install_hint: "the system macOS screencapture utility".to_string(),
            });
        }
        if !CGPreflightScreenCaptureAccess() {
            return Err(permission_error("Screen Recording"));
        }
        if !CGPreflightPostEventAccess() {
            return Err(permission_error("Accessibility or Input Monitoring"));
        }
        let source = CGEventSource::new(CGEventSourceStateID::HIDSystemState).ok_or_else(|| {
            ComputerError::CommandFailed {
                program: "CGEventSourceCreate".to_string(),
                detail: "CoreGraphics returned null".to_string(),
            }
        })?;
        Ok(Self {
            source,
            geometry: query_geometry()?,
            held_keys: Vec::new(),
            held_buttons: Vec::new(),
        })
    }

    fn capture_png(&self, region: Option<PixelRect>) -> Result<Vec<u8>, ComputerError> {
        let mut command = Command::new(SCREENCAPTURE);
        command.args(["-x", "-t", "png"]);
        if let Some(region) = region {
            let scale = self.geometry.scale_factor.0;
            command.arg(format!(
                "-R{},{},{},{}",
                (f64::from(region.x) / scale).round() as u32,
                (f64::from(region.y) / scale).round() as u32,
                (f64::from(region.width) / scale).round() as u32,
                (f64::from(region.height) / scale).round() as u32,
            ));
        } else {
            // Keep the backend geometry and capture surface identical: the
            // main physical display, not a changing multi-file screen set.
            command.arg("-m");
        }
        let output = command
            .arg("-")
            .stdin(Stdio::null())
            .stderr(Stdio::piped())
            .output()
            .map_err(|error| command_error("screencapture", error))?;
        if !output.status.success() {
            return Err(ComputerError::CommandFailed {
                program: "screencapture".to_string(),
                detail: String::from_utf8_lossy(&output.stderr).trim().to_string(),
            });
        }
        if !output.stdout.starts_with(b"\x89PNG\r\n\x1a\n") {
            return Err(ComputerError::CommandFailed {
                program: "screencapture".to_string(),
                detail: "capture did not return a PNG".to_string(),
            });
        }
        Ok(output.stdout)
    }

    fn post_mouse(
        &self,
        event_type: CGEventType,
        button: MouseButton,
        point: CGPoint,
        flags: CGEventFlags,
        click_state: i64,
    ) -> Result<(), ComputerError> {
        let event = CGEvent::new_mouse_event(
            Some(&self.source),
            event_type,
            point,
            cg_button(button),
        )
        .ok_or_else(|| cg_null("CGEventCreateMouseEvent"))?;
        CGEvent::set_flags(Some(&event), flags);
        if click_state > 0 {
            CGEvent::set_integer_value_field(
                Some(&event),
                CGEventField::MouseEventClickState,
                click_state,
            );
        }
        CGEvent::post(CGEventTapLocation::HIDEventTap, Some(&event));
        Ok(())
    }

    fn cursor(&self) -> Result<CGPoint, ComputerError> {
        let event = CGEvent::new(Some(&self.source)).ok_or_else(|| cg_null("CGEventCreate"))?;
        Ok(CGEvent::location(Some(&event)))
    }

    fn move_cursor(
        &self,
        target: PixelPoint,
        duration: Duration,
        easing: Easing,
        drag_button: Option<MouseButton>,
    ) -> Result<(), ComputerError> {
        let scale = self.geometry.scale_factor.0;
        let target = CGPoint::new(f64::from(target.x) / scale, f64::from(target.y) / scale);
        let start = self.cursor()?;
        let steps = if duration.is_zero() { 1 } else { MOVE_STEPS };
        let delay = duration / steps;
        for step in 1..=steps {
            let progress = eased_progress(f64::from(step) / f64::from(steps), easing);
            let point = CGPoint::new(
                start.x + (target.x - start.x) * progress,
                start.y + (target.y - start.y) * progress,
            );
            let event_type = drag_button.map_or(CGEventType::MouseMoved, drag_event_type);
            self.post_mouse(
                event_type,
                drag_button.unwrap_or(MouseButton::Left),
                point,
                CGEventFlags::empty(),
                0,
            )?;
            if !delay.is_zero() {
                std::thread::sleep(delay);
            }
        }
        Ok(())
    }

    fn post_key(&self, code: u16, down: bool, flags: CGEventFlags) -> Result<(), ComputerError> {
        let event = CGEvent::new_keyboard_event(Some(&self.source), code, down)
            .ok_or_else(|| cg_null("CGEventCreateKeyboardEvent"))?;
        CGEvent::set_flags(Some(&event), flags);
        CGEvent::post(CGEventTapLocation::HIDEventTap, Some(&event));
        Ok(())
    }

    fn type_text(&self, text: &str) -> Result<(), ComputerError> {
        // CoreGraphics accepts UTF-16 payloads. Chunking avoids undocumented
        // event-size limits while preserving surrogate pairs.
        for chunk in text.encode_utf16().collect::<Vec<_>>().chunks(20) {
            let down = CGEvent::new_keyboard_event(Some(&self.source), 0, true)
                .ok_or_else(|| cg_null("CGEventCreateKeyboardEvent"))?;
            // SAFETY: `chunk` is alive for the call and supplies exactly len
            // initialized UniChar values.
            unsafe {
                CGEvent::keyboard_set_unicode_string(Some(&down), chunk.len(), chunk.as_ptr());
            }
            CGEvent::post(CGEventTapLocation::HIDEventTap, Some(&down));
            let up = CGEvent::new_keyboard_event(Some(&self.source), 0, false)
                .ok_or_else(|| cg_null("CGEventCreateKeyboardEvent"))?;
            CGEvent::post(CGEventTapLocation::HIDEventTap, Some(&up));
        }
        Ok(())
    }

    fn execute_action(
        &mut self,
        action: &ComputerAction,
    ) -> Result<ComputerActionOutcome, ComputerError> {
        match action {
            ComputerAction::CaptureFull => Ok(ComputerActionOutcome::Captured(CaptureFrame {
                png: self.capture_png(None)?,
                geometry: self.geometry.clone(),
                region: None,
                native_zoom: None,
            })),
            ComputerAction::CaptureRegion { rect } => {
                let region = checked_rect(*rect, &self.geometry)?;
                Ok(ComputerActionOutcome::Captured(CaptureFrame {
                    png: self.capture_png(Some(region))?,
                    geometry: self.geometry.clone(),
                    region: Some(region),
                    native_zoom: None,
                }))
            }
            ComputerAction::CaptureNativeZoom { rect, scale } => {
                let region = checked_rect(*rect, &self.geometry)?;
                let scale = checked_zoom_scale(*scale)?;
                Ok(ComputerActionOutcome::Captured(CaptureFrame {
                    png: scale_png(self.capture_png(Some(region))?, scale)?,
                    geometry: self.geometry.clone(),
                    region: Some(region),
                    native_zoom: Some(scale),
                }))
            }
            ComputerAction::MoveCursor {
                to,
                duration,
                easing,
            } => {
                checked_action_duration(*duration)?;
                self.move_cursor(
                    checked_point(*to, &self.geometry)?,
                    *duration,
                    *easing,
                    None,
                )?;
                Ok(ComputerActionOutcome::Completed)
            }
            ComputerAction::Click {
                button,
                count,
                modifiers,
            } => {
                let point = self.cursor()?;
                let flags = modifier_flags(*modifiers);
                for click in 1..=click_repetitions(*count) {
                    self.post_mouse(
                        mouse_down_type(*button),
                        *button,
                        point,
                        flags,
                        i64::from(click),
                    )?;
                    self.post_mouse(
                        mouse_up_type(*button),
                        *button,
                        point,
                        flags,
                        i64::from(click),
                    )?;
                }
                Ok(ComputerActionOutcome::Completed)
            }
            ComputerAction::MouseDown { button } => {
                self.post_mouse(
                    mouse_down_type(*button),
                    *button,
                    self.cursor()?,
                    CGEventFlags::empty(),
                    1,
                )?;
                if !self.held_buttons.contains(button) {
                    self.held_buttons.push(*button);
                }
                Ok(ComputerActionOutcome::Completed)
            }
            ComputerAction::MouseUp { button } => {
                self.post_mouse(
                    mouse_up_type(*button),
                    *button,
                    self.cursor()?,
                    CGEventFlags::empty(),
                    1,
                )?;
                self.held_buttons.retain(|held| held != button);
                Ok(ComputerActionOutcome::Completed)
            }
            ComputerAction::Drag {
                button,
                path,
                modifiers,
            } => {
                let Some(first) = path.first() else {
                    return Err(ComputerError::InvalidCoordinates(
                        "drag path must contain at least one point".to_string(),
                    ));
                };
                for step in path {
                    checked_action_duration(step.duration)?;
                    checked_point(step.point, &self.geometry)?;
                }
                self.move_cursor(
                    checked_point(first.point, &self.geometry)?,
                    first.duration,
                    first.easing,
                    None,
                )?;
                let flags = modifier_flags(*modifiers);
                self.post_mouse(
                    mouse_down_type(*button),
                    *button,
                    self.cursor()?,
                    flags,
                    1,
                )?;
                self.held_buttons.push(*button);
                for step in path.iter().skip(1) {
                    self.move_cursor(
                        checked_point(step.point, &self.geometry)?,
                        step.duration,
                        step.easing,
                        Some(*button),
                    )?;
                }
                self.post_mouse(
                    mouse_up_type(*button),
                    *button,
                    self.cursor()?,
                    flags,
                    1,
                )?;
                self.held_buttons.retain(|held| held != button);
                Ok(ComputerActionOutcome::Completed)
            }
            ComputerAction::TypeText { text } => {
                self.type_text(text)?;
                Ok(ComputerActionOutcome::Completed)
            }
            ComputerAction::KeyChord { chord } => {
                let mut codes = Vec::with_capacity(chord.keys.len());
                for key in &chord.keys {
                    codes.push(key_code(key).ok_or_else(|| {
                        ComputerError::Refused(format!("unsupported macOS key `{key}`"))
                    })?);
                }
                let flags = flags_for_keys(&chord.keys);
                for code in &codes {
                    self.post_key(*code, true, flags)?;
                }
                for code in codes.iter().rev() {
                    self.post_key(*code, false, flags)?;
                }
                Ok(ComputerActionOutcome::Completed)
            }
            ComputerAction::HoldKey { key, duration } => {
                checked_action_duration(*duration)?;
                let code = key_code(key).ok_or_else(|| {
                    ComputerError::Refused(format!("unsupported macOS key `{key}`"))
                })?;
                self.post_key(code, true, flags_for_keys(std::slice::from_ref(key)))?;
                self.held_keys.push(code);
                std::thread::sleep(*duration);
                self.post_key(code, false, CGEventFlags::empty())?;
                self.held_keys.retain(|held| *held != code);
                Ok(ComputerActionOutcome::Completed)
            }
            ComputerAction::Scroll {
                delta_x,
                delta_y,
                modifiers,
            } => {
                checked_scroll_delta(*delta_x)?;
                checked_scroll_delta(*delta_y)?;
                let event = CGEvent::new_scroll_wheel_event2(
                    Some(&self.source),
                    CGScrollEventUnit::Pixel,
                    2,
                    -*delta_y,
                    -*delta_x,
                    0,
                )
                .ok_or_else(|| cg_null("CGEventCreateScrollWheelEvent2"))?;
                CGEvent::set_flags(Some(&event), modifier_flags(*modifiers));
                CGEvent::post(CGEventTapLocation::HIDEventTap, Some(&event));
                Ok(ComputerActionOutcome::Completed)
            }
            ComputerAction::Wait { duration } => {
                checked_action_duration(*duration)?;
                std::thread::sleep(*duration);
                Ok(ComputerActionOutcome::Waited(*duration))
            }
        }
    }
}

#[async_trait]
impl ComputerBackend for MacOsComputerBackend {
    fn backend_kind(&self) -> BackendKind {
        BackendKind::RealDesktopMacOs
    }

    async fn geometry(&mut self) -> Result<DisplayGeometry, ComputerError> {
        self.geometry = query_geometry()?;
        Ok(self.geometry.clone())
    }

    async fn execute_one(
        &mut self,
        action: &ComputerAction,
    ) -> Result<ComputerActionOutcome, ComputerError> {
        self.execute_action(action)
    }

    fn release_all(&mut self) -> Result<(), ComputerError> {
        let mut first_error = None;
        for code in std::mem::take(&mut self.held_keys) {
            if let Err(error) = self.post_key(code, false, CGEventFlags::empty())
                && first_error.is_none()
            {
                first_error = Some(error);
            }
        }
        let cursor = self.cursor();
        for button in std::mem::take(&mut self.held_buttons) {
            let result = cursor.as_ref().map_err(Clone::clone).and_then(|point| {
                self.post_mouse(
                    mouse_up_type(button),
                    button,
                    *point,
                    CGEventFlags::empty(),
                    1,
                )
            });
            if let Err(error) = result
                && first_error.is_none()
            {
                first_error = Some(error);
            }
        }
        if let Some(error) = first_error {
            return Err(error);
        }
        Ok(())
    }
}

fn query_geometry() -> Result<DisplayGeometry, ComputerError> {
    let display = CGMainDisplayID();
    let mode = CGDisplayCopyDisplayMode(display).ok_or_else(|| ComputerError::CommandFailed {
        program: "CGDisplayCopyDisplayMode".to_string(),
        detail: "main display has no current mode".to_string(),
    })?;
    let logical_width = CGDisplayMode::width(Some(&mode));
    let logical_height = CGDisplayMode::height(Some(&mode));
    let physical_width = CGDisplayMode::pixel_width(Some(&mode));
    let physical_height = CGDisplayMode::pixel_height(Some(&mode));
    let scale = physical_width as f64 / logical_width as f64;
    if logical_width == 0
        || logical_height == 0
        || physical_width == 0
        || physical_height == 0
        || !scale.is_finite()
        || scale <= 0.0
    {
        return Err(ComputerError::CommandFailed {
            program: "CGDisplayCopyDisplayMode".to_string(),
            detail: "main display returned invalid geometry".to_string(),
        });
    }
    Ok(DisplayGeometry {
        physical: PixelSize {
            width: u32::try_from(physical_width).map_err(|error| command_error("CoreGraphics", error))?,
            height: u32::try_from(physical_height).map_err(|error| command_error("CoreGraphics", error))?,
        },
        logical: super::LogicalSize {
            width: logical_width as f64,
            height: logical_height as f64,
        },
        scale_factor: ScaleFactor(scale),
    })
}

fn permission_error(permission: &str) -> ComputerError {
    ComputerError::Refused(format!(
        "macOS {permission} permission is required for real desktop control"
    ))
}

fn command_error(program: &str, error: impl std::fmt::Display) -> ComputerError {
    ComputerError::CommandFailed {
        program: program.to_string(),
        detail: error.to_string(),
    }
}

fn cg_null(program: &str) -> ComputerError {
    command_error(program, "CoreGraphics returned null")
}

fn modifier_flags(modifiers: Modifiers) -> CGEventFlags {
    let mut flags = CGEventFlags::empty();
    if modifiers.shift {
        flags |= CGEventFlags::MaskShift;
    }
    if modifiers.control {
        flags |= CGEventFlags::MaskControl;
    }
    if modifiers.alt {
        flags |= CGEventFlags::MaskAlternate;
    }
    if modifiers.meta {
        flags |= CGEventFlags::MaskCommand;
    }
    flags
}

fn flags_for_keys(keys: &[String]) -> CGEventFlags {
    modifier_flags(Modifiers {
        shift: keys.iter().any(|key| key.eq_ignore_ascii_case("shift")),
        control: keys
            .iter()
            .any(|key| key.eq_ignore_ascii_case("control") || key.eq_ignore_ascii_case("ctrl")),
        alt: keys.iter().any(|key| {
            key.eq_ignore_ascii_case("alt") || key.eq_ignore_ascii_case("option")
        }),
        meta: keys.iter().any(|key| {
            key.eq_ignore_ascii_case("meta") || key.eq_ignore_ascii_case("command")
        }),
    })
}

fn cg_button(button: MouseButton) -> CGMouseButton {
    match button {
        MouseButton::Left => CGMouseButton::Left,
        MouseButton::Right => CGMouseButton::Right,
        MouseButton::Middle => CGMouseButton::Center,
    }
}

fn mouse_down_type(button: MouseButton) -> CGEventType {
    match button {
        MouseButton::Left => CGEventType::LeftMouseDown,
        MouseButton::Right => CGEventType::RightMouseDown,
        MouseButton::Middle => CGEventType::OtherMouseDown,
    }
}

fn mouse_up_type(button: MouseButton) -> CGEventType {
    match button {
        MouseButton::Left => CGEventType::LeftMouseUp,
        MouseButton::Right => CGEventType::RightMouseUp,
        MouseButton::Middle => CGEventType::OtherMouseUp,
    }
}

fn drag_event_type(button: MouseButton) -> CGEventType {
    match button {
        MouseButton::Left => CGEventType::LeftMouseDragged,
        MouseButton::Right => CGEventType::RightMouseDragged,
        MouseButton::Middle => CGEventType::OtherMouseDragged,
    }
}

/// US ANSI virtual-key map used for command chords. Literal text does not use
/// this table; it is injected with CGEvent's UTF-16 API.
fn key_code(key: &str) -> Option<u16> {
    let normalized = key.to_ascii_lowercase();
    Some(match normalized.as_str() {
        "a" => 0x00,
        "s" => 0x01,
        "d" => 0x02,
        "f" => 0x03,
        "h" => 0x04,
        "g" => 0x05,
        "z" => 0x06,
        "x" => 0x07,
        "c" => 0x08,
        "v" => 0x09,
        "b" => 0x0b,
        "q" => 0x0c,
        "w" => 0x0d,
        "e" => 0x0e,
        "r" => 0x0f,
        "y" => 0x10,
        "t" => 0x11,
        "1" => 0x12,
        "2" => 0x13,
        "3" => 0x14,
        "4" => 0x15,
        "6" => 0x16,
        "5" => 0x17,
        "=" => 0x18,
        "9" => 0x19,
        "7" => 0x1a,
        "-" => 0x1b,
        "8" => 0x1c,
        "0" => 0x1d,
        "]" => 0x1e,
        "o" => 0x1f,
        "u" => 0x20,
        "[" => 0x21,
        "i" => 0x22,
        "p" => 0x23,
        "l" => 0x25,
        "j" => 0x26,
        "'" => 0x27,
        "k" => 0x28,
        ";" => 0x29,
        "\\" => 0x2a,
        "," => 0x2b,
        "/" => 0x2c,
        "n" => 0x2d,
        "m" => 0x2e,
        "." => 0x2f,
        "tab" => 0x30,
        "space" => 0x31,
        "`" => 0x32,
        "backspace" | "delete" => 0x33,
        "escape" | "esc" => 0x35,
        "command" | "meta" => 0x37,
        "shift" => 0x38,
        "capslock" => 0x39,
        "option" | "alt" => 0x3a,
        "control" | "ctrl" => 0x3b,
        "enter" | "return" => 0x24,
        "f17" => 0x40,
        "volumeup" => 0x48,
        "volumedown" => 0x49,
        "mute" => 0x4a,
        "f18" => 0x4f,
        "f19" => 0x50,
        "f20" => 0x5a,
        "f5" => 0x60,
        "f6" => 0x61,
        "f7" => 0x62,
        "f3" => 0x63,
        "f8" => 0x64,
        "f9" => 0x65,
        "f11" => 0x67,
        "f13" => 0x69,
        "f16" => 0x6a,
        "f14" => 0x6b,
        "f10" => 0x6d,
        "f12" => 0x6f,
        "f15" => 0x71,
        "home" => 0x73,
        "pageup" => 0x74,
        "forwarddelete" => 0x75,
        "f4" => 0x76,
        "end" => 0x77,
        "f2" => 0x78,
        "pagedown" => 0x79,
        "f1" => 0x7a,
        "left" | "arrowleft" => 0x7b,
        "right" | "arrowright" => 0x7c,
        "down" | "arrowdown" => 0x7d,
        "up" | "arrowup" => 0x7e,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_map_and_modifier_flags_cover_primary_chords() {
        assert_eq!(key_code("Command"), Some(0x37));
        assert_eq!(key_code("ArrowLeft"), Some(0x7b));
        assert!(flags_for_keys(&["Command".into(), "Shift".into()])
            .contains(CGEventFlags::MaskCommand | CGEventFlags::MaskShift));
        assert_eq!(key_code("not-a-key"), None);
    }

    #[test]
    #[ignore = "requires an interactive macOS login plus Screen Recording and Accessibility grants"]
    fn constructs_and_captures_real_desktop_when_tcc_granted() {
        let mut backend = MacOsComputerBackend::construct().expect("construct macOS backend");
        let runtime = tokio::runtime::Runtime::new().expect("runtime");
        let outcome = runtime
            .block_on(backend.execute_one(&ComputerAction::CaptureFull))
            .expect("capture main display");
        let ComputerActionOutcome::Captured(frame) = outcome else {
            panic!("capture returned a non-capture outcome");
        };
        assert!(frame.png.starts_with(b"\x89PNG\r\n\x1a\n"));
        assert_eq!(backend.backend_kind(), BackendKind::RealDesktopMacOs);
    }
}
