//! Windows physical-desktop backend and target-evidence adapter.
//!
//! Pixel perception remains authoritative. UI Automation contributes only
//! target identity/control-type evidence used by the approval boundary.

use std::mem::size_of;
use std::thread;
use std::time::Duration;

use async_trait::async_trait;
use windows::Win32::Foundation::{CloseHandle, HANDLE, HWND, POINT, RECT};
use windows::Win32::Graphics::Gdi::{
    BI_RGB, BITMAPINFO, BITMAPINFOHEADER, BitBlt, CAPTUREBLT, CreateCompatibleBitmap,
    CreateCompatibleDC, DIB_RGB_COLORS, DISPLAY_DEVICEW, DeleteDC, DeleteObject,
    EnumDisplayDevicesW, GetDC, GetDIBits, GetMonitorInfoW, HGDIOBJ, MONITOR_DEFAULTTONEAREST,
    MONITORINFOEXW, MonitorFromWindow, ReleaseDC, SRCCOPY, SelectObject,
};
use windows::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx, CoUninitialize,
};
use windows::Win32::System::Ole::{
    SafeArrayAccessData, SafeArrayDestroy, SafeArrayGetLBound, SafeArrayGetUBound,
    SafeArrayUnaccessData,
};
use windows::Win32::System::RemoteDesktop::ProcessIdToSessionId;
use windows::Win32::System::StationsAndDesktops::{
    CloseDesktop, DESKTOP_CONTROL_FLAGS, DESKTOP_READOBJECTS, GetProcessWindowStation,
    GetThreadDesktop, GetUserObjectInformationW, OpenInputDesktop, UOI_NAME,
};
use windows::Win32::System::Threading::{
    GetCurrentProcessId, GetCurrentThreadId, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    QueryFullProcessImageNameW,
};
use windows::Win32::UI::Accessibility::{CUIAutomation, IUIAutomation, IUIAutomationElement};
use windows::Win32::UI::HiDpi::{GetDpiForSystem, GetDpiForWindow};
use windows::Win32::UI::Input::KeyboardAndMouse::*;
use windows::Win32::UI::WindowsAndMessaging::{
    EDD_GET_DEVICE_INTERFACE_NAME, GA_ROOT, GetAncestor, GetClassNameW, GetCursorPos,
    GetForegroundWindow, GetSystemMetrics, GetWindowRect, GetWindowThreadProcessId, IsChild,
    IsWindow, SM_CXVIRTUALSCREEN, SM_CYVIRTUALSCREEN, SM_XVIRTUALSCREEN, SM_YVIRTUALSCREEN,
};
use windows::core::{PCWSTR, PWSTR};

#[cfg(test)]
use crate::computer::ComputerAction;
use crate::computer::host_identity::{
    RealHostIdentityFs, SysHostIdentityRng, domain_hash, load_or_create_host_installation_id,
};
use crate::computer::target::{
    BackendKind, EvidenceSource, FieldEvidence, FocusGenerationReducer, OpaqueWindowId,
    RedactedHint, StableApplicationId, TargetEvidenceAdapter, TargetGeometry,
    TargetIdentityEvidence, TargetUnavailableReason, empty_unavailable,
};
use crate::computer::{
    CaptureFrame, ClickCount, ComputerActionOutcome, ComputerBackend, ComputerError,
    DisplayGeometry, DisplayTarget, EVIDENCED_WINDOW_MISMATCH, Easing, LogicalSize, Modifiers,
    MouseButton, NormalizedComputerAction, NormalizedComputerEffect, NormalizedKeyCode, PixelPoint,
    PixelRect, PixelSize, RealDesktopGrantStore, SYNTHETIC_INPUT_REQUIRES_EVIDENCED_WINDOW,
    ScaleFactor,
};

#[derive(Debug)]
pub(crate) struct WindowsDesktopBackend {
    geometry: DisplayGeometry,
    origin_x: i32,
    origin_y: i32,
    held_keyboard_inputs: Vec<HeldKeyboardInput>,
    held_input_journal: WindowsHeldInputJournal,
    held_buttons: Vec<MouseButton>,
    physical_capability: Option<crate::computer::coordinator::PhysicalDispatchCapability>,
    evidenced_window: Option<OpaqueWindowId>,
}

/// Every keyboard down event is made durable before `SendInput`. Recovery uses
/// the journal under the Windows session-wide host lease, so an extra key-up is
/// preferred over handing a possibly held key to a replacement daemon.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
enum HeldKeyboardInput {
    VirtualKey { key: u16, extended: bool },
    Unicode(u16),
}

/// The exact Win32 input required for one layout-independent key identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct VirtualKeyInput {
    key: VIRTUAL_KEY,
    extended: bool,
}

impl VirtualKeyInput {
    const fn plain(key: VIRTUAL_KEY) -> Self {
        Self {
            key,
            extended: is_extended_key(key),
        }
    }
}

#[derive(Debug)]
struct WindowsHeldInputJournal {
    path: std::path::PathBuf,
}

impl WindowsHeldInputJournal {
    fn for_current_input_session() -> Result<Self, ComputerError> {
        let root = crate::config::resolve::cockpit_data_dir()
            .map_err(win_input_error)?
            .join("computer-input-state");
        cockpit_host::private_fs::ensure_private_dir(&root).map_err(win_input_error)?;
        let digest = windows_input_session_identity()?;
        let name = digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        Ok(Self {
            path: root.join(format!("windows-{name}.json")),
        })
    }

    fn load(&self) -> Result<Vec<HeldKeyboardInput>, ComputerError> {
        let Some(bytes) =
            cockpit_host::private_fs::read_private_file(&self.path, "Windows computer held-input")
                .map_err(win_input_error)?
        else {
            return Ok(Vec::new());
        };
        serde_json::from_slice(&bytes)
            .map_err(|_| win_input_error("Windows held-input journal is malformed"))
    }

    fn store(&self, inputs: &[HeldKeyboardInput]) -> Result<(), ComputerError> {
        if inputs.is_empty() {
            return cockpit_host::private_fs::delete_private_file(&self.path)
                .map_err(win_input_error);
        }
        let bytes = serde_json::to_vec(inputs).map_err(win_input_error)?;
        cockpit_host::private_fs::write_private_file(&self.path, &bytes).map_err(win_input_error)
    }
}

impl WindowsDesktopBackend {
    pub(crate) fn construct(
        target: DisplayTarget,
        grant_store: Option<&RealDesktopGrantStore>,
    ) -> Result<Self, ComputerError> {
        if target != DisplayTarget::RealDesktop {
            return Err(ComputerError::UnsupportedPlatform {
                platform: "windows-virtual-display".to_string(),
            });
        }
        if !grant_store.is_some_and(RealDesktopGrantStore::has_current_machine_grant) {
            return Err(ComputerError::RealDesktopGrantMissing);
        }
        let (geometry, origin_x, origin_y) = query_geometry()?;
        let held_input_journal = WindowsHeldInputJournal::for_current_input_session()?;
        let held_keyboard_inputs = held_input_journal.load()?;
        Ok(Self {
            geometry,
            origin_x,
            origin_y,
            held_keyboard_inputs,
            held_input_journal,
            held_buttons: Vec::new(),
            physical_capability: None,
            evidenced_window: None,
        })
    }

    fn require_physical_capability(&self) -> Result<(), ComputerError> {
        self.physical_capability
            .as_ref()
            .ok_or_else(|| {
                ComputerError::Refused("physical backend is not coordinator-bound".into())
            })?
            .recheck(BackendKind::RealDesktopWindows)
    }

    fn require_live_evidenced_window(&self) -> Result<(), ComputerError> {
        let expected = self.evidenced_window.ok_or_else(|| {
            ComputerError::Refused(SYNTHETIC_INPUT_REQUIRES_EVIDENCED_WINDOW.to_string())
        })?;
        let live = foreground_opaque_window_id()?;
        if live != expected {
            return Err(ComputerError::Refused(
                EVIDENCED_WINDOW_MISMATCH.to_string(),
            ));
        }
        Ok(())
    }

    fn reload_held_keyboard_inputs(&mut self) -> Result<(), ComputerError> {
        self.held_keyboard_inputs = self.held_input_journal.load()?;
        Ok(())
    }

    fn remember_held_keyboard_input(
        &mut self,
        input: HeldKeyboardInput,
    ) -> Result<(), ComputerError> {
        let mut inputs = self.held_keyboard_inputs.clone();
        inputs.push(input);
        self.held_input_journal.store(&inputs)?;
        self.held_keyboard_inputs = inputs;
        Ok(())
    }

    fn forget_held_keyboard_input(
        &mut self,
        input: HeldKeyboardInput,
    ) -> Result<(), ComputerError> {
        let mut inputs = self.held_keyboard_inputs.clone();
        let Some(index) = inputs.iter().rposition(|held| *held == input) else {
            return Err(win_input_error(
                "Windows key-up has no durable key-down record",
            ));
        };
        inputs.remove(index);
        self.held_input_journal.store(&inputs)?;
        self.held_keyboard_inputs = inputs;
        Ok(())
    }

    fn key_down(&mut self, key: VirtualKeyInput) -> Result<(), ComputerError> {
        self.remember_held_keyboard_input(HeldKeyboardInput::VirtualKey {
            key: key.key.0,
            extended: key.extended,
        })?;
        send_key(key, false)
    }

    fn key_up(&mut self, key: VirtualKeyInput) -> Result<(), ComputerError> {
        send_key(key, true)?;
        self.forget_held_keyboard_input(HeldKeyboardInput::VirtualKey {
            key: key.key.0,
            extended: key.extended,
        })
    }

    fn unicode_down(&mut self, unit: u16) -> Result<(), ComputerError> {
        self.remember_held_keyboard_input(HeldKeyboardInput::Unicode(unit))?;
        send_unicode(unit, false)
    }

    fn unicode_up(&mut self, unit: u16) -> Result<(), ComputerError> {
        send_unicode(unit, true)?;
        self.forget_held_keyboard_input(HeldKeyboardInput::Unicode(unit))
    }

    fn send_modifiers(&mut self, modifiers: Modifiers, up: bool) -> Result<(), ComputerError> {
        let keys = [
            (modifiers.shift, VirtualKeyInput::plain(VK_SHIFT)),
            (modifiers.control, VirtualKeyInput::plain(VK_CONTROL)),
            (modifiers.alt, VirtualKeyInput::plain(VK_MENU)),
            (modifiers.meta, VirtualKeyInput::plain(VK_LWIN)),
        ];
        if up {
            for (enabled, key) in keys.iter().rev() {
                if *enabled {
                    self.key_up(*key)?;
                }
            }
        } else {
            for (enabled, key) in keys {
                if enabled {
                    self.key_down(key)?;
                }
            }
        }
        Ok(())
    }

    fn key_input_down(&mut self, key: VirtualKeyInput) -> Result<(), ComputerError> {
        self.key_down(key)
    }

    fn key_input_up(&mut self, key: VirtualKeyInput) -> Result<(), ComputerError> {
        self.key_up(key)
    }

    fn refresh_geometry(&mut self) -> Result<(), ComputerError> {
        let (geometry, origin_x, origin_y) = query_geometry()?;
        self.geometry = geometry;
        self.origin_x = origin_x;
        self.origin_y = origin_y;
        Ok(())
    }

    fn capture(&self, region: Option<PixelRect>) -> Result<Vec<u8>, ComputerError> {
        let region = region.unwrap_or(PixelRect {
            x: 0,
            y: 0,
            width: self.geometry.physical.width,
            height: self.geometry.physical.height,
        });
        let width = i32::try_from(region.width).map_err(win_input_error)?;
        let height = i32::try_from(region.height).map_err(win_input_error)?;
        let byte_len = usize::try_from(region.width)
            .ok()
            .and_then(|w| {
                usize::try_from(region.height)
                    .ok()
                    .and_then(|h| w.checked_mul(h))
            })
            .and_then(|pixels| pixels.checked_mul(4))
            .ok_or_else(|| win_input_error("capture dimensions overflow"))?;

        // SAFETY: every GDI handle is checked and released on all paths below;
        // the DIB buffer is sized to width * height * 4 for a 32-bit BI_RGB DIB.
        unsafe {
            let screen = GetDC(None);
            if screen.is_invalid() {
                return Err(win32_error("GetDC"));
            }
            let memory = CreateCompatibleDC(Some(screen));
            let bitmap = CreateCompatibleBitmap(screen, width, height);
            if memory.is_invalid() || bitmap.is_invalid() {
                if !bitmap.is_invalid() {
                    let _ = DeleteObject(HGDIOBJ(bitmap.0));
                }
                if !memory.is_invalid() {
                    let _ = DeleteDC(memory);
                }
                let _ = ReleaseDC(None, screen);
                return Err(win32_error("CreateCompatibleDC/CreateCompatibleBitmap"));
            }
            let old = SelectObject(memory, HGDIOBJ(bitmap.0));
            let blit = BitBlt(
                memory,
                0,
                0,
                width,
                height,
                Some(screen),
                self.origin_x + i32::try_from(region.x).map_err(win_input_error)?,
                self.origin_y + i32::try_from(region.y).map_err(win_input_error)?,
                SRCCOPY | CAPTUREBLT,
            );
            let mut pixels = vec![0_u8; byte_len];
            let mut info = BITMAPINFO::default();
            info.bmiHeader = BITMAPINFOHEADER {
                biSize: size_of::<BITMAPINFOHEADER>() as u32,
                biWidth: width,
                biHeight: -height,
                biPlanes: 1,
                biBitCount: 32,
                biCompression: BI_RGB.0,
                ..Default::default()
            };
            let rows = if blit.is_ok() {
                GetDIBits(
                    memory,
                    bitmap,
                    0,
                    region.height,
                    Some(pixels.as_mut_ptr().cast()),
                    &mut info,
                    DIB_RGB_COLORS,
                )
            } else {
                0
            };
            let _ = SelectObject(memory, old);
            let _ = DeleteObject(HGDIOBJ(bitmap.0));
            let _ = DeleteDC(memory);
            let _ = ReleaseDC(None, screen);
            if rows != height {
                return Err(win32_error("BitBlt/GetDIBits"));
            }
            gdi_bgra_to_rgba_opaque(&mut pixels);
            let image = image::RgbaImage::from_raw(region.width, region.height, pixels)
                .ok_or_else(|| win_input_error("GDI returned an invalid image buffer"))?;
            crate::media_image::encode_png_rgba(
                &image,
                &crate::media_image::ImageProfile::screenshot(),
            )
            .map_err(|error| win_input_error(error.to_string()))
        }
    }

    fn move_cursor(&self, point: PixelPoint) -> Result<(), ComputerError> {
        let (x, y) = (point.x, point.y);
        let width = self.geometry.physical.width.saturating_sub(1).max(1);
        let height = self.geometry.physical.height.saturating_sub(1).max(1);
        send_mouse(
            ((u64::from(x) * 65_535) / u64::from(width)) as i32,
            ((u64::from(y) * 65_535) / u64::from(height)) as i32,
            0,
            MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK,
        )
    }
}

/// A 32-bit `BI_RGB` DIB is BGRA-shaped in memory, but GDI does not define its
/// fourth byte as alpha. Screenshots are opaque, so normalize it before PNG
/// encoding rather than preserving uninitialized or zero alpha values.
fn gdi_bgra_to_rgba_opaque(pixels: &mut [u8]) {
    for pixel in pixels.chunks_exact_mut(4) {
        pixel.swap(0, 2);
        pixel[3] = u8::MAX;
    }
}

#[async_trait]
impl ComputerBackend for WindowsDesktopBackend {
    fn backend_kind(&self) -> BackendKind {
        BackendKind::RealDesktopWindows
    }

    async fn geometry(&mut self) -> Result<DisplayGeometry, ComputerError> {
        self.refresh_geometry()?;
        Ok(self.geometry.clone())
    }

    async fn execute_normalized_one(
        &mut self,
        action: &NormalizedComputerAction,
    ) -> Result<ComputerActionOutcome, ComputerError> {
        self.require_physical_capability()?;
        if action.effect().injects_synthetic_input() {
            self.require_live_evidenced_window()?;
        }
        match action.effect() {
            NormalizedComputerEffect::CaptureFull => Ok(captured(self, None, None)?),
            NormalizedComputerEffect::CaptureRegion { rect } => {
                Ok(captured(self, Some(*rect), None)?)
            }
            NormalizedComputerEffect::CaptureNativeZoom {
                rect,
                scale,
                output,
            } => {
                let png = self.capture(Some(*rect))?;
                let profile = crate::media_image::ImageProfile::screenshot();
                let decoded = crate::media_image::decode_and_orient(&png, &profile)
                    .map_err(|error| win_input_error(error.to_string()))?;
                let scaled =
                    crate::media_image::scale(decoded, output.width, output.height, &profile);
                let png = crate::media_image::encode_png(&scaled, &profile)
                    .map_err(|error| win_input_error(error.to_string()))?;
                Ok(ComputerActionOutcome::Captured(CaptureFrame {
                    png,
                    geometry: self.geometry.clone(),
                    region: Some(*rect),
                    native_zoom: Some(*scale),
                }))
            }
            NormalizedComputerEffect::MoveCursor {
                to,
                duration,
                easing,
            } => {
                move_with_timing(self, *to, *duration, *easing)?;
                Ok(ComputerActionOutcome::Completed)
            }
            NormalizedComputerEffect::Click {
                button,
                count,
                modifiers,
            } => {
                self.send_modifiers(*modifiers, false)?;
                for _ in 0..click_count(*count) {
                    send_button(*button, false)?;
                    send_button(*button, true)?;
                }
                self.send_modifiers(*modifiers, true)?;
                Ok(ComputerActionOutcome::Completed)
            }
            NormalizedComputerEffect::MouseDown { button } => {
                send_button(*button, false)?;
                if !self.held_buttons.contains(button) {
                    self.held_buttons.push(*button);
                }
                Ok(ComputerActionOutcome::Completed)
            }
            NormalizedComputerEffect::MouseUp { button } => {
                send_button(*button, true)?;
                self.held_buttons.retain(|held| held != button);
                Ok(ComputerActionOutcome::Completed)
            }
            NormalizedComputerEffect::Drag {
                button,
                path,
                modifiers,
            } => {
                self.send_modifiers(*modifiers, false)?;
                move_with_timing(self, path[0].point, path[0].duration, path[0].easing)?;
                send_button(*button, false)?;
                self.held_buttons.push(*button);
                for step in &path[1..] {
                    move_with_timing(self, step.point, step.duration, step.easing)?;
                }
                send_button(*button, true)?;
                self.held_buttons.retain(|held| held != button);
                self.send_modifiers(*modifiers, true)?;
                Ok(ComputerActionOutcome::Completed)
            }
            NormalizedComputerEffect::TypeText { text } => {
                for unit in text.encode_utf16() {
                    self.unicode_down(unit)?;
                    self.unicode_up(unit)?;
                }
                Ok(ComputerActionOutcome::Completed)
            }
            NormalizedComputerEffect::KeyChord { chord } => {
                let keys = chord.keys().iter().map(virtual_key).collect::<Vec<_>>();
                for key in &keys {
                    self.key_input_down(*key)?;
                }
                for key in keys.iter().rev() {
                    self.key_input_up(*key)?;
                }
                Ok(ComputerActionOutcome::Completed)
            }
            NormalizedComputerEffect::HoldKey { key, duration } => {
                let key = virtual_key(key);
                self.key_input_down(key)?;
                thread::sleep(*duration);
                self.key_input_up(key)?;
                Ok(ComputerActionOutcome::Completed)
            }
            NormalizedComputerEffect::Scroll {
                delta_x,
                delta_y,
                modifiers,
            } => {
                self.send_modifiers(*modifiers, false)?;
                if *delta_y != 0 {
                    send_mouse(0, 0, (*delta_y * 120) as u32, MOUSEEVENTF_WHEEL)?;
                }
                if *delta_x != 0 {
                    send_mouse(0, 0, (*delta_x * 120) as u32, MOUSEEVENTF_HWHEEL)?;
                }
                self.send_modifiers(*modifiers, true)?;
                Ok(ComputerActionOutcome::Completed)
            }
            NormalizedComputerEffect::Wait { duration } => {
                thread::sleep(*duration);
                Ok(ComputerActionOutcome::Waited(*duration))
            }
        }
    }

    fn release_all(&mut self) -> Result<(), ComputerError> {
        let mut first = None;
        if let Err(error) = self.reload_held_keyboard_inputs() {
            first.get_or_insert(error);
        }
        for input in self.held_keyboard_inputs.clone().into_iter().rev() {
            let released = match input {
                HeldKeyboardInput::VirtualKey { key, extended } => send_key(
                    VirtualKeyInput {
                        key: VIRTUAL_KEY(key),
                        extended,
                    },
                    true,
                ),
                HeldKeyboardInput::Unicode(unit) => send_unicode(unit, true),
            };
            match released {
                Ok(()) => {
                    if let Err(error) = self.forget_held_keyboard_input(input) {
                        first.get_or_insert(error);
                    }
                }
                Err(error) => {
                    first.get_or_insert(error);
                }
            }
        }
        for button in self.held_buttons.drain(..).chain([
            MouseButton::Left,
            MouseButton::Right,
            MouseButton::Middle,
        ]) {
            if let Err(error) = send_button(button, true) {
                first.get_or_insert(error);
            }
        }
        first.map_or(Ok(()), Err)
    }

    fn bind_physical_capability(
        &mut self,
        capability: crate::computer::coordinator::PhysicalDispatchCapability,
    ) -> Result<(), ComputerError> {
        capability.recheck(BackendKind::RealDesktopWindows)?;
        self.physical_capability = Some(capability);
        Ok(())
    }

    fn bind_evidenced_window(&mut self, window: OpaqueWindowId) -> Result<(), ComputerError> {
        self.evidenced_window = Some(window);
        self.require_live_evidenced_window()
    }

    fn recheck_evidenced_window(&mut self) -> Result<(), ComputerError> {
        if self.evidenced_window.is_none() {
            return Ok(());
        }
        self.require_live_evidenced_window()
    }
}

fn captured(
    backend: &WindowsDesktopBackend,
    region: Option<PixelRect>,
    zoom: Option<ScaleFactor>,
) -> Result<ComputerActionOutcome, ComputerError> {
    Ok(ComputerActionOutcome::Captured(CaptureFrame {
        png: backend.capture(region)?,
        geometry: backend.geometry.clone(),
        region,
        native_zoom: zoom,
    }))
}

fn query_geometry() -> Result<(DisplayGeometry, i32, i32), ComputerError> {
    // SAFETY: GetSystemMetrics/GetDpiForSystem take no pointers and have no lifetime contract.
    let (x, y, width, height, dpi) = unsafe {
        (
            GetSystemMetrics(SM_XVIRTUALSCREEN),
            GetSystemMetrics(SM_YVIRTUALSCREEN),
            GetSystemMetrics(SM_CXVIRTUALSCREEN),
            GetSystemMetrics(SM_CYVIRTUALSCREEN),
            GetDpiForSystem(),
        )
    };
    if width <= 0 || height <= 0 || dpi == 0 {
        return Err(win32_error("virtual desktop geometry"));
    }
    let scale = f64::from(dpi) / 96.0;
    Ok((
        DisplayGeometry {
            physical: PixelSize {
                width: width as u32,
                height: height as u32,
            },
            logical: LogicalSize {
                width: f64::from(width) / scale,
                height: f64::from(height) / scale,
            },
            scale_factor: ScaleFactor(scale),
        },
        x,
        y,
    ))
}

fn move_with_timing(
    backend: &WindowsDesktopBackend,
    point: PixelPoint,
    duration: Duration,
    easing: Easing,
) -> Result<(), ComputerError> {
    if duration.is_zero() {
        return backend.move_cursor(point);
    }
    let mut cursor = POINT::default();
    // SAFETY: `cursor` is valid writable storage for the duration of the call.
    unsafe { GetCursorPos(&mut cursor) }.map_err(|_| win32_error("GetCursorPos"))?;
    let start_x = f64::from(cursor.x - backend.origin_x);
    let start_y = f64::from(cursor.y - backend.origin_y);
    let steps = 12;
    for step in 1..=steps {
        let mut progress = f64::from(step) / f64::from(steps);
        if easing == Easing::EaseInOut {
            progress = if progress < 0.5 {
                2.0 * progress * progress
            } else {
                1.0 - (-2.0 * progress + 2.0).powi(2) / 2.0
            };
        }
        backend.move_cursor(PixelPoint {
            x: (start_x + (f64::from(point.x) - start_x) * progress).round() as u32,
            y: (start_y + (f64::from(point.y) - start_y) * progress).round() as u32,
        })?;
        thread::sleep(duration / steps);
    }
    Ok(())
}

fn send(inputs: &[INPUT]) -> Result<(), ComputerError> {
    // SAFETY: INPUT is ABI-owned by the pinned windows binding; the slice stays live for the call.
    let sent = unsafe { SendInput(inputs, size_of::<INPUT>() as i32) };
    if sent == inputs.len() as u32 {
        Ok(())
    } else {
        Err(win32_error("SendInput"))
    }
}

fn send_mouse(dx: i32, dy: i32, data: u32, flags: MOUSE_EVENT_FLAGS) -> Result<(), ComputerError> {
    send(&[INPUT {
        r#type: INPUT_MOUSE,
        Anonymous: INPUT_0 {
            mi: MOUSEINPUT {
                dx,
                dy,
                mouseData: data,
                dwFlags: flags,
                time: 0,
                dwExtraInfo: 0,
            },
        },
    }])
}

fn send_button(button: MouseButton, up: bool) -> Result<(), ComputerError> {
    let flags = match (button, up) {
        (MouseButton::Left, false) => MOUSEEVENTF_LEFTDOWN,
        (MouseButton::Left, true) => MOUSEEVENTF_LEFTUP,
        (MouseButton::Right, false) => MOUSEEVENTF_RIGHTDOWN,
        (MouseButton::Right, true) => MOUSEEVENTF_RIGHTUP,
        (MouseButton::Middle, false) => MOUSEEVENTF_MIDDLEDOWN,
        (MouseButton::Middle, true) => MOUSEEVENTF_MIDDLEUP,
    };
    send_mouse(0, 0, 0, flags)
}

fn send_key(key: VirtualKeyInput, up: bool) -> Result<(), ComputerError> {
    send(&[INPUT {
        r#type: INPUT_KEYBOARD,
        Anonymous: INPUT_0 {
            ki: KEYBDINPUT {
                wVk: key.key,
                wScan: 0,
                dwFlags: key_event_flags(key, up),
                time: 0,
                dwExtraInfo: 0,
            },
        },
    }])
}

fn key_event_flags(key: VirtualKeyInput, up: bool) -> KEYBD_EVENT_FLAGS {
    (if key.extended {
        KEYEVENTF_EXTENDEDKEY
    } else {
        KEYBD_EVENT_FLAGS(0)
    }) | if up {
        KEYEVENTF_KEYUP
    } else {
        KEYBD_EVENT_FLAGS(0)
    }
}

fn send_unicode(unit: u16, up: bool) -> Result<(), ComputerError> {
    send(&[INPUT {
        r#type: INPUT_KEYBOARD,
        Anonymous: INPUT_0 {
            ki: KEYBDINPUT {
                wVk: VIRTUAL_KEY(0),
                wScan: unit,
                dwFlags: KEYEVENTF_UNICODE
                    | if up {
                        KEYEVENTF_KEYUP
                    } else {
                        KEYBD_EVENT_FLAGS(0)
                    },
                time: 0,
                dwExtraInfo: 0,
            },
        },
    }])
}

fn virtual_key(key: &NormalizedKeyCode) -> VirtualKeyInput {
    VirtualKeyInput {
        key: VIRTUAL_KEY(key.windows_virtual_key()),
        extended: key.windows_extended(),
    }
}

const fn is_extended_key(key: VIRTUAL_KEY) -> bool {
    matches!(
        key,
        VK_RCONTROL
            | VK_RMENU
            | VK_INSERT
            | VK_DELETE
            | VK_HOME
            | VK_END
            | VK_PRIOR
            | VK_NEXT
            | VK_UP
            | VK_DOWN
            | VK_LEFT
            | VK_RIGHT
            | VK_NUMLOCK
            | VK_SNAPSHOT
            | VK_DIVIDE
            | VK_LWIN
            | VK_RWIN
            | VK_APPS
    )
}

fn click_count(count: ClickCount) -> usize {
    match count {
        ClickCount::Single => 1,
        ClickCount::Double => 2,
        ClickCount::Triple => 3,
    }
}
fn win32_error(operation: &str) -> ComputerError {
    win_input_error(format!(
        "{operation}: {}",
        windows::core::Error::from_win32()
    ))
}
fn win_input_error(error: impl std::fmt::Display) -> ComputerError {
    ComputerError::CommandFailed {
        program: "windows computer backend".to_string(),
        detail: error.to_string(),
    }
}

#[derive(Debug)]
pub struct WindowsTargetEvidenceAdapter {
    host: crate::computer::host_identity::HostInstallationId,
    reducer: FocusGenerationReducer,
    observed_epoch: u64,
}

impl WindowsTargetEvidenceAdapter {
    pub fn new() -> Result<Self, TargetUnavailableReason> {
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

    fn native_snapshot(&self) -> Result<TargetIdentityEvidence, TargetUnavailableReason> {
        // SAFETY: queried HWND is validated before use; output pointers refer to initialized locals.
        unsafe {
            let hwnd = GetForegroundWindow();
            if hwnd.is_invalid() || !IsWindow(Some(hwnd)).as_bool() {
                return Err(TargetUnavailableReason::FocusIdentityUnavailable);
            }
            let mut pid = 0_u32;
            GetWindowThreadProcessId(hwnd, Some(&mut pid));
            if pid == 0 {
                return Err(TargetUnavailableReason::FocusIdentityUnavailable);
            }
            let mut rect = RECT::default();
            GetWindowRect(hwnd, &mut rect)
                .map_err(|_| TargetUnavailableReason::FocusIdentityUnavailable)?;
            let mut class = [0_u16; 256];
            let class_len = GetClassNameW(hwnd, &mut class);
            let class =
                (class_len > 0).then(|| String::from_utf16_lossy(&class[..class_len as usize]));
            let dpi = GetDpiForWindow(hwnd).max(96);
            let mut session = 0_u32;
            ProcessIdToSessionId(GetCurrentProcessId(), &mut session)
                .map_err(|_| TargetUnavailableReason::SessionInactive)?;
            if session == 0 {
                return Err(TargetUnavailableReason::SessionInactive);
            }
            let desktop =
                query_geometry().map_err(|_| TargetUnavailableReason::MissingCapability)?;
            let (station_name, desktop_name) = session_desktop_names()?;
            let session_id = domain_hash(
                b"cockpit.windows.session.v1",
                &[
                    &session.to_le_bytes(),
                    station_name.as_bytes(),
                    desktop_name.as_bytes(),
                ],
            );
            let display_id = monitor_identity(hwnd)?;
            let UiaCapture {
                fingerprint: uia_fingerprint,
                name: uia_name,
            } = uia_evidence(hwnd)?;
            let window_id = uia_fingerprint.window_runtime_id;
            let uia_role = uia_fingerprint.role.clone();
            let uia_subrole = uia_fingerprint.subrole.clone();
            let mut snapshot = empty_unavailable(BackendKind::RealDesktopWindows);
            snapshot.host_installation_id =
                FieldEvidence::available(self.host, EvidenceSource::WinSessionDesktop);
            snapshot.platform_session_or_seat_id =
                FieldEvidence::available(session_id, EvidenceSource::WinSessionDesktop);
            snapshot.physical_display_id =
                FieldEvidence::available(display_id, EvidenceSource::WinMonitor);
            snapshot.focused_window_id = FieldEvidence::available(
                OpaqueWindowId::from_bytes(window_id),
                EvidenceSource::WinForeground,
            );
            snapshot.process_id = FieldEvidence::available(pid, EvidenceSource::WinForeground);
            snapshot.stable_application_id = process_image_name(pid).map_or_else(
                || {
                    FieldEvidence::unavailable(
                        TargetUnavailableReason::PartialEvidence,
                        Some(EvidenceSource::WinForeground),
                    )
                },
                |image| {
                    FieldEvidence::available(
                        StableApplicationId {
                            kind: "win32.image",
                            value: image,
                        },
                        EvidenceSource::WinForeground,
                    )
                },
            );
            snapshot.accessibility_role = uia_role.map_or_else(
                || {
                    FieldEvidence::unavailable(
                        TargetUnavailableReason::PartialEvidence,
                        Some(EvidenceSource::Accessibility),
                    )
                },
                |role| FieldEvidence::available(role, EvidenceSource::Accessibility),
            );
            // TODO(a11y perception): UIA remains approval evidence only; pixel
            // capture drives perception and targeting. Subrole carries
            // IsPassword so credential fields are distinguishable from Edit.
            snapshot.accessibility_subrole = uia_subrole.map_or_else(
                || {
                    FieldEvidence::unavailable(
                        TargetUnavailableReason::PartialEvidence,
                        Some(EvidenceSource::Accessibility),
                    )
                },
                |subrole| FieldEvidence::available(subrole, EvidenceSource::Accessibility),
            );
            snapshot.title_hint = uia_name.map_or_else(
                || {
                    FieldEvidence::unavailable(
                        TargetUnavailableReason::PartialEvidence,
                        Some(EvidenceSource::Accessibility),
                    )
                },
                |name| {
                    FieldEvidence::available(
                        RedactedHint::from_raw(&name),
                        EvidenceSource::Accessibility,
                    )
                },
            );
            snapshot.class_hint = class.map_or_else(
                || {
                    FieldEvidence::unavailable(
                        TargetUnavailableReason::PartialEvidence,
                        Some(EvidenceSource::WinForeground),
                    )
                },
                |class| {
                    FieldEvidence::available(
                        RedactedHint::from_raw(&class),
                        EvidenceSource::WinForeground,
                    )
                },
            );
            snapshot.geometry = FieldEvidence::available(
                TargetGeometry {
                    x: rect.left,
                    y: rect.top,
                    width: (rect.right - rect.left).max(0) as u32,
                    height: (rect.bottom - rect.top).max(0) as u32,
                    scale: f64::from(dpi) / 96.0,
                },
                EvidenceSource::WinForeground,
            );
            snapshot.desktop_geometry = FieldEvidence::available(
                TargetGeometry {
                    x: desktop.1,
                    y: desktop.2,
                    width: desktop.0.physical.width,
                    height: desktop.0.physical.height,
                    scale: desktop.0.scale_factor.0,
                },
                EvidenceSource::WinMonitor,
            );
            snapshot.synchronous_recheck = GetForegroundWindow() == hwnd
                && IsWindow(Some(hwnd)).as_bool()
                && matches!(
                    uia_evidence(hwnd),
                    Ok(live) if live.fingerprint == uia_fingerprint
                );
            if !snapshot.synchronous_recheck {
                return Err(TargetUnavailableReason::QueryMismatch);
            }
            Ok(snapshot)
        }
    }
}

unsafe fn user_object_name(handle: HANDLE) -> Result<String, TargetUnavailableReason> {
    let mut needed = 0_u32;
    let _ = unsafe { GetUserObjectInformationW(handle, UOI_NAME, None, 0, Some(&mut needed)) };
    if needed < 2 {
        return Err(TargetUnavailableReason::SessionInactive);
    }
    let mut buffer = vec![0_u16; (needed as usize).div_ceil(2)];
    unsafe {
        GetUserObjectInformationW(
            handle,
            UOI_NAME,
            Some(buffer.as_mut_ptr().cast()),
            needed,
            Some(&mut needed),
        )
    }
    .map_err(|_| TargetUnavailableReason::SessionInactive)?;
    let end = buffer
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(buffer.len());
    let name = String::from_utf16_lossy(&buffer[..end]);
    if name.is_empty() {
        Err(TargetUnavailableReason::SessionInactive)
    } else {
        Ok(name)
    }
}

unsafe fn session_desktop_names() -> Result<(String, String), TargetUnavailableReason> {
    let station = unsafe { GetProcessWindowStation() }
        .map_err(|_| TargetUnavailableReason::SessionInactive)?;
    let thread_desktop = unsafe { GetThreadDesktop(GetCurrentThreadId()) }
        .map_err(|_| TargetUnavailableReason::SessionInactive)?;
    let input_desktop =
        unsafe { OpenInputDesktop(DESKTOP_CONTROL_FLAGS(0), false, DESKTOP_READOBJECTS) }
            .map_err(|_| TargetUnavailableReason::LockOrSecureDesktop)?;
    let station_name = unsafe { user_object_name(HANDLE(station.0)) };
    let thread_desktop_name = unsafe { user_object_name(HANDLE(thread_desktop.0)) };
    let input_desktop_name = unsafe { user_object_name(HANDLE(input_desktop.0)) };
    let _ = unsafe { CloseDesktop(input_desktop) };
    let thread_desktop_name = thread_desktop_name?;
    let input_desktop_name = input_desktop_name?;
    if thread_desktop_name != input_desktop_name {
        return Err(TargetUnavailableReason::LockOrSecureDesktop);
    }
    Ok((station_name?, input_desktop_name))
}

/// The input journal follows the Windows interactive session/desktop rather
/// than a monitor. `SendInput` is scoped to precisely this input namespace.
fn windows_input_session_identity() -> Result<[u8; 32], ComputerError> {
    // SAFETY: the Win32 calls write only to initialized local storage.
    unsafe {
        let mut session = 0_u32;
        ProcessIdToSessionId(GetCurrentProcessId(), &mut session)
            .map_err(|_| win_input_error("could not determine the Windows input session"))?;
        if session == 0 {
            return Err(win_input_error(
                "Windows session zero cannot receive desktop input",
            ));
        }
        let (station_name, desktop_name) = session_desktop_names()
            .map_err(|_| win_input_error("Windows interactive desktop is unavailable"))?;
        Ok(domain_hash(
            b"cockpit.windows.held-input.v1",
            &[
                &session.to_le_bytes(),
                station_name.as_bytes(),
                desktop_name.as_bytes(),
            ],
        ))
    }
}

unsafe fn monitor_identity(hwnd: HWND) -> Result<[u8; 32], TargetUnavailableReason> {
    let monitor = unsafe { MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST) };
    if monitor.is_invalid() {
        return Err(TargetUnavailableReason::AmbiguousOutput);
    }
    let mut info = MONITORINFOEXW::default();
    info.monitorInfo.cbSize = size_of::<MONITORINFOEXW>() as u32;
    if !unsafe { GetMonitorInfoW(monitor, (&mut info as *mut MONITORINFOEXW).cast()) }.as_bool() {
        return Err(TargetUnavailableReason::MissingCapability);
    }
    let device_name =
        wide_array(&info.szDevice).ok_or(TargetUnavailableReason::MissingCapability)?;
    let mut adapter = None;
    for index in 0..64 {
        let mut candidate = DISPLAY_DEVICEW {
            cb: size_of::<DISPLAY_DEVICEW>() as u32,
            ..Default::default()
        };
        if !unsafe {
            EnumDisplayDevicesW(
                PCWSTR::null(),
                index,
                &mut candidate,
                EDD_GET_DEVICE_INTERFACE_NAME,
            )
        }
        .as_bool()
        {
            break;
        }
        if wide_array(&candidate.DeviceName).as_deref() == Some(device_name.as_str()) {
            adapter = Some(candidate);
            break;
        }
    }
    let adapter = adapter.ok_or(TargetUnavailableReason::MissingCapability)?;
    let adapter_id =
        wide_array(&adapter.DeviceID).ok_or(TargetUnavailableReason::MissingCapability)?;
    let mut display = DISPLAY_DEVICEW {
        cb: size_of::<DISPLAY_DEVICEW>() as u32,
        ..Default::default()
    };
    if !unsafe {
        EnumDisplayDevicesW(
            PCWSTR(adapter.DeviceName.as_ptr()),
            0,
            &mut display,
            EDD_GET_DEVICE_INTERFACE_NAME,
        )
    }
    .as_bool()
    {
        return Err(TargetUnavailableReason::MissingCapability);
    }
    let display_id =
        wide_array(&display.DeviceID).ok_or(TargetUnavailableReason::MissingCapability)?;
    Ok(domain_hash(
        b"cockpit.windows.monitor.v1",
        &[
            device_name.as_bytes(),
            adapter_id.as_bytes(),
            display_id.as_bytes(),
        ],
    ))
}

fn wide_array<const N: usize>(value: &[u16; N]) -> Option<String> {
    let end = value.iter().position(|unit| *unit == 0).unwrap_or(N);
    (end > 0).then(|| String::from_utf16_lossy(&value[..end]))
}

unsafe fn process_image_name(pid: u32) -> Option<String> {
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok()?;
    let mut buffer = vec![0_u16; 32_768];
    let mut len = buffer.len() as u32;
    let result = unsafe {
        QueryFullProcessImageNameW(
            process,
            Default::default(),
            PWSTR(buffer.as_mut_ptr()),
            &mut len,
        )
    };
    let _ = unsafe { CloseHandle(process) };
    result.ok()?;
    std::path::Path::new(&String::from_utf16_lossy(&buffer[..len as usize]))
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
}

impl TargetEvidenceAdapter for WindowsTargetEvidenceAdapter {
    fn backend_kind(&self) -> BackendKind {
        BackendKind::RealDesktopWindows
    }
    fn capture_snapshot(&mut self) -> Result<TargetIdentityEvidence, TargetUnavailableReason> {
        let mut snapshot = self.native_snapshot()?;
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

struct UiaCapture {
    fingerprint: super::windows::UiaWidgetFingerprint,
    name: Option<String>,
}

fn foreground_opaque_window_id() -> Result<OpaqueWindowId, ComputerError> {
    // SAFETY: queried HWND is validated before use; UI Automation is initialized
    // for the duration of `uia_evidence`.
    unsafe {
        let hwnd = GetForegroundWindow();
        if hwnd.is_invalid() || !IsWindow(Some(hwnd)).as_bool() {
            return Err(ComputerError::Refused(
                EVIDENCED_WINDOW_MISMATCH.to_string(),
            ));
        }
        let capture = uia_evidence(hwnd).map_err(|_| {
            ComputerError::Refused(SYNTHETIC_INPUT_REQUIRES_EVIDENCED_WINDOW.to_string())
        })?;
        Ok(OpaqueWindowId::from_bytes(
            capture.fingerprint.window_runtime_id,
        ))
    }
}

unsafe fn uia_evidence(hwnd: HWND) -> Result<UiaCapture, TargetUnavailableReason> {
    let initialized = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) }.is_ok();
    let evidence = (|| -> Result<_, TargetUnavailableReason> {
        let automation: IUIAutomation =
            unsafe { CoCreateInstance(&CUIAutomation, None, CLSCTX_INPROC_SERVER) }
                .map_err(|_| TargetUnavailableReason::FocusIdentityUnavailable)?;
        // Window identity and title stay on the foreground HWND. Widget
        // role/subrole come from the focused UIA element (issue #290),
        // never from the window's control type, and only when that element
        // belongs to this HWND.
        let window = unsafe { automation.ElementFromHandle(hwnd) }
            .map_err(|_| TargetUnavailableReason::FocusIdentityUnavailable)?;
        let identity = unsafe { uia_runtime_id(&window) }?;
        let name = unsafe { window.CurrentName() }
            .ok()
            .map(|value| value.to_string())
            .filter(|value| !value.is_empty());
        let fingerprint = match unsafe { automation.GetFocusedElement() } {
            Ok(focused)
                if unsafe {
                    uia_focused_widget_in_window(&automation, &focused, &window, hwnd)
                } =>
            {
                match unsafe { uia_runtime_id(&focused) } {
                    Ok(focused_id) => {
                        let control_type = unsafe { focused.CurrentControlType() }
                            .ok()
                            .map(|value| value.0);
                        let password = match unsafe { focused.CurrentIsPassword() } {
                            Ok(value) => super::windows::UiaPasswordEvidence::from_query(
                                true,
                                value.as_bool(),
                            ),
                            Err(_) => super::windows::UiaPasswordEvidence::Unknown,
                        };
                        let (role, subrole) =
                            super::windows::uia_focused_widget_roles(control_type, password);
                        super::windows::UiaWidgetFingerprint::with_bound_widget(
                            identity, focused_id, role, subrole,
                        )
                    }
                    Err(_) => super::windows::UiaWidgetFingerprint::window_only(identity),
                }
            }
            _ => super::windows::UiaWidgetFingerprint::window_only(identity),
        };
        Ok(UiaCapture { fingerprint, name })
    })();
    if initialized {
        unsafe { CoUninitialize() };
    }
    evidence
}

/// True when `focused` is the foreground window or a descendant of it.
/// Unbound UIA focus (a different top-level window) must not contribute
/// ordinary-text roles to this snapshot.
unsafe fn uia_focused_widget_in_window(
    automation: &IUIAutomation,
    focused: &IUIAutomationElement,
    window: &IUIAutomationElement,
    hwnd: HWND,
) -> bool {
    if unsafe { uia_same_element(automation, focused, window) } {
        return true;
    }
    if unsafe { uia_native_handle_belongs_to_foreground(focused, hwnd) } {
        return true;
    }
    let Ok(walker) = (unsafe { automation.RawViewWalker() }) else {
        return false;
    };
    let mut current = focused.clone();
    for _ in 0..64 {
        let Ok(parent) = (unsafe { walker.GetParentElement(&current) }) else {
            break;
        };
        if unsafe { uia_same_element(automation, &parent, window) } {
            return true;
        }
        if unsafe { uia_native_handle_belongs_to_foreground(&parent, hwnd) } {
            return true;
        }
        current = parent;
    }
    false
}

unsafe fn uia_same_element(
    automation: &IUIAutomation,
    left: &IUIAutomationElement,
    right: &IUIAutomationElement,
) -> bool {
    unsafe { automation.CompareElements(left, right) }
        .ok()
        .is_some_and(|value| value.as_bool())
}

unsafe fn uia_native_handle_belongs_to_foreground(
    element: &IUIAutomationElement,
    foreground: HWND,
) -> bool {
    match unsafe { element.CurrentNativeWindowHandle() } {
        Ok(native) if !native.is_invalid() => unsafe {
            hwnd_belongs_to_foreground(native, foreground)
        },
        _ => false,
    }
}

unsafe fn hwnd_belongs_to_foreground(native: HWND, foreground: HWND) -> bool {
    let root = unsafe { GetAncestor(native, GA_ROOT) };
    super::windows::native_hwnd_belongs_to_foreground(
        native == foreground,
        unsafe { IsChild(foreground, native) }.as_bool(),
        !root.is_invalid() && root == foreground,
    )
}

/// UI Automation runtime IDs identify a live automation element, unlike an
/// HWND value which Windows can recycle after destruction. The array belongs
/// to the caller and is always destroyed after copying its bounded contents.
unsafe fn uia_runtime_id(
    element: &IUIAutomationElement,
) -> Result<[u8; 16], TargetUnavailableReason> {
    struct RuntimeIdArray(*mut windows::Win32::System::Com::SAFEARRAY);

    impl Drop for RuntimeIdArray {
        fn drop(&mut self) {
            // SAFETY: UI Automation transferred ownership of this SAFEARRAY.
            let _ = unsafe { SafeArrayDestroy(self.0) };
        }
    }

    let array = unsafe { element.GetRuntimeId() }
        .map_err(|_| TargetUnavailableReason::FocusIdentityUnavailable)?;
    if array.is_null() {
        return Err(TargetUnavailableReason::FocusIdentityUnavailable);
    }
    let array = RuntimeIdArray(array);
    let lower = unsafe { SafeArrayGetLBound(array.0, 1) }
        .map_err(|_| TargetUnavailableReason::FocusIdentityUnavailable)?;
    let upper = unsafe { SafeArrayGetUBound(array.0, 1) }
        .map_err(|_| TargetUnavailableReason::FocusIdentityUnavailable)?;
    let count = upper
        .checked_sub(lower)
        .and_then(|length| length.checked_add(1))
        .and_then(|length| usize::try_from(length).ok())
        .filter(|length| (1..=64).contains(length))
        .ok_or(TargetUnavailableReason::FocusIdentityUnavailable)?;
    let mut data = std::ptr::null_mut();
    unsafe { SafeArrayAccessData(array.0, &mut data) }
        .map_err(|_| TargetUnavailableReason::FocusIdentityUnavailable)?;
    if data.is_null() {
        let _ = unsafe { SafeArrayUnaccessData(array.0) };
        return Err(TargetUnavailableReason::FocusIdentityUnavailable);
    }
    // SAFETY: UI Automation documents runtime IDs as SAFEARRAY(VT_I4); the
    // bounds above constrain the copied slice before the array is unlocked.
    let values = unsafe { std::slice::from_raw_parts(data.cast::<i32>(), count) };
    let bytes = values
        .iter()
        .flat_map(|value| value.to_le_bytes())
        .collect::<Vec<_>>();
    unsafe { SafeArrayUnaccessData(array.0) }
        .map_err(|_| TargetUnavailableReason::FocusIdentityUnavailable)?;
    let digest = domain_hash(b"cockpit.windows.uia-runtime-id.v1", &[&bytes]);
    let mut identity = [0_u8; 16];
    identity.copy_from_slice(&digest[..16]);
    Ok(identity)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::computer::KeyCode;

    fn translated(key: &str) -> VirtualKeyInput {
        virtual_key(&NormalizedKeyCode::new(&KeyCode::parse(key).unwrap()).unwrap())
    }

    #[test]
    fn named_virtual_key_mapping_covers_approval_actions() {
        assert_eq!(translated("ctrl"), VirtualKeyInput::plain(VK_CONTROL));
        assert!(KeyCode::parse("not-a-key").is_err());
    }

    #[test]
    fn alphabetic_key_identity_is_case_insensitive_without_implicit_shift() {
        let lower = translated("a");
        let upper = translated("A");
        assert_eq!(lower, upper);
        assert_eq!(upper, VirtualKeyInput::plain(VIRTUAL_KEY(b'A' as u16)));
    }

    #[test]
    fn extended_navigation_keys_keep_the_extended_flag() {
        for key in [
            "delete", "up", "down", "left", "right", "pageup", "pagedown",
        ] {
            let input = translated(key);
            assert!(input.extended, "{key}");
            assert_eq!(key_event_flags(input, true).0, 3, "{key}");
        }
        assert!(!translated("enter").extended);
        assert!(KeyCode::parse("not-a-key").is_err());
    }

    #[test]
    fn gdi_capture_pixels_are_converted_to_opaque_rgba() {
        let mut pixels = [0x11, 0x22, 0x33, 0x00, 0x44, 0x55, 0x66, 0x7f];

        gdi_bgra_to_rgba_opaque(&mut pixels);

        assert_eq!(pixels, [0x33, 0x22, 0x11, 0xff, 0x66, 0x55, 0x44, 0xff]);
    }

    #[test]
    #[ignore = "drives the interactive Windows desktop; run manually with a stored grant"]
    fn real_desktop_capture_smoke() {
        let store = RealDesktopGrantStore::for_cockpit_data_dir().unwrap();
        let mut backend =
            WindowsDesktopBackend::construct(DisplayTarget::RealDesktop, Some(&store)).unwrap();
        let frame = futures::executor::block_on(super::super::execute_backend_action(
            &mut backend,
            &ComputerAction::CaptureFull,
        ))
        .unwrap();
        assert!(
            matches!(frame, ComputerActionOutcome::Captured(frame) if frame.png.starts_with(&[137, 80, 78, 71]))
        );
    }

    #[test]
    #[ignore = "queries the interactive Windows desktop and UI Automation"]
    fn target_evidence_smoke() {
        let mut adapter = WindowsTargetEvidenceAdapter::new().unwrap();
        let evidence = adapter.capture_snapshot().unwrap();
        assert_eq!(evidence.backend_kind, BackendKind::RealDesktopWindows);
        assert!(evidence.physical_target_key().is_ok());
        assert!(evidence.synchronous_recheck);
    }
}
