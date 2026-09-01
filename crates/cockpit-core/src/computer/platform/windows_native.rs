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
    EnumDisplayDevicesW, GetDC, GetDIBits, GetMonitorInfoW,
    HGDIOBJ, MONITOR_DEFAULTTONEAREST, MONITORINFOEXW, MonitorFromWindow, ReleaseDC, SRCCOPY,
    SelectObject,
};
use windows::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx, CoUninitialize,
};
use windows::Win32::System::StationsAndDesktops::{
    CloseDesktop, DESKTOP_CONTROL_FLAGS, DESKTOP_READOBJECTS, GetProcessWindowStation,
    GetThreadDesktop, GetUserObjectInformationW, OpenInputDesktop, UOI_NAME,
};
use windows::Win32::System::RemoteDesktop::ProcessIdToSessionId;
use windows::Win32::System::Threading::{
    GetCurrentProcessId, GetCurrentThreadId, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    QueryFullProcessImageNameW,
};
use windows::Win32::UI::Accessibility::{CUIAutomation, IUIAutomation};
use windows::Win32::UI::HiDpi::{GetDpiForSystem, GetDpiForWindow};
use windows::Win32::UI::Input::KeyboardAndMouse::*;
use windows::Win32::UI::WindowsAndMessaging::{
    EDD_GET_DEVICE_INTERFACE_NAME, GetClassNameW, GetCursorPos, GetForegroundWindow,
    GetSystemMetrics, GetWindowRect, GetWindowThreadProcessId, IsWindow, SM_CXVIRTUALSCREEN, SM_CYVIRTUALSCREEN,
    SM_XVIRTUALSCREEN, SM_YVIRTUALSCREEN,
};
use windows::core::{PCWSTR, PWSTR};

use crate::computer::host_identity::{
    RealHostIdentityFs, SysHostIdentityRng, domain_hash, load_or_create_host_installation_id,
};
use crate::computer::target::{
    BackendKind, EvidenceSource, FieldEvidence, FocusGenerationReducer, OpaqueWindowId,
    RedactedHint, StableApplicationId, TargetEvidenceAdapter, TargetGeometry,
    TargetIdentityEvidence, TargetUnavailableReason, empty_unavailable,
};
use crate::computer::{
    CaptureFrame, ClickCount, ComputerAction, ComputerActionOutcome, ComputerBackend, ComputerError,
    CoordinateSpace, DisplayGeometry, DisplayTarget, Easing, LogicalSize, Modifiers, MouseButton,
    PixelRect, PixelSize, Point, RealDesktopGrantStore, ScaleFactor, checked_action_duration,
    checked_rect, checked_scroll_delta,
};

#[derive(Debug)]
pub struct WindowsDesktopBackend {
    geometry: DisplayGeometry,
    origin_x: i32,
    origin_y: i32,
    held_keys: Vec<VIRTUAL_KEY>,
    held_buttons: Vec<MouseButton>,
}

impl WindowsDesktopBackend {
    pub fn construct(
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
        Ok(Self {
            geometry,
            origin_x,
            origin_y,
            held_keys: Vec::new(),
            held_buttons: Vec::new(),
        })
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
            .and_then(|w| usize::try_from(region.height).ok().and_then(|h| w.checked_mul(h)))
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
            for pixel in pixels.chunks_exact_mut(4) {
                pixel.swap(0, 2);
            }
            let image = image::RgbaImage::from_raw(region.width, region.height, pixels)
                .ok_or_else(|| win_input_error("GDI returned an invalid image buffer"))?;
            crate::media_image::encode_png_rgba(
                &image,
                &crate::media_image::ImageProfile::screenshot(),
            )
            .map_err(|error| win_input_error(error.to_string()))
        }
    }

    fn move_cursor(&self, point: Point) -> Result<(), ComputerError> {
        let (x, y) = checked_windows_point(point, &self.geometry)?;
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

#[async_trait]
impl ComputerBackend for WindowsDesktopBackend {
    fn backend_kind(&self) -> BackendKind {
        BackendKind::RealDesktopWindows
    }

    async fn geometry(&mut self) -> Result<DisplayGeometry, ComputerError> {
        self.refresh_geometry()?;
        Ok(self.geometry.clone())
    }

    async fn execute_one(
        &mut self,
        action: &ComputerAction,
    ) -> Result<ComputerActionOutcome, ComputerError> {
        match action {
            ComputerAction::CaptureFull => Ok(captured(self, None, None)?),
            ComputerAction::CaptureRegion { rect } => {
                let region = checked_rect(*rect, &self.geometry)?;
                Ok(captured(self, Some(region), None)?)
            }
            ComputerAction::CaptureNativeZoom { rect, scale } => {
                let region = checked_rect(*rect, &self.geometry)?;
                if !scale.0.is_finite() || scale.0 <= 0.0 {
                    return Err(win_input_error("native zoom scale must be positive"));
                }
                let png = self.capture(Some(region))?;
                let profile = crate::media_image::ImageProfile::screenshot();
                let decoded = crate::media_image::decode_and_orient(&png, &profile)
                    .map_err(|error| win_input_error(error.to_string()))?;
                let width = (f64::from(region.width) * scale.0).round() as u32;
                let height = (f64::from(region.height) * scale.0).round() as u32;
                if width == 0 || height == 0 {
                    return Err(win_input_error("native zoom produced zero geometry"));
                }
                let scaled = crate::media_image::scale(decoded, width, height, &profile);
                let png = crate::media_image::encode_png(&scaled, &profile)
                    .map_err(|error| win_input_error(error.to_string()))?;
                Ok(ComputerActionOutcome::Captured(CaptureFrame {
                    png,
                    geometry: self.geometry.clone(),
                    region: Some(region),
                    native_zoom: Some(*scale),
                }))
            }
            ComputerAction::MoveCursor { to, duration, easing } => {
                checked_action_duration(*duration)?;
                move_with_timing(self, *to, *duration, *easing)?;
                Ok(ComputerActionOutcome::Completed)
            }
            ComputerAction::Click { button, count, modifiers } => {
                send_modifiers(*modifiers, false)?;
                for _ in 0..click_count(*count) {
                    send_button(*button, false)?;
                    send_button(*button, true)?;
                }
                send_modifiers(*modifiers, true)?;
                Ok(ComputerActionOutcome::Completed)
            }
            ComputerAction::MouseDown { button } => {
                send_button(*button, false)?;
                if !self.held_buttons.contains(button) {
                    self.held_buttons.push(*button);
                }
                Ok(ComputerActionOutcome::Completed)
            }
            ComputerAction::MouseUp { button } => {
                send_button(*button, true)?;
                self.held_buttons.retain(|held| held != button);
                Ok(ComputerActionOutcome::Completed)
            }
            ComputerAction::Drag { button, path, modifiers } => {
                if path.is_empty() {
                    return Err(win_input_error("drag path must not be empty"));
                }
                for step in path { checked_action_duration(step.duration)?; }
                send_modifiers(*modifiers, false)?;
                move_with_timing(self, path[0].point, path[0].duration, path[0].easing)?;
                send_button(*button, false)?;
                self.held_buttons.push(*button);
                for step in &path[1..] {
                    move_with_timing(self, step.point, step.duration, step.easing)?;
                }
                send_button(*button, true)?;
                self.held_buttons.retain(|held| held != button);
                send_modifiers(*modifiers, true)?;
                Ok(ComputerActionOutcome::Completed)
            }
            ComputerAction::TypeText { text } => {
                for unit in text.encode_utf16() {
                    send_unicode(unit, false)?;
                    send_unicode(unit, true)?;
                }
                Ok(ComputerActionOutcome::Completed)
            }
            ComputerAction::KeyChord { chord } => {
                let keys = chord.keys.iter().map(|key| virtual_key(key)).collect::<Result<Vec<_>, _>>()?;
                for key in &keys { send_key(*key, false)?; }
                for key in keys.iter().rev() { send_key(*key, true)?; }
                Ok(ComputerActionOutcome::Completed)
            }
            ComputerAction::HoldKey { key, duration } => {
                checked_action_duration(*duration)?;
                let key = virtual_key(key)?;
                send_key(key, false)?;
                self.held_keys.push(key);
                thread::sleep(*duration);
                send_key(key, true)?;
                self.held_keys.retain(|held| *held != key);
                Ok(ComputerActionOutcome::Completed)
            }
            ComputerAction::Scroll { delta_x, delta_y, modifiers } => {
                checked_scroll_delta(*delta_x)?;
                checked_scroll_delta(*delta_y)?;
                send_modifiers(*modifiers, false)?;
                if *delta_y != 0 { send_mouse(0, 0, (*delta_y * 120) as u32, MOUSEEVENTF_WHEEL)?; }
                if *delta_x != 0 { send_mouse(0, 0, (*delta_x * 120) as u32, MOUSEEVENTF_HWHEEL)?; }
                send_modifiers(*modifiers, true)?;
                Ok(ComputerActionOutcome::Completed)
            }
            ComputerAction::Wait { duration } => {
                checked_action_duration(*duration)?;
                thread::sleep(*duration);
                Ok(ComputerActionOutcome::Waited(*duration))
            }
        }
    }

    fn release_all(&mut self) -> Result<(), ComputerError> {
        let mut first = None;
        for key in self.held_keys.drain(..).chain([VK_SHIFT, VK_CONTROL, VK_MENU, VK_LWIN]) {
            if let Err(error) = send_key(key, true) { first.get_or_insert(error); }
        }
        for button in self.held_buttons.drain(..).chain([MouseButton::Left, MouseButton::Right, MouseButton::Middle]) {
            if let Err(error) = send_button(button, true) { first.get_or_insert(error); }
        }
        first.map_or(Ok(()), Err)
    }
}

fn captured(backend: &WindowsDesktopBackend, region: Option<PixelRect>, zoom: Option<ScaleFactor>) -> Result<ComputerActionOutcome, ComputerError> {
    Ok(ComputerActionOutcome::Captured(CaptureFrame {
        png: backend.capture(region)?, geometry: backend.geometry.clone(), region, native_zoom: zoom,
    }))
}

fn query_geometry() -> Result<(DisplayGeometry, i32, i32), ComputerError> {
    // SAFETY: GetSystemMetrics/GetDpiForSystem take no pointers and have no lifetime contract.
    let (x, y, width, height, dpi) = unsafe {
        (GetSystemMetrics(SM_XVIRTUALSCREEN), GetSystemMetrics(SM_YVIRTUALSCREEN),
         GetSystemMetrics(SM_CXVIRTUALSCREEN), GetSystemMetrics(SM_CYVIRTUALSCREEN), GetDpiForSystem())
    };
    if width <= 0 || height <= 0 || dpi == 0 { return Err(win32_error("virtual desktop geometry")); }
    let scale = f64::from(dpi) / 96.0;
    Ok((DisplayGeometry {
        physical: PixelSize { width: width as u32, height: height as u32 },
        logical: LogicalSize { width: f64::from(width) / scale, height: f64::from(height) / scale },
        scale_factor: ScaleFactor(scale),
    }, x, y))
}

fn checked_windows_point(point: Point, geometry: &DisplayGeometry) -> Result<(u32, u32), ComputerError> {
    let (x, y) = match point.space {
        CoordinateSpace::Physical => (point.x, point.y),
        CoordinateSpace::Logical => (point.x * geometry.scale_factor.0, point.y * geometry.scale_factor.0),
    };
    if !x.is_finite() || !y.is_finite() || x < 0.0 || y < 0.0
        || x >= f64::from(geometry.physical.width) || y >= f64::from(geometry.physical.height) {
        return Err(win_input_error("point is outside the virtual desktop"));
    }
    Ok((x.round() as u32, y.round() as u32))
}

fn move_with_timing(backend: &WindowsDesktopBackend, point: Point, duration: Duration, easing: Easing) -> Result<(), ComputerError> {
    if duration.is_zero() { return backend.move_cursor(point); }
    let mut cursor = POINT::default();
    // SAFETY: `cursor` is valid writable storage for the duration of the call.
    unsafe { GetCursorPos(&mut cursor) }.map_err(|_| win32_error("GetCursorPos"))?;
    let start_x = f64::from(cursor.x - backend.origin_x);
    let start_y = f64::from(cursor.y - backend.origin_y);
    let steps = 12;
    for step in 1..=steps {
        let mut progress = f64::from(step) / f64::from(steps);
        if easing == Easing::EaseInOut { progress = if progress < 0.5 { 2.0 * progress * progress } else { 1.0 - (-2.0 * progress + 2.0).powi(2) / 2.0 }; }
        let (target_x, target_y) = match point.space {
            CoordinateSpace::Physical => (point.x, point.y),
            CoordinateSpace::Logical => (point.x * backend.geometry.scale_factor.0, point.y * backend.geometry.scale_factor.0),
        };
        backend.move_cursor(Point { x: start_x + (target_x - start_x) * progress, y: start_y + (target_y - start_y) * progress, space: CoordinateSpace::Physical })?;
        thread::sleep(duration / steps);
    }
    Ok(())
}

fn send(inputs: &[INPUT]) -> Result<(), ComputerError> {
    // SAFETY: INPUT is ABI-owned by the pinned windows binding; the slice stays live for the call.
    let sent = unsafe { SendInput(inputs, size_of::<INPUT>() as i32) };
    if sent == inputs.len() as u32 { Ok(()) } else { Err(win32_error("SendInput")) }
}

fn send_mouse(dx: i32, dy: i32, data: u32, flags: MOUSE_EVENT_FLAGS) -> Result<(), ComputerError> {
    send(&[INPUT { r#type: INPUT_MOUSE, Anonymous: INPUT_0 { mi: MOUSEINPUT { dx, dy, mouseData: data, dwFlags: flags, time: 0, dwExtraInfo: 0 } } }])
}

fn send_button(button: MouseButton, up: bool) -> Result<(), ComputerError> {
    let flags = match (button, up) {
        (MouseButton::Left, false) => MOUSEEVENTF_LEFTDOWN, (MouseButton::Left, true) => MOUSEEVENTF_LEFTUP,
        (MouseButton::Right, false) => MOUSEEVENTF_RIGHTDOWN, (MouseButton::Right, true) => MOUSEEVENTF_RIGHTUP,
        (MouseButton::Middle, false) => MOUSEEVENTF_MIDDLEDOWN, (MouseButton::Middle, true) => MOUSEEVENTF_MIDDLEUP,
    };
    send_mouse(0, 0, 0, flags)
}

fn send_key(key: VIRTUAL_KEY, up: bool) -> Result<(), ComputerError> {
    send(&[INPUT { r#type: INPUT_KEYBOARD, Anonymous: INPUT_0 { ki: KEYBDINPUT { wVk: key, wScan: 0, dwFlags: if up { KEYEVENTF_KEYUP } else { KEYBD_EVENT_FLAGS(0) }, time: 0, dwExtraInfo: 0 } } }])
}

fn send_unicode(unit: u16, up: bool) -> Result<(), ComputerError> {
    send(&[INPUT { r#type: INPUT_KEYBOARD, Anonymous: INPUT_0 { ki: KEYBDINPUT { wVk: VIRTUAL_KEY(0), wScan: unit, dwFlags: KEYEVENTF_UNICODE | if up { KEYEVENTF_KEYUP } else { KEYBD_EVENT_FLAGS(0) }, time: 0, dwExtraInfo: 0 } } }])
}

fn send_modifiers(modifiers: Modifiers, up: bool) -> Result<(), ComputerError> {
    let keys = [(modifiers.shift, VK_SHIFT), (modifiers.control, VK_CONTROL), (modifiers.alt, VK_MENU), (modifiers.meta, VK_LWIN)];
    let iter: Box<dyn Iterator<Item = &(bool, VIRTUAL_KEY)>> = if up { Box::new(keys.iter().rev()) } else { Box::new(keys.iter()) };
    for (enabled, key) in iter { if *enabled { send_key(*key, up)?; } }
    Ok(())
}

fn virtual_key(key: &str) -> Result<VIRTUAL_KEY, ComputerError> {
    let upper = key.to_ascii_uppercase();
    let vk = match upper.as_str() {
        "SHIFT" => VK_SHIFT, "CONTROL" | "CTRL" => VK_CONTROL, "ALT" => VK_MENU,
        "META" | "WIN" | "SUPER" => VK_LWIN, "ENTER" | "RETURN" => VK_RETURN,
        "TAB" => VK_TAB, "ESC" | "ESCAPE" => VK_ESCAPE, "BACKSPACE" => VK_BACK,
        "DELETE" => VK_DELETE, "SPACE" => VK_SPACE, "UP" => VK_UP, "DOWN" => VK_DOWN,
        "LEFT" => VK_LEFT, "RIGHT" => VK_RIGHT,
        _ if upper.len() == 1 => VIRTUAL_KEY(upper.as_bytes()[0] as u16),
        _ => return Err(win_input_error(format!("unsupported Windows key: {key}"))),
    };
    Ok(vk)
}

fn click_count(count: ClickCount) -> usize { match count { ClickCount::Single => 1, ClickCount::Double => 2, ClickCount::Triple => 3 } }
fn win32_error(operation: &str) -> ComputerError { win_input_error(format!("{operation}: {}", windows::core::Error::from_win32())) }
fn win_input_error(error: impl std::fmt::Display) -> ComputerError { ComputerError::CommandFailed { program: "windows computer backend".to_string(), detail: error.to_string() } }

#[derive(Debug)]
pub struct WindowsTargetEvidenceAdapter {
    host: crate::computer::host_identity::HostInstallationId,
    reducer: FocusGenerationReducer,
    observed_epoch: u64,
}

impl WindowsTargetEvidenceAdapter {
    pub fn new() -> Result<Self, TargetUnavailableReason> {
        let data_dir = crate::config::resolve::cockpit_data_dir().map_err(|_| TargetUnavailableReason::HostIdentityUnavailable)?;
        let host = load_or_create_host_installation_id(&data_dir, &mut SysHostIdentityRng, &mut RealHostIdentityFs)
            .map_err(|_| TargetUnavailableReason::HostIdentityUnavailable)?;
        Ok(Self { host, reducer: FocusGenerationReducer::new(), observed_epoch: 0 })
    }

    fn native_snapshot(&self) -> Result<TargetIdentityEvidence, TargetUnavailableReason> {
        // SAFETY: queried HWND is validated before use; output pointers refer to initialized locals.
        unsafe {
            let hwnd = GetForegroundWindow();
            if hwnd.is_invalid() || !IsWindow(Some(hwnd)).as_bool() { return Err(TargetUnavailableReason::FocusIdentityUnavailable); }
            let mut pid = 0_u32;
            GetWindowThreadProcessId(hwnd, Some(&mut pid));
            if pid == 0 { return Err(TargetUnavailableReason::FocusIdentityUnavailable); }
            let mut rect = RECT::default();
            GetWindowRect(hwnd, &mut rect).map_err(|_| TargetUnavailableReason::FocusIdentityUnavailable)?;
            let mut class = [0_u16; 256];
            let class_len = GetClassNameW(hwnd, &mut class);
            let class = (class_len > 0).then(|| String::from_utf16_lossy(&class[..class_len as usize]));
            let dpi = GetDpiForWindow(hwnd).max(96);
            let mut session = 0_u32;
            ProcessIdToSessionId(GetCurrentProcessId(), &mut session).map_err(|_| TargetUnavailableReason::SessionInactive)?;
            if session == 0 { return Err(TargetUnavailableReason::SessionInactive); }
            let desktop = query_geometry().map_err(|_| TargetUnavailableReason::MissingCapability)?;
            let (station_name, desktop_name) = session_desktop_names()?;
            let session_id = domain_hash(b"cockpit.windows.session.v1", &[
                &session.to_le_bytes(), station_name.as_bytes(), desktop_name.as_bytes(),
            ]);
            let display_id = monitor_identity(hwnd)?;
            let mut window_id = [0_u8; 16];
            window_id[..size_of::<isize>()].copy_from_slice(&hwnd.0.to_le_bytes());
            let (uia_role, uia_name) = uia_evidence(hwnd);
            let mut snapshot = empty_unavailable(BackendKind::RealDesktopWindows);
            snapshot.host_installation_id = FieldEvidence::available(self.host, EvidenceSource::WinSessionDesktop);
            snapshot.platform_session_or_seat_id = FieldEvidence::available(session_id, EvidenceSource::WinSessionDesktop);
            snapshot.physical_display_id = FieldEvidence::available(display_id, EvidenceSource::WinMonitor);
            snapshot.focused_window_id = FieldEvidence::available(OpaqueWindowId::from_bytes(window_id), EvidenceSource::WinForeground);
            snapshot.process_id = FieldEvidence::available(pid, EvidenceSource::WinForeground);
            snapshot.stable_application_id = process_image_name(pid).map_or_else(
                || FieldEvidence::unavailable(TargetUnavailableReason::PartialEvidence, Some(EvidenceSource::WinForeground)),
                |image| FieldEvidence::available(StableApplicationId { kind: "win32.image", value: image }, EvidenceSource::WinForeground));
            snapshot.accessibility_role = uia_role.map_or_else(
                || FieldEvidence::unavailable(TargetUnavailableReason::PartialEvidence, Some(EvidenceSource::Accessibility)),
                |role| FieldEvidence::available(role, EvidenceSource::Accessibility));
            // TODO(a11y perception): UIA remains approval evidence only; pixel capture drives perception and targeting.
            snapshot.accessibility_subrole = FieldEvidence::unavailable(TargetUnavailableReason::PartialEvidence, Some(EvidenceSource::Accessibility));
            snapshot.title_hint = uia_name.map_or_else(
                || FieldEvidence::unavailable(TargetUnavailableReason::PartialEvidence, Some(EvidenceSource::Accessibility)),
                |name| FieldEvidence::available(RedactedHint::from_raw(&name), EvidenceSource::Accessibility));
            snapshot.class_hint = class.map_or_else(
                || FieldEvidence::unavailable(TargetUnavailableReason::PartialEvidence, Some(EvidenceSource::WinForeground)),
                |class| FieldEvidence::available(RedactedHint::from_raw(&class), EvidenceSource::WinForeground));
            snapshot.geometry = FieldEvidence::available(TargetGeometry { x: rect.left, y: rect.top, width: (rect.right - rect.left).max(0) as u32, height: (rect.bottom - rect.top).max(0) as u32, scale: f64::from(dpi) / 96.0 }, EvidenceSource::WinForeground);
            snapshot.desktop_geometry = FieldEvidence::available(TargetGeometry { x: desktop.1, y: desktop.2, width: desktop.0.physical.width, height: desktop.0.physical.height, scale: desktop.0.scale_factor.0 }, EvidenceSource::WinMonitor);
            snapshot.synchronous_recheck = GetForegroundWindow() == hwnd && IsWindow(Some(hwnd)).as_bool();
            if !snapshot.synchronous_recheck { return Err(TargetUnavailableReason::QueryMismatch); }
            Ok(snapshot)
        }
    }
}

unsafe fn user_object_name(handle: HANDLE) -> Result<String, TargetUnavailableReason> {
    let mut needed = 0_u32;
    let _ = unsafe { GetUserObjectInformationW(handle, UOI_NAME, None, 0, Some(&mut needed)) };
    if needed < 2 { return Err(TargetUnavailableReason::SessionInactive); }
    let mut buffer = vec![0_u16; (needed as usize).div_ceil(2)];
    unsafe { GetUserObjectInformationW(handle, UOI_NAME, Some(buffer.as_mut_ptr().cast()), needed, Some(&mut needed)) }
        .map_err(|_| TargetUnavailableReason::SessionInactive)?;
    let end = buffer.iter().position(|unit| *unit == 0).unwrap_or(buffer.len());
    let name = String::from_utf16_lossy(&buffer[..end]);
    if name.is_empty() { Err(TargetUnavailableReason::SessionInactive) } else { Ok(name) }
}

unsafe fn session_desktop_names() -> Result<(String, String), TargetUnavailableReason> {
    let station = unsafe { GetProcessWindowStation() }.map_err(|_| TargetUnavailableReason::SessionInactive)?;
    let thread_desktop = unsafe { GetThreadDesktop(GetCurrentThreadId()) }.map_err(|_| TargetUnavailableReason::SessionInactive)?;
    let input_desktop = unsafe { OpenInputDesktop(DESKTOP_CONTROL_FLAGS(0), false, DESKTOP_READOBJECTS) }
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

unsafe fn monitor_identity(hwnd: HWND) -> Result<[u8; 32], TargetUnavailableReason> {
    let monitor = unsafe { MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST) };
    if monitor.is_invalid() { return Err(TargetUnavailableReason::AmbiguousOutput); }
    let mut info = MONITORINFOEXW::default();
    info.monitorInfo.cbSize = size_of::<MONITORINFOEXW>() as u32;
    if !unsafe { GetMonitorInfoW(monitor, (&mut info as *mut MONITORINFOEXW).cast()) }.as_bool() {
        return Err(TargetUnavailableReason::MissingCapability);
    }
    let device_name = wide_array(&info.szDevice).ok_or(TargetUnavailableReason::MissingCapability)?;
    let mut adapter = None;
    for index in 0..64 {
        let mut candidate = DISPLAY_DEVICEW { cb: size_of::<DISPLAY_DEVICEW>() as u32, ..Default::default() };
        if !unsafe { EnumDisplayDevicesW(PCWSTR::null(), index, &mut candidate, EDD_GET_DEVICE_INTERFACE_NAME) }.as_bool() {
            break;
        }
        if wide_array(&candidate.DeviceName).as_deref() == Some(device_name.as_str()) {
            adapter = Some(candidate);
            break;
        }
    }
    let adapter = adapter.ok_or(TargetUnavailableReason::MissingCapability)?;
    let adapter_id = wide_array(&adapter.DeviceID).ok_or(TargetUnavailableReason::MissingCapability)?;
    let mut display = DISPLAY_DEVICEW { cb: size_of::<DISPLAY_DEVICEW>() as u32, ..Default::default() };
    if !unsafe { EnumDisplayDevicesW(PCWSTR(adapter.DeviceName.as_ptr()), 0, &mut display, EDD_GET_DEVICE_INTERFACE_NAME) }.as_bool() {
        return Err(TargetUnavailableReason::MissingCapability);
    }
    let display_id = wide_array(&display.DeviceID).ok_or(TargetUnavailableReason::MissingCapability)?;
    Ok(domain_hash(b"cockpit.windows.monitor.v1", &[device_name.as_bytes(), adapter_id.as_bytes(), display_id.as_bytes()]))
}

fn wide_array<const N: usize>(value: &[u16; N]) -> Option<String> {
    let end = value.iter().position(|unit| *unit == 0).unwrap_or(N);
    (end > 0).then(|| String::from_utf16_lossy(&value[..end]))
}

unsafe fn process_image_name(pid: u32) -> Option<String> {
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok()?;
    let mut buffer = vec![0_u16; 32_768];
    let mut len = buffer.len() as u32;
    let result = unsafe { QueryFullProcessImageNameW(process, Default::default(), PWSTR(buffer.as_mut_ptr()), &mut len) };
    let _ = unsafe { CloseHandle(process) };
    result.ok()?;
    std::path::Path::new(&String::from_utf16_lossy(&buffer[..len as usize]))
        .file_name().map(|name| name.to_string_lossy().into_owned())
}

impl TargetEvidenceAdapter for WindowsTargetEvidenceAdapter {
    fn backend_kind(&self) -> BackendKind { BackendKind::RealDesktopWindows }
    fn capture_snapshot(&mut self) -> Result<TargetIdentityEvidence, TargetUnavailableReason> {
        let mut snapshot = self.native_snapshot()?;
        self.observed_epoch = self.observed_epoch.checked_add(1).ok_or(TargetUnavailableReason::EpochOverflow)?;
        snapshot.adapter_observed_epoch = self.observed_epoch;
        snapshot.focus_generation = self.reducer.observe(&snapshot)?;
        Ok(snapshot)
    }
    fn observed_focus_epoch(&self) -> u64 { self.observed_epoch }
}

unsafe fn uia_evidence(hwnd: HWND) -> (Option<String>, Option<String>) {
    let initialized = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) }.is_ok();
    let evidence = (|| {
        let automation: IUIAutomation = unsafe { CoCreateInstance(&CUIAutomation, None, CLSCTX_INPROC_SERVER) }.ok()?;
        let element = unsafe { automation.ElementFromHandle(hwnd) }.ok()?;
        let role = unsafe { element.CurrentControlType() }.ok().map(|value| format!("uia.control_type.{}", value.0));
        let name = unsafe { element.CurrentName() }.ok().map(|value| value.to_string()).filter(|value| !value.is_empty());
        Some((role, name))
    })().unwrap_or((None, None));
    if initialized { unsafe { CoUninitialize() }; }
    evidence
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn virtual_key_mapping_covers_approval_actions() {
        assert_eq!(virtual_key("ctrl").unwrap(), VK_CONTROL);
        assert_eq!(virtual_key("A").unwrap(), VIRTUAL_KEY(b'A' as u16));
        assert!(virtual_key("not-a-key").is_err());
    }

    #[test]
    #[ignore = "drives the interactive Windows desktop; run manually with a stored grant"]
    fn real_desktop_capture_smoke() {
        let store = RealDesktopGrantStore::for_cockpit_data_dir().unwrap();
        let mut backend = WindowsDesktopBackend::construct(DisplayTarget::RealDesktop, Some(&store)).unwrap();
        let frame = futures::executor::block_on(backend.execute_one(&ComputerAction::CaptureFull)).unwrap();
        assert!(matches!(frame, ComputerActionOutcome::Captured(frame) if frame.png.starts_with(&[137, 80, 78, 71])));
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
