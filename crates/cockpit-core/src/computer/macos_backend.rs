//! macOS physical-desktop capture and CGEvent input backend.
//!
//! Perception remains pixel-based. Accessibility is queried separately by the
//! target-evidence adapter and is never used to choose action coordinates.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use async_trait::async_trait;
use objc2_core_foundation::CGPoint;
use objc2_core_graphics::{
    CGDisplayBounds, CGDisplayCopyDisplayMode, CGDisplayMode, CGEvent, CGEventField, CGEventFlags,
    CGEventSource, CGEventSourceStateID, CGEventType, CGMainDisplayID, CGMouseButton,
    CGPreflightPostEventAccess, CGPreflightScreenCaptureAccess, CGScrollEventUnit,
};

use super::{
    CANNOT_DIRECT_INPUT_TO_EVIDENCED_WINDOW, CaptureFrame, ComputerActionOutcome, ComputerBackend,
    ComputerError, DisplayGeometry, DisplayTarget, EVIDENCED_WINDOW_MISMATCH, Easing, Modifiers,
    MouseButton, NormalizedComputerAction, NormalizedComputerEffect, PixelPoint, PixelRect,
    PixelSize, RealDesktopGrantStore, SYNTHETIC_INPUT_REQUIRES_EVIDENCED_WINDOW, ScaleFactor,
    click_repetitions, eased_progress, scale_png,
};
use crate::computer::platform::{
    MacAddressedInjection, MacFocusedWindowWitness, MacLiveFocusedWindow, MacosAxDeliveryError,
    MacosAxWindowDelivery, address_macos_injection_window, ax_window_element_is_live,
    deliver_to_authenticated_ax_window, live_focused_macos_injection_target,
    macos_injection_target_from_opaque, macos_window_identity_from_opaque,
    restore_macos_injection_target,
};
use crate::computer::target::{BackendKind, OpaqueWindowId};

const SCREENCAPTURE: &str = "/usr/sbin/screencapture";
const MOVE_STEPS: u32 = 12;
const HOST_INPUT_AUTHORITY: &str = "/Users/Shared/.flycockpit-input-authority-v1.json";

/// Physical macOS desktop backend. Construction performs both TCC preflights;
/// it never opens a usable backend when Screen Recording or Accessibility /
/// Input Monitoring access is absent.
pub(super) struct MacOsComputerBackend {
    source: objc2_core_foundation::CFRetained<CGEventSource>,
    geometry: DisplayGeometry,
    active_console_session: super::platform::MacActiveConsoleSession,
    outstanding_keys: HashSet<u16>,
    outstanding_buttons: HashSet<MouseButton>,
    physical_capability: Option<super::coordinator::PhysicalDispatchCapability>,
    input_authority: MacHostInputAuthority,
    evidenced_window: Option<EvidencedMacWindow>,
    cleanup_window: Option<OpaqueWindowId>,
}

#[derive(Debug, Clone)]
struct EvidencedMacWindow {
    opaque: OpaqueWindowId,
    pid: u32,
    window_number: u32,
    ax: MacFocusedWindowWitness,
}

// CoreGraphics' immutable event source is safe to retain behind the backend's
// unique `&mut self` dispatch seam. objc2 conservatively does not mark every CF
// wrapper Send/Sync, while the native CGEventSourceRef is thread-safe.
unsafe impl Send for MacOsComputerBackend {}
unsafe impl Sync for MacOsComputerBackend {}

#[cfg(not(test))]
impl super::backend_seal::Sealed for MacOsComputerBackend {}

impl MacOsComputerBackend {
    pub(super) fn construct(
        target: DisplayTarget,
        grant_store: Option<&RealDesktopGrantStore>,
    ) -> Result<Self, ComputerError> {
        if target != DisplayTarget::RealDesktop {
            return Err(ComputerError::UnsupportedPlatform {
                platform: "macos-virtual-display".to_string(),
            });
        }
        if !grant_store.is_some_and(RealDesktopGrantStore::has_current_machine_grant) {
            return Err(ComputerError::RealDesktopGrantMissing);
        }
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
        let active_console_session =
            super::platform::MacActiveConsoleSession::capture().map_err(|_| {
                ComputerError::Refused(
                    "a stable active macOS console session is required".to_string(),
                )
            })?;
        let input_authority = MacHostInputAuthority::open(&active_console_session)?;
        let cleanup_window = input_authority
            .state
            .window
            .map(crate::computer::target::OpaqueWindowId::from_bytes);
        Ok(Self {
            source,
            geometry: query_geometry()?,
            active_console_session,
            physical_capability: None,
            outstanding_keys: input_authority.state.keys.iter().copied().collect(),
            outstanding_buttons: input_authority.state.buttons.iter().copied().collect(),
            input_authority,
            evidenced_window: None,
            cleanup_window,
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
        &mut self,
        event_type: CGEventType,
        button: MouseButton,
        point: CGPoint,
        flags: CGEventFlags,
        click_state: i64,
        require_live_window: bool,
    ) -> Result<(), ComputerError> {
        let event =
            CGEvent::new_mouse_event(Some(&self.source), event_type, point, cg_button(button))
                .ok_or_else(|| cg_null("CGEventCreateMouseEvent"))?;
        CGEvent::set_flags(Some(&event), flags);
        if click_state > 0 {
            CGEvent::set_integer_value_field(
                Some(&event),
                CGEventField::MouseEventClickState,
                click_state,
            );
        }
        self.post_event(
            &event,
            match event_type {
                CGEventType::LeftMouseDown
                | CGEventType::RightMouseDown
                | CGEventType::OtherMouseDown => Some(InputTransition::ButtonDown(button)),
                CGEventType::LeftMouseUp
                | CGEventType::RightMouseUp
                | CGEventType::OtherMouseUp => Some(InputTransition::ButtonUp(button)),
                _ => None,
            },
            require_live_window,
        )
    }

    fn cursor(&self) -> Result<CGPoint, ComputerError> {
        let event = CGEvent::new(Some(&self.source)).ok_or_else(|| cg_null("CGEventCreate"))?;
        Ok(CGEvent::location(Some(&event)))
    }

    fn move_cursor(
        &mut self,
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
                true,
            )?;
            if !delay.is_zero() {
                std::thread::sleep(delay);
            }
        }
        Ok(())
    }

    fn post_key(
        &mut self,
        code: u16,
        down: bool,
        flags: CGEventFlags,
        require_live_window: bool,
    ) -> Result<(), ComputerError> {
        let event = CGEvent::new_keyboard_event(Some(&self.source), code, down)
            .ok_or_else(|| cg_null("CGEventCreateKeyboardEvent"))?;
        CGEvent::set_flags(Some(&event), flags);
        self.post_event(
            &event,
            Some(if down {
                InputTransition::KeyDown(code)
            } else {
                InputTransition::KeyUp(code)
            }),
            require_live_window,
        )
    }

    fn type_text(&mut self, text: &str) -> Result<(), ComputerError> {
        // CoreGraphics accepts UTF-16 payloads. Chunking avoids undocumented
        // event-size limits while preserving surrogate pairs.
        for chunk in utf16_chunks(text) {
            let down = CGEvent::new_keyboard_event(Some(&self.source), 0, true)
                .ok_or_else(|| cg_null("CGEventCreateKeyboardEvent"))?;
            // `UniCharCount` is the C `unsigned long` (u64 on LP64 macOS);
            // a bounded UTF-16 chunk length always fits it.
            let string_length =
                u64::try_from(chunk.len()).expect("bounded UTF-16 chunk length fits UniCharCount");
            // SAFETY: `chunk` is alive for the call and supplies exactly
            // `string_length` initialized UniChar values.
            unsafe {
                CGEvent::keyboard_set_unicode_string(Some(&down), string_length, chunk.as_ptr());
            }
            self.post_event(&down, Some(InputTransition::KeyDown(0)), true)?;
            let up = CGEvent::new_keyboard_event(Some(&self.source), 0, false)
                .ok_or_else(|| cg_null("CGEventCreateKeyboardEvent"))?;
            self.post_event(&up, Some(InputTransition::KeyUp(0)), true)?;
        }
        Ok(())
    }

    fn require_evidenced_window(&self) -> Result<EvidencedMacWindow, ComputerError> {
        self.evidenced_window.clone().ok_or_else(|| {
            ComputerError::Refused(SYNTHETIC_INPUT_REQUIRES_EVIDENCED_WINDOW.to_string())
        })
    }

    fn held_input_window_bytes(&self) -> Option<[u8; 16]> {
        self.evidenced_window
            .as_ref()
            .map(|window| *window.opaque.as_bytes())
            .or_else(|| self.cleanup_window.map(|window| *window.as_bytes()))
    }

    fn require_live_injection_window(&self) -> Result<EvidencedMacWindow, ComputerError> {
        let bound = self.require_evidenced_window()?;
        let live = live_focused_macos_injection_target()
            .map_err(|_| ComputerError::Refused(EVIDENCED_WINDOW_MISMATCH.to_string()))?;
        if live.window
            != (MacLiveFocusedWindow {
                pid: bound.pid,
                window_number: bound.window_number,
            })
            || !bound.ax.same_element(live.ax.element())
        {
            return Err(ComputerError::Refused(
                EVIDENCED_WINDOW_MISMATCH.to_string(),
            ));
        }
        address_macos_injection_window(&bound.ax, &bound.opaque)
            .map_err(|_| ComputerError::Refused(EVIDENCED_WINDOW_MISMATCH.to_string()))?;
        Ok(bound)
    }

    fn require_cleanup_injection_window(&self) -> Result<EvidencedMacWindow, ComputerError> {
        if let Some(bound) = self.evidenced_window.clone() {
            if ax_window_element_is_live(bound.ax.element()) {
                return Ok(bound);
            }
        }
        let opaque = self.cleanup_window.ok_or_else(|| {
            ComputerError::Refused(SYNTHETIC_INPUT_REQUIRES_EVIDENCED_WINDOW.to_string())
        })?;
        let live = restore_macos_injection_target(&opaque)
            .map_err(|_| ComputerError::Refused(EVIDENCED_WINDOW_MISMATCH.to_string()))?;
        Ok(EvidencedMacWindow {
            opaque,
            pid: live.window.pid,
            window_number: live.window.window_number,
            ax: live.ax,
        })
    }

    fn execute_action(
        &mut self,
        action: &NormalizedComputerAction,
    ) -> Result<ComputerActionOutcome, ComputerError> {
        if action.effect().injects_synthetic_input() {
            self.require_evidenced_window()?;
        }
        match action.effect() {
            NormalizedComputerEffect::CaptureFull => {
                Ok(ComputerActionOutcome::Captured(CaptureFrame {
                    png: self.capture_png(None)?,
                    geometry: self.geometry.clone(),
                    region: None,
                    native_zoom: None,
                }))
            }
            NormalizedComputerEffect::CaptureRegion { rect } => {
                Ok(ComputerActionOutcome::Captured(CaptureFrame {
                    png: self.capture_png(Some(*rect))?,
                    geometry: self.geometry.clone(),
                    region: Some(*rect),
                    native_zoom: None,
                }))
            }
            NormalizedComputerEffect::CaptureNativeZoom {
                rect,
                scale,
                output,
            } => Ok(ComputerActionOutcome::Captured(CaptureFrame {
                png: scale_png(self.capture_png(Some(*rect))?, *output)?,
                geometry: self.geometry.clone(),
                region: Some(*rect),
                native_zoom: Some(*scale),
            })),
            NormalizedComputerEffect::MoveCursor {
                to,
                duration,
                easing,
            } => {
                self.move_cursor(*to, *duration, *easing, None)?;
                Ok(ComputerActionOutcome::Completed)
            }
            NormalizedComputerEffect::Click {
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
                        true,
                    )?;
                    self.post_mouse(
                        mouse_up_type(*button),
                        *button,
                        point,
                        flags,
                        i64::from(click),
                        true,
                    )?;
                }
                Ok(ComputerActionOutcome::Completed)
            }
            NormalizedComputerEffect::MouseDown { button } => {
                self.post_mouse(
                    mouse_down_type(*button),
                    *button,
                    self.cursor()?,
                    CGEventFlags::empty(),
                    1,
                    true,
                )?;
                Ok(ComputerActionOutcome::Completed)
            }
            NormalizedComputerEffect::MouseUp { button } => {
                self.post_mouse(
                    mouse_up_type(*button),
                    *button,
                    self.cursor()?,
                    CGEventFlags::empty(),
                    1,
                    true,
                )?;
                Ok(ComputerActionOutcome::Completed)
            }
            NormalizedComputerEffect::Drag {
                button,
                path,
                modifiers,
            } => {
                let first = path[0];
                self.move_cursor(first.point, first.duration, first.easing, None)?;
                let flags = modifier_flags(*modifiers);
                self.post_mouse(
                    mouse_down_type(*button),
                    *button,
                    self.cursor()?,
                    flags,
                    1,
                    true,
                )?;
                for step in path.iter().skip(1) {
                    self.move_cursor(step.point, step.duration, step.easing, Some(*button))?;
                }
                self.post_mouse(
                    mouse_up_type(*button),
                    *button,
                    self.cursor()?,
                    flags,
                    1,
                    true,
                )?;
                Ok(ComputerActionOutcome::Completed)
            }
            NormalizedComputerEffect::TypeText { text } => {
                self.type_text(text)?;
                Ok(ComputerActionOutcome::Completed)
            }
            NormalizedComputerEffect::KeyChord { chord } => {
                let mut codes = Vec::with_capacity(chord.keys().len());
                for key in chord.keys() {
                    codes.push(key.macos_key_code().ok_or_else(|| {
                        ComputerError::Refused("unsupported macOS key identity".to_string())
                    })?);
                }
                let flags = flags_for_macos_key_codes(&codes);
                for code in &codes {
                    self.post_key(*code, true, flags, true)?;
                }
                for code in codes.iter().rev() {
                    self.post_key(*code, false, flags, true)?;
                }
                Ok(ComputerActionOutcome::Completed)
            }
            NormalizedComputerEffect::HoldKey { key, duration } => {
                let code = key.macos_key_code().ok_or_else(|| {
                    ComputerError::Refused("unsupported macOS key identity".to_string())
                })?;
                self.post_key(code, true, flags_for_macos_key_codes(&[code]), true)?;
                std::thread::sleep(*duration);
                self.post_key(code, false, CGEventFlags::empty(), true)?;
                Ok(ComputerActionOutcome::Completed)
            }
            NormalizedComputerEffect::Scroll {
                delta_x,
                delta_y,
                modifiers,
            } => {
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
                self.post_event(&event, None, true)?;
                Ok(ComputerActionOutcome::Completed)
            }
            NormalizedComputerEffect::Wait { duration } => {
                std::thread::sleep(*duration);
                Ok(ComputerActionOutcome::Waited(*duration))
            }
        }
    }

    /// Sole irreversible CoreGraphics post primitive. Every event, including
    /// cleanup releases, must pass the retained active-console-session rebound
    /// and then be addressed through the retained AX window object.
    /// [`deliver_to_authenticated_ax_window`] is the object-identity fence.
    fn post_event(
        &mut self,
        event: &CGEvent,
        transition: Option<InputTransition>,
        require_live_window: bool,
    ) -> Result<(), ComputerError> {
        let prepared = transition
            .map(|transition| self.input_authority.prepare(transition))
            .transpose()?;

        // `prepare` is the final blocking pre-post operation: it durably marks
        // ownership uncertain before a down/up transition can reach the host.
        // Rebind both retained identities after that write, at the last
        // reversible boundary. Do not insert fallible or blocking work between
        // these checks and the irreversible post.
        if self.active_console_session.recheck().is_err() {
            return self.rollback_known_pre_post_refusal(
                prepared,
                ComputerError::Refused(
                    "macOS active console session changed before CGEvent post".to_string(),
                ),
            );
        }
        let capability_check = match self.physical_capability.as_ref() {
            Some(capability) => capability.recheck(BackendKind::RealDesktopMacOs),
            None => Err(ComputerError::Refused(
                "macOS physical backend is not coordinator-bound".into(),
            )),
        };
        if let Err(error) = capability_check {
            return self.rollback_known_pre_post_refusal(prepared, error);
        }
        let bound = if require_live_window {
            match self.require_live_injection_window() {
                Ok(bound) => bound,
                Err(error) => return self.rollback_known_pre_post_refusal(prepared, error),
            }
        } else {
            match self.require_cleanup_injection_window() {
                Ok(bound) => bound,
                Err(error) => return self.rollback_known_pre_post_refusal(prepared, error),
            }
        };
        let mut delivery = LiveAxDelivery {
            event,
            witness: &bound.ax,
            opaque: &bound.opaque,
        };
        match deliver_to_authenticated_ax_window(&mut delivery, bound.opaque) {
            Ok(()) => {}
            Err(MacosAxDeliveryError::AmbiguousDelivery) => {
                return Err(ambiguous_ax_delivery());
            }
            Err(MacosAxDeliveryError::MissingWindowLocationSetter) => {
                return self.rollback_known_pre_post_refusal(
                    prepared,
                    ComputerError::Refused(CANNOT_DIRECT_INPUT_TO_EVIDENCED_WINDOW.to_string()),
                );
            }
            Err(_) => {
                return self.rollback_known_pre_post_refusal(
                    prepared,
                    ComputerError::Refused(EVIDENCED_WINDOW_MISMATCH.to_string()),
                );
            }
        }

        // From the post onward this backend owns the transition even if the
        // commit write fails. Update process-local cleanup ownership first;
        // a failed commit deliberately leaves the durable record pending so a
        // later process cannot guess whether the event reached the host.
        match transition {
            Some(InputTransition::KeyDown(code)) => {
                self.outstanding_keys.insert(code);
            }
            Some(InputTransition::KeyUp(code)) => {
                self.outstanding_keys.remove(&code);
            }
            Some(InputTransition::ButtonDown(button)) => {
                self.outstanding_buttons.insert(button);
            }
            Some(InputTransition::ButtonUp(button)) => {
                self.outstanding_buttons.remove(&button);
            }
            None => {}
        }
        if transition.is_some() {
            self.input_authority.commit(
                &self.outstanding_keys,
                &self.outstanding_buttons,
                self.held_input_window_bytes(),
            )?;
        }
        let identity_after = if require_live_window {
            self.require_live_injection_window()
        } else {
            self.require_cleanup_injection_window()
        };
        identity_after.map(|_| ())
    }

    /// A refusal before the raw post is a known non-effect. Restore the exact
    /// authority snapshot that existed before `prepare`; only failures after
    /// the post (or a failed rollback write) remain fail-closed as ambiguous.
    fn rollback_known_pre_post_refusal(
        &mut self,
        prepared: Option<MacHostInputState>,
        refusal: ComputerError,
    ) -> Result<(), ComputerError> {
        if let Some(previous) = prepared {
            self.input_authority
                .rollback(previous)
                .map_err(|rollback| {
                    ComputerError::Refused(format!(
                        "{refusal}; exact pre-post authority rollback failed: {rollback}"
                    ))
                })?;
        }
        Err(refusal)
    }
}

#[derive(Debug, Clone, Copy)]
enum InputTransition {
    KeyDown(u16),
    KeyUp(u16),
    ButtonDown(MouseButton),
    ButtonUp(MouseButton),
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct MacHostInputState {
    version: u32,
    owner_uid: u32,
    console_set: u32,
    audit_session_id: u32,
    pending: bool,
    keys: Vec<u16>,
    buttons: Vec<MouseButton>,
    /// Opaque window identity that received the matching downs. Cleanup must
    /// address this object; a missing identity with leftover keys fails closed.
    #[serde(default)]
    window: Option<[u8; 16]>,
}

/// Protected host-wide authority for exact Cockpit-owned down transitions.
/// The first active user exclusively creates this file beneath a root-owned
/// sticky directory with mode 0600. If another login user, a crash-torn
/// transition, malformed data, or missing authority makes ownership
/// unknowable, physical construction fails closed.
#[derive(Debug)]
struct MacHostInputAuthority {
    path: PathBuf,
    state: MacHostInputState,
}

impl MacHostInputAuthority {
    fn open(session: &super::platform::MacActiveConsoleSession) -> Result<Self, ComputerError> {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        let path = PathBuf::from(HOST_INPUT_AUTHORITY);
        let parent = path
            .parent()
            .ok_or_else(|| authority_unavailable("authority path has no parent"))?;
        let mut parent_options = std::fs::OpenOptions::new();
        parent_options
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
        let parent_file = parent_options.open(parent).map_err(authority_unavailable)?;
        let parent_meta = parent_file.metadata().map_err(authority_unavailable)?;
        let parent_mode = parent_meta.mode();
        let protected_parent = parent_meta.is_dir()
            && parent_meta.uid() == 0
            && (parent_mode & 0o022 == 0
                || (parent_mode & libc::S_ISVTX as u32 != 0 && parent_mode & 0o002 != 0));
        if !protected_parent {
            return Err(authority_unavailable(
                "authority parent is neither root-owned non-writable nor root-owned sticky",
            ));
        }
        let (owner_uid, console_set, audit_session_id) =
            session.identity().map_err(authority_unavailable)?;
        if !path.exists() {
            let initial = MacHostInputState {
                version: 1,
                owner_uid,
                console_set,
                audit_session_id,
                pending: false,
                keys: Vec::new(),
                buttons: Vec::new(),
                window: None,
            };
            let bytes = serde_json::to_vec(&initial).map_err(authority_unavailable)?;
            let mut create = std::fs::OpenOptions::new();
            create
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
            match create.open(&path) {
                Ok(mut file) => {
                    use std::io::Write as _;
                    file.write_all(&bytes).map_err(authority_unavailable)?;
                    file.sync_all().map_err(authority_unavailable)?;
                    parent_file.sync_all().map_err(authority_unavailable)?;
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(authority_unavailable(error)),
            }
        }
        let euid = u32::try_from(unsafe { libc::geteuid() }).map_err(authority_unavailable)?;
        let mut file = open_validated_authority_file(&path, euid)?;
        let mut bytes = Vec::new();
        use std::io::Read as _;
        file.read_to_end(&mut bytes)
            .map_err(authority_unavailable)?;
        let state: MacHostInputState =
            serde_json::from_slice(&bytes).map_err(authority_unavailable)?;
        if state.version != 1
            || state.pending
            || !super::platform::macos::mac_held_input_identity_is_complete(
                &state.keys,
                !state.buttons.is_empty(),
                state.window,
            )
            || ((state.owner_uid, state.console_set, state.audit_session_id)
                != (owner_uid, console_set, audit_session_id)
                && (!state.keys.is_empty() || !state.buttons.is_empty()))
        {
            return Err(authority_unavailable(
                "authority contains uncertain or foreign-session outstanding input",
            ));
        }
        Ok(Self {
            path,
            state: MacHostInputState {
                owner_uid,
                console_set,
                audit_session_id,
                ..state
            },
        })
    }

    fn prepare(
        &mut self,
        _transition: InputTransition,
    ) -> Result<MacHostInputState, ComputerError> {
        let previous = super::platform::macos::begin_known_pre_post(&mut self.state, |state| {
            state.pending = true
        });
        if let Err(error) = self.store() {
            self.state = previous;
            return Err(error);
        }
        Ok(previous)
    }

    fn rollback(&mut self, previous: MacHostInputState) -> Result<(), ComputerError> {
        super::platform::macos::rollback_known_pre_post(&mut self.state, previous);
        if let Err(error) = self.store() {
            // Never let later work treat a failed rollback as known state.
            self.state.pending = true;
            return Err(error);
        }
        Ok(())
    }

    fn commit(
        &mut self,
        keys: &HashSet<u16>,
        buttons: &HashSet<MouseButton>,
        window: Option<[u8; 16]>,
    ) -> Result<(), ComputerError> {
        self.state.keys = keys.iter().copied().collect();
        self.state.keys.sort_unstable();
        self.state.buttons = buttons.iter().copied().collect();
        self.state.buttons.sort_by_key(|button| match button {
            MouseButton::Left => 0,
            MouseButton::Right => 1,
            MouseButton::Middle => 2,
        });
        self.state.window = if self.state.keys.is_empty() && self.state.buttons.is_empty() {
            None
        } else {
            window
        };
        if !super::platform::macos::mac_held_input_identity_is_complete(
            &self.state.keys,
            !self.state.buttons.is_empty(),
            self.state.window,
        ) {
            return Err(ComputerError::Refused(
                SYNTHETIC_INPUT_REQUIRES_EVIDENCED_WINDOW.to_string(),
            ));
        }
        self.state.pending = false;
        self.store()
    }

    fn store(&self) -> Result<(), ComputerError> {
        use std::io::Write;
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        let bytes = serde_json::to_vec(&self.state).map_err(authority_unavailable)?;
        let parent = self
            .path
            .parent()
            .ok_or_else(|| authority_unavailable("authority path has no parent"))?;
        let mut parent_options = std::fs::OpenOptions::new();
        parent_options
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
        let parent_file = parent_options.open(parent).map_err(authority_unavailable)?;
        let parent_meta = parent_file.metadata().map_err(authority_unavailable)?;
        let parent_mode = parent_meta.mode();
        let protected_parent = parent_meta.is_dir()
            && parent_meta.uid() == 0
            && (parent_mode & 0o022 == 0
                || (parent_mode & libc::S_ISVTX as u32 != 0 && parent_mode & 0o002 != 0));
        if !protected_parent {
            return Err(authority_unavailable(
                "authority parent changed protection before update",
            ));
        }

        // Validate the currently authoritative inode immediately before the
        // replacement. Never turn a missing, linked, foreign, or loose-mode
        // destination into a trusted record merely by overwriting its name.
        drop(open_validated_authority_file(
            &self.path,
            self.state.owner_uid,
        )?);

        let file_name = self
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| authority_unavailable("authority filename is invalid"))?;
        let temp_path = parent.join(format!(
            ".{file_name}.{}.{}.tmp",
            std::process::id(),
            rand::random::<u64>()
        ));
        let result = (|| {
            let mut options = std::fs::OpenOptions::new();
            options
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
            let mut temp = options.open(&temp_path).map_err(authority_unavailable)?;
            let meta = temp.metadata().map_err(authority_unavailable)?;
            if !meta.is_file()
                || meta.uid() != self.state.owner_uid
                || meta.mode() & 0o777 != 0o600
                || meta.nlink() != 1
            {
                return Err(authority_unavailable(
                    "authority temporary file failed ownership validation",
                ));
            }
            temp.write_all(&bytes).map_err(authority_unavailable)?;
            temp.sync_all().map_err(authority_unavailable)?;
            std::fs::rename(&temp_path, &self.path).map_err(authority_unavailable)?;
            parent_file.sync_all().map_err(authority_unavailable)
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&temp_path);
        }
        result
    }
}

fn open_validated_authority_file(
    path: &Path,
    expected_uid: u32,
) -> Result<std::fs::File, ComputerError> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let mut options = std::fs::OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let file = options.open(path).map_err(authority_unavailable)?;
    let meta = file.metadata().map_err(authority_unavailable)?;
    if !meta.is_file()
        || meta.uid() != expected_uid
        || meta.mode() & 0o777 != 0o600
        || meta.nlink() != 1
    {
        return Err(authority_unavailable(
            "authority file is not an active-user-owned, singly-linked 0600 regular file",
        ));
    }
    Ok(file)
}

fn authority_unavailable(error: impl std::fmt::Display) -> ComputerError {
    ComputerError::Refused(format!(
        "protected macOS host input authority unavailable; cleanup ownership is unknowable: {error}"
    ))
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

    async fn execute_normalized_one(
        &mut self,
        action: &NormalizedComputerAction,
    ) -> Result<ComputerActionOutcome, ComputerError> {
        self.execute_action(action)
    }

    fn release_all(&mut self) -> Result<(), ComputerError> {
        // Release only down transitions successfully posted by this backend.
        // Synthesizing unrelated key-ups mutates physical user input and is
        // never a safe substitute for exact ownership accounting.
        // Reload only after the coordinator has acquired the host-wide lease:
        // construction may have raced a predecessor's final journal commit.
        self.input_authority = MacHostInputAuthority::open(&self.active_console_session)?;
        self.outstanding_keys = self.input_authority.state.keys.iter().copied().collect();
        self.outstanding_buttons = self.input_authority.state.buttons.iter().copied().collect();
        if let Some(bytes) = self.input_authority.state.window {
            self.cleanup_window = Some(OpaqueWindowId::from_bytes(bytes));
        }
        if self.evidenced_window.is_none()
            && let Some(opaque) = self.cleanup_window
        {
            let live = restore_macos_injection_target(&opaque)
                .map_err(|_| ComputerError::Refused(EVIDENCED_WINDOW_MISMATCH.to_string()))?;
            self.evidenced_window = Some(EvidencedMacWindow {
                opaque,
                pid: live.window.pid,
                window_number: live.window.window_number,
                ax: live.ax,
            });
        }
        if self.evidenced_window.is_none()
            && (!self.outstanding_keys.is_empty() || !self.outstanding_buttons.is_empty())
        {
            return Err(ComputerError::Refused(
                SYNTHETIC_INPUT_REQUIRES_EVIDENCED_WINDOW.to_string(),
            ));
        }
        let keys: Vec<_> = self.outstanding_keys.iter().copied().collect();
        for code in keys {
            // Releases stay addressed to the evidenced window even if focus
            // has moved: a live-window refusal would leave keys down in the
            // window that received the matching downs.
            self.post_key(code, false, CGEventFlags::empty(), false)?;
        }
        let cursor = self.cursor()?;
        let buttons: Vec<_> = self.outstanding_buttons.iter().copied().collect();
        for button in buttons {
            self.post_mouse(
                mouse_up_type(button),
                button,
                cursor,
                CGEventFlags::empty(),
                1,
                false,
            )?;
        }
        Ok(())
    }

    fn bind_physical_capability(
        &mut self,
        capability: super::coordinator::PhysicalDispatchCapability,
    ) -> Result<(), ComputerError> {
        capability.recheck(BackendKind::RealDesktopMacOs)?;
        self.physical_capability = Some(capability);
        Ok(())
    }

    fn bind_evidenced_window(&mut self, window: OpaqueWindowId) -> Result<(), ComputerError> {
        if let Some(bound) = &self.evidenced_window
            && bound.opaque == window
        {
            return self.require_live_injection_window().map(|_| ());
        }
        let (pid, window_number) =
            macos_injection_target_from_opaque(&window).ok_or_else(|| {
                ComputerError::Refused(CANNOT_DIRECT_INPUT_TO_EVIDENCED_WINDOW.to_string())
            })?;
        let live = live_focused_macos_injection_target()
            .map_err(|_| ComputerError::Refused(EVIDENCED_WINDOW_MISMATCH.to_string()))?;
        if live.window != (MacLiveFocusedWindow { pid, window_number }) {
            return Err(ComputerError::Refused(
                EVIDENCED_WINDOW_MISMATCH.to_string(),
            ));
        }
        self.evidenced_window = Some(EvidencedMacWindow {
            opaque: window,
            pid,
            window_number,
            ax: live.ax,
        });
        self.cleanup_window = Some(window);
        self.require_live_injection_window().map(|_| ())
    }

    fn recheck_evidenced_window(&mut self) -> Result<(), ComputerError> {
        if self.evidenced_window.is_none() {
            return Ok(());
        }
        self.require_live_injection_window().map(|_| ())
    }
}

fn query_geometry() -> Result<DisplayGeometry, ComputerError> {
    let display = CGMainDisplayID();
    let bounds = CGDisplayBounds(display);
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
        || bounds.origin.x != 0.0
        || bounds.origin.y != 0.0
    {
        return Err(ComputerError::CommandFailed {
            program: "CGDisplayCopyDisplayMode".to_string(),
            detail: "main display returned invalid geometry or a nonzero coordinate origin"
                .to_string(),
        });
    }
    Ok(DisplayGeometry {
        physical: PixelSize {
            width: u32::try_from(physical_width)
                .map_err(|error| command_error("CoreGraphics", error))?,
            height: u32::try_from(physical_height)
                .map_err(|error| command_error("CoreGraphics", error))?,
        },
        logical: super::LogicalSize {
            width: logical_width as f64,
            height: logical_height as f64,
        },
        scale_factor: ScaleFactor(scale),
    })
}

/// Split at scalar boundaries, never between a UTF-16 high/low surrogate
/// pair. `CGEventKeyboardSetUnicodeString` receives each vector atomically.
fn utf16_chunks(text: &str) -> Vec<Vec<u16>> {
    const MAX_UNITS: usize = 20;
    let mut chunks = Vec::new();
    let mut current = Vec::with_capacity(MAX_UNITS);
    for scalar in text.chars() {
        let mut encoded = [0_u16; 2];
        let units = scalar.encode_utf16(&mut encoded);
        if current.len() + units.len() > MAX_UNITS && !current.is_empty() {
            chunks.push(std::mem::take(&mut current));
            current.reserve(MAX_UNITS);
        }
        current.extend_from_slice(units);
    }
    if !current.is_empty() {
        chunks.push(current);
    }
    chunks
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

/// AppKit's `NSEvent.windowNumber` destination, carried on the CGEvent record
/// (`CGSEventRecord.window`). Distinct from the public
/// `kCGMouseEventWindowUnderMousePointer` annotation, which is not a destination.
const EVENT_DESTINATION_WINDOW_NUMBER: CGEventField = CGEventField(55);

const AMBIGUOUS_AX_WINDOW_DELIVERY: &str = "macOS window-addressed CGEvent post could not re-authenticate the retained AX window; delivery is uncertain";

fn ambiguous_ax_delivery() -> ComputerError {
    ComputerError::CommandFailed {
        program: "macos computer backend".to_string(),
        detail: AMBIGUOUS_AX_WINDOW_DELIVERY.to_string(),
    }
}

/// Delivery host whose irreversible post takes the retained AX window as the
/// operand. Pid and CGWindowID are re-read from that object at post time.
struct LiveAxDelivery<'a> {
    event: &'a CGEvent,
    witness: &'a MacFocusedWindowWitness,
    opaque: &'a crate::computer::target::OpaqueWindowId,
}

impl MacosAxWindowDelivery for LiveAxDelivery<'_> {
    fn ax_is_live(&self) -> bool {
        ax_window_element_is_live(self.witness.element())
    }

    fn resolve_from_ax(
        &self,
    ) -> Result<
        (
            u32,
            u32,
            [u8; crate::computer::platform::macos::MACOS_WINDOW_GENERATION_LEN],
            (f64, f64),
        ),
        MacosAxDeliveryError,
    > {
        let addressed = address_macos_injection_window(self.witness, self.opaque)
            .map_err(macos_address_error)?;
        let (_, _, generation) = macos_window_identity_from_opaque(self.opaque)
            .ok_or(MacosAxDeliveryError::QueryMismatch)?;
        let pid = u32::try_from(addressed.pid).map_err(|_| MacosAxDeliveryError::QueryMismatch)?;
        Ok((
            pid,
            addressed.window_number,
            generation,
            (addressed.origin.x, addressed.origin.y),
        ))
    }

    fn window_location_setter_available(&self) -> bool {
        cg_event_set_window_location().is_some()
    }

    fn post_to_held_ax(&mut self) -> Result<(), MacosAxDeliveryError> {
        let addressed = address_macos_injection_window(self.witness, self.opaque)
            .map_err(macos_address_error)?;
        stamp_event_window_destination(self.event, addressed)?;
        CGEvent::post_to_pid(addressed.pid, Some(self.event));
        Ok(())
    }
}

fn macos_address_error(
    reason: crate::computer::target::TargetUnavailableReason,
) -> MacosAxDeliveryError {
    match reason {
        crate::computer::target::TargetUnavailableReason::QueryMismatch => {
            MacosAxDeliveryError::QueryMismatch
        }
        crate::computer::target::TargetUnavailableReason::MissingCapability => {
            // `address_macos_injection_window` only surfaces this when
            // `CGWindowListCopyWindowInfo` is unavailable, not when the
            // window-local location setter is missing.
            MacosAxDeliveryError::QueryMismatch
        }
        _ => MacosAxDeliveryError::StaleTarget,
    }
}

fn stamp_event_window_destination(
    event: &CGEvent,
    addressed: MacAddressedInjection,
) -> Result<(), MacosAxDeliveryError> {
    let Some(set_location) = cg_event_set_window_location() else {
        return Err(MacosAxDeliveryError::MissingWindowLocationSetter);
    };
    CGEvent::set_integer_value_field(
        Some(event),
        CGEventField::EventTargetUnixProcessID,
        i64::from(addressed.pid),
    );
    CGEvent::set_integer_value_field(
        Some(event),
        EVENT_DESTINATION_WINDOW_NUMBER,
        i64::from(addressed.window_number),
    );
    CGEvent::set_integer_value_field(
        Some(event),
        CGEventField::MouseEventWindowUnderMousePointer,
        i64::from(addressed.window_number),
    );
    CGEvent::set_integer_value_field(
        Some(event),
        CGEventField::MouseEventWindowUnderMousePointerThatCanHandleThisEvent,
        i64::from(addressed.window_number),
    );
    let screen = CGEvent::location(Some(event));
    let local = CGPoint::new(screen.x - addressed.origin.x, screen.y - addressed.origin.y);
    // SAFETY: `event` is a live CGEvent; the setter writes the window-local
    // point AppKit uses to route inside the authenticated window object.
    unsafe { set_location(std::ptr::from_ref(event).cast(), local) };
    Ok(())
}

type CgEventSetWindowLocationFn =
    unsafe extern "C" fn(event: *const std::ffi::c_void, point: CGPoint);

fn cg_event_set_window_location() -> Option<CgEventSetWindowLocationFn> {
    static CACHED: std::sync::OnceLock<Option<CgEventSetWindowLocationFn>> =
        std::sync::OnceLock::new();
    *CACHED.get_or_init(|| {
        const RTLD_DEFAULT: *mut std::ffi::c_void = (-2_isize) as *mut std::ffi::c_void;
        let ptr = unsafe { libc::dlsym(RTLD_DEFAULT, c"CGEventSetWindowLocation".as_ptr()) };
        if ptr.is_null() {
            None
        } else {
            Some(unsafe { std::mem::transmute(ptr) })
        }
    })
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

fn flags_for_macos_key_codes(codes: &[u16]) -> CGEventFlags {
    modifier_flags(Modifiers {
        shift: codes.iter().any(|code| matches!(*code, 0x38 | 0x3c)),
        control: codes.iter().any(|code| matches!(*code, 0x3b | 0x3e)),
        alt: codes.iter().any(|code| matches!(*code, 0x3a | 0x3d)),
        meta: codes.iter().any(|code| matches!(*code, 0x37 | 0x36)),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::computer::KeyCode;

    #[test]
    fn construction_fails_before_platform_access_without_machine_grant() {
        let temp = tempfile::TempDir::new().expect("temp dir");
        let grant = RealDesktopGrantStore::new(temp.path().join("missing-grant"));
        let result = MacOsComputerBackend::construct(DisplayTarget::RealDesktop, Some(&grant));
        assert!(matches!(
            result,
            Err(ComputerError::RealDesktopGrantMissing)
        ));
    }

    #[test]
    fn key_map_and_modifier_flags_cover_primary_chords() {
        assert_eq!(
            crate::computer::translate_macos_key(&KeyCode::parse("LEFTMETA").expect("meta")),
            Some(0x37)
        );
        assert_eq!(
            crate::computer::translate_macos_key(&KeyCode::parse("ARROWLEFT").expect("arrow")),
            Some(0x7b)
        );
        assert!(
            flags_for_macos_key_codes(&[0x37, 0x38])
                .contains(CGEventFlags::MaskCommand | CGEventFlags::MaskShift)
        );
        assert_eq!(
            crate::computer::translate_macos_key(&KeyCode::parse("INSERT").expect("insert")),
            None
        );
    }

    #[test]
    fn utf16_chunking_keeps_surrogate_pairs_together() {
        let text = format!("{}🙂tail", "a".repeat(19));
        let chunks = utf16_chunks(&text);
        assert_eq!(chunks.iter().map(Vec::len).collect::<Vec<_>>(), vec![19, 6]);
        assert_eq!(chunks[1], "🙂tail".encode_utf16().collect::<Vec<_>>());
    }

    #[test]
    #[ignore = "requires an interactive macOS login plus Screen Recording and Accessibility grants; set COCKPIT_TEST_ALLOW_REAL_HOME=1"]
    fn constructs_and_captures_real_desktop_when_tcc_granted() {
        let env = cockpit_test_support::TestEnvGuard::blocking_lock();
        env.set_var(
            cockpit_test_support::home_isolation::COCKPIT_TEST_ALLOW_REAL_HOME_ENV,
            "1",
        );
        let grant = RealDesktopGrantStore::for_cockpit_data_dir().expect("grant store");
        let mut backend = MacOsComputerBackend::construct(DisplayTarget::RealDesktop, Some(&grant))
            .expect("construct macOS backend");
        let runtime = tokio::runtime::Runtime::new().expect("runtime");
        let outcome = runtime
            .block_on(crate::computer::execute_backend_action(
                &mut backend,
                &crate::computer::ComputerAction::CaptureFull,
            ))
            .expect("capture main display");
        let ComputerActionOutcome::Captured(frame) = outcome else {
            panic!("capture returned a non-capture outcome");
        };
        assert!(frame.png.starts_with(b"\x89PNG\r\n\x1a\n"));
        assert_eq!(backend.backend_kind(), BackendKind::RealDesktopMacOs);
    }
}
