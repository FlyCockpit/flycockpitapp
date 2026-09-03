//! Windows target-evidence pure logic and host-identity security fixtures.
//!
//! Production uses the audited `windows 0.62.2` crate for UI evidence and
//! host-ID security. Required tests inject session/desktop/monitor answers.

use crate::computer::host_identity::domain_hash;
use crate::computer::target::OpaqueWindowId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsSessionParts {
    pub process_session_id: u32,
    pub window_station_name: String,
    pub input_desktop_name: String,
    pub open_input_desktop_matches: bool,
    pub is_session_zero: bool,
    pub disconnected_or_locked: bool,
    pub secure_desktop: bool,
    pub session_transition: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WindowsEvidenceError {
    SessionZero,
    DesktopMismatch,
    DisconnectOrLock,
    SecureDesktop,
    SessionTransition,
    InaccessibleName,
    NullOrDestroyedHwnd,
    MonitorRemap,
    MissingDeviceId,
    AmbiguousDeviceId,
    AccessDenied,
    UipiLimitation,
}

pub fn windows_session_id(parts: &WindowsSessionParts) -> Result<[u8; 32], WindowsEvidenceError> {
    if parts.is_session_zero {
        return Err(WindowsEvidenceError::SessionZero);
    }
    if parts.disconnected_or_locked {
        return Err(WindowsEvidenceError::DisconnectOrLock);
    }
    if parts.secure_desktop {
        return Err(WindowsEvidenceError::SecureDesktop);
    }
    if parts.session_transition {
        return Err(WindowsEvidenceError::SessionTransition);
    }
    if !parts.open_input_desktop_matches {
        return Err(WindowsEvidenceError::DesktopMismatch);
    }
    if parts.window_station_name.is_empty() || parts.input_desktop_name.is_empty() {
        return Err(WindowsEvidenceError::InaccessibleName);
    }
    Ok(domain_hash(
        b"cockpit.windows.session.v1",
        &[
            &parts.process_session_id.to_le_bytes(),
            parts.window_station_name.as_bytes(),
            parts.input_desktop_name.as_bytes(),
        ],
    ))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsForeground {
    pub hwnd_null: bool,
    pub hwnd_destroyed: bool,
    pub pid: u32,
    pub exe_identity: Option<String>,
    pub appx_package: Option<String>,
    pub appx_application: Option<String>,
    pub class_name: Option<String>,
    pub uia_control_type: Option<String>,
    pub access_denied: bool,
    pub uipi_limited: bool,
}

pub fn validate_foreground(fg: &WindowsForeground) -> Result<u32, WindowsEvidenceError> {
    if fg.hwnd_null || fg.hwnd_destroyed {
        return Err(WindowsEvidenceError::NullOrDestroyedHwnd);
    }
    if fg.access_denied {
        return Err(WindowsEvidenceError::AccessDenied);
    }
    if fg.uipi_limited {
        return Err(WindowsEvidenceError::UipiLimitation);
    }
    Ok(fg.pid)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsMonitorIdentity {
    pub sz_device: String,
    pub adapter_device_id: Option<String>,
    pub monitor_device_id: Option<String>,
    pub remapped: bool,
    pub ambiguous: bool,
}

pub fn windows_monitor_display_id(
    mon: &WindowsMonitorIdentity,
) -> Result<[u8; 32], WindowsEvidenceError> {
    if mon.remapped {
        return Err(WindowsEvidenceError::MonitorRemap);
    }
    if mon.ambiguous {
        return Err(WindowsEvidenceError::AmbiguousDeviceId);
    }
    let adapter = mon
        .adapter_device_id
        .as_deref()
        .ok_or(WindowsEvidenceError::MissingDeviceId)?;
    let monitor = mon
        .monitor_device_id
        .as_deref()
        .ok_or(WindowsEvidenceError::MissingDeviceId)?;
    if mon.sz_device.is_empty() {
        return Err(WindowsEvidenceError::MissingDeviceId);
    }
    Ok(domain_hash(
        b"cockpit.windows.monitor.v1",
        &[
            mon.sz_device.as_bytes(),
            adapter.as_bytes(),
            monitor.as_bytes(),
        ],
    ))
}

/// Windows host-identity DACL fixture model (no real Win32 in unit tests).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsAclFixture {
    pub owner_is_current_user: bool,
    pub dacl_present: bool,
    pub dacl_defaulted: bool,
    pub se_dacl_protected: bool,
    /// Exact allow ACE SIDs: must be {current_user, SYSTEM} order-insensitive.
    pub allow_aces: Vec<WindowsAce>,
    pub has_inherited_ace: bool,
    pub extra_aces: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsAce {
    pub sid: WindowsSidKind,
    pub mask_file_all_access: bool,
    pub object_inherit: bool,
    pub container_inherit: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WindowsSidKind {
    CurrentUser,
    System,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WindowsAclValidation {
    Ok,
    WrongOwner,
    DaclMissing,
    DaclDefaulted,
    NotProtected,
    WrongAceSet,
    InheritedAce,
    ExtraAce,
    WrongMaskOrFlags,
}

pub fn validate_windows_id_acl(
    acl: &WindowsAclFixture,
    is_directory: bool,
) -> WindowsAclValidation {
    if !acl.owner_is_current_user {
        return WindowsAclValidation::WrongOwner;
    }
    if !acl.dacl_present {
        return WindowsAclValidation::DaclMissing;
    }
    if acl.dacl_defaulted {
        return WindowsAclValidation::DaclDefaulted;
    }
    if !acl.se_dacl_protected {
        return WindowsAclValidation::NotProtected;
    }
    if acl.has_inherited_ace {
        return WindowsAclValidation::InheritedAce;
    }
    if acl.extra_aces || acl.allow_aces.len() != 2 {
        return WindowsAclValidation::ExtraAce;
    }
    let mut has_user = false;
    let mut has_system = false;
    for ace in &acl.allow_aces {
        match ace.sid {
            WindowsSidKind::CurrentUser => has_user = true,
            WindowsSidKind::System => has_system = true,
            WindowsSidKind::Other => return WindowsAclValidation::WrongAceSet,
        }
        if !ace.mask_file_all_access {
            return WindowsAclValidation::WrongMaskOrFlags;
        }
        if is_directory {
            if !ace.object_inherit || !ace.container_inherit {
                return WindowsAclValidation::WrongMaskOrFlags;
            }
        } else if ace.object_inherit || ace.container_inherit {
            return WindowsAclValidation::WrongMaskOrFlags;
        }
    }
    if !has_user || !has_system {
        return WindowsAclValidation::WrongAceSet;
    }
    WindowsAclValidation::Ok
}

pub fn valid_file_acl() -> WindowsAclFixture {
    WindowsAclFixture {
        owner_is_current_user: true,
        dacl_present: true,
        dacl_defaulted: false,
        se_dacl_protected: true,
        allow_aces: vec![
            WindowsAce {
                sid: WindowsSidKind::CurrentUser,
                mask_file_all_access: true,
                object_inherit: false,
                container_inherit: false,
            },
            WindowsAce {
                sid: WindowsSidKind::System,
                mask_file_all_access: true,
                object_inherit: false,
                container_inherit: false,
            },
        ],
        has_inherited_ace: false,
        extra_aces: false,
    }
}

pub fn valid_directory_acl() -> WindowsAclFixture {
    let mut acl = valid_file_acl();
    for ace in &mut acl.allow_aces {
        ace.object_inherit = true;
        ace.container_inherit = true;
    }
    acl
}

/// Observed-epoch for Windows native events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WindowsNativeEvent {
    Foreground,
    Focus,
    Location,
    Destroy,
    DesktopSwitch,
    DisplayChange,
    WtsSessionChange,
}

#[derive(Debug, Default)]
pub struct WindowsObservedEpoch {
    pub epoch: u64,
    pub unavailable: bool,
}

impl WindowsObservedEpoch {
    pub fn consume(&mut self, _ev: WindowsNativeEvent) -> Result<u64, WindowsEvidenceError> {
        if self.unavailable {
            return Err(WindowsEvidenceError::SessionTransition);
        }
        match self.epoch.checked_add(1) {
            Some(v) => {
                self.epoch = v;
                Ok(v)
            }
            None => {
                self.unavailable = true;
                Err(WindowsEvidenceError::SessionTransition)
            }
        }
    }
}

#[derive(Debug, Default)]
pub struct WindowsEvidenceLogic;

/// UIA `Edit` control type (`UIA_EditControlTypeId`).
pub const UIA_EDIT_CONTROL_TYPE_ID: i32 = 50004;
/// UIA `Document` control type (`UIA_DocumentControlTypeId`).
pub const UIA_DOCUMENT_CONTROL_TYPE_ID: i32 = 50030;

/// Observed UIA `IsPassword` result. Query failure is [`Self::Unknown`],
/// never coerced to "not a password".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UiaPasswordEvidence {
    Password,
    NotPassword,
    Unknown,
}

impl UiaPasswordEvidence {
    /// Map a `CurrentIsPassword` query. `query_ok` false is [`Self::Unknown`]
    /// even when `is_password` is false — a failed query must not become an
    /// ordinary-field classification.
    pub fn from_query(query_ok: bool, is_password: bool) -> Self {
        if !query_ok {
            Self::Unknown
        } else if is_password {
            Self::Password
        } else {
            Self::NotPassword
        }
    }
}

/// Classification fingerprint for one Windows UIA snapshot.
///
/// Ordinary-text roles are coherent only when this fingerprint is bound to
/// the foreground window and the synchronous recheck observes the same
/// window id, focused-element id, role, and subrole.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UiaWidgetFingerprint {
    pub window_runtime_id: [u8; 16],
    pub focused_runtime_id: Option<[u8; 16]>,
    pub role: Option<String>,
    pub subrole: Option<String>,
}

/// Whether a widget native handle belongs to the snapshot's foreground window.
///
/// `same_as_foreground` is identity with the top-level HWND.
/// `is_child_of_foreground` is Win32 `IsChild`.
/// `root_ancestor_is_foreground` is `GetAncestor(..., GA_ROOT)`.
pub fn native_hwnd_belongs_to_foreground(
    same_as_foreground: bool,
    is_child_of_foreground: bool,
    root_ancestor_is_foreground: bool,
) -> bool {
    same_as_foreground || is_child_of_foreground || root_ancestor_is_foreground
}

impl UiaWidgetFingerprint {
    pub fn window_only(window_runtime_id: [u8; 16]) -> Self {
        Self {
            window_runtime_id,
            focused_runtime_id: None,
            role: None,
            subrole: None,
        }
    }

    /// Widget roles may be published only with a recheckable focused-element
    /// identity. Missing identity drops the roles so TypeText fail-closes.
    pub fn with_bound_widget(
        window_runtime_id: [u8; 16],
        focused_runtime_id: [u8; 16],
        role: Option<String>,
        subrole: Option<String>,
    ) -> Self {
        Self {
            window_runtime_id,
            focused_runtime_id: Some(focused_runtime_id),
            role,
            subrole,
        }
    }
}

/// Map a focused UIA control to classifier vocabulary (issue #290).
///
/// Ordinary-text roles (`EditText`, `TextArea`) require
/// [`UiaPasswordEvidence::NotPassword`]. [`UiaPasswordEvidence::Unknown`]
/// keeps the raw `uia.control_type.{id}` so TypeText fail-closes as
/// Credential — a failed `IsPassword` query must not classify a password
/// Edit as ordinary text. [`UiaPasswordEvidence::Password`] always wins so
/// an ordinary Edit control type cannot mask a password box.
pub fn uia_focused_widget_roles(
    control_type: Option<i32>,
    password: UiaPasswordEvidence,
) -> (Option<String>, Option<String>) {
    match password {
        UiaPasswordEvidence::Password => (
            Some("PasswordBox".to_string()),
            Some("password".to_string()),
        ),
        UiaPasswordEvidence::Unknown => match control_type {
            Some(id) => (Some(format!("uia.control_type.{id}")), None),
            None => (None, None),
        },
        UiaPasswordEvidence::NotPassword => match control_type {
            Some(UIA_EDIT_CONTROL_TYPE_ID) => (Some("EditText".to_string()), None),
            Some(UIA_DOCUMENT_CONTROL_TYPE_ID) => (Some("TextArea".to_string()), None),
            Some(id) => (Some(format!("uia.control_type.{id}")), None),
            None => (None, None),
        },
    }
}

/// USER message delivered through a retained window object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowsUserMessage {
    pub msg: u32,
    pub wparam: usize,
    pub lparam: isize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowsWindowDeliveryError {
    Mismatch,
    MissingObject,
    AmbiguousDelivery,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowsWindowSendOutcome {
    Delivered,
    DestroyedDuringSend,
    TimeoutWhileLive,
}

/// Host for UIA-object delivery. The irreversible send is
/// [`WindowsWindowObjectDelivery::send_from_object`]; an HWND integer is not
/// an operand of that call.
pub trait WindowsWindowObjectDelivery {
    fn object_is_live(&self) -> bool;
    fn resolve_from_object(&self) -> Result<(isize, OpaqueWindowId), WindowsWindowDeliveryError>;
    fn foreground_handle(&self) -> Option<isize>;
    fn planted_identity_is_live(&self, hwnd: isize, opaque: OpaqueWindowId) -> bool;
    fn send_from_object(
        &mut self,
        message: WindowsUserMessage,
    ) -> Result<WindowsWindowSendOutcome, WindowsWindowDeliveryError>;
}

/// Authenticate the retained window object, then send to that held object.
///
/// A recycled HWND is a different object: `send_from_object` must resolve the
/// retained object at send time, so a handle integer captured earlier cannot
/// be the send operand.
pub fn deliver_to_authenticated_window_object<H: WindowsWindowObjectDelivery>(
    host: &mut H,
    expected: OpaqueWindowId,
    expected_hwnd: isize,
    require_foreground: bool,
    message: WindowsUserMessage,
) -> Result<(), WindowsWindowDeliveryError> {
    if !host.object_is_live() {
        return Err(WindowsWindowDeliveryError::MissingObject);
    }
    let (hwnd, opaque) = host.resolve_from_object()?;
    if hwnd != expected_hwnd || opaque != expected {
        return Err(WindowsWindowDeliveryError::Mismatch);
    }
    if !host.planted_identity_is_live(hwnd, expected) {
        return Err(WindowsWindowDeliveryError::Mismatch);
    }
    if require_foreground && host.foreground_handle() != Some(hwnd) {
        return Err(WindowsWindowDeliveryError::Mismatch);
    }
    match host.send_from_object(message)? {
        WindowsWindowSendOutcome::Delivered => {}
        WindowsWindowSendOutcome::DestroyedDuringSend => return Ok(()),
        WindowsWindowSendOutcome::TimeoutWhileLive => {
            return Err(WindowsWindowDeliveryError::AmbiguousDelivery);
        }
    }
    if !host.object_is_live() {
        return Ok(());
    }
    match host.resolve_from_object() {
        Ok((live_hwnd, live_opaque))
            if live_hwnd == expected_hwnd
                && live_opaque == expected
                && host.planted_identity_is_live(live_hwnd, expected) =>
        {
            Ok(())
        }
        _ => Err(WindowsWindowDeliveryError::AmbiguousDelivery),
    }
}

#[cfg(test)]
mod uia_focused_widget_roles_tests {
    use super::{
        UIA_DOCUMENT_CONTROL_TYPE_ID, UIA_EDIT_CONTROL_TYPE_ID, UiaPasswordEvidence,
        UiaWidgetFingerprint, native_hwnd_belongs_to_foreground, uia_focused_widget_roles,
    };

    #[test]
    fn password_property_wins_over_edit_control_type() {
        assert_eq!(
            UiaPasswordEvidence::from_query(true, true),
            UiaPasswordEvidence::Password
        );
        assert_eq!(
            uia_focused_widget_roles(
                Some(UIA_EDIT_CONTROL_TYPE_ID),
                UiaPasswordEvidence::Password
            ),
            (Some("PasswordBox".into()), Some("password".into()))
        );
    }

    #[test]
    fn ordinary_edit_and_document_map_to_unambiguous_text_roles() {
        assert_eq!(
            UiaPasswordEvidence::from_query(true, false),
            UiaPasswordEvidence::NotPassword
        );
        assert_eq!(
            uia_focused_widget_roles(
                Some(UIA_EDIT_CONTROL_TYPE_ID),
                UiaPasswordEvidence::NotPassword
            ),
            (Some("EditText".into()), None)
        );
        assert_eq!(
            uia_focused_widget_roles(
                Some(UIA_DOCUMENT_CONTROL_TYPE_ID),
                UiaPasswordEvidence::NotPassword
            ),
            (Some("TextArea".into()), None)
        );
    }

    #[test]
    fn unknown_password_query_does_not_map_edit_to_ordinary_text() {
        assert_eq!(
            UiaPasswordEvidence::from_query(false, false),
            UiaPasswordEvidence::Unknown
        );
        assert_eq!(
            UiaPasswordEvidence::from_query(false, true),
            UiaPasswordEvidence::Unknown
        );
        assert_eq!(
            uia_focused_widget_roles(Some(UIA_EDIT_CONTROL_TYPE_ID), UiaPasswordEvidence::Unknown),
            (Some("uia.control_type.50004".into()), None)
        );
        assert_eq!(
            uia_focused_widget_roles(
                Some(UIA_DOCUMENT_CONTROL_TYPE_ID),
                UiaPasswordEvidence::Unknown
            ),
            (Some("uia.control_type.50030".into()), None)
        );
        assert_ne!(
            uia_focused_widget_roles(Some(UIA_EDIT_CONTROL_TYPE_ID), UiaPasswordEvidence::Unknown),
            uia_focused_widget_roles(
                Some(UIA_EDIT_CONTROL_TYPE_ID),
                UiaPasswordEvidence::NotPassword
            )
        );
    }

    #[test]
    fn window_and_unknown_types_stay_ambiguous() {
        // UIA Window = 50032. Must not be treated as a text field.
        assert_eq!(
            uia_focused_widget_roles(Some(50032), UiaPasswordEvidence::NotPassword),
            (Some("uia.control_type.50032".into()), None)
        );
        assert_eq!(
            uia_focused_widget_roles(None, UiaPasswordEvidence::NotPassword),
            (None, None)
        );
        assert_eq!(
            uia_focused_widget_roles(None, UiaPasswordEvidence::Unknown),
            (None, None)
        );
    }

    #[test]
    fn widget_fingerprint_requires_same_focused_identity_and_roles() {
        let window = [1u8; 16];
        let focused = [2u8; 16];
        let captured =
            UiaWidgetFingerprint::with_bound_widget(window, focused, Some("EditText".into()), None);
        assert_eq!(captured, captured.clone());
        assert_ne!(
            captured,
            UiaWidgetFingerprint::with_bound_widget(
                window,
                [3u8; 16],
                Some("EditText".into()),
                None,
            )
        );
        assert_ne!(
            captured,
            UiaWidgetFingerprint::with_bound_widget(
                window,
                focused,
                Some("uia.control_type.50004".into()),
                None,
            )
        );
        assert_ne!(captured, UiaWidgetFingerprint::window_only(window));
    }

    #[test]
    fn widget_hwnd_belongs_to_foreground_when_same_child_or_root() {
        assert!(native_hwnd_belongs_to_foreground(true, false, false));
        assert!(native_hwnd_belongs_to_foreground(false, true, false));
        assert!(native_hwnd_belongs_to_foreground(false, false, true));
        assert!(!native_hwnd_belongs_to_foreground(false, false, false));
    }
}

#[cfg(test)]
mod window_object_delivery_tests {
    use super::{
        WindowsUserMessage, WindowsWindowDeliveryError, WindowsWindowObjectDelivery,
        WindowsWindowSendOutcome, deliver_to_authenticated_window_object,
    };
    use crate::computer::target::OpaqueWindowId;
    use std::collections::HashMap;

    const MSG: WindowsUserMessage = WindowsUserMessage {
        msg: 0x0100,
        wparam: 1,
        lparam: 2,
    };

    struct RecordingUiaHost {
        bound_hwnd: isize,
        bound_opaque: OpaqueWindowId,
        object_hwnd: isize,
        object_opaque: OpaqueWindowId,
        planted: HashMap<isize, OpaqueWindowId>,
        foreground: Option<isize>,
        live: bool,
        recycle_on_send: bool,
        recycled_hwnd: isize,
        recycled_opaque: OpaqueWindowId,
        sent: Vec<(isize, WindowsUserMessage)>,
    }

    impl WindowsWindowObjectDelivery for RecordingUiaHost {
        fn object_is_live(&self) -> bool {
            self.live
        }

        fn resolve_from_object(
            &self,
        ) -> Result<(isize, OpaqueWindowId), WindowsWindowDeliveryError> {
            if !self.live {
                return Err(WindowsWindowDeliveryError::MissingObject);
            }
            Ok((self.object_hwnd, self.object_opaque))
        }

        fn foreground_handle(&self) -> Option<isize> {
            self.foreground
        }

        fn planted_identity_is_live(&self, hwnd: isize, opaque: OpaqueWindowId) -> bool {
            self.planted.get(&hwnd).copied() == Some(opaque)
        }

        fn send_from_object(
            &mut self,
            message: WindowsUserMessage,
        ) -> Result<WindowsWindowSendOutcome, WindowsWindowDeliveryError> {
            if self.recycle_on_send {
                self.object_hwnd = self.recycled_hwnd;
                self.object_opaque = self.recycled_opaque;
            }
            let (hwnd, opaque) = self.resolve_from_object()?;
            if hwnd != self.bound_hwnd || opaque != self.bound_opaque {
                return Err(WindowsWindowDeliveryError::Mismatch);
            }
            if self.planted.get(&hwnd).copied() != Some(opaque) {
                return Err(WindowsWindowDeliveryError::Mismatch);
            }
            self.sent.push((hwnd, message));
            Ok(WindowsWindowSendOutcome::Delivered)
        }
    }

    fn host(hwnd: isize, opaque: OpaqueWindowId) -> RecordingUiaHost {
        let mut planted = HashMap::new();
        planted.insert(hwnd, opaque);
        RecordingUiaHost {
            bound_hwnd: hwnd,
            bound_opaque: opaque,
            object_hwnd: hwnd,
            object_opaque: opaque,
            planted,
            foreground: Some(hwnd),
            live: true,
            recycle_on_send: false,
            recycled_hwnd: hwnd.wrapping_add(1),
            recycled_opaque: OpaqueWindowId::from_bytes([0xff; 16]),
            sent: Vec::new(),
        }
    }

    #[test]
    fn deliver_sends_only_through_the_retained_object() {
        let opaque = OpaqueWindowId::from_bytes([7; 16]);
        let mut live = host(0x1000, opaque);
        assert_eq!(
            deliver_to_authenticated_window_object(&mut live, opaque, 0x1000, true, MSG),
            Ok(())
        );
        assert_eq!(live.sent, vec![(0x1000, MSG)]);
    }

    #[test]
    fn deliver_refuses_a_recycled_hwnd_that_the_retained_object_no_longer_names() {
        let opaque = OpaqueWindowId::from_bytes([7; 16]);
        let recycled_opaque = OpaqueWindowId::from_bytes([8; 16]);
        let mut recycled = host(0x1000, opaque);
        recycled.recycle_on_send = true;
        recycled.recycled_hwnd = 0x1000;
        recycled.recycled_opaque = recycled_opaque;
        assert_eq!(
            deliver_to_authenticated_window_object(&mut recycled, opaque, 0x1000, true, MSG),
            Err(WindowsWindowDeliveryError::Mismatch)
        );
        assert!(recycled.sent.is_empty());
    }

    #[test]
    fn deliver_refuses_when_the_object_is_dead_or_not_foreground() {
        let opaque = OpaqueWindowId::from_bytes([7; 16]);
        let mut dead = host(0x1000, opaque);
        dead.live = false;
        assert_eq!(
            deliver_to_authenticated_window_object(&mut dead, opaque, 0x1000, true, MSG),
            Err(WindowsWindowDeliveryError::MissingObject)
        );
        assert!(dead.sent.is_empty());

        let mut unfocused = host(0x1000, opaque);
        unfocused.foreground = Some(0x2000);
        assert_eq!(
            deliver_to_authenticated_window_object(&mut unfocused, opaque, 0x1000, true, MSG),
            Err(WindowsWindowDeliveryError::Mismatch)
        );
        assert!(unfocused.sent.is_empty());
    }
}
