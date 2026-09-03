//! Windows target-evidence pure logic and host-identity security fixtures.
//!
//! Production uses the audited `windows 0.62.2` crate for UI evidence and
//! host-ID security. Required tests inject session/desktop/monitor answers.

use crate::computer::host_identity::domain_hash;

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

/// Map a focused UIA control to classifier vocabulary (issue #290).
///
/// Window/pane/custom types stay as `uia.control_type.{id}` (ambiguous,
/// fail-closed as Credential for TypeText). `IsPassword` always wins so
/// an ordinary Edit control type cannot mask a password box.
pub fn uia_focused_widget_roles(
    control_type: Option<i32>,
    is_password: bool,
) -> (Option<String>, Option<String>) {
    if is_password {
        return (
            Some("PasswordBox".to_string()),
            Some("password".to_string()),
        );
    }
    match control_type {
        Some(UIA_EDIT_CONTROL_TYPE_ID) => (Some("EditText".to_string()), None),
        Some(UIA_DOCUMENT_CONTROL_TYPE_ID) => (Some("TextArea".to_string()), None),
        Some(id) => (Some(format!("uia.control_type.{id}")), None),
        None => (None, None),
    }
}

#[cfg(test)]
mod uia_focused_widget_roles_tests {
    use super::{UIA_DOCUMENT_CONTROL_TYPE_ID, UIA_EDIT_CONTROL_TYPE_ID, uia_focused_widget_roles};

    #[test]
    fn password_property_wins_over_edit_control_type() {
        assert_eq!(
            uia_focused_widget_roles(Some(UIA_EDIT_CONTROL_TYPE_ID), true),
            (Some("PasswordBox".into()), Some("password".into()))
        );
    }

    #[test]
    fn ordinary_edit_and_document_map_to_unambiguous_text_roles() {
        assert_eq!(
            uia_focused_widget_roles(Some(UIA_EDIT_CONTROL_TYPE_ID), false),
            (Some("EditText".into()), None)
        );
        assert_eq!(
            uia_focused_widget_roles(Some(UIA_DOCUMENT_CONTROL_TYPE_ID), false),
            (Some("TextArea".into()), None)
        );
    }

    #[test]
    fn window_and_unknown_types_stay_ambiguous() {
        // UIA Window = 50032. Must not be treated as a text field.
        assert_eq!(
            uia_focused_widget_roles(Some(50032), false),
            (Some("uia.control_type.50032".into()), None)
        );
        assert_eq!(uia_focused_widget_roles(None, false), (None, None));
    }
}
