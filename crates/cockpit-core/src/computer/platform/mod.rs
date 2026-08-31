//! Platform target-evidence adapters.
//!
//! Each OS module owns native types and converts them before returning.
//! Required tests inject fake adapters and pure-logic fixtures; they never
//! enumerate real windows or perform desktop actions.

pub mod macos;
pub mod wayland;
pub mod windows;
pub mod x11;

pub use macos::{
    AU_DEFAUDITSID, CgSessionKey, MacAxAttribute, MacAxNotification, MacCallbackGate,
    MacCallbackTerminalReason, MacNativeEvent, MacOsEvidenceLogic, MacProducerKind,
    TASK_AUDIT_TOKEN_COUNT_EXPECTED, extract_audit_session_id, join_ax_to_cg_window,
};
pub use wayland::{
    WaylandCapabilityDescriptor, WaylandFocusGuarantee, WaylandProviderKind,
    WaylandTargetEvidenceProvider, evaluate_wayland_provider,
};
pub use windows::{
    WindowsEvidenceLogic, WindowsSessionParts, windows_monitor_display_id, windows_session_id,
};
pub use x11::{
    EdidValidation, MirrorGroup, RandrOutputSnapshot, X11EvidenceLogic, X11SessionParts,
    select_mirror_group, validate_edid, x11_physical_display_id, x11_session_or_seat_id,
};
#[cfg(target_os = "linux")]
pub use x11::X11TargetEvidenceAdapter;
