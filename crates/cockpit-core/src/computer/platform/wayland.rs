//! Wayland target evidence: only a registered provider is accepted.
//!
//! No generic Wayland dependency, no title/process inference, and no
//! XWayland `_NET_ACTIVE_WINDOW` evidence may be presented as native proof.

use crate::computer::host_identity::domain_hash;
use crate::computer::target::{
    BackendKind, EvidenceSource, FieldEvidence, OpaqueWindowId, TargetGeometry,
    TargetIdentityEvidence, TargetUnavailableReason, empty_unavailable,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WaylandProviderKind {
    CompositorIntegration,
    ScreenCastPortal,
    RemoteDesktopPortal,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WaylandFocusGuarantee {
    /// Provider guarantees a monotonic focus/change sequence.
    MonotonicFocusSequence,
    /// Portal supplies PipeWire/input only — no stable focus identity.
    StreamOnlyNoFocus,
    None,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WaylandCapabilityDescriptor {
    pub kind: WaylandProviderKind,
    pub implementation: String,
    pub version: String,
    pub session_token: String,
    pub source_token: String,
    pub display_token: String,
    pub focus_guarantee: WaylandFocusGuarantee,
    pub backend_generation: u64,
    pub portal_expired: bool,
    pub portal_revoked: bool,
    pub source_replaced: bool,
    pub reconnected: bool,
    /// XWayland presence must never upgrade to native Wayland proof.
    pub xwayland_present: bool,
    pub registered: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WaylandProviderError {
    Unregistered,
    UnknownProvider,
    VersionDrift,
    PortalExpired,
    PortalRevoked,
    SourceReplaced,
    Reconnect,
    FocusIdentityUnavailable,
    XwaylandFallbackForbidden,
    MissingMethod,
}

pub fn evaluate_wayland_provider(
    desc: &WaylandCapabilityDescriptor,
    expected_implementation: Option<&str>,
    expected_version: Option<&str>,
) -> Result<WaylandAcceptedEvidence, WaylandProviderError> {
    if !desc.registered {
        return Err(WaylandProviderError::Unregistered);
    }
    if matches!(desc.kind, WaylandProviderKind::Unknown) {
        return Err(WaylandProviderError::UnknownProvider);
    }
    if let Some(exp) = expected_implementation
        && desc.implementation != exp
    {
        return Err(WaylandProviderError::VersionDrift);
    }
    if let Some(exp) = expected_version
        && desc.version != exp
    {
        return Err(WaylandProviderError::VersionDrift);
    }
    if desc.portal_expired {
        return Err(WaylandProviderError::PortalExpired);
    }
    if desc.portal_revoked {
        return Err(WaylandProviderError::PortalRevoked);
    }
    if desc.source_replaced {
        return Err(WaylandProviderError::SourceReplaced);
    }
    if desc.reconnected {
        return Err(WaylandProviderError::Reconnect);
    }
    // XWayland presence alone never yields native proof.
    if desc.xwayland_present && desc.focus_guarantee == WaylandFocusGuarantee::None {
        return Err(WaylandProviderError::XwaylandFallbackForbidden);
    }
    match desc.focus_guarantee {
        WaylandFocusGuarantee::MonotonicFocusSequence => {
            let session = domain_hash(
                b"cockpit.wayland.session.v1",
                &[
                    desc.implementation.as_bytes(),
                    desc.version.as_bytes(),
                    desc.session_token.as_bytes(),
                ],
            );
            let display = domain_hash(
                b"cockpit.wayland.display.v1",
                &[desc.display_token.as_bytes(), desc.source_token.as_bytes()],
            );
            Ok(WaylandAcceptedEvidence {
                session,
                display,
                sequence: desc.backend_generation,
            })
        }
        WaylandFocusGuarantee::StreamOnlyNoFocus => {
            Err(WaylandProviderError::FocusIdentityUnavailable)
        }
        WaylandFocusGuarantee::None => Err(WaylandProviderError::MissingMethod),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WaylandAcceptedEvidence {
    pub session: [u8; 32],
    pub display: [u8; 32],
    pub sequence: u64,
}

/// Registered provider owned by compositor integration or portal session.
pub trait WaylandTargetEvidenceProvider: Send {
    fn capability_descriptor(&self) -> &WaylandCapabilityDescriptor;
    fn current_sequence(&self) -> u64;
}

#[derive(Debug, Clone)]
pub struct FakeWaylandProvider {
    pub descriptor: WaylandCapabilityDescriptor,
    pub sequence: u64,
}

impl WaylandTargetEvidenceProvider for FakeWaylandProvider {
    fn capability_descriptor(&self) -> &WaylandCapabilityDescriptor {
        &self.descriptor
    }

    fn current_sequence(&self) -> u64 {
        self.sequence
    }
}

pub fn wayland_snapshot_from_provider(
    provider: &dyn WaylandTargetEvidenceProvider,
    host: crate::computer::host_identity::HostInstallationId,
    expected_implementation: Option<&str>,
    expected_version: Option<&str>,
) -> Result<TargetIdentityEvidence, TargetUnavailableReason> {
    let desc = provider.capability_descriptor();
    let accepted = evaluate_wayland_provider(desc, expected_implementation, expected_version)
        .map_err(|e| match e {
            WaylandProviderError::Unregistered | WaylandProviderError::UnknownProvider => {
                TargetUnavailableReason::ProviderUnregistered
            }
            WaylandProviderError::VersionDrift => TargetUnavailableReason::UnsupportedPlatform,
            WaylandProviderError::PortalExpired | WaylandProviderError::PortalRevoked => {
                TargetUnavailableReason::PortalExpired
            }
            WaylandProviderError::SourceReplaced => TargetUnavailableReason::SourceReplaced,
            WaylandProviderError::Reconnect => TargetUnavailableReason::Reconnect,
            WaylandProviderError::FocusIdentityUnavailable => {
                TargetUnavailableReason::FocusIdentityUnavailable
            }
            WaylandProviderError::XwaylandFallbackForbidden => {
                TargetUnavailableReason::XwaylandFallbackForbidden
            }
            WaylandProviderError::MissingMethod => TargetUnavailableReason::MissingCapability,
        })?;

    let mut snap = empty_unavailable(BackendKind::RealDesktopWayland);
    snap.host_installation_id = FieldEvidence::available(host, EvidenceSource::WaylandProvider);
    snap.platform_session_or_seat_id =
        FieldEvidence::available(accepted.session, EvidenceSource::WaylandProvider);
    snap.physical_display_id =
        FieldEvidence::available(accepted.display, EvidenceSource::WaylandProvider);
    snap.focused_window_id = FieldEvidence::available(
        OpaqueWindowId::from_bytes({
            let mut w = [0u8; 16];
            w.copy_from_slice(&accepted.display[..16]);
            w
        }),
        EvidenceSource::WaylandProvider,
    );
    snap.geometry = FieldEvidence::available(
        TargetGeometry {
            x: 0,
            y: 0,
            width: 1920,
            height: 1080,
            scale: 1.0,
        },
        EvidenceSource::WaylandProvider,
    );
    snap.adapter_observed_epoch = provider.current_sequence();
    Ok(snap)
}

/// Fabricating global focus or X11-derived fallback is forbidden.
pub fn reject_x11_as_wayland_evidence() -> TargetUnavailableReason {
    TargetUnavailableReason::XwaylandFallbackForbidden
}

pub fn reject_generic_global_focus_claim() -> TargetUnavailableReason {
    TargetUnavailableReason::UnsupportedPlatform
}
