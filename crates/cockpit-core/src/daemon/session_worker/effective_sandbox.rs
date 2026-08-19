//! Persist sandbox *intent*; compute *effective* mode from host capabilities.
//!
//! Unavailable container never silently rewrites to host Sandbox. Missing host
//! sandbox is effective Off, not Refuse. Refuse remains the fail-closed
//! backstop if a session still believes it is sandboxed.

use cockpit_proto::{
    FeatureCapabilityRow, FeatureCapabilityState, HostCapabilitySnapshot, SecretStoreSnapshot,
};

use crate::host_capabilities::{FEATURE_SANDBOX_CONTAINER, FEATURE_SANDBOX_HOST};
use crate::tools::sandbox_mode::SandboxMode;

/// Typed reject when [`SetSandbox`](super::SessionWorkerHandle::set_sandbox)
/// asks for a mode the snapshot cannot honor. The caller must not persist
/// `requested` and must not treat this as success.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxCapabilityMissing {
    pub requested: SandboxMode,
    pub persisted_intent: SandboxMode,
    pub effective: SandboxMode,
    pub reason: String,
    pub fix_command: Option<String>,
}

impl std::fmt::Display for SandboxCapabilityMissing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "sandbox capability missing for {}: {} (persisted intent {}, effective {})",
            sandbox_mode_label(self.requested),
            self.reason,
            sandbox_mode_label(self.persisted_intent),
            sandbox_mode_label(self.effective),
        )?;
        if let Some(fix) = &self.fix_command {
            write!(f, "; fix: {fix}")?;
        }
        Ok(())
    }
}

impl std::error::Error for SandboxCapabilityMissing {}

/// Successful [`evaluate_set_sandbox`]: persist `persisted_intent` and run
/// `effective`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SetSandboxApplied {
    pub persisted_intent: SandboxMode,
    pub effective: SandboxMode,
}

/// Failure from [`super::SessionWorkerHandle::set_sandbox`].
#[derive(Debug)]
pub enum SetSandboxError {
    CapabilityMissing(SandboxCapabilityMissing),
    Persist(String),
}

impl std::fmt::Display for SetSandboxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CapabilityMissing(error) => write!(f, "{error}"),
            Self::Persist(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for SetSandboxError {}

/// Snapshot with no feature rows. Runtime treats missing `sandbox.host` as
/// still usable (Refuse remains the backstop). Wizard treats missing rows as
/// unselectable.
pub fn unpublished_host_capability_snapshot() -> HostCapabilitySnapshot {
    HostCapabilitySnapshot {
        generation: 0,
        features: Vec::new(),
        dependencies: Vec::new(),
        secret_store: SecretStoreSnapshot::unconfigured_placeholder(),
    }
}

/// Test/production helper: build a snapshot with explicit sandbox feature rows.
pub fn sandbox_capability_snapshot(
    host: FeatureCapabilityState,
    container: FeatureCapabilityState,
) -> HostCapabilitySnapshot {
    sandbox_capability_snapshot_with_reasons(
        host,
        container,
        feature_reason(FEATURE_SANDBOX_HOST, host),
        feature_reason(FEATURE_SANDBOX_CONTAINER, container),
        None,
        None,
    )
}

pub fn sandbox_capability_snapshot_with_reasons(
    host: FeatureCapabilityState,
    container: FeatureCapabilityState,
    host_reason: impl Into<String>,
    container_reason: impl Into<String>,
    host_fix: Option<String>,
    container_fix: Option<String>,
) -> HostCapabilitySnapshot {
    HostCapabilitySnapshot {
        generation: 1,
        features: vec![
            FeatureCapabilityRow {
                id: FEATURE_SANDBOX_HOST.to_string(),
                state: host,
                reason: host_reason.into(),
                fix_command: host_fix,
                remedy_text: None,
                dependency_ids: vec!["safety.bubblewrap".to_string()],
            },
            FeatureCapabilityRow {
                id: FEATURE_SANDBOX_CONTAINER.to_string(),
                state: container,
                reason: container_reason.into(),
                fix_command: container_fix,
                remedy_text: None,
                dependency_ids: vec![
                    "container.docker".to_string(),
                    "container.podman".to_string(),
                ],
            },
        ],
        dependencies: Vec::new(),
        secret_store: SecretStoreSnapshot::unconfigured_placeholder(),
    }
}

fn feature_reason(id: &str, state: FeatureCapabilityState) -> String {
    match (id, state) {
        (_, FeatureCapabilityState::Available) => format!("{id} is available"),
        (_, FeatureCapabilityState::Missing) => format!("{id} is missing"),
        (_, FeatureCapabilityState::Failed) => format!("{id} probe failed"),
        (_, FeatureCapabilityState::Unsupported) => format!("{id} is unsupported"),
    }
}

fn feature_row<'a>(caps: &'a HostCapabilitySnapshot, id: &str) -> Option<&'a FeatureCapabilityRow> {
    caps.feature(id)
}

fn feature_state_is_available(state: FeatureCapabilityState) -> bool {
    state.is_available()
}

/// Whether `intent` can be the live effective mode under `caps`.
///
/// A missing feature row is unavailable. An unpublished snapshot therefore
/// yields effective Off for Sandbox/container intents, never a silent
/// host-Sandbox enable.
pub fn sandbox_mode_available(intent: SandboxMode, caps: &HostCapabilitySnapshot) -> bool {
    match intent {
        SandboxMode::Off => true,
        SandboxMode::Sandbox => match feature_row(caps, FEATURE_SANDBOX_HOST) {
            Some(row) => feature_state_is_available(row.state),
            None => false,
        },
        SandboxMode::Container | SandboxMode::ContainerReadonly => {
            feature_row(caps, FEATURE_SANDBOX_CONTAINER)
                .is_some_and(|row| feature_state_is_available(row.state))
        }
    }
}

/// Whether the wizard may offer `intent` as a selectable row.
///
/// Unlike [`sandbox_mode_available`], a missing feature row is not offered.
/// Failed and timed-out probes are the same as missing.
pub fn sandbox_mode_selectable(intent: SandboxMode, caps: &HostCapabilitySnapshot) -> bool {
    match intent {
        SandboxMode::Off => true,
        SandboxMode::Sandbox => feature_row(caps, FEATURE_SANDBOX_HOST)
            .is_some_and(|row| feature_state_is_available(row.state)),
        SandboxMode::Container | SandboxMode::ContainerReadonly => {
            feature_row(caps, FEATURE_SANDBOX_CONTAINER)
                .is_some_and(|row| feature_state_is_available(row.state))
        }
    }
}

/// Compute the mode this session actually runs from persisted intent + snapshot.
///
/// There is no container → host Sandbox rewrite. Unavailable container is
/// effective Off even when host sandbox works.
pub fn effective_sandbox_mode(intent: SandboxMode, caps: &HostCapabilitySnapshot) -> SandboxMode {
    if sandbox_mode_available(intent, caps) {
        intent
    } else {
        SandboxMode::Off
    }
}

/// Decide a `SetSandbox` request. Unavailable intent is a typed reject and
/// must not be persisted.
pub fn evaluate_set_sandbox(
    requested: SandboxMode,
    persisted_intent: SandboxMode,
    caps: &HostCapabilitySnapshot,
) -> Result<SetSandboxApplied, SandboxCapabilityMissing> {
    if sandbox_mode_available(requested, caps) {
        return Ok(SetSandboxApplied {
            persisted_intent: requested,
            effective: requested,
        });
    }
    let row = capability_row_for_mode(requested, caps);
    Err(SandboxCapabilityMissing {
        requested,
        persisted_intent,
        effective: effective_sandbox_mode(persisted_intent, caps),
        reason: row
            .map(|row| row.reason.clone())
            .unwrap_or_else(|| format!("{} is unavailable", sandbox_mode_label(requested))),
        fix_command: row.and_then(|row| row.fix_command.clone()),
    })
}

fn capability_row_for_mode(
    mode: SandboxMode,
    caps: &HostCapabilitySnapshot,
) -> Option<&FeatureCapabilityRow> {
    match mode {
        SandboxMode::Off => None,
        SandboxMode::Sandbox => feature_row(caps, FEATURE_SANDBOX_HOST),
        SandboxMode::Container | SandboxMode::ContainerReadonly => {
            feature_row(caps, FEATURE_SANDBOX_CONTAINER)
        }
    }
}

fn sandbox_mode_label(mode: SandboxMode) -> &'static str {
    match mode {
        SandboxMode::Off => "off",
        SandboxMode::Sandbox => "sandbox",
        SandboxMode::Container => "container",
        SandboxMode::ContainerReadonly => "container_readonly",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn effective_sandbox_mode_table() {
        let host_up = FeatureCapabilityState::Available;
        let host_missing = FeatureCapabilityState::Missing;
        let host_failed = FeatureCapabilityState::Failed;
        let host_unsupported = FeatureCapabilityState::Unsupported;
        let container_up = FeatureCapabilityState::Available;
        let container_down = FeatureCapabilityState::Missing;
        let container_failed = FeatureCapabilityState::Failed;

        let cases: &[(
            SandboxMode,
            FeatureCapabilityState,
            FeatureCapabilityState,
            SandboxMode,
        )] = &[
            (SandboxMode::Off, host_up, container_up, SandboxMode::Off),
            (
                SandboxMode::Off,
                host_missing,
                container_down,
                SandboxMode::Off,
            ),
            (
                SandboxMode::Off,
                host_unsupported,
                container_failed,
                SandboxMode::Off,
            ),
            (
                SandboxMode::Sandbox,
                host_up,
                container_down,
                SandboxMode::Sandbox,
            ),
            (
                SandboxMode::Sandbox,
                host_up,
                container_up,
                SandboxMode::Sandbox,
            ),
            (
                SandboxMode::Sandbox,
                host_missing,
                container_up,
                SandboxMode::Off,
            ),
            (
                SandboxMode::Sandbox,
                host_failed,
                container_up,
                SandboxMode::Off,
            ),
            (
                SandboxMode::Sandbox,
                host_unsupported,
                container_up,
                SandboxMode::Off,
            ),
            (
                SandboxMode::Container,
                host_up,
                container_up,
                SandboxMode::Container,
            ),
            (
                SandboxMode::Container,
                host_missing,
                container_up,
                SandboxMode::Container,
            ),
            (
                SandboxMode::Container,
                host_up,
                container_down,
                SandboxMode::Off,
            ),
            (
                SandboxMode::Container,
                host_up,
                container_failed,
                SandboxMode::Off,
            ),
            (
                SandboxMode::ContainerReadonly,
                host_up,
                container_up,
                SandboxMode::ContainerReadonly,
            ),
            (
                SandboxMode::ContainerReadonly,
                host_up,
                container_down,
                SandboxMode::Off,
            ),
        ];

        for (intent, host, container, expected) in cases {
            let caps = sandbox_capability_snapshot(*host, *container);
            assert_eq!(
                effective_sandbox_mode(*intent, &caps),
                *expected,
                "intent={intent:?} host={host:?} container={container:?}"
            );
        }
    }

    #[test]
    fn host_sandbox_missing_does_not_keep_sandbox_on() {
        let caps = sandbox_capability_snapshot(
            FeatureCapabilityState::Missing,
            FeatureCapabilityState::Available,
        );
        let effective = effective_sandbox_mode(SandboxMode::Sandbox, &caps);
        assert_eq!(effective, SandboxMode::Off);
        assert!(
            !effective.enabled(),
            "missing host sandbox is effective Off, not Refuse"
        );
    }

    #[test]
    fn unpublished_snapshot_does_not_enable_host_sandbox() {
        let caps = HostCapabilitySnapshot {
            generation: 0,
            features: Vec::new(),
            dependencies: Vec::new(),
            secret_store: SecretStoreSnapshot::unconfigured_placeholder(),
        };
        assert_eq!(
            effective_sandbox_mode(SandboxMode::Sandbox, &caps),
            SandboxMode::Off
        );
        assert!(evaluate_set_sandbox(SandboxMode::Sandbox, SandboxMode::Off, &caps).is_err());
    }

    #[test]
    fn container_unavailable_defaults_off_not_host_sandbox() {
        let caps = sandbox_capability_snapshot(
            FeatureCapabilityState::Available,
            FeatureCapabilityState::Missing,
        );
        assert_eq!(
            effective_sandbox_mode(SandboxMode::Container, &caps),
            SandboxMode::Off
        );
        assert_eq!(
            effective_sandbox_mode(SandboxMode::ContainerReadonly, &caps),
            SandboxMode::Off
        );
        assert_ne!(
            effective_sandbox_mode(SandboxMode::Container, &caps),
            SandboxMode::Sandbox,
            "unavailable container must not silently rewrite to host Sandbox"
        );
    }

    #[test]
    fn set_sandbox_rejects_unavailable_intent() {
        let host_down = sandbox_capability_snapshot_with_reasons(
            FeatureCapabilityState::Missing,
            FeatureCapabilityState::Available,
            "bwrap is not installed",
            "podman is available",
            Some("sudo apt-get install bubblewrap".to_string()),
            None,
        );
        let previous = SandboxMode::Off;
        let err = evaluate_set_sandbox(SandboxMode::Sandbox, previous, &host_down)
            .expect_err("SetSandbox(Sandbox) must reject when host cap is missing");
        assert_eq!(err.requested, SandboxMode::Sandbox);
        assert_eq!(err.persisted_intent, previous);
        assert_eq!(err.effective, SandboxMode::Off);
        assert!(err.reason.contains("bwrap"));
        assert_eq!(
            err.fix_command.as_deref(),
            Some("sudo apt-get install bubblewrap")
        );

        let container_down = sandbox_capability_snapshot_with_reasons(
            FeatureCapabilityState::Available,
            FeatureCapabilityState::Failed,
            "host sandbox is available",
            "docker daemon is not running",
            None,
            None,
        );
        let previous = SandboxMode::Sandbox;
        let err = evaluate_set_sandbox(SandboxMode::Container, previous, &container_down)
            .expect_err("SetSandbox(Container) must reject when container cap is down");
        assert_eq!(err.requested, SandboxMode::Container);
        assert_eq!(err.persisted_intent, previous);
        assert_eq!(
            err.effective,
            SandboxMode::Sandbox,
            "reject leaves effective as effective_sandbox_mode(persisted_intent)"
        );
        let err = evaluate_set_sandbox(SandboxMode::ContainerReadonly, previous, &container_down)
            .expect_err("SetSandbox(ContainerReadonly) must reject when container cap is down");
        assert_eq!(err.requested, SandboxMode::ContainerReadonly);
        assert_eq!(err.persisted_intent, previous);

        let both_up = sandbox_capability_snapshot(
            FeatureCapabilityState::Available,
            FeatureCapabilityState::Available,
        );
        let applied = evaluate_set_sandbox(SandboxMode::Sandbox, SandboxMode::Off, &both_up)
            .expect("available host Sandbox persists");
        assert_eq!(applied.persisted_intent, SandboxMode::Sandbox);
        assert_eq!(applied.effective, SandboxMode::Sandbox);
        let applied = evaluate_set_sandbox(
            SandboxMode::ContainerReadonly,
            SandboxMode::Sandbox,
            &both_up,
        )
        .expect("available container persists");
        assert_eq!(applied.persisted_intent, SandboxMode::ContainerReadonly);
        assert_eq!(applied.effective, SandboxMode::ContainerReadonly);
    }

    #[test]
    fn windows_unsupported_host_sandbox_is_effective_off() {
        let caps = sandbox_capability_snapshot(
            FeatureCapabilityState::Unsupported,
            FeatureCapabilityState::Missing,
        );
        assert_eq!(
            effective_sandbox_mode(SandboxMode::Sandbox, &caps),
            SandboxMode::Off
        );
        let caps = sandbox_capability_snapshot(
            FeatureCapabilityState::Unsupported,
            FeatureCapabilityState::Available,
        );
        assert_eq!(
            effective_sandbox_mode(SandboxMode::Container, &caps),
            SandboxMode::Container
        );
    }
}
