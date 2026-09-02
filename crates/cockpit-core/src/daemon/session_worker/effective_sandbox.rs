//! Persist sandbox *intent*; compute *effective* mode from host capabilities.
//!
//! Unavailable container never silently rewrites to host Sandbox. A configured
//! sandbox/container intent whose capability is missing, Failed, Unsupported,
//! or unpublished is effective [`SandboxMode::Refuse`], never silent Off.

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

/// Snapshot with no feature rows. Runtime fail-closes sandboxed intents to
/// Refuse. Wizard treats missing rows as unselectable.
pub fn unpublished_host_capability_snapshot() -> HostCapabilitySnapshot {
    HostCapabilitySnapshot::unpublished()
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
/// cannot honor Sandbox/container intents. [`SandboxMode::Refuse`] is never
/// a selectable intent.
pub fn sandbox_mode_available(intent: SandboxMode, caps: &HostCapabilitySnapshot) -> bool {
    match intent {
        SandboxMode::Off => true,
        SandboxMode::Refuse => false,
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
        SandboxMode::Refuse => false,
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
/// There is no container → host Sandbox rewrite. Unavailable sandbox or
/// container is [`SandboxMode::Refuse`], never silent Off. Explicit Off
/// (`--no-sandbox` / `/sandbox off`) remains Off.
pub fn effective_sandbox_mode(intent: SandboxMode, caps: &HostCapabilitySnapshot) -> SandboxMode {
    match intent {
        SandboxMode::Off => SandboxMode::Off,
        SandboxMode::Refuse => SandboxMode::Refuse,
        SandboxMode::Sandbox | SandboxMode::Container | SandboxMode::ContainerReadonly => {
            if sandbox_mode_available(intent, caps) {
                intent
            } else {
                SandboxMode::Refuse
            }
        }
    }
}

/// Reason and optional fix command when `intent` cannot be honored.
///
/// `None` when `intent` is Off or the snapshot can honor it.
pub fn sandbox_capability_unavailable_notice(
    intent: SandboxMode,
    caps: &HostCapabilitySnapshot,
) -> Option<(String, Option<String>)> {
    if matches!(intent, SandboxMode::Off) || sandbox_mode_available(intent, caps) {
        return None;
    }
    let row = capability_row_for_mode(intent, caps);
    let reason = row.map(|row| row.reason.clone()).unwrap_or_else(|| {
        if caps.generation == 0 && caps.features.is_empty() {
            format!(
                "{} is unavailable because the host capability snapshot is unpublished",
                sandbox_mode_label(intent)
            )
        } else {
            format!("{} is unavailable", sandbox_mode_label(intent))
        }
    });
    Some((reason, row.and_then(|row| row.fix_command.clone())))
}

/// User-facing capability reason for a fail-closed session.
pub fn fail_closed_capability_reason(intent: SandboxMode, caps: &HostCapabilitySnapshot) -> String {
    sandbox_capability_unavailable_notice(intent, caps)
        .map(|(reason, _)| reason)
        .unwrap_or_else(|| format!("{} is unavailable", sandbox_mode_label(intent)))
}

/// Decide a `SetSandbox` request. Unavailable intent is a typed reject and
/// must not be persisted. [`SandboxMode::Refuse`] is not a selectable intent.
pub fn evaluate_set_sandbox(
    requested: SandboxMode,
    persisted_intent: SandboxMode,
    caps: &HostCapabilitySnapshot,
) -> Result<SetSandboxApplied, SandboxCapabilityMissing> {
    if requested == SandboxMode::Refuse {
        return Err(SandboxCapabilityMissing {
            requested,
            persisted_intent,
            effective: effective_sandbox_mode(persisted_intent, caps),
            reason: "refuse is a runtime fail-closed state, not a selectable sandbox mode"
                .to_string(),
            fix_command: None,
        });
    }
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
        SandboxMode::Off | SandboxMode::Refuse => None,
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
        SandboxMode::Refuse => "refuse",
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
                SandboxMode::Refuse,
            ),
            (
                SandboxMode::Sandbox,
                host_failed,
                container_up,
                SandboxMode::Refuse,
            ),
            (
                SandboxMode::Sandbox,
                host_unsupported,
                container_up,
                SandboxMode::Refuse,
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
                SandboxMode::Refuse,
            ),
            (
                SandboxMode::Container,
                host_up,
                container_failed,
                SandboxMode::Refuse,
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
                SandboxMode::Refuse,
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
    fn host_sandbox_missing_refuses_instead_of_off() {
        let caps = sandbox_capability_snapshot(
            FeatureCapabilityState::Missing,
            FeatureCapabilityState::Available,
        );
        let effective = effective_sandbox_mode(SandboxMode::Sandbox, &caps);
        assert_eq!(effective, SandboxMode::Refuse);
        assert!(
            effective.enabled() && effective.refuses(),
            "missing host sandbox is effective Refuse, never silent Off"
        );
    }

    #[test]
    fn unpublished_snapshot_refuses_host_sandbox() {
        let caps = HostCapabilitySnapshot {
            generation: 0,
            features: Vec::new(),
            dependencies: Vec::new(),
            secret_store: SecretStoreSnapshot::unconfigured_placeholder(),
        };
        assert_eq!(
            effective_sandbox_mode(SandboxMode::Sandbox, &caps),
            SandboxMode::Refuse
        );
        assert!(evaluate_set_sandbox(SandboxMode::Sandbox, SandboxMode::Off, &caps).is_err());
        let notice = sandbox_capability_unavailable_notice(SandboxMode::Sandbox, &caps)
            .expect("unpublished snapshot must surface a fail-closed notice");
        assert!(
            notice.0.contains("unpublished"),
            "unpublished snapshot notice: {}",
            notice.0
        );
    }

    #[test]
    fn container_unavailable_refuses_not_host_sandbox() {
        let caps = sandbox_capability_snapshot(
            FeatureCapabilityState::Available,
            FeatureCapabilityState::Missing,
        );
        assert_eq!(
            effective_sandbox_mode(SandboxMode::Container, &caps),
            SandboxMode::Refuse
        );
        assert_eq!(
            effective_sandbox_mode(SandboxMode::ContainerReadonly, &caps),
            SandboxMode::Refuse
        );
        assert_ne!(
            effective_sandbox_mode(SandboxMode::Container, &caps),
            SandboxMode::Sandbox,
            "unavailable container must not silently rewrite to host Sandbox"
        );
        assert_ne!(
            effective_sandbox_mode(SandboxMode::Container, &caps),
            SandboxMode::Off,
            "unavailable container must not silently fail open to Off"
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
    fn windows_unsupported_host_sandbox_is_effective_refuse() {
        let caps = sandbox_capability_snapshot(
            FeatureCapabilityState::Unsupported,
            FeatureCapabilityState::Missing,
        );
        assert_eq!(
            effective_sandbox_mode(SandboxMode::Sandbox, &caps),
            SandboxMode::Refuse
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

    #[test]
    fn configured_sandbox_refuses_for_missing_failed_and_empty_snapshot() {
        let missing = sandbox_capability_snapshot(
            FeatureCapabilityState::Missing,
            FeatureCapabilityState::Available,
        );
        let failed = sandbox_capability_snapshot(
            FeatureCapabilityState::Failed,
            FeatureCapabilityState::Available,
        );
        let empty = unpublished_host_capability_snapshot();
        for (caps, label) in [
            (missing, "missing"),
            (failed, "failed"),
            (empty, "empty-snapshot"),
        ] {
            let effective = effective_sandbox_mode(SandboxMode::Sandbox, &caps);
            assert_eq!(
                effective,
                SandboxMode::Refuse,
                "intent=Sandbox capability {label} must refuse, not fail open"
            );
            assert!(
                sandbox_capability_unavailable_notice(SandboxMode::Sandbox, &caps).is_some(),
                "intent=Sandbox capability {label} must surface a notice"
            );
        }
    }

    #[test]
    fn set_sandbox_rejects_refuse_as_requested_intent() {
        let caps = sandbox_capability_snapshot(
            FeatureCapabilityState::Available,
            FeatureCapabilityState::Available,
        );
        let err = evaluate_set_sandbox(SandboxMode::Refuse, SandboxMode::Sandbox, &caps)
            .expect_err("Refuse is not a selectable intent");
        assert_eq!(err.requested, SandboxMode::Refuse);
        assert_eq!(err.persisted_intent, SandboxMode::Sandbox);
        assert_eq!(err.effective, SandboxMode::Sandbox);
    }

    #[test]
    fn explicit_off_stays_off_when_capabilities_are_down() {
        let caps = sandbox_capability_snapshot(
            FeatureCapabilityState::Failed,
            FeatureCapabilityState::Failed,
        );
        assert_eq!(
            effective_sandbox_mode(SandboxMode::Off, &caps),
            SandboxMode::Off
        );
        assert!(sandbox_capability_unavailable_notice(SandboxMode::Off, &caps).is_none());
    }
}
