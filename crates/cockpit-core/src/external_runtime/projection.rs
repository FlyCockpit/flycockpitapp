//! One safe, deterministic projection for every dependency-health surface.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::{
    DependencyImportance, ExternalRuntimeDescriptor, ExternalRuntimeSnapshot, HealthCause,
    HealthEntry, HealthState, HostPlatform, RemedyKind,
};
use crate::capabilities::ExecutionTarget;

pub const DEPENDENCY_HEADLESS_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencyViewState {
    Pending,
    Available,
    Missing,
    Incompatible,
    TimedOut,
    Failed,
    Unknown,
    NotApplicable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DependencyProjectionRow {
    pub id: String,
    pub state: DependencyViewState,
    pub importance: DependencyImportance,
    pub target: ExecutionTarget,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub discovered_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cause: Option<HealthCause>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remedy: Option<RemedyKind>,
    /// Canonical bounded reason text reused byte-for-byte by text surfaces.
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DependencyProjection {
    pub schema_version: u32,
    pub generation: u64,
    pub platform: HostPlatform,
    pub rows: Vec<DependencyProjectionRow>,
}

impl DependencyProjection {
    pub fn has_required_failures(&self) -> bool {
        self.rows.iter().any(|row| {
            is_required(row.importance)
                && !matches!(
                    row.state,
                    DependencyViewState::Available | DependencyViewState::NotApplicable
                )
        })
    }

    pub fn render_lines(&self) -> Vec<String> {
        self.rows
            .iter()
            .map(|row| format!("{}: {}", row.id, row.reason))
            .collect()
    }

    /// Canonical contextual failure text. This is deliberately the exact row
    /// used by Settings, doctor, and headless projections.
    pub fn contextual_line(&self, id: &str) -> Option<String> {
        self.rows
            .iter()
            .find(|row| row.id == id)
            .map(|row| format!("{}: {}", row.id, row.reason))
    }
}

pub fn current_dependency_context_line(id: &str) -> Option<String> {
    let snapshot = super::global_health_store().current()?;
    let projection = project_dependencies(
        Some(snapshot.as_ref()),
        &super::global_registry().descriptors(),
    );
    projection.contextual_line(id)
}

fn is_required(importance: DependencyImportance) -> bool {
    matches!(
        importance,
        DependencyImportance::RequiredForDefaultSafety
            | DependencyImportance::RequiredWhenFeatureSelected
    )
}

pub fn project_dependencies(
    snapshot: Option<&ExternalRuntimeSnapshot>,
    descriptors: &[ExternalRuntimeDescriptor],
) -> DependencyProjection {
    let generation = snapshot.map_or(0, |value| value.generation);
    let platform = snapshot.map_or_else(super::detect_host_platform, |value| value.platform);
    let descriptor_by_id: BTreeMap<_, _> = descriptors
        .iter()
        .map(|descriptor| (descriptor.id.as_str(), descriptor))
        .collect();
    let mut ids: Vec<String> = descriptor_by_id.keys().map(|id| (*id).to_owned()).collect();
    if let Some(snapshot) = snapshot {
        ids.extend(
            snapshot
                .entries
                .keys()
                .filter(|id| !descriptor_by_id.contains_key(id.as_str()))
                .cloned(),
        );
    }
    ids.sort();
    ids.dedup();
    let mut rows: Vec<_> = ids
        .into_iter()
        .map(|id| {
            let descriptor = descriptor_by_id.get(id.as_str()).copied();
            let entry = snapshot.and_then(|value| value.get(&id));
            let mut row = project_row(&id, entry, descriptor, platform);
            let feature = descriptor.map(|value| value.owner.feature.as_str());
            let group_available = snapshot.is_some_and(|value| {
                feature
                    .and_then(|name| value.groups.get(name))
                    .is_some_and(super::GroupHealth::is_available)
                    || ([super::ID_DOCKER, super::ID_PODMAN].contains(&id.as_str())
                        && [super::ID_DOCKER, super::ID_PODMAN]
                            .iter()
                            .any(|candidate| {
                                value
                                    .get(candidate)
                                    .is_some_and(|entry| entry.state.is_available())
                            }))
            });
            if group_available {
                // A satisfied any-of group makes each alternative
                // non-blocking while preserving its own diagnostic state.
                row.importance = DependencyImportance::OptionalIntegration;
            }
            row
        })
        .collect();
    rows.sort_by(|left, right| {
        left.importance
            .cmp(&right.importance)
            .then_with(|| left.id.cmp(&right.id))
    });
    DependencyProjection {
        schema_version: DEPENDENCY_HEADLESS_SCHEMA_VERSION,
        generation,
        platform,
        rows,
    }
}

fn project_row(
    id: &str,
    entry: Option<&HealthEntry>,
    descriptor: Option<&ExternalRuntimeDescriptor>,
    platform: HostPlatform,
) -> DependencyProjectionRow {
    let importance = entry
        .map(|value| value.importance)
        .or_else(|| descriptor.map(|value| value.importance))
        .unwrap_or(DependencyImportance::OptionalIntegration);
    let target = entry
        .map(|value| value.target)
        .or_else(|| descriptor.map(|value| value.target))
        .unwrap_or(ExecutionTarget::Host);
    let remedy = entry
        .and_then(|value| value.remedy.clone())
        .or_else(|| descriptor.map(|value| value.remedy.clone()))
        .map(safe_remedy);
    let required_version = descriptor
        .and_then(|value| value.compatibility.as_ref())
        .map(|rule| match rule {
            super::CompatibilityRule::MinVersion { version } => format!(">={version}"),
            super::CompatibilityRule::ExactVersion { version } => format!("={version}"),
            super::CompatibilityRule::CatalogRule { rule_id } => format!("rule:{rule_id}"),
        });
    let state = entry.map_or(
        HealthState::Unknown {
            cause: HealthCause::NeverProbed,
        },
        |value| value.state.clone(),
    );
    let (state, discovered_version, cause, detail) = match state {
        HealthState::Pending => (
            DependencyViewState::Pending,
            None,
            None,
            "pending".to_owned(),
        ),
        HealthState::Available {
            version_evidence, ..
        } => (
            DependencyViewState::Available,
            version_evidence,
            None,
            "available".to_owned(),
        ),
        HealthState::Missing => (
            DependencyViewState::Missing,
            None,
            Some(HealthCause::ResolutionFailed),
            "missing".to_owned(),
        ),
        HealthState::Incompatible { detail } => (
            DependencyViewState::Incompatible,
            None,
            None,
            format!("incompatible ({detail})"),
        ),
        HealthState::TimedOut => (
            DependencyViewState::TimedOut,
            None,
            Some(HealthCause::Cancellation),
            "timed out".to_owned(),
        ),
        HealthState::Failed { cause } => {
            let cause = safe_cause(cause);
            (
                DependencyViewState::Failed,
                None,
                Some(cause.clone()),
                format!("failed ({})", cause_label(&cause)),
            )
        }
        HealthState::Unknown { cause } => {
            let cause = safe_cause(cause);
            (
                DependencyViewState::Unknown,
                None,
                Some(cause.clone()),
                format!("unknown ({})", cause_label(&cause)),
            )
        }
        HealthState::NotApplicable => (
            DependencyViewState::NotApplicable,
            None,
            None,
            "not applicable".to_owned(),
        ),
    };
    let remedy = if matches!(
        state,
        DependencyViewState::Available | DependencyViewState::NotApplicable
    ) {
        None
    } else {
        remedy
    };
    let reason = remedy.as_ref().map_or(detail.clone(), |value| {
        format!("{detail}; {}", value.render_for(platform))
    });
    DependencyProjectionRow {
        id: id.to_owned(),
        state,
        importance,
        target,
        required_version,
        discovered_version,
        cause,
        remedy,
        reason,
    }
}

fn safe_cause(cause: HealthCause) -> HealthCause {
    match cause {
        HealthCause::Internal { .. } => HealthCause::Internal {
            message: "internal diagnostics error".to_owned(),
        },
        other => other,
    }
}

fn safe_remedy(remedy: RemedyKind) -> RemedyKind {
    match remedy {
        RemedyKind::ConfigGuidance { .. } => RemedyKind::config_guidance(
            "Review the configured executable path; configured commands are not executed by diagnostics.",
        ),
        other => other,
    }
}

fn cause_label(cause: &HealthCause) -> &'static str {
    match cause {
        HealthCause::NeverProbed => "not yet probed",
        HealthCause::SpawnFailed { .. } => "spawn failed",
        HealthCause::NonZeroExit { .. } => "non-zero exit",
        HealthCause::OutputParseFailed => "version output invalid",
        HealthCause::Cancellation => "cancelled",
        HealthCause::Internal { .. } => "internal diagnostics error",
        HealthCause::ResolutionFailed => "resolution failed",
        HealthCause::NotSpawnable => "not spawnable",
        HealthCause::PermissionDenied => "permission denied",
        HealthCause::SocketUnavailable => "socket unavailable",
        HealthCause::DaemonUnavailable => "runtime daemon unavailable",
    }
}

pub fn freeze_pending_as_timed_out(snapshot: &ExternalRuntimeSnapshot) -> ExternalRuntimeSnapshot {
    let mut frozen = snapshot.clone();
    for entry in frozen.entries.values_mut() {
        if matches!(entry.state, HealthState::Pending) {
            entry.state = HealthState::TimedOut;
        }
    }
    frozen
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependencyStartupPolicy {
    pub allowed: bool,
    pub summary: Option<String>,
}

pub fn startup_dependency_policy(projection: &DependencyProjection) -> DependencyStartupPolicy {
    let failures: Vec<_> = projection
        .rows
        .iter()
        .filter(|row| {
            is_required(row.importance)
                && !matches!(
                    row.state,
                    DependencyViewState::Available | DependencyViewState::NotApplicable
                )
        })
        .map(|row| format!("{}: {}", row.id, row.reason))
        .collect();
    DependencyStartupPolicy {
        allowed: failures.is_empty(),
        summary: (!failures.is_empty()).then(|| {
            format!(
                "required dependencies unavailable: {}",
                failures.join(" | ")
            )
        }),
    }
}

/// Non-blocking startup read: absence means no completed snapshot yet and does
/// not delay first usable UI.
pub fn current_startup_dependency_policy() -> Option<DependencyStartupPolicy> {
    let snapshot = super::global_health_store().current()?;
    // Startup never invents Unknown rows for catalog entries that have not
    // participated in the latest complete snapshot.
    let descriptors: Vec<_> = super::global_registry()
        .descriptors()
        .into_iter()
        .filter(|descriptor| snapshot.entries.contains_key(descriptor.id.as_str()))
        .collect();
    let projection = project_dependencies(Some(snapshot.as_ref()), &descriptors);
    Some(startup_dependency_policy(&projection))
}

/// Generation gate used by the read-only Settings page. Failed refreshes keep
/// the last complete projection; closing invalidates every in-flight result.
#[derive(Debug, Clone)]
pub struct DependenciesPageState {
    pub displayed: DependencyProjection,
    pub refresh_failure: Option<String>,
    generation: u64,
    open: bool,
}

impl DependenciesPageState {
    pub fn first_paint(
        current: Option<&ExternalRuntimeSnapshot>,
        descriptors: &[ExternalRuntimeDescriptor],
    ) -> Self {
        Self {
            displayed: project_dependencies(current, descriptors),
            refresh_failure: None,
            generation: current.map_or(0, |snapshot| snapshot.generation),
            open: true,
        }
    }

    pub fn begin_refresh(&mut self) -> u64 {
        self.generation = self.generation.saturating_add(1);
        self.refresh_failure = None;
        self.generation
    }

    pub fn apply_success(
        &mut self,
        view_generation: u64,
        projection: DependencyProjection,
    ) -> bool {
        if !self.open || view_generation != self.generation {
            return false;
        }
        self.displayed = projection;
        self.refresh_failure = None;
        true
    }

    pub fn apply_failure(&mut self, view_generation: u64, message: impl Into<String>) -> bool {
        if !self.open || view_generation != self.generation {
            return false;
        }
        self.refresh_failure = Some(message.into());
        true
    }

    pub fn close(&mut self) {
        self.open = false;
        self.generation = self.generation.saturating_add(1);
    }
}
