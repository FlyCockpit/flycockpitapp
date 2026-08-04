//! Typed external-runtime dependency health foundation.
//!
//! Provides a closed descriptor schema, feature-owned registration, immutable
//! generation-tagged snapshots, bounded trusted-catalog probes, and
//! resolution-only handling of user-configured commands.
//!
//! Health is in-memory only and is never persisted. Remedies never execute
//! package managers, elevation, downloads, browsers, auth, or runtime mutation.

mod health;
mod platform;
mod probe;
mod registry;
mod sanitize;
mod schema;

#[cfg(test)]
mod tests;

pub use health::{
    ExternalRuntimeSnapshot, GroupHealth, HealthCause, HealthEntry, HealthSnapshotStore,
    HealthState, SpawnFailureKind, evaluate_requirement_group,
};
pub use platform::{
    common_platform_remedy, configured_command_remedy, detect_host_platform,
    detect_host_platform_from, package_remedy_table,
};
pub use probe::{
    CancelToken, EvaluationContext, ProbeCommandResult, ProbeDeadlines, ProbeExecutor,
    RecordingProbeExecutor, RunRecord, SystemProbeExecutor, evaluate_descriptor, refresh_snapshot,
};
pub use registry::{ExternalRuntimeRegistry, RegistryError, global_registry};
pub use sanitize::sanitize_version_evidence;
pub use schema::{
    Applicability, CompatibilityRule, DependencyImportance, ExternalRuntimeDescriptor,
    ExternalRuntimeDescriptorBuilder, ExternalRuntimeId, ExternalRuntimeOwner,
    ExternalRuntimeSchemaDocument, FUNCTIONAL_PROBE_DEADLINE, HostPlatform, PROBE_CAPTURE_BUDGET,
    ProbePolicy, RemedyKind, RequirementGroup, SchemaError, TrustedCatalogPolicy,
    VERSION_EVIDENCE_BUDGET, VERSION_PROBE_DEADLINE, VersionParser,
};
