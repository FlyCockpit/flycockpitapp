//! Typed external-runtime dependency health foundation.
//!
//! Provides a closed descriptor schema, feature-owned registration, immutable
//! generation-tagged snapshots, bounded trusted-catalog probes, and
//! resolution-only handling of user-configured commands.
//!
//! Health is in-memory only and is never persisted. Remedies never execute
//! package managers, elevation, downloads, browsers, auth, or runtime mutation.

mod adapters;
mod health;
mod platform;
mod probe;
mod projection;
mod registry;
mod safety_adapters;
mod sanitize;
mod schema;

#[cfg(test)]
mod tests;

pub use adapters::{
    ConfiguredCommandInput, GhAuthState, ID_ACCEL_FD, ID_ACCEL_GSED, ID_ACCEL_RG, ID_GH, ID_GIT,
    ID_HARNESS_CLAUDE, ID_HARNESS_CODEX, ID_HARNESS_GEMINI, ID_HARNESS_OPENCODE, ID_JQ_EXTERNAL,
    ID_KCL, ID_LAZYGIT, IntegrationHealthComposeInput, LaunchGateError, accelerator_adapter_id,
    assert_catalog_discovery_is_safe, catalog_adapter_descriptors,
    cockpit_owned_jq_requires_host_jq, compose_settings_doctor_health,
    compose_settings_doctor_health_with_executor, custom_harness_id, discovery_performs_gh_auth,
    discovery_probe_argv_is_safe, discovery_side_effects_forbidden,
    ensure_integration_adapters_registered, external_jq_adapter_id, gh_binary_health_implies_auth,
    global_health_store, harness_compose_inputs, known_catalog_adapter_ids,
    known_harness_preset_names, lsp_command_input, lsp_server_id, mcp_stdio_input,
    register_integration_adapters, require_available_for_launch,
    require_available_for_launch_uncancelled, require_configured_command_available_for_launch,
    require_configured_command_available_for_launch_with_cancel, require_live_available_for_launch,
    require_live_available_for_launch_with_cancel, stdio_mcp_id, upsert_custom_harness,
    upsert_custom_harnesses, upsert_lsp_server, upsert_lsp_servers, upsert_stdio_mcp,
    upsert_stdio_mcp_servers,
};
pub(crate) use adapters::{
    compose_settings_doctor_health_for_invocation, invocation_descriptor_roster,
    publish_invocation_descriptor_roster,
};
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
pub use projection::{
    DEPENDENCY_HEADLESS_SCHEMA_VERSION, DependenciesPageState, DependencyProjection,
    DependencyProjectionRow, DependencyStartupPolicy, DependencyViewState,
    current_dependency_context_line, current_startup_dependency_policy,
    freeze_pending_as_timed_out, project_dependencies, startup_dependency_policy,
};
pub use safety_adapters::{
    ContainerEngineMode, ContainerEngineSelection, ContainerRuntime as SafetyContainerRuntime,
    FORBIDDEN_MUTATING_PROBE_VERBS, ID_BUBBLEWRAP, ID_DOCKER, ID_IMPORT, ID_PODMAN, ID_SCROT,
    ID_XDOTOOL, ID_XVFB, bubblewrap_requirement_group, classify_container_daemon_failure,
    computer_use_requirement_group, container_probe_argv_is_readonly, container_reason_from_health,
    container_version_evidence_is_valid, current_container_engine_mode,
    detect_container_runtime_health, ensure_container_engine_adapters_registered,
    ensure_safety_adapters_registered, known_global_safety_adapter_ids, known_safety_adapter_ids,
    probe_argv_forbids_mutation, publish_safety_refresh, refresh_safety_snapshot,
    register_safety_adapters, resolve_container_engine, safety_adapter_descriptors,
    set_container_engine_mode,
};
// SystemProbeExecutor is used by container::detect_runtime production path.
// CancelToken is re-exported above for launch-gate callers.
pub use registry::{ExternalRuntimeRegistry, RegistryError, global_registry};
pub use sanitize::sanitize_version_evidence;
pub use schema::{
    Applicability, CompatibilityRule, DependencyImportance, ExternalRuntimeDescriptor,
    ExternalRuntimeDescriptorBuilder, ExternalRuntimeId, ExternalRuntimeOwner,
    ExternalRuntimeSchemaDocument, FUNCTIONAL_PROBE_DEADLINE, HostPlatform, PROBE_CAPTURE_BUDGET,
    ProbePolicy, RemedyKind, RequirementGroup, SchemaError, TrustedCatalogPolicy,
    VERSION_EVIDENCE_BUDGET, VERSION_PROBE_DEADLINE, VersionParser,
};
