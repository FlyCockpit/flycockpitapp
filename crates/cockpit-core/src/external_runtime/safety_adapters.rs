//! Read-only safety, container-engine, and Linux computer-use runtime adapters.
//!
//! Registers Bubblewrap, Docker/Podman, and computer-use tooling through the
//! external-runtime foundation. Discovery probes are bounded and read-only:
//! Docker/Podman evidence is only `version` + `info` argv forms. No adapter
//! creates, runs, pulls, stops, or removes containers, images, volumes, or
//! networks during health refresh.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::health::{
    ExternalRuntimeSnapshot, HealthCause, HealthEntry, HealthState, evaluate_requirement_group,
};
use super::platform::package_remedy_table;
use super::probe::{
    CancelToken, EvaluationContext, ProbeDeadlines, ProbeExecutor, evaluate_descriptor,
};
use super::registry::{ExternalRuntimeRegistry, RegistryError};
use super::schema::{
    Applicability, DependencyImportance, ExternalRuntimeDescriptor, HostPlatform, ProbePolicy,
    RemedyKind, RequirementGroup, VersionParser,
};
use crate::capabilities::ExecutionTarget;
use crate::daemon::proto::{
    ContainerAvailability, ContainerRuntimeKind, ContainerUnavailableReason,
};

// ── Stable catalog IDs ──────────────────────────────────────────────────────

/// Bubblewrap host sandbox binary (`bwrap`).
pub const ID_BUBBLEWRAP: &str = "safety.bubblewrap";
/// Docker engine CLI with read-only version+info health.
pub const ID_DOCKER: &str = "container.docker";
/// Podman engine CLI with read-only version+info health.
pub const ID_PODMAN: &str = "container.podman";
/// Xvfb virtual display for Linux computer use.
pub const ID_XVFB: &str = "computer.xvfb";
/// xdotool input automation for Linux computer use.
pub const ID_XDOTOOL: &str = "computer.xdotool";
/// scrot screenshot capture (one arm of scrot-or-import).
pub const ID_SCROT: &str = "computer.scrot";
/// ImageMagick `import` capture (other arm of scrot-or-import).
pub const ID_IMPORT: &str = "computer.import";

/// Closed exact roster of safety/container/computer-use adapters.
pub fn known_safety_adapter_ids() -> &'static [&'static str] {
    &[
        ID_BUBBLEWRAP,
        ID_DOCKER,
        ID_PODMAN,
        ID_XVFB,
        ID_XDOTOOL,
        ID_SCROT,
        ID_IMPORT,
    ]
}

/// Safety adapters registered into the global Settings/doctor catalog.
///
/// Docker/Podman are intentionally **omitted** here: they are probed only
/// through [`refresh_safety_snapshot`] / [`detect_container_runtime_health`]
/// with an explicit [`ContainerEngineMode`]. That keeps Disabled from spawning
/// container probes during generic Settings/doctor refresh.
pub fn known_global_safety_adapter_ids() -> &'static [&'static str] {
    &[ID_BUBBLEWRAP, ID_XVFB, ID_XDOTOOL, ID_SCROT, ID_IMPORT]
}

/// Mutating probe argv verbs that must never appear in read-only evidence probes.
pub const FORBIDDEN_MUTATING_PROBE_VERBS: &[&str] = &[
    "run",
    "create",
    "pull",
    "push",
    "stop",
    "start",
    "restart",
    "kill",
    "rm",
    "rmi",
    "image",
    "volume",
    "network",
    "compose",
    "build",
    "exec",
    "attach",
    "commit",
    "tag",
    "load",
    "save",
    "import",
    "export",
    "system",
    "container",
    "pod",
];

/// True when argv is an allowed Docker/Podman evidence form: only `version` or `info`
/// (optionally with harmless read-only flags such as `--format`).
pub fn container_probe_argv_is_readonly(args: &[String]) -> bool {
    if args.is_empty() {
        return false;
    }
    let head = args[0].as_str();
    if head != "version" && head != "info" {
        return false;
    }
    for arg in &args[1..] {
        let lower = arg.to_ascii_lowercase();
        // Allow only formatting / help-ish flags after the subcommand.
        if lower == "--format" || lower == "-f" || lower.starts_with("--format=") {
            continue;
        }
        if lower.starts_with('-') {
            // Reject other flags that could imply mutation or side effects.
            return false;
        }
        // Bare tokens after version/info are not allowed.
        return false;
    }
    true
}

/// Returns false if any token matches a forbidden mutating verb (case-insensitive).
pub fn probe_argv_forbids_mutation(args: &[impl AsRef<str>]) -> bool {
    for arg in args {
        let token = arg.as_ref().trim_start_matches('-').to_ascii_lowercase();
        // Strip path-like prefix if any.
        let base = token.rsplit('/').next().unwrap_or(&token);
        if FORBIDDEN_MUTATING_PROBE_VERBS.contains(&base) {
            // `import` is forbidden as a docker/podman verb but is a separate
            // ImageMagick binary candidate — only flag when it appears as a
            // subcommand-shaped token in multi-arg engine argv.
            if base == "import" && args.len() == 1 {
                continue;
            }
            return false;
        }
    }
    true
}

/// User/settings container engine selection. Explicit modes never fall back.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContainerEngineMode {
    Disabled,
    Auto,
    Docker,
    Podman,
}

/// Result of resolving a container engine for a generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerEngineSelection {
    pub availability: ContainerAvailability,
    pub runtime: Option<ContainerRuntime>,
}

/// Resolved engine binary for a selected mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerRuntime {
    pub kind: ContainerRuntimeKind,
    pub binary: PathBuf,
}

fn safety_owner(feature: &str) -> (String, String) {
    ("cockpit-core".into(), feature.into())
}

fn linux_computer_platforms() -> Vec<HostPlatform> {
    vec![
        HostPlatform::DebianUbuntu,
        HostPlatform::FedoraRhel,
        HostPlatform::Arch,
        HostPlatform::GenericLinux,
    ]
}

fn version_first_line() -> ProbePolicy {
    ProbePolicy::trusted_catalog(["--version"], VersionParser::FirstLine, None)
}

fn docker_probe_policy() -> ProbePolicy {
    ProbePolicy::trusted_catalog(
        ["version"],
        VersionParser::FirstLine,
        Some(vec!["info".into()]),
    )
}

fn podman_probe_policy() -> ProbePolicy {
    ProbePolicy::trusted_catalog(
        ["version"],
        VersionParser::FirstLine,
        Some(vec!["info".into()]),
    )
}

fn bubblewrap_descriptor() -> Result<ExternalRuntimeDescriptor, super::schema::SchemaError> {
    ExternalRuntimeDescriptor::builder(ID_BUBBLEWRAP)
        .owner("cockpit-core", "shell-sandbox")
        .candidates(["bwrap"])
        .applicability(Applicability::WhenFeatureSelectedOnPlatforms {
            platforms: vec![
                HostPlatform::DebianUbuntu,
                HostPlatform::FedoraRhel,
                HostPlatform::Arch,
                HostPlatform::GenericLinux,
                HostPlatform::OtherUnix,
            ],
        })
        .importance(DependencyImportance::RequiredWhenFeatureSelected)
        .target(ExecutionTarget::Host)
        .probe_policy(version_first_line())
        .remedy(RemedyKind::platform_recipes(
            "Install Bubblewrap (`bwrap`) for the host shell sandbox.",
            package_remedy_table("bubblewrap", "bubblewrap", "bubblewrap", "bubblewrap", None),
        ))
        .build()
}

fn docker_descriptor() -> Result<ExternalRuntimeDescriptor, super::schema::SchemaError> {
    ExternalRuntimeDescriptor::builder(ID_DOCKER)
        .owner(
            safety_owner("container-sandbox").0,
            safety_owner("container-sandbox").1,
        )
        .candidates(["docker"])
        .applicability(Applicability::WhenFeatureSelected)
        .importance(DependencyImportance::RequiredWhenFeatureSelected)
        .target(ExecutionTarget::Host)
        .probe_policy(docker_probe_policy())
        .remedy(RemedyKind::platform_recipes(
            "Install Docker and ensure the daemon is reachable for container sandbox mode.",
            package_remedy_table(
                "docker.io",
                "docker",
                "docker",
                "docker",
                Some("Docker.DockerDesktop"),
            ),
        ))
        .build()
}

fn podman_descriptor() -> Result<ExternalRuntimeDescriptor, super::schema::SchemaError> {
    ExternalRuntimeDescriptor::builder(ID_PODMAN)
        .owner(
            safety_owner("container-sandbox").0,
            safety_owner("container-sandbox").1,
        )
        .candidates(["podman"])
        .applicability(Applicability::WhenFeatureSelected)
        .importance(DependencyImportance::RequiredWhenFeatureSelected)
        .target(ExecutionTarget::Host)
        .probe_policy(podman_probe_policy())
        .remedy(RemedyKind::platform_recipes(
            "Install Podman and ensure the service is reachable for container sandbox mode.",
            package_remedy_table(
                "podman",
                "podman",
                "podman",
                "podman",
                Some("RedHat.Podman"),
            ),
        ))
        .build()
}

fn computer_leaf(
    id: &str,
    candidates: &[&str],
    feature: &str,
    prose: &str,
    packages: (&str, &str, &str, &str, Option<&str>),
) -> Result<ExternalRuntimeDescriptor, super::schema::SchemaError> {
    ExternalRuntimeDescriptor::builder(id)
        .owner(safety_owner(feature).0, safety_owner(feature).1)
        .candidates(candidates.iter().copied())
        .applicability(Applicability::WhenFeatureSelectedOnPlatforms {
            platforms: linux_computer_platforms(),
        })
        .importance(DependencyImportance::RequiredWhenFeatureSelected)
        .target(ExecutionTarget::Host)
        .probe_policy(version_first_line())
        .remedy(RemedyKind::platform_recipes(
            prose,
            package_remedy_table(packages.0, packages.1, packages.2, packages.3, packages.4),
        ))
        .build()
}

/// Descriptors for the closed safety/container/computer-use roster.
pub fn safety_adapter_descriptors() -> Result<Vec<ExternalRuntimeDescriptor>, RegistryError> {
    Ok(vec![
        bubblewrap_descriptor()?,
        docker_descriptor()?,
        podman_descriptor()?,
        computer_leaf(
            ID_XVFB,
            &["Xvfb"],
            "computer-use",
            "Install Xvfb for the Linux computer-use virtual display.",
            (
                "xvfb",
                "xorg-x11-server-Xvfb",
                "xorg-server-xvfb",
                "xvfb",
                None,
            ),
        )?,
        computer_leaf(
            ID_XDOTOOL,
            &["xdotool"],
            "computer-use",
            "Install xdotool for Linux computer-use input automation.",
            ("xdotool", "xdotool", "xdotool", "xdotool", None),
        )?,
        computer_leaf(
            ID_SCROT,
            &["scrot"],
            "computer-use",
            "Install scrot (or ImageMagick `import`) for computer-use screenshots.",
            ("scrot", "scrot", "scrot", "scrot", None),
        )?,
        computer_leaf(
            ID_IMPORT,
            &["import"],
            "computer-use",
            "Install ImageMagick `import` (or scrot) for computer-use screenshots.",
            (
                "imagemagick",
                "ImageMagick",
                "imagemagick",
                "imagemagick",
                None,
            ),
        )?,
    ])
}

/// Register every safety adapter. Fails on duplicate IDs.
pub fn register_safety_adapters(registry: &ExternalRuntimeRegistry) -> Result<(), RegistryError> {
    for descriptor in safety_adapter_descriptors()? {
        registry.register(descriptor)?;
    }
    Ok(())
}

/// Idempotent registration of **global** safety adapters (no docker/podman).
pub fn ensure_safety_adapters_registered(
    registry: &ExternalRuntimeRegistry,
) -> Result<(), RegistryError> {
    let allowed: std::collections::BTreeSet<&str> =
        known_global_safety_adapter_ids().iter().copied().collect();
    for descriptor in safety_adapter_descriptors()? {
        if !allowed.contains(descriptor.id.as_str()) {
            continue;
        }
        match registry.register(descriptor) {
            Ok(()) => {}
            Err(RegistryError::DuplicateId(_)) => {}
            Err(err) => return Err(err),
        }
    }
    Ok(())
}

/// Register docker/podman (and all safety) descriptors for mode-aware health.
pub fn ensure_container_engine_adapters_registered(
    registry: &ExternalRuntimeRegistry,
) -> Result<(), RegistryError> {
    for descriptor in safety_adapter_descriptors()? {
        match registry.register(descriptor) {
            Ok(()) => {}
            Err(RegistryError::DuplicateId(_)) => {}
            Err(err) => return Err(err),
        }
    }
    Ok(())
}

/// Computer-use fail-closed group: Xvfb ∧ xdotool ∧ (scrot ∨ import).
pub fn computer_use_requirement_group() -> RequirementGroup {
    RequirementGroup::all_of([
        RequirementGroup::leaf(ID_XVFB),
        RequirementGroup::leaf(ID_XDOTOOL),
        RequirementGroup::any_of([
            RequirementGroup::leaf(ID_SCROT),
            RequirementGroup::leaf(ID_IMPORT),
        ]),
    ])
}

/// Bubblewrap as a single-leaf required group when shell sandbox is selected.
pub fn bubblewrap_requirement_group() -> RequirementGroup {
    RequirementGroup::leaf(ID_BUBBLEWRAP)
}

/// True when sanitized version evidence looks like a real docker/podman engine.
///
/// Requires an engine name token and a dotted numeric version (e.g. `24.0.0`),
/// so strings like `Docker error 500` or `podman failed 1` are rejected.
pub fn container_version_evidence_is_valid(runtime_id: &str, evidence: &str) -> bool {
    let lower = evidence.to_ascii_lowercase();
    if lower.trim().is_empty() {
        return false;
    }
    let engine_ok = match runtime_id {
        ID_DOCKER => lower.contains("docker") || lower.contains("moby"),
        ID_PODMAN => lower.contains("podman"),
        _ => true,
    };
    if !engine_ok {
        return false;
    }
    // Reject obvious non-version diagnostics that still mention the engine.
    for bad in [
        "error",
        "failed",
        "cannot",
        "permission",
        "denied",
        "unknown",
        "shim",
        "wrapper",
        "mock",
        "fake",
    ] {
        if lower.contains(bad) {
            return false;
        }
    }
    // Require a dotted version token with at least major.minor digits.
    lower
        .split(|c: char| c.is_whitespace() || c == ',' || c == ';')
        .any(|tok| {
            let tok = tok.trim_matches(|c: char| !c.is_ascii_digit() && c != '.');
            let mut parts = tok.split('.');
            let Some(major) = parts.next() else {
                return false;
            };
            let Some(minor) = parts.next() else {
                return false;
            };
            !major.is_empty()
                && major.chars().all(|c| c.is_ascii_digit())
                && !minor.is_empty()
                && minor.chars().all(|c| c.is_ascii_digit())
        })
}

/// Classify Docker/Podman `info` (or similar) non-zero/error output into typed causes.
///
/// Uses only coarse lowercase substring classes — never returns raw paths or
/// environment dumps.
pub fn classify_container_daemon_failure(
    combined_output: &str,
    exit_code: Option<i32>,
) -> HealthCause {
    let lower = combined_output.to_ascii_lowercase();
    if lower.contains("permission denied")
        || lower.contains("access denied")
        || lower.contains("operation not permitted")
        || lower.contains("not allowed")
    {
        return HealthCause::PermissionDenied;
    }
    // Daemon-not-running messages take priority over socket path substrings that
    // often appear in the same diagnostic line (e.g. docker.sock in a daemon error).
    if lower.contains("is the docker daemon running")
        || lower.contains("cannot connect to the docker daemon")
        || lower.contains("daemon is not running")
        || lower.contains("cannot connect to podman")
        || lower.contains("failed to connect")
        || lower.contains("connection refused")
    {
        return HealthCause::DaemonUnavailable;
    }
    if lower.contains("no such file or directory")
        && (lower.contains("sock") || lower.contains("docker.sock") || lower.contains("podman"))
        || lower.contains("dial unix")
        || lower.contains("connect: no such file")
        || (lower.contains("socket")
            && (lower.contains("connect")
                || lower.contains("dial")
                || lower.contains("unavailable")
                || lower.contains("no such file")))
    {
        return HealthCause::SocketUnavailable;
    }
    HealthCause::NonZeroExit { code: exit_code }
}

/// Map a health entry for docker/podman into a container-unavailable reason.
pub fn container_reason_from_health(entry: &HealthEntry) -> Option<ContainerUnavailableReason> {
    match &entry.state {
        HealthState::Available { .. } => None,
        HealthState::Missing | HealthState::NotApplicable => {
            Some(ContainerUnavailableReason::NoRuntime)
        }
        HealthState::TimedOut => Some(ContainerUnavailableReason::NoRuntime),
        HealthState::Failed { cause } | HealthState::Unknown { cause } => match cause {
            HealthCause::PermissionDenied => Some(ContainerUnavailableReason::PermissionDenied),
            HealthCause::SocketUnavailable => Some(ContainerUnavailableReason::SocketUnavailable),
            HealthCause::DaemonUnavailable => Some(ContainerUnavailableReason::DaemonUnavailable),
            HealthCause::SpawnFailed {
                failure: super::health::SpawnFailureKind::PermissionDenied,
            } => Some(ContainerUnavailableReason::PermissionDenied),
            _ => Some(ContainerUnavailableReason::NoRuntime),
        },
        HealthState::Incompatible { .. } | HealthState::Pending => {
            Some(ContainerUnavailableReason::NoRuntime)
        }
    }
}

fn entry_available(entry: Option<&HealthEntry>) -> bool {
    entry.is_some_and(|e| e.state.is_available())
}

fn resolved_path(entry: Option<&HealthEntry>) -> Option<PathBuf> {
    match entry.map(|e| &e.state) {
        Some(HealthState::Available {
            resolved_path: Some(path),
            ..
        }) => Some(path.clone()),
        _ => None,
    }
}

/// Resolve container engine for a mode using **health**, not binary presence alone.
///
/// - `Disabled` performs no selection (unavailable, no reason probe).
/// - `Auto` prefers healthy Docker, then healthy Podman, from one generation.
/// - Explicit `Docker` / `Podman` fail closed with no cross-engine fallback.
/// - Nested harness always yields [`ContainerUnavailableReason::HarnessInContainer`].
pub fn resolve_container_engine(
    mode: ContainerEngineMode,
    snapshot: &ExternalRuntimeSnapshot,
    harness_in_container: bool,
) -> ContainerEngineSelection {
    if harness_in_container {
        return ContainerEngineSelection {
            availability: ContainerAvailability {
                runtime: None,
                harness_in_container: true,
                available: false,
                reason: Some(ContainerUnavailableReason::HarnessInContainer),
            },
            runtime: None,
        };
    }

    if matches!(mode, ContainerEngineMode::Disabled) {
        return ContainerEngineSelection {
            availability: ContainerAvailability {
                runtime: None,
                harness_in_container: false,
                available: false,
                reason: Some(ContainerUnavailableReason::NoRuntime),
            },
            runtime: None,
        };
    }

    let docker = snapshot.get(ID_DOCKER);
    let podman = snapshot.get(ID_PODMAN);

    match mode {
        ContainerEngineMode::Disabled => unreachable!(),
        ContainerEngineMode::Docker => select_explicit(
            ContainerRuntimeKind::Docker,
            docker,
            ContainerUnavailableReason::NoRuntime,
        ),
        ContainerEngineMode::Podman => select_explicit(
            ContainerRuntimeKind::Podman,
            podman,
            ContainerUnavailableReason::NoRuntime,
        ),
        ContainerEngineMode::Auto => {
            if entry_available(docker) {
                return select_explicit(
                    ContainerRuntimeKind::Docker,
                    docker,
                    ContainerUnavailableReason::NoRuntime,
                );
            }
            if entry_available(podman) {
                return select_explicit(
                    ContainerRuntimeKind::Podman,
                    podman,
                    ContainerUnavailableReason::NoRuntime,
                );
            }
            // Prefer a typed docker failure reason when docker was present but unhealthy.
            let reason = docker
                .and_then(container_reason_from_health)
                .or_else(|| podman.and_then(container_reason_from_health))
                .unwrap_or(ContainerUnavailableReason::NoRuntime);
            ContainerEngineSelection {
                availability: ContainerAvailability {
                    runtime: None,
                    harness_in_container: false,
                    available: false,
                    reason: Some(reason),
                },
                runtime: None,
            }
        }
    }
}

fn select_explicit(
    kind: ContainerRuntimeKind,
    entry: Option<&HealthEntry>,
    default_reason: ContainerUnavailableReason,
) -> ContainerEngineSelection {
    if entry_available(entry) {
        let binary = resolved_path(entry).unwrap_or_else(|| PathBuf::from(kind.as_str()));
        return ContainerEngineSelection {
            availability: ContainerAvailability {
                runtime: Some(kind),
                harness_in_container: false,
                available: true,
                reason: None,
            },
            runtime: Some(ContainerRuntime { kind, binary }),
        };
    }
    let reason = entry
        .and_then(container_reason_from_health)
        .unwrap_or(default_reason);
    ContainerEngineSelection {
        availability: ContainerAvailability {
            runtime: Some(kind),
            harness_in_container: false,
            available: false,
            reason: Some(reason),
        },
        runtime: None,
    }
}

/// Evaluate safety descriptors into a generation-tagged snapshot using the
/// given executor (tests inject recordings; production uses system probes).
///
/// When `mode` is [`ContainerEngineMode::Disabled`], Docker/Podman descriptors
/// are recorded as NotApplicable and **no** container probe is spawned.
/// Explicit Docker/Podman modes only probe the selected engine.
#[allow(clippy::too_many_arguments)]
pub fn refresh_safety_snapshot(
    registry: &ExternalRuntimeRegistry,
    executor: &dyn ProbeExecutor,
    path_env: Option<&str>,
    cwd: &Path,
    ctx: &EvaluationContext,
    deadlines: ProbeDeadlines,
    cancel: &CancelToken,
    generation: u64,
    mode: ContainerEngineMode,
) -> ExternalRuntimeSnapshot {
    let _ = ensure_container_engine_adapters_registered(registry);
    let descriptors: Vec<_> = known_safety_adapter_ids()
        .iter()
        .filter_map(|id| registry.get(id))
        .collect();
    let mut entries = BTreeMap::new();
    for descriptor in &descriptors {
        let id = descriptor.id.as_str();
        let skip_container = match mode {
            ContainerEngineMode::Disabled => id == ID_DOCKER || id == ID_PODMAN,
            ContainerEngineMode::Docker => id == ID_PODMAN,
            ContainerEngineMode::Podman => id == ID_DOCKER,
            ContainerEngineMode::Auto => false,
        };
        if skip_container {
            entries.insert(
                id.to_string(),
                HealthEntry {
                    id: descriptor.id.clone(),
                    state: HealthState::NotApplicable,
                    importance: descriptor.importance,
                    target: descriptor.target,
                    remedy: None,
                    platform: ctx.platform,
                },
            );
            continue;
        }
        let entry =
            evaluate_descriptor(descriptor, executor, path_env, cwd, ctx, deadlines, cancel);
        entries.insert(descriptor.id.as_str().to_string(), entry);
    }
    let mut snapshot = ExternalRuntimeSnapshot {
        generation,
        platform: ctx.platform,
        entries,
        groups: BTreeMap::new(),
    };
    snapshot.groups.insert(
        "computer-use".into(),
        evaluate_requirement_group(&computer_use_requirement_group(), &snapshot),
    );
    snapshot.groups.insert(
        "bubblewrap".into(),
        evaluate_requirement_group(&bubblewrap_requirement_group(), &snapshot),
    );
    snapshot
}

/// Refresh safety adapters through [`HealthSnapshotStore`] generation gates.
///
/// Returns the snapshot only when publish succeeds (latest reserved generation).
/// Late completions of older reservations return `None`.
#[allow(clippy::too_many_arguments)]
pub fn publish_safety_refresh(
    store: &super::health::HealthSnapshotStore,
    registry: &ExternalRuntimeRegistry,
    executor: &dyn ProbeExecutor,
    path_env: Option<&str>,
    cwd: &Path,
    ctx: &EvaluationContext,
    deadlines: ProbeDeadlines,
    cancel: &CancelToken,
    mode: ContainerEngineMode,
) -> Option<ExternalRuntimeSnapshot> {
    let generation = store.begin_refresh();
    let snapshot = refresh_safety_snapshot(
        registry, executor, path_env, cwd, ctx, deadlines, cancel, generation, mode,
    );
    if store.publish(snapshot.clone()) {
        Some(snapshot)
    } else {
        None
    }
}

/// Production-facing detection: read-only health probes + mode selection.
///
/// Uses the external-runtime registry and system (or injected) probe executor.
/// Never mutates containers/images/volumes/networks.
pub fn detect_container_runtime_health(
    mode: ContainerEngineMode,
    executor: &dyn ProbeExecutor,
    harness_in_container: bool,
    platform: HostPlatform,
) -> ContainerEngineSelection {
    if harness_in_container {
        return resolve_container_engine(mode, &ExternalRuntimeSnapshot::empty(0, platform), true);
    }
    if matches!(mode, ContainerEngineMode::Disabled) {
        return resolve_container_engine(mode, &ExternalRuntimeSnapshot::empty(0, platform), false);
    }
    // Private registry — never pollute the process-global Settings/doctor catalog
    // with Docker/Podman descriptors (mode-aware probing only).
    let registry = ExternalRuntimeRegistry::new();
    let _ = ensure_container_engine_adapters_registered(&registry);
    let mut features = std::collections::BTreeSet::new();
    features.insert("container-sandbox".into());
    let ctx = EvaluationContext {
        platform,
        selected_features: features,
    };
    let cancel = CancelToken::new();
    let generation = 1;
    let snapshot = refresh_safety_snapshot(
        &registry,
        executor,
        None,
        Path::new("/"),
        &ctx,
        ProbeDeadlines::default(),
        &cancel,
        generation,
        mode,
    );
    resolve_container_engine(mode, &snapshot, false)
}

/// Process-default container engine mode (Settings/config can update later).
static CONTAINER_ENGINE_MODE: std::sync::RwLock<ContainerEngineMode> =
    std::sync::RwLock::new(ContainerEngineMode::Auto);

/// Read the process-default container engine mode.
pub fn current_container_engine_mode() -> ContainerEngineMode {
    *CONTAINER_ENGINE_MODE
        .read()
        .unwrap_or_else(|p| p.into_inner())
}

/// Set the process-default container engine mode used by [`crate::container::detect_runtime`].
pub fn set_container_engine_mode(mode: ContainerEngineMode) {
    *CONTAINER_ENGINE_MODE
        .write()
        .unwrap_or_else(|p| p.into_inner()) = mode;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::external_runtime::health::{GroupHealth, HealthState, SpawnFailureKind};
    use crate::external_runtime::probe::{
        ProbeCommandResult, ProbeDeadlines, RecordingProbeExecutor,
    };
    use crate::external_runtime::schema::{ExternalRuntimeId, HostPlatform};
    use std::time::Duration;

    // current_container_engine_mode / set_container_engine_mode / detect_container_runtime_health
    // are in super.

    fn ctx_linux_with_features(features: &[&str]) -> EvaluationContext {
        let mut selected = std::collections::BTreeSet::new();
        for f in features {
            selected.insert((*f).to_string());
        }
        EvaluationContext {
            platform: HostPlatform::DebianUbuntu,
            selected_features: selected,
        }
    }

    #[test]
    fn safety_runtime_adapter_roster() {
        let ids: Vec<_> = known_safety_adapter_ids().to_vec();
        assert!(ids.contains(&ID_BUBBLEWRAP));
        assert!(ids.contains(&ID_DOCKER));
        assert!(ids.contains(&ID_PODMAN));
        assert!(ids.contains(&ID_XVFB));
        assert!(ids.contains(&ID_XDOTOOL));
        assert!(ids.contains(&ID_SCROT));
        assert!(ids.contains(&ID_IMPORT));
        let registry = ExternalRuntimeRegistry::new();
        register_safety_adapters(&registry).unwrap();
        for id in known_safety_adapter_ids() {
            assert!(registry.get(id).is_some(), "missing {id}");
        }
    }

    #[test]
    fn docker_and_podman_probe_argv_are_readonly_version_and_info_only() {
        let docker = docker_descriptor().unwrap();
        let policy = docker.probe_policy.as_trusted_catalog().unwrap();
        assert!(container_probe_argv_is_readonly(policy.version_argv()));
        assert!(container_probe_argv_is_readonly(
            policy.functional_argv().unwrap()
        ));
        assert!(probe_argv_forbids_mutation(policy.version_argv()));
        assert!(probe_argv_forbids_mutation(
            policy.functional_argv().unwrap()
        ));

        let podman = podman_descriptor().unwrap();
        let policy = podman.probe_policy.as_trusted_catalog().unwrap();
        assert!(container_probe_argv_is_readonly(policy.version_argv()));
        assert!(container_probe_argv_is_readonly(
            policy.functional_argv().unwrap()
        ));

        // Forbidden mutating forms
        assert!(!container_probe_argv_is_readonly(&[
            "run".into(),
            "-d".into(),
            "nginx".into()
        ]));
        assert!(!container_probe_argv_is_readonly(&[
            "pull".into(),
            "alpine".into()
        ]));
        assert!(!container_probe_argv_is_readonly(&[
            "rm".into(),
            "-f".into(),
            "x".into()
        ]));
        assert!(!probe_argv_forbids_mutation(&["run", "nginx"]));
        assert!(!probe_argv_forbids_mutation(&["image", "rm", "x"]));
        assert!(!probe_argv_forbids_mutation(&["volume", "create", "v"]));
        assert!(!probe_argv_forbids_mutation(&["network", "rm", "n"]));
    }

    #[test]
    fn docker_read_only_health_probe_spawns_only_version_and_info() {
        let registry = ExternalRuntimeRegistry::new();
        register_safety_adapters(&registry).unwrap();
        let executor = RecordingProbeExecutor::new().with_resolve("docker", "/usr/bin/docker");
        executor.set_handler(|_program, args| {
            assert!(
                container_probe_argv_is_readonly(args),
                "mutating argv reached probe: {args:?}"
            );
            ProbeCommandResult {
                exit_code: Some(0),
                stdout: b"Docker version 24.0.0\n".to_vec(),
                stderr: Vec::new(),
                timed_out: false,
                cancelled: false,
                spawn_error: None,
            }
        });
        let snap = refresh_safety_snapshot(
            &registry,
            &executor,
            None,
            Path::new("/"),
            &ctx_linux_with_features(&["container-sandbox"]),
            ProbeDeadlines::default(),
            &CancelToken::new(),
            1,
            ContainerEngineMode::Auto,
        );
        let entry = snap.get(ID_DOCKER).unwrap();
        assert!(entry.state.is_available());
        let log = executor.run_log.lock().unwrap().clone();
        assert!(
            log.iter()
                .all(|r| container_probe_argv_is_readonly(&r.args)),
            "log={log:?}"
        );
        assert!(
            log.iter()
                .any(|r| r.args.first().map(String::as_str) == Some("version"))
        );
        assert!(
            log.iter()
                .any(|r| r.args.first().map(String::as_str) == Some("info"))
        );
        // Never a mutating verb.
        for r in &log {
            assert!(probe_argv_forbids_mutation(&r.args));
        }
    }

    #[test]
    fn podman_read_only_health_probe_spawns_only_version_and_info() {
        let registry = ExternalRuntimeRegistry::new();
        register_safety_adapters(&registry).unwrap();
        let executor = RecordingProbeExecutor::new().with_resolve("podman", "/usr/bin/podman");
        executor.set_handler(|_program, args| {
            assert!(container_probe_argv_is_readonly(args));
            ProbeCommandResult {
                exit_code: Some(0),
                stdout: b"podman version 4.9.0\n".to_vec(),
                stderr: Vec::new(),
                timed_out: false,
                cancelled: false,
                spawn_error: None,
            }
        });
        let snap = refresh_safety_snapshot(
            &registry,
            &executor,
            None,
            Path::new("/"),
            &ctx_linux_with_features(&["container-sandbox"]),
            ProbeDeadlines::default(),
            &CancelToken::new(),
            1,
            ContainerEngineMode::Podman,
        );
        assert!(snap.get(ID_PODMAN).unwrap().state.is_available());
        // Explicit Podman mode must not probe Docker.
        assert!(matches!(
            snap.get(ID_DOCKER).unwrap().state,
            HealthState::NotApplicable
        ));
        let log = executor.run_log.lock().unwrap().clone();
        assert!(log.iter().all(|r| {
            r.program.ends_with("podman") && container_probe_argv_is_readonly(&r.args)
        }));
    }

    #[test]
    fn disabled_mode_spawns_no_container_probes() {
        let registry = ExternalRuntimeRegistry::new();
        register_safety_adapters(&registry).unwrap();
        let executor = RecordingProbeExecutor::new()
            .with_resolve("docker", "/usr/bin/docker")
            .with_resolve("podman", "/usr/bin/podman");
        let snap = refresh_safety_snapshot(
            &registry,
            &executor,
            None,
            Path::new("/"),
            &ctx_linux_with_features(&["container-sandbox"]),
            ProbeDeadlines::default(),
            &CancelToken::new(),
            1,
            ContainerEngineMode::Disabled,
        );
        assert!(matches!(
            snap.get(ID_DOCKER).unwrap().state,
            HealthState::NotApplicable
        ));
        assert!(matches!(
            snap.get(ID_PODMAN).unwrap().state,
            HealthState::NotApplicable
        ));
        assert_eq!(
            executor.run_count.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "Disabled must not spawn docker/podman probes"
        );
        let sel = resolve_container_engine(ContainerEngineMode::Disabled, &snap, false);
        assert!(!sel.availability.available);
    }

    #[test]
    fn malformed_container_version_output_is_not_available() {
        let registry = ExternalRuntimeRegistry::new();
        register_safety_adapters(&registry).unwrap();
        for (stdout, label) in [
            (b"not an engine at all\n".as_slice(), "no engine token"),
            (b"Docker error 500\n".as_slice(), "error with digit"),
            (b"Docker shim 1\n".as_slice(), "no dotted version"),
            (b"Docker shim 1.2\n".as_slice(), "shim with dotted version"),
            (b"podman failed 404\n".as_slice(), "podman error text"),
        ] {
            let executor = RecordingProbeExecutor::new()
                .with_resolve("docker", "/usr/bin/docker")
                .with_resolve("podman", "/usr/bin/podman");
            let body = stdout.to_vec();
            executor.set_handler(move |_program, _args| ProbeCommandResult {
                exit_code: Some(0),
                stdout: body.clone(),
                stderr: Vec::new(),
                timed_out: false,
                cancelled: false,
                spawn_error: None,
            });
            let mode = if label.contains("podman") {
                ContainerEngineMode::Podman
            } else {
                ContainerEngineMode::Docker
            };
            let id = if label.contains("podman") {
                ID_PODMAN
            } else {
                ID_DOCKER
            };
            let snap = refresh_safety_snapshot(
                &registry,
                &executor,
                None,
                Path::new("/"),
                &ctx_linux_with_features(&["container-sandbox"]),
                ProbeDeadlines::default(),
                &CancelToken::new(),
                1,
                mode,
            );
            assert!(
                matches!(
                    snap.get(id).unwrap().state,
                    HealthState::Failed {
                        cause: HealthCause::OutputParseFailed
                    }
                ),
                "expected parse fail for {label}"
            );
        }
    }

    #[test]
    fn global_safety_registration_excludes_container_engines() {
        let registry = ExternalRuntimeRegistry::new();
        ensure_safety_adapters_registered(&registry).unwrap();
        assert!(registry.get(ID_BUBBLEWRAP).is_some());
        assert!(
            registry.get(ID_DOCKER).is_none(),
            "docker must not be in global doctor catalog"
        );
        assert!(registry.get(ID_PODMAN).is_none());
    }

    #[test]
    fn process_mode_disabled_detect_spawns_no_engine_probes() {
        let previous = current_container_engine_mode();
        set_container_engine_mode(ContainerEngineMode::Disabled);
        let executor = RecordingProbeExecutor::new()
            .with_resolve("docker", "/usr/bin/docker")
            .with_resolve("podman", "/usr/bin/podman");
        let sel = detect_container_runtime_health(
            current_container_engine_mode(),
            &executor,
            false,
            HostPlatform::DebianUbuntu,
        );
        assert!(!sel.availability.available);
        assert_eq!(
            executor.run_count.load(std::sync::atomic::Ordering::SeqCst),
            0
        );
        set_container_engine_mode(previous);
    }

    /// AC5: container-adapter path kills and reaps a real probe child on timeout
    /// (no multi-second sleep; FIFO hang + short deadline).
    #[cfg(unix)]
    #[test]
    fn container_probe_timeout_kills_and_reaps_child() {
        use crate::external_runtime::probe::{SystemProbeExecutor, evaluate_descriptor};
        use crate::external_runtime::schema::{ProbePolicy, VersionParser};
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("hang-docker.sh");
        let pidfile = dir.path().join("child.pid");
        let fifo = dir.path().join("block.fifo");
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$$\" > '{}'\nmkfifo '{}'\nexec cat '{}'\n",
                pidfile.display(),
                fifo.display(),
                fifo.display()
            ),
        )
        .unwrap();
        let mut perms = std::fs::metadata(&script).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&script, perms).unwrap();

        // Same trusted-catalog shape as container.docker (version argv only for this test).
        let descriptor = ExternalRuntimeDescriptor::builder(ID_DOCKER)
            .owner("cockpit-core", "container-sandbox")
            .candidates([script.to_str().unwrap()])
            .applicability(Applicability::Always)
            .importance(DependencyImportance::RequiredWhenFeatureSelected)
            .target(ExecutionTarget::Host)
            .probe_policy(ProbePolicy::trusted_catalog(
                ["version"],
                VersionParser::FirstLine,
                Some(vec!["info".into()]),
            ))
            .remedy(RemedyKind::prose("test hang docker"))
            .build()
            .unwrap();

        let short = ProbeDeadlines {
            version: Duration::from_millis(500),
            functional: Duration::from_millis(500),
        };
        let started = std::time::Instant::now();
        let entry = evaluate_descriptor(
            &descriptor,
            &SystemProbeExecutor,
            None,
            Path::new("/"),
            &ctx_linux_with_features(&["container-sandbox"]),
            short,
            &CancelToken::new(),
        );
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "probe hung instead of kill/reap"
        );
        assert!(
            matches!(entry.state, HealthState::TimedOut),
            "expected TimedOut, got {:?}",
            entry.state
        );
        let pid_txt = std::fs::read_to_string(&pidfile).expect("child never wrote pidfile");
        let pid: i32 = pid_txt.trim().parse().expect("pid");
        let deadline = std::time::Instant::now() + Duration::from_millis(500);
        let mut alive = true;
        while std::time::Instant::now() < deadline {
            let rc = unsafe { libc::kill(pid, 0) };
            if rc != 0 {
                alive = false;
                break;
            }
            std::thread::yield_now();
        }
        assert!(!alive, "child pid {pid} still alive after TimedOut");
    }

    #[test]
    fn container_mode_matrix_disabled_auto_explicit_and_failures() {
        // Build a synthetic snapshot with controlled health.
        let mut snap = ExternalRuntimeSnapshot::empty(1, HostPlatform::DebianUbuntu);
        snap.entries.insert(
            ID_DOCKER.into(),
            HealthEntry {
                id: ExternalRuntimeId::new(ID_DOCKER),
                state: HealthState::Available {
                    resolved_path: Some(PathBuf::from("/usr/bin/docker")),
                    version_evidence: Some("24.0.0".into()),
                },
                importance: DependencyImportance::RequiredWhenFeatureSelected,
                target: ExecutionTarget::Host,
                remedy: None,
                platform: HostPlatform::DebianUbuntu,
            },
        );
        snap.entries.insert(
            ID_PODMAN.into(),
            HealthEntry {
                id: ExternalRuntimeId::new(ID_PODMAN),
                state: HealthState::Available {
                    resolved_path: Some(PathBuf::from("/usr/bin/podman")),
                    version_evidence: Some("4.0.0".into()),
                },
                importance: DependencyImportance::RequiredWhenFeatureSelected,
                target: ExecutionTarget::Host,
                remedy: None,
                platform: HostPlatform::DebianUbuntu,
            },
        );

        // Disabled
        let sel = resolve_container_engine(ContainerEngineMode::Disabled, &snap, false);
        assert!(!sel.availability.available);
        assert!(sel.runtime.is_none());

        // Auto prefers Docker
        let sel = resolve_container_engine(ContainerEngineMode::Auto, &snap, false);
        assert!(sel.availability.available);
        assert_eq!(sel.availability.runtime, Some(ContainerRuntimeKind::Docker));

        // Explicit Podman even when Docker healthy
        let sel = resolve_container_engine(ContainerEngineMode::Podman, &snap, false);
        assert_eq!(sel.availability.runtime, Some(ContainerRuntimeKind::Podman));
        assert!(sel.availability.available);

        // Nested always blocked
        let sel = resolve_container_engine(ContainerEngineMode::Auto, &snap, true);
        assert!(!sel.availability.available);
        assert_eq!(
            sel.availability.reason,
            Some(ContainerUnavailableReason::HarnessInContainer)
        );

        // Explicit Docker with only Podman healthy — no fallback
        snap.entries.insert(
            ID_DOCKER.into(),
            HealthEntry {
                id: ExternalRuntimeId::new(ID_DOCKER),
                state: HealthState::Failed {
                    cause: HealthCause::DaemonUnavailable,
                },
                importance: DependencyImportance::RequiredWhenFeatureSelected,
                target: ExecutionTarget::Host,
                remedy: None,
                platform: HostPlatform::DebianUbuntu,
            },
        );
        let sel = resolve_container_engine(ContainerEngineMode::Docker, &snap, false);
        assert!(!sel.availability.available);
        assert_eq!(
            sel.availability.reason,
            Some(ContainerUnavailableReason::DaemonUnavailable)
        );
        // Auto falls through to Podman
        let sel = resolve_container_engine(ContainerEngineMode::Auto, &snap, false);
        assert!(sel.availability.available);
        assert_eq!(sel.availability.runtime, Some(ContainerRuntimeKind::Podman));

        // Permission / socket
        snap.entries.insert(
            ID_DOCKER.into(),
            HealthEntry {
                id: ExternalRuntimeId::new(ID_DOCKER),
                state: HealthState::Failed {
                    cause: HealthCause::PermissionDenied,
                },
                importance: DependencyImportance::RequiredWhenFeatureSelected,
                target: ExecutionTarget::Host,
                remedy: None,
                platform: HostPlatform::DebianUbuntu,
            },
        );
        snap.entries.insert(
            ID_PODMAN.into(),
            HealthEntry {
                id: ExternalRuntimeId::new(ID_PODMAN),
                state: HealthState::Missing,
                importance: DependencyImportance::RequiredWhenFeatureSelected,
                target: ExecutionTarget::Host,
                remedy: None,
                platform: HostPlatform::DebianUbuntu,
            },
        );
        let sel = resolve_container_engine(ContainerEngineMode::Docker, &snap, false);
        assert_eq!(
            sel.availability.reason,
            Some(ContainerUnavailableReason::PermissionDenied)
        );

        snap.entries.insert(
            ID_DOCKER.into(),
            HealthEntry {
                id: ExternalRuntimeId::new(ID_DOCKER),
                state: HealthState::Failed {
                    cause: HealthCause::SocketUnavailable,
                },
                importance: DependencyImportance::RequiredWhenFeatureSelected,
                target: ExecutionTarget::Host,
                remedy: None,
                platform: HostPlatform::DebianUbuntu,
            },
        );
        let sel = resolve_container_engine(ContainerEngineMode::Docker, &snap, false);
        assert_eq!(
            sel.availability.reason,
            Some(ContainerUnavailableReason::SocketUnavailable)
        );

        // Timeout → unavailable
        snap.entries.insert(
            ID_DOCKER.into(),
            HealthEntry {
                id: ExternalRuntimeId::new(ID_DOCKER),
                state: HealthState::TimedOut,
                importance: DependencyImportance::RequiredWhenFeatureSelected,
                target: ExecutionTarget::Host,
                remedy: None,
                platform: HostPlatform::DebianUbuntu,
            },
        );
        let sel = resolve_container_engine(ContainerEngineMode::Docker, &snap, false);
        assert!(!sel.availability.available);
    }

    #[test]
    fn classify_container_daemon_failure_typed_causes() {
        assert_eq!(
            classify_container_daemon_failure(
                "Got permission denied while trying to connect",
                Some(1)
            ),
            HealthCause::PermissionDenied
        );
        assert_eq!(
            classify_container_daemon_failure(
                "Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?",
                Some(1)
            ),
            HealthCause::DaemonUnavailable
        );
        assert_eq!(
            classify_container_daemon_failure(
                "dial unix /run/podman/podman.sock: connect: no such file or directory",
                Some(1)
            ),
            HealthCause::SocketUnavailable
        );
        assert!(matches!(
            classify_container_daemon_failure("something else failed", Some(2)),
            HealthCause::NonZeroExit { code: Some(2) }
        ));
        let _ = SpawnFailureKind::Other;
    }

    #[test]
    fn container_generation_and_cancel_late_results() {
        use crate::external_runtime::health::HealthSnapshotStore;

        let registry = ExternalRuntimeRegistry::new();
        register_safety_adapters(&registry).unwrap();
        let store = HealthSnapshotStore::new();
        let ctx = ctx_linux_with_features(&["container-sandbox"]);

        // Reserve gen1, then reserve gen2 before gen1 finishes — gen1 publish is late.
        let gen1 = store.begin_refresh();
        let gen2 = store.begin_refresh();
        assert_eq!(gen1, 1);
        assert_eq!(gen2, 2);

        let executor_late = RecordingProbeExecutor::new().with_resolve("docker", "/usr/bin/docker");
        executor_late.set_handler(|_p, _a| ProbeCommandResult {
            exit_code: Some(0),
            stdout: b"Docker version 24.0.0\n".to_vec(),
            stderr: Vec::new(),
            timed_out: false,
            cancelled: false,
            spawn_error: None,
        });
        let late = refresh_safety_snapshot(
            &registry,
            &executor_late,
            None,
            Path::new("/"),
            &ctx,
            ProbeDeadlines::default(),
            &CancelToken::new(),
            gen1,
            ContainerEngineMode::Docker,
        );
        assert!(!store.publish(late), "stale generation must not publish");
        assert!(store.current().is_none());

        let executor_new = RecordingProbeExecutor::new().with_resolve("docker", "/usr/bin/docker");
        executor_new.set_handler(|_p, _a| ProbeCommandResult {
            exit_code: Some(0),
            stdout: b"Docker version 25.0.0\n".to_vec(),
            stderr: Vec::new(),
            timed_out: false,
            cancelled: false,
            spawn_error: None,
        });
        let fresh = refresh_safety_snapshot(
            &registry,
            &executor_new,
            None,
            Path::new("/"),
            &ctx,
            ProbeDeadlines::default(),
            &CancelToken::new(),
            gen2,
            ContainerEngineMode::Docker,
        );
        assert!(store.publish(fresh.clone()));
        let published = store.current().expect("published");
        assert_eq!(published.generation, 2);
        // Launch selection is bound to the published generation only.
        let launch = resolve_container_engine(ContainerEngineMode::Docker, &published, false);
        assert!(launch.availability.available);
        assert_eq!(
            launch.availability.runtime,
            Some(ContainerRuntimeKind::Docker)
        );

        // Cancellation during probe → Unknown, not available for launch.
        let cancel = CancelToken::new();
        cancel.cancel();
        let executor = RecordingProbeExecutor::new().with_resolve("docker", "/usr/bin/docker");
        let cancelled = refresh_safety_snapshot(
            &registry,
            &executor,
            None,
            Path::new("/"),
            &ctx,
            ProbeDeadlines::default(),
            &cancel,
            store.begin_refresh(),
            ContainerEngineMode::Docker,
        );
        assert!(matches!(
            cancelled.get(ID_DOCKER).unwrap().state,
            HealthState::Unknown {
                cause: HealthCause::Cancellation
            }
        ));
        let sel = resolve_container_engine(ContainerEngineMode::Docker, &cancelled, false);
        assert!(!sel.availability.available);

        // Zero deadline → TimedOut (simulates probe deadline kill without real sleep).
        let executor = RecordingProbeExecutor::new().with_resolve("docker", "/usr/bin/docker");
        let timed = refresh_safety_snapshot(
            &registry,
            &executor,
            None,
            Path::new("/"),
            &ctx,
            ProbeDeadlines {
                version: Duration::ZERO,
                functional: Duration::ZERO,
            },
            &CancelToken::new(),
            store.begin_refresh(),
            ContainerEngineMode::Docker,
        );
        assert!(matches!(
            timed.get(ID_DOCKER).unwrap().state,
            HealthState::TimedOut
        ));
    }

    #[test]
    fn bubblewrap_and_computer_use_preserve_fail_closed_policy() {
        let mut snap = ExternalRuntimeSnapshot::empty(1, HostPlatform::DebianUbuntu);
        // Missing all computer-use tools
        for id in [ID_XVFB, ID_XDOTOOL, ID_SCROT, ID_IMPORT, ID_BUBBLEWRAP] {
            snap.entries.insert(
                id.into(),
                HealthEntry {
                    id: ExternalRuntimeId::new(id),
                    state: HealthState::Missing,
                    importance: DependencyImportance::RequiredWhenFeatureSelected,
                    target: ExecutionTarget::Host,
                    remedy: None,
                    platform: HostPlatform::DebianUbuntu,
                },
            );
        }
        assert!(!matches!(
            evaluate_requirement_group(&computer_use_requirement_group(), &snap),
            GroupHealth::Available
        ));
        assert!(!matches!(
            evaluate_requirement_group(&bubblewrap_requirement_group(), &snap),
            GroupHealth::Available
        ));

        // All-of requires every leaf; any-of for capture tools.
        snap.entries.insert(
            ID_XVFB.into(),
            HealthEntry {
                id: ExternalRuntimeId::new(ID_XVFB),
                state: HealthState::Available {
                    resolved_path: Some(PathBuf::from("/usr/bin/Xvfb")),
                    version_evidence: None,
                },
                importance: DependencyImportance::RequiredWhenFeatureSelected,
                target: ExecutionTarget::Host,
                remedy: None,
                platform: HostPlatform::DebianUbuntu,
            },
        );
        snap.entries.insert(
            ID_XDOTOOL.into(),
            HealthEntry {
                id: ExternalRuntimeId::new(ID_XDOTOOL),
                state: HealthState::Available {
                    resolved_path: Some(PathBuf::from("/usr/bin/xdotool")),
                    version_evidence: None,
                },
                importance: DependencyImportance::RequiredWhenFeatureSelected,
                target: ExecutionTarget::Host,
                remedy: None,
                platform: HostPlatform::DebianUbuntu,
            },
        );
        // Only scrot — still available via any-of
        snap.entries.insert(
            ID_SCROT.into(),
            HealthEntry {
                id: ExternalRuntimeId::new(ID_SCROT),
                state: HealthState::Available {
                    resolved_path: Some(PathBuf::from("/usr/bin/scrot")),
                    version_evidence: None,
                },
                importance: DependencyImportance::RequiredWhenFeatureSelected,
                target: ExecutionTarget::Host,
                remedy: None,
                platform: HostPlatform::DebianUbuntu,
            },
        );
        assert_eq!(
            evaluate_requirement_group(&computer_use_requirement_group(), &snap),
            GroupHealth::Available
        );

        // Drop scrot; import still missing → fail closed
        snap.entries.insert(
            ID_SCROT.into(),
            HealthEntry {
                id: ExternalRuntimeId::new(ID_SCROT),
                state: HealthState::Missing,
                importance: DependencyImportance::RequiredWhenFeatureSelected,
                target: ExecutionTarget::Host,
                remedy: None,
                platform: HostPlatform::DebianUbuntu,
            },
        );
        assert!(!matches!(
            evaluate_requirement_group(&computer_use_requirement_group(), &snap),
            GroupHealth::Available
        ));
    }

    #[test]
    fn source_inventory_forbids_mutating_probe_verbs_in_safety_descriptors() {
        for desc in safety_adapter_descriptors().unwrap() {
            if let Some(policy) = desc.probe_policy.as_trusted_catalog() {
                assert!(
                    probe_argv_forbids_mutation(policy.version_argv()),
                    "{} version argv mutates",
                    desc.id
                );
                if let Some(func) = policy.functional_argv() {
                    assert!(
                        probe_argv_forbids_mutation(func),
                        "{} functional argv mutates",
                        desc.id
                    );
                    if desc.id.as_str() == ID_DOCKER || desc.id.as_str() == ID_PODMAN {
                        assert!(container_probe_argv_is_readonly(func));
                        assert!(container_probe_argv_is_readonly(policy.version_argv()));
                    }
                }
            }
        }
    }
}
