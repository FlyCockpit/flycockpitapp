//! Daemon-owned host capability snapshot.
//!
//! Shared probes run once at boot and again on `RefreshHostCapabilities`.
//! The TUI in-process doctor compose is not this authority.

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use cockpit_proto::{
    CatalogDependencyImportance, CatalogDependencyRow, CatalogDependencyState,
    CatalogExecutionTarget, ContainerAvailability, ContainerRuntimeKind,
    ContainerUnavailableReason, FeatureCapabilityRow, FeatureCapabilityState,
    HostCapabilitySnapshot, SecretStoreSnapshot,
};

use crate::external_runtime::{
    CancelToken, DependencyImportance, EvaluationContext, ExternalRuntimeDescriptor,
    ExternalRuntimeId, ExternalRuntimeSnapshot, HealthCause, HealthEntry, HealthState,
    HostPlatform, ID_BUBBLEWRAP, ID_DOCKER, ID_KEYRING, ID_MEDIA_FFMPEG, ID_MEDIA_FFPROBE,
    ID_PODMAN, ProbeDeadlines, ProbeExecutor, SystemProbeExecutor, catalog_adapter_descriptors,
    detect_host_platform, keyring_health_entry, media_runtime_pair_is_compatible,
    project_dependencies, refresh_snapshot, safety_adapter_descriptors,
};
use crate::secure_key::{
    KeyringProbeResult, probe_platform_keyring, probe_platform_keyring_refresh,
};
use crate::tools::shell_sandbox::{SandboxAvailability, probe_host_sandbox};

/// Feature capability IDs consulted by settings/spawn/vault.
pub const FEATURE_SECRET_STORE_KEYRING: &str = "secret_store.keyring";
pub const FEATURE_SANDBOX_HOST: &str = "sandbox.host";
pub const FEATURE_SANDBOX_CONTAINER: &str = "sandbox.container";
pub const FEATURE_MEDIA_DECODE: &str = "media.decode";

/// Catalog IDs listed on the daemon snapshot.
pub const DAEMON_CATALOG_IDS: &[&str] = &[
    ID_KEYRING,
    ID_BUBBLEWRAP,
    ID_DOCKER,
    ID_PODMAN,
    ID_MEDIA_FFMPEG,
    ID_MEDIA_FFPROBE,
];

/// Injectable probe sources. Production uses the shared live probes; tests
/// inject results through these fields.
#[derive(Clone)]
pub struct HostCapabilityProbeInputs {
    pub keyring: KeyringProbeSource,
    pub sandbox: SandboxProbeSource,
    pub container: ContainerProbeSource,
    pub catalog: CatalogProbeSource,
    pub platform: HostPlatform,
    pub cwd: PathBuf,
}

#[derive(Clone)]
pub enum KeyringProbeSource {
    Production,
    Injected {
        result: KeyringProbeResult,
        calls: Arc<AtomicUsize>,
    },
}

#[derive(Clone)]
pub enum SandboxProbeSource {
    Production,
    Injected(SandboxAvailability),
}

#[derive(Clone)]
pub enum ContainerProbeSource {
    /// Reuse [`crate::container::availability_snapshot`] (boot: one detect already ran).
    ReuseSnapshot,
    /// Call [`crate::container::detect_runtime`] once (refresh).
    DetectOnce,
    Injected {
        availability: ContainerAvailability,
        detect_calls: Arc<AtomicUsize>,
    },
}

#[derive(Clone)]
pub enum CatalogProbeSource {
    Production,
    Injected(ExternalRuntimeSnapshot),
}

impl HostCapabilityProbeInputs {
    pub fn production(cwd: PathBuf) -> Self {
        Self {
            keyring: KeyringProbeSource::Production,
            sandbox: SandboxProbeSource::Production,
            container: ContainerProbeSource::ReuseSnapshot,
            catalog: CatalogProbeSource::Production,
            platform: detect_host_platform(),
            cwd,
        }
    }

    pub fn for_refresh(&self) -> Self {
        let mut next = self.clone();
        if matches!(next.container, ContainerProbeSource::ReuseSnapshot) {
            next.container = ContainerProbeSource::DetectOnce;
        }
        next
    }
}

/// Generation-tagged snapshot store. Late refreshes are discarded.
#[derive(Clone, Debug, Default)]
pub struct HostCapabilitySnapshotStore {
    inner: Arc<Mutex<StoreInner>>,
}

#[derive(Debug, Default)]
struct StoreInner {
    next_generation: u64,
    current: Option<Arc<HostCapabilitySnapshot>>,
}

impl HostCapabilitySnapshotStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn begin_refresh(&self) -> u64 {
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        inner.next_generation = inner.next_generation.saturating_add(1);
        inner.next_generation
    }

    pub fn publish(&self, snapshot: HostCapabilitySnapshot) -> bool {
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        if snapshot.generation != inner.next_generation {
            return false;
        }
        if let Some(current) = &inner.current
            && snapshot.generation <= current.generation
        {
            return false;
        }
        inner.current = Some(Arc::new(snapshot));
        true
    }

    pub fn current(&self) -> Option<Arc<HostCapabilitySnapshot>> {
        let inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        inner.current.clone()
    }
}

/// Run shared probes once and publish the unconfigured secret-store placeholder.
///
/// Production boot uses [`publish_host_capabilities_with_secret_store`] after
/// vault start so `secretStore` is filled from the authority row.
pub async fn publish_initial_host_capabilities(
    store: &HostCapabilitySnapshotStore,
    inputs: &HostCapabilityProbeInputs,
) {
    publish_host_capabilities_with_secret_store(
        store,
        inputs,
        SecretStoreSnapshot::unconfigured_placeholder(),
    )
    .await;
}

/// Collect shared probes and publish a snapshot with the given secret-store
/// projection. Call after vault start (or with a fail-closed snapshot).
pub async fn publish_host_capabilities_with_secret_store(
    store: &HostCapabilitySnapshotStore,
    inputs: &HostCapabilityProbeInputs,
    secret_store: SecretStoreSnapshot,
) {
    let generation = store.begin_refresh();
    let probes = collect_shared_host_probes(inputs, false).await;
    let snapshot = build_host_capability_snapshot(generation, &probes, secret_store);
    let _ = store.publish(snapshot);
}

/// Re-run shared probes and publish when the reserved generation is current.
pub async fn refresh_host_capabilities(
    store: &HostCapabilitySnapshotStore,
    inputs: &HostCapabilityProbeInputs,
) -> Result<(HostCapabilitySnapshot, bool), String> {
    refresh_host_capabilities_inner(store, inputs, None).await
}

/// Same as [`refresh_host_capabilities`], but publish `secret_store` (already
/// post-migrate) instead of the pre-refresh placement. Reconcile still applies
/// so a keyring dest can fail closed on a fresh probe.
pub async fn refresh_host_capabilities_with_secret_store(
    store: &HostCapabilitySnapshotStore,
    inputs: &HostCapabilityProbeInputs,
    secret_store: SecretStoreSnapshot,
) -> Result<(HostCapabilitySnapshot, bool), String> {
    refresh_host_capabilities_inner(store, inputs, Some(secret_store)).await
}

async fn refresh_host_capabilities_inner(
    store: &HostCapabilitySnapshotStore,
    inputs: &HostCapabilityProbeInputs,
    secret_store: Option<SecretStoreSnapshot>,
) -> Result<(HostCapabilitySnapshot, bool), String> {
    let generation = store.begin_refresh();
    let inputs = inputs.for_refresh();
    let probes = collect_shared_host_probes(&inputs, true).await;
    let previous = secret_store.unwrap_or_else(|| {
        store
            .current()
            .map(|current| current.secret_store.clone())
            .unwrap_or_else(SecretStoreSnapshot::unconfigured_placeholder)
    });
    let secret_store = reconcile_secret_store_with_probe(previous, &probes.keyring);
    let snapshot = build_host_capability_snapshot(generation, &probes, secret_store);
    if store.publish(snapshot.clone()) {
        Ok((snapshot, true))
    } else {
        store
            .current()
            .map(|current| ((*current).clone(), false))
            .ok_or_else(|| "host capability snapshot was superseded".to_string())
    }
}

pub struct SharedHostProbes {
    pub keyring: KeyringProbeResult,
    pub sandbox: SandboxAvailability,
    pub container: ContainerAvailability,
    pub catalog: ExternalRuntimeSnapshot,
    pub catalog_descriptors: Vec<ExternalRuntimeDescriptor>,
    pub platform: HostPlatform,
}

pub async fn collect_shared_host_probes(
    inputs: &HostCapabilityProbeInputs,
    refresh_keyring: bool,
) -> SharedHostProbes {
    let keyring = match &inputs.keyring {
        KeyringProbeSource::Production => {
            if refresh_keyring {
                probe_platform_keyring_refresh()
            } else {
                probe_platform_keyring()
            }
        }
        KeyringProbeSource::Injected { result, calls } => {
            calls.fetch_add(1, Ordering::SeqCst);
            result.clone()
        }
    };
    let sandbox = match &inputs.sandbox {
        SandboxProbeSource::Production => probe_host_sandbox(&inputs.cwd).await,
        SandboxProbeSource::Injected(availability) => availability.clone(),
    };
    let container = match &inputs.container {
        ContainerProbeSource::ReuseSnapshot => crate::container::availability_snapshot(),
        ContainerProbeSource::DetectOnce => crate::container::detect_runtime().1,
        ContainerProbeSource::Injected {
            availability,
            detect_calls,
        } => {
            detect_calls.fetch_add(1, Ordering::SeqCst);
            availability.clone()
        }
    };
    let (catalog, catalog_descriptors) = match &inputs.catalog {
        CatalogProbeSource::Production => {
            evaluate_daemon_catalog(&inputs.cwd, &SystemProbeExecutor, inputs.platform)
        }
        CatalogProbeSource::Injected(snapshot) => (snapshot.clone(), daemon_catalog_descriptors()),
    };
    SharedHostProbes {
        keyring,
        sandbox,
        container,
        catalog,
        catalog_descriptors,
        platform: inputs.platform,
    }
}

fn daemon_catalog_descriptors() -> Vec<ExternalRuntimeDescriptor> {
    let mut descriptors = catalog_adapter_descriptors()
        .into_iter()
        .filter(|descriptor| matches!(descriptor.id.as_str(), ID_MEDIA_FFMPEG | ID_MEDIA_FFPROBE))
        .collect::<Vec<_>>();
    if let Ok(safety) = safety_adapter_descriptors() {
        descriptors.extend(safety.into_iter().filter(|descriptor| {
            matches!(
                descriptor.id.as_str(),
                ID_BUBBLEWRAP | ID_KEYRING | ID_DOCKER | ID_PODMAN
            )
        }));
    }
    descriptors.sort_by(|left, right| left.id.cmp(&right.id));
    descriptors
}

fn evaluate_daemon_catalog(
    cwd: &std::path::Path,
    executor: &dyn ProbeExecutor,
    platform: HostPlatform,
) -> (ExternalRuntimeSnapshot, Vec<ExternalRuntimeDescriptor>) {
    let descriptors = daemon_catalog_descriptors();
    let eval_descriptors: Vec<_> = descriptors
        .iter()
        .filter(|descriptor| {
            matches!(
                descriptor.id.as_str(),
                ID_MEDIA_FFMPEG | ID_MEDIA_FFPROBE | ID_BUBBLEWRAP
            )
        })
        .cloned()
        .collect();
    let ctx =
        EvaluationContext::new(platform).with_features([FEATURE_MEDIA_DECODE, "shell-sandbox"]);
    let snapshot = refresh_snapshot(
        1,
        &eval_descriptors,
        executor,
        None,
        cwd,
        &ctx,
        ProbeDeadlines::default(),
        &CancelToken::new(),
    );
    (snapshot, descriptors)
}

fn reconcile_secret_store_with_probe(
    previous: SecretStoreSnapshot,
    probe: &KeyringProbeResult,
) -> SecretStoreSnapshot {
    match previous.intent {
        cockpit_proto::SecretStoreIntent::Keyring if !probe.state.is_available() => {
            SecretStoreSnapshot {
                intent: cockpit_proto::SecretStoreIntent::Keyring,
                effective_placement: cockpit_proto::SecretStorePlacement::Unavailable,
                fail_closed_reason: Some(probe.reason.clone()),
                fix_command: probe
                    .fix_command
                    .clone()
                    .or_else(|| Some(crate::secure_key::DEFAULT_FIX_COMMAND.to_string())),
                unification_complete: previous.unification_complete,
            }
        }
        cockpit_proto::SecretStoreIntent::Keyring if probe.state.is_available() => {
            SecretStoreSnapshot {
                intent: cockpit_proto::SecretStoreIntent::Keyring,
                effective_placement: cockpit_proto::SecretStorePlacement::Keyring,
                fail_closed_reason: None,
                fix_command: None,
                unification_complete: previous.unification_complete,
            }
        }
        _ => previous,
    }
}

pub fn build_host_capability_snapshot(
    generation: u64,
    probes: &SharedHostProbes,
    secret_store: SecretStoreSnapshot,
) -> HostCapabilitySnapshot {
    let mut catalog = probes.catalog.clone();
    catalog.generation = generation;
    catalog.platform = probes.platform;
    catalog.entries.insert(
        ID_KEYRING.to_string(),
        keyring_health_entry(&probes.keyring, probes.platform),
    );
    for entry in container_health_entries(&probes.container, probes.platform) {
        catalog.entries.insert(entry.id.as_str().to_string(), entry);
    }
    if !catalog.entries.contains_key(ID_BUBBLEWRAP) {
        catalog.entries.insert(
            ID_BUBBLEWRAP.to_string(),
            bwrap_placeholder_entry(probes.platform),
        );
    }
    for id in [ID_MEDIA_FFMPEG, ID_MEDIA_FFPROBE] {
        if !catalog.entries.contains_key(id) {
            catalog.entries.insert(
                id.to_string(),
                HealthEntry {
                    id: ExternalRuntimeId::new(id),
                    state: HealthState::Missing,
                    importance: DependencyImportance::RequiredWhenFeatureSelected,
                    target: crate::capabilities::ExecutionTarget::Host,
                    remedy: None,
                    platform: probes.platform,
                },
            );
        }
    }

    let projection = project_dependencies(Some(&catalog), &probes.catalog_descriptors);
    let mut dependencies: Vec<CatalogDependencyRow> = projection
        .rows
        .into_iter()
        .filter(|row| DAEMON_CATALOG_IDS.contains(&row.id.as_str()))
        .map(catalog_row_from_projection)
        .collect();
    dependencies.sort_by(|left, right| left.id.cmp(&right.id));

    let features = vec![
        feature_from_keyring(&probes.keyring),
        feature_sandbox_host(probes.platform, &probes.sandbox, &dependencies),
        feature_sandbox_container(&probes.container),
        feature_media_decode(&catalog, &dependencies),
    ];

    HostCapabilitySnapshot {
        generation,
        features,
        dependencies,
        secret_store,
    }
}

fn bwrap_placeholder_entry(platform: HostPlatform) -> HealthEntry {
    let linux = matches!(
        platform,
        HostPlatform::DebianUbuntu
            | HostPlatform::FedoraRhel
            | HostPlatform::Arch
            | HostPlatform::GenericLinux
            | HostPlatform::OtherUnix
    );
    HealthEntry {
        id: ExternalRuntimeId::new(ID_BUBBLEWRAP),
        state: if linux {
            HealthState::Missing
        } else {
            HealthState::NotApplicable
        },
        importance: DependencyImportance::RequiredWhenFeatureSelected,
        target: crate::capabilities::ExecutionTarget::Host,
        remedy: None,
        platform,
    }
}

fn container_health_entries(
    availability: &ContainerAvailability,
    platform: HostPlatform,
) -> Vec<HealthEntry> {
    vec![
        container_health_entry(
            ID_DOCKER,
            ContainerRuntimeKind::Docker,
            availability,
            platform,
        ),
        container_health_entry(
            ID_PODMAN,
            ContainerRuntimeKind::Podman,
            availability,
            platform,
        ),
    ]
}

fn container_health_entry(
    id: &str,
    kind: ContainerRuntimeKind,
    availability: &ContainerAvailability,
    platform: HostPlatform,
) -> HealthEntry {
    let selected = availability.available && availability.runtime == Some(kind);
    let other_selected =
        availability.available && availability.runtime.is_some_and(|runtime| runtime != kind);
    let importance = if other_selected {
        DependencyImportance::OptionalIntegration
    } else {
        DependencyImportance::RequiredWhenFeatureSelected
    };
    let state = if selected {
        HealthState::Available {
            resolved_path: None,
            version_evidence: None,
        }
    } else {
        match availability.reason {
            Some(ContainerUnavailableReason::PermissionDenied) => HealthState::Failed {
                cause: HealthCause::PermissionDenied,
            },
            Some(ContainerUnavailableReason::SocketUnavailable) => HealthState::Failed {
                cause: HealthCause::SocketUnavailable,
            },
            Some(ContainerUnavailableReason::DaemonUnavailable) => HealthState::Failed {
                cause: HealthCause::DaemonUnavailable,
            },
            Some(ContainerUnavailableReason::HarnessInContainer) => HealthState::Failed {
                cause: HealthCause::Internal {
                    message: "cockpit is already running inside a container".into(),
                },
            },
            Some(ContainerUnavailableReason::NoRuntime) | None => HealthState::Missing,
        }
    };
    HealthEntry {
        id: ExternalRuntimeId::new(id),
        state,
        importance,
        target: crate::capabilities::ExecutionTarget::Host,
        remedy: None,
        platform,
    }
}

fn feature_from_keyring(probe: &KeyringProbeResult) -> FeatureCapabilityRow {
    FeatureCapabilityRow {
        id: FEATURE_SECRET_STORE_KEYRING.to_string(),
        state: probe.state,
        reason: probe.reason.clone(),
        fix_command: probe.fix_command.clone(),
        remedy_text: probe.remedy_text.clone(),
        dependency_ids: vec![ID_KEYRING.to_string()],
    }
}

fn feature_sandbox_host(
    platform: HostPlatform,
    sandbox: &SandboxAvailability,
    dependencies: &[CatalogDependencyRow],
) -> FeatureCapabilityRow {
    let bwrap = dependencies.iter().find(|row| row.id == ID_BUBBLEWRAP);
    let from_zerobox = |availability: &SandboxAvailability| match availability {
        SandboxAvailability::Available => FeatureCapabilityRow {
            id: FEATURE_SANDBOX_HOST.to_string(),
            state: FeatureCapabilityState::Available,
            reason: "host sandbox probe succeeded".into(),
            fix_command: None,
            remedy_text: None,
            dependency_ids: vec![ID_BUBBLEWRAP.to_string()],
        },
        SandboxAvailability::Unavailable {
            reason,
            fix_command,
        } => FeatureCapabilityRow {
            id: FEATURE_SANDBOX_HOST.to_string(),
            state: FeatureCapabilityState::Missing,
            reason: reason.clone(),
            fix_command: fix_command.clone(),
            remedy_text: Some(reason.clone()),
            dependency_ids: vec![ID_BUBBLEWRAP.to_string()],
        },
        SandboxAvailability::UnsupportedPlatform { reason } => FeatureCapabilityRow {
            id: FEATURE_SANDBOX_HOST.to_string(),
            state: FeatureCapabilityState::Unsupported,
            reason: reason.clone(),
            fix_command: None,
            remedy_text: Some(reason.clone()),
            dependency_ids: vec![ID_BUBBLEWRAP.to_string()],
        },
    };

    match platform {
        HostPlatform::Windows => FeatureCapabilityRow {
            id: FEATURE_SANDBOX_HOST.to_string(),
            state: FeatureCapabilityState::Unsupported,
            reason: "host sandbox is unsupported on Windows".into(),
            fix_command: None,
            remedy_text: Some("Use container sandbox mode on Windows.".into()),
            dependency_ids: vec![ID_BUBBLEWRAP.to_string()],
        },
        HostPlatform::MacOs => from_zerobox(sandbox),
        HostPlatform::Unsupported => FeatureCapabilityRow {
            id: FEATURE_SANDBOX_HOST.to_string(),
            state: FeatureCapabilityState::Unsupported,
            reason: "host sandbox is unsupported on this platform".into(),
            fix_command: None,
            remedy_text: None,
            dependency_ids: vec![ID_BUBBLEWRAP.to_string()],
        },
        HostPlatform::DebianUbuntu
        | HostPlatform::FedoraRhel
        | HostPlatform::Arch
        | HostPlatform::GenericLinux
        | HostPlatform::OtherUnix => {
            let bwrap_available =
                bwrap.is_some_and(|row| matches!(row.state, CatalogDependencyState::Available));
            if !bwrap_available {
                let (state, reason, fix_command, remedy_text) = match bwrap {
                    Some(row) if matches!(row.state, CatalogDependencyState::Failed) => (
                        FeatureCapabilityState::Failed,
                        row.reason.clone(),
                        None,
                        Some(row.reason.clone()),
                    ),
                    Some(row) => (
                        FeatureCapabilityState::Missing,
                        row.reason.clone(),
                        None,
                        Some(row.reason.clone()),
                    ),
                    None => (
                        FeatureCapabilityState::Missing,
                        "safety.bubblewrap is not available".into(),
                        None,
                        Some("Install Bubblewrap (`bwrap`) for the host shell sandbox.".into()),
                    ),
                };
                return FeatureCapabilityRow {
                    id: FEATURE_SANDBOX_HOST.to_string(),
                    state,
                    reason,
                    fix_command,
                    remedy_text,
                    dependency_ids: vec![ID_BUBBLEWRAP.to_string()],
                };
            }
            from_zerobox(sandbox)
        }
    }
}

fn feature_sandbox_container(availability: &ContainerAvailability) -> FeatureCapabilityRow {
    if availability.available {
        return FeatureCapabilityRow {
            id: FEATURE_SANDBOX_CONTAINER.to_string(),
            state: FeatureCapabilityState::Available,
            reason: availability
                .runtime
                .map(|runtime| format!("{} engine is available", runtime.as_str()))
                .unwrap_or_else(|| "container engine is available".into()),
            fix_command: None,
            remedy_text: None,
            dependency_ids: vec![ID_DOCKER.to_string(), ID_PODMAN.to_string()],
        };
    }
    let (state, reason) = match availability.reason {
        Some(ContainerUnavailableReason::NoRuntime) | None => (
            FeatureCapabilityState::Missing,
            availability
                .unavailable_reason_text()
                .unwrap_or_else(|| "no healthy docker or podman engine available".into()),
        ),
        Some(_) => (
            FeatureCapabilityState::Failed,
            availability
                .unavailable_reason_text()
                .unwrap_or_else(|| "container engine is not usable".into()),
        ),
    };
    FeatureCapabilityRow {
        id: FEATURE_SANDBOX_CONTAINER.to_string(),
        state,
        reason,
        fix_command: None,
        remedy_text: availability.unavailable_reason_text(),
        dependency_ids: vec![ID_DOCKER.to_string(), ID_PODMAN.to_string()],
    }
}

fn feature_media_decode(
    catalog: &ExternalRuntimeSnapshot,
    dependencies: &[CatalogDependencyRow],
) -> FeatureCapabilityRow {
    let ffmpeg = dependencies.iter().find(|row| row.id == ID_MEDIA_FFMPEG);
    let ffprobe = dependencies.iter().find(|row| row.id == ID_MEDIA_FFPROBE);
    let timed_out = [ffmpeg, ffprobe]
        .into_iter()
        .flatten()
        .any(|row| matches!(row.state, CatalogDependencyState::TimedOut));
    let failed = [ffmpeg, ffprobe]
        .into_iter()
        .flatten()
        .any(|row| matches!(row.state, CatalogDependencyState::Failed));
    if media_runtime_pair_is_compatible(catalog) {
        FeatureCapabilityRow {
            id: FEATURE_MEDIA_DECODE.to_string(),
            state: FeatureCapabilityState::Available,
            reason: "ffmpeg and ffprobe are a compatible pair".into(),
            fix_command: None,
            remedy_text: None,
            dependency_ids: vec![ID_MEDIA_FFMPEG.to_string(), ID_MEDIA_FFPROBE.to_string()],
        }
    } else if timed_out || failed {
        let reason = [ffmpeg, ffprobe]
            .into_iter()
            .flatten()
            .find(|row| {
                matches!(
                    row.state,
                    CatalogDependencyState::TimedOut | CatalogDependencyState::Failed
                )
            })
            .map(|row| row.reason.clone())
            .unwrap_or_else(|| "media decoder probe failed".into());
        FeatureCapabilityRow {
            id: FEATURE_MEDIA_DECODE.to_string(),
            state: FeatureCapabilityState::Failed,
            reason,
            fix_command: None,
            remedy_text: Some(
                "Install a matching FFmpeg/FFprobe pair from https://ffmpeg.org/download.html."
                    .into(),
            ),
            dependency_ids: vec![ID_MEDIA_FFMPEG.to_string(), ID_MEDIA_FFPROBE.to_string()],
        }
    } else {
        FeatureCapabilityRow {
            id: FEATURE_MEDIA_DECODE.to_string(),
            state: FeatureCapabilityState::Missing,
            reason: "ffmpeg/ffprobe compatible pair is not available".into(),
            fix_command: None,
            remedy_text: Some(
                "Install a matching FFmpeg/FFprobe pair from https://ffmpeg.org/download.html."
                    .into(),
            ),
            dependency_ids: vec![ID_MEDIA_FFMPEG.to_string(), ID_MEDIA_FFPROBE.to_string()],
        }
    }
}

fn catalog_row_from_projection(
    row: crate::external_runtime::DependencyProjectionRow,
) -> CatalogDependencyRow {
    CatalogDependencyRow {
        id: row.id,
        state: match row.state {
            crate::external_runtime::DependencyViewState::Pending => {
                CatalogDependencyState::Pending
            }
            crate::external_runtime::DependencyViewState::Available => {
                CatalogDependencyState::Available
            }
            crate::external_runtime::DependencyViewState::Missing => {
                CatalogDependencyState::Missing
            }
            crate::external_runtime::DependencyViewState::Incompatible => {
                CatalogDependencyState::Incompatible
            }
            crate::external_runtime::DependencyViewState::TimedOut => {
                CatalogDependencyState::TimedOut
            }
            crate::external_runtime::DependencyViewState::Failed => CatalogDependencyState::Failed,
            crate::external_runtime::DependencyViewState::Unknown => {
                CatalogDependencyState::Unknown
            }
            crate::external_runtime::DependencyViewState::NotApplicable => {
                CatalogDependencyState::NotApplicable
            }
        },
        importance: match row.importance {
            DependencyImportance::RequiredForDefaultSafety => {
                CatalogDependencyImportance::RequiredForDefaultSafety
            }
            DependencyImportance::RequiredWhenFeatureSelected => {
                CatalogDependencyImportance::RequiredWhenFeatureSelected
            }
            DependencyImportance::OptionalIntegration => {
                CatalogDependencyImportance::OptionalIntegration
            }
            DependencyImportance::OptionalAccelerator => {
                CatalogDependencyImportance::OptionalAccelerator
            }
        },
        target: match row.target {
            crate::capabilities::ExecutionTarget::Host => CatalogExecutionTarget::Host,
            crate::capabilities::ExecutionTarget::Container => CatalogExecutionTarget::Container,
        },
        required_version: row.required_version,
        discovered_version: row.discovered_version,
        cause: row.cause.and_then(|cause| serde_json::to_value(cause).ok()),
        remedy: row
            .remedy
            .and_then(|remedy| serde_json::to_value(remedy).ok()),
        reason: row.reason,
    }
}
