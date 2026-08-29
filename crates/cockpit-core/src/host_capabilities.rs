//! Daemon-owned host capability snapshot.
//!
//! Shared probes run once at boot and again on `RefreshHostCapabilities`.
//! The TUI in-process doctor compose is not this authority.

use std::collections::HashSet;
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
pub const FEATURE_MEDIA_AUDIO_ENCODE: &str = "media.audio_encode";
pub const FEATURE_MEDIA_CLIP_ENCODE: &str = "media.clip_encode";

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

    /// In-process unit tests must not exec host ffmpeg/docker/keyring probes.
    #[cfg(test)]
    pub fn for_unit_tests(cwd: PathBuf) -> Self {
        Self {
            keyring: KeyringProbeSource::Injected {
                result: KeyringProbeResult {
                    state: FeatureCapabilityState::Missing,
                    reason: "unit test: no host keyring".into(),
                    fix_command: None,
                    remedy_text: None,
                },
                calls: Arc::new(AtomicUsize::new(0)),
            },
            sandbox: SandboxProbeSource::Injected(SandboxAvailability::Unavailable {
                reason: "unit test: no sandbox".into(),
                fix_command: None,
            }),
            container: ContainerProbeSource::Injected {
                availability: ContainerAvailability {
                    runtime: None,
                    harness_in_container: false,
                    available: false,
                    reason: Some(ContainerUnavailableReason::NoRuntime),
                },
                detect_calls: Arc::new(AtomicUsize::new(0)),
            },
            catalog: CatalogProbeSource::Injected(ExternalRuntimeSnapshot::empty(
                1,
                detect_host_platform(),
            )),
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

/// Generation-tagged snapshot store. An older *committed* refresh never
/// overwrites a newer committed snapshot; an uncommitted probe reservation has
/// no authority to suppress a durable receipt.
#[derive(Clone, Debug, Default)]
pub struct HostCapabilitySnapshotStore {
    inner: Arc<Mutex<StoreInner>>,
    // The daemon-global outbox dispatcher and refresh execution hold this
    // across ordered receipt replay, probe, and acknowledgement. It lives
    // beside the shared snapshot state (rather than a session-worker config
    // clone) so every session using this store observes one serialization
    // boundary. The matching DB claim is global too: this lock is not merely
    // an in-process optimization over per-session durability.
    refresh_serialization: Arc<tokio::sync::Mutex<()>>,
    // Refresh operations are global to this store as well. Keeping this
    // registry beside the serialization lock makes duplicate dispatch
    // suppression survive the per-session configuration snapshots which
    // merely clone the store. The durable DB lease remains the cross-process
    // authority; this set prevents an unbounded pile of same-process retry
    // tasks while a lease owner is still making progress.
    refresh_in_flight_operations: Arc<Mutex<HashSet<uuid::Uuid>>>,
    // Stable per-session keyset cursors for bounded allowed-refresh
    // maintenance. This is scheduling state only; durable ordering and
    // eligibility remain in SQLite.
    refresh_allowed_operation_cursors:
        Arc<Mutex<std::collections::HashMap<uuid::Uuid, Option<(i64, uuid::Uuid)>>>>,
}

/// Probe output reserved for a later, explicitly authorized publication.
///
/// A durable host operation must not make a probe observable merely because
/// collecting it succeeded: cancellation or a failed completion CAS may win
/// between the read-only probe and the durable terminal receipt.  Keeping the
/// snapshot staged makes the caller choose that receipt boundary before it
/// mutates the live store.
#[derive(Clone)]
pub struct StagedHostCapabilityRefresh {
    snapshot: HostCapabilitySnapshot,
}

impl StagedHostCapabilityRefresh {
    pub fn snapshot(&self) -> &HostCapabilitySnapshot {
        &self.snapshot
    }

    pub fn into_snapshot(self) -> HostCapabilitySnapshot {
        self.snapshot
    }
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

    pub(crate) fn refresh_serialization(&self) -> Arc<tokio::sync::Mutex<()>> {
        Arc::clone(&self.refresh_serialization)
    }

    pub(crate) fn refresh_in_flight_operations(&self) -> Arc<Mutex<HashSet<uuid::Uuid>>> {
        Arc::clone(&self.refresh_in_flight_operations)
    }

    pub(crate) fn refresh_allowed_operation_cursor(
        &self,
        session_id: uuid::Uuid,
    ) -> Option<(i64, uuid::Uuid)> {
        self.refresh_allowed_operation_cursors
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&session_id)
            .copied()
            .flatten()
    }

    pub(crate) fn set_refresh_allowed_operation_cursor(
        &self,
        session_id: uuid::Uuid,
        cursor: Option<(i64, uuid::Uuid)>,
    ) {
        self.refresh_allowed_operation_cursors
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(session_id, cursor);
    }

    pub fn begin_refresh(&self) -> u64 {
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        inner.next_generation = inner.next_generation.saturating_add(1);
        inner.next_generation
    }

    /// Seed a newly constructed daemon store from durable refresh state before
    /// it creates any local snapshot. This advances only the reservation
    /// high-water; callers which have a completed receipt should additionally
    /// install it with [`Self::publish_committed`].
    pub fn observe_durable_generation(&self, generation: u64) {
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        inner.next_generation = inner.next_generation.max(generation);
    }

    /// Accept the exact generation already reserved by the database at the
    /// host-effect execution boundary. This is not a new reservation: the DB
    /// has already made it globally durable. A stale process cannot stage an
    /// older number beneath a live or recovered receipt.
    pub fn accept_durable_refresh_reservation(&self, generation: u64) -> Result<(), String> {
        if generation == 0 {
            return Err("host capability durable refresh generation must be positive".to_string());
        }
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(current) = &inner.current
            && generation <= current.generation
        {
            return Err(format!(
                "host capability durable refresh generation {generation} is not newer than live generation {}",
                current.generation
            ));
        }
        // A restart may load a global allocator value ahead of this process;
        // the exact claimed generation may equal that high-water. Do not call
        // `begin_refresh` here, which would invent a second number.
        inner.next_generation = inner.next_generation.max(generation);
        Ok(())
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

    /// Atomically make a durably committed refresh visible.  Unlike
    /// [`Self::publish`], a reservation from a later probe cannot strand an
    /// earlier receipt: an uncommitted later probe must never suppress a
    /// committed result.  A snapshot that has already been superseded by a
    /// newer *committed* generation leaves that newer current value intact.
    ///
    /// This is deliberately an in-memory mutex-protected swap with no fallible
    /// I/O after the durable completion transaction.  The returned flag says
    /// whether this receipt changed the live view. A receipt may also be
    /// replayed after a crash, in which case the store accepts it only when it
    /// already contains the *exact* same snapshot. A different snapshot at the
    /// same or a newer generation is a durable/in-memory split-brain signal;
    /// callers must retain the outbox entry and fail closed rather than
    /// acknowledging an unpublished result.
    pub fn publish_committed(&self, snapshot: HostCapabilitySnapshot) -> Result<bool, String> {
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        match &inner.current {
            Some(current) if current.generation > snapshot.generation => {
                return Err(format!(
                    "host capability receipt generation {} is older than live generation {}",
                    snapshot.generation, current.generation
                ));
            }
            Some(current) if current.generation == snapshot.generation => {
                if current.as_ref() != &snapshot {
                    return Err(format!(
                        "host capability receipt generation {} disagrees with the live snapshot",
                        snapshot.generation
                    ));
                }
                // Recovery may install a committed receipt before any local
                // refresh reservation has happened. Keep the high-water mark
                // coupled to that receipt so the next `begin_refresh` cannot
                // reuse this generation and be silently rejected later.
                inner.next_generation = inner.next_generation.max(snapshot.generation);
                return Ok(false);
            }
            _ => {}
        }
        // The generation high-water and visible committed snapshot advance
        // under the same mutex. This includes outbox recovery: after replaying
        // durable generation N, the next reservation is strictly greater than
        // N even on a freshly constructed store.
        inner.next_generation = inner.next_generation.max(snapshot.generation);
        inner.current = Some(Arc::new(snapshot));
        Ok(true)
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
    let staged = stage_host_capabilities_refresh(store, inputs).await?;
    publish_staged_host_capabilities_refresh(store, staged)
}

/// Same as [`refresh_host_capabilities`], but publish `secret_store` (already
/// post-migrate) instead of the pre-refresh placement. Reconcile still applies
/// so a keyring dest can fail closed on a fresh probe.
pub async fn refresh_host_capabilities_with_secret_store(
    store: &HostCapabilitySnapshotStore,
    inputs: &HostCapabilityProbeInputs,
    secret_store: SecretStoreSnapshot,
) -> Result<(HostCapabilitySnapshot, bool), String> {
    let staged =
        stage_host_capabilities_refresh_with_secret_store(store, inputs, secret_store).await?;
    publish_staged_host_capabilities_refresh(store, staged)
}

/// Collect a new host-capability snapshot without publishing it.  The caller
/// must first commit any durable operation receipt that authorizes this exact
/// probe, then call [`publish_staged_host_capabilities_refresh`].
pub async fn stage_host_capabilities_refresh(
    store: &HostCapabilitySnapshotStore,
    inputs: &HostCapabilityProbeInputs,
) -> Result<StagedHostCapabilityRefresh, String> {
    stage_host_capabilities_refresh_inner(store, inputs, None, store.begin_refresh()).await
}

/// Stage a refresh using the supplied post-migration secret-store projection
/// without exposing it until the caller has committed its own durable receipt.
pub async fn stage_host_capabilities_refresh_with_secret_store(
    store: &HostCapabilitySnapshotStore,
    inputs: &HostCapabilityProbeInputs,
    secret_store: SecretStoreSnapshot,
) -> Result<StagedHostCapabilityRefresh, String> {
    stage_host_capabilities_refresh_inner(store, inputs, Some(secret_store), store.begin_refresh())
        .await
}

/// Stage a host refresh at the generation reserved by the durable operation
/// claim. AgentTree is the only production caller: it must never derive this
/// value from process-local state after a restart.
pub async fn stage_host_capabilities_refresh_at_generation(
    store: &HostCapabilitySnapshotStore,
    inputs: &HostCapabilityProbeInputs,
    generation: u64,
) -> Result<StagedHostCapabilityRefresh, String> {
    store.accept_durable_refresh_reservation(generation)?;
    stage_host_capabilities_refresh_inner(store, inputs, None, generation).await
}

async fn stage_host_capabilities_refresh_inner(
    store: &HostCapabilitySnapshotStore,
    inputs: &HostCapabilityProbeInputs,
    secret_store: Option<SecretStoreSnapshot>,
    generation: u64,
) -> Result<StagedHostCapabilityRefresh, String> {
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
    Ok(StagedHostCapabilityRefresh { snapshot })
}

/// Publish a snapshot that was staged by one prior probe *after* its durable
/// receipt succeeds. Publication atomically installs the result unless the
/// store already contains that exact receipt. A different same/newer live
/// snapshot is an error: callers must retain the durable outbox item rather
/// than acknowledge a snapshot that was not made visible. The returned
/// snapshot is always this staged operation's durable receipt, never a lossy
/// projection of a concurrent refresh.
pub fn publish_staged_host_capabilities_refresh(
    store: &HostCapabilitySnapshotStore,
    staged: StagedHostCapabilityRefresh,
) -> Result<(HostCapabilitySnapshot, bool), String> {
    let snapshot = staged.into_snapshot();
    let published = store.publish_committed(snapshot.clone())?;
    Ok((snapshot, published))
}

pub struct SharedHostProbes {
    pub keyring: KeyringProbeResult,
    pub sandbox: SandboxAvailability,
    pub container: ContainerAvailability,
    pub catalog: ExternalRuntimeSnapshot,
    pub catalog_descriptors: Vec<ExternalRuntimeDescriptor>,
    pub platform: HostPlatform,
    pub av_runtime_capabilities: crate::tool_media_authority::AvRuntimeCapabilities,
}

pub async fn collect_shared_host_probes(
    inputs: &HostCapabilityProbeInputs,
    refresh_keyring: bool,
) -> SharedHostProbes {
    let keyring = match &inputs.keyring {
        KeyringProbeSource::Production => {
            // zbus Store::new builds a nested Tokio runtime. Never probe on a
            // worker that is already inside `block_on` (daemon boot / refresh).
            let refresh = refresh_keyring;
            std::thread::Builder::new()
                .name("cockpit-keyring-probe".into())
                .spawn(move || {
                    if refresh {
                        probe_platform_keyring_refresh()
                    } else {
                        probe_platform_keyring()
                    }
                })
                .and_then(|handle| {
                    handle.join().map_err(|_| {
                        std::io::Error::other("platform keyring probe thread panicked")
                    })
                })
                .unwrap_or_else(|error| {
                    let panicked = error.to_string().contains("panicked");
                    KeyringProbeResult {
                        state: FeatureCapabilityState::Failed,
                        reason: format!("platform keyring probe failed: {error}"),
                        fix_command: None,
                        remedy_text: Some(if panicked {
                            "The OS keyring probe panicked while a Tokio runtime was active.".into()
                        } else {
                            format!("The OS keyring probe could not be started: {error}")
                        }),
                    }
                })
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
    let av_runtime_capabilities = match &inputs.catalog {
        CatalogProbeSource::Production => {
            probe_av_runtime_capabilities(&catalog, &SystemProbeExecutor)
        }
        CatalogProbeSource::Injected(_) => {
            let compatible = media_runtime_pair_is_compatible(&catalog);
            crate::tool_media_authority::AvRuntimeCapabilities {
                ffprobe_compatible: crate::external_runtime::select_media_ffprobe(&catalog).is_ok(),
                ffmpeg_decode: compatible,
                audio_encoder: false,
                clip_encoders: false,
            }
        }
    };
    SharedHostProbes {
        keyring,
        sandbox,
        container,
        catalog,
        catalog_descriptors,
        platform: inputs.platform,
        av_runtime_capabilities,
    }
}

fn probe_av_runtime_capabilities(
    catalog: &ExternalRuntimeSnapshot,
    executor: &dyn ProbeExecutor,
) -> crate::tool_media_authority::AvRuntimeCapabilities {
    let ffprobe_compatible = crate::external_runtime::select_media_ffprobe(catalog).is_ok();
    let Ok((ffmpeg, _)) = crate::external_runtime::select_media_runtime_pair(catalog) else {
        return crate::tool_media_authority::AvRuntimeCapabilities {
            ffprobe_compatible,
            ..crate::tool_media_authority::AvRuntimeCapabilities::default()
        };
    };
    let succeeds = |args: &[&str]| {
        let args = args
            .iter()
            .map(|value| (*value).to_owned())
            .collect::<Vec<_>>();
        let result = executor.run(
            ffmpeg,
            &args,
            crate::external_runtime::FUNCTIONAL_PROBE_DEADLINE,
            &CancelToken::new(),
        );
        result.exit_code == Some(0)
            && !result.timed_out
            && !result.cancelled
            && result.spawn_error.is_none()
    };
    let ffmpeg_decode = succeeds(&[
        "-nostdin",
        "-v",
        "error",
        "-f",
        "lavfi",
        "-i",
        "color=c=black:s=2x2:d=0.04",
        "-frames:v",
        "1",
        "-vf",
        "format=rgb24",
        "-f",
        "image2pipe",
        "-vcodec",
        "png",
        "pipe:1",
    ]);
    let audio_encoder = ffmpeg_decode
        && succeeds(&[
            "-nostdin",
            "-v",
            "error",
            "-f",
            "lavfi",
            "-i",
            "anullsrc=r=8000:cl=mono",
            "-t",
            "0.001",
            "-c:a",
            "pcm_s16le",
            "-f",
            "wav",
            "pipe:1",
        ]);
    let clip_encoders = audio_encoder
        && succeeds(&[
            "-nostdin",
            "-v",
            "error",
            "-f",
            "lavfi",
            "-i",
            "color=c=black:s=2x2:d=0.04",
            "-f",
            "lavfi",
            "-i",
            "anullsrc=r=8000:cl=mono",
            "-t",
            "0.04",
            "-c:v",
            "libx264",
            "-pix_fmt",
            "yuv420p",
            "-c:a",
            "aac",
            "-f",
            "null",
            "-",
        ]);
    crate::tool_media_authority::AvRuntimeCapabilities {
        ffprobe_compatible,
        ffmpeg_decode,
        audio_encoder,
        clip_encoders,
    }
}

pub(crate) fn live_av_runtime_capabilities() -> crate::tool_media_authority::AvRuntimeCapabilities {
    crate::external_runtime::global_health_store()
        .current()
        .map(|snapshot| probe_av_runtime_capabilities(&snapshot, &SystemProbeExecutor))
        .unwrap_or_default()
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
            }
        }
        cockpit_proto::SecretStoreIntent::Keyring if probe.state.is_available() => {
            SecretStoreSnapshot {
                intent: cockpit_proto::SecretStoreIntent::Keyring,
                effective_placement: cockpit_proto::SecretStorePlacement::Keyring,
                fail_closed_reason: None,
                fix_command: None,
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
        feature_media_decode(
            &catalog,
            &dependencies,
            probes.av_runtime_capabilities.ffmpeg_decode,
        ),
        feature_media_runtime_stage(
            FEATURE_MEDIA_AUDIO_ENCODE,
            probes.av_runtime_capabilities.audio_encoder,
            if probes.av_runtime_capabilities.audio_encoder {
                "FFmpeg PCM/WAV audio extraction encoder is available"
            } else {
                "FFmpeg PCM/WAV audio extraction encoder probe failed"
            },
        ),
        feature_media_runtime_stage(
            FEATURE_MEDIA_CLIP_ENCODE,
            probes.av_runtime_capabilities.clip_encoders,
            if probes.av_runtime_capabilities.clip_encoders {
                "FFmpeg H.264/yuv420p/AAC clip encoders are available"
            } else {
                "FFmpeg H.264/yuv420p/AAC clip encoder probe failed"
            },
        ),
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
    functional_decode_available: bool,
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
    if media_runtime_pair_is_compatible(catalog) && functional_decode_available {
        FeatureCapabilityRow {
            id: FEATURE_MEDIA_DECODE.to_string(),
            state: FeatureCapabilityState::Available,
            reason: "ffmpeg and ffprobe are a compatible pair".into(),
            fix_command: None,
            remedy_text: None,
            dependency_ids: vec![ID_MEDIA_FFMPEG.to_string(), ID_MEDIA_FFPROBE.to_string()],
        }
    } else if media_runtime_pair_is_compatible(catalog) {
        FeatureCapabilityRow {
            id: FEATURE_MEDIA_DECODE.to_string(),
            state: FeatureCapabilityState::Missing,
            reason: "FFmpeg storyboard/decode functional probe failed".into(),
            fix_command: None,
            remedy_text: Some(
                "Install an FFmpeg build containing PNG storyboard/decode support.".into(),
            ),
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

fn feature_media_runtime_stage(id: &str, available: bool, reason: &str) -> FeatureCapabilityRow {
    FeatureCapabilityRow {
        id: id.to_owned(),
        state: if available {
            FeatureCapabilityState::Available
        } else {
            FeatureCapabilityState::Missing
        },
        reason: reason.to_owned(),
        fix_command: None,
        remedy_text: (!available).then(|| {
            "Install an FFmpeg build containing the codecs required by this media stage.".to_owned()
        }),
        dependency_ids: vec![ID_MEDIA_FFMPEG.to_owned(), ID_MEDIA_FFPROBE.to_owned()],
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
