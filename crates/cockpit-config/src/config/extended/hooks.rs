//! Trust-aware, source-preserving native command-hook configuration.
//!
//! This module only discovers and validates metadata. It never executes a
//! command, constructs a process environment, interprets a decision, or owns
//! runtime authority.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fmt;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use serde::de::{MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::config::dirs::{
    COCKPIT_CONFIG_ENV, CONFIG_FILE, ConfigDirKind, config_file_paths_for_load,
    discover_config_dirs,
};

// Closed matcher vocabulary for the `stopFailure` event's `errorClass` matcher.
// These tokens are the wire spelling of each `InferenceErrorClass` variant
// (`cockpit-proto`); the runtime classifier in `cockpit-core` maps a failure to
// exactly one of these strings. Keeping the vocabulary here — beside matcher
// validation — lets us reject an authored matcher that names a class the engine
// can never emit, instead of silently configuring a hook that never fires.
pub const ERROR_CLASS_TIMEOUT_TTFT: &str = "timeout_ttft";
pub const ERROR_CLASS_TIMEOUT_IDLE: &str = "timeout_idle";
pub const ERROR_CLASS_NETWORK: &str = "network";
pub const ERROR_CLASS_HTTP: &str = "http";
pub const ERROR_CLASS_UTILITY_TIMEOUT: &str = "utility_timeout";
pub const ERROR_CLASS_MISSING_TOOL_ENTITLEMENT: &str = "missing_tool_entitlement";
pub const ERROR_CLASS_CLIENT_SIDE_TOOLS_UNSUPPORTED: &str = "client_side_tools_unsupported";
pub const ERROR_CLASS_RESPONSES_TOOL_IDENTITY: &str = "responses_tool_identity";
pub const ERROR_CLASS_PROVIDER_NOT_CONFIGURED: &str = "provider_not_configured";
pub const ERROR_CLASS_PROVIDER_RATE_LIMIT: &str = "provider_rate_limit";
pub const ERROR_CLASS_BILLING_OR_QUOTA_EXHAUSTED: &str = "billing_or_quota_exhausted";
pub const ERROR_CLASS_UNRENDERABLE_WIRE_FIELD: &str = "unrenderable_wire_field";
pub const ERROR_CLASS_OTHER: &str = "other";

/// Closed set of recognized `errorClass` matcher tokens for `stopFailure`.
///
/// One entry per `InferenceErrorClass` variant; data-bearing variants
/// (`Http`, `Other`) collapse to their coarse token. An authored matcher value
/// outside this set is rejected at config-validation time.
pub const HOOK_ERROR_CLASS_MATCH_VALUES: &[&str] = &[
    ERROR_CLASS_TIMEOUT_TTFT,
    ERROR_CLASS_TIMEOUT_IDLE,
    ERROR_CLASS_NETWORK,
    ERROR_CLASS_HTTP,
    ERROR_CLASS_UTILITY_TIMEOUT,
    ERROR_CLASS_MISSING_TOOL_ENTITLEMENT,
    ERROR_CLASS_CLIENT_SIDE_TOOLS_UNSUPPORTED,
    ERROR_CLASS_RESPONSES_TOOL_IDENTITY,
    ERROR_CLASS_PROVIDER_NOT_CONFIGURED,
    ERROR_CLASS_PROVIDER_RATE_LIMIT,
    ERROR_CLASS_BILLING_OR_QUOTA_EXHAUSTED,
    ERROR_CLASS_UNRENDERABLE_WIRE_FIELD,
    ERROR_CLASS_OTHER,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum HookEvent {
    SessionStart,
    UserPromptSubmit,
    PreToolUse,
    PostToolUse,
    PostToolUseFailure,
    PermissionDenied,
    Stop,
    StopFailure,
    SubagentStart,
    SubagentStop,
    PreCompact,
    PostCompact,
    SessionEnd,
}

impl HookEvent {
    pub const ALL: [Self; 13] = [
        Self::SessionStart,
        Self::UserPromptSubmit,
        Self::PreToolUse,
        Self::PostToolUse,
        Self::PostToolUseFailure,
        Self::PermissionDenied,
        Self::Stop,
        Self::StopFailure,
        Self::SubagentStart,
        Self::SubagentStop,
        Self::PreCompact,
        Self::PostCompact,
        Self::SessionEnd,
    ];

    pub const fn key(self) -> &'static str {
        match self {
            Self::SessionStart => "sessionStart",
            Self::UserPromptSubmit => "userPromptSubmit",
            Self::PreToolUse => "preToolUse",
            Self::PostToolUse => "postToolUse",
            Self::PostToolUseFailure => "postToolUseFailure",
            Self::PermissionDenied => "permissionDenied",
            Self::Stop => "stop",
            Self::StopFailure => "stopFailure",
            Self::SubagentStart => "subagentStart",
            Self::SubagentStop => "subagentStop",
            Self::PreCompact => "preCompact",
            Self::PostCompact => "postCompact",
            Self::SessionEnd => "sessionEnd",
        }
    }

    pub const fn policy(self) -> HookEventPolicy {
        use HookApplicability as A;
        use HookGate as G;
        use HookMatcherPolicy as M;
        match self {
            Self::SessionStart => HookEventPolicy::new(
                G::Observe,
                A::RootAndChild,
                M::Closed(&["fresh", "resume"]),
                5,
            ),
            Self::UserPromptSubmit => {
                HookEventPolicy::new(G::Observe, A::RootOnly, M::Closed(&["user", "queued"]), 5)
            }
            Self::PreToolUse => {
                HookEventPolicy::new(G::Tool, A::OrdinaryToolOnly, M::CanonicalToolName, 5)
            }
            Self::PostToolUse | Self::PostToolUseFailure => HookEventPolicy::new(
                G::Observe,
                A::RealOrdinaryExecutionOnly,
                M::CanonicalToolName,
                5,
            ),
            Self::PermissionDenied => HookEventPolicy::new(
                G::Observe,
                A::AnyDeniedToolApproval,
                M::CanonicalToolName,
                5,
            ),
            Self::Stop => {
                HookEventPolicy::new(G::Stop, A::NormalRootDoneOnly, M::Closed(&["end_turn"]), 60)
            }
            Self::StopFailure => {
                HookEventPolicy::new(G::Observe, A::InferenceErrorOnly, M::ErrorClass, 5)
            }
            Self::SubagentStart => {
                HookEventPolicy::new(G::Observe, A::ChildOnly, M::ChildAgentType, 5)
            }
            Self::SubagentStop => {
                HookEventPolicy::new(G::Stop, A::ChildOnly, M::ChildAgentType, 60)
            }
            Self::PreCompact | Self::PostCompact => HookEventPolicy::new(
                G::Observe,
                A::SuccessfulCompactionOnly,
                M::Closed(&["manual", "auto"]),
                5,
            ),
            Self::SessionEnd => HookEventPolicy::new(
                G::Observe,
                A::EverySession,
                M::Closed(&["completed", "interrupted", "cancelled", "shutdown", "error"]),
                5,
            ),
        }
    }

    fn from_key(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|event| event.key() == value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HookGate {
    Observe,
    Tool,
    Stop,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HookApplicability {
    RootAndChild,
    RootOnly,
    OrdinaryToolOnly,
    RealOrdinaryExecutionOnly,
    AnyDeniedToolApproval,
    NormalRootDoneOnly,
    InferenceErrorOnly,
    ChildOnly,
    SuccessfulCompactionOnly,
    EverySession,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookMatcherPolicy {
    Closed(&'static [&'static str]),
    CanonicalToolName,
    ChildAgentType,
    ErrorClass,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HookEventPolicy {
    pub gate: HookGate,
    pub applicability: HookApplicability,
    pub matcher: HookMatcherPolicy,
    pub default_timeout_secs: u16,
}

impl HookEventPolicy {
    const fn new(
        gate: HookGate,
        applicability: HookApplicability,
        matcher: HookMatcherPolicy,
        default_timeout_secs: u16,
    ) -> Self {
        Self {
            gate,
            applicability,
            matcher,
            default_timeout_secs,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HookSourceKind {
    Layer(ConfigDirKind),
    Explicit,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookConfigSource {
    pub kind: HookSourceKind,
    pub path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HookOrigin(String);

impl HookOrigin {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for HookOrigin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(any(test, feature = "test-support"))]
impl HookOrigin {
    /// Construct a `HookOrigin` for tests. The origin must be a valid
    /// `layer:digest:index` string.
    pub fn for_test(value: impl Into<String>) -> Self {
        Self(value.into())
    }
}

/// Execution context for an already-resolved hook command.
///
/// This is deliberately runtime-only. It is neither serializable nor included
/// in diagnostics: a daemon may attach a capability-backed implementation for
/// a workspace-relative hook, and that capability must never cross a protocol,
/// log, audit record, or configuration export.
#[derive(Clone)]
pub struct HookExecutionLaunch {
    executable: PathBuf,
    working_directory: HookWorkingDirectory,
    /// Holds any daemon-private execution bundle alive until the child has
    /// inherited its program and working-directory state.
    _lease: Option<Arc<dyn HookExecutionLease>>,
}

impl HookExecutionLaunch {
    pub fn ambient(executable: PathBuf, working_directory: PathBuf) -> Self {
        Self {
            executable,
            working_directory: HookWorkingDirectory::Path(working_directory),
            _lease: None,
        }
    }

    pub fn retained(
        executable: PathBuf,
        working_directory: HookWorkingDirectory,
        lease: Arc<dyn HookExecutionLease>,
    ) -> Self {
        Self {
            executable,
            working_directory,
            _lease: Some(lease),
        }
    }

    pub fn executable(&self) -> &Path {
        &self.executable
    }

    pub fn working_directory(&self) -> &HookWorkingDirectory {
        &self.working_directory
    }
}

impl fmt::Debug for HookExecutionLaunch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HookExecutionLaunch")
            .field("execution", &"runtime-private")
            .finish_non_exhaustive()
    }
}

/// Object retained solely to keep a capability-backed hook launch valid.
/// Implementations must not expose their path/handle through `Debug` or any
/// serialization boundary.
pub trait HookExecutionLease: Send + Sync {}

/// Windows-specific working-directory lease.  `CreateProcess` accepts a
/// pathname rather than a directory handle, so the daemon implementation keeps
/// a no-delete handle chain alive and re-proves the canonical spelling still
/// names that exact chain immediately before spawning the child.  This narrow
/// trait keeps the handle and its private proof out of config, protocol, and
/// diagnostics while allowing the core runner to use the verified spelling.
#[cfg(windows)]
pub trait RetainedWindowsHookWorkingDirectory: HookExecutionLease {
    fn canonical_path(&self) -> &Path;
    fn revalidate_before_spawn(&self) -> Result<(), String>;
}

/// A working directory selected by the hook authority.  The retained Unix
/// variant keeps an already-open directory alive so `pre_exec(fchdir)` can use
/// the original directory even after its pathname is renamed or replaced. The
/// Windows variant carries a typed no-delete lease because `CreateProcess`
/// requires a path for `lpCurrentDirectory`.
#[derive(Clone)]
pub enum HookWorkingDirectory {
    Path(PathBuf),
    #[cfg(unix)]
    RetainedUnixDirectory(Arc<std::fs::File>),
    #[cfg(windows)]
    RetainedWindowsDirectory(Arc<dyn RetainedWindowsHookWorkingDirectory>),
}

impl fmt::Debug for HookWorkingDirectory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Path(_) => formatter.write_str("HookWorkingDirectory::Path(..)"),
            #[cfg(unix)]
            Self::RetainedUnixDirectory(_) => {
                formatter.write_str("HookWorkingDirectory::RetainedUnixDirectory(..)")
            }
            #[cfg(windows)]
            Self::RetainedWindowsDirectory(_) => {
                formatter.write_str("HookWorkingDirectory::RetainedWindowsDirectory(..)")
            }
        }
    }
}

/// Daemon-only authority for one source-relative hook executable.  The config
/// crate owns the typed hand-off while the daemon supplies the platform file
/// capability and private execution bundle below it.
pub trait RetainedHookExecutionAuthority: Send + Sync {
    fn launch(&self, relative_components: &[String]) -> Result<HookExecutionLaunch, String>;
}

/// How `command[0]` was resolved.  Relative project/explicit commands are not
/// lexicalized into a mutable source pathname: they require a daemon-retained
/// authority to produce a launch context at execution time.
#[derive(Clone)]
pub enum HookExecutionProvenance {
    Ambient,
    RetainedRelative {
        components: Vec<String>,
        authority: Option<Arc<dyn RetainedHookExecutionAuthority>>,
    },
}

impl fmt::Debug for HookExecutionProvenance {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ambient => formatter.write_str("HookExecutionProvenance::Ambient"),
            Self::RetainedRelative {
                components,
                authority,
            } => formatter
                .debug_struct("HookExecutionProvenance::RetainedRelative")
                .field("component_count", &components.len())
                .field("authority_bound", &authority.is_some())
                .finish(),
        }
    }
}

impl PartialEq for HookExecutionProvenance {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Ambient, Self::Ambient) => true,
            (
                Self::RetainedRelative {
                    components: left, ..
                },
                Self::RetainedRelative {
                    components: right, ..
                },
            ) => left == right,
            _ => false,
        }
    }
}

impl Eq for HookExecutionProvenance {}

#[derive(Clone)]
pub struct ResolvedHook {
    pub event: HookEvent,
    pub matcher: Option<BTreeSet<String>>,
    pub command: Vec<String>,
    pub timeout_secs: u16,
    pub env: BTreeMap<String, String>,
    pub origin: HookOrigin,
    pub source_config_path: PathBuf,
    pub source_directory: PathBuf,
    pub execution: HookExecutionProvenance,
}

impl ResolvedHook {
    /// Bind the non-serializable daemon capability for a captured
    /// source-relative executable. Calling this for an ambient command is a
    /// construction invariant violation, so it is intentionally a typed error
    /// rather than silently widening execution to a pathname.
    pub fn bind_retained_execution_authority(
        &mut self,
        authority: Arc<dyn RetainedHookExecutionAuthority>,
    ) -> Result<(), &'static str> {
        match &mut self.execution {
            HookExecutionProvenance::RetainedRelative {
                authority: bound, ..
            } => {
                *bound = Some(authority);
                Ok(())
            }
            HookExecutionProvenance::Ambient => {
                Err("ambient hook executable must not receive retained execution authority")
            }
        }
    }

    pub fn retained_execution_launch(&self) -> Result<Option<HookExecutionLaunch>, String> {
        match &self.execution {
            HookExecutionProvenance::Ambient => Ok(None),
            HookExecutionProvenance::RetainedRelative {
                components,
                authority: Some(authority),
            } => authority.launch(components).map(Some),
            HookExecutionProvenance::RetainedRelative {
                authority: None, ..
            } => Err("retained relative hook executable has no daemon execution authority".into()),
        }
    }
}

impl PartialEq for ResolvedHook {
    fn eq(&self, other: &Self) -> bool {
        self.event == other.event
            && self.matcher == other.matcher
            && self.command == other.command
            && self.timeout_secs == other.timeout_secs
            && self.env == other.env
            && self.origin == other.origin
            && self.source_config_path == other.source_config_path
            && self.source_directory == other.source_directory
            && self.execution == other.execution
    }
}

impl Eq for ResolvedHook {}

impl fmt::Debug for ResolvedHook {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResolvedHook")
            .field("event", &self.event)
            .field("matcher", &self.matcher)
            .field("executable", &self.command.first())
            .field("argument_count", &self.command.len().saturating_sub(1))
            .field("timeout_secs", &self.timeout_secs)
            .field("env_keys", &self.env.keys().collect::<Vec<_>>())
            .field("origin", &self.origin)
            .field("execution", &self.execution)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookWarning {
    pub source_config_path: PathBuf,
    pub event: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HookRegistry {
    pub hooks: Vec<ResolvedHook>,
    pub warnings: Vec<HookWarning>,
}

pub fn resolve_hooks_for_cwd(cwd: &Path) -> HookRegistry {
    let paths = config_file_paths_for_load(cwd);
    let explicit = std::env::var_os(COCKPIT_CONFIG_ENV).is_some_and(|value| !value.is_empty());
    let sources = hook_sources_for_config_paths(cwd, paths, explicit);
    resolve_hooks_from_sources(&sources)
}

/// Classify a caller-captured sequence of effective config paths for hook
/// resolution without re-reading `COCKPIT_CONFIG`. Daemon workers retain this
/// source selection at attach time so later process-environment mutation
/// cannot redirect a running session's hook configuration.
pub fn hook_sources_for_config_paths(
    cwd: &Path,
    paths: Vec<PathBuf>,
    explicit_config_override: bool,
) -> Vec<HookConfigSource> {
    if explicit_config_override {
        return paths
            .into_iter()
            .map(|path| HookConfigSource {
                kind: HookSourceKind::Explicit,
                path,
            })
            .collect();
    }
    let dirs = discover_config_dirs(cwd);
    paths
        .into_iter()
        .filter_map(|path| {
            dirs.iter()
                .find(|dir| dir.path.join(CONFIG_FILE) == path)
                .map(|dir| HookConfigSource {
                    kind: HookSourceKind::Layer(dir.kind.clone()),
                    path,
                })
        })
        .collect()
}

pub fn resolve_hooks_from_sources(sources: &[HookConfigSource]) -> HookRegistry {
    let mut registry = HookRegistry::default();
    let mut seen = HashSet::new();
    for source in sources {
        resolve_source(source, &mut registry, &mut seen);
    }
    registry
}

/// Resolve hooks from bytes acquired by the caller's filesystem authority.
///
/// The parser deliberately retains the original source metadata for warning,
/// precedence, origin, and relative-command behavior, but does not reopen the
/// path represented by a captured entry.  Daemon workers use this for
/// workspace/explicit layers held at attach; ordinary global callers can keep
/// using [`resolve_hooks_from_sources`].
pub fn resolve_hooks_from_captured_sources(
    sources: &[(HookConfigSource, Result<Option<Vec<u8>>, String>)],
) -> HookRegistry {
    let mut registry = HookRegistry::default();
    let mut seen = HashSet::new();
    for (source, captured) in sources {
        match captured {
            Ok(bytes) => resolve_source_bytes(
                source,
                bytes.as_deref(),
                &source_digest(&source.path),
                matches!(
                    source.kind,
                    HookSourceKind::Layer(ConfigDirKind::Project) | HookSourceKind::Explicit
                ),
                &mut registry,
                &mut seen,
            ),
            Err(error) => warn(
                &mut registry,
                source,
                None,
                format!("could not read config: {error}"),
            ),
        }
    }
    registry
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawHook {
    #[serde(default)]
    matcher: Option<Vec<String>>,
    command: Vec<String>,
    #[serde(default, rename = "timeoutSecs")]
    timeout_secs: Option<u16>,
    #[serde(default)]
    env: BTreeMap<String, String>,
}

#[derive(Debug, Default)]
struct RawHooks(Vec<(String, Value)>);

impl<'de> Deserialize<'de> for RawHooks {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct RawHooksVisitor;
        impl<'de> Visitor<'de> for RawHooksVisitor {
            type Value = RawHooks;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a hooks object")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut entries = Vec::new();
                while let Some(entry) = map.next_entry()? {
                    entries.push(entry);
                }
                Ok(RawHooks(entries))
            }
        }
        deserializer.deserialize_map(RawHooksVisitor)
    }
}

#[derive(Debug, Deserialize)]
struct RawConfig {
    #[serde(default)]
    hooks: Option<RawHooks>,
}

#[derive(Debug, PartialEq, Eq, Hash)]
struct DedupKey {
    event: HookEvent,
    matcher: Option<Vec<String>>,
    command: Vec<String>,
}

fn resolve_source(
    source: &HookConfigSource,
    registry: &mut HookRegistry,
    seen: &mut HashSet<DedupKey>,
) {
    // Ordinary global/non-daemon resolution retains the previous canonical
    // origin behavior. Daemon-held sources use the captured-byte entry point
    // above, which intentionally never canonicalizes/reopens their path.
    let source_identity_path =
        std::fs::canonicalize(&source.path).unwrap_or_else(|_| source.path.clone());
    let bytes = match crate::config::files::read_workspace_config_bytes(&source.path) {
        Ok(bytes) => bytes,
        Err(error) => {
            warn(
                registry,
                source,
                None,
                format!("could not read config: {error}"),
            );
            return;
        }
    };
    resolve_source_bytes(
        source,
        bytes.as_deref(),
        &source_digest(&source_identity_path),
        false,
        registry,
        seen,
    );
}

fn resolve_source_bytes(
    source: &HookConfigSource,
    bytes: Option<&[u8]>,
    digest: &str,
    retain_relative_executable: bool,
    registry: &mut HookRegistry,
    seen: &mut HashSet<DedupKey>,
) {
    let Some(bytes) = bytes else {
        return;
    };
    if bytes.iter().all(u8::is_ascii_whitespace) {
        return;
    }
    let root: RawConfig = match serde_json::from_slice(&bytes) {
        Ok(value) => value,
        Err(_) => {
            warn(
                registry,
                source,
                None,
                "malformed JSON or `hooks` object".into(),
            );
            return;
        }
    };
    let Some(hooks) = root.hooks else {
        return;
    };
    let source_directory = source
        .path
        .parent()
        .unwrap_or_else(|| Path::new(""))
        .to_path_buf();
    let kind = origin_kind(&source.kind);
    let mut index = 0_usize;
    for (event_key, value) in hooks.0 {
        let Some(event) = HookEvent::from_key(&event_key) else {
            if let Some(handlers) = value.as_array() {
                index += handlers.len();
            }
            warn(
                registry,
                source,
                Some(event_key),
                "unsupported hook event".into(),
            );
            continue;
        };
        let Some(handlers) = value.as_array() else {
            warn(
                registry,
                source,
                Some(event_key.clone()),
                "event value must be an array".into(),
            );
            continue;
        };
        for value in handlers {
            let handler_index = index;
            index += 1;
            let raw: RawHook = match serde_json::from_value(value.clone()) {
                Ok(raw) => raw,
                Err(_) => {
                    warn(
                        registry,
                        source,
                        Some(event.key().into()),
                        format!("malformed handler at index {handler_index}"),
                    );
                    continue;
                }
            };
            let resolved = match validate_handler(
                event,
                raw,
                &source.path,
                &source_directory,
                kind,
                digest,
                handler_index,
                retain_relative_executable,
            ) {
                Ok(resolved) => resolved,
                Err(error) => {
                    warn(
                        registry,
                        source,
                        Some(event.key().into()),
                        format!("invalid handler at index {handler_index}: {error}"),
                    );
                    continue;
                }
            };
            let key = DedupKey {
                event,
                matcher: resolved
                    .matcher
                    .as_ref()
                    .map(|values| values.iter().cloned().collect()),
                command: resolved.command.clone(),
            };
            if seen.insert(key) {
                registry.hooks.push(resolved);
            }
        }
    }
}

fn validate_handler(
    event: HookEvent,
    raw: RawHook,
    source_path: &Path,
    source_directory: &Path,
    kind: &str,
    digest: &str,
    index: usize,
    retain_relative_executable: bool,
) -> Result<ResolvedHook, &'static str> {
    if raw.command.is_empty() || raw.command.iter().any(String::is_empty) {
        return Err("command must be a non-empty argv array with no empty items");
    }
    if raw.command[0].contains("://") {
        return Err("only local command hooks are supported");
    }
    if raw.env.keys().any(String::is_empty) {
        return Err("environment keys must not be empty");
    }
    let timeout_secs = raw
        .timeout_secs
        .unwrap_or(event.policy().default_timeout_secs);
    if !(1..=600).contains(&timeout_secs) {
        return Err("timeoutSecs must be in 1..=600");
    }
    let matcher = validate_matcher(event.policy().matcher, raw.matcher)?;
    let mut command = raw.command;
    let execution = if retain_relative_executable
        && !Path::new(&command[0]).is_absolute()
        && !is_bare_executable(Path::new(&command[0]))
    {
        let components = retained_relative_components(&command[0])?;
        // Keep the source-relative spelling deterministic for deduplication and
        // diagnostics, but never turn it into a source-directory pathname.
        // The daemon binds a retained execution authority before this registry
        // can reach a running worker.
        command[0] = components.join("/");
        HookExecutionProvenance::RetainedRelative {
            components,
            authority: None,
        }
    } else {
        command[0] = resolve_executable(&command[0], source_directory)
            .ok_or("resolved executable path is not valid UTF-8")?;
        HookExecutionProvenance::Ambient
    };
    Ok(ResolvedHook {
        event,
        matcher,
        command,
        timeout_secs,
        env: raw.env,
        origin: HookOrigin(format!("{kind}:{digest}:{index}")),
        source_config_path: source_path.to_path_buf(),
        source_directory: source_directory.to_path_buf(),
        execution,
    })
}

/// Convert an attached workspace hook's relative executable into a bounded
/// no-parent-traversal component list.  The retained authority will open each
/// component without following links; accepting `..` here would escape that
/// capability and reintroduce the very mutable-path authority this type
/// protects against.
fn retained_relative_components(executable: &str) -> Result<Vec<String>, &'static str> {
    let path = Path::new(executable);
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(component) => {
                let component = component
                    .to_str()
                    .ok_or("relative executable path is not valid UTF-8")?;
                if component.is_empty() {
                    return Err("relative executable path has an empty component");
                }
                components.push(component.to_owned());
            }
            Component::ParentDir => {
                return Err("relative executable path must not traverse parent directories");
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err("relative executable path is not relative");
            }
        }
    }
    if components.is_empty() {
        return Err("relative executable path must name a file");
    }
    Ok(components)
}

fn validate_matcher(
    policy: HookMatcherPolicy,
    matcher: Option<Vec<String>>,
) -> Result<Option<BTreeSet<String>>, &'static str> {
    let Some(values) = matcher else {
        return Ok(None);
    };
    if values.is_empty() || values.iter().any(String::is_empty) {
        return Err("matcher must be omitted or a non-empty string array");
    }
    let set: BTreeSet<_> = values.iter().cloned().collect();
    match policy {
        HookMatcherPolicy::Closed(allowed)
            if values
                .iter()
                .any(|value| !allowed.contains(&value.as_str())) =>
        {
            return Err("matcher value is not valid for this event");
        }
        HookMatcherPolicy::ErrorClass
            if values
                .iter()
                .any(|value| !HOOK_ERROR_CLASS_MATCH_VALUES.contains(&value.as_str())) =>
        {
            return Err("matcher value is not a recognized inference error class");
        }
        HookMatcherPolicy::CanonicalToolName | HookMatcherPolicy::ChildAgentType
            if values.iter().any(|value| !canonical_match_value(value)) =>
        {
            return Err("matcher value is not canonical");
        }
        _ => {}
    }
    Ok(Some(set))
}

fn canonical_match_value(value: &str) -> bool {
    value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':' | b'/')
    })
}

fn resolve_executable(executable: &str, source_directory: &Path) -> Option<String> {
    let path = Path::new(executable);
    if path.is_absolute() || is_bare_executable(path) {
        return Some(executable.to_owned());
    }
    lexical_normalize(&source_directory.join(path))
        .into_os_string()
        .into_string()
        .ok()
}

fn is_bare_executable(path: &Path) -> bool {
    path.components().count() == 1 && matches!(path.components().next(), Some(Component::Normal(_)))
}

fn lexical_normalize(path: &Path) -> PathBuf {
    let mut output = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                output.pop();
            }
            _ => output.push(component.as_os_str()),
        }
    }
    output
}

fn source_digest(path: &Path) -> String {
    use std::fmt::Write as _;

    // Captured daemon source paths are immutable attach-time descriptors, so
    // hashing their spelling is sufficient for a stable origin and cannot
    // reopen a possibly replaced path merely to decorate metadata.
    let digest = Sha256::digest(path.to_string_lossy().as_bytes());
    let mut output = String::with_capacity(16);
    for byte in digest.iter().take(8) {
        write!(&mut output, "{byte:02x}").expect("writing to a String cannot fail");
    }
    output
}

#[cfg(test)]
mod tests;

fn origin_kind(kind: &HookSourceKind) -> &'static str {
    match kind {
        HookSourceKind::Layer(ConfigDirKind::HomeXdg) => "global",
        HookSourceKind::Layer(ConfigDirKind::MachineLocal) => "machine",
        HookSourceKind::Layer(ConfigDirKind::Project) => "project",
        HookSourceKind::Explicit => "explicit",
    }
}

fn warn(
    registry: &mut HookRegistry,
    source: &HookConfigSource,
    event: Option<String>,
    message: String,
) {
    tracing::warn!(path = %source.path.display(), event = event.as_deref().unwrap_or("<hooks>"), %message, "skipping malformed hook configuration");
    registry.warnings.push(HookWarning {
        source_config_path: source.path.clone(),
        event,
        message,
    });
}
