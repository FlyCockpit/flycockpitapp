//! Trust-aware, source-preserving native command-hook configuration.
//!
//! This module only discovers and validates metadata. It never executes a
//! command, constructs a process environment, interprets a decision, or owns
//! runtime authority.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fmt;
use std::path::{Component, Path, PathBuf};

use serde::de::{MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::config::dirs::{
    COCKPIT_CONFIG_ENV, CONFIG_FILE, ConfigDirKind, config_file_paths_for_load,
    discover_config_dirs,
};

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
            Self::PreCompact => HookEventPolicy::new(
                G::Observe,
                A::PreparedApplyAttempt,
                M::Closed(&["manual", "auto"]),
                5,
            ),
            Self::PostCompact => HookEventPolicy::new(
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
    PreparedApplyAttempt,
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

#[derive(Clone, PartialEq, Eq)]
pub struct ResolvedHook {
    pub event: HookEvent,
    pub matcher: Option<BTreeSet<String>>,
    pub command: Vec<String>,
    pub timeout_secs: u16,
    pub env: BTreeMap<String, String>,
    pub origin: HookOrigin,
    pub source_config_path: PathBuf,
    pub source_directory: PathBuf,
}

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
    let sources = sources_for_cwd(cwd, paths);
    resolve_hooks_from_sources(&sources)
}

fn sources_for_cwd(cwd: &Path, paths: Vec<PathBuf>) -> Vec<HookConfigSource> {
    if std::env::var_os(COCKPIT_CONFIG_ENV).is_some_and(|value| !value.is_empty()) {
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
    if !source.path.exists() {
        return;
    }
    let bytes = match std::fs::read(&source.path) {
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
    let digest = source_digest(&source.path);
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
                &digest,
                handler_index,
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
    command[0] = resolve_executable(&command[0], source_directory)
        .ok_or("resolved executable path is not valid UTF-8")?;
    Ok(ResolvedHook {
        event,
        matcher,
        command,
        timeout_secs,
        env: raw.env,
        origin: HookOrigin(format!("{kind}:{digest}:{index}")),
        source_config_path: source_path.to_path_buf(),
        source_directory: source_directory.to_path_buf(),
    })
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
        HookMatcherPolicy::CanonicalToolName
        | HookMatcherPolicy::ChildAgentType
        | HookMatcherPolicy::ErrorClass
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

    let canonical = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let digest = Sha256::digest(canonical.to_string_lossy().as_bytes());
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
        HookSourceKind::Layer(ConfigDirKind::HomeDot) => "user",
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
