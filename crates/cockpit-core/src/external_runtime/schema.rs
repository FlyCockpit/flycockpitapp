//! Closed external-runtime descriptor schema.
//!
//! Runtime IDs are open strings so later adapter prompts can register
//! Git/media/harness/container/LSP entries without editing a closed enum.
//! Field shapes, states, and probe policies form a closed schema.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::capabilities::ExecutionTarget;

/// Stable open-string runtime ID (not a closed registry).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ExternalRuntimeId(pub String);

impl ExternalRuntimeId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&str> for ExternalRuntimeId {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

impl From<String> for ExternalRuntimeId {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl std::fmt::Display for ExternalRuntimeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Who owns the registration and which product feature it serves.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalRuntimeOwner {
    pub owner: String,
    pub feature: String,
}

/// Why the dependency matters for health aggregation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencyImportance {
    RequiredForDefaultSafety,
    RequiredWhenFeatureSelected,
    OptionalIntegration,
    OptionalAccelerator,
}

/// Host applicability for a registration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Applicability {
    /// Always considered on the named target when the process can evaluate it.
    Always,
    /// Only when the named feature is selected/enabled by configuration.
    WhenFeatureSelected,
    /// Only when the host platform matches one of the listed platforms.
    Platforms(Vec<HostPlatform>),
    /// Combination: feature selected and platform matches (if platforms non-empty).
    WhenFeatureSelectedOnPlatforms { platforms: Vec<HostPlatform> },
}

/// Platform taxonomy used for recipes and applicability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostPlatform {
    MacOs,
    Windows,
    DebianUbuntu,
    FedoraRhel,
    Arch,
    GenericLinux,
    OtherUnix,
    Unsupported,
}

/// Nested all-of / any-of requirement tree over runtime IDs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "nodes")]
pub enum RequirementGroup {
    AllOf(Vec<RequirementGroup>),
    AnyOf(Vec<RequirementGroup>),
    #[serde(rename = "leaf")]
    Leaf(ExternalRuntimeId),
}

impl RequirementGroup {
    pub fn leaf(id: impl Into<ExternalRuntimeId>) -> Self {
        Self::Leaf(id.into())
    }

    pub fn all_of(nodes: impl IntoIterator<Item = RequirementGroup>) -> Self {
        Self::AllOf(nodes.into_iter().collect())
    }

    pub fn any_of(nodes: impl IntoIterator<Item = RequirementGroup>) -> Self {
        Self::AnyOf(nodes.into_iter().collect())
    }

    pub fn collect_ids(&self, out: &mut Vec<ExternalRuntimeId>) {
        match self {
            Self::Leaf(id) => out.push(id.clone()),
            Self::AllOf(nodes) | Self::AnyOf(nodes) => {
                for node in nodes {
                    node.collect_ids(out);
                }
            }
        }
    }
}

/// Optional compatibility constraint evaluated after a successful version probe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum CompatibilityRule {
    MinVersion {
        version: String,
    },
    ExactVersion {
        version: String,
    },
    /// Free-form catalog rule id interpreted by the owning feature later.
    CatalogRule {
        rule_id: String,
    },
}

/// How a remedy is expressed. Remedies never execute package managers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum RemedyKind {
    /// Platform-specific install recipe strings for trusted catalog entries.
    PlatformRecipes {
        prose: String,
        recipes: BTreeMap<HostPlatform, String>,
    },
    /// Exact PATH/config guidance for user-configured commands (no package guess).
    ConfigGuidance { message: String },
    /// Prose-only fallback.
    Prose { message: String },
}

impl RemedyKind {
    pub fn platform_recipes(
        prose: impl Into<String>,
        recipes: BTreeMap<HostPlatform, String>,
    ) -> Self {
        Self::PlatformRecipes {
            prose: prose.into(),
            recipes,
        }
    }

    pub fn config_guidance(message: impl Into<String>) -> Self {
        Self::ConfigGuidance {
            message: message.into(),
        }
    }

    pub fn prose(message: impl Into<String>) -> Self {
        Self::Prose {
            message: message.into(),
        }
    }

    pub fn render_for(&self, platform: HostPlatform) -> String {
        match self {
            Self::PlatformRecipes { prose, recipes } => {
                if let Some(cmd) = recipes.get(&platform) {
                    format!("{prose} Fix: {cmd}")
                } else if let Some(cmd) = recipes.get(&HostPlatform::GenericLinux) {
                    // Prefer a generic Linux fallback before bare prose when
                    // the exact distro recipe is missing.
                    if matches!(
                        platform,
                        HostPlatform::DebianUbuntu
                            | HostPlatform::FedoraRhel
                            | HostPlatform::Arch
                            | HostPlatform::GenericLinux
                    ) {
                        format!("{prose} Fix: {cmd}")
                    } else {
                        prose.clone()
                    }
                } else {
                    prose.clone()
                }
            }
            Self::ConfigGuidance { message } | Self::Prose { message } => message.clone(),
        }
    }
}

/// Version/functional probe policy.
///
/// [`ProbePolicy::TrustedCatalog`] wraps a privately-fielded
/// [`TrustedCatalogPolicy`] so only [`ProbePolicy::trusted_catalog`] (and
/// serde rehydration for schema fixtures) can construct executable probe argv.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum ProbePolicy {
    /// Repository-authored version/functional argv. Catalog construction only.
    TrustedCatalog(TrustedCatalogPolicy),
    /// User-configured command: resolve + spawnability only. Never executes.
    ConfiguredCommand {
        /// Exact command string from settings (basename or path).
        command: String,
        /// Optional absolute path override from settings.
        exact_path: Option<PathBuf>,
    },
}

/// Repository-authored trusted catalog probe configuration.
///
/// Fields are private so callers outside this module cannot forge version or
/// functional probe argv except through [`ProbePolicy::trusted_catalog`].
///
/// Deserialized policies are never executable: only
/// [`ProbePolicy::trusted_catalog`] mints [`TrustedCatalogPolicy::is_executable`]
/// as true. Serde rehydration is for schema fixtures and headless documents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustedCatalogPolicy {
    version_argv: Vec<String>,
    version_parser: VersionParser,
    functional_argv: Option<Vec<String>>,
    /// True only when constructed via [`ProbePolicy::trusted_catalog`].
    /// Fully skipped by serde so JSON cannot set `"executable": true`.
    #[serde(skip)]
    executable: bool,
}

impl TrustedCatalogPolicy {
    pub fn version_argv(&self) -> &[String] {
        &self.version_argv
    }

    pub fn version_parser(&self) -> &VersionParser {
        &self.version_parser
    }

    pub fn functional_argv(&self) -> Option<&[String]> {
        self.functional_argv.as_deref()
    }

    /// Whether this policy may spawn version/functional probes.
    pub fn is_executable(&self) -> bool {
        self.executable
    }
}

impl ProbePolicy {
    /// Construct a trusted-catalog probe policy.
    ///
    /// `pub(crate)` so only repository catalog registrations inside
    /// `cockpit-core` can mint executable version/functional argv. Downstream
    /// crates and user config cannot construct an executable trusted policy.
    ///
    /// Allowed unused until adapter prompts register concrete catalog entries;
    /// unit tests exercise this constructor now.
    #[allow(dead_code)]
    pub(crate) fn trusted_catalog(
        version_argv: impl IntoIterator<Item = impl Into<String>>,
        version_parser: VersionParser,
        functional_argv: Option<Vec<String>>,
    ) -> Self {
        Self::TrustedCatalog(TrustedCatalogPolicy {
            version_argv: version_argv.into_iter().map(Into::into).collect(),
            version_parser,
            functional_argv,
            executable: true,
        })
    }

    pub fn configured_command(command: impl Into<String>, exact_path: Option<PathBuf>) -> Self {
        Self::ConfiguredCommand {
            command: command.into(),
            exact_path,
        }
    }

    pub fn is_trusted_catalog(&self) -> bool {
        matches!(self, Self::TrustedCatalog(_))
    }

    pub fn is_configured_command(&self) -> bool {
        matches!(self, Self::ConfiguredCommand { .. })
    }

    pub fn as_trusted_catalog(&self) -> Option<&TrustedCatalogPolicy> {
        match self {
            Self::TrustedCatalog(policy) => Some(policy),
            Self::ConfiguredCommand { .. } => None,
        }
    }
}

/// Closed set of version parsers for trusted catalog probes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum VersionParser {
    /// First non-empty whitespace-trimmed line.
    FirstLine,
    /// Capture group from the first regex match in combined output.
    RegexCapture { pattern: String, group: usize },
    /// Take the first token that looks like a dotted version.
    FirstSemverToken,
}

/// Immutable closed descriptor for one external runtime dependency.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalRuntimeDescriptor {
    pub id: ExternalRuntimeId,
    pub owner: ExternalRuntimeOwner,
    /// Ordered executable basenames / candidates tried on PATH.
    pub executable_candidates: Vec<String>,
    pub applicability: Applicability,
    pub importance: DependencyImportance,
    pub target: ExecutionTarget,
    pub probe_policy: ProbePolicy,
    pub compatibility: Option<CompatibilityRule>,
    pub remedy: RemedyKind,
    /// Optional nested group this leaf participates in (for aggregation docs).
    pub group: Option<RequirementGroup>,
}

impl ExternalRuntimeDescriptor {
    pub fn builder(id: impl Into<ExternalRuntimeId>) -> ExternalRuntimeDescriptorBuilder {
        ExternalRuntimeDescriptorBuilder::new(id)
    }
}

/// Fluent builder for catalog descriptors.
#[derive(Debug, Clone)]
pub struct ExternalRuntimeDescriptorBuilder {
    id: ExternalRuntimeId,
    owner: ExternalRuntimeOwner,
    executable_candidates: Vec<String>,
    applicability: Applicability,
    importance: DependencyImportance,
    target: ExecutionTarget,
    probe_policy: Option<ProbePolicy>,
    compatibility: Option<CompatibilityRule>,
    remedy: RemedyKind,
    group: Option<RequirementGroup>,
}

impl ExternalRuntimeDescriptorBuilder {
    pub fn new(id: impl Into<ExternalRuntimeId>) -> Self {
        Self {
            id: id.into(),
            owner: ExternalRuntimeOwner {
                owner: "cockpit-core".into(),
                feature: "unknown".into(),
            },
            executable_candidates: Vec::new(),
            applicability: Applicability::Always,
            importance: DependencyImportance::OptionalIntegration,
            target: ExecutionTarget::Host,
            probe_policy: None,
            compatibility: None,
            remedy: RemedyKind::prose("Install the required command and ensure it is on PATH."),
            group: None,
        }
    }

    pub fn owner(mut self, owner: impl Into<String>, feature: impl Into<String>) -> Self {
        self.owner = ExternalRuntimeOwner {
            owner: owner.into(),
            feature: feature.into(),
        };
        self
    }

    pub fn candidates(mut self, candidates: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.executable_candidates = candidates.into_iter().map(Into::into).collect();
        self
    }

    pub fn applicability(mut self, applicability: Applicability) -> Self {
        self.applicability = applicability;
        self
    }

    pub fn importance(mut self, importance: DependencyImportance) -> Self {
        self.importance = importance;
        self
    }

    pub fn target(mut self, target: ExecutionTarget) -> Self {
        self.target = target;
        self
    }

    pub fn probe_policy(mut self, policy: ProbePolicy) -> Self {
        self.probe_policy = Some(policy);
        self
    }

    pub fn compatibility(mut self, rule: CompatibilityRule) -> Self {
        self.compatibility = Some(rule);
        self
    }

    pub fn remedy(mut self, remedy: RemedyKind) -> Self {
        self.remedy = remedy;
        self
    }

    pub fn group(mut self, group: RequirementGroup) -> Self {
        self.group = Some(group);
        self
    }

    pub fn build(self) -> Result<ExternalRuntimeDescriptor, SchemaError> {
        let probe_policy = self.probe_policy.ok_or(SchemaError::MissingProbePolicy)?;
        if self.executable_candidates.is_empty()
            && !matches!(probe_policy, ProbePolicy::ConfiguredCommand { .. })
        {
            return Err(SchemaError::MissingCandidates);
        }
        if let ProbePolicy::ConfiguredCommand { command, .. } = &probe_policy
            && command.trim().is_empty()
        {
            return Err(SchemaError::EmptyConfiguredCommand);
        }
        Ok(ExternalRuntimeDescriptor {
            id: self.id,
            owner: self.owner,
            executable_candidates: self.executable_candidates,
            applicability: self.applicability,
            importance: self.importance,
            target: self.target,
            probe_policy,
            compatibility: self.compatibility,
            remedy: self.remedy,
            group: self.group,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SchemaError {
    #[error("descriptor is missing a probe policy")]
    MissingProbePolicy,
    #[error("trusted-catalog descriptor requires executable candidates")]
    MissingCandidates,
    #[error("configured command must not be empty")]
    EmptyConfiguredCommand,
}

/// Canonical probe deadlines from the prompt decisions.
pub const VERSION_PROBE_DEADLINE: Duration = Duration::from_secs(2);
pub const FUNCTIONAL_PROBE_DEADLINE: Duration = Duration::from_secs(5);
/// Combined stdout+stderr capture budget.
pub const PROBE_CAPTURE_BUDGET: usize = 8 * 1024;
/// Normalized single-line version evidence budget.
pub const VERSION_EVIDENCE_BUDGET: usize = 512;

/// Complete closed schema document for round-trip tests and headless consumers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalRuntimeSchemaDocument {
    pub schema_version: u32,
    pub descriptors: Vec<ExternalRuntimeDescriptor>,
    pub groups: Vec<RequirementGroup>,
}

impl ExternalRuntimeSchemaDocument {
    pub const CURRENT_VERSION: u32 = 1;

    pub fn empty() -> Self {
        Self {
            schema_version: Self::CURRENT_VERSION,
            descriptors: Vec::new(),
            groups: Vec::new(),
        }
    }
}
